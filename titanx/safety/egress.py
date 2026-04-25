"""Outbound HTTP allowlist enforcement.

This module turns ``IronClawWasmToolSpec.http_allowlist`` from
*declarative metadata* into a *runtime-enforced* trust boundary. It is
the missing link that closes the gap identified in 0.2.x: TitanX could
*describe* what a tool is allowed to reach, but nothing stopped a buggy
or malicious tool from issuing arbitrary outbound requests.

Why a programmatic guard, not a transparent proxy
==================================================

TitanX is an SDK, not a service mesh. It does not control the host's
network namespace, and we deliberately avoid shipping a process-level
TLS-terminating proxy because that adds a CVE surface, requires CA
trust manipulation, and turns every outbound request into a hot path
through a Python proxy.

Instead, ``EgressGuard`` is a pure function over an ``EgressPolicy``:
hosts call ``check(host, path, method)`` (or ``check_url(url, method)``)
right before they issue a request from inside a tool. Denials are
audited via the same ``AuditLog`` pipeline as policy decisions, so a
break-glass relaxation that opens up a destination is forensically
visible.

The contract for tool authors is one line:

    decision = guard.check_url(url, method)
    if not decision.allowed:
        raise EgressDenied(decision.reason)

For tools that go through TitanX's own ``SandboxedToolHandler``, the
host is responsible for installing the guard inside whatever HTTP
client the tool uses (``httpx``, ``aiohttp``, etc). A future change can
make this automatic for handlers that opt in via metadata.

Why default-deny
=================

The IronClaw catalog declares a strict allowlist per tool. The guard
inherits that posture: any host that didn't appear in any rule is
denied, even if the URL is otherwise innocuous. Operators who genuinely
want a permissive default must build an explicit ``OutboundRule`` for
``"*"`` (matches everything) and audit the consequence.
"""

from __future__ import annotations

import asyncio
import contextvars
import inspect
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Iterator, Literal
from urllib.parse import urlsplit


# ── Contextvar-backed caller scope ────────────────────────────────────────
#
# A caller passed explicitly to ``EgressGuard.check / check_url / enforce``
# always wins. When the kwarg is omitted, the guard falls back to the
# *ambient* caller bound by ``caller_scope(name)``. The runtime sets this
# scope around every tool dispatch so a tool author that just does
# ``guard.enforce(url, method)`` from inside their handler still gets a
# correctly-scoped decision — forgetting to thread ``caller=`` no longer
# silently downgrades the call to "anonymous, denied by every preset".
#
# ``ContextVar`` is the right primitive here: asyncio tasks copy the parent
# context on creation, so a tool that fans out work via ``asyncio.gather``
# inside its handler still sees the ambient caller. Threads created via
# ``run_in_executor`` *also* inherit because the executor copies the
# context. Bare ``threading.Thread`` does not — tools that spawn raw
# threads must propagate explicitly with ``contextvars.copy_context()``.

_CURRENT_CALLER: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "titanx_egress_current_caller", default=None,
)


def current_caller() -> str | None:
    """Return the caller currently bound by ``caller_scope`` (or None)."""
    return _CURRENT_CALLER.get()


@contextmanager
def caller_scope(name: str | None) -> Iterator[None]:
    """Bind ``name`` as the ambient egress caller for the enclosed block.

    Synchronous and async callers both work — ``ContextVar`` propagates
    across ``await`` boundaries automatically. Reset is paired in a
    ``finally`` block so a raise inside the scope still unwinds the
    binding. Passing ``None`` deliberately clears any inherited caller
    so a top-level "no caller" branch can be expressed without a
    separate API.
    """
    token = _CURRENT_CALLER.set(name)
    try:
        yield
    finally:
        _CURRENT_CALLER.reset(token)


def _resolve_caller(explicit: str | None) -> str | None:
    """Pick the caller to use for an egress decision.

    Explicit kwargs always win. An empty string is treated as "no
    caller" so the resolution rule aligns with the rest of the
    module's ``caller if caller else None`` idiom.
    """
    if explicit:
        return explicit
    ambient = _CURRENT_CALLER.get()
    return ambient or None


# ── Public types ──────────────────────────────────────────────────────────

EgressAction = Literal["allow", "deny"]


class EgressDenied(RuntimeError):
    """Raised by ``EgressGuard.enforce`` when a request is denied.

    Subclasses ``RuntimeError`` so existing ``except RuntimeError``
    handlers in tool code don't need updating, but distinct enough that
    callers can ``except EgressDenied`` to surface a tighter error to
    the LLM.
    """

    def __init__(self, decision: "EgressDecision") -> None:
        self.decision = decision
        super().__init__(decision.reason)


@dataclass(frozen=True)
class OutboundRule:
    """One declarative entry in an ``EgressPolicy``.

    ``host_pattern`` matches the request authority (case-insensitive,
    no port). Two forms:

    - ``"api.example.com"`` — exact host match.
    - ``"*.example.com"``   — subdomain wildcard. Matches any number of
      sub-labels but **not** the bare apex (``example.com``). This is
      stricter than a typical glob and reflects the IronClaw spec
      style; an apex must be allowlisted explicitly.

    ``path_prefix`` matches the URL path with a literal prefix.
    ``"/"`` matches everything; otherwise the request path must
    start with the rule's prefix after path-normalisation.

    ``methods`` is an iterable of HTTP method names; comparison is
    case-insensitive. An empty tuple means "any method".

    ``allowed_schemes`` defaults to ``("https",)`` — silently
    permitting plaintext http to an allowlisted destination invites
    downgrade attacks against credentialed traffic. Operators who
    need plaintext should opt in explicitly.

    ``allowed_ports`` defaults to "any" (``()``); set to e.g.
    ``(443,)`` to pin a destination to its TLS port.

    ``caller`` optionally pins the rule to a specific tool / process
    identity. NemoClaw's ``binaries:`` list scopes a network policy to
    e.g. ``/usr/local/bin/claude``; the SDK equivalent is the calling
    tool name (or any opaque string the host populates). Matching is
    fail-closed: a rule with ``caller="github_tool"`` does **not**
    match calls that omit the caller — i.e. you cannot accidentally
    inherit privileged egress from generic code paths.
    ``None`` (default) means the rule applies to every caller.
    """

    host_pattern: str
    path_prefix: str = "/"
    methods: tuple[str, ...] = ()
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_ports: tuple[int, ...] = ()
    caller: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.host_pattern, str) or not self.host_pattern:
            raise ValueError("OutboundRule.host_pattern must be a non-empty str")
        if not isinstance(self.path_prefix, str) or not self.path_prefix.startswith("/"):
            raise ValueError(
                f"OutboundRule.path_prefix must start with '/': {self.path_prefix!r}"
            )
        if "*" in self.host_pattern and not self.host_pattern.startswith("*."):
            raise ValueError(
                f"OutboundRule.host_pattern wildcard must be of the form "
                f"'*.example.com': {self.host_pattern!r}"
            )
        if self.caller is not None and (
            not isinstance(self.caller, str) or not self.caller
        ):
            raise ValueError(
                f"OutboundRule.caller must be None or a non-empty str: "
                f"{self.caller!r}"
            )


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    reason: str
    matched_rule: OutboundRule | None = None
    host: str = ""
    path: str = ""
    method: str = ""
    scheme: str = ""
    caller: str | None = None


@dataclass
class EgressPolicy:
    """Container for ``OutboundRule``s plus a default action.

    The default is ``"deny"``. We strongly recommend leaving it at
    deny; flipping to ``"allow"`` makes the guard advisory only.
    """

    rules: list[OutboundRule] = field(default_factory=list)
    default_action: EgressAction = "deny"

    def add(self, rule: OutboundRule) -> None:
        self.rules.append(rule)


# ── Audit hook signature ──────────────────────────────────────────────────
# Sync or async; failures are warned-and-swallowed by the guard so a
# misbehaving sink can't pin every outbound request.
EgressAuditHook = Callable[[EgressDecision], "Awaitable[None] | None"]


class EgressGuard:
    """Stateless allowlist enforcer for outbound HTTP requests."""

    def __init__(
        self,
        policy: EgressPolicy,
        *,
        audit_hook: EgressAuditHook | None = None,
    ) -> None:
        self._policy = policy
        self._audit_hook = audit_hook

    @property
    def policy(self) -> EgressPolicy:
        return self._policy

    # ── factories ────────────────────────────────────────────────────────

    @classmethod
    def from_ironclaw_specs(
        cls,
        specs: Iterable[Any],
        *,
        default_action: EgressAction = "deny",
        audit_hook: EgressAuditHook | None = None,
        allowed_schemes: tuple[str, ...] = ("https",),
        scope_to_caller: bool = False,
    ) -> "EgressGuard":
        """Build a guard from a list of ``IronClawWasmToolSpec``.

        Avoids importing the spec dataclass directly (it lives in
        ``titanx.tools`` which would be a circular import) by duck-typing
        on ``http_allowlist``: each entry is expected to expose
        ``host``, ``path_prefix``, and ``methods``. Anything else is
        silently skipped — the catalog is operator-curated.

        ``scope_to_caller=True`` mirrors NemoClaw's ``binaries:`` list:
        each rule is pinned to the spec's ``name`` so only the matching
        tool can use the egress. Default is ``False`` for backward
        compatibility — existing hosts that pass spec lists straight
        into the guard keep the broader allow surface.
        """
        rules: list[OutboundRule] = []
        for spec in specs:
            allowlist = getattr(spec, "http_allowlist", None) or ()
            spec_name = getattr(spec, "name", None)
            caller = spec_name if scope_to_caller and spec_name else None
            for entry in allowlist:
                host = getattr(entry, "host", None)
                path_prefix = getattr(entry, "path_prefix", "/")
                methods = tuple(getattr(entry, "methods", ()))
                if not host:
                    continue
                rules.append(OutboundRule(
                    host_pattern=host,
                    path_prefix=path_prefix or "/",
                    methods=methods,
                    allowed_schemes=allowed_schemes,
                    caller=caller,
                ))
        return cls(EgressPolicy(rules=rules, default_action=default_action),
                   audit_hook=audit_hook)

    # ── primary API ──────────────────────────────────────────────────────

    def check(
        self,
        host: str,
        path: str = "/",
        method: str = "GET",
        *,
        scheme: str = "https",
        port: int | None = None,
        caller: str | None = None,
    ) -> EgressDecision:
        """Synchronously decide whether a request is allowed.

        ``caller`` identifies the tool / handler making the request and
        is matched against ``OutboundRule.caller``. It is the SDK
        analogue of NemoClaw's per-binary scoping: a rule pinned to
        ``caller="github_tool"`` only fires when the call carries the
        same identity, never when generic code reaches the guard
        without one.

        Does **not** invoke the audit hook (see ``check_async``);
        synchronous callers that want auditing should pass the result
        to ``EgressGuard.audit(decision)`` themselves, or use the async
        wrappers below.
        """
        host = (host or "").strip().lower()
        path = path or "/"
        method = (method or "GET").upper()
        scheme = (scheme or "https").lower()
        # Explicit caller kwarg wins; otherwise inherit whatever the
        # runtime bound via ``caller_scope`` (typically the dispatched
        # tool's name). This is what makes
        # ``guard.enforce(url, method)`` from inside a tool handler
        # automatically match a caller-pinned rule without the author
        # having to thread the identity through.
        caller_id = _resolve_caller(caller)

        if not host:
            return EgressDecision(
                allowed=False,
                reason="missing host",
                host=host, path=path, method=method, scheme=scheme,
                caller=caller_id,
            )

        for rule in self._policy.rules:
            if not _caller_matches(caller_id, rule.caller):
                continue
            if not _scheme_matches(scheme, rule.allowed_schemes):
                continue
            if not _host_matches(host, rule.host_pattern):
                continue
            if not _path_matches(path, rule.path_prefix):
                continue
            if not _method_matches(method, rule.methods):
                continue
            if rule.allowed_ports and (port not in rule.allowed_ports):
                continue
            return EgressDecision(
                allowed=True,
                reason=(
                    f"matched rule host={rule.host_pattern} "
                    f"path={rule.path_prefix}"
                    + (f" caller={rule.caller}" if rule.caller else "")
                ),
                matched_rule=rule,
                host=host, path=path, method=method, scheme=scheme,
                caller=caller_id,
            )

        return EgressDecision(
            allowed=(self._policy.default_action == "allow"),
            reason=(
                "no matching rule (default deny)"
                if self._policy.default_action == "deny"
                else "no matching rule (default allow)"
            ),
            host=host, path=path, method=method, scheme=scheme,
            caller=caller_id,
        )

    def check_url(
        self,
        url: str,
        method: str = "GET",
        *,
        caller: str | None = None,
    ) -> EgressDecision:
        parts = urlsplit(url)
        scheme = (parts.scheme or "https").lower()
        host = (parts.hostname or "").lower()
        port = parts.port
        path = parts.path or "/"
        # Resolve once at the entry point so the contextvar lookup is
        # not repeated by ``check()`` further down. Passing the resolved
        # value through as an explicit kwarg also makes the path the
        # decision actually took observable for tests.
        caller_id = _resolve_caller(caller)
        if not host:
            return EgressDecision(
                allowed=False,
                reason=f"unparseable URL: {url!r}",
                host=host, path=path, method=method.upper(), scheme=scheme,
                caller=caller_id,
            )
        if scheme not in ("http", "https"):
            return EgressDecision(
                allowed=False,
                reason=f"refused scheme {scheme!r} (only http/https supported)",
                host=host, path=path, method=method.upper(), scheme=scheme,
                caller=caller_id,
            )
        return self.check(host, path, method, scheme=scheme, port=port, caller=caller_id)

    async def check_async(
        self,
        host: str,
        path: str = "/",
        method: str = "GET",
        *,
        scheme: str = "https",
        port: int | None = None,
        caller: str | None = None,
    ) -> EgressDecision:
        decision = self.check(
            host, path, method, scheme=scheme, port=port, caller=caller
        )
        await self._fire_audit(decision)
        return decision

    async def check_url_async(
        self,
        url: str,
        method: str = "GET",
        *,
        caller: str | None = None,
    ) -> EgressDecision:
        decision = self.check_url(url, method, caller=caller)
        await self._fire_audit(decision)
        return decision

    async def enforce(
        self,
        url: str,
        method: str = "GET",
        *,
        caller: str | None = None,
    ) -> EgressDecision:
        """Audit + raise on deny.

        Convenience wrapper for tool authors who want a one-liner. The
        guard fires the audit hook on every call (allow and deny), and
        raises ``EgressDenied`` when the decision is deny.
        """
        decision = await self.check_url_async(url, method, caller=caller)
        if not decision.allowed:
            raise EgressDenied(decision)
        return decision

    # ── audit plumbing ───────────────────────────────────────────────────

    async def _fire_audit(self, decision: EgressDecision) -> None:
        if self._audit_hook is None:
            return
        try:
            result = self._audit_hook(decision)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:  # noqa: BLE001
            # Mirror AuditLog's posture: a broken sink must never break
            # the request path. We don't permanently disable here
            # because the guard is shorter-lived than AuditLog and
            # sinks here are typically just a logger call.
            import sys
            print(
                f"[titanx.egress] WARNING: audit_hook raised: {exc!r}",
                file=sys.stderr, flush=True,
            )


# ── Helpers for AuditLog wiring ───────────────────────────────────────────

def audit_log_egress_hook(audit_log: Any, *, actor: str = "system") -> EgressAuditHook:
    """Adapter that turns an ``AuditLog`` into an ``EgressAuditHook``.

    Each decision becomes one ``AuditEntry`` with ``event="tool_decision"``
    (existing schema; the ``details`` payload differentiates egress
    decisions). The actor defaults to ``"system"`` because the guard
    is enforced by TitanX itself, not a host policy mutation.
    """
    from ..policy.types import AuditEntry  # local import avoids cycle

    async def _hook(decision: EgressDecision) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event="tool_decision",
            actor=actor,  # type: ignore[arg-type]
            reason=decision.reason,
            decision=("allow" if decision.allowed else "deny"),
            details={
                "kind": "egress",
                "host": decision.host,
                "path": decision.path,
                "method": decision.method,
                "scheme": decision.scheme,
                "caller": decision.caller,
                "matched_rule": (
                    {
                        "host_pattern": decision.matched_rule.host_pattern,
                        "path_prefix": decision.matched_rule.path_prefix,
                        "methods": list(decision.matched_rule.methods),
                        "caller": decision.matched_rule.caller,
                    }
                    if decision.matched_rule
                    else None
                ),
            },
        )
        try:
            await audit_log.append(entry)
        except Exception:
            # AuditLog has its own warn-and-swallow policy; the guard's
            # _fire_audit will catch anything that escapes, but most
            # real AuditLogs already swallow.
            raise

    return _hook


# ── Internal matchers ─────────────────────────────────────────────────────

def _host_matches(host: str, pattern: str) -> bool:
    pattern = pattern.lower()
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        # Wildcard must match at least one extra label, not the bare apex.
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    if not path.startswith(prefix):
        return False
    # When the rule prefix already ends with '/', the slash itself is
    # the boundary so "/v1/" matches "/v1/items" without needing a
    # second separator after the prefix.
    if prefix.endswith("/"):
        return True
    # Otherwise avoid the classic "/foo" prefix-matching "/foobar":
    # require the next char to be a separator or end-of-string.
    if len(path) == len(prefix):
        return True
    return path[len(prefix):][:1] in ("/", "?", "#")


def _method_matches(method: str, allowed: tuple[str, ...]) -> bool:
    if not allowed:
        return True
    return method in {m.upper() for m in allowed}


def _scheme_matches(scheme: str, allowed: tuple[str, ...]) -> bool:
    if not allowed:
        return True
    return scheme in {s.lower() for s in allowed}


def _caller_matches(caller: str | None, rule_caller: str | None) -> bool:
    """Decide whether a rule's caller pin matches the request's caller.

    - rule_caller is None → rule is generic, applies to every caller.
    - rule_caller is set, caller is None → fail closed: a generic
      caller must not inherit egress that a specific tool is supposed
      to own. This mirrors NemoClaw, where a network policy with a
      ``binaries:`` list is unreachable to processes not in the list.
    - both set → exact, case-sensitive match.
    """
    if rule_caller is None:
        return True
    if caller is None:
        return False
    return caller == rule_caller


__all__ = [
    "EgressAction",
    "EgressAuditHook",
    "EgressDecision",
    "EgressDenied",
    "EgressGuard",
    "EgressPolicy",
    "OutboundRule",
    "audit_log_egress_hook",
    "caller_scope",
    "current_caller",
]


# Suppress the unused-import warning for asyncio: imported for callers
# that want to construct ``asyncio.Lock`` etc. when wrapping the guard.
_ = asyncio
