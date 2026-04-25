"""Programmatic security posture audit for TitanX configurations.

Why this module exists
======================

TitanX has a layered defense (Safety → Policy → Sandbox → Audit), but
each layer's defaults are tuned for *development convenience*: the
gateway accepts ``allowed_origins=["*"]`` without an API key, the audit
log can be ``None``, the policy can have an empty
``allowed_write_paths`` list. Operators routinely ship those defaults
to production and only find out when something breaks.

``titanx.audit`` is the diagnostic surface that catches that drift. It
is **read-only** by default; ``apply_fixes`` is opt-in and is the only
function that changes anything on disk. The same checks are exposed
via the ``titanx audit`` CLI (see ``titanx/cli.py``) so operators can
run them without writing Python.

Severity model
==============

- ``critical`` — a misconfiguration we believe will cause a security
  failure under realistic adversarial pressure (e.g. gateway with no
  API key, world-writable audit log, allowlist permitting ``/etc``).
- ``warn``     — a foot-gun that is acceptable in dev but dangerous in
  prod (e.g. ``auto_approve_tools=True``, CORS wildcard, missing
  egress allowlist).
- ``info``     — observation, no action required (e.g. retry budget
  unset, secondary sink not configured).
- ``ok``       — explicit positive — the check ran and the value is
  good. Returned so the audit output can prove coverage rather than
  just enumerate failures.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from .policy.types import AgentPolicy
from .policy.validation import PolicyValidationError, validate_policy
from .gateway.types import GatewayOptions
from .safety.egress import EgressPolicy

Severity = Literal["critical", "warn", "info", "ok"]


@dataclass(frozen=True)
class AuditFinding:
    check_id: str
    severity: Severity
    title: str
    detail: str
    fix_hint: str | None = None
    auto_fixable: bool = False
    # Path that ``apply_fixes`` will operate on for permission/perm-fix
    # findings. Other findings leave this as None.
    fix_target: str | None = None


@dataclass
class AuditReport:
    findings: list[AuditFinding] = field(default_factory=list)

    def add(self, finding: AuditFinding) -> None:
        self.findings.append(finding)

    def merge(self, other: "AuditReport") -> None:
        self.findings.extend(other.findings)

    def summary(self) -> dict[str, int]:
        out = {"critical": 0, "warn": 0, "info": 0, "ok": 0}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def to_json(self) -> str:
        return json.dumps(
            {
                "findings": [asdict(f) for f in self.findings],
                "summary": self.summary(),
            },
            ensure_ascii=False,
            indent=2,
        )

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    @property
    def has_warn(self) -> bool:
        return any(f.severity == "warn" for f in self.findings)


# ── Policy checks ─────────────────────────────────────────────────────────

def audit_policy(policy: AgentPolicy) -> AuditReport:
    """Static audit of an ``AgentPolicy`` instance.

    Wraps ``validate_policy`` so a policy that would be *rejected* at
    install time is reported as ``critical`` here too. The remaining
    checks flag soft-but-risky configurations (auto-approval, empty
    write paths, etc.).
    """
    report = AuditReport()

    # Hard validation first — these would raise inside PolicyStore.set.
    try:
        validate_policy(policy)
        report.add(AuditFinding(
            check_id="policy.validate_policy",
            severity="ok",
            title="policy passes validate_policy()",
            detail=(
                "No privileged paths, all entries normalised, "
                "max_iterations within ceiling."
            ),
        ))
    except PolicyValidationError as exc:
        report.add(AuditFinding(
            check_id="policy.validate_policy",
            severity="critical",
            title="policy rejected by validate_policy()",
            detail=str(exc),
            fix_hint="Remove the offending allowed_write_paths entry "
                     "or fix the type/range error.",
        ))
        return report  # downstream checks assume basic shape

    # Empty allowlist — tools that try to write will fail with EROFS,
    # which is loud but the operator may not have intended it.
    if not policy.allowed_write_paths:
        report.add(AuditFinding(
            check_id="policy.allowed_write_paths.empty",
            severity="warn",
            title="allowed_write_paths is empty",
            detail=(
                "No tool can write anywhere on the host. This is the "
                "most restrictive setting and may be intentional; "
                "otherwise add at least the workspace dir."
            ),
            fix_hint='Set allowed_write_paths=["/var/lib/titanx/work"] '
                     "or your tenant workspace.",
        ))
    else:
        report.add(AuditFinding(
            check_id="policy.allowed_write_paths.set",
            severity="ok",
            title=f"allowed_write_paths has {len(policy.allowed_write_paths)} entries",
            detail=", ".join(policy.allowed_write_paths),
        ))

    # auto_approve_tools is the single biggest foot-gun.
    if policy.auto_approve_tools:
        report.add(AuditFinding(
            check_id="policy.auto_approve_tools.enabled",
            severity="warn",
            title="auto_approve_tools=True bypasses the approval gate",
            detail=(
                "Every tool decision becomes 'allow' regardless of "
                "ToolDefinition.requires_approval. Acceptable in CI/dev; "
                "in production this turns the LLM into a fully autonomous "
                "operator."
            ),
            fix_hint=(
                "Set auto_approve_tools=False and rely on per-tool "
                "requires_approval, or use BreakGlassController for "
                "time-bounded relaxations instead of a permanent flag."
            ),
        ))
    else:
        report.add(AuditFinding(
            check_id="policy.auto_approve_tools.disabled",
            severity="ok",
            title="auto_approve_tools=False",
            detail="Tool decisions go through the approval gate.",
        ))

    # tool_denylist — empty is fine but worth noting.
    if not policy.tool_denylist:
        report.add(AuditFinding(
            check_id="policy.tool_denylist.empty",
            severity="info",
            title="tool_denylist is empty",
            detail="No tool is unconditionally denied. Consider adding "
                   "any tool you never want the agent to invoke.",
        ))
    else:
        report.add(AuditFinding(
            check_id="policy.tool_denylist.set",
            severity="ok",
            title=f"tool_denylist has {len(policy.tool_denylist)} entries",
            detail=", ".join(policy.tool_denylist),
        ))

    # max_iterations — flag suspiciously high values even if validation passes.
    if policy.max_iterations >= 1000:
        report.add(AuditFinding(
            check_id="policy.max_iterations.high",
            severity="warn",
            title=f"max_iterations={policy.max_iterations} is very high",
            detail=(
                "This caps the agent loop per user prompt. Values in "
                "the thousands risk runaway costs if an LLM gets stuck "
                "in a tool-call loop."
            ),
            fix_hint="Most workflows fit in <50 iterations.",
        ))
    return report


# ── Gateway checks ────────────────────────────────────────────────────────

def audit_gateway_options(opts: GatewayOptions) -> AuditReport:
    report = AuditReport()

    if not opts.api_key:
        report.add(AuditFinding(
            check_id="gateway.api_key.unset",
            severity="critical",
            title="gateway.api_key is None — endpoint is unauthenticated",
            detail=(
                "Anyone who can reach the gateway can issue prompts, "
                "approve tool calls, and read history. The HTTP "
                "middleware logs a startup warning but does not refuse "
                "to start."
            ),
            fix_hint="Set GatewayOptions(api_key=...) and require "
                     "x-api-key on every /api/* request.",
        ))
    else:
        report.add(AuditFinding(
            check_id="gateway.api_key.set",
            severity="ok",
            title="gateway.api_key is configured",
            detail="Constant-time comparison via hmac.compare_digest "
                   "is used in both HTTP and WebSocket handshake paths.",
        ))

    if "*" in opts.allowed_origins:
        report.add(AuditFinding(
            check_id="gateway.cors.wildcard",
            severity="warn",
            title='allowed_origins contains "*"',
            detail=(
                "CORS wildcard combined with custom-header auth lets "
                "any third-party site probe the gateway from a "
                "victim's browser. Acceptable in development."
            ),
            fix_hint='Replace ["*"] with the explicit origin list, '
                     'e.g. ["https://app.example"].',
        ))
    else:
        report.add(AuditFinding(
            check_id="gateway.cors.explicit",
            severity="ok",
            title=f"CORS allowlist has {len(opts.allowed_origins)} origins",
            detail=", ".join(opts.allowed_origins),
        ))

    if opts.max_sessions <= 0:
        report.add(AuditFinding(
            check_id="gateway.max_sessions.invalid",
            severity="critical",
            title=f"max_sessions={opts.max_sessions} disables LRU eviction",
            detail="Session map can grow without bound; an "
                   "unauthenticated WS client could OOM the host.",
        ))
    elif opts.max_sessions > 10_000:
        report.add(AuditFinding(
            check_id="gateway.max_sessions.high",
            severity="warn",
            title=f"max_sessions={opts.max_sessions} is very high",
            detail="The default of 1000 is sufficient for most "
                   "deployments. Higher values may indicate a "
                   "missing tenant boundary.",
        ))
    else:
        report.add(AuditFinding(
            check_id="gateway.max_sessions.ok",
            severity="ok",
            title=f"max_sessions={opts.max_sessions}",
            detail="LRU cap on the in-memory session map.",
        ))

    if opts.session_idle_ttl_seconds <= 0:
        report.add(AuditFinding(
            check_id="gateway.session_idle_ttl.disabled",
            severity="warn",
            title="session_idle_ttl_seconds<=0 disables idle eviction",
            detail="Idle sessions persist until LRU eviction. Set a "
                   "positive value (default 3600) to reap quickly.",
        ))

    return report


# ── Audit-log file checks ─────────────────────────────────────────────────

def audit_audit_log_path(log_path: str | None) -> AuditReport:
    report = AuditReport()

    if not log_path:
        report.add(AuditFinding(
            check_id="audit_log.unconfigured",
            severity="warn",
            title="AuditLog has no log_path — events are in-memory only",
            detail=(
                "Without persistent audit, a forensic investigation "
                "after a tool misbehaviour has no record. Recommended "
                "for production: configure a JSONL path on a "
                "monitored volume."
            ),
            fix_hint='AuditLog("/var/log/titanx/audit.jsonl", '
                     'fsync_policy="interval")',
        ))
        return report

    p = Path(log_path)
    if not p.exists():
        report.add(AuditFinding(
            check_id="audit_log.missing",
            severity="info",
            title=f"audit log file {log_path!r} does not exist yet",
            detail="It will be created on first append. Make sure the "
                   "parent directory has correct permissions.",
        ))
        # Fall through to parent-dir checks.
        parent = p.parent
        _check_dir_perms(parent, report, role="audit-log parent")
        return report

    try:
        st = p.stat()
    except OSError as exc:
        report.add(AuditFinding(
            check_id="audit_log.stat_failed",
            severity="critical",
            title=f"cannot stat audit log {log_path!r}: {exc}",
            detail="Audit log is unreadable; investigation may be "
                   "blocked.",
        ))
        return report

    mode = stat.S_IMODE(st.st_mode)
    # World/group write on the audit log is bad: any other process or
    # user on the box can forge entries. World read leaks operator
    # secrets that may be in the ``details`` payload.
    if mode & stat.S_IWOTH:
        report.add(AuditFinding(
            check_id="audit_log.world_writable",
            severity="critical",
            title=f"audit log {log_path!r} is world-writable (mode={oct(mode)})",
            detail="Any local user can forge audit entries. This "
                   "destroys the forensic value of the log.",
            fix_hint="chmod 0600 (single-operator) or 0640 with a "
                     "trusted group.",
            auto_fixable=True,
            fix_target=str(p),
        ))
    elif mode & stat.S_IWGRP:
        report.add(AuditFinding(
            check_id="audit_log.group_writable",
            severity="warn",
            title=f"audit log {log_path!r} is group-writable (mode={oct(mode)})",
            detail="Any member of the file's group can forge audit "
                   "entries. Verify group membership matches your "
                   "operator/forensics team.",
            auto_fixable=True,
            fix_target=str(p),
        ))

    if mode & stat.S_IROTH:
        report.add(AuditFinding(
            check_id="audit_log.world_readable",
            severity="warn",
            title=f"audit log {log_path!r} is world-readable (mode={oct(mode)})",
            detail="Audit entries can include user prompts and tool "
                   "arguments. Restrict to operator/forensics only.",
            auto_fixable=True,
            fix_target=str(p),
        ))

    if not (mode & stat.S_IWOTH or mode & stat.S_IWGRP or mode & stat.S_IROTH):
        report.add(AuditFinding(
            check_id="audit_log.perms_ok",
            severity="ok",
            title=f"audit log {log_path!r} permissions",
            detail=f"mode={oct(mode)} — restricted to owner.",
        ))

    _check_dir_perms(p.parent, report, role="audit-log parent")
    return report


def _check_dir_perms(path: Path, report: AuditReport, *, role: str) -> None:
    if not path.exists():
        report.add(AuditFinding(
            check_id="audit_log.parent_missing",
            severity="warn",
            title=f"{role} {str(path)!r} does not exist",
            detail="AuditLog will create it lazily, but verify the "
                   "umask of the creating process.",
        ))
        return
    try:
        st = path.stat()
    except OSError:
        return
    mode = stat.S_IMODE(st.st_mode)
    if mode & stat.S_IWOTH:
        report.add(AuditFinding(
            check_id="audit_log.parent_world_writable",
            severity="critical",
            title=f"{role} {str(path)!r} is world-writable (mode={oct(mode)})",
            detail="Any user can rotate, replace, or delete audit "
                   "files in this directory.",
            fix_hint="chmod 0700 or 0750 on the parent directory.",
            auto_fixable=True,
            fix_target=str(path),
        ))


# ── Egress-policy checks ──────────────────────────────────────────────────

def audit_egress_policy(policy: EgressPolicy | None) -> AuditReport:
    report = AuditReport()
    if policy is None:
        report.add(AuditFinding(
            check_id="egress.unconfigured",
            severity="warn",
            title="No EgressGuard wired — outbound HTTP from tools is unrestricted",
            detail=(
                "IronClawWasmToolSpec.http_allowlist is metadata only "
                "until you build an EgressGuard from it. Tools that "
                "bypass the host's HTTP client and call the network "
                "directly will not be filtered."
            ),
            fix_hint=(
                "EgressGuard.from_ironclaw_specs("
                "IRONCLAW_WASM_TOOLS, audit_hook=...)"
            ),
        ))
        return report

    if policy.default_action == "allow":
        report.add(AuditFinding(
            check_id="egress.default_allow",
            severity="critical",
            title="EgressPolicy.default_action='allow' — guard is advisory only",
            detail="Any host not explicitly denied is reachable. The "
                   "expected posture is default-deny with explicit "
                   "allow rules.",
            fix_hint="Set default_action='deny' and add OutboundRules "
                     "for the destinations you actually need.",
        ))
    else:
        report.add(AuditFinding(
            check_id="egress.default_deny",
            severity="ok",
            title="EgressPolicy is default-deny",
            detail=f"{len(policy.rules)} explicit rules.",
        ))

    if not policy.rules:
        report.add(AuditFinding(
            check_id="egress.no_rules",
            severity="info",
            title="EgressPolicy has zero rules",
            detail="Every outbound request will be denied. Acceptable "
                   "for tools that don't need network access.",
        ))

    for i, rule in enumerate(policy.rules):
        if "http" in rule.allowed_schemes and "https" not in rule.allowed_schemes:
            report.add(AuditFinding(
                check_id=f"egress.rule_{i}.http_only",
                severity="warn",
                title=f"rule '{rule.host_pattern}' allows http but not https",
                detail="Likely a typo. Plaintext outbound is rarely "
                       "intentional in 2026.",
            ))
        if "http" in rule.allowed_schemes and "https" in rule.allowed_schemes:
            report.add(AuditFinding(
                check_id=f"egress.rule_{i}.allows_plaintext",
                severity="warn",
                title=f"rule '{rule.host_pattern}' allows plaintext http",
                detail="Combined http+https permits TLS-stripping "
                       "downgrade. Restrict to https unless the "
                       "destination genuinely requires http.",
            ))

    return report


# ── Composite ────────────────────────────────────────────────────────────

def audit_runtime(
    *,
    policy: AgentPolicy | None = None,
    gateway: GatewayOptions | None = None,
    audit_log_path: str | None = None,
    egress: EgressPolicy | None = None,
) -> AuditReport:
    """Run every check that was supplied non-None inputs.

    Each input is independent — pass only what you have, the rest are
    skipped. This is the function the CLI calls.
    """
    report = AuditReport()
    if policy is not None:
        report.merge(audit_policy(policy))
    if gateway is not None:
        report.merge(audit_gateway_options(gateway))
    # audit_audit_log_path handles None internally (warns) so we always
    # call it; the CLI can suppress with --skip-audit-log if needed.
    report.merge(audit_audit_log_path(audit_log_path))
    if egress is not None:
        report.merge(audit_egress_policy(egress))
    return report


def apply_fixes(report: AuditReport, *, dry_run: bool = False) -> list[str]:
    """Apply auto-fixable findings.

    Returns a list of human-readable lines describing what was (or
    would be) changed. The function is deliberately conservative —
    only file-permission findings are auto-fixable. Anything that
    would silently rewrite an ``AgentPolicy`` or an Egress allowlist
    is left to the operator.
    """
    actions: list[str] = []
    for f in report.findings:
        if not f.auto_fixable or f.fix_target is None:
            continue
        target = Path(f.fix_target)
        if not target.exists():
            actions.append(f"skip {f.check_id}: {target} no longer exists")
            continue
        try:
            current_mode = stat.S_IMODE(target.stat().st_mode)
        except OSError as exc:
            actions.append(f"skip {f.check_id}: stat failed: {exc}")
            continue

        if target.is_dir():
            new_mode = 0o700
        else:
            new_mode = 0o600

        if current_mode == new_mode:
            actions.append(f"skip {f.check_id}: already {oct(new_mode)}")
            continue

        action = (
            f"chmod {oct(new_mode)} {target} (was {oct(current_mode)})"
        )
        if dry_run:
            actions.append(f"would {action}")
            continue
        try:
            os.chmod(target, new_mode)
            actions.append(f"applied: {action}")
        except OSError as exc:
            actions.append(f"failed {action}: {exc}")
    return actions


# ── JSON loaders for the CLI ──────────────────────────────────────────────

def load_policy_from_json(data: dict[str, Any]) -> AgentPolicy:
    return AgentPolicy(
        allowed_write_paths=list(data.get("allowed_write_paths", [])),
        auto_approve_tools=bool(data.get("auto_approve_tools", False)),
        max_iterations=int(data.get("max_iterations", 10)),
        tool_denylist=list(data.get("tool_denylist", [])),
    )


def load_gateway_options_from_json(data: dict[str, Any]) -> GatewayOptions:
    # Construct without create_runtime — auditing only inspects flags.
    opts = GatewayOptions(
        port=int(data.get("port", 3000)),
        api_key=data.get("api_key"),
        storage=None,
        retriever=None,
        create_runtime=None,  # type: ignore[arg-type]
        allowed_origins=list(data.get("allowed_origins", ["*"])),
        allowed_methods=list(data.get("allowed_methods", ["GET", "POST"])),
        allowed_headers=list(
            data.get("allowed_headers", ["x-api-key", "content-type"])
        ),
        max_sessions=int(data.get("max_sessions", 1000)),
        session_idle_ttl_seconds=float(data.get("session_idle_ttl_seconds", 3600.0)),
    )
    return opts


__all__ = [
    "AuditFinding",
    "AuditReport",
    "Severity",
    "apply_fixes",
    "audit_audit_log_path",
    "audit_egress_policy",
    "audit_gateway_options",
    "audit_policy",
    "audit_runtime",
    "load_gateway_options_from_json",
    "load_policy_from_json",
]
