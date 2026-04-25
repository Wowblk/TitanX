"""EgressGuard: outbound HTTP allowlist enforcement.

Covers the gap between IronClaw's declarative ``http_allowlist``
metadata and runtime enforcement:

- exact + wildcard host matching (and the apex-not-included rule).
- path-prefix matching with no false positives on prefix-truncation.
- method and scheme filtering, default-deny posture.
- the ``EgressDenied`` raise path from ``enforce``.
- audit hooks fire on every decision, sync and async sinks both work.
- ``from_ironclaw_specs`` produces a working policy from the catalog.
"""

from __future__ import annotations

import asyncio

import pytest

from titanx.safety.egress import (
    EgressDecision,
    EgressDenied,
    EgressGuard,
    EgressPolicy,
    OutboundRule,
)
from titanx.tools import IRONCLAW_WASM_TOOLS


def _guard(*rules: OutboundRule, default: str = "deny") -> EgressGuard:
    return EgressGuard(EgressPolicy(rules=list(rules), default_action=default))


class TestRuleValidation:
    def test_path_prefix_must_be_absolute(self):
        with pytest.raises(ValueError, match="path_prefix"):
            OutboundRule(host_pattern="example.com", path_prefix="api/v1")

    def test_wildcard_must_be_leading_dot(self):
        with pytest.raises(ValueError, match="wildcard"):
            OutboundRule(host_pattern="ex*ple.com")

    def test_empty_host_rejected(self):
        with pytest.raises(ValueError, match="host_pattern"):
            OutboundRule(host_pattern="")


class TestHostMatching:
    def test_exact_host(self):
        g = _guard(OutboundRule("api.github.com"))
        assert g.check("api.github.com").allowed
        assert not g.check("api.github.com.evil.com").allowed

    def test_wildcard_subdomain_matches_one_label(self):
        g = _guard(OutboundRule("*.example.com"))
        assert g.check("foo.example.com").allowed
        assert g.check("a.b.example.com").allowed

    def test_wildcard_does_not_match_apex(self):
        g = _guard(OutboundRule("*.example.com"))
        # Apex must be allowlisted explicitly per the docs.
        assert not g.check("example.com").allowed

    def test_host_match_is_case_insensitive(self):
        g = _guard(OutboundRule("API.example.com"))
        assert g.check("api.example.com").allowed
        assert g.check("API.EXAMPLE.COM").allowed


class TestPathMatching:
    def test_root_prefix_matches_anything(self):
        g = _guard(OutboundRule("api.github.com", "/"))
        assert g.check("api.github.com", "/anything/at/all").allowed

    def test_prefix_does_not_truncate(self):
        # /foo must not match /foobar.
        g = _guard(OutboundRule("api.example.com", "/foo"))
        assert g.check("api.example.com", "/foo").allowed
        assert g.check("api.example.com", "/foo/").allowed
        assert g.check("api.example.com", "/foo/bar").allowed
        assert not g.check("api.example.com", "/foobar").allowed

    def test_prefix_with_trailing_slash(self):
        g = _guard(OutboundRule("api.example.com", "/v1/"))
        assert g.check("api.example.com", "/v1/items").allowed
        assert not g.check("api.example.com", "/v2/items").allowed


class TestMethodAndScheme:
    def test_default_methods_allow_any(self):
        g = _guard(OutboundRule("api.example.com"))
        assert g.check("api.example.com", "/", "DELETE").allowed

    def test_method_restriction(self):
        g = _guard(OutboundRule("api.example.com", methods=("GET", "POST")))
        assert g.check("api.example.com", "/", "GET").allowed
        assert g.check("api.example.com", "/", "POST").allowed
        assert not g.check("api.example.com", "/", "DELETE").allowed

    def test_default_scheme_is_https_only(self):
        g = _guard(OutboundRule("api.example.com"))
        assert g.check("api.example.com", scheme="https").allowed
        assert not g.check("api.example.com", scheme="http").allowed

    def test_explicit_http_opt_in(self):
        g = _guard(OutboundRule("api.example.com", allowed_schemes=("http", "https")))
        assert g.check("api.example.com", scheme="http").allowed

    def test_check_url_refuses_non_http(self):
        g = _guard(OutboundRule("api.example.com"))
        # ftp parses with a host, so we hit the scheme branch (not the
        # "unparseable URL" branch). file:// would be earlier-rejected
        # for missing host, which is also fine but tests a different
        # branch.
        decision = g.check_url("ftp://api.example.com/path")
        assert not decision.allowed
        assert "scheme" in decision.reason


class TestDefaultPosture:
    def test_default_deny(self):
        g = _guard()
        d = g.check("anything.com")
        assert not d.allowed
        assert "default deny" in d.reason

    def test_default_allow_is_advisory_only(self):
        g = _guard(default="allow")
        assert g.check("anything.com").allowed


class TestAuditHook:
    @pytest.mark.asyncio
    async def test_async_hook_fires_on_each_check(self):
        seen: list[EgressDecision] = []

        async def hook(d: EgressDecision) -> None:
            seen.append(d)

        guard = EgressGuard(
            EgressPolicy(rules=[OutboundRule("api.example.com")], default_action="deny"),
            audit_hook=hook,
        )

        await guard.check_url_async("https://api.example.com/v1/items")
        await guard.check_url_async("https://evil.com/")
        assert len(seen) == 2
        assert seen[0].allowed is True
        assert seen[1].allowed is False

    @pytest.mark.asyncio
    async def test_sync_hook_supported(self):
        seen: list[EgressDecision] = []

        def hook(d: EgressDecision) -> None:
            seen.append(d)

        guard = EgressGuard(
            EgressPolicy(rules=[OutboundRule("api.example.com")]),
            audit_hook=hook,
        )
        await guard.check_url_async("https://api.example.com/")
        assert len(seen) == 1

    @pytest.mark.asyncio
    async def test_hook_failure_does_not_break_request_path(self, capsys):
        def hook(d: EgressDecision) -> None:
            raise RuntimeError("sink down")

        guard = EgressGuard(
            EgressPolicy(rules=[OutboundRule("api.example.com")]),
            audit_hook=hook,
        )
        decision = await guard.check_url_async("https://api.example.com/")
        assert decision.allowed
        # Warning printed to stderr; capsys intercepts via fd capture.
        captured = capsys.readouterr()
        assert "audit_hook raised" in captured.err


class TestEnforce:
    @pytest.mark.asyncio
    async def test_enforce_raises_on_deny(self):
        guard = _guard(OutboundRule("api.example.com"))
        with pytest.raises(EgressDenied):
            await guard.enforce("https://evil.com/")

    @pytest.mark.asyncio
    async def test_enforce_returns_decision_on_allow(self):
        guard = _guard(OutboundRule("api.example.com"))
        decision = await guard.enforce("https://api.example.com/v1")
        assert decision.allowed
        assert decision.matched_rule is not None


class TestIronClawAdapter:
    def test_from_specs_produces_real_rules(self):
        guard = EgressGuard.from_ironclaw_specs(IRONCLAW_WASM_TOOLS)
        assert len(guard.policy.rules) > 0

    def test_specs_default_deny(self):
        guard = EgressGuard.from_ironclaw_specs(IRONCLAW_WASM_TOOLS)
        assert not guard.check_url("https://example.com/").allowed

    def test_github_api_allowed(self):
        guard = EgressGuard.from_ironclaw_specs(IRONCLAW_WASM_TOOLS)
        d = guard.check_url("https://api.github.com/repos/foo/bar", "GET")
        assert d.allowed

    def test_github_method_filter(self):
        guard = EgressGuard.from_ironclaw_specs(IRONCLAW_WASM_TOOLS)
        d = guard.check_url("https://api.github.com/repos/foo/bar", "PATCH")
        # IronClaw github spec is GET/POST/PUT/DELETE; PATCH should miss.
        assert not d.allowed

    def test_brave_search_path_pinned(self):
        guard = EgressGuard.from_ironclaw_specs(IRONCLAW_WASM_TOOLS)
        # web_search is pinned to /res/v1/web/search; sibling paths are denied.
        ok = guard.check_url("https://api.search.brave.com/res/v1/web/search?q=x")
        bad = guard.check_url("https://api.search.brave.com/internal")
        assert ok.allowed
        assert not bad.allowed


class TestAuditLogHook:
    @pytest.mark.asyncio
    async def test_audit_log_hook_appends_entry(self):
        from titanx.policy import AuditLog
        from titanx.safety.egress import audit_log_egress_hook

        log = AuditLog()  # in-memory only
        hook = audit_log_egress_hook(log)
        guard = EgressGuard(
            EgressPolicy(rules=[OutboundRule("api.example.com")]),
            audit_hook=hook,
        )
        await guard.check_url_async("https://evil.com/")
        entries = log.get_entries()
        assert len(entries) == 1
        e = entries[0]
        assert e.event == "tool_decision"
        assert e.decision == "deny"
        assert e.details["kind"] == "egress"
        assert e.details["host"] == "evil.com"
