"""Per-tool ``OutboundRule.caller`` semantics.

Verifies the NemoClaw ``binaries:`` analogue: a rule pinned to a
caller is unreachable from any other caller (or from generic code that
forgets to identify itself), and unconstrained rules still apply to
everyone.
"""

from __future__ import annotations

import pytest

from titanx.safety.egress import (
    EgressDenied,
    EgressGuard,
    EgressPolicy,
    OutboundRule,
)


def _guard(*rules: OutboundRule, default: str = "deny") -> EgressGuard:
    return EgressGuard(EgressPolicy(rules=list(rules), default_action=default))  # type: ignore[arg-type]


class TestCallerScopedRule:
    def test_rule_pinned_to_caller_matches_that_caller(self):
        guard = _guard(OutboundRule(
            host_pattern="api.github.com",
            path_prefix="/repos/",
            caller="github_tool",
        ))
        decision = guard.check_url(
            "https://api.github.com/repos/foo/bar",
            caller="github_tool",
        )
        assert decision.allowed
        assert decision.matched_rule is not None
        assert decision.matched_rule.caller == "github_tool"
        assert decision.caller == "github_tool"

    def test_rule_pinned_to_caller_rejects_other_caller(self):
        # The host/path/method are otherwise allowable. Only the caller
        # mismatch should prevent the match. Default-deny means the
        # request is denied because no other rule applies.
        guard = _guard(OutboundRule(
            host_pattern="api.github.com",
            path_prefix="/repos/",
            caller="github_tool",
        ))
        decision = guard.check_url(
            "https://api.github.com/repos/foo/bar",
            caller="slack_tool",
        )
        assert not decision.allowed
        assert "default deny" in decision.reason

    def test_rule_pinned_to_caller_rejects_unidentified_caller(self):
        # Fail-closed: omitting the caller must NOT inherit a
        # privileged egress rule.
        guard = _guard(OutboundRule(
            host_pattern="api.github.com",
            path_prefix="/repos/",
            caller="github_tool",
        ))
        decision = guard.check_url("https://api.github.com/repos/foo/bar")
        assert not decision.allowed

    def test_unscoped_rule_matches_every_caller(self):
        # Backwards compatibility: existing rules without caller pins
        # keep applying to every caller.
        guard = _guard(OutboundRule(
            host_pattern="api.example.com",
            path_prefix="/",
        ))
        for caller in (None, "anything", "another"):
            decision = guard.check_url(
                "https://api.example.com/v1", caller=caller
            )
            assert decision.allowed, f"caller={caller}"

    def test_two_callers_two_rules_no_cross_pollination(self):
        # Per-tool egress in practice: each integration registers its
        # own rule. Cross-tool calls must fall through to default-deny.
        guard = _guard(
            OutboundRule(host_pattern="slack.com", path_prefix="/api/",
                         caller="slack"),
            OutboundRule(host_pattern="api.github.com", path_prefix="/",
                         caller="github"),
        )

        # slack -> slack: ok
        assert guard.check_url(
            "https://slack.com/api/chat.postMessage", caller="slack",
        ).allowed
        # slack -> github: deny (no rule for caller=slack on github host)
        assert not guard.check_url(
            "https://api.github.com/user", caller="slack",
        ).allowed
        # github -> slack: deny
        assert not guard.check_url(
            "https://slack.com/api/chat.postMessage", caller="github",
        ).allowed

    def test_caller_match_is_case_sensitive(self):
        # Tool names are identifiers, not hostnames; we keep matching
        # exact so different runtime IDs ("github_v1" vs "GitHub_v1")
        # don't accidentally collide.
        guard = _guard(OutboundRule(
            host_pattern="api.example.com", caller="my_tool",
        ))
        assert guard.check_url(
            "https://api.example.com", caller="my_tool",
        ).allowed
        assert not guard.check_url(
            "https://api.example.com", caller="My_Tool",
        ).allowed


class TestEnforce:
    async def test_enforce_passes_caller_through(self):
        guard = _guard(OutboundRule(
            host_pattern="api.example.com", caller="alice",
        ))
        decision = await guard.enforce(
            "https://api.example.com/v1", caller="alice",
        )
        assert decision.allowed
        assert decision.caller == "alice"

    async def test_enforce_raises_on_caller_mismatch(self):
        guard = _guard(OutboundRule(
            host_pattern="api.example.com", caller="alice",
        ))
        with pytest.raises(EgressDenied) as excinfo:
            await guard.enforce(
                "https://api.example.com/v1", caller="bob",
            )
        assert excinfo.value.decision.caller == "bob"


class TestOutboundRuleValidation:
    def test_caller_must_be_non_empty_when_set(self):
        with pytest.raises(ValueError, match="caller"):
            OutboundRule(host_pattern="api.example.com", caller="")

    def test_caller_none_is_allowed(self):
        # Default; should not raise.
        OutboundRule(host_pattern="api.example.com")


class TestFromIronclawScopeToCaller:
    def test_scope_to_caller_pins_each_rule(self):
        # Mock spec shape — duck-typed in production.
        class _AllowEntry:
            def __init__(self, host: str, path: str = "/"):
                self.host = host
                self.path_prefix = path
                self.methods = ()

        class _Spec:
            def __init__(self, name: str, entries):
                self.name = name
                self.http_allowlist = entries

        specs = [
            _Spec("github_tool", [_AllowEntry("api.github.com", "/")]),
            _Spec("slack_tool", [_AllowEntry("slack.com", "/api/")]),
        ]

        guard = EgressGuard.from_ironclaw_specs(specs, scope_to_caller=True)
        # Each rule should be bound to its tool name.
        rules_by_caller = {r.caller: r for r in guard.policy.rules}
        assert set(rules_by_caller) == {"github_tool", "slack_tool"}
        assert rules_by_caller["github_tool"].host_pattern == "api.github.com"

        # And cross-tool calls must fail.
        decision = guard.check_url(
            "https://slack.com/api/chat", caller="github_tool",
        )
        assert not decision.allowed

    def test_scope_to_caller_default_off_keeps_legacy_behavior(self):
        # The legacy hosts that just feed spec lists in must keep the
        # broader allow surface (caller=None on every generated rule).
        class _AllowEntry:
            def __init__(self, host: str, path: str = "/"):
                self.host = host
                self.path_prefix = path
                self.methods = ()

        class _Spec:
            def __init__(self, name: str, entries):
                self.name = name
                self.http_allowlist = entries

        specs = [_Spec("github_tool", [_AllowEntry("api.github.com")])]
        guard = EgressGuard.from_ironclaw_specs(specs)  # scope_to_caller=False
        for rule in guard.policy.rules:
            assert rule.caller is None
