"""Bundled egress presets — registry, composition, and shape.

These tests exercise the contract callers depend on:

- every bundled preset registers itself on import,
- ``compose`` produces a default-deny policy,
- preset rules are pinned to a stable ``caller`` value,
- ``compose`` is idempotent and order-stable across calls,
- unknown names fail loudly.
"""

from __future__ import annotations

import pytest

from titanx.safety import egress, presets


BUNDLED = {
    "brave_search",
    "composio",
    "discord",
    "github",
    "google",
    "huggingface",
    "npm_registry",
    "pypi",
    "slack",
    "telegram",
}


class TestRegistry:
    def test_all_bundled_presets_are_registered(self):
        # ``available()`` reflects the live registry; the bundled
        # set must be a subset (apps may register their own presets
        # downstream).
        registered = set(presets.available())
        missing = BUNDLED - registered
        assert not missing, f"missing presets: {missing}"

    def test_unknown_preset_raises_with_helpful_message(self):
        with pytest.raises(KeyError, match="unknown egress preset"):
            presets.get("definitely-not-a-preset")

    def test_register_rejects_duplicates(self):
        # The registry refuses double-registration so a downstream
        # plugin that fights with a bundled preset crashes loudly at
        # import.
        with pytest.raises(ValueError, match="already registered"):
            presets.register("github", lambda: egress.EgressPolicy(rules=[]))


class TestPresetShape:
    @pytest.mark.parametrize("name", sorted(BUNDLED))
    def test_each_preset_is_default_deny(self, name: str):
        policy = presets.get(name)
        assert policy.default_action == "deny"
        assert policy.rules, f"{name}: empty rule list"

    @pytest.mark.parametrize(
        "name,expected_caller",
        [
            ("github", "github"),
            ("slack", "slack"),
            ("discord", "discord"),
            ("composio", "composio"),
            ("huggingface", "huggingface"),
            ("npm_registry", "npm_registry"),
            ("pypi", "pypi"),
            ("brave_search", "web_search"),
            ("telegram", "telegram_mtproto"),
        ],
    )
    def test_caller_pinning(self, name: str, expected_caller: str):
        # The IronClaw spec name is the contract — callers pass it
        # into ``EgressGuard.enforce(..., caller=NAME)`` and expect a
        # match. At least one rule must use the canonical caller.
        policy = presets.get(name)
        callers = {rule.caller for rule in policy.rules}
        assert expected_caller in callers, (
            f"{name}: expected caller={expected_caller!r}, got {callers!r}"
        )

    def test_google_has_multiple_callers(self):
        # Google is the one preset that bundles several IronClaw tools
        # (Gmail, Drive, Calendar, …) under one preset, so it needs
        # multiple distinct callers — each tool gets its own scope.
        policy = presets.get("google")
        callers = {rule.caller for rule in policy.rules}
        assert "gmail" in callers
        assert "google_drive" in callers
        # The OAuth token endpoint is the one rule shared by every
        # caller, so a None entry is expected.
        assert None in callers


class TestCompose:
    def test_compose_keeps_default_deny(self):
        policy = presets.compose(["github", "slack"])
        assert policy.default_action == "deny"

    def test_compose_concatenates_rules_in_input_order(self):
        # Order matters: ``EgressGuard.check`` is first-match-wins, so
        # tests asserting on order protect that invariant.
        gh = presets.get("github")
        slack = presets.get("slack")
        composed = presets.compose(["github", "slack"])
        assert composed.rules == [*gh.rules, *slack.rules]

    def test_compose_is_idempotent_modulo_rule_count(self):
        a = presets.compose(["github"])
        b = presets.compose(["github"])
        assert a.rules == b.rules
        assert a.default_action == b.default_action

    def test_compose_then_guard_routes_correctly(self):
        # End-to-end: a guard built from compose([...]) actually
        # admits the canonical hosts for the right callers and
        # denies cross-tool traffic.
        guard = egress.EgressGuard(presets.compose(["github", "slack"]))

        # github tool may hit api.github.com
        assert guard.check_url(
            "https://api.github.com/repos", caller="github",
        ).allowed

        # slack tool may hit slack.com/api
        assert guard.check_url(
            "https://slack.com/api/chat.postMessage", caller="slack",
        ).allowed

        # github tool calling slack: deny.
        assert not guard.check_url(
            "https://slack.com/api/chat.postMessage", caller="github",
        ).allowed

        # No caller at all: deny everywhere because every rule has a
        # caller pin.
        assert not guard.check_url("https://api.github.com/repos").allowed
