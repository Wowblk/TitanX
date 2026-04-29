"""Tests for the SSRF private-destination block in EgressGuard.

The contract under test is: a default-deny policy with a single
allowlist entry refuses any URL whose authority is a literal RFC1918,
loopback, link-local, reserved, or cloud-metadata address — even when
the host string itself happens to match the allowed host pattern. A
per-rule ``allow_private=True`` opt-out lets a specific rule reach a
private destination without flipping the global block.

These tests exercise *only* the synchronous ``check_url`` path: the
async ``enforce`` wrapper inherits the same code path so adding a
parallel set of async tests for the SSRF dimension would be pure
duplication. The secret-scanner-on-enforce contract is tested
separately in ``tests/test_outbound_secret_scan.py``.
"""

from __future__ import annotations

import pytest

from titanx.safety.egress import (
    EgressGuard,
    EgressPolicy,
    OutboundRule,
    PrivateAddressDecision,
    _classify_address,
)


# ── _classify_address: pure function unit tests ─────────────────────────

class TestClassifyAddress:
    @pytest.mark.parametrize("addr", [
        "127.0.0.1",
        "127.255.255.254",
        "::1",
    ])
    def test_loopback(self, addr: str) -> None:
        decision = _classify_address(addr)
        assert decision.blocked is True
        assert decision.category == "loopback"

    @pytest.mark.parametrize("addr", [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.1.100",
        "fc00::1",
        "fd12:3456:789a::1",
    ])
    def test_private(self, addr: str) -> None:
        decision = _classify_address(addr)
        assert decision.blocked is True
        assert decision.category == "private"

    @pytest.mark.parametrize("addr", [
        "169.254.0.1",
        "169.254.169.254",  # AWS metadata IP
        "fe80::1",
    ])
    def test_link_local(self, addr: str) -> None:
        decision = _classify_address(addr)
        assert decision.blocked is True
        assert decision.category == "link_local"

    @pytest.mark.parametrize("addr", [
        "100.64.0.1",
        "100.127.255.255",
    ])
    def test_cgnat(self, addr: str) -> None:
        decision = _classify_address(addr)
        assert decision.blocked is True
        assert decision.category == "private"

    @pytest.mark.parametrize("addr", [
        "224.0.0.1",
        "239.255.255.255",
        "ff02::1",
    ])
    def test_multicast(self, addr: str) -> None:
        decision = _classify_address(addr)
        assert decision.blocked is True
        assert decision.category == "multicast"

    @pytest.mark.parametrize("addr", [
        "0.0.0.0",
        "::",
    ])
    def test_unspecified(self, addr: str) -> None:
        decision = _classify_address(addr)
        assert decision.blocked is True
        assert decision.category in ("reserved", "private")

    @pytest.mark.parametrize("addr", [
        "8.8.8.8",
        "1.1.1.1",
        "151.101.0.1",  # Fastly
        "2606:4700:4700::1111",  # Cloudflare
    ])
    def test_public_passes(self, addr: str) -> None:
        decision = _classify_address(addr)
        assert decision.blocked is False
        assert decision.category == ""

    @pytest.mark.parametrize("name", [
        "metadata.google.internal",
        "instance-data",
        "metadata.azure.com",
        "METADATA.GOOGLE.INTERNAL",  # case-insensitive
    ])
    def test_metadata_hostnames(self, name: str) -> None:
        decision = _classify_address(name)
        assert decision.blocked is True
        assert decision.category == "metadata_host"

    @pytest.mark.parametrize("name", [
        "api.example.com",
        "github.com",
        "",  # empty short-circuits to not-blocked
    ])
    def test_arbitrary_names_pass(self, name: str) -> None:
        decision = _classify_address(name)
        assert decision.blocked is False

    def test_ipv6_bracketed(self) -> None:
        decision = _classify_address("[::1]")
        assert decision.blocked is True
        assert decision.category == "loopback"

    def test_ipv4_mapped_v6_private(self) -> None:
        decision = _classify_address("::ffff:10.0.0.1")
        assert decision.blocked is True
        assert decision.category == "private"


# ── EgressGuard.check_url integration ───────────────────────────────────

def _make_guard(
    *,
    rules: list[OutboundRule] | None = None,
    block: bool = True,
    extra_blocked: tuple[str, ...] = (),
) -> EgressGuard:
    policy = EgressPolicy(
        rules=rules or [],
        default_action="deny",
        block_private_addresses=block,
        extra_blocked_hostnames=extra_blocked,
    )
    return EgressGuard(policy)


class TestSsrfAtGuard:
    def test_default_blocks_loopback(self) -> None:
        guard = _make_guard(rules=[
            OutboundRule(host_pattern="127.0.0.1"),
        ])
        decision = guard.check_url("https://127.0.0.1/admin", "GET")
        assert decision.allowed is False
        assert decision.private_address_category == "loopback"
        # The reason explains *why*, not "no matching rule".
        assert "loopback" in decision.reason

    def test_default_blocks_aws_metadata(self) -> None:
        # Even when the operator allowlists the metadata address (a
        # common SSRF lure), the SSRF guard still refuses.
        guard = _make_guard(rules=[
            OutboundRule(host_pattern="169.254.169.254"),
        ])
        decision = guard.check_url(
            "http://169.254.169.254/latest/meta-data/", "GET"
        )
        assert decision.allowed is False
        assert decision.private_address_category == "link_local"

    def test_default_blocks_rfc1918(self) -> None:
        guard = _make_guard(rules=[
            OutboundRule(host_pattern="10.0.0.5"),
        ])
        decision = guard.check_url("https://10.0.0.5/", "GET")
        assert decision.allowed is False
        assert decision.private_address_category == "private"

    def test_default_blocks_metadata_hostname(self) -> None:
        guard = _make_guard(rules=[
            OutboundRule(host_pattern="metadata.google.internal"),
        ])
        decision = guard.check_url(
            "http://metadata.google.internal/computeMetadata/v1/", "GET"
        )
        assert decision.allowed is False
        assert decision.private_address_category == "metadata_host"

    def test_public_address_passes(self) -> None:
        guard = _make_guard(rules=[
            OutboundRule(host_pattern="api.example.com"),
        ])
        decision = guard.check_url("https://api.example.com/v1/", "GET")
        assert decision.allowed is True
        assert decision.private_address_category == ""

    def test_block_disabled_lets_loopback_through(self) -> None:
        guard = _make_guard(
            rules=[OutboundRule(host_pattern="127.0.0.1",
                                allowed_schemes=("http", "https"))],
            block=False,
        )
        decision = guard.check_url("http://127.0.0.1/admin", "GET")
        assert decision.allowed is True

    def test_extra_blocked_hostname(self) -> None:
        guard = _make_guard(
            rules=[OutboundRule(host_pattern="my-jumphost.internal")],
            extra_blocked=("my-jumphost.internal",),
        )
        decision = guard.check_url(
            "https://my-jumphost.internal/", "GET"
        )
        assert decision.allowed is False
        assert decision.private_address_category == "metadata_host"


class TestAllowPrivateOptOut:
    def test_allow_private_rule_overrides(self) -> None:
        guard = _make_guard(rules=[
            OutboundRule(
                host_pattern="10.0.0.5",
                allowed_schemes=("http", "https"),
                allow_private=True,
                caller="internal_api",
            ),
        ])
        decision = guard.check_url(
            "http://10.0.0.5/", "GET", caller="internal_api"
        )
        assert decision.allowed is True
        # Even on allow, the audit field still surfaces the category
        # so the operator can see this was a private-destination
        # opt-in, not a regular allow.
        assert decision.private_address_category == "private"
        assert decision.matched_rule is not None
        assert decision.matched_rule.allow_private is True

    def test_allow_private_only_applies_to_matching_rule(self) -> None:
        # A rule that says ``allow_private=True`` for *its own* host
        # must not bypass the SSRF block for a different host.
        guard = _make_guard(rules=[
            OutboundRule(
                host_pattern="10.0.0.5",
                allow_private=True,
                allowed_schemes=("http", "https"),
            ),
        ])
        decision = guard.check_url("http://192.168.1.1/", "GET")
        assert decision.allowed is False

    def test_allow_private_respects_caller_pin(self) -> None:
        guard = _make_guard(rules=[
            OutboundRule(
                host_pattern="10.0.0.5",
                allow_private=True,
                caller="internal_api",
                allowed_schemes=("http", "https"),
            ),
        ])
        # Wrong caller — opt-out does not apply.
        decision = guard.check_url(
            "http://10.0.0.5/", "GET", caller="other_tool"
        )
        assert decision.allowed is False
        # Right caller — opt-out applies.
        decision = guard.check_url(
            "http://10.0.0.5/", "GET", caller="internal_api"
        )
        assert decision.allowed is True

    def test_default_rules_do_not_bypass(self) -> None:
        # An operator who forgets to mark a rule allow_private=True
        # gets the safe default.
        guard = _make_guard(rules=[
            OutboundRule(host_pattern="10.0.0.5",
                         allowed_schemes=("http", "https")),
        ])
        decision = guard.check_url("http://10.0.0.5/", "GET")
        assert decision.allowed is False
