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


# ── Non-canonical / alternate-encoding bypasses ────────────────────────
#
# ``ipaddress.ip_address`` only accepts the canonical dotted-quad, so the
# SSRF classifier missed every *other* spelling that libc's ``inet_aton``
# (and therefore most HTTP clients) happily resolves: the bare 32-bit
# integer (``2130706433``), hex (``0x7f000001``), octal (``0177.0.0.1``),
# and short forms (``127.1``). It also missed the trailing-dot FQDN
# (``metadata.google.internal.``), which is a valid spelling of the same
# name and defeated the sentinel list. Each of these reached a private
# destination while ``private_address_category`` stayed empty.

def _make_advisory_guard(*, extra_blocked: tuple[str, ...] = ()) -> EgressGuard:
    """A default-*allow* policy — the documented "advisory allowlist" posture.

    The SSRF pre-filter is the only thing standing between a tool and a
    private destination here, so it is the sharpest way to show the
    bypass: pre-fix the request is allowed, post-fix it is refused.
    """
    return EgressGuard(EgressPolicy(
        rules=[],
        default_action="allow",
        block_private_addresses=True,
        extra_blocked_hostnames=extra_blocked,
    ))


class TestNonCanonicalAddressBypasses:
    @pytest.mark.parametrize("addr,category", [
        ("2130706433", "loopback"),      # 127.0.0.1 as a 32-bit int
        ("0x7f000001", "loopback"),      # hex
        ("0x7F000001", "loopback"),      # hex, upper-case
        ("0177.0.0.1", "loopback"),      # octal first octet
        ("127.1", "loopback"),           # 2-component short form
        ("127.0.1", "loopback"),         # 3-component short form
        ("127.0.0.1.", "loopback"),      # trailing dot on an IP
        ("2130706433.", "loopback"),     # trailing dot on the integer form
        ("3232235777", "private"),       # 192.168.1.1
        ("2852039166", "link_local"),    # 169.254.169.254
        ("0xa9fea9fe", "link_local"),    # 169.254.169.254 in hex
    ])
    def test_non_canonical_ipv4_forms_blocked(self, addr: str, category: str) -> None:
        decision = _classify_address(addr)
        assert decision.blocked is True, f"{addr!r} slipped past the SSRF check"
        assert decision.category == category

    def test_unspecified_integer_form_blocked(self) -> None:
        decision = _classify_address("0")  # 0.0.0.0
        assert decision.blocked is True
        assert decision.category in ("reserved", "private")

    @pytest.mark.parametrize("name", [
        "metadata.google.internal.",
        "METADATA.GOOGLE.INTERNAL.",
        "instance-data.",
        "metadata.azure.com.",
    ])
    def test_metadata_sentinel_trailing_dot_blocked(self, name: str) -> None:
        decision = _classify_address(name)
        assert decision.blocked is True, f"{name!r} dodged the sentinel list"
        assert decision.category == "metadata_host"

    def test_advisory_guard_blocks_non_canonical_loopback(self) -> None:
        guard = _make_advisory_guard()
        for url in (
            "http://2130706433/admin",
            "http://0x7f000001/admin",
            "http://0177.0.0.1/admin",
            "http://127.1/admin",
        ):
            decision = guard.check_url(url, "GET")
            assert decision.allowed is False, url
            assert decision.private_address_category == "loopback"

    def test_advisory_guard_blocks_metadata_trailing_dot(self) -> None:
        guard = _make_advisory_guard()
        decision = guard.check_url(
            "http://metadata.google.internal./computeMetadata/v1/", "GET"
        )
        assert decision.allowed is False
        assert decision.private_address_category == "metadata_host"

    def test_extra_blocked_hostname_trailing_dot(self) -> None:
        guard = _make_advisory_guard(extra_blocked=("my-jumphost.internal",))
        decision = guard.check_url("https://my-jumphost.internal./", "GET")
        assert decision.allowed is False


class TestNonCanonicalFalsePositives:
    def test_public_trailing_dot_not_over_blocked(self) -> None:
        assert _classify_address("api.example.com.").blocked is False

    def test_five_component_dotted_quad_is_not_an_ip(self) -> None:
        # Not a valid IPv4 literal; a resolver would treat it as a name.
        assert _classify_address("1.2.3.4.5").blocked is False

    def test_integer_overflow_wraps_modulo_2_32_not_allowed(self) -> None:
        # A bare integer literal wraps modulo 2**32 in inet_aton (and in
        # the clients inheriting it): 2**32 -> 0.0.0.0, 2**32+1 -> 0.0.0.1.
        # Both are private destinations and must not fall through.
        zero = _classify_address("4294967296")
        assert zero.blocked is True
        assert zero.category in ("reserved", "private")
        wrapped = _classify_address("4294967297")  # 2**32+1 -> 0.0.0.1
        assert wrapped.blocked is True
        assert wrapped.category in ("loopback", "private", "reserved")

    def test_hex_integer_overflow_wraps_and_is_blocked(self) -> None:
        decision = _classify_address("0x100000000")  # 2**32 -> 0.0.0.0
        assert decision.blocked is True

    def test_alpha_hostname_still_passes(self) -> None:
        assert _classify_address("notanip.example.com").blocked is False
