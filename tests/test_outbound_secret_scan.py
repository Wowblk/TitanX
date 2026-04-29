"""Tests for ``OutboundSecretScanner`` and its EgressGuard integration.

The threat model is the credential-exfil chain: an agent legitimately
holds a long-lived secret in its environment and a buggy or
adversarial tool writes that secret into a request destined for the
wrong host. These tests verify that the scanner finds those secrets
in URL / header / body, and that the guard's three-mode policy
(``"off"`` / ``"warn"`` / ``"block"``) actually changes the decision
in the documented ways.

The scanner is reused as the redactor pattern catalogue, so we only
cover *outbound-specific* assertions here — the patterns themselves
are exercised in the redactor tests.
"""

from __future__ import annotations

import pytest

from titanx.safety.egress import (
    EgressDenied,
    EgressGuard,
    EgressPolicy,
    OutboundRule,
)
from titanx.safety.secret_scan import OutboundSecretScanner


# ── Pattern-level scanner tests ─────────────────────────────────────────

class TestScannerPatterns:
    def setup_method(self) -> None:
        self.scanner = OutboundSecretScanner()

    def test_finds_github_pat_in_body(self) -> None:
        body = '{"token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        result = self.scanner.scan_request(body=body)
        assert result.hit
        assert any(m.pattern_name == "github_pat" for m in result.matches)
        # The match's location is preserved without storing the value.
        match = next(m for m in result.matches if m.pattern_name == "github_pat")
        assert match.where == "body"
        assert match.replacement == "[REDACTED:GITHUB_TOKEN]"

    def test_finds_aws_access_key(self) -> None:
        body = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = self.scanner.scan_request(body=body)
        assert result.hit
        assert any(m.pattern_name == "aws_access_key" for m in result.matches)

    def test_finds_bearer_in_authorization_header(self) -> None:
        result = self.scanner.scan_request(
            headers={"Authorization": "Bearer abcdef0123456789abcdef0123456789"},
        )
        assert result.hit
        # We don't care which pattern fired; either the bearer-shape
        # or the generic api-key pattern can match. The key invariant
        # is the location.
        assert all(m.where == "header:Authorization" for m in result.matches)

    def test_finds_token_in_url_query(self) -> None:
        # Google Maps key in a URL is the classic leak shape. A real
        # key is ``AIza`` + exactly 35 base64url chars.
        url = "https://api.example.com/q?key=AIza" + "S" * 35
        result = self.scanner.scan_request(url=url)
        assert result.hit
        assert any(m.pattern_name == "google_api_key" for m in result.matches)
        assert all(m.where == "url" for m in result.matches)

    def test_skip_headers_are_not_scanned(self) -> None:
        # ``Host`` is in the default skip list — even if it contained
        # a credential-shape (it shouldn't), the scanner ignores it.
        result = self.scanner.scan_request(
            headers={"Host": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        )
        # Host is skipped; no match.
        assert not result.hit

    def test_anthropic_key(self) -> None:
        body = '{"key": "sk-ant-' + "a" * 50 + '"}'
        result = self.scanner.scan_request(body=body)
        assert result.hit
        assert any(m.pattern_name == "anthropic_api_key" for m in result.matches)

    def test_jwt_in_body(self) -> None:
        # Token components are length-bounded only by the JWT regex.
        body = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "abc123_xyz-789"
        )
        result = self.scanner.scan_request(body=body)
        assert result.hit
        assert any(m.pattern_name == "jwt" for m in result.matches)

    def test_no_false_positive_on_uuid(self) -> None:
        # UUIDs look opaque but contain no credential-shape we match.
        body = "request_id=550e8400-e29b-41d4-a716-446655440000"
        result = self.scanner.scan_request(body=body)
        assert not result.hit

    def test_bytes_body_is_decoded(self) -> None:
        body = b'{"token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        result = self.scanner.scan_request(body=body)
        assert result.hit

    def test_empty_inputs_short_circuit(self) -> None:
        result = self.scanner.scan_request()
        assert not result.hit
        result = self.scanner.scan_request(url="", body=None)
        assert not result.hit


# ── EgressGuard integration ─────────────────────────────────────────────

def _make_guard(
    *,
    action: str = "warn",
) -> EgressGuard:
    policy = EgressPolicy(
        rules=[
            OutboundRule(
                host_pattern="api.example.com",
                methods=("POST",),
            ),
        ],
        default_action="deny",
        outbound_secret_action=action,  # type: ignore[arg-type]
    )
    return EgressGuard(policy)


class TestGuardWarnMode:
    @pytest.mark.asyncio
    async def test_warn_passes_request_through(self) -> None:
        guard = _make_guard(action="warn")
        body = '{"token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        decision = await guard.enforce(
            "https://api.example.com/", "POST", body=body,
        )
        # The request still goes through.
        assert decision.allowed is True
        # But the audit/decision record exposes the finding.
        assert decision.secret_matches
        assert "github_pat" in decision.secret_matches
        # The matched value is NOT in the reason (only the pattern name).
        assert "ghp_" not in decision.reason

    @pytest.mark.asyncio
    async def test_warn_with_no_match_unchanged(self) -> None:
        guard = _make_guard(action="warn")
        decision = await guard.enforce(
            "https://api.example.com/", "POST", body='{"q": "hello"}',
        )
        assert decision.allowed is True
        assert decision.secret_matches == ()


class TestGuardBlockMode:
    @pytest.mark.asyncio
    async def test_block_refuses_request(self) -> None:
        guard = _make_guard(action="block")
        body = '{"key": "AKIAIOSFODNN7EXAMPLE"}'
        with pytest.raises(EgressDenied) as exc:
            await guard.enforce(
                "https://api.example.com/", "POST", body=body,
            )
        decision = exc.value.decision
        assert decision.allowed is False
        assert "credential shapes" in decision.reason
        assert "aws_access_key" in decision.secret_matches

    @pytest.mark.asyncio
    async def test_block_passes_clean_request(self) -> None:
        guard = _make_guard(action="block")
        decision = await guard.enforce(
            "https://api.example.com/", "POST", body="hello world",
        )
        assert decision.allowed is True


class TestGuardOffMode:
    @pytest.mark.asyncio
    async def test_off_skips_scan(self) -> None:
        guard = _make_guard(action="off")
        body = '{"token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        decision = await guard.enforce(
            "https://api.example.com/", "POST", body=body,
        )
        assert decision.allowed is True
        assert decision.secret_matches == ()


class TestScanOnDeniedRequest:
    @pytest.mark.asyncio
    async def test_no_scan_when_already_denied(self) -> None:
        # A request the allowlist already refuses must not run the
        # scanner: it would just spend cycles without changing the
        # outcome and would be confusing in the audit log.
        guard = _make_guard(action="block")
        body = '{"token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        with pytest.raises(EgressDenied) as exc:
            await guard.enforce(
                "https://disallowed.example.com/", "POST", body=body,
            )
        decision = exc.value.decision
        # The deny reason is the allowlist miss, not the secret scan.
        assert "no matching rule" in decision.reason
        assert decision.secret_matches == ()


class TestAuditPayload:
    @pytest.mark.asyncio
    async def test_audit_payload_omits_value(self) -> None:
        captured: list = []

        async def hook(decision):
            captured.append(decision)

        policy = EgressPolicy(
            rules=[OutboundRule(host_pattern="api.example.com",
                                methods=("POST",))],
            default_action="deny",
            outbound_secret_action="warn",
        )
        guard = EgressGuard(policy, audit_hook=hook)
        body = '{"token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        await guard.enforce("https://api.example.com/", "POST", body=body)
        assert len(captured) == 1
        assert captured[0].secret_matches == ("github_pat",)
        # And the captured decision does not contain the raw token.
        assert "ghp_" not in captured[0].reason
