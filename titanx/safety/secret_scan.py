"""Outbound secret-scan for HTTP egress.

Scope and threat model
======================

This module is the *outbound* counterpart to :mod:`titanx.safety.redactor`.
Where the redactor strips PII from data flowing **into** the LLM, the
scanner inspects the bytes a tool is about to send **out** to a remote
HTTP endpoint and refuses (or audits) the request when the payload
matches a credential shape.

The motivating scenario is the classic credential-exfil chain:

1. The agent legitimately holds a long-lived secret in its environment
   (an OAuth refresh token, an AWS access key, a Stripe live key).
2. A tool — through a prompt-injection bug, a buggy template, or an
   adversarial server's response — writes that secret into a request
   destined for an attacker-controlled host (or the wrong tenant's
   webhook URL).
3. By the time the attacker has the secret, neither the audit log nor
   the policy gate notice: the policy was "post to ``hooks.example.com``"
   and that's exactly what happened.

A redaction pass on the LLM input cannot stop this — the secret never
went *through* the LLM. The scanner sits one layer further out: it
reuses the same pattern catalogue (``DEFAULT_PII_PATTERNS``) but
classifies each match as a *credential* rather than PII, and surfaces
the match to ``EgressGuard`` so the request can be denied or audited
before the socket opens.

Why pattern matching, not entropy
=================================

Entropy-only detectors are noisy on JSON payloads and tend to flag
opaque IDs (UUIDs, content hashes) that *look* random but aren't
secret. The vendors whose tokens we care about — GitHub, AWS, Slack,
Stripe, Google — all publish stable structural prefixes (``ghp_``,
``AKIA``, ``xoxb-``, ``sk_live_``, ``AIza``). Matching on those is
high-precision and zero false-positive on normal traffic.

The existing :data:`DEFAULT_PII_PATTERNS` already encodes the right
shapes; we just project a *subset* of them to the credential
category and add a small handful that are interesting only on the
outbound path (``Authorization: Bearer …`` is fine to log on input,
but exfiltrating it on output is the breach).

Composition with EgressGuard
============================

The scanner exposes a single :class:`OutboundSecretScanner` whose
``scan(payload)`` returns the list of matches. ``EgressGuard.enforce``
calls it on the URL + headers + (optionally) body before returning.
A non-empty match list either short-circuits to deny or fires an
audit warning, depending on ``EgressPolicy.outbound_secret_action``.

We do not block by default. This is a deliberate trade-off: a false
positive that takes down a legitimate webhook (e.g. an HMAC signature
that happens to match ``[A-Za-z0-9/+=]{40}``) is a customer-impacting
incident. Operators who *can* tolerate false positives (most
production deployments) should flip ``outbound_secret_action="block"``
explicitly. The audit module flags the default mode as ``warn`` so
the choice is at least visible in the posture report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Literal, Mapping

from .patterns import DEFAULT_PII_PATTERNS, PiiPattern


# Subset of ``DEFAULT_PII_PATTERNS`` that represent **credentials** rather
# than personal data. Email / phone / SSN / credit-card matches are PII
# but not credentials and emitting them in an outbound request body is a
# different problem (data exfil) handled by the redactor *before* the
# tool sees the data, not by this scanner. Keeping the credential set
# small means the scanner is fast (one combined regex) and has near-zero
# false positives on typical JSON payloads.
_CREDENTIAL_PII_NAMES: frozenset[str] = frozenset({
    "github_pat",
    "gitlab_pat",
    "slack_token",
    "stripe_key",
    "aws_access_key",
    "aws_secret_key",
    "api_key_generic",
    "bearer_token",
    "private_key_header",
    "jwt",
})


# Outbound-specific patterns that aren't worth redacting on the *inbound*
# path (they're often legitimate content there) but are high-signal on
# the outbound path. Add new entries here, keep them anchored on a
# vendor-specific prefix to stay false-positive-free.
_OUTBOUND_EXTRA_PATTERNS: list[PiiPattern] = [
    # Google API keys (Maps, Cloud, Firebase). ``AIza`` prefix + 35 base32-ish
    # chars is the documented shape; any string matching this in an
    # outbound URL parameter is a leaked key with very high probability.
    PiiPattern(
        "google_api_key",
        re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
        "[REDACTED:GOOGLE_API_KEY]",
    ),
    # OpenAI API keys: ``sk-`` followed by ≥40 chars including allowed
    # alphabet. Tighter than the generic ``sk_*`` pattern in the PII set
    # because OpenAI keys don't have the underscore separator.
    PiiPattern(
        "openai_api_key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b"),
        "[REDACTED:OPENAI_KEY]",
    ),
    # Anthropic API keys are ``sk-ant-...``. The fixed prefix is
    # unambiguous so the rest of the body doesn't need a tight bound.
    PiiPattern(
        "anthropic_api_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{40,}\b"),
        "[REDACTED:ANTHROPIC_KEY]",
    ),
    # SendGrid API keys: ``SG.`` + 22 base64 + ``.`` + 43 base64.
    PiiPattern(
        "sendgrid_api_key",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        "[REDACTED:SENDGRID_KEY]",
    ),
]


# Action taken when the scanner finds a match on the outbound path.
# ``block`` raises ``EgressDenied`` (treated like any other deny);
# ``warn`` allows the request but adds a finding to the audit hook.
SecretScanAction = Literal["block", "warn", "off"]


@dataclass(frozen=True)
class SecretMatch:
    """One credential shape that fired during an outbound scan.

    ``where`` says which part of the request the match landed in
    (``"url"`` / ``"header:Authorization"`` / ``"body"`` / etc.) so an
    operator triaging a finding doesn't have to grep their own logs.
    The matched span itself is **not** stored — we don't want secrets
    getting copied into audit entries that are themselves not as
    tightly access-controlled as the original credential. The
    ``replacement`` token from the underlying ``PiiPattern`` is what
    we surface for forensic context (e.g. ``[REDACTED:GITHUB_TOKEN]``
    tells you "a GitHub PAT was about to leak" without leaking the PAT).
    """

    pattern_name: str
    where: str
    replacement: str
    # ``start``/``end`` give the *byte* offsets within the scanned
    # field. Useful for tests; not surfaced into audit payloads.
    start: int = 0
    end: int = 0


@dataclass
class ScanResult:
    matches: list[SecretMatch] = field(default_factory=list)

    @property
    def hit(self) -> bool:
        return bool(self.matches)


class OutboundSecretScanner:
    """Scans an outbound HTTP request for credential shapes.

    The scanner is a small wrapper around a combined regex and is
    safe to share across requests — it has no per-call mutable state.
    The combined regex uses the same named-group dispatch trick as
    :class:`PiiRedactor` so it works correctly with patterns that
    contain inner capture groups.

    Operators who want to add their own patterns pass them in
    ``extra_patterns``. The bundled set is conservative on purpose;
    nothing here matches an arbitrary opaque token.
    """

    _GROUP_PREFIX = "_titanx_s"

    def __init__(
        self,
        *,
        extra_patterns: Iterable[PiiPattern] | None = None,
        include_default: bool = True,
    ) -> None:
        patterns: list[PiiPattern] = []
        if include_default:
            for p in DEFAULT_PII_PATTERNS:
                if p.name in _CREDENTIAL_PII_NAMES:
                    patterns.append(p)
            patterns.extend(_OUTBOUND_EXTRA_PATTERNS)
        if extra_patterns:
            patterns.extend(extra_patterns)
        self._patterns = patterns
        self._tags: list[str] = []
        self._names: dict[str, str] = {}
        self._replacements: dict[str, str] = {}
        sources: list[str] = []
        for idx, p in enumerate(patterns):
            tag = f"{self._GROUP_PREFIX}{idx}"
            self._tags.append(tag)
            self._names[tag] = p.name
            self._replacements[tag] = p.replacement
            inline = ""
            f = p.regex.flags
            if f & re.IGNORECASE:
                inline += "i"
            if f & re.MULTILINE:
                inline += "m"
            if f & re.DOTALL:
                inline += "s"
            body = p.regex.pattern
            inner = f"(?{inline}:{body})" if inline else body
            sources.append(f"(?P<{tag}>{inner})")
        self._combined = re.compile("|".join(sources)) if sources else None

    @property
    def patterns(self) -> tuple[PiiPattern, ...]:
        return tuple(self._patterns)

    # ── primary API ──────────────────────────────────────────────────────

    def scan(self, content: str, *, where: str) -> list[SecretMatch]:
        """Scan one piece of text. ``where`` becomes the match's tag."""
        if self._combined is None or not content:
            return []
        out: list[SecretMatch] = []
        for m in self._combined.finditer(content):
            for tag in self._tags:
                if m.group(tag) is not None:
                    out.append(SecretMatch(
                        pattern_name=self._names[tag],
                        where=where,
                        replacement=self._replacements[tag],
                        start=m.start(),
                        end=m.end(),
                    ))
                    break
        return out

    def scan_request(
        self,
        *,
        url: str = "",
        headers: Mapping[str, str] | None = None,
        body: str | bytes | None = None,
        skip_headers: Iterable[str] = ("host", "content-length",
                                       "content-type", "accept",
                                       "user-agent"),
    ) -> ScanResult:
        """Scan URL + headers + body in one pass.

        Header names in ``skip_headers`` are excluded from the scan
        because they cannot reasonably contain credentials and adding
        them to the loop just multiplies false positives. The
        Authorization header is **not** in the skip list — leaking a
        bearer to the wrong host is exactly what we're guarding against.

        ``body`` may be ``str`` (already-decoded JSON / form text) or
        ``bytes`` (raw payload). Bytes are decoded as UTF-8 with
        replacement, which is safe for the regex layer; non-text
        payloads (uploaded binaries) would not contain a credential
        text token by accident, and a deliberately-embedded one would
        still surface as long as it's encoded in ASCII (which every
        token format we know is).
        """
        result = ScanResult()
        if url:
            result.matches.extend(self.scan(url, where="url"))
        if headers:
            skip = {h.lower() for h in skip_headers}
            for name, value in headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    continue
                if name.lower() in skip:
                    continue
                result.matches.extend(
                    self.scan(value, where=f"header:{name}")
                )
        if body is not None:
            if isinstance(body, bytes):
                try:
                    body_text = body.decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    body_text = ""
            else:
                body_text = body
            if body_text:
                result.matches.extend(self.scan(body_text, where="body"))
        return result


__all__ = [
    "OutboundSecretScanner",
    "ScanResult",
    "SecretMatch",
    "SecretScanAction",
]
