from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


@dataclass
class InjectionPattern:
    name: str
    regex: re.Pattern[str]
    action: Literal["warn", "block"]


@dataclass
class PiiPattern:
    name: str
    regex: re.Pattern[str]
    replacement: str


DEFAULT_INJECTION_PATTERNS: list[InjectionPattern] = [
    InjectionPattern("ignore_instructions",   re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.I), "block"),
    InjectionPattern("forget_instructions",   re.compile(r"(?:forget|disregard|ignore)\s+(?:your|all)\s+(?:instructions?|guidelines?|rules?|training|prompt)", re.I), "block"),
    InjectionPattern("jailbreak_token",       re.compile(r"\b(?:DAN|JAILBREAK|DEVELOPER\s+MODE)\b", re.I), "block"),
    InjectionPattern("role_override",         re.compile(r"you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|without|free\s+from)", re.I), "block"),
    InjectionPattern("bypass_safety",         re.compile(r"(?:override|bypass|disable|circumvent)\s+(?:your\s+)?(?:safety|security|filter|restriction|policy)", re.I), "block"),
    InjectionPattern("fake_system_prompt",    re.compile(r"###\s*(?:SYSTEM|INSTRUCTION|PROMPT)", re.I), "block"),
    InjectionPattern("special_token_injection", re.compile(r"<\|(?:system|endoftext|im_start|im_end)[^|]*\|>", re.I), "block"),
    InjectionPattern("null_byte",             re.compile(r"\x00"), "block"),
    InjectionPattern("act_unrestricted",      re.compile(r"act\s+as\s+(?:if\s+you\s+(?:have\s+no|are\s+without)|an?\s+unrestricted)", re.I), "block"),
    InjectionPattern("pretend_no_rules",      re.compile(r"pretend\s+(?:you\s+have\s+no|there\s+are\s+no)\s+(?:rules?|restrictions?|guidelines?)", re.I), "block"),
]

DEFAULT_PII_PATTERNS: list[PiiPattern] = [
    PiiPattern("email",               re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"), "[REDACTED:EMAIL]"),
    PiiPattern("phone_us",            re.compile(r"(?:\+1[\s-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}"), "[REDACTED:PHONE]"),
    PiiPattern("ssn",                 re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:SSN]"),
    PiiPattern("credit_card",         re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"), "[REDACTED:CC]"),
    PiiPattern("api_key_generic",     re.compile(r"\b(?:sk|pk|api|key|token|secret)[-_][A-Za-z0-9]{20,}\b", re.I), "[REDACTED:API_KEY]"),
    PiiPattern("bearer_token",        re.compile(r"Bearer\s+[A-Za-z0-9._\-+/]{20,}", re.I), "Bearer [REDACTED:TOKEN]"),
    PiiPattern("aws_access_key",      re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_KEY]"),
    PiiPattern("private_key_header",  re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"), "[REDACTED:PRIVATE_KEY]"),
]
