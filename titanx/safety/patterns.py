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


# ---------------------------------------------------------------------------
# Injection patterns
# ---------------------------------------------------------------------------
#
# All English-language patterns are intended to run against text that has
# already been normalised by :class:`SafetyLayer` (NFKC + zero-width / BiDi
# stripping). They therefore deliberately do NOT try to defend against the
# Unicode-bypass family at the regex level — that is handled before the scan.
#
# The CJK and Spanish patterns provide a minimum multilingual baseline.
# They are not exhaustive translation coverage, but they catch the most
# common phrasings of the canonical English attacks. Add more languages
# via ``InjectionPattern`` and pass them to ``SafetyLayer(injection_patterns=…)``.
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

    # Chinese — covers 忽略/无视/忘记/无须遵守 + 之前/上面/系统/指令
    InjectionPattern("zh_ignore_instructions",
        re.compile(r"(?:忽略|无视|忘记|无须遵守|不要遵守)(?:[\s之前\u4e00-\u9fff]{0,8})?(?:之前|上面|前面|系统|所有)?(?:[\s\u4e00-\u9fff]{0,4})?指(?:令|示)"), "block"),
    InjectionPattern("zh_jailbreak_role",
        re.compile(r"(?:你现在是|从现在起你是|扮演)(?:一个)?(?:不受限|无限制|无道德|越狱|开发者模式)"), "block"),
    InjectionPattern("zh_disable_safety",
        re.compile(r"(?:关闭|禁用|绕过|跳过)(?:你的)?(?:安全|过滤|审查|限制|策略)"), "block"),

    # Japanese — 無視/忘れ + 指示/命令/プロンプト, with up to 8 chars of
    # intervening particles ("を" / "すべて" / etc.) between target and verb.
    InjectionPattern("ja_ignore_instructions",
        re.compile(r"(?:前の|これまでの|以前の|上記の|すべての)?(?:指示|命令|プロンプト|ルール)(?:[\u3040-\u30ff\u4e00-\u9fff\s]{0,12})?(?:無視|忘れ)"), "block"),
    # Spanish — ignora / olvida + instrucciones / reglas
    InjectionPattern("es_ignore_instructions",
        re.compile(r"(?:ignora|olvida|desestima)\s+(?:todas\s+)?(?:las\s+)?(?:instrucciones|reglas|directrices|gu[íi]a)\s+(?:anteriores|previas)?", re.I), "block"),
]


# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------
#
# Notable expansions over the previous version:
#   * GitHub fine-grained / classic PATs (ghp_, gho_, ghu_, ghs_, ghr_)
#   * GitLab PATs (glpat-…)
#   * Slack tokens (xoxa-, xoxb-, xoxp-, xoxr-, xoxs-)
#   * Stripe live/test keys (sk_live_, sk_test_, pk_live_, pk_test_)
#   * AWS access keys for ALL prefixes — IAM (AKIA), STS (ASIA), root (AIDA),
#     role (AROA), group (AGPA), service (ANPA / ANVA), etc.
#   * China mainland mobile numbers (+86 1xx xxxx xxxx) and generic E.164
#   * UK / EU / Indian mobile numbers via E.164
#   * Generic high-entropy bearer tokens stayed last to avoid clobbering
#     the more specific patterns when matching from left to right.
DEFAULT_PII_PATTERNS: list[PiiPattern] = [
    PiiPattern("email",               re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"), "[REDACTED:EMAIL]"),
    PiiPattern("phone_us",            re.compile(r"(?:\+1[\s-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}"), "[REDACTED:PHONE]"),
    PiiPattern("phone_cn",            re.compile(r"(?:\+?86[\s.-]?)?1[3-9]\d[\s.-]?\d{4}[\s.-]?\d{4}"), "[REDACTED:PHONE]"),
    PiiPattern("phone_e164",          re.compile(r"\+(?:[1-9]\d{0,2})[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b"), "[REDACTED:PHONE]"),
    PiiPattern("ssn",                 re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:SSN]"),
    PiiPattern("credit_card",         re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"), "[REDACTED:CC]"),

    # Vendor-specific tokens. Order matters: vendor-specific must come before
    # the generic ``api_key_generic`` catch-all so the more informative tag
    # is preferred when both could match.
    PiiPattern("github_pat",          re.compile(r"\bgh[posru]_[A-Za-z0-9]{16,}\b"), "[REDACTED:GITHUB_TOKEN]"),
    PiiPattern("gitlab_pat",          re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED:GITLAB_TOKEN]"),
    PiiPattern("slack_token",         re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:SLACK_TOKEN]"),
    PiiPattern("stripe_key",          re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "[REDACTED:STRIPE_KEY]"),
    # AWS access key IDs for every documented prefix. Case-sensitive on
    # purpose — all real keys are uppercase, and the case-insensitive
    # compile that used to wrap the combined regex was a false-positive
    # multiplier.
    PiiPattern("aws_access_key",      re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|AIPA|APKA)[0-9A-Z]{16}\b"), "[REDACTED:AWS_KEY]"),
    PiiPattern("aws_secret_key",      re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), "[REDACTED:AWS_SECRET]"),
    PiiPattern("api_key_generic",     re.compile(r"\b(?:sk|pk|api|key|token|secret)[-_][A-Za-z0-9]{20,}\b", re.I), "[REDACTED:API_KEY]"),
    PiiPattern("bearer_token",        re.compile(r"Bearer\s+[A-Za-z0-9._\-+/]{20,}", re.I), "Bearer [REDACTED:TOKEN]"),
    PiiPattern("private_key_header",  re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"), "[REDACTED:PRIVATE_KEY]"),
    PiiPattern("jwt",                 re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), "[REDACTED:JWT]"),
]
