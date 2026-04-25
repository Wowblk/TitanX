from __future__ import annotations

import re
from dataclasses import dataclass

from .patterns import DEFAULT_PII_PATTERNS, PiiPattern


@dataclass
class RedactionResult:
    content: str
    redacted_count: int


class PiiRedactor:
    """Single-pass O(n) redactor that combines N patterns into one regex.

    Each input pattern is wrapped in a *named* outer capture group (
    ``_titanx_p0``, ``_titanx_p1``, …). Match dispatch walks the list of
    known tags and picks the first one whose group matched, instead of
    relying on positional indexing into ``m.groups()``.

    This keeps the redactor robust against two real-world failure modes
    of the previous implementation:

    1. **User patterns with internal capture groups** (e.g.
       ``re.compile(r"(\\d{3})-(\\d{2})-(\\d{4})")``) used to crash the
       redactor with ``IndexError: list index out of range`` because
       the index math assumed each pattern contributed exactly one group.
    2. **Per-pattern flag loss**. The previous code applied
       ``re.IGNORECASE`` to the *combined* regex, which silently flipped
       case-sensitive patterns (e.g. ``AKIA[0-9A-Z]{16}``) into
       case-insensitive ones. Per-pattern flags are now preserved by
       re-encoding them inline as ``(?i:…)`` / ``(?m:…)`` / ``(?s:…)``.
    """

    _GROUP_PREFIX = "_titanx_p"

    def __init__(self, patterns: list[PiiPattern] | None = None) -> None:
        self._patterns = patterns or DEFAULT_PII_PATTERNS
        self._tags: list[str] = []
        self._replacements: dict[str, str] = {}
        sources: list[str] = []
        for idx, p in enumerate(self._patterns):
            tag = f"{self._GROUP_PREFIX}{idx}"
            self._tags.append(tag)
            self._replacements[tag] = p.replacement
            inner = self._with_inline_flags(p)
            sources.append(f"(?P<{tag}>{inner})")
        self._combined = re.compile("|".join(sources)) if sources else None

    @staticmethod
    def _with_inline_flags(pattern: PiiPattern) -> str:
        """Re-encode ``pattern.regex``'s flags as inline modifiers.

        ``re.Pattern.pattern`` returns only the source string and drops
        the flags supplied at compile time. Combining N patterns into a
        single regex therefore loses each pattern's per-pattern flag
        intent. We rebuild it with ``(?i:…)`` and friends so the
        combined matcher behaves identically to running each pattern
        on its own.
        """
        flags = pattern.regex.flags
        inline = ""
        if flags & re.IGNORECASE:
            inline += "i"
        if flags & re.MULTILINE:
            inline += "m"
        if flags & re.DOTALL:
            inline += "s"
        body = pattern.regex.pattern
        return f"(?{inline}:{body})" if inline else body

    def redact(self, content: str) -> RedactionResult:
        if self._combined is None or not content:
            return RedactionResult(content=content, redacted_count=0)

        count = 0

        def replace(m: re.Match[str]) -> str:
            nonlocal count
            # Walk our known outer-group tags in declaration order and
            # take the first one with a non-None match. Exactly one of
            # the alternation branches will have produced a match, so
            # exactly one outer group is populated regardless of how
            # many *inner* groups the user pattern contains.
            for tag in self._tags:
                if m.group(tag) is not None:
                    count += 1
                    return self._replacements[tag]
            return m.group(0)

        result = self._combined.sub(replace, content)
        return RedactionResult(content=result, redacted_count=count)
