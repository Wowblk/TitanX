from __future__ import annotations

import re
from dataclasses import dataclass

from .patterns import DEFAULT_PII_PATTERNS, PiiPattern


@dataclass
class RedactionResult:
    content: str
    redacted_count: int


class PiiRedactor:
    """Single-pass O(n) redactor: combines N patterns into one regex."""

    def __init__(self, patterns: list[PiiPattern] | None = None) -> None:
        self._patterns = patterns or DEFAULT_PII_PATTERNS
        self._replacements = [p.replacement for p in self._patterns]
        sources = [f"({p.regex.pattern})" for p in self._patterns]
        self._combined = re.compile("|".join(sources), re.IGNORECASE)

    def redact(self, content: str) -> RedactionResult:
        count = 0

        def replace(m: re.Match[str]) -> str:
            nonlocal count
            count += 1
            for i, group in enumerate(m.groups()):
                if group is not None:
                    return self._replacements[i]
            return "[REDACTED]"

        result = self._combined.sub(replace, content)
        return RedactionResult(content=result, redacted_count=count)
