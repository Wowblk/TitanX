from __future__ import annotations

from .patterns import DEFAULT_INJECTION_PATTERNS, DEFAULT_PII_PATTERNS, InjectionPattern, PiiPattern
from .redactor import PiiRedactor
from .validator import InputValidator
from ..types import SafetyLayerLike, SafetyResult, SafetyViolation


class SafetyLayer(SafetyLayerLike):
    def __init__(
        self,
        injection_patterns: list[InjectionPattern] | None = None,
        pii_patterns: list[PiiPattern] | None = None,
    ) -> None:
        self._injection_patterns = injection_patterns or DEFAULT_INJECTION_PATTERNS
        self._validator = InputValidator(self._injection_patterns)
        self._redactor = PiiRedactor(pii_patterns or DEFAULT_PII_PATTERNS)

    @property
    def validator(self) -> InputValidator:
        return self._validator

    def check_input(self, content: str) -> SafetyResult:
        sanitized = self._redactor.redact(content).content

        violations: list[SafetyViolation] = []
        for pattern in self._injection_patterns:
            if pattern.regex.search(sanitized):
                violations.append(SafetyViolation(pattern=pattern.name, action=pattern.action))

        return SafetyResult(
            safe=not any(v.action == "block" for v in violations),
            sanitized_content=sanitized,
            violations=violations,
        )

    def sanitize_tool_output(self, _tool_name: str, output: str) -> dict[str, str]:
        return {"content": self._redactor.redact(output).content}
