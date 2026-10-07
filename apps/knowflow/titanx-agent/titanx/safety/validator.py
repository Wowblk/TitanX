from __future__ import annotations

from typing import Any

from .patterns import DEFAULT_INJECTION_PATTERNS, InjectionPattern
from ..types import ValidatorLike, ValidationIssue, ValidationResult

MAX_INPUT_LENGTH = 100_000


class InputValidator(ValidatorLike):
    def __init__(self, injection_patterns: list[InjectionPattern] | None = None) -> None:
        self._patterns = injection_patterns or DEFAULT_INJECTION_PATTERNS

    def get_injection_patterns(self) -> list[InjectionPattern]:
        return self._patterns

    def validate_input(self, content: str, field: str = "input") -> ValidationResult:
        errors: list[ValidationIssue] = []
        warnings: list[ValidationIssue] = []

        if not content:
            errors.append(ValidationIssue(field=field, message="Input cannot be empty", code="empty_input", severity="error"))

        if len(content) > MAX_INPUT_LENGTH:
            errors.append(ValidationIssue(field=field, message="Input exceeds maximum length", code="input_too_long", severity="error"))

        for pattern in self._patterns:
            if pattern.regex.search(content):
                issue = ValidationIssue(
                    field=field,
                    message=f"Potential prompt injection detected: {pattern.name}",
                    code=f"injection_{pattern.name}",
                    severity="error" if pattern.action == "block" else "warning",
                )
                (errors if pattern.action == "block" else warnings).append(issue)

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)

    def validate_tool_params(self, params: dict[str, Any]) -> ValidationResult:
        errors: list[ValidationIssue] = []
        warnings: list[ValidationIssue] = []

        for key, value in params.items():
            if isinstance(value, str):
                result = self.validate_input(value, key)
                errors.extend(result.errors)
                warnings.extend(result.warnings)

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)
