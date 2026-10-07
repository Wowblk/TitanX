from __future__ import annotations

from typing import Any

from .normalization import canonicalise_for_scan
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

        # Match against the canonicalised view so zero-width / BiDi /
        # NFKC-decomposable bypasses share the same defence as
        # ``SafetyLayer.check_input``.
        canonical = canonicalise_for_scan(content)
        for pattern in self._patterns:
            if pattern.regex.search(canonical):
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
            self._scan_value(value, key, errors, warnings)

        return ValidationResult(is_valid=len(errors) == 0, errors=errors, warnings=warnings)

    def _scan_value(
        self,
        value: Any,
        field: str,
        errors: list[ValidationIssue],
        warnings: list[ValidationIssue],
    ) -> None:
        """Scan ``value`` for injections, recursing through containers.

        Tool parameters are arbitrary JSON, so a trigger can be smuggled one
        level down — ``{"payload": {"inner": "ignore previous instructions"}}``
        — precisely to dodge a top-level-only scan. Walk dicts and lists so the
        same defence applies at every depth.
        """
        if isinstance(value, str):
            result = self.validate_input(value, field)
            errors.extend(result.errors)
            warnings.extend(result.warnings)
        elif isinstance(value, dict):
            for key, child in value.items():
                self._scan_value(child, f"{field}.{key}", errors, warnings)
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                self._scan_value(child, f"{field}[{index}]", errors, warnings)
