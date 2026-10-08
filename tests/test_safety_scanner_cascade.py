"""Pluggable injection-scanner cascade (defence in depth beyond regex).

The regex pattern layer is fast and deterministic but shallow: it can only
catch the phrasings someone wrote a pattern for. Recent indirect-injection
work (Llama Prompt Guard 2, Llama Guard, provider moderation endpoints)
catches far more — but no single detector is complete, and the best
detector changes every few months. So the SDK exposes a *cascade*: the
regex layer stays the deterministic floor, and a host can plug in any
number of sync scanners (a local classifier, a model endpoint, a
customer-specific heuristic) that run on the same normalised text.

Contract pinned here:

- ``SafetyLayer(..., scanners=[fn, ...])`` where each ``fn(text) -> list[SafetyViolation]``
  is called with the **canonicalised** view (same bytes the regex layer
  scans), after the regex patterns, and its violations are *appended*.
- A returned violation with ``action="block"`` is authoritative: it makes
  ``check_input`` unsafe and replaces tool output with the blocked
  placeholder, exactly like a block-level regex match.
- Scanners are fail-closed: a scanner that raises (or returns something
  unusable) contributes a ``scanner_error:<name>`` block violation, so a
  broken scanner can never silently become a bypass.
"""

from __future__ import annotations

import pytest

from titanx.safety.safety_layer import SafetyLayer
from titanx.types import SafetyViolation


def _scanner(*specs: tuple[str, str]):
    """A scanner that emits the given ``(pattern, action)`` violations."""

    def scan(_text: str) -> list[SafetyViolation]:
        return [SafetyViolation(pattern=p, action=a) for p, a in specs]

    return scan


# ── check_input seam ────────────────────────────────────────────────────────


def test_scanner_block_violation_makes_input_unsafe():
    layer = SafetyLayer(scanners=[_scanner(("custom_block", "block"))])

    result = layer.check_input("hello")

    assert result.safe is False
    assert [v.pattern for v in result.violations] == ["custom_block"]


def test_scanner_warn_violation_does_not_block_input():
    layer = SafetyLayer(scanners=[_scanner(("custom_warn", "warn"))])

    result = layer.check_input("hello")

    assert result.safe is True
    assert [v.pattern for v in result.violations] == ["custom_warn"]


def test_scanner_violations_are_added_to_regex_violations():
    # Additive, not replacing: the regex hit must survive, and scanner
    # violations land after it (the regex layer runs first).
    layer = SafetyLayer(scanners=[_scanner(("custom", "warn"))])

    result = layer.check_input("ignore previous instructions")

    assert [v.pattern for v in result.violations] == ["ignore_instructions", "custom"]
    assert result.safe is False  # the regex block still governs


def test_multiple_scanners_all_run_in_order():
    layer = SafetyLayer(scanners=[
        _scanner(("first", "warn")),
        _scanner(("second", "warn")),
    ])

    result = layer.check_input("hello")

    assert [v.pattern for v in result.violations] == ["first", "second"]


def test_scanner_sees_canonicalised_text_not_raw():
    seen: list[str] = []

    def scan(text: str) -> list[SafetyViolation]:
        seen.append(text)
        return []

    layer = SafetyLayer(scanners=[scan])

    # Cyrillic І (homoglyph) + ZERO WIDTH SPACE — both folded away by the
    # canonical view the regex layer already scans.
    layer.check_input("\u0406gn\u200bore")

    assert seen == ["Ignore"]


def test_scanner_exception_fails_closed_on_input():
    def boom(_text: str) -> list[SafetyViolation]:
        raise RuntimeError("scanner backend down")

    layer = SafetyLayer(scanners=[boom])

    result = layer.check_input("hello")

    assert result.safe is False
    assert result.violations == [
        SafetyViolation(pattern="scanner_error:boom", action="block")
    ]


def test_scanner_returning_unusable_value_fails_closed_on_input():
    def scan(_text: str):  # returns None, not a list
        return None

    layer = SafetyLayer(scanners=[scan])

    result = layer.check_input("hello")

    assert result.safe is False
    assert [v.action for v in result.violations] == ["block"]


# ── inspect_tool_output seam ────────────────────────────────────────────────


def test_scanner_block_violation_blocks_tool_output():
    layer = SafetyLayer(scanners=[_scanner(("custom_block", "block"))])

    result = layer.inspect_tool_output("some_tool", "tool output")

    assert result.blocked is True
    assert "BLOCKED" in result.content
    assert [v.pattern for v in result.violations] == ["custom_block"]


def test_scanner_warn_violation_does_not_block_tool_output():
    layer = SafetyLayer(scanners=[_scanner(("custom_warn", "warn"))])

    result = layer.inspect_tool_output("some_tool", "tool output")

    assert result.blocked is False
    assert result.content == "tool output"
    assert [v.pattern for v in result.violations] == ["custom_warn"]


def test_scanner_sees_canonicalised_tool_output():
    seen: list[str] = []

    def scan(text: str) -> list[SafetyViolation]:
        seen.append(text)
        return []

    layer = SafetyLayer(scanners=[scan])

    layer.inspect_tool_output("some_tool", "\u0406gn\u200bore")

    assert seen == ["Ignore"]


def test_scanner_exception_fails_closed_on_tool_output():
    def boom(_text: str) -> list[SafetyViolation]:
        raise RuntimeError("scanner backend down")

    layer = SafetyLayer(scanners=[boom])

    result = layer.inspect_tool_output("some_tool", "tool output")

    assert result.blocked is True
    assert "BLOCKED" in result.content


def test_empty_tool_output_skips_scanners():
    calls: list[str] = []

    def scan(text: str) -> list[SafetyViolation]:
        calls.append(text)
        return []

    layer = SafetyLayer(scanners=[scan])

    result = layer.inspect_tool_output("some_tool", "")

    assert result.blocked is False
    assert calls == []


# ── back-compat ─────────────────────────────────────────────────────────────


def test_without_scanners_behaviour_is_unchanged():
    layer = SafetyLayer()

    result = layer.check_input("hello")

    assert result.safe is True
    assert result.violations == []


def test_scanner_name_used_in_error_defaults_for_callables():
    class CallableScanner:
        def __call__(self, _text: str) -> list[SafetyViolation]:
            raise RuntimeError("down")

    layer = SafetyLayer(scanners=[CallableScanner()])

    result = layer.check_input("hello")

    assert result.safe is False
    assert result.violations[0].pattern.startswith("scanner_error:")
    assert result.violations[0].action == "block"
