"""Explicit context-recovery state (design review §3.2).

``AgentRuntime`` used to carry the recovery disposition in two loose private
flags (``_context_stop_reason`` and ``_context_completion_pending``) read and
written at eleven scattered sites — a hidden second state machine layered on
``AgentState.signal``.  ``ContextRecovery`` centralises the transitions behind
named methods and answers the single decision ``retry_context`` actually needs:
*which* recovery mode is required.

These tests pin the decision table (stop reason x archive outcome -> mode), not
the private storage, so the field layout can change freely.
"""
from __future__ import annotations

from titanx.context.recovery import ContextRecovery


def test_fresh_recovery_is_not_stopped() -> None:
    recovery = ContextRecovery()

    assert recovery.mode == "none"
    assert recovery.stopped is False
    assert recovery.archive_blocked is False


def test_preflight_stop_needs_a_full_resume() -> None:
    recovery = ContextRecovery()

    recovery.stop("context_budget_exceeded")

    assert recovery.mode == "full"
    assert recovery.stopped is True
    assert recovery.archive_blocked is False


def test_storage_failure_without_a_pending_answer_needs_a_full_resume() -> None:
    recovery = ContextRecovery()

    recovery.stop("context_storage_failed")

    assert recovery.mode == "full"
    assert recovery.stopped is True
    assert recovery.archive_blocked is True


def test_failed_final_archive_of_a_completed_turn_retries_storage_only() -> None:
    recovery = ContextRecovery()

    recovery.stop("context_storage_failed")
    recovery.note_archive_failure(answer_pending=True)

    assert recovery.mode == "archive_only"


def test_failed_archive_without_a_completed_answer_needs_a_full_resume() -> None:
    recovery = ContextRecovery()

    recovery.note_archive_failure(answer_pending=False)
    recovery.stop("context_storage_failed")

    assert recovery.mode == "full"


def test_clear_returns_to_the_fresh_state() -> None:
    recovery = ContextRecovery()
    recovery.stop("context_storage_failed")
    recovery.note_archive_failure(answer_pending=True)

    recovery.clear()

    assert recovery.mode == "none"
    assert recovery.stopped is False


def test_clearing_completion_keeps_the_stop_reason() -> None:
    recovery = ContextRecovery()
    recovery.stop("context_storage_failed")
    recovery.note_archive_failure(answer_pending=True)

    recovery.clear_completion()

    assert recovery.mode == "full"
    assert recovery.archive_blocked is True


def test_stop_reason_and_archive_outcome_are_independent() -> None:
    recovery = ContextRecovery()
    recovery.stop("context_storage_failed")
    recovery.note_archive_failure(answer_pending=True)

    # A later stop overwrites only the reason; the pending answer disposition
    # (which selects archive-only repair) must survive it.
    recovery.stop("compaction_exhausted")

    assert recovery.mode == "archive_only"
    assert recovery.archive_blocked is False
