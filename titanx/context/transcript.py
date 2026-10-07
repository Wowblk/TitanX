"""Single owner for wholesale transcript replacement.

Before this module the conversation transcript was rewritten wholesale in two
independent places — ``ContextManager.prepare`` (offload) and
``auto_compact_if_needed`` (compaction) — coordinated only by their call order
in ``AgentRuntime._run_loop_inner``. Nothing enforced the invariants that make
a transcript admissible to a provider:

- host-authored pinned system messages must survive every rewrite,
- at most one active summary ``SystemMessage`` may exist at a time,
- an assistant message carrying ``tool_calls`` must stay immediately followed
  by the matching ``tool`` result messages.

``Transcript`` is the one chokepoint both writers go through. ``AgentState``
keeps ``messages`` as a plain list, so every host/test that reads or mutates it
continues to work.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..types import (
    AgentConfig,
    AgentState,
    AssistantMessage,
    Message,
    SystemMessage,
    ToolMessage,
)

SUMMARY_PREFIX = "[Conversation summary so far]\n"


class TranscriptInvariantError(RuntimeError):
    """A proposed transcript would violate the tool-call protocol."""


def is_summary(message: Message) -> bool:
    """Recognise SDK summaries and legacy prefix-only summaries."""
    if not isinstance(message, SystemMessage):
        return False
    return message.is_summary is True or (
        message.is_summary is None and message.content.startswith(SUMMARY_PREFIX)
    )


@dataclass(frozen=True)
class TranscriptCommit:
    """One recorded wholesale replacement."""

    reason: str
    before: int
    after: int


def _check_tool_groups(messages: list[Message]) -> None:
    """Fail closed when an assistant tool declaration is orphaned.

    An assistant message with ``tool_calls`` must be followed immediately by
    one ``tool`` result per declared call id, in declaration order. Anything
    else is the protocol violation OpenAI/Anthropic reject with HTTP 400.
    """
    index, total = 0, len(messages)
    while index < total:
        message = messages[index]
        if isinstance(message, AssistantMessage) and message.tool_calls:
            expected = [call.id for call in message.tool_calls]
            got: list[str] = []
            cursor = index + 1
            while cursor < total and isinstance(messages[cursor], ToolMessage):
                got.append(messages[cursor].tool_call_id)
                cursor += 1
            if got != expected:
                raise TranscriptInvariantError(
                    "assistant tool_calls must be immediately followed by matching tool results"
                )
            index = cursor
        else:
            index += 1


def enforce_invariants(previous: list[Message], proposed: list[Message]) -> list[Message]:
    """Return ``proposed`` with the transcript invariants restored."""
    result = list(proposed)

    # 1. Preserve host-authored pinned (non-summary) system messages. A buggy
    #    writer that forgot the leading instructions must not silently drop the
    #    host's system prompt / pinned context.
    pinned = [m for m in previous if isinstance(m, SystemMessage) and not is_summary(m)]
    present_ids = {m.id for m in result}
    missing = [m for m in pinned if m.id not in present_ids]
    if missing:
        result = [*missing, *result]

    # 2. At most one active summary. When a writer proposes several, keep the
    #    newest (last) — repeated compaction always merges into one.
    summaries = [m for m in result if is_summary(m)]
    if len(summaries) > 1:
        newest = summaries[-1]
        result = [m for m in result if not is_summary(m) or m is newest]

    # 3. Tool-call protocol: never separate a declaration from its results.
    _check_tool_groups(result)
    return result


class Transcript:
    """The single owner of wholesale ``state.messages`` replacement.

    Both ``ContextManager`` (offload) and the compaction pass call
    :meth:`replace`; each successful call is recorded so hosts and tests can
    confirm that a given rewrite went through the owner.
    """

    def __init__(self, config: AgentConfig | None = None) -> None:
        self._config = config
        self._commits: list[TranscriptCommit] = []
        self._closed = False

    @property
    def commits(self) -> tuple[TranscriptCommit, ...]:
        return tuple(self._commits)

    @property
    def commit_count(self) -> int:
        return len(self._commits)

    @property
    def closed(self) -> bool:
        return self._closed

    def replace(self, state: AgentState, messages: list[Message], *, reason: str) -> list[Message]:
        """Commit ``messages`` as the new transcript, enforcing invariants."""
        before = len(state.messages)
        normalized = enforce_invariants(list(state.messages), list(messages))
        state.messages = normalized
        self._commits.append(TranscriptCommit(reason=reason, before=before, after=len(normalized)))
        return normalized

    async def aclose(self) -> None:
        """Flush/close the owner. Idempotent; holds no external resources."""
        self._closed = True
