from __future__ import annotations

import asyncio
import json
import math
from dataclasses import asdict, dataclass, replace
from html import escape

from ..types import AgentConfig, AgentState, ContextOffloadedEvent, ToolDefinition, ToolExecutionResult, ToolMessage
from .store import ContextStore
from .tasks import model_messages
from .transcript import Transcript

CONTEXT_TOOL_NAMES = frozenset({"context_read", "context_search"})


@dataclass
class ContextOptions:
    store: ContextStore
    session_id: str | None = None
    offload_threshold_chars: int = 12000
    preview_chars: int = 800
    read_max_chars: int = 4000
    storage_timeout_seconds: float = 10.0
    capture_task: bool = True

    def __post_init__(self):
        for name in ("offload_threshold_chars", "preview_chars", "read_max_chars"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.preview_chars >= self.offload_threshold_chars:
            raise ValueError("preview must be smaller than offload threshold")
        if self.read_max_chars > 16000:
            raise ValueError("read_max_chars cannot exceed 16000")
        if not math.isfinite(self.storage_timeout_seconds) or self.storage_timeout_seconds <= 0:
            raise ValueError("storage timeout must be positive and finite")
        if self.session_id is not None and (not isinstance(self.session_id, str) or not self.session_id):
            raise ValueError("context session_id must be a nonempty host-owned identifier")


def context_tool_definitions(*, read_max_chars: int = 4000) -> list[ToolDefinition]:
    """Tool contracts for the context tools.

    ``read_max_chars`` must be the effective ``ContextOptions.read_max_chars``
    so ``context_read``'s advertised ``limit`` bound matches what ``execute``
    actually applies (it clamps to that value). It defaults to the
    ``ContextOptions`` default (4000) only for standalone use.
    """
    return [
        ToolDefinition(
            name="context_read",
            description="Read a bounded page of archived message JSON or original tool output in this session. Use next_offset to continue; no tools are re-executed.",
            parameters={"type": "object", "properties": {
                "kind": {"type": "string", "enum": ["message", "artifact"]},
                "id": {"type": "string"}, "offset": {"type": "integer", "minimum": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": read_max_chars},
            }, "required": ["kind", "id"], "additionalProperties": False},
            requires_sanitization=True,
        ),
        ToolDefinition(
            name="context_search",
            description="Search this session's original message JSON with literal text. Results include message_id and character offset for context_read; after is the previous result cursor.",
            parameters={"type": "object", "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 256},
                "after": {"type": "integer", "minimum": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20},
            }, "required": ["query"], "additionalProperties": False},
            requires_sanitization=True,
        ),
    ]


class ContextManager:
    def __init__(self, options: ContextOptions, config: AgentConfig, *, transcript: Transcript | None = None):
        self.options = options
        self.config = config
        # The runtime threads one owner in; standalone construction (tests,
        # embedding) still routes the commit through a private owner.
        self._transcript = transcript or Transcript(config)
        # Message ids already committed to the canonical store. Ids are
        # immutable and archival is ``INSERT OR IGNORE``, so a committed id
        # never needs re-serializing. This turns the per-iteration
        # re-archival of the whole transcript (O(n²) over a session) into an
        # incremental delta. The set only grows for the session's lifetime;
        # it is bounded by the number of distinct ids and reclaimed when the
        # host drops the manager (e.g. gateway session eviction).
        self._archived_ids: set[str] = set()

    async def _wait(self, awaitable):
        return await asyncio.wait_for(awaitable, self.options.storage_timeout_seconds)

    async def archive(self, state: AgentState):
        fresh = [m for m in model_messages(state) if m.id not in self._archived_ids]
        if fresh:
            await self._wait(self.options.store.archive(self.config.session_id, fresh))
            # Mark committed only after the write succeeds, so a timed-out or
            # failed archival is retried on the next call instead of being
            # silently skipped.
            self._archived_ids.update(m.id for m in fresh)
        if state.task:
            await self._wait(self.options.store.save_task(self.config.session_id, state.task))

    async def prepare(self, state: AgentState) -> list[ContextOffloadedEvent]:
        # Canonical, already-inspected outputs are committed before a model view
        # can replace them with references. Commit the view only after all puts.
        await self.archive(state)
        rebuilt, events = [], []
        for message in state.messages:
            if (
                not isinstance(message, ToolMessage) or message.artifact_id
                or message.tool_name in CONTEXT_TOOL_NAMES
                or len(message.content) <= self.options.offload_threshold_chars
            ):
                rebuilt.append(message)
                continue
            artifact_id = await self._wait(self.options.store.put_artifact(self.config.session_id, message.content))
            content = json.dumps({
                "archived_tool_output": artifact_id,
                "original_chars": len(message.content),
                "read_with": {"tool": "context_read", "kind": "artifact", "id": artifact_id, "offset": 0},
                "preview_is_untrusted_data": message.content[:self.options.preview_chars],
            }, ensure_ascii=False)
            if self.config.wrap_tool_output:
                content = (f'<tool_output tool="{escape(message.tool_name, quote=True)}" trust="untrusted">\n'
                           f'{escape(content, quote=False)}\n</tool_output>')
            if len(content) >= len(message.content):
                rebuilt.append(message)
                continue
            rebuilt.append(replace(message, content=content, artifact_id=artifact_id))
            events.append(ContextOffloadedEvent(message.id, artifact_id, len(message.content), len(content)))
        if events:
            self._transcript.replace(state, rebuilt, reason="offload")
        return events

    async def execute(self, name: str, params: dict) -> ToolExecutionResult:
        if name == "context_read":
            if not {"kind", "id"} <= params.keys() or params.keys() - {"kind", "id", "offset", "limit"}:
                raise ValueError("invalid context_read arguments")
            if not isinstance(params["id"], str) or not params["id"]:
                raise ValueError("id must be nonempty text")
            requested = params.get("limit", min(1024, self.options.read_max_chars))
            if type(requested) is not int or requested <= 0:
                raise ValueError("limit must be positive")
            page = await self._wait(self.options.store.read(
                self.config.session_id, params["kind"], params["id"], params.get("offset", 0),
                min(requested, self.options.read_max_chars)))
            return ToolExecutionResult(output=json.dumps(asdict(page), ensure_ascii=False))
        if name == "context_search":
            if "query" not in params or params.keys() - {"query", "after", "limit"}:
                raise ValueError("invalid context_search arguments")
            results = await self._wait(self.options.store.search(
                self.config.session_id, params["query"], params.get("after", 0), params.get("limit", 5)))
            return ToolExecutionResult(output=json.dumps({"matches": results}, ensure_ascii=False))
        raise ValueError("unknown context tool")
