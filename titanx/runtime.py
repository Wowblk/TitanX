from __future__ import annotations

import asyncio
import inspect
from uuid import uuid4

from .state import append_message, create_config, create_initial_state, set_pending_approval
from .types import (
    AgentConfig,
    AgentState,
    AssistantMessage,
    LlmAdapter,
    PendingApproval,
    RuntimeEvent,
    RuntimeHooks,
    SafetyLayerLike,
    ToolCall,
    ToolMessage,
    ToolRuntime,
    UserMessage,
)


def _msg_id() -> str:
    return str(uuid4())


class AgentRuntime:
    def __init__(
        self,
        llm: LlmAdapter,
        tools: ToolRuntime,
        safety: SafetyLayerLike,
        *,
        user_id: str = "default",
        channel: str = "repl",
        system_prompt: str = "",
        max_iterations: int = 10,
        auto_approve_tools: bool = False,
        hooks: RuntimeHooks | None = None,
        policy_store=None,
        compaction_strategy=None,
        compaction_options=None,
    ) -> None:
        from .context.compactor import CompactionTracking

        available_tools = tools.list_tools()
        self.config: AgentConfig = create_config(
            user_id=user_id,
            channel=channel,
            system_prompt=system_prompt,
            available_tools=available_tools,
            max_iterations=max_iterations,
            auto_approve_tools=auto_approve_tools,
        )
        self.state: AgentState = create_initial_state()

        self._llm = llm
        self._tools = tools
        self._safety = safety
        self._hooks = hooks or RuntimeHooks()
        self._policy_store = policy_store
        self._compaction_strategy = compaction_strategy
        self._compaction_options = compaction_options
        self._compaction_tracking = CompactionTracking()

        self._approval_event: asyncio.Event = asyncio.Event()

    # ── Public API ────────────────────────────────────────────────────────────

    async def run_prompt(self, content: str) -> AgentState:
        input_check = self._safety.check_input(content)
        if not input_check.safe:
            blocked = [v.pattern for v in input_check.violations if v.action == "block"]
            raise ValueError(f"Unsafe input blocked: {', '.join(blocked)}")

        validation = self._safety.validator.validate_input(content, "input")
        if not validation.is_valid:
            issues = "; ".join(f"{e.field}: {e.message}" for e in validation.errors)
            raise ValueError(f"Invalid input: {issues}")

        user_msg = UserMessage(role="user", content=input_check.sanitized_content)
        append_message(self.state, user_msg)

        from .types import LoopStartEvent
        await self._emit(LoopStartEvent())
        self.state.signal = "continue"
        return await self._run_loop()

    def approve_pending_tool(self) -> None:
        set_pending_approval(self.state, None)
        self.state.signal = "continue"
        self.state.last_response_type = "none"
        self._approval_event.set()

    async def resume(self) -> AgentState:
        if self.state.signal != "continue":
            return self.state
        return await self._run_loop()

    # ── Internal loop ─────────────────────────────────────────────────────────

    @property
    def _effective_max_iterations(self) -> int:
        if self._policy_store:
            return self._policy_store.get_policy().max_iterations
        return self.config.max_iterations

    @property
    def _effective_auto_approve(self) -> bool:
        if self._policy_store:
            return self._policy_store.get_policy().auto_approve_tools
        return self.config.auto_approve_tools

    async def _run_loop(self) -> AgentState:
        from .types import (
            AssistantTextEvent,
            AssistantToolCallsEvent,
            CompactionFailedEvent,
            CompactionTriggeredEvent,
            IterationStartEvent,
            LoopEndEvent,
        )
        from .context.compactor import auto_compact_if_needed

        while self.state.signal != "stop":
            self.state.iteration += 1
            await self._emit(IterationStartEvent(iteration=self.state.iteration))

            if self.state.iteration > self._effective_max_iterations:
                self.state.signal = "stop"
                await self._emit(LoopEndEvent(reason="max_iterations"))
                break

            turn = await self._llm.respond(self.config, self.state)
            self.state.total_input_tokens += (turn.usage.input_tokens if turn.usage else 0)
            self.state.total_output_tokens += (turn.usage.output_tokens if turn.usage else 0)

            if self._compaction_strategy and self._compaction_options:
                prev_failures = self._compaction_tracking.consecutive_failures
                compact = await auto_compact_if_needed(
                    self.state,
                    self._compaction_strategy,
                    self._compaction_options,
                    self._compaction_tracking,
                )
                self._compaction_tracking = compact.tracking
                if compact.was_compacted and compact.result:
                    await self._emit(CompactionTriggeredEvent(
                        summary=compact.result.summary,
                        ptl_attempts=compact.result.ptl_attempts,
                    ))
                elif not compact.was_compacted and compact.tracking.consecutive_failures > prev_failures:
                    await self._emit(CompactionFailedEvent(
                        consecutive_failures=compact.tracking.consecutive_failures,
                    ))

            if turn.type == "text":
                text = turn.text or ""
                assistant_msg = AssistantMessage(role="assistant", content=text)
                append_message(self.state, assistant_msg)
                self.state.last_response_type = "text"
                self.state.last_text_response = text
                await self._emit(AssistantTextEvent(text=text))
                self.state.signal = "stop"
                from .types import LoopEndEvent
                await self._emit(LoopEndEvent(reason="completed"))
                break

            tool_calls = turn.tool_calls or []
            assistant_msg = AssistantMessage(
                role="assistant",
                content=turn.text or "",
                tool_calls=tool_calls,
            )
            append_message(self.state, assistant_msg)
            self.state.last_response_type = "tool_calls"
            await self._emit(AssistantToolCallsEvent(tool_calls=tool_calls))

            outcome = await self._execute_tool_calls(tool_calls)
            if outcome == "pending_approval":
                self.state.last_response_type = "need_approval"
                self.state.signal = "stop"
                from .types import LoopEndEvent
                await self._emit(LoopEndEvent(reason="pending_approval"))
                break

            self.state.last_response_type = "none"

        return self.state

    async def _execute_tool_calls(
        self, tool_calls: list[ToolCall]
    ) -> str:
        from .types import PendingApprovalEvent, ToolResultEvent

        for tool_call in tool_calls:
            tool_def = next(
                (t for t in self.config.available_tools if t.name == tool_call.name), None
            )
            validation = self._safety.validator.validate_tool_params(tool_call.args)
            if not validation.is_valid:
                msg = "; ".join(e.message for e in validation.errors)
                append_message(self.state, self._build_tool_message(tool_call, f"Invalid tool parameters: {msg}", True))
                continue

            if tool_def and tool_def.requires_approval and not self._effective_auto_approve:
                approval = PendingApproval(
                    tool_name=tool_call.name,
                    tool_call_id=tool_call.id,
                    parameters=tool_call.args,
                    requires_always=True,
                )
                set_pending_approval(self.state, approval)
                await self._emit(PendingApprovalEvent(approval=approval))
                return "pending_approval"

            result = await self._tools.execute(tool_call.name, tool_call.args)
            content = result.output
            if tool_def and tool_def.requires_sanitization:
                content = self._safety.sanitize_tool_output(tool_call.name, result.output)["content"]
            is_error = result.error is not None
            append_message(self.state, self._build_tool_message(tool_call, content, is_error))
            await self._emit(ToolResultEvent(
                tool_name=tool_call.name,
                tool_call_id=tool_call.id,
                is_error=is_error,
            ))

        return "continue"

    def _build_tool_message(self, tool_call: ToolCall, content: str, is_error: bool) -> ToolMessage:
        return ToolMessage(
            role="tool",
            tool_name=tool_call.name,
            tool_call_id=tool_call.id,
            content=content,
            is_error=is_error,
        )

    async def _emit(self, event: RuntimeEvent) -> None:
        if self._hooks.on_event:
            result = self._hooks.on_event(event, self.config, self.state)
            if inspect.isawaitable(result):
                await result
