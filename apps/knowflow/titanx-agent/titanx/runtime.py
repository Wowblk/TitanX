from __future__ import annotations

import asyncio
import inspect
import json
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
        self.state.iteration = 0
        self.state.signal = "continue"
        return await self._run_loop()

    def approve_pending_tool(self) -> None:
        set_pending_approval(self.state, None)
        self.state.signal = "continue"
        self.state.last_response_type = "none"
        self._approval_event.set()

    def set_hooks(self, hooks: RuntimeHooks) -> None:
        self._hooks = hooks

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
            if outcome == "stop":
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
            if tool_def and tool_def.metadata.get("return_direct") and not is_error:
                from .types import AssistantTextEvent, LoopEndEvent

                text = self._direct_tool_response(tool_call.name, content)
                assistant_msg = AssistantMessage(role="assistant", content=text)
                append_message(self.state, assistant_msg)
                self.state.last_response_type = "text"
                self.state.last_text_response = text
                self.state.signal = "stop"
                await self._emit(AssistantTextEvent(text=text))
                await self._emit(LoopEndEvent(reason="completed"))
                return "stop"

        return "continue"

    def _direct_tool_response(self, tool_name: str, content: str) -> str:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = {}

        if tool_name == "knowflow_search_posts":
            items = data.get("items") or []
            if not items:
                return "没有找到相关知文。你可以换一个关键词再试。"
            lines = ["找到这些相关知文："]
            for item in items[:5]:
                title = item.get("title") or "未命名知文"
                post_id = item.get("id") or ""
                description = item.get("description") or ""
                suffix = f"：{description}" if description else ""
                lines.append(f"- {title}（ID：{post_id}）{suffix}")
            return "\n".join(lines)

        if tool_name == "knowflow_get_my_posts":
            items = data.get("items") or []
            if not items:
                return "你目前没有已发布的知文。草稿不会出现在“已发布内容”列表里。"
            lines = ["你已发布的知文有："]
            for item in items[:10]:
                title = item.get("title") or "未命名知文"
                post_id = item.get("id") or ""
                description = item.get("description") or ""
                suffix = f"：{description}" if description else ""
                lines.append(f"- {title}（ID：{post_id}）{suffix}")
            return "\n".join(lines)

        if tool_name == "knowflow_get_post_detail":
            title = data.get("title") or "未命名知文"
            post_id = data.get("id") or ""
            description = data.get("description") or "暂无摘要"
            tags = data.get("tags") or []
            tag_text = "、".join(tags) if tags else "无标签"
            return f"{title}（ID：{post_id}）\n摘要：{description}\n标签：{tag_text}"

        if tool_name == "knowflow_create_draft":
            draft_id = data.get("draftId")
            if draft_id:
                return f"草稿已创建成功，草稿 ID：{draft_id}。你可以到创作/我的草稿里继续编辑。"
            return "草稿已创建成功。你可以到创作/我的草稿里继续编辑。"
        return content

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
