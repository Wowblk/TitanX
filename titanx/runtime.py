from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timezone

from .safety.egress import caller_scope
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
    ToolDefinition,
    ToolMessage,
    ToolRuntime,
    UserMessage,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Mirrors the legacy InputValidator cap. Callers wanting a different bound
# can subclass AgentRuntime or wrap run_prompt; the constant stays here so
# the trust-boundary enforcement is in one place.
_MAX_PROMPT_LENGTH = 100_000


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
        from .policy import AgentPolicy, AuditLog, PolicyStore

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
        # Always have a PolicyStore + AuditLog so every tool call is audited,
        # even when the caller did not configure dynamic policy.
        if policy_store is None:
            policy_store = PolicyStore(
                AgentPolicy(
                    auto_approve_tools=auto_approve_tools,
                    max_iterations=max_iterations,
                ),
                AuditLog(),
            )
        self._policy_store = policy_store
        self._audit_log = policy_store.get_audit_log()
        self._compaction_strategy = compaction_strategy
        self._compaction_options = compaction_options
        self._compaction_tracking = CompactionTracking()

        self._approval_event: asyncio.Event = asyncio.Event()

    # ── Public API ────────────────────────────────────────────────────────────

    async def run_prompt(self, content: str) -> AgentState:
        # Empty / oversized check stays here so it's enforced at the trust
        # boundary regardless of which SafetyLayerLike implementation is
        # plugged in. We deliberately DO NOT call
        # ``self._safety.validator.validate_input`` separately: it would
        # rescan the same patterns ``check_input`` already scanned, doubling
        # the regex work on every prompt for zero added signal. The
        # validator is still used for tool-parameter scanning where the
        # distinction matters.
        if not content:
            raise ValueError("Invalid input: input cannot be empty")
        if len(content) > _MAX_PROMPT_LENGTH:
            raise ValueError(
                f"Invalid input: input exceeds maximum length ({_MAX_PROMPT_LENGTH})"
            )

        input_check = self._safety.check_input(content)
        if not input_check.safe:
            blocked = [v.pattern for v in input_check.violations if v.action == "block"]
            raise ValueError(f"Unsafe input blocked: {', '.join(blocked)}")

        user_msg = UserMessage(role="user", content=input_check.sanitized_content)
        append_message(self.state, user_msg)

        # Reset the per-prompt iteration budget. ``max_iterations`` caps the
        # work this *prompt* triggers, not the lifetime of the session.
        # Without this reset, a long-lived AgentRuntime that has handled
        # N>=max prompts in the past will refuse to take a single LLM turn
        # for the next prompt — silent failure mode in production gateways.
        self.state.iteration = 0
        # Approval allow-list is also per-prompt: an approval granted for
        # a tool_call_id from a previous prompt should not silently
        # auto-approve a re-issued (different id) call this turn. The set
        # gets repopulated as ``approve_pending_tool`` is invoked.
        self.state.approved_tool_call_ids = set()

        from .types import LoopStartEvent
        await self._emit(LoopStartEvent())
        self.state.signal = "continue"
        return await self._run_loop()

    def approve_pending_tool(self) -> None:
        """Approve the currently pending tool call.

        Records the tool_call_id in ``state.approved_tool_call_ids`` so the
        policy decision on resume promotes ``needs_approval`` to ``allow``
        for *this specific* call without globally relaxing the policy.

        Caller must invoke ``resume()`` to actually drain the remaining batch.
        """
        if self.state.pending_approval is not None:
            self.state.approved_tool_call_ids.add(self.state.pending_approval.tool_call_id)
        set_pending_approval(self.state, None)
        self.state.signal = "continue"
        self.state.last_response_type = "none"
        self._approval_event.set()

    def reject_pending_tool(self, reason: str = "Rejected by host") -> None:
        """Reject the currently pending tool call.

        Synthesises an error ``ToolMessage`` for the rejected tool_call_id so
        the LLM-side message protocol stays well-formed (every assistant
        tool_call has a matching tool result), advances the batch cursor
        past the rejected call, and arms ``resume()`` to continue draining
        the remaining tool calls.
        """
        approval = self.state.pending_approval
        if approval is None:
            return

        # Synthesise the error tool result so the protocol is complete.
        i = self.state.pending_tool_call_index
        if i < len(self.state.pending_tool_calls):
            tool_call = self.state.pending_tool_calls[i]
            append_message(
                self.state,
                self._build_tool_message(
                    tool_call,
                    f"Tool call rejected by host: {reason}",
                    True,
                ),
            )
            self.state.pending_tool_call_index = i + 1

        set_pending_approval(self.state, None)
        self.state.signal = "continue"
        self.state.last_response_type = "none"
        self._approval_event.set()

    async def wait_for_approval(self, timeout: float | None = None) -> bool:
        """Block until the current pending approval is resolved.

        Useful for callers that want to coordinate UI workflows
        asynchronously (e.g. a FastAPI WebSocket handler that pushes the
        approval prompt to a browser and awaits the human decision)
        without polling ``state.pending_approval`` on a timer.

        Returns ``True`` when an approval is resolved (approve or reject) —
        or when there is nothing to wait for in the first place — and
        ``False`` if ``timeout`` elapsed before resolution.
        """
        if self.state.pending_approval is None:
            return True
        try:
            if timeout is None:
                await self._approval_event.wait()
            else:
                await asyncio.wait_for(self._approval_event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def resume(self) -> AgentState:
        if self.state.signal != "continue":
            return self.state
        return await self._run_loop()

    # ── Internal loop ─────────────────────────────────────────────────────────

    @property
    def _effective_max_iterations(self) -> int:
        return self._policy_store.get_policy().max_iterations

    @property
    def _effective_auto_approve(self) -> bool:
        return self._policy_store.get_policy().auto_approve_tools

    async def _run_loop(self) -> AgentState:
        from .types import (
            AssistantTextEvent,
            AssistantToolCallsEvent,
            IterationStartEvent,
            LoopEndEvent,
        )

        try:
            return await self._run_loop_inner()
        except asyncio.CancelledError:
            # Cancellation is observable: a host that cancels the task (e.g.
            # gateway client disconnect, request timeout) must be able to
            # tell what state we left behind. We:
            #   1. Mark the loop as interrupted so resume() picks the
            #      cancellation path explicitly rather than silently
            #      continuing.
            #   2. Emit LoopEndEvent(reason="cancelled") so the on_event
            #      hook can do its own cleanup symmetrically with all
            #      other terminal reasons.
            #   3. Re-raise so the caller's task tree learns about the
            #      cancellation — swallowing CancelledError is the
            #      classic asyncio anti-pattern that turns "cancel" into
            #      "the task hangs forever waiting for an event that
            #      will never fire".
            # In-flight tool calls are handled at the tool-execution
            # boundary inside ``_execute_tool_calls`` — by the time we
            # reach this handler, every started tool already has a
            # corresponding ToolMessage in state, so the LLM-side
            # protocol invariant is preserved.
            self.state.signal = "interrupt"
            try:
                await self._emit(LoopEndEvent(reason="cancelled"))
            except Exception:
                pass
            raise

    async def _run_loop_inner(self) -> AgentState:
        from .types import (
            AssistantTextEvent,
            AssistantToolCallsEvent,
            IterationStartEvent,
            LoopEndEvent,
        )

        while self.state.signal != "stop":
            # ── Resume path ──────────────────────────────────────────────────
            # If a previous turn's tool-call batch was paused (e.g. by an
            # approval), drain it BEFORE asking the LLM for another turn.
            # Skipping this would call the LLM with an AssistantMessage that
            # has N tool_calls but only k<N matching ToolMessages — a
            # protocol violation that OpenAI / Anthropic reject with HTTP 400.
            if self._has_in_flight_batch():
                outcome = await self._execute_tool_calls()
                if outcome == "pending_approval":
                    self.state.last_response_type = "need_approval"
                    self.state.signal = "stop"
                    await self._emit(LoopEndEvent(reason="pending_approval"))
                    break
                # Batch fully drained — fall through to next iteration so the
                # LLM gets called with a complete tool-result history.
                self.state.last_response_type = "none"
                continue

            # ── Normal path: a fresh LLM turn ────────────────────────────────
            self.state.iteration += 1
            await self._emit(IterationStartEvent(iteration=self.state.iteration))

            if self.state.iteration > self._effective_max_iterations:
                self.state.signal = "stop"
                await self._emit(LoopEndEvent(reason="max_iterations"))
                break

            # ── Pre-flight compaction ─────────────────────────────────────────
            # Run compaction BEFORE calling the LLM, not after. The historical
            # post-call placement meant the very turn that breached the budget
            # was always shipped — the host paid the latency, the tokens, and
            # often a 400 ``context_length_exceeded`` from the provider before
            # we even got a chance to compact. Pre-flight relies on the
            # *previous* turn's reported ``input_tokens`` (state.last_input_tokens)
            # as the proxy for current context size; on iteration 1 the metric
            # is 0 and the gate naturally no-ops, which is correct because
            # there's no history to compact yet.
            if self._compaction_strategy and self._compaction_options:
                if not await self._maybe_compact():
                    # Exhausted: terminate loop with explicit signal so the host
                    # doesn't keep pumping bigger and bigger contexts at the LLM.
                    self.state.signal = "stop"
                    await self._emit(LoopEndEvent(reason="compaction_exhausted"))
                    break

            turn = await self._llm.respond(self.config, self.state)
            # Two-counter token accounting:
            #   - last_input_tokens: this turn's prompt size, the canonical
            #     "current context" proxy used by compaction triggering.
            #   - total_input_tokens: cumulative across the session, used only
            #     for cost reporting. NEVER feed this into the budget check.
            self.state.last_input_tokens = turn.usage.input_tokens if turn.usage else 0
            self.state.total_input_tokens += (turn.usage.input_tokens if turn.usage else 0)
            self.state.total_output_tokens += (turn.usage.output_tokens if turn.usage else 0)

            if turn.type == "text":
                text = turn.text or ""
                assistant_msg = AssistantMessage(role="assistant", content=text)
                append_message(self.state, assistant_msg)
                self.state.last_response_type = "text"
                self.state.last_text_response = text
                await self._emit(AssistantTextEvent(text=text))
                self.state.signal = "stop"
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
                await self._emit(LoopEndEvent(reason="pending_approval"))
                break

            self.state.last_response_type = "none"

        return self.state

    def _has_in_flight_batch(self) -> bool:
        return self.state.pending_tool_call_index < len(self.state.pending_tool_calls)

    async def _maybe_compact(self) -> bool:
        """Run a pre-flight compaction pass.

        Returns ``False`` if compaction has been exhausted (consecutive
        failures hit the configured ceiling), in which case the caller MUST
        terminate the loop — keeping going would just keep submitting an
        ever-larger context to the LLM until the provider rejects with HTTP
        400. Returns ``True`` for both "did not need to compact" and
        "compacted successfully or failed-but-not-exhausted"; in those
        cases the loop continues normally.
        """
        from .context.compactor import auto_compact_if_needed
        from .types import (
            CompactionExhaustedEvent,
            CompactionFailedEvent,
            CompactionTriggeredEvent,
        )

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
        elif compact.exhausted:
            # Terminal: the host needs to know we are no longer protecting
            # the budget so it can decide between "show degraded mode notice",
            # "rotate to a fresh session", or "fail the request".
            await self._emit(CompactionExhaustedEvent(
                consecutive_failures=compact.tracking.consecutive_failures,
                last_input_tokens=self.state.last_input_tokens,
            ))
            return False
        elif compact.tracking.consecutive_failures > prev_failures:
            await self._emit(CompactionFailedEvent(
                consecutive_failures=compact.tracking.consecutive_failures,
            ))
        return True

    async def _execute_tool_calls(
        self, tool_calls: list[ToolCall] | None = None
    ) -> str:
        """Drive a tool-call batch to completion, cursor-style.

        - When ``tool_calls`` is provided, this is a *fresh* batch from the
          current LLM turn: stash it on state and start at index 0.
        - When ``tool_calls`` is ``None``, this is a *resumption*: continue
          from ``state.pending_tool_call_index`` against
          ``state.pending_tool_calls`` (set by an earlier turn that paused
          for approval).

        Returns ``"pending_approval"`` if execution paused on a tool call
        that requires human approval, otherwise ``"continue"`` once the
        batch has been fully drained.
        """
        from .policy import AuditEntry
        from .types import PendingApprovalEvent, ToolResultEvent

        if tool_calls is not None:
            self.state.pending_tool_calls = list(tool_calls)
            self.state.pending_tool_call_index = 0

        while self.state.pending_tool_call_index < len(self.state.pending_tool_calls):
            i = self.state.pending_tool_call_index
            tool_call = self.state.pending_tool_calls[i]
            tool_def = self._lookup_tool(tool_call.name)

            # ── 1. Parameter validation ──────────────────────────────────────
            validation = self._safety.validator.validate_tool_params(tool_call.args)
            if not validation.is_valid:
                msg = "; ".join(e.message for e in validation.errors)
                await self._audit_tool_decision(
                    tool_call, decision="deny",
                    reason=f"safety validator rejected parameters: {msg}",
                )
                append_message(
                    self.state,
                    self._build_tool_message(tool_call, f"Invalid tool parameters: {msg}", True),
                )
                self.state.pending_tool_call_index = i + 1
                continue

            # ── 2. Policy decision (centralised in PolicyStore) ──────────────
            check = self._policy_store.check_tool_call(tool_call, tool_def)

            # If the host has explicitly approved this specific tool_call_id
            # via approve_pending_tool(), promote needs_approval -> allow.
            if check.decision == "needs_approval" and tool_call.id in self.state.approved_tool_call_ids:
                from .policy import PolicyCheckResult
                check = PolicyCheckResult(
                    decision="allow",
                    reason=f"human-approved via approve_pending_tool (id={tool_call.id})",
                )

            await self._audit_tool_decision(
                tool_call,
                decision=check.decision,
                reason=check.reason,
            )

            if check.decision == "deny":
                append_message(
                    self.state,
                    self._build_tool_message(
                        tool_call,
                        f"Tool call denied by policy: {check.reason}",
                        True,
                    ),
                )
                await self._emit(ToolResultEvent(
                    tool_name=tool_call.name,
                    tool_call_id=tool_call.id,
                    is_error=True,
                ))
                self.state.pending_tool_call_index = i + 1
                continue

            if check.decision == "needs_approval":
                approval = PendingApproval(
                    tool_name=tool_call.name,
                    tool_call_id=tool_call.id,
                    parameters=tool_call.args,
                    requires_always=True,
                )
                set_pending_approval(self.state, approval)
                # Reset the approval event so wait_for_approval() blocks until
                # *this* approval is resolved by approve_/reject_pending_tool.
                # Without clear() the event would stay set from any prior
                # resolution and wait_for_approval() would return immediately.
                self._approval_event.clear()
                await self._emit(PendingApprovalEvent(approval=approval))
                # Cursor stays at i so resume picks up the same call.
                return "pending_approval"

            # ── 3. Execution + tool-output safety + post-execution audit ─────
            # Cancellation handling: if the host cancels (gateway client
            # disconnect, request timeout, etc.) WHILE a tool is running,
            # we MUST still close the protocol — the assistant message
            # already declared this tool_call.id, and shipping it to the
            # LLM next turn without a matching ToolMessage is the same
            # HTTP 400 we fixed in Q2. So we synthesise a placeholder
            # ToolMessage, advance the cursor past the cancelled call,
            # mark the loop interrupted, and re-raise. The next
            # ``resume()`` sees a consistent message stream; the host
            # can also choose to drop the runtime entirely.
            #
            # ``caller_scope`` binds the dispatched tool's name as the
            # ambient caller for any ``EgressGuard`` check inside the
            # handler (or anything the handler awaits transitively).
            # Tool authors no longer need to thread ``caller=`` through
            # to ``guard.enforce(...)``: forgetting it used to silently
            # collapse the call into "no caller", which a preset pinned
            # to that same tool name would correctly reject. The
            # contextvar is unwound in ``finally`` so a raise (including
            # ``CancelledError``) cannot leak the binding into sibling
            # tool calls.
            try:
                with caller_scope(tool_call.name):
                    result = await self._tools.execute(tool_call.name, tool_call.args)
            except asyncio.CancelledError:
                append_message(
                    self.state,
                    self._build_tool_message(
                        tool_call,
                        "Tool execution was cancelled before completion.",
                        True,
                    ),
                )
                self.state.pending_tool_call_index = i + 1
                self.state.signal = "interrupt"
                # Best-effort audit so cancellation is observable in the
                # forensic trail. Wrapped in try/except because we are in
                # a cancellation cleanup path — failing to audit must not
                # mask the original CancelledError.
                try:
                    await self._audit_log.append(AuditEntry(
                        timestamp=_now_iso(),
                        event="tool_invocation",
                        actor="agent",
                        reason=check.reason,
                        tool_name=tool_call.name,
                        tool_call_id=tool_call.id,
                        decision=check.decision,
                        is_error=True,
                        details={
                            "args_keys": sorted(tool_call.args.keys()),
                            "cancelled": True,
                        },
                    ))
                except Exception:
                    pass
                raise

            # Indirect prompt injection / tool-output poisoning defence:
            # we ALWAYS scan the output regardless of the per-tool
            # ``requires_sanitization`` flag. That flag now only gates
            # PII redaction (which rewrites structured data and would
            # otherwise create false positives for JSON/CSV-shaped tool
            # outputs). Injection scan is non-mutating unless a
            # ``block``-action pattern fires, in which case the content
            # is replaced with a placeholder before the LLM sees it.
            redact_pii = bool(tool_def and tool_def.requires_sanitization)
            inspection = self._safety.inspect_tool_output(
                tool_call.name, result.output, redact_pii=redact_pii,
            )
            content = inspection.content
            is_error = result.error is not None or inspection.blocked

            audit_details: dict[str, object] = {
                "error": result.error,
                "args_keys": sorted(tool_call.args.keys()),
            }
            if inspection.violations:
                audit_details["output_violations"] = [
                    {"pattern": v.pattern, "action": v.action}
                    for v in inspection.violations
                ]
            if inspection.blocked:
                audit_details["output_blocked"] = True
                audit_details["original_output_length"] = len(result.output)
            if inspection.redacted_count:
                audit_details["pii_redacted_count"] = inspection.redacted_count

            await self._audit_log.append(AuditEntry(
                timestamp=_now_iso(),
                event="tool_invocation",
                actor="agent",
                reason=check.reason,
                tool_name=tool_call.name,
                tool_call_id=tool_call.id,
                decision=check.decision,
                is_error=is_error,
                details=audit_details,
            ))

            append_message(
                self.state,
                self._build_tool_message(tool_call, content, is_error),
            )
            await self._emit(ToolResultEvent(
                tool_name=tool_call.name,
                tool_call_id=tool_call.id,
                is_error=is_error,
            ))
            self.state.pending_tool_call_index = i + 1

        # Batch drained — clear the queue so a future resume() doesn't loop.
        self.state.pending_tool_calls = []
        self.state.pending_tool_call_index = 0
        return "continue"

    def _lookup_tool(self, name: str) -> ToolDefinition | None:
        return next((t for t in self.config.available_tools if t.name == name), None)

    async def _audit_tool_decision(
        self,
        tool_call: ToolCall,
        *,
        decision: str,
        reason: str,
    ) -> None:
        from .policy import AuditEntry

        await self._audit_log.append(AuditEntry(
            timestamp=_now_iso(),
            event="tool_decision",
            actor="host",
            reason=reason,
            tool_name=tool_call.name,
            tool_call_id=tool_call.id,
            decision=decision,  # type: ignore[arg-type]
            details={"args_keys": sorted(tool_call.args.keys())},
        ))

    def _build_tool_message(self, tool_call: ToolCall, content: str, is_error: bool) -> ToolMessage:
        if self.config.wrap_tool_output:
            # Structural marker so the LLM has an explicit cue that this
            # body is *data*, not *instructions*. Effective only when the
            # system prompt carries a corresponding directive — see
            # ``AgentConfig.wrap_tool_output`` docstring.
            content = (
                f'<tool_output tool="{tool_call.name}" trust="untrusted">\n'
                f"{content}\n"
                f"</tool_output>"
            )
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
