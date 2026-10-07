from __future__ import annotations

import asyncio
import copy
import inspect
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from dataclasses import replace
from html import escape

from .safety.egress import caller_scope
from .policy.execution import ExecutionAuthorizationError, ExecutionGuard, ExecutionGuardOptions
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
    TaskState,
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
        wrap_tool_output: bool = False,
        max_output_tokens: int | None = None,
        hooks: RuntimeHooks | None = None,
        policy_store=None,
        compaction_strategy=None,
        compaction_options=None,
        context_options=None,
        execution_guard_options: ExecutionGuardOptions | None = None,
    ) -> None:
        from .context.compactor import CompactionTracking
        from .policy import AgentPolicy, AuditLog, PolicyStore

        available_tools = list(tools.list_tools())
        injected_context_tools: list[str] = []
        if context_options is not None:
            from .context.manager import CONTEXT_TOOL_NAMES, context_tool_definitions
            if any(tool.name in CONTEXT_TOOL_NAMES for tool in available_tools):
                raise ValueError("context_read and context_search are reserved when context management is enabled")
            context_definitions = context_tool_definitions(
                read_max_chars=context_options.read_max_chars
            )
            injected_context_tools = [
                definition.name for definition in context_definitions
            ]
            available_tools.extend(context_definitions)
        self.config: AgentConfig = create_config(
            user_id=user_id,
            channel=channel,
            system_prompt=system_prompt,
            available_tools=available_tools,
            max_iterations=max_iterations,
            auto_approve_tools=auto_approve_tools,
            wrap_tool_output=wrap_tool_output,
            max_output_tokens=max_output_tokens,
        )
        self.state: AgentState = create_initial_state()
        if context_options is not None and context_options.session_id is not None:
            self.config = replace(self.config, session_id=context_options.session_id)

        self._llm = llm
        self._tools = tools
        self._safety = safety
        self._hooks = hooks or RuntimeHooks()
        # Request-specific hooks must not be stored by assignment on the
        # runtime: long-lived gateway sessions reuse this object and sibling
        # asyncio tasks would overwrite one another.  ContextVar gives each
        # task (and nested resume() calls in that task) an isolated binding,
        # while constructor hooks remain the default outside a scope.
        self._scoped_runtime_hooks: ContextVar[RuntimeHooks | None] = ContextVar(
            f"titanx_runtime_hooks_{id(self)}",
            default=None,
        )
        # Always have a PolicyStore + AuditLog so every tool call is audited,
        # even when the caller did not configure dynamic policy.
        if policy_store is None:
            # The runtime itself injects the context tools, so it also
            # authorises them on the deny-by-default allowlist. Host tools are
            # deliberately *not* seeded: the host must opt them in explicitly.
            policy_store = PolicyStore(
                AgentPolicy(
                    auto_approve_tools=auto_approve_tools,
                    max_iterations=max_iterations,
                    tool_allowlist=list(injected_context_tools),
                ),
                AuditLog(),
            )
        self._policy_store = policy_store
        self._audit_log = policy_store.get_audit_log()
        self._execution_guard = ExecutionGuard(policy_store, available_tools, execution_guard_options)
        self._active_execution = False
        self._approval_resume_task: asyncio.Task | None = None
        self._compaction_strategy = compaction_strategy
        self._compaction_options = compaction_options
        if compaction_options is not None:
            from .context.tokens import estimate_input_tokens
            if compaction_options.token_estimator is estimate_input_tokens:
                def count_current_input(config, messages):
                    counter = getattr(self._llm, "count_input_tokens", None)
                    count = counter(config, messages) if counter else None
                    return estimate_input_tokens(config, messages) if count is None else count
                self._compaction_options = replace(compaction_options, token_estimator=count_current_input)
        # One owner for wholesale transcript replacement, shared by offload
        # (ContextManager) and compaction so neither can silently violate the
        # pinned-message / single-summary / tool-group invariants.
        from .context.transcript import Transcript
        self._transcript = Transcript(self.config)
        self._context_manager = None
        if context_options is not None:
            from .context.manager import ContextManager
            self._context_manager = ContextManager(context_options, self.config, transcript=self._transcript)
            if compaction_options is not None and compaction_strategy is None:
                from .context.summary import LlmCompactionStrategy
                self._compaction_strategy = LlmCompactionStrategy(llm)
        self._compaction_tracking = CompactionTracking()
        self._context_stop_reason: str | None = None
        self._context_completion_pending = False
        self._closed = False

        # ``reject_pending_tool`` intentionally stays synchronous for host/UI
        # compatibility. Its ToolMessage is committed immediately, while the
        # audit + RuntimeEvent side effects are queued here and flushed at the
        # start of the next ``_run_loop`` (normally ``resume()``).
        self._pending_host_rejections: list[tuple[str, str, str]] = []

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def transcript(self):
        """The single owner of wholesale transcript replacement."""
        return self._transcript

    async def aclose(self) -> None:
        """Tear down this runtime's session-scoped resources.

        Idempotent and never raises. Flushes the transcript owner with a final
        archive when context management is enabled, tears down the tool layer
        (sandbox sessions) when it supports it, and deletes this session's rows
        from the context store so evicted sessions cannot leak on disk.
        """
        if self._closed:
            return
        self._closed = True

        if self._context_manager is not None:
            try:
                await self._context_manager.archive(self.state)
            except Exception:
                pass
        try:
            await self._transcript.aclose()
        except Exception:
            pass

        closer = getattr(self._tools, "aclose", None)
        if closer is not None:
            try:
                result = closer()
                if inspect.isawaitable(result):
                    await result
            except Exception:
                pass

        store = self._context_manager.options.store if self._context_manager is not None else None
        delete_session = getattr(store, "delete_session", None)
        if delete_session is not None:
            try:
                await delete_session(self.config.session_id)
            except Exception:
                pass

    def set_task(
        self, objective: str, *, constraints=(), acceptance_criteria=(), new_task: bool = False,
        source_message_ids=(),
    ) -> TaskState:
        """Set or explicitly revise the host-owned task; never changes approvals.

        Call before run_prompt when the user's goal changes. New conversation
        messages alone cannot safely tell the SDK which constraints to revoke.
        Like run_prompt, hosts must serialize this method with active execution.
        """
        if self.state.pending_approval is not None or self.state.pending_tool_calls:
            raise RuntimeError("finish the pending tool batch before changing the task")
        previous = None if new_task else self.state.task
        task = TaskState(objective=objective, constraints=constraints, acceptance_criteria=acceptance_criteria,
                         source_message_ids=source_message_ids)
        if previous is not None:
            task = replace(task, id=previous.id, revision=previous.revision + 1)
        self.state.task = task
        return task

    async def retry_context(self, *, hooks: RuntimeHooks | None = None) -> AgentState:
        """After fixing a context/storage problem, retry without replaying tools.

        This is an explicit host recovery action, not an automatic retry loop.
        Existing approval requirements remain in force.
        """
        if self._context_stop_reason is None:
            raise RuntimeError("runtime is not stopped by a context failure")
        if self._context_completion_pending:
            # The answer already exists. Repair only its failed final archive;
            # requesting another model turn could cause duplicate work.
            with self.scoped_hooks(hooks):
                self._context_stop_reason = None
                await self._finish_loop("completed")
                return self.state
        if self.state.pending_approval is not None:
            raise RuntimeError("resolve pending approval before retrying context")
        from .context.types import CompactionTracking
        self._compaction_tracking = CompactionTracking()
        self._context_stop_reason = None
        self.state.iteration = 0
        self.state.signal = "continue"
        return await self.resume(hooks=hooks)

    @contextmanager
    def scoped_hooks(self, hooks: RuntimeHooks | None) -> Iterator[None]:
        """Bind hooks to the current async task for the duration of a run.

        The binding is context-local rather than an attribute assignment, so
        overlapping tasks cannot redirect each other's events. ``None`` keeps
        the surrounding binding (or the constructor default) unchanged.
        Runtime state is still mutable and must be serialised by the host; the
        gateway does that with ``SessionEntry.lock``.
        """
        if hooks is None:
            yield
            return

        token = self._scoped_runtime_hooks.set(hooks)
        try:
            yield
        finally:
            self._scoped_runtime_hooks.reset(token)

    async def run_prompt(
        self,
        content: str,
        *,
        hooks: RuntimeHooks | None = None,
    ) -> AgentState:
        """Start a new user turn after any previous tool batch is finished.

        Raises ``RuntimeError`` without changing the conversation if approval
        is pending or a tool batch still needs to be resumed. Resolve the
        approval and await ``resume()`` before submitting another prompt.
        Rejected prompts are not queued. Overlapping run/resume calls on the
        same event loop are rejected before changing state.
        """
        with self._exclusive_execution(), self.scoped_hooks(hooks):
            return await self._run_prompt(content)

    @contextmanager
    def _exclusive_execution(self, *, resume: bool = False) -> Iterator[None]:
        if self._active_execution:
            # Existing gateway hooks wait for approval at loop_end and resume
            # in the same task. That outer loop is paused, not a second runner.
            if resume and self._approval_resume_task is asyncio.current_task():
                previous = self._approval_resume_task
                self._approval_resume_task = None
                try:
                    yield
                finally:
                    self._approval_resume_task = previous
                return
            raise RuntimeError("this runtime is already executing; await the active run before run_prompt/resume")
        self._active_execution = True
        try:
            yield
        finally:
            self._active_execution = False

    async def _run_prompt(self, content: str) -> AgentState:
        # Check before input processing, history writes, budget resets, or
        # hooks. An approval helper clears pending_approval but leaves the
        # batch for resume(); even an exhausted rejection cursor still needs
        # its audit/event publication and the original turn's completion.
        if self.state.pending_approval is not None or self.state.pending_tool_calls:
            raise RuntimeError(
                "Cannot start a new prompt while a tool-call batch is unfinished. "
                "Resolve any pending approval and call resume() first."
            )

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
        if self._context_manager and self._context_manager.options.capture_task and self.state.task is None:
            self.set_task(user_msg.content, source_message_ids=(user_msg.id,))
        self._context_stop_reason = None
        self._context_completion_pending = False

        # Reset the per-prompt iteration budget. ``max_iterations`` caps the
        # work this *prompt* triggers, not the lifetime of the session.
        # Without this reset, a long-lived AgentRuntime that has handled
        # N>=max prompts in the past will refuse to take a single LLM turn
        # for the next prompt — silent failure mode in production gateways.
        self.state.iteration = 0
        # Reset the compatibility observation set and private authorization
        # scope together. Only the guard's operation-bound grants authorize.
        self.state.approved_tool_call_ids = set()
        self._execution_guard.start_run(self.config)

        from .types import LoopStartEvent
        await self._emit(LoopStartEvent())
        self.state.signal = "continue"
        return await self._run_loop()

    def approve_pending_tool(self, *, execution_id: str | None = None) -> None:
        """Approve the currently pending tool call.

        Issues a private, operation-bound grant. The public call-ID set is
        retained for compatibility only. Pass execution_id from PendingApproval
        to reject a stale host/UI decision targeting a different operation.

        Caller must invoke ``resume()`` to actually drain the remaining batch.
        """
        if self.state.pending_approval is None:
            if execution_id is not None:
                raise ExecutionAuthorizationError("no_pending_approval")
            return
        self._execution_guard.approve(self.state.pending_approval, execution_id=execution_id)
        self.state.approved_tool_call_ids.add(self.state.pending_approval.tool_call_id)
        set_pending_approval(self.state, None)
        self.state.signal = "continue"
        self.state.last_response_type = "none"

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
        self._execution_guard.revoke_pending()

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

        # Preserve the host's final decision for the async half of the runtime
        # protocol. Cancellation-generated closure never writes to this queue,
        # so forensic consumers can distinguish a real human rejection from a
        # task cancellation.
        self._pending_host_rejections.append((
            approval.tool_name,
            approval.tool_call_id,
            reason,
        ))

        set_pending_approval(self.state, None)
        self.state.signal = "continue"
        self.state.last_response_type = "none"

    def revoke_tool_approval(self, execution_id: str) -> None:
        """Revoke a granted operation before admission; never undo a side effect."""
        call_id = self._execution_guard.revoke_approval(execution_id)
        self.state.approved_tool_call_ids.discard(call_id)

    async def resume(self, *, hooks: RuntimeHooks | None = None) -> AgentState:
        # A resume invoked from an on_event callback inherits the active
        # run_prompt scope. Hosts resuming later from another task can pass
        # hooks explicitly and receive the same per-run isolation guarantees.
        with self._exclusive_execution(resume=True), self.scoped_hooks(hooks):
            if self.state.signal != "continue":
                return self.state
            return await self._run_loop()

    # ── Internal loop ─────────────────────────────────────────────────────────

    @property
    def _effective_max_iterations(self) -> int:
        return self._policy_store.get_policy().max_iterations

    async def _run_loop(self) -> AgentState:
        from .types import (
            AssistantTextEvent,
            AssistantToolCallsEvent,
            IterationStartEvent,
            LoopEndEvent,
        )

        try:
            await self._publish_pending_host_rejections()
            return await self._run_loop_inner()
        except asyncio.CancelledError:
            # Close every still-unanswered call synchronously *before* doing
            # any best-effort awaits. A cancellation can land in any hook or
            # audit sink, not just inside ``ToolRuntime.execute``; leaving even
            # one declared call without a ToolMessage makes the next provider
            # request malformed (and, worse, lets a new UserMessage be
            # appended directly after an open assistant tool-call batch).
            cancelled_calls = self._close_cancelled_tool_batch()
            self.state.signal = "interrupt"

            # Audit only the calls for which this handler synthesised a
            # result. Calls cancelled inside ToolRuntime.execute are already
            # audited at that boundary, so this avoids duplicate forensic
            # entries. Deliberately record no exception text or argument
            # values: cancellation cleanup must not reflect backend errors or
            # secrets into either the transcript or the audit payload.
            await self._audit_cancelled_tool_calls(cancelled_calls)

            try:
                await self._emit(LoopEndEvent(reason="cancelled"))
            except (Exception, asyncio.CancelledError):
                # Cleanup events are best-effort. A hook that is itself being
                # cancelled must not replace the original cancellation or
                # prevent the protocol state above from being committed.
                pass
            finally:
                # A cleanup hook could call an approval helper, which normally
                # flips the signal back to ``continue``. Cancellation is a
                # terminal control-plane fact for this run, so restore the
                # interrupt signal after all callbacks.
                self.state.signal = "interrupt"
            raise

    async def _publish_pending_host_rejections(self) -> None:
        """Flush synchronous host rejections into audit + event streams."""
        from .policy import AuditEntry
        from .types import ToolResultEvent

        while self._pending_host_rejections:
            tool_name, tool_call_id, reason = self._pending_host_rejections[0]
            await self._audit_log.append(AuditEntry(
                timestamp=_now_iso(),
                event="tool_decision",
                actor="host",
                reason=reason,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                decision="deny",
                is_error=True,
                details={"rejected_by_host": True},
            ))
            # Commit queue progress before the async event hook. If the hook is
            # cancelled, the outer _run_loop handler closes the rest of the
            # tool batch without re-emitting this final decision on a retry.
            self._pending_host_rejections.pop(0)
            await self._emit(ToolResultEvent(
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                is_error=True,
            ))

        # Rejecting the final call advances the cursor to ``len(batch)``;
        # ``_has_in_flight_batch`` is then false, so the normal drain path has
        # no opportunity to clear the exhausted queue for us.
        if (
            self.state.pending_tool_calls
            and self.state.pending_tool_call_index
            >= len(self.state.pending_tool_calls)
        ):
            self.state.pending_tool_calls = []
            self.state.pending_tool_call_index = 0

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
                    await self._finish_loop("pending_approval")
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
                await self._finish_loop("max_iterations")
                break

            # ── Pre-flight compaction ─────────────────────────────────────────
            # Size the request being sent now, including new input/tool output.
            # Compaction must fit the configured estimate before the LLM call;
            # an oversized pinned tail or estimation failure stops this loop.
            if self._context_manager:
                try:
                    offloaded = await self._context_manager.prepare(self.state)
                except Exception:
                    await self._stop_for_context("context_storage_failed")
                    break
                for event in offloaded:
                    await self._emit(event)
            if self._compaction_strategy and self._compaction_options:
                stop_reason = await self._maybe_compact()
                if stop_reason is not None:
                    self._context_stop_reason = stop_reason
                    self.state.signal = "stop"
                    await self._finish_loop(stop_reason)
                    break

            # Compatibility IDs convey no authority and need not be sent to
            # an adapter. Actual grants stay private to the execution guard.
            model_state = replace(self.state, approved_tool_call_ids=set())
            if self.state.task is not None:
                from .context.tasks import model_messages
                model_state = copy.deepcopy(model_state)
                model_state.messages = model_messages(model_state)
            turn = await self._llm.respond(copy.deepcopy(self.config), model_state)
            # Two-counter token accounting:
            #   - last_input_tokens: this turn's provider-reported prompt size.
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
                await self._finish_loop("completed")
                break

            # The adapter owns its return object. Keep both transcript history
            # and the mutable execution queue independently isolated so an
            # adapter (or a tool mutating its dispatched params) cannot rewrite
            # a past AssistantMessage through shared nested references.
            try:
                tool_calls = copy.deepcopy(turn.tool_calls or [])
                pending_tool_calls = copy.deepcopy(tool_calls)
                event_tool_calls = copy.deepcopy(tool_calls)
            except Exception:
                # No assistant declaration has been committed yet, so failing
                # closed here cannot leave an open tool-call protocol batch.
                raise ValueError(
                    "LLM tool-call batch could not be isolated safely"
                ) from None
            call_ids: set[str] = set()
            for call in tool_calls:
                if (not isinstance(call, ToolCall) or not isinstance(call.id, str) or not call.id
                        or not isinstance(call.name, str) or not call.name or call.id in call_ids):
                    raise ValueError("LLM tool calls require nonempty names and unique call IDs per batch")
                call_ids.add(call.id)
            assistant_msg = AssistantMessage(
                role="assistant",
                content=turn.text or "",
                tool_calls=tool_calls,
            )
            append_message(self.state, assistant_msg)
            self.state.last_response_type = "tool_calls"

            # Persist the complete batch before the first event hook. Hooks
            # are arbitrary async host code and may be cancelled; if the batch
            # lived only in this stack frame, the outer cancellation cleanup
            # could not synthesise the ToolMessages required to close the
            # assistant declaration.
            self.state.pending_tool_calls = pending_tool_calls
            self.state.pending_tool_call_index = 0
            self._execution_guard.start_batch()
            # Event consumers receive another detached view; observability code
            # must not be able to mutate either durable history or execution
            # inputs in place.
            await self._emit(AssistantToolCallsEvent(
                tool_calls=event_tool_calls,
            ))

            outcome = await self._execute_tool_calls()
            if outcome == "pending_approval":
                self.state.last_response_type = "need_approval"
                self.state.signal = "stop"
                await self._finish_loop("pending_approval")
                break

            self.state.last_response_type = "none"

        return self.state

    def _has_in_flight_batch(self) -> bool:
        return self.state.pending_tool_call_index < len(self.state.pending_tool_calls)

    def _close_cancelled_tool_batch(self) -> list[ToolCall]:
        """Synchronously close and clear the current tool-call batch.

        Returns the calls for which this method added a synthetic result, so
        the async cancellation handler can audit exactly those calls. Existing
        ToolMessages are discovered only after the latest assistant tool-call
        declaration; a provider reusing an old call id must not make a result
        from an earlier turn appear to close the current batch.
        """
        pending = list(self.state.pending_tool_calls)

        batch_start = -1
        for index in range(len(self.state.messages) - 1, -1, -1):
            message = self.state.messages[index]
            if isinstance(message, AssistantMessage) and message.tool_calls:
                batch_start = index
                break

        completed_ids = {
            message.tool_call_id
            for message in self.state.messages[batch_start + 1:]
            if isinstance(message, ToolMessage)
        }
        synthesised: list[ToolCall] = []
        for tool_call in pending:
            if tool_call.id in completed_ids:
                continue
            append_message(
                self.state,
                self._build_tool_message(
                    tool_call,
                    "Tool call was cancelled by the runtime before completion.",
                    True,
                ),
            )
            completed_ids.add(tool_call.id)
            synthesised.append(tool_call)

        set_pending_approval(self.state, None)
        self.state.approved_tool_call_ids.clear()
        self._execution_guard.start_batch()
        self.state.pending_tool_calls = []
        self.state.pending_tool_call_index = 0
        self.state.last_response_type = "none"
        return synthesised

    async def _audit_cancelled_tool_calls(self, tool_calls: list[ToolCall]) -> None:
        """Best-effort, secret-free cancellation audit entries."""
        from .policy import AuditEntry

        for tool_call in tool_calls:
            try:
                await self._audit_log.append(AuditEntry(
                    timestamp=_now_iso(),
                    event="tool_invocation",
                    actor="system",
                    reason="runtime task cancelled before tool batch completed",
                    tool_name=tool_call.name,
                    tool_call_id=tool_call.id,
                    is_error=True,
                    details={
                        "cancelled": True,
                        "runtime_cleanup": True,
                    },
                ))
            except (Exception, asyncio.CancelledError):
                # State closure above is the hard invariant; observability is
                # necessarily best-effort once the host has cancelled us.
                pass

    async def _maybe_compact(self) -> str | None:
        """Return a stop reason if preflight cannot safely admit the request."""
        from .context.compactor import auto_compact_if_needed
        from .types import (
            CompactionBlockedEvent,
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
            config=self.config,
            store=self._context_manager.options.store if self._context_manager else None,
            store_timeout_seconds=self._context_manager.options.storage_timeout_seconds if self._context_manager else 10.0,
            transcript=self._transcript,
        )
        self._compaction_tracking = compact.tracking

        if compact.was_compacted and compact.result:
            await self._emit(CompactionTriggeredEvent(
                summary=compact.result.summary,
                ptl_attempts=compact.result.ptl_attempts,
                input_tokens_before=compact.result.input_tokens_before,
                input_tokens_after=compact.result.input_tokens_after,
                target_tokens=self._compaction_options.target_tokens,
                duration_ms=compact.result.duration_ms,
                summary_input_tokens=compact.result.summary_input_tokens,
                summary_output_tokens=compact.result.summary_output_tokens,
                source_message_ids=compact.result.source_message_ids,
                omitted_message_ids=compact.result.omitted_message_ids,
            ))
        elif compact.tracking.consecutive_failures > prev_failures:
            await self._emit(CompactionFailedEvent(
                consecutive_failures=compact.tracking.consecutive_failures,
                reason=compact.failure_reason,
                duration_ms=compact.duration_ms,
                summary_input_tokens=compact.summary_input_tokens,
                summary_output_tokens=compact.summary_output_tokens,
            ))

        if compact.blocked_reason:
            await self._emit(CompactionBlockedEvent(
                reason=compact.blocked_reason,
                estimated_input_tokens=compact.estimated_input_tokens,
                token_budget=self._compaction_options.input_budget,
            ))
            return compact.blocked_reason
        if compact.exhausted:
            # Terminal: the host needs to know we are no longer protecting
            # the budget so it can decide between "show degraded mode notice",
            # "rotate to a fresh session", or "fail the request".
            await self._emit(CompactionExhaustedEvent(
                consecutive_failures=compact.tracking.consecutive_failures,
                last_input_tokens=self.state.last_input_tokens,
            ))
            return "compaction_exhausted"
        return None

    async def _finish_loop(self, reason: str) -> None:
        from .types import LoopEndEvent
        if self._context_manager and self._context_stop_reason != "context_storage_failed":
            try:
                await self._context_manager.archive(self.state)
            except Exception:
                self._context_completion_pending = reason == "completed"
                await self._stop_for_context("context_storage_failed")
                return
        self._context_completion_pending = False
        previous = self._approval_resume_task
        if reason == "pending_approval":
            self._approval_resume_task = asyncio.current_task()
        try:
            await self._emit(LoopEndEvent(reason=reason))
        finally:
            self._approval_resume_task = previous

    async def _stop_for_context(self, reason: str) -> None:
        from .types import CompactionBlockedEvent, LoopEndEvent
        self._context_stop_reason = reason
        self.state.signal = "stop"
        budget = self._compaction_options.input_budget if self._compaction_options else 0
        await self._emit(CompactionBlockedEvent(reason, None, budget))
        await self._emit(LoopEndEvent(reason=reason))

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
            self._execution_guard.start_batch()

        while self.state.pending_tool_call_index < len(self.state.pending_tool_calls):
            i = self.state.pending_tool_call_index
            tool_call = self.state.pending_tool_calls[i]
            tool_def = self._lookup_tool(tool_call.name)

            try:
                intent = self._execution_guard.prepare(
                    tool_call, i, self.config, self._current_tool_definitions(),
                )
            except ExecutionAuthorizationError as exc:
                await self._deny_execution_authorization(tool_call, i, str(exc))
                continue

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
            check = self._execution_guard.decision(intent)

            await self._audit_tool_decision(
                tool_call,
                decision=check.decision,
                reason=check.reason,
                execution_details=self._execution_guard.audit_details(i),
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
                # Commit progress before invoking arbitrary async host code.
                # A ToolResultEvent hook that is cancelled must not cause this
                # already-closed call to be retried or synthesised twice.
                self.state.pending_tool_call_index = i + 1
                try:
                    await self._emit(ToolResultEvent(
                        tool_name=tool_call.name,
                        tool_call_id=tool_call.id,
                        is_error=True,
                    ))
                except Exception:
                    # Observability must not strand the rest of a declared
                    # batch. Cancellation still propagates to the outer
                    # protocol-closure handler (CancelledError is BaseException).
                    pass
                continue

            if check.decision == "needs_approval":
                # Approval state and observer payloads are separate snapshots.
                # A host callback may render or transform its event, but must
                # not be able to rewrite the params that will be dispatched
                # after a later approval.
                state_approval = self._execution_guard.request_approval(intent)
                event_approval = copy.deepcopy(state_approval)
                set_pending_approval(self.state, state_approval)
                await self._emit(PendingApprovalEvent(
                    approval=event_approval,
                ))
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
                dispatch_args = self._execution_guard.admit(
                    intent, self.state.pending_tool_calls[i],
                    self.state.pending_tool_call_index, self.config, self._current_tool_definitions(),
                )
            except ExecutionAuthorizationError as exc:
                await self._deny_execution_authorization(tool_call, i, str(exc))
                continue

            try:
                with caller_scope(tool_call.name):
                    from .context.manager import CONTEXT_TOOL_NAMES
                    if self._context_manager and tool_call.name in CONTEXT_TOOL_NAMES:
                        result = await self._context_manager.execute(tool_call.name, dispatch_args)
                    else:
                        result = await self._tools.execute(tool_call.name, dispatch_args)
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
                            **self._execution_guard.audit_details(i),
                        },
                    ))
                except Exception:
                    pass
                raise
            except Exception as exc:
                # Ordinary tool failures are data, not runtime failures.  The
                # assistant has already declared this tool_call_id, so aborting
                # here would leave the provider message history malformed and
                # would also skip later calls in the same batch. Close the
                # protocol with an error ToolMessage, audit the failed
                # invocation, advance the cursor, and keep draining.  This is
                # deliberately separate from CancelledError above: host
                # cancellation must still propagate through the task tree.
                # Commit before message/audit/event post-processing. Even a
                # tool that raises may have completed an irreversible side
                # effect before doing so, so retrying it is unsafe.
                self.state.pending_tool_call_index = i + 1
                self._upsert_safe_error_tool_message(
                    tool_call,
                    f"Tool execution failed: {type(exc).__name__}",
                )
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
                            "exception_type": type(exc).__name__,
                            **self._execution_guard.audit_details(i),
                        },
                    ))
                except Exception:
                    pass
                try:
                    await self._emit(ToolResultEvent(
                        tool_name=tool_call.name,
                        tool_call_id=tool_call.id,
                        is_error=True,
                    ))
                except Exception:
                    pass
                continue

            # ``execute`` returned: this is the at-most-once commit point. From
            # here on, no output validator, audit sink, message builder, or
            # observer failure may move the cursor backwards and replay the
            # external side effect.
            self.state.pending_tool_call_index = i + 1
            try:
                self._validate_tool_execution_result(result)

                # Indirect prompt injection / tool-output poisoning defence:
                # always scan output; requires_sanitization only controls PII
                # redaction because rewriting structured data can break it.
                redact_pii = bool(tool_def and tool_def.requires_sanitization)
                inspection = self._safety.inspect_tool_output(
                    tool_call.name, result.output, redact_pii=redact_pii,
                )
                self._validate_tool_output_inspection(inspection)
                content = inspection.content
                is_error = result.error is not None or inspection.blocked

                # A tool-reported error can contain stderr, provider response
                # bodies, credentials, or other backend-controlled text. The
                # model-visible result has already gone through the output
                # safety boundary; the forensic log only needs the fact that
                # the tool reported an error, never its raw value.
                audit_details: dict[str, object] = {
                    **self._execution_guard.audit_details(i),
                    "tool_reported_error": result.error is not None,
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
            except asyncio.CancelledError:
                raise
            except Exception:
                # The external call already returned and must never be replayed.
                # Replace any partially committed result (e.g. an observer
                # raised after seeing it) with a generic error that cannot leak
                # the backend exception or untrusted output.
                self._upsert_safe_error_tool_message(
                    tool_call,
                    "Tool result processing failed safely.",
                )
                await self._record_postprocessing_failure(
                    tool_call,
                    decision=check.decision,
                    reason="tool result post-processing failed safely",
                )
            continue

        # Batch drained — clear the queue so a future resume() doesn't loop.
        self.state.pending_tool_calls = []
        self.state.pending_tool_call_index = 0
        return "continue"

    def _lookup_tool(self, name: str) -> ToolDefinition | None:
        return self._execution_guard.definition(name)

    def _current_tool_definitions(self) -> list[ToolDefinition]:
        try:
            current = list(self._tools.list_tools())
            if not all(isinstance(tool, ToolDefinition) for tool in current):
                raise TypeError("invalid catalog")
        except Exception:
            raise ExecutionAuthorizationError("tool_catalog_unavailable") from None
        if self._context_manager is not None:
            from .context.manager import context_tool_definitions
            current.extend(context_tool_definitions(
                read_max_chars=self._context_manager.options.read_max_chars
            ))
        return current

    async def _deny_execution_authorization(self, call: ToolCall, ordinal: int, reason: str) -> None:
        details = self._execution_guard.audit_details(ordinal)
        original = self._execution_guard.original_call(ordinal)
        if original is not None:
            call = original
            # Keep the error paired with the assistant's original declaration,
            # even if a host accidentally edited the pending call ID/name.
            if ordinal < len(self.state.pending_tool_calls):
                self.state.pending_tool_calls[ordinal] = original
        self._execution_guard.revoke_pending()
        set_pending_approval(self.state, None)
        self.state.pending_tool_call_index = ordinal + 1
        self._upsert_safe_error_tool_message(call, f"Tool call denied by policy: {reason}.")
        try:
            await self._audit_tool_decision(
                call, decision="deny", reason=reason, execution_details=details,
            )
            from .types import ToolResultEvent
            await self._emit(ToolResultEvent(
                tool_name=call.name, tool_call_id=call.id, is_error=True,
            ))
        except Exception:
            pass

    @staticmethod
    def _validate_tool_execution_result(result: object) -> None:
        """Validate the untrusted ToolRuntime return before reading fields."""
        from .types import ToolExecutionResult

        if not isinstance(result, ToolExecutionResult):
            raise TypeError("tool runtime returned an invalid result object")
        if not isinstance(result.output, str):
            raise TypeError("tool runtime output must be a string")
        if result.error is not None and not isinstance(result.error, str):
            raise TypeError("tool runtime error must be a string or None")

    @staticmethod
    def _validate_tool_output_inspection(inspection: object) -> None:
        """Validate the SafetyLayer result before it reaches audit/history."""
        from .types import ToolOutputSafetyResult

        if not isinstance(inspection, ToolOutputSafetyResult):
            raise TypeError("safety layer returned an invalid inspection object")
        if not isinstance(inspection.content, str):
            raise TypeError("inspected tool output must be a string")
        if not isinstance(inspection.blocked, bool):
            raise TypeError("inspection blocked flag must be boolean")
        if not isinstance(inspection.violations, list):
            raise TypeError("inspection violations must be a list")
        if (
            isinstance(inspection.redacted_count, bool)
            or not isinstance(inspection.redacted_count, int)
            or inspection.redacted_count < 0
        ):
            raise TypeError("inspection redacted_count must be a non-negative integer")

    def _upsert_safe_error_tool_message(
        self,
        tool_call: ToolCall,
        content: str,
    ) -> None:
        """Commit one generic error result without relying on host callbacks."""
        replacement = self._build_tool_message(tool_call, content, True)

        batch_start = -1
        for index in range(len(self.state.messages) - 1, -1, -1):
            message = self.state.messages[index]
            if isinstance(message, AssistantMessage) and message.tool_calls:
                batch_start = index
                break

        for message in reversed(self.state.messages[batch_start + 1:]):
            if isinstance(message, ToolMessage) and message.tool_call_id == tool_call.id:
                # Keep the stable message id while replacing any partially
                # committed untrusted output with the safe terminal result.
                message.tool_name = replacement.tool_name
                message.content = replacement.content
                message.is_error = True
                return

        # Direct list append is intentional: this is the recovery path for a
        # possible message-helper failure, and AgentState.messages is the
        # canonical in-memory commit log.
        self.state.messages.append(replacement)

    async def _record_postprocessing_failure(
        self,
        tool_call: ToolCall,
        *,
        decision: str,
        reason: str,
    ) -> None:
        """Best-effort audit/event for a safely closed processing failure."""
        from .policy import AuditEntry
        from .types import ToolResultEvent

        try:
            await self._audit_log.append(AuditEntry(
                timestamp=_now_iso(),
                event="tool_invocation",
                actor="agent",
                reason=reason,
                tool_name=tool_call.name,
                tool_call_id=tool_call.id,
                decision=decision,  # type: ignore[arg-type]
                is_error=True,
                details={"postprocessing_failed": True},
            ))
        except Exception:
            pass

        try:
            await self._emit(ToolResultEvent(
                tool_name=tool_call.name,
                tool_call_id=tool_call.id,
                is_error=True,
            ))
        except Exception:
            pass

    async def _audit_tool_decision(
        self,
        tool_call: ToolCall,
        *,
        decision: str,
        reason: str,
        execution_details: dict | None = None,
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
            details={
                "args_keys": sorted(key for key in tool_call.args if isinstance(key, str))
                if isinstance(tool_call.args, dict) else [],
                **(execution_details or {}),
            },
        ))

    def _build_tool_message(self, tool_call: ToolCall, content: str, is_error: bool) -> ToolMessage:
        if self.config.wrap_tool_output:
            # Structural marker so the LLM has an explicit cue that this
            # body is *data*, not *instructions*. Effective only when the
            # system prompt carries a corresponding directive — see
            # ``AgentConfig.wrap_tool_output`` docstring.
            # Both interpolations are escaped: otherwise a malicious tool
            # name containing a quote can inject attributes, and output that
            # contains ``</tool_output>`` can close the trust boundary early.
            escaped_tool_name = escape(tool_call.name, quote=True)
            escaped_content = escape(content, quote=False)
            content = (
                f'<tool_output tool="{escaped_tool_name}" trust="untrusted">\n'
                f"{escaped_content}\n"
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
        hooks = self._scoped_runtime_hooks.get() or self._hooks
        if hooks.on_event:
            result = hooks.on_event(event, self.config, self.state)
            if inspect.isawaitable(result):
                await result
