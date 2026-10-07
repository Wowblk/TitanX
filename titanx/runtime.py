from __future__ import annotations

import asyncio
import copy
import inspect
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace

from .context.compactor import auto_compact_if_needed
from .context.manager import CONTEXT_TOOL_NAMES, ContextManager, context_tool_definitions
from .context.recovery import ContextRecovery
from .context.summary import LlmCompactionStrategy
from .context.tasks import model_messages
from .context.tokens import estimate_input_tokens
from .context.transcript import Transcript
from .context.types import CompactionTracking
from .policy import AgentPolicy, AuditEntry, AuditLog, PolicyStore
from .policy.execution import ExecutionAuthorizationError, ExecutionGuard, ExecutionGuardOptions
from .state import append_message, create_config, create_initial_state, now_iso, set_pending_approval
from .tool_pipeline import ToolCallPipeline
from .types import (
    AgentConfig,
    AgentState,
    AssistantMessage,
    AssistantTextEvent,
    AssistantToolCallsEvent,
    CompactionBlockedEvent,
    CompactionExhaustedEvent,
    CompactionFailedEvent,
    CompactionTriggeredEvent,
    IterationStartEvent,
    LlmAdapter,
    LoopEndEvent,
    LoopStartEvent,
    PendingApproval,
    RuntimeEvent,
    RuntimeHooks,
    SafetyLayerLike,
    ToolCall,
    ToolResultEvent,
    ToolRuntime,
    TaskState,
    UserMessage,
)


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
        available_tools = list(tools.list_tools())
        injected_context_tools: list[str] = []
        if context_options is not None:
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
            if compaction_options.token_estimator is estimate_input_tokens:
                def count_current_input(config, messages):
                    counter = getattr(self._llm, "count_input_tokens", None)
                    count = counter(config, messages) if counter else None
                    return estimate_input_tokens(config, messages) if count is None else count
                self._compaction_options = replace(compaction_options, token_estimator=count_current_input)
        # One owner for wholesale transcript replacement, shared by offload
        # (ContextManager) and compaction so neither can silently violate the
        # pinned-message / single-summary / tool-group invariants.
        self._transcript = Transcript(self.config)
        self._context_manager = None
        if context_options is not None:
            self._context_manager = ContextManager(context_options, self.config, transcript=self._transcript)
            if compaction_options is not None and compaction_strategy is None:
                self._compaction_strategy = LlmCompactionStrategy(llm)
        self._compaction_tracking = CompactionTracking()
        self._recovery = ContextRecovery()
        self._closed = False

        # ``reject_pending_tool`` intentionally stays synchronous for host/UI
        # compatibility. Its ToolMessage is committed immediately, while the
        # audit + RuntimeEvent side effects are queued here and flushed at the
        # start of the next ``_run_loop`` (normally ``resume()``).
        self._pending_host_rejections: list[tuple[str, str, str]] = []

        # One collaborator owns the tool-call batch pipeline (authorization →
        # validation → policy → approval → execution → output safety → audit →
        # commit → event). ``config`` and ``safety`` are read live rather than
        # snapshotted: a host may replace ``runtime.config`` to change the
        # execution identity between calls, and the guard must see the new one.
        self._tool_pipeline = ToolCallPipeline(
            config=lambda: self.config,
            safety=lambda: self._safety,
            guard=self._execution_guard,
            tools=self._tools,
            context_manager=self._context_manager,
            audit_log=self._audit_log,
            emit=self._emit,
        )

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
        if not self._recovery.stopped:
            raise RuntimeError("runtime is not stopped by a context failure")
        if self._recovery.mode == "archive_only":
            # The answer already exists. Repair only its failed final archive;
            # requesting another model turn could cause duplicate work.
            with self.scoped_hooks(hooks):
                self._recovery.clear()
                await self._finish_loop("completed")
                return self.state
        if self.state.pending_approval is not None:
            raise RuntimeError("resolve pending approval before retrying context")
        self._compaction_tracking = CompactionTracking()
        self._recovery.clear()
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
        self._recovery.clear()


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
                self._tool_pipeline.build_tool_message(
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
            cancelled_calls = self._tool_pipeline.close_cancelled_batch(self.state)
            self.state.signal = "interrupt"

            # Audit only the calls for which this handler synthesised a
            # result. Calls cancelled inside ToolRuntime.execute are already
            # audited at that boundary, so this avoids duplicate forensic
            # entries. Deliberately record no exception text or argument
            # values: cancellation cleanup must not reflect backend errors or
            # secrets into either the transcript or the audit payload.
            await self._tool_pipeline.audit_cancelled_calls(cancelled_calls)

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
        while self._pending_host_rejections:
            tool_name, tool_call_id, reason = self._pending_host_rejections[0]
            await self._audit_log.append(AuditEntry(
                timestamp=now_iso(),
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
        while self.state.signal != "stop":
            # ── Resume path ──────────────────────────────────────────────────
            # If a previous turn's tool-call batch was paused (e.g. by an
            # approval), drain it BEFORE asking the LLM for another turn.
            # Skipping this would call the LLM with an AssistantMessage that
            # has N tool_calls but only k<N matching ToolMessages — a
            # protocol violation that OpenAI / Anthropic reject with HTTP 400.
            if self._has_in_flight_batch():
                outcome = await self._tool_pipeline.run(self.state)
                if outcome == "pending_approval":
                    self.state.last_response_type = "need_approval"
                    self.state.signal = "stop"
                    await self._finish_loop("pending_approval")
                    break
                if outcome == "return_direct":
                    # The pipeline already committed the tool output as the
                    # final assistant message and set ``signal``; close the
                    # turn like a plain text response.
                    await self._finish_loop("completed")
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
                    self._recovery.stop(stop_reason)
                    self.state.signal = "stop"
                    await self._finish_loop(stop_reason)
                    break

            # Compatibility IDs convey no authority and need not be sent to
            # an adapter. Actual grants stay private to the execution guard.
            model_state = replace(self.state, approved_tool_call_ids=set())
            if self.state.task is not None:
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

            outcome = await self._tool_pipeline.run(self.state)
            if outcome == "pending_approval":
                self.state.last_response_type = "need_approval"
                self.state.signal = "stop"
                await self._finish_loop("pending_approval")
                break
            if outcome == "return_direct":
                # The pipeline already committed the tool output as the final
                # assistant message and set ``signal``; close the turn like a
                # plain text response.
                await self._finish_loop("completed")
                break

            self.state.last_response_type = "none"

        return self.state

    def _has_in_flight_batch(self) -> bool:
        return self.state.pending_tool_call_index < len(self.state.pending_tool_calls)

    async def _maybe_compact(self) -> str | None:
        """Return a stop reason if preflight cannot safely admit the request."""
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
        if self._context_manager and not self._recovery.archive_blocked:
            try:
                await self._context_manager.archive(self.state)
            except Exception:
                self._recovery.note_archive_failure(answer_pending=reason == "completed")
                await self._stop_for_context("context_storage_failed")
                return
        self._recovery.clear_completion()
        previous = self._approval_resume_task
        if reason == "pending_approval":
            self._approval_resume_task = asyncio.current_task()
        try:
            await self._emit(LoopEndEvent(reason=reason))
        finally:
            self._approval_resume_task = previous

    async def _stop_for_context(self, reason: str) -> None:
        self._recovery.stop(reason)
        self.state.signal = "stop"
        budget = self._compaction_options.input_budget if self._compaction_options else 0
        await self._emit(CompactionBlockedEvent(reason, None, budget))
        await self._emit(LoopEndEvent(reason=reason))

    async def _emit(self, event: RuntimeEvent) -> None:
        hooks = self._scoped_runtime_hooks.get() or self._hooks
        if hooks.on_event:
            result = hooks.on_event(event, self.config, self.state)
            if inspect.isawaitable(result):
                await result
