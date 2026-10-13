"""Tool-call execution pipeline, extracted from ``AgentRuntime`` (review §3.1).

Drives one tool-call batch to completion, cursor-style: authorization →
parameter validation → policy decision → approval pause → execution → output
safety → audit → message commit → event.

Lifted verbatim out of ``AgentRuntime`` so that class is orchestration and host
API only.  The collaborator reads the runtime's live ``config`` and safety layer
through callables rather than snapshots: a host (or test) may replace
``runtime.config`` to change the execution identity between calls, and the guard
must observe the current value.
"""
from __future__ import annotations

import asyncio
import copy
from html import escape
from typing import Awaitable, Callable

from .context.manager import CONTEXT_TOOL_NAMES, ContextManager, context_tool_definitions
from .policy import AuditEntry, AuditLog
from .policy.execution import ExecutionAuthorizationError, ExecutionGuard
from .safety.egress import caller_scope
from .state import append_message, now_iso, set_pending_approval
from .types import (
    AgentConfig,
    AgentState,
    AssistantMessage,
    AssistantTextEvent,
    PendingApprovalEvent,
    RuntimeEvent,
    SafetyLayerLike,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolMessage,
    ToolOutputSafetyResult,
    ToolResultEvent,
    ToolRuntime,
)


class ToolCallPipeline:
    def __init__(
        self,
        *,
        config: Callable[[], AgentConfig],
        safety: Callable[[], SafetyLayerLike],
        guard: ExecutionGuard,
        tools: ToolRuntime,
        context_manager: ContextManager | None,
        audit_log: AuditLog,
        emit: Callable[[RuntimeEvent], Awaitable[None]],
    ) -> None:
        self._config = config
        self._safety = safety
        self._guard = guard
        self._tools = tools
        self._context_manager = context_manager
        self._audit_log = audit_log
        self._emit = emit

    async def run(self, state: AgentState) -> str:
        """Drain ``state``'s pending tool-call batch, cursor-style.

        Returns ``"pending_approval"`` if execution paused on a tool call that
        requires human approval; ``"return_direct"`` if a successful
        ``return_direct`` tool short-circuited the turn (its output is already
        committed as the final assistant message and ``state.signal`` is set to
        ``"stop"``); otherwise ``"continue"`` once the batch has been fully
        drained.
        """
        while state.pending_tool_call_index < len(state.pending_tool_calls):
            i = state.pending_tool_call_index
            tool_call = state.pending_tool_calls[i]
            tool_def = self._lookup_tool(tool_call.name)

            try:
                intent = self._guard.prepare(
                    tool_call, i, self._config(), self._current_tool_definitions(),
                )
            except ExecutionAuthorizationError as exc:
                await self._deny_execution_authorization(state, tool_call, i, str(exc))
                continue

            # ── 1. Parameter validation ──────────────────────────────────────
            validation = self._safety().validator.validate_tool_params(tool_call.args)
            if not validation.is_valid:
                msg = "; ".join(e.message for e in validation.errors)
                await self._audit_tool_decision(
                    tool_call, decision="deny",
                    reason=f"safety validator rejected parameters: {msg}",
                )
                append_message(
                    state,
                    self.build_tool_message(tool_call, f"Invalid tool parameters: {msg}", True),
                )
                state.pending_tool_call_index = i + 1
                continue

            # ── 2. Policy decision (centralised in PolicyStore) ──────────────
            check = self._guard.decision(intent)

            await self._audit_tool_decision(
                tool_call,
                decision=check.decision,
                reason=check.reason,
                execution_details=self._guard.audit_details(i),
            )

            if check.decision == "deny":
                append_message(
                    state,
                    self.build_tool_message(
                        tool_call,
                        f"Tool call denied by policy: {check.reason}",
                        True,
                    ),
                )
                # Commit progress before invoking arbitrary async host code.
                # A ToolResultEvent hook that is cancelled must not cause this
                # already-closed call to be retried or synthesised twice.
                state.pending_tool_call_index = i + 1
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
                state_approval = self._guard.request_approval(intent)
                event_approval = copy.deepcopy(state_approval)
                set_pending_approval(state, state_approval)
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
                dispatch_args = self._guard.admit(
                    intent, state.pending_tool_calls[i],
                    state.pending_tool_call_index, self._config(), self._current_tool_definitions(),
                )
            except ExecutionAuthorizationError as exc:
                await self._deny_execution_authorization(state, tool_call, i, str(exc))
                continue

            try:
                with caller_scope(tool_call.name):
                    if self._context_manager and tool_call.name in CONTEXT_TOOL_NAMES:
                        result = await self._context_manager.execute(tool_call.name, dispatch_args)
                    else:
                        result = await self._tools.execute(tool_call.name, dispatch_args)
            except asyncio.CancelledError:
                append_message(
                    state,
                    self.build_tool_message(
                        tool_call,
                        "Tool execution was cancelled before completion.",
                        True,
                    ),
                )
                state.pending_tool_call_index = i + 1
                state.signal = "interrupt"
                # Best-effort audit so cancellation is observable in the
                # forensic trail. Wrapped in try/except because we are in
                # a cancellation cleanup path — failing to audit must not
                # mask the original CancelledError.
                try:
                    await self._audit_log.append(AuditEntry(
                        timestamp=now_iso(),
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
                            **self._guard.audit_details(i),
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
                state.pending_tool_call_index = i + 1
                self._upsert_safe_error_tool_message(
                    state,
                    tool_call,
                    f"Tool execution failed: {type(exc).__name__}",
                )
                try:
                    await self._audit_log.append(AuditEntry(
                        timestamp=now_iso(),
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
                            **self._guard.audit_details(i),
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
            state.pending_tool_call_index = i + 1
            direct_output: str | None = None
            try:
                self._validate_tool_execution_result(result)

                # Indirect prompt injection / tool-output poisoning defence:
                # always scan output; requires_sanitization only controls PII
                # redaction because rewriting structured data can break it.
                redact_pii = bool(tool_def and tool_def.requires_sanitization)
                inspection = self._safety().inspect_tool_output(
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
                    **self._guard.audit_details(i),
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
                    timestamp=now_iso(),
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
                    state,
                    self.build_tool_message(tool_call, content, is_error),
                )
                await self._emit(ToolResultEvent(
                    tool_name=tool_call.name,
                    tool_call_id=tool_call.id,
                    is_error=is_error,
                ))
                # Only a *successful* return_direct result becomes the answer;
                # an error/blocked result still needs the LLM (or the host) to
                # handle it. It must also be the batch's final call so ending
                # the turn cannot strand earlier-declared calls without a
                # matching ToolMessage, and it must carry something: an empty
                # output is not an answer, so the turn falls through to the LLM
                # rather than ending on an empty assistant message. Computed
                # last so a post-processing failure above cannot leave a
                # half-committed short-circuit armed.
                if (
                    tool_def
                    and tool_def.return_direct
                    and not is_error
                    and content != ""
                    and i + 1 >= len(state.pending_tool_calls)
                ):
                    direct_output = content
            except asyncio.CancelledError:
                raise
            except Exception:
                # The external call already returned and must never be replayed.
                # Replace any partially committed result (e.g. an observer
                # raised after seeing it) with a generic error that cannot leak
                # the backend exception or untrusted output.
                self._upsert_safe_error_tool_message(
                    state,
                    tool_call,
                    "Tool result processing failed safely.",
                )
                await self._record_postprocessing_failure(
                    tool_call,
                    decision=check.decision,
                    reason="tool result post-processing failed safely",
                )
            if direct_output is not None:
                # The tool's output *is* the answer: close the turn exactly as a
                # plain text turn would, so the loop never asks the LLM for a
                # second turn. Drain the queue first (the batch's last call was
                # just committed) so a later run_prompt is not blocked by a
                # stale, fully-consumed batch. The runtime loop observes the
                # returned outcome and finishes with ``LoopEndEvent("completed")``.
                #
                # The answer is the *inspected* content, and it is deliberately
                # not run through ``build_tool_message``'s ``<tool_output>``
                # wrapper: this message is presented as the assistant's own
                # final answer, so wrapping it would leak the markers into the
                # host UI. ``content`` has already passed the output safety
                # boundary (injection scan, optional PII redaction).
                state.pending_tool_calls = []
                state.pending_tool_call_index = 0
                append_message(
                    state,
                    AssistantMessage(role="assistant", content=direct_output),
                )
                state.last_response_type = "text"
                state.last_text_response = direct_output
                await self._emit(AssistantTextEvent(text=direct_output))
                state.signal = "stop"
                return "return_direct"
            continue

        # Batch drained — clear the queue so a future resume() doesn't loop.
        state.pending_tool_calls = []
        state.pending_tool_call_index = 0
        return "continue"

    def close_cancelled_batch(self, state: AgentState) -> list[ToolCall]:
        """Synchronously close and clear the current tool-call batch.

        Returns the calls for which this method added a synthetic result, so
        the async cancellation handler can audit exactly those calls. Existing
        ToolMessages are discovered only after the latest assistant tool-call
        declaration; a provider reusing an old call id must not make a result
        from an earlier turn appear to close the current batch.
        """
        pending = list(state.pending_tool_calls)

        batch_start = -1
        for index in range(len(state.messages) - 1, -1, -1):
            message = state.messages[index]
            if isinstance(message, AssistantMessage) and message.tool_calls:
                batch_start = index
                break

        completed_ids = {
            message.tool_call_id
            for message in state.messages[batch_start + 1:]
            if isinstance(message, ToolMessage)
        }
        synthesised: list[ToolCall] = []
        for tool_call in pending:
            if tool_call.id in completed_ids:
                continue
            append_message(
                state,
                self.build_tool_message(
                    tool_call,
                    "Tool call was cancelled by the runtime before completion.",
                    True,
                ),
            )
            completed_ids.add(tool_call.id)
            synthesised.append(tool_call)

        set_pending_approval(state, None)
        state.approved_tool_call_ids.clear()
        self._guard.start_batch()
        state.pending_tool_calls = []
        state.pending_tool_call_index = 0
        state.last_response_type = "none"
        return synthesised

    async def audit_cancelled_calls(self, tool_calls: list[ToolCall]) -> None:
        """Best-effort, secret-free cancellation audit entries."""
        for tool_call in tool_calls:
            try:
                await self._audit_log.append(AuditEntry(
                    timestamp=now_iso(),
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

    def _lookup_tool(self, name: str) -> ToolDefinition | None:
        return self._guard.definition(name)

    def _current_tool_definitions(self) -> list[ToolDefinition]:
        try:
            current = list(self._tools.list_tools())
            if not all(isinstance(tool, ToolDefinition) for tool in current):
                raise TypeError("invalid catalog")
        except Exception:
            raise ExecutionAuthorizationError("tool_catalog_unavailable") from None
        if self._context_manager is not None:
            current.extend(context_tool_definitions(
                read_max_chars=self._context_manager.options.read_max_chars
            ))
        return current

    async def _deny_execution_authorization(
        self, state: AgentState, call: ToolCall, ordinal: int, reason: str
    ) -> None:
        details = self._guard.audit_details(ordinal)
        original = self._guard.original_call(ordinal)
        if original is not None:
            call = original
            # Keep the error paired with the assistant's original declaration,
            # even if a host accidentally edited the pending call ID/name.
            if ordinal < len(state.pending_tool_calls):
                state.pending_tool_calls[ordinal] = original
        self._guard.revoke_pending()
        set_pending_approval(state, None)
        state.pending_tool_call_index = ordinal + 1
        self._upsert_safe_error_tool_message(state, call, f"Tool call denied by policy: {reason}.")
        try:
            await self._audit_tool_decision(
                call, decision="deny", reason=reason, execution_details=details,
            )
            await self._emit(ToolResultEvent(
                tool_name=call.name, tool_call_id=call.id, is_error=True,
            ))
        except Exception:
            pass

    @staticmethod
    def _validate_tool_execution_result(result: object) -> None:
        """Validate the untrusted ToolRuntime return before reading fields."""
        if not isinstance(result, ToolExecutionResult):
            raise TypeError("tool runtime returned an invalid result object")
        if not isinstance(result.output, str):
            raise TypeError("tool runtime output must be a string")
        if result.error is not None and not isinstance(result.error, str):
            raise TypeError("tool runtime error must be a string or None")

    @staticmethod
    def _validate_tool_output_inspection(inspection: object) -> None:
        """Validate the SafetyLayer result before it reaches audit/history."""
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
        state: AgentState,
        tool_call: ToolCall,
        content: str,
    ) -> None:
        """Commit one generic error result without relying on host callbacks."""
        replacement = self.build_tool_message(tool_call, content, True)

        batch_start = -1
        for index in range(len(state.messages) - 1, -1, -1):
            message = state.messages[index]
            if isinstance(message, AssistantMessage) and message.tool_calls:
                batch_start = index
                break

        for message in reversed(state.messages[batch_start + 1:]):
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
        state.messages.append(replacement)

    async def _record_postprocessing_failure(
        self,
        tool_call: ToolCall,
        *,
        decision: str,
        reason: str,
    ) -> None:
        """Best-effort audit/event for a safely closed processing failure."""
        try:
            await self._audit_log.append(AuditEntry(
                timestamp=now_iso(),
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
        await self._audit_log.append(AuditEntry(
            timestamp=now_iso(),
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

    def build_tool_message(self, tool_call: ToolCall, content: str, is_error: bool) -> ToolMessage:
        if self._config().wrap_tool_output:
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
