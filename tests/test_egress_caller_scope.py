"""Auto-injected caller via ``caller_scope``.

These tests pin down four contractual claims:

1. Inside ``caller_scope(name)``, ``EgressGuard.check / check_url /
   enforce`` resolve ``caller`` to ``name`` even when the kwarg is
   omitted.
2. An explicit ``caller=`` kwarg always wins over the ambient binding.
3. The binding does not leak to sibling tool calls — running two
   ``caller_scope`` blocks back-to-back must not bleed identity from
   one into the other, and a raise inside the scope still unwinds it.
4. The runtime actually wraps tool dispatch in ``caller_scope`` so a
   tool handler that calls ``guard.enforce(url, method)`` without
   threading ``caller=`` still gets a correctly-scoped decision.
"""

from __future__ import annotations

import asyncio

import pytest

from titanx.safety.egress import (
    EgressDenied,
    EgressGuard,
    EgressPolicy,
    OutboundRule,
    caller_scope,
    current_caller,
)
from titanx.types import (
    LlmTurnResult,
    ToolCall,
    ToolDefinition,
    ToolExecutionResult,
    ToolRuntime,
)

from ._helpers import ScriptedLlm, make_runtime


def _guard(*rules: OutboundRule) -> EgressGuard:
    return EgressGuard(EgressPolicy(rules=list(rules), default_action="deny"))


# ── Plain caller_scope semantics ─────────────────────────────────────────


class TestCallerScope:
    def test_outside_scope_caller_is_none(self):
        assert current_caller() is None

    def test_scope_binds_and_unwinds(self):
        with caller_scope("github"):
            assert current_caller() == "github"
        assert current_caller() is None

    def test_nested_scope_restores_outer(self):
        with caller_scope("outer"):
            assert current_caller() == "outer"
            with caller_scope("inner"):
                assert current_caller() == "inner"
            assert current_caller() == "outer"
        assert current_caller() is None

    def test_raise_unwinds_scope(self):
        # Even when the body raises, the binding must not leak.
        with pytest.raises(RuntimeError, match="boom"):
            with caller_scope("github"):
                raise RuntimeError("boom")
        assert current_caller() is None

    def test_scope_with_none_clears_inherited(self):
        # ``caller_scope(None)`` is a documented way to express
        # "explicitly no caller for this block".
        with caller_scope("outer"):
            with caller_scope(None):
                assert current_caller() is None
            assert current_caller() == "outer"


# ── Guard fallback semantics ──────────────────────────────────────────────


class TestGuardFallback:
    def test_check_url_picks_up_ambient_caller(self):
        guard = _guard(OutboundRule(
            host_pattern="api.github.com", caller="github",
        ))

        # Without a caller, the rule cannot match (fail-closed).
        assert not guard.check_url("https://api.github.com/").allowed

        # Inside a caller_scope, it does match — without the author
        # ever passing ``caller=`` to the guard.
        with caller_scope("github"):
            decision = guard.check_url("https://api.github.com/")
        assert decision.allowed
        assert decision.caller == "github"

    def test_explicit_caller_wins_over_ambient(self):
        guard = _guard(
            OutboundRule(host_pattern="slack.com", caller="slack"),
            OutboundRule(host_pattern="api.github.com", caller="github"),
        )

        # Ambient says "github", but the call explicitly identifies
        # itself as "slack". The explicit identity must win.
        with caller_scope("github"):
            decision = guard.check_url(
                "https://slack.com/api/foo", caller="slack",
            )
        assert decision.allowed
        assert decision.caller == "slack"

    def test_check_uses_ambient_caller(self):
        # Ensure both check_url and the lower-level check resolve the
        # contextvar — historic regressions tend to land in just one.
        guard = _guard(OutboundRule(
            host_pattern="api.example.com", caller="alice",
        ))
        with caller_scope("alice"):
            decision = guard.check("api.example.com", "/", "GET")
        assert decision.allowed
        assert decision.caller == "alice"

    async def test_enforce_picks_up_ambient_caller(self):
        guard = _guard(OutboundRule(
            host_pattern="api.example.com", caller="alice",
        ))
        with caller_scope("alice"):
            decision = await guard.enforce("https://api.example.com/")
        assert decision.allowed
        assert decision.caller == "alice"

    async def test_enforce_outside_scope_still_denies(self):
        guard = _guard(OutboundRule(
            host_pattern="api.example.com", caller="alice",
        ))
        with pytest.raises(EgressDenied):
            await guard.enforce("https://api.example.com/")

    async def test_contextvar_propagates_into_child_task(self):
        # ContextVars are copied to asyncio child tasks at creation
        # time. A tool that fans out via gather must still see its
        # ambient caller from inside each child.
        guard = _guard(OutboundRule(
            host_pattern="api.example.com", caller="alice",
        ))

        async def _worker():
            return guard.check_url("https://api.example.com/")

        with caller_scope("alice"):
            results = await asyncio.gather(_worker(), _worker())
        assert all(r.allowed for r in results)


# ── Runtime integration ───────────────────────────────────────────────────


class _RecordingToolRuntime(ToolRuntime):
    """Tool runtime that captures ``current_caller()`` at dispatch time.

    The runtime is supposed to wrap each ``self._tools.execute`` call
    in ``caller_scope(tool_call.name)`` so a handler that asks
    ``current_caller()`` sees the dispatched name. We assert exactly
    that.
    """

    def __init__(self) -> None:
        self.observed: list[str | None] = []

    def list_tools(self) -> list[ToolDefinition]:
        return [
            ToolDefinition(
                name="github", description="", parameters={},
            ),
        ]

    async def execute(self, name: str, params: dict) -> ToolExecutionResult:
        # The contextvar is read here, mid-dispatch, exactly the way a
        # production tool handler would when it builds an HTTP request.
        self.observed.append(current_caller())
        return ToolExecutionResult(output="ok", error=None)


class TestRuntimeWiring:
    async def test_runtime_binds_tool_name_as_caller(self):
        # Outside the runtime entry point the contextvar is None.
        assert current_caller() is None

        tools = _RecordingToolRuntime()
        # Two-turn script: first turn issues a tool_call for 'github',
        # second turn produces plain text so the loop terminates.
        llm = ScriptedLlm([
            LlmTurnResult(
                type="tool_calls",
                tool_calls=[ToolCall(id="c1", name="github", args={})],
            ),
            LlmTurnResult(type="text", text="done"),
        ])
        runtime = make_runtime(llm, tools=tools, max_iterations=4)
        await runtime.run_prompt("hello")

        # The tool ran exactly once and saw its own name as the caller.
        assert tools.observed == ["github"]
        # And after run_prompt returns the binding is gone — no leak
        # into the surrounding test process.
        assert current_caller() is None

    async def test_runtime_binds_each_tool_call_independently(self):
        # Two tool_calls in one assistant turn. Each must see its own
        # name; the second call must not inherit the first's binding.
        observed: list[tuple[str, str | None]] = []

        class _Recorder(ToolRuntime):
            def list_tools(self) -> list[ToolDefinition]:
                return [
                    ToolDefinition(
                        name="github", description="", parameters={},
                    ),
                    ToolDefinition(
                        name="slack", description="", parameters={},
                    ),
                ]

            async def execute(
                self, name: str, params: dict,
            ) -> ToolExecutionResult:
                observed.append((name, current_caller()))
                return ToolExecutionResult(output="ok", error=None)

        llm = ScriptedLlm([
            LlmTurnResult(
                type="tool_calls",
                tool_calls=[
                    ToolCall(id="c1", name="github", args={}),
                    ToolCall(id="c2", name="slack", args={}),
                ],
            ),
            LlmTurnResult(type="text", text="done"),
        ])
        runtime = make_runtime(llm, tools=_Recorder(), max_iterations=4)
        await runtime.run_prompt("hello")

        assert observed == [("github", "github"), ("slack", "slack")]
        assert current_caller() is None
