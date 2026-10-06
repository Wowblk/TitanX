"""Shared offline application wiring; SDK constructors remain opt-in."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import sys
from typing import Sequence
from uuid import uuid4

from .context import CompactionOptions, ContextOptions, SQLiteContextStore
from .factory import CreateSandboxedRuntimeOptions, create_sandboxed_runtime
from .runtime import AgentRuntime
from .safety import SafetyLayer
from .types import (
    LlmAdapter, LlmTurnResult, RuntimeHooks, ToolCall, ToolDefinition,
    ToolExecutionResult, ToolMessage, ToolRuntime,
)


class EchoLlm(LlmAdapter):
    """Offline echo and summary fixtures; not a model retention evaluation."""

    async def respond(self, config, state):
        if not config.available_tools:
            data = json.loads(state.messages[0].content)
            task = data["task"]
            summary = {
                "overview": "Offline demo history; original evidence remains in the session archive.",
                "source_message_ids": [m["id"] for m in data["messages"]],
                "task_id": task["id"] if task else None,
                "task_revision": task["revision"] if task else None,
                "decisions": [], "completed": [], "pending": [],
            }
            return LlmTurnResult(type="text", text=json.dumps(summary))
        last = next((m for m in reversed(state.messages) if m.role == "user"), None)
        return LlmTurnResult(type="text", text=f"Echo: {last.content}" if last else "Hello!")


class DemoApplication:
    """Own one store and provide identical context settings to every runtime."""

    def __init__(self, data_dir: str | Path = ".titanx"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store = SQLiteContextStore(self.data_dir / "context.sqlite")

    def create_runtime(
        self, hooks: RuntimeHooks | None = None, *,
        llm: LlmAdapter | None = None, tools: ToolRuntime | None = None,
    ) -> AgentRuntime:
        # A host UUID is separate from the browser's untrusted session selector.
        shared = dict(
            llm=llm or EchoLlm(), safety=SafetyLayer(), hooks=hooks,
            system_prompt="You are an offline TitanX demo assistant.",
            context_options=ContextOptions(self.store, session_id=str(uuid4())),
            compaction_options=CompactionOptions(
                # Leave room for the full sandbox/context tool schemas and
                # six pinned messages, while freeing 25% of the input budget.
                token_budget=12000, target_token_budget=9000,
                model_context_window=20000, reserved_output_tokens=1000,
                safety_margin_tokens=1000, require_structured_summary=True,
            ),
        )
        if tools is not None:
            # Only the synthetic walkthrough substitutes an in-process fixture.
            # Normal terminal and gateway sessions retain the sandbox factory.
            return AgentRuntime(tools=tools, **shared)
        return create_sandboxed_runtime(CreateSandboxedRuntimeOptions(**shared))

    async def close(self):
        await self.store.close()


def create_demo_gateway(data_dir: str | Path = ".titanx", *, port: int = 3000):
    """Build an ASGI app without opening a database at import time."""
    from .gateway import GatewayOptions, create_gateway

    def create_runtime(_client_session_id, hooks):
        return app.state.titanx_application.create_runtime(hooks)

    app = create_gateway(GatewayOptions(
        port=port, create_runtime=create_runtime,
        allowed_origins=[f"http://127.0.0.1:{port}", f"http://localhost:{port}"],
    ))
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app):
        application = DemoApplication(data_dir)
        app.state.titanx_application = application
        try:
            async with original_lifespan(app):
                yield
        finally:
            await application.close()
            del app.state.titanx_application

    app.router.lifespan_context = lifespan
    return app


class _ContextDemoTools(ToolRuntime):
    """Only generates text in-process; no filesystem or network access."""

    def __init__(self):
        self.executions = 0

    def list_tools(self):
        return [ToolDefinition("read_demo_log", "Read the synthetic demo log", {
            "type": "object", "properties": {}, "additionalProperties": False,
        })]

    async def execute(self, name, params):
        if name != "read_demo_log" or params:
            raise ValueError("invalid synthetic log request")
        self.executions += 1
        return ToolExecutionResult(output="synthetic observation\n" * 2000 + "EXACT_RESULT=9182")


class _ContextDemoLlm(EchoLlm):
    def __init__(self):
        self.main_turns = 0

    async def respond(self, config, state):
        if not config.available_tools:
            return await super().respond(config, state)
        self.main_turns += 1
        if self.main_turns == 1:
            return LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("logs", "read_demo_log", {})])
        if self.main_turns == 2:
            message = next(m for m in state.messages if isinstance(m, ToolMessage))
            reference = json.loads(message.content)
            return LlmTurnResult(type="tool_calls", tool_calls=[ToolCall("recall", "context_read", {
                "kind": "artifact", "id": reference["archived_tool_output"],
                "offset": reference["original_chars"] - 64, "limit": 64,
            })])
        if self.main_turns == 3:
            result = json.loads(state.messages[-1].content)
            if "EXACT_RESULT=9182" not in result["content"]:
                raise RuntimeError("archived result could not be recovered")
            return LlmTurnResult(type="text", text="分页回查原文，确认 EXACT_RESULT=9182。")
        return LlmTurnResult(type="text", text=f"按当前任务第 {state.task.revision} 版继续。")


class _TerminalEvents:
    def __init__(self):
        self.reason = None

    def __call__(self, event, config, state):
        if event.type == "assistant_text":
            print(event.text)
        elif event.type == "context_offloaded":
            print(f"[转存] {event.original_chars} → {event.retained_chars} 字符")
        elif event.type == "compaction_triggered":
            print(f"[压缩] {event.input_tokens_before} → {event.input_tokens_after}，目标 ≤ {event.target_tokens}")
        elif event.type == "compaction_failed":
            print(f"[压缩失败] {event.reason}", file=sys.stderr)
        elif event.type == "loop_end":
            self.reason = event.reason
            if event.reason != "completed":
                print(f"[已停止] {event.reason}", file=sys.stderr)


async def check_context(application: DemoApplication) -> None:
    """Verify archive/recall/three compactions using the shared configuration."""
    events, display, tools = [], _TerminalEvents(), _ContextDemoTools()

    def on_event(event, config, state):
        events.append(event)
        display(event, config, state)

    runtime = application.create_runtime(
        RuntimeHooks(on_event=on_event), llm=_ContextDemoLlm(), tools=tools,
    )
    runtime.set_task("查明日志中的精确结果", constraints=("只读",), acceptance_criteria=("结果必须来自原文",))
    await runtime.run_prompt("检查示例日志并读取末尾结果。")
    for i in range(3):
        if i == 1:
            runtime.set_task("整理结果及证据引用", constraints=("只读",), acceptance_criteria=("保留可回查引用",))
        runtime.state.needs_compaction = True
        await runtime.run_prompt(f"继续整理，第 {i + 1} 次。")
    matches = await application.store.search(runtime.config.session_id, "EXACT_RESULT=9182")
    records = await application.store.list_compactions(runtime.config.session_id)
    if (not matches or len(records) != 3 or tools.executions != 1
        or runtime.state.task.revision != 2
        or any(e.type in {"compaction_blocked", "compaction_exhausted"} for e in events)):
        raise RuntimeError("context walkthrough did not complete successfully")
    print(f"完成 {len(records)} 次压缩；原始工具执行 {tools.executions} 次；当前任务版本 {runtime.state.task.revision}。")
    print(f"原文仍可检索：{matches[0]['message_id']}")


async def _run_terminal(args) -> int:
    application = DemoApplication(args.data_dir)
    try:
        if args.check_context:
            await check_context(application)
            return 0
        display = _TerminalEvents()
        runtime = application.create_runtime(RuntimeHooks(on_event=display))
        if args.prompt is not None:
            await runtime.run_prompt(args.prompt)
            return 0 if display.reason == "completed" else 1
        print("输入消息开始；/compact 请求下次压缩，/exit 退出。")
        while True:
            try:
                prompt = await asyncio.to_thread(input, "> ")
            except EOFError:
                return 0
            if prompt.strip() == "/exit":
                return 0
            if prompt.strip() == "/compact":
                runtime.state.needs_compaction = True
                print("已请求压缩，将在下一条消息调用模型前处理。")
                continue
            if not prompt.strip():
                continue
            display.reason = None
            try:
                await runtime.run_prompt(prompt)
            except (ValueError, RuntimeError) as exc:
                print(f"[错误] {exc}", file=sys.stderr)
                continue
            if display.reason != "completed":
                return 1
    finally:
        await application.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TitanX：统一离线示例，默认启用上下文归档、转存和压缩。")
    parser.add_argument("prompt", nargs="?", help="单次输入；不传则进入交互终端")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--web", action="store_true", help="启动本机网页/API 服务")
    mode.add_argument("--check-context", action="store_true", help="验证转存、回查和连续压缩")
    parser.add_argument("--data-dir", type=Path, default=Path(".titanx"), help="归档目录（默认 .titanx）")
    parser.add_argument("--port", type=int, default=3000, help="网页端口（默认 3000）")
    args = parser.parse_args(argv)
    if args.prompt is not None and (args.web or args.check_context):
        parser.error("单次输入不能与 --web 或 --check-context 同时使用")
    if not 1 <= args.port <= 65535:
        parser.error("端口必须在 1 到 65535 之间")
    print("TitanX · 离线模拟模型 · 上下文管理已开启")
    print(f"归档：{args.data_dir / 'context.sqlite'}")
    try:
        if args.web:
            import uvicorn
            app = create_demo_gateway(args.data_dir, port=args.port)
            print(f"网页：http://127.0.0.1:{args.port}")
            uvicorn.run(app, host="127.0.0.1", port=args.port)
            return 0
        return asyncio.run(_run_terminal(args))
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"TitanX: {exc}", file=sys.stderr)
        return 1
