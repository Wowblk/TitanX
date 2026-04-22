# TitanX

TitanX is a Python Agent SDK for building autonomous agents with explicit runtime semantics, multi-layer safety, policy controls, context compaction, and sandboxed tool execution.

This repository now tracks the Python implementation. The previous TypeScript implementation is kept next to it as `../TitanX-ts/` for reference.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python demo.py
```

## Gateway Demo

```bash
python run_gateway.py
```

The gateway starts on `http://localhost:3000`.

## Project Layout

| Path | Purpose |
| --- | --- |
| `titanx/runtime.py` | Main agent runtime loop |
| `titanx/types.py` | Core dataclasses and adapter interfaces |
| `titanx/factory.py` | Default runtime wiring |
| `titanx/safety/` | Input validation, redaction, and safety checks |
| `titanx/sandbox/` | Tool runtime, router, path guard, and backend interfaces |
| `titanx/resilience/` | Retry and circuit breaker support |
| `titanx/context/` | Token tracking and compaction |
| `titanx/policy/` | Policy store, audit log, and break-glass controls |
| `titanx/storage/` | Storage backend interfaces and implementations |
| `titanx/retrieval/` | Hybrid retrieval and MMR ranking |
| `titanx/tools/` | Optional tool catalogs, including IronClaw-inspired WASM tools |
| `titanx/gateway/` | FastAPI gateway and UI serving |

## IronClaw WASM Tool Catalog

TitanX includes an optional catalog of IronClaw-inspired WASM tools: `github`,
`gmail`, `google_calendar`, `google_docs`, `google_drive`, `google_sheets`,
`google_slides`, `slack`, `telegram_mtproto`, `web_search`, `llm_context`, and
`composio`.

Enable the catalog when constructing the runtime:

```python
from titanx import CreateSandboxedRuntimeOptions, create_sandboxed_runtime
from titanx.sandbox import WasmCommandRegistration

runtime = create_sandboxed_runtime(CreateSandboxedRuntimeOptions(
    llm=llm,
    safety=safety,
    enable_ironclaw_wasm_tools=True,
    wasm_commands={
        # Each command should point to a TitanX-compatible WASI wrapper.
        "web_search_tool": WasmCommandRegistration(module_path="./wasm/web_search_tool.wasm"),
        "github_tool": WasmCommandRegistration(module_path="./wasm/github_tool.wasm"),
    },
))
```

The ABI for these handlers is `titanx-wasi-json-argv`: TitanX executes a
registered WASI command and passes one JSON argument:

```json
{"tool":"web_search","action":"search","params":{"query":"TitanX"}}
```

This intentionally does not assume IronClaw's component-model/WIT ABI. To run
the actual tools, compile or wrap them as TitanX-compatible WASI commands that
read `argv[1]` and write their result to stdout.

## Minimal LLM Adapter

```python
from titanx import AgentConfig, AgentState, LlmAdapter, LlmTurnResult


class EchoLlm(LlmAdapter):
    async def respond(self, config: AgentConfig, state: AgentState) -> LlmTurnResult:
        last = next((m for m in reversed(state.messages) if m.role == "user"), None)
        return LlmTurnResult(type="text", text=f"Echo: {last.content}" if last else "Hello")
```

Pass your adapter into `create_sandboxed_runtime()` to run TitanX with any LLM provider.
