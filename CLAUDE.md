# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup (Python >= 3.11)
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run the stub demo (wires EchoLlm through the full runtime)
python demo.py

# Start the FastAPI gateway on http://localhost:3000
python run_gateway.py

# Tests (pytest + pytest-asyncio, asyncio_mode=auto)
pytest                       # run everything
pytest tests/test_safety.py  # single file
pytest -k router             # by keyword
```

No linter/formatter is configured. The TypeScript implementation has been removed from `main`; it lives on the `ts` branch and in a sibling `../TitanX-ts/` checkout.

## Architecture

TitanX is a Python Agent SDK for building autonomous agents with explicit runtime semantics, multi-layer safety, and sandboxed tool execution. Control flow is plain async Python — **not** LangGraph or any other graph framework.

### Request Lifecycle

```
AgentRuntime.run_prompt(input)
  → SafetyLayer          (injection detection, PII redaction, path-escape blocking)
  → runtime loop         (explicit signal: "continue" | "stop" | "interrupt")
      ├─ LlmAdapter.respond(config, state)   (user-supplied; TitanX is LLM-agnostic)
      ├─ ContextCompactor                    (summarize + PTL fallback on budget overflow)
      ├─ SandboxRouter                       (WASM / Docker / E2B by risk level)
      │    └─ ResilientSandboxBackend        (retry + circuit breaker wrapper)
      ├─ PolicyStore                         (dynamic policies, approval gates, break-glass)
      └─ AuditLog                            (append-only JSONL for every policy/tool event)
```

### Key Design Decisions

- **Config vs. state split**: `AgentConfig` is `@dataclass(frozen=True)`; `AgentState` is mutable. Never merge them.
- **LlmAdapter is user-supplied**: implement `async def respond(config, state) -> LlmTurnResult` to plug in any LLM. See `EchoLlm` in `demo.py` for the minimal shape.
- **Three-tier sandboxing**: WASM (low-risk, registered commands), Docker (medium, filesystem), E2B (high, remote/browser).
- **Compaction**: optional but critical for long sessions. `CompactionStrategy.summarize()` is called when the token budget is exceeded; on failure, PTL strips the oldest 20% of messages and retries.
- **Circuit breaker**: 3-state machine (closed → open → half-open) with rolling-window failure tracking, configurable per backend.
- **PolicyStore** snapshots are versioned for rollback; `BreakGlassController` grants time-limited elevated permissions with full audit trail.
- **IronClaw WASM catalog** (optional): enable via `enable_ironclaw_wasm_tools=True` on `CreateSandboxedRuntimeOptions`. ABI is `titanx-wasi-json-argv` — each registered WASI command receives one JSON argument via `argv[1]` and writes its result to stdout.

### Module Map

| Location | Responsibility |
|---|---|
| `titanx/runtime.py` | Main event loop — orchestrates all subsystems |
| `titanx/types.py` | Core dataclasses: `AgentConfig`, `AgentState`, messages, `ToolCall`, `LlmAdapter`, `LlmTurnResult`, `RuntimeHooks` |
| `titanx/state.py` | State builders, message append, approval management |
| `titanx/factory.py` | `create_sandboxed_runtime()` — default wiring via `CreateSandboxedRuntimeOptions` |
| `titanx/safety/` | `SafetyLayer`: injection patterns, PII patterns, path-escape scenarios, single-pass redaction |
| `titanx/resilience/` | `CircuitBreaker`, retry with exponential backoff + jitter, `ResilientSandboxBackend` |
| `titanx/sandbox/` | `SandboxRouter`, `SandboxedToolRuntime`, `PathGuard`, `SessionManager` |
| `titanx/sandbox/backends/` | `WasmSandboxBackend` (wasmtime), `DockerSandboxBackend` (aiodocker), `E2BSandboxBackend` |
| `titanx/context/` | Token tracking, `ContextCompactor`, PTL retry strategy |
| `titanx/policy/` | `PolicyStore` (snapshots/rollback), `BreakGlassController`, `AuditLog` |
| `titanx/storage/` | `StorageBackend` interface; `PgVectorBackend` (asyncpg + pgvector), `LibsqlBackend` (Turso/SQLite) |
| `titanx/retrieval/` | `HybridRetrieval` (vector + FTS), `MMR`, time-decay scoring |
| `titanx/tools/ironclaw_wasm.py` | Optional IronClaw-inspired WASM tool catalog |
| `titanx/gateway/` | FastAPI server; routes: `/api/chat`, `/api/memory`, `/api/jobs`, `/api/logs`; browser UI served from `../ui` |

### Extension Points

- **Custom LLM**: subclass `LlmAdapter` from `titanx/types.py` and implement `respond()`.
- **Custom compaction**: implement `CompactionStrategy`.
- **Custom sandbox backend**: implement `SandboxBackend` from `titanx/sandbox/types.py`.
- **Custom storage**: implement `StorageBackend` from `titanx/storage/types.py`.
- **Custom embedding**: implement `EmbeddingProvider` from `titanx/retrieval/types.py`.

Use `create_sandboxed_runtime()` from `titanx/factory.py` to wire components together. For a minimal working example, see `demo.py`; for the gateway wiring, see `run_gateway.py`.
