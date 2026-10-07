# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`titanx-agent` is the KnowFlow application layer on top of the TitanX SDK. The
SDK is not vendored: it lives once at the monorepo root (`../../../titanx`) and
this package depends on it as a path dependency. **When a change belongs to the
SDK (runtime, types, gateway, policy), edit `../../../titanx/` — not this
directory.**

## Commands

```bash
# Setup (Python >= 3.11); pulls the monorepo SDK in as a path dependency
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start the FastAPI gateway on http://localhost:3000
python run_gateway.py

# Agent tests. Run from this directory so ``knowflow_agent`` is importable;
# the SDK suite (repo root) is separate.
python -m pytest -q
python -m pytest tests/test_knowflow_tools.py -q
```

## What lives here

| Location | Responsibility |
|---|---|
| `knowflow_agent/llm/kimi.py` | `KimiLlm` — Moonshot `chat/completions` `LlmAdapter` |
| `knowflow_agent/tools/knowflow.py` | `KnowFlowToolClient` (HTTP) + `KnowFlowToolRuntime` (the four tools) |
| `run_gateway.py` | Session factory + `GatewayOptions`/`create_gateway` bootstrap |

Imports of the SDK use absolute paths (`from titanx.types import ...`) because
the SDK is a separate distribution.

## Key design decisions

- **All four KnowFlow tools are `return_direct`.** Their result *is* the answer,
  so the SDK ends the turn on that output instead of asking the LLM to summarise
  it. The user-facing wording lives in `KnowFlowToolRuntime._format_output`
  (application side) — the SDK never hard-codes business copy.
- **The policy is deny-by-default.** A registered tool is refused unless its name
  is in `AgentPolicy.tool_allowlist`. `run_gateway.py` allowlists the four tools
  via `KNOWFLOW_TOOLS`; add any new tool there.
- **Per-session credentials arrive through `request_context`.** The gateway's
  session factory opts in by naming its third parameter `request_context`; it
  receives the `POST /api/chat` body (or the first WS frame), from which the
  bearer token and user id are read. The body is consulted only when the session
  is created.
- **`run_gateway.py` supports two LLMs**: `KimiLlm` when `KIMI_API_KEY` is set,
  otherwise the offline `EchoLlm` (which never calls a tool).

## Related

- SDK API surface and architecture: `../../../CLAUDE.md` and `../../../README.md`.
- Deployment (compose, Dockerfile build context): `../deploy/docker-compose.yml`.
  The `titanx-agent` image builds from the monorepo root because it needs the
  SDK source.
