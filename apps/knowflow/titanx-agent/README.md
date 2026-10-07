# KnowFlow agent (`titanx-agent`)

The Python agent service behind KnowFlow's assistant. It adapts the generic
TitanX runtime to KnowFlow: a Kimi (Moonshot) LLM adapter, a tool runtime that
calls the KnowFlow HTTP API, and a gateway bootstrap.

The TitanX SDK is **not** vendored here. It lives once, at the monorepo root
(`../../../titanx`).

## Layout

| Path | Purpose |
| --- | --- |
| `knowflow_agent/llm/kimi.py` | `KimiLlm` — Moonshot `chat/completions` adapter |
| `knowflow_agent/tools/knowflow.py` | `KnowFlowToolRuntime` — the four KnowFlow tools (all `return_direct`) |
| `run_gateway.py` | Session factory + `create_gateway` bootstrap (port 3000) |
| `tests/` | Agent-specific tests; the SDK suite lives at the repo root |

## Setup

The easiest path is the monorepo root venv, which already has the SDK installed
editable (see the root `README.md`); from here you only need the agent package:

```bash
pip install -e ".[dev]"
```

For a standalone venv, install the SDK from the repo root **first**:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ../../..      # the TitanX SDK
pip install -e ".[dev]"      # this agent
```

The SDK is not listed in this package's `dependencies`: a relative
`titanx @ file:../../..` reference is not installable by pip, so it is installed
explicitly instead.

## Run

```bash
KIMI_API_KEY=... python run_gateway.py    # http://localhost:3000
```

Without `KIMI_API_KEY` the gateway falls back to `EchoLlm` (which never calls a
tool).

Environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `KIMI_API_KEY` | — | Moonshot API key; unset ⇒ `EchoLlm` |
| `KIMI_BASE_URL` | `https://api.moonshot.cn` | Chat API base |
| `KIMI_CHAT_MODEL` | `moonshot-v1-8k` | Chat model |
| `KNOWFLOW_API_BASE_URL` | `http://127.0.0.1:8080` | KnowFlow backend the tools call |
| `TITANX_MAX_ITERATIONS` | `8` | Iteration budget per prompt |

## Two things worth knowing

**Deny-by-default policy.** The SDK refuses a registered tool unless the policy
allowlists it. `run_gateway.py` names the four KnowFlow tools in
`KNOWFLOW_TOOLS`; a new tool must be added there or the agent cannot call it.

**Per-session credentials.** The gateway hands the session factory the request
body through the `request_context` parameter, so the per-user bearer token and
user id are bound when the session is created (and reused for that session
afterwards).

## Tests

```bash
python -m pytest -q      # from this directory: knowflow_agent must be importable
```

## Docker

The image is built from the monorepo root, since it needs the SDK source: see
the `titanx-agent` service in `../deploy/docker-compose.yml` and the `Dockerfile`
in this directory.
