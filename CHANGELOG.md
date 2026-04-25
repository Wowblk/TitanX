# Changelog

All notable changes to TitanX (Python) are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0 is released, breaking changes may land in MINOR versions but will
always be flagged in the **Changed** / **Removed** sections.

## [Unreleased]

### Added

- **NemoClaw-parity sandbox hardening** — `AgentPolicy` gains
  `allowed_read_paths` (host paths the workload may read but not
  write; bind-mounted `:ro` by `DockerSandboxBackend`) and
  `image_digest` (OCI digest pin; the Docker backend resolves the
  configured image and refuses to launch on mismatch via
  `ImageDigestMismatch`). Both fields are validated by
  `validate_policy` against the same forbidden subtree list
  (`/etc`, `/proc`, `/var/run/...`) and surfaced by `audit_policy`.
- **Per-tool egress rules** — `OutboundRule` gains a `caller`
  field; `EgressGuard.check`, `check_url`, `check_async`,
  `check_url_async`, and `enforce` accept a matching `caller`
  argument. Matching is fail-closed: a rule pinned to
  `caller="github_tool"` will not match calls that omit the caller.
  `EgressGuard.from_ironclaw_specs(..., scope_to_caller=True)`
  pins each generated rule to its spec name (mirrors NemoClaw's
  `binaries:`).
- **Auto-injected egress caller** — `titanx.safety.egress.caller_scope`
  is a `contextvars`-backed scope; `AgentRuntime` wraps every
  `tools.execute(...)` call in `caller_scope(tool_call.name)` so a
  tool handler that calls `guard.enforce(url, method)` automatically
  gets the dispatched tool's identity as the caller. Explicit
  `caller=` kwargs still win over the ambient binding. The scope
  propagates into asyncio child tasks (`gather`, `run_in_executor`)
  but not into raw `threading.Thread` workers (use
  `contextvars.copy_context()` for those). Exposes
  `current_caller()` for handlers that want to read the binding
  directly.
- **Bundled egress presets** — `titanx.safety.presets` ships
  default-deny `EgressPolicy` builders for `slack`, `github`,
  `discord`, `google` (Gmail / Calendar / Drive / Docs / Sheets /
  Slides + OAuth token endpoint), `huggingface`, `pypi`,
  `npm_registry`, `brave_search`, `composio`, and `telegram`. Use
  `presets.compose(["github", "slack"])` to build a guard policy
  without hand-rolling allowlists.
- **Audit additions** —
  - `audit_policy` reports overlap between `allowed_read_paths`
    and `allowed_write_paths` (the `:ro` mount would shadow the
    `:rw` mount; the flag builder drops the duplicate so audit
    surfaces the misconfig early).
  - `audit_policy` warns when `image_digest` is unset.
  - `audit_egress_policy` warns when a rule pairs `host_pattern="*"`
    with `caller=None` (an unintentionally wildcard egress).
  - New `audit_docker_options` checks that `DockerSandboxBackendOptions`
    pins the image (either inline `@sha256:` or
    `expected_image_digest`).
- **CLI flags** — `python -m titanx.cli audit` accepts
  `--preset {name|help}` (audit a bundled preset),
  `--docker-image` and `--docker-image-digest` (audit a Docker
  backend configuration).
- **Egress allowlist** — `titanx.safety.egress` (`EgressGuard`,
  `EgressPolicy`, `OutboundRule`, `EgressDenied`,
  `audit_log_egress_hook`). Closes the gap where
  `IronClawWasmToolSpec.http_allowlist` was declarative metadata only;
  hosts that issue HTTP from inside a tool can now route through the
  guard for default-deny enforcement with structured audit entries.
  `EgressGuard.from_ironclaw_specs(IRONCLAW_WASM_TOOLS)` builds a
  policy directly from the bundled catalog.
- **Security audit CLI** — `python -m titanx.cli audit` (also installed
  as the `titanx` console script). Loads JSON-formatted `AgentPolicy`
  and `GatewayOptions`, inspects audit-log file permissions, runs
  `audit_egress_policy`, and emits a human-readable table or
  `--json`. `--fix` applies the only auto-fixable findings (file/dir
  permissions); `--fail-on=critical|warn` controls the exit code.
- **Programmatic audit API** — `titanx.audit.audit_policy`,
  `audit_gateway_options`, `audit_audit_log_path`,
  `audit_egress_policy`, and the composite `audit_runtime`. Each returns
  an `AuditReport` of `AuditFinding` dataclasses (`severity` ∈
  `{critical, warn, info, ok}`).
- **SECURITY.md** — explicit trust model, in-scope defenses,
  out-of-scope assumptions, and a researcher preflight that points at
  the audit CLI.

### Changed

- `SandboxBackend.create_session` and `ResilientSandboxBackend.create_session`
  accept new keyword-only arguments `allowed_read_paths` and
  `image_digest`. Existing custom backends keep working: the
  session manager only forwards the new kwargs when the operator
  actually populated the corresponding policy fields, so backends
  written against the 0.2.x signature still accept the call.
- `SandboxExecutionRequest` gains optional `allowed_read_paths` and
  `image_digest` fields. Tool runtime / session manager
  late-bind them from the live `AgentPolicy` if the handler did
  not set them itself.
- `pyproject.toml` registers a `titanx` console script entry point
  (`titanx.cli:main`).

## [0.2.0] - 2026-04-25

Hardening release: 10 production-blocking issues (Q13–Q22) fixed across the
runtime, gateway, sandbox, retrieval, storage, and policy layers. See the
**Migration notes** at the bottom of this file before upgrading from 0.1.x.

### Added

- **Gateway** — `GatewayOptions` gained `allowed_origins`, `allowed_methods`,
  `allowed_headers`, `max_sessions`, and `session_idle_ttl_seconds`. CORS is
  now opt-in instead of `*`-by-default and the session map is bounded with
  LRU + idle-TTL eviction. Startup logs a stderr warning when `api_key` is
  unset or when CORS is left at `*`. (Q14)
- **Gateway** — `titanx.gateway.session_registry.SessionRegistry` exposes the
  bounded session map for hosts that want to introspect or pre-populate it.
  Concurrent `run_prompt` calls against the same `session_id` are serialised
  by a per-entry `asyncio.Lock`. (Q14)
- **Audit** — `AuditLog(secondary_sink=...)` fan-out hook plus the
  `titanx.policy.storage_secondary_sink` adapter for routing entries into a
  `StorageBackend.save_log` schema. The on-disk JSONL remains the canonical
  pipeline. (Q20)
- **Break-glass** — `BreakGlassController.revoke(reason)` and `aclose()` for
  graceful operator-driven and shutdown-driven rollback. Exposed
  `BreakGlassController.is_active()` for observability. (Q15)
- **Sandbox** — `SandboxRouterInput.min_isolation` lets callers refuse to
  silently downgrade to a weaker backend (e.g. `wasm` when only `wasm` is
  reachable but the call requires `docker`). New `SandboxRouter(on_selection=)`
  observability callback fires on every successful backend selection. (Q18)
- **Sandbox** — `SandboxSessionManager` now accepts `max_sessions`,
  `idle_ttl_seconds`, and `policy_store=` for live `allowed_write_paths`
  lookup. New `aclose()` destroys all live backend sessions and cleans up
  workspace directories. (Q19)
- **Resilience** — `RetryOptions.max_total_time_ms` enforces a wall-clock
  ceiling across all attempts and inter-attempt sleeps. (Q16)
- **Runtime** — `LoopEndEvent(reason="cancelled")` is emitted when the host
  cancels the task running `run_prompt`. (Q22)

### Changed

- **Runtime** — `state.iteration` resets to `0` at the start of every
  `run_prompt`. `max_iterations` therefore caps work per user turn, not per
  session. Long-lived gateway sessions that previously went silent after
  hitting a per-session ceiling now work correctly. (Q13)
- **Runtime** — `run_prompt` rejects empty input and inputs longer than
  `_MAX_PROMPT_LENGTH = 100_000` with `ValueError` directly at the trust
  boundary. The redundant second injection scan that previously ran inside
  `validate_input` is gone. (Q21)
- **Runtime** — When the host cancels `run_prompt` mid tool-execution, the
  runtime now appends a synthesised `ToolMessage` for the in-flight call,
  sets `state.signal = "interrupt"`, and re-raises `asyncio.CancelledError`.
  `state.pending_tool_call_index` advances past the cancelled call so a
  subsequent `resume()` continues from the next pending tool. The previous
  behaviour left the assistant `tool_call` without a matching tool result,
  which broke OpenAI/Anthropic protocol on the next turn. (Q22)
- **Gateway** — API-key comparison now uses `hmac.compare_digest` to defeat
  timing attacks; WebSocket handlers authenticate inline before
  `accept()`, since Starlette HTTP middleware does not run on WS handshakes.
  (Q14)
- **Resilience** — `with_retry` no longer retries `asyncio.CancelledError` or
  `KeyboardInterrupt`. Cooperative cancellation always propagates
  immediately. (Q16)
- **Storage (libsql)** — `_cosine` raises `ValueError` on dimension mismatch
  instead of silently truncating the longer vector. `LibSQLBackend.save_memory`
  now persists the row and FTS index in a single transaction; partial writes
  no longer leave the FTS view inconsistent. `search_by_vector` is bounded by
  `max_vector_scan` (default 5,000) and orders rows by `created_at DESC` so a
  growing memory table doesn't pin scans forever. (Q17)
- **Sandbox** — `SandboxSessionManager` consults the live `policy_store` for
  `allowed_write_paths` on every `create()` and `write_files()`. The
  constructor list is a fallback for hosts without a `PolicyStore`. (Q19)

### Deprecated

- **Break-glass** — `BreakGlassController.dispose()` cancels the TTL timer
  but does **not** roll back the relaxed policy. Retained for source-compat
  only; new code must use `revoke()` or `aclose()`. The deprecated path will
  be removed in a future release. (Q15)

### Fixed

- **Runtime** — `state.approved_tool_call_ids` no longer leaks across
  `run_prompt` invocations; an approval granted in turn N can no longer
  silently auto-approve a re-issued tool call in turn N+1. (Q13)
- **Break-glass** — `ttl_ms <= 0` and non-int (incl. `bool`) values are
  rejected at `activate()` instead of producing a 1-millisecond session.
  Concurrent activate / expire / revoke are serialised by a single
  `asyncio.Lock`, eliminating double-rollback / double-audit races. Snapshot
  of the pre-relaxation policy is deep-copied so subsequent edits to the live
  policy cannot mutate audit history. (Q15)
- **Sandbox** — `SandboxRouter` no longer silently picks a weaker backend
  when the requested isolation tier is unavailable. With `min_isolation` set,
  it raises `RuntimeError` with a per-backend rejection trail. (Q18)
- **Sandbox** — `SandboxSessionManager.destroy()` now best-effort cleans the
  per-session workspace directory in a worker thread, so long-running hosts
  no longer accumulate orphan dirs in `workspace_dir`. (Q19)
- **Audit** — A failing `secondary_sink` is permanently disabled with a
  stderr warning instead of breaking subsequent `append()` calls. The on-disk
  JSONL pipeline is unaffected, so audit failures cannot mask policy
  failures. (Q20)

### Tests

- New pytest suite covers Q13–Q22 hardening:
  `tests/test_runtime_lifecycle.py`, `tests/test_break_glass.py`,
  `tests/test_retry.py`, `tests/test_gateway_hardening.py`,
  `tests/test_libsql_cosine.py`, `tests/test_sandbox_router.py`,
  `tests/test_session_manager.py`, `tests/test_audit_sink.py`. Plus the
  existing `tests/test_path_guard.py` regression suite. Run with `pytest`.

## Migration notes

- **Hosts that called `BreakGlassController.dispose()`** must switch to
  `revoke()` (operator-driven) or `aclose()` (shutdown-driven). The old call
  no longer rolls back the policy.
- **Hosts that cancel `run_prompt`** must let `asyncio.CancelledError`
  propagate; swallowing it leaks the cancellation contract and prevents the
  runtime from emitting `LoopEndEvent(reason="cancelled")`. After cancel,
  `state.signal == "interrupt"`; call `resume()` to continue from the next
  pending tool, or drop the runtime to reset.
- **Hosts that ran without `api_key`** still work, but a stderr warning fires
  on startup. Set `GatewayOptions.api_key` to silence it. Likewise for
  `allowed_origins=["*"]`.
- **Hosts that called `SandboxBackend.create_session(...)` directly** now
  receive an `allowed_write_paths` keyword argument forwarded by the session
  manager. Custom backend implementations should add the kwarg (default
  `None`) to stay compatible — the existing E2B and Docker backends already
  do.
- **Hosts that wrote audit entries directly to `StorageBackend.save_log`**
  should switch to a `secondary_sink` on `AuditLog` so the JSONL file and
  the relational store stay reconciled.
