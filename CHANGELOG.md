# Changelog

All notable changes to TitanX (Python) are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0 is released, breaking changes may land in MINOR versions but will
always be flagged in the **Changed** / **Removed** sections.

## [Unreleased]

### Added

- **Single transcript owner** — wholesale replacement of the active message
  list now goes through one `Transcript` owner (`titanx/context/transcript.py`),
  shared by context offloading (`ContextManager.prepare`) and compaction. The
  owner enforces the invariants that were previously only maintained by call
  ordering: host-pinned system messages are preserved, at most one active
  summary survives, and assistant `tool_calls` stay paired with their `tool`
  results. `AgentRuntime.transcript` exposes the owner
  (`docs/design-review-2026-10-07.md` problem #5).
- **Runtime teardown contract** — `AgentRuntime.aclose()` (idempotent, never
  raises) flushes/archives the transcript and tears down the tool layer;
  `SandboxedToolRuntime.aclose()` forwards to the session manager. The gateway
  runs teardown on idle/LRU eviction and on shutdown, and per-session context
  rows are deleted so sessions no longer leak. Eviction tears down swept victims
  even if session creation subsequently fails, so a detached session cannot leak
  its sandbox/storage resources (`docs/design-review-2026-10-07.md` problem #6).
- **`titanx-app` console script and demo wiring** — `pyproject.toml` now
  registers `titanx-app = titanx.application:main` (the audit CLI remains
  `titanx`), and `create_demo_gateway(storage=, retriever=)` accepts optional
  backends so the `/api/memory`, `/api/jobs` and `/api/logs` routes are served
  instead of always returning 501. `server.run_gateway` is intentionally
  **kept** as exported public API (the programmatic one-call launcher); the
  `create_demo_gateway` default still builds with no backend so an unconfigured
  host keeps its hermetic behavior, while `application.main --web` opens a
  `LibSQLBackend` under the data dir so the shipped CLI serves those routes
  without 501 (`docs/design-review-2026-10-07.md` problem #12).

### Changed

- **Deny-by-default tool authorization** — registered tools that do not require
  approval are now **denied** unless explicitly allowlisted via
  `AgentPolicy.tool_allowlist` (a validated, normalized list of tool names). The
  `PolicyStore.check_tool_call` precedence is denylist → unregistered → approval
  gate → allowlist → deny, with `auto_approve_tools` as an explicit global
  opt-in. **Breaking:** hosts that relied on the previous implicit allow must add
  their tools to the allowlist (helper: `PolicyStore.allow_tools()`), or, when
  using `create_sandboxed_runtime`, via the new
  `CreateSandboxedRuntimeOptions.tool_allowlist` field — so a factory-built
  runtime can authorise its own non-approval handlers without hand-building a
  `PolicyStore`. Matches TXS-02
  (`docs/design-review-2026-10-07.md` problem #4).
- **MCP authorization unified under `PolicyStore`** — `McpAdmissionRuntime`
  accepts an optional `policy_store`, projects admitted `mcp__{server}__{tool}`
  names into the single allowlist plane, and writes discovery/admit/deny/drift
  decisions into the shared `AuditLog` with the `policy_epoch`. MCP tools carry
  `ToolDefinition.mandatory_approval` so they cannot be silently auto-approved
  (`docs/design-review-2026-10-07.md` problem #3).
- **Output-token budget is no longer silently rewritten** — the runtime no
  longer overwrites `max_output_tokens` with `reserved_output_tokens` (which is
  a compaction-budget reserve only). Hosts can set the limit explicitly via
  `create_config(max_output_tokens=...)` or `AgentRuntime(max_output_tokens=...)`
  (`docs/design-review-2026-10-07.md` problem #7).
- **Single canonical API-key check** — `titanx/gateway/chat.py` had a second
  `_check_api_key` with the opposite semantics to the one in
  `titanx/gateway/server.py`. There is now one documented helper: if no key is
  configured the gateway is open; if a key is configured, a non-empty
  constant-time match is required. The dead `require_api_key` was removed
  (`docs/design-review-2026-10-07.md` problems #11, #15).
- **Gateway bind default unified** — `create_gateway`/`run_gateway` and
  `application.main` now default to loopback (`127.0.0.1`) and accept an
  explicit host, instead of disagreeing between `127.0.0.1` and `0.0.0.0`
  (`docs/design-review-2026-10-07.md` problem #12).
- **`StorageBackend.save_log` deprecated** — the second audit table is no longer
  a lossy path: `storage_secondary_sink` now stores the full audit record
  (including `execution_id`/`run_id`/`batch_id`/`ordinal`/`policy_epoch` and the
  remaining details). The `save_log` interface method is kept but marked
  deprecated (`docs/design-review-2026-10-07.md` problem #13).
- **`BreakGlassController.dispose()` rolls back (breaking)** — `dispose()` is now
  **async** and restores the pre-break-glass policy instead of only cancelling
  the expiry timer, so disposing cannot leave elevated permissions live. It is
  idempotent and safe when no grant is active (`docs/design-review-2026-10-07.md`
  problem #14).

### Fixed

- **Tool audit records carry identity, session and tool contract** —
  `ExecutionGuard.audit_details()` now emits `thread_id`, `session_id`,
  `user_id`, `channel` (from the operation-bound `ToolIntent.identity`) and the
  `contract_digest` alongside the existing execution IDs. `tool_decision` and
  `tool_invocation` records routed through `audit_details()` — i.e. those that
  reach a prepared `ToolIntent` — can now be attributed to the host
  identity/session and to the exact tool contract that was authorized, as
  required by TXS-11, without joining against mutable runtime state or the live
  tool catalog (`docs/design-review-2026-10-07.md` problem #2).
- **MCP `list_tools()` fails loud before `discover()`** — an undiscovered
  `McpAdmissionRuntime` now raises `McpAdmissionError` instead of returning an
  empty tool list, so a runtime constructed before discovery surfaces the
  mistake at construction rather than silently dispatching `unknown_tool`
  (`docs/design-review-2026-10-07.md` problem #8).
- **Context store close hardening** — `SQLiteContextStore` raises a typed
  `ContextStoreClosedError` (a `sqlite3.ProgrammingError` subclass, now exported
  from `titanx`/`titanx.context`) for operations after `close()`, re-checks the
  closed flag under its lock so a worker queued before `close()` fails with that
  same typed error instead of a raw driver error, and makes `close()` idempotent.
  The single write lock still serializes sessions, and a cancelled caller's
  `to_thread` worker still runs to completion — it releases the lock when it
  returns, so the store is not permanently wedged, but cancellation does not stop
  the in-flight transaction (`docs/design-review-2026-10-07.md` problem #9).
- **PTL drops the group the configured tokenizer ranks largest** —
  `ContextCompactor` victim selection now uses `options.token_estimator` rather
  than a byte-size estimate, and no longer deep-copies the frozen config on every
  estimate (`docs/design-review-2026-10-07.md` problem #10).
- **Documentation drift corrected** — demo transcript size, the compaction commit
  condition, the compaction enable condition, `resume()` exclusivity, and the
  pre-integration status table were corrected against the implementation
  (`docs/design-review-2026-10-07.md` problem #16).

### Removed

- Dead runtime/gateway code: `AgentRuntime._effective_auto_approve`,
  `AgentRuntime.wait_for_approval` (and its `_approval_event`), and the
  unreachable `require_api_key` (`docs/design-review-2026-10-07.md` problem #15).

## [0.4.0] - 2026-10-07

### Added

- **Operation-bound tool authorization** — `ToolIntent`, private `ApprovalGrant`
  records and `ExecutionGuard` bind approval to the run, batch, arguments,
  registered contract, host identity and monotonic policy revision. Approval
  expires (300 seconds by default), can be revoked before admission, and is
  consumed once. Every dispatch validates JSON Schema and bounded JSON values,
  then rechecks authorization after awaited audit/hooks. Overlapping runtime
  runners are refused; same-task resume from the paused gateway hook remains
  supported. See the [trigger and implementation report](docs/model-tool-loop-operation-authorization.md).
- **Context archive and bounded recall** — optional session-scoped SQLite
  transcripts, large inspected tool-output offloading, paged `context_read`
  and literal `context_search`. Originals and summary provenance are committed
  before replacing the active view. Host-owned versioned `TaskState`, structured
  LLM summaries, adapter token counting, lower compaction targets, output/window
  reserves, summary/storage timeouts and richer events support long sessions.
  `retry_context()` recovers context failures without replaying completed tool
  batches; a failed final archive retries storage only. Legacy strategies remain
  supported. Includes an offline demo and [design/trigger report](docs/context-management.md).
- **Deny-by-default MCP admission runtime** — transport-independent
  `McpAdmissionRuntime` accepts official Python SDK object shapes without a
  core `mcp` dependency, exposes only tools present in exact server and tool
  allowlists as `mcp__{server_id}__{tool}`, and requires approval plus output
  sanitization by default. Initial discovery caches a SHA-256 baseline of
  the model-visible contract (`name`, `title`, `description`, `inputSchema`,
  and `outputSchema`); optional administrator-supplied contract pins protect
  first contact, while unpinned tools are labelled as process-local TOFU.
  Execution re-lists by default and refuses tool-surface or contract drift.
  Discovery time/tool count/contract size and call time/result size are
  bounded, MCP annotations cannot relax approval, and result `_meta` is
  excluded while text, structured content, and `isError` are preserved.
- **SSRF private-destination block** — `EgressPolicy.block_private_addresses`
  (default `True`) refuses outbound URLs whose authority resolves to
  literal RFC1918 / loopback / link-local / CGNAT / multicast /
  reserved IPs, or to a known cloud-metadata sentinel hostname
  (`metadata.google.internal`, `instance-data`, `metadata.azure.com`,
  …). The check runs **before** the allowlist so a rule that matches
  `*.example.com` cannot accidentally permit reaching
  `169.254.169.254` because of a hostile DNS record. Per-rule opt-out
  via `OutboundRule.allow_private=True` (auditable; flagged by
  `audit_egress_policy`). Operator-extended sentinels via
  `EgressPolicy.extra_blocked_hostnames`. Decision exposes
  `private_address_category` so audit consumers can branch on the
  *kind* of SSRF block.
- **Outbound secret scan** — `OutboundSecretScanner` inspects URL +
  headers + body of an `EgressGuard.enforce(...)` call and detects
  vendor-specific credential shapes (GitHub PAT, AWS access/secret
  key, Slack/Stripe/JWT/Bearer/private-key/Anthropic/OpenAI/Google/
  SendGrid). `EgressPolicy.outbound_secret_action` ∈
  `{"warn", "block", "off"}` (default `"warn"`) controls whether a
  hit downgrades the decision to deny or just adds a finding to the
  audit hook. Matched values are deliberately not stored in the
  decision or audit payload — only the pattern names — so the audit
  log does not become its own exfil path.
- **Audit additions for SSRF + secret scan** —
  `audit_egress_policy` now reports
  `block_private_addresses` posture (critical when off),
  `outbound_secret_action` posture (info/warn/ok), and lists every
  `OutboundRule` with `allow_private=True` so a reviewer can see the
  surface.
- **Sidecar WASM backend (skeleton)** — `titanx-sidecar` Rust crate
  at `sidecar/` plus Python adapter
  `titanx.sandbox.backends.SidecarSandboxBackend`. Tools execute in a
  separate OS process, isolating the agent's heap from a hostile or
  miscompiled WASM module. The Rust binary registers WASI preview1
  only — `wasi-sockets` and `wasi-http` imports fail at instantiation
  (structural network deny). Per-call `memory_bytes`, `fuel`, and
  `wall_clock_ms` enforced in both processes. NDJSON over stdin/
  stdout for IPC; protocol envelope and error codes documented in
  `docs/sidecar-rfc.md`. v0.1.0 ships preview1; the WIT
  capability-handle path is sketched in `sidecar/wit/titanx.wit` and
  scheduled for a follow-up. The Python adapter is fully tested
  against a scripted fake; the Rust crate's tests are present but
  the build system is not wired (operator runs `cargo build
  --release` themselves).
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
- **Background sandbox sessions** — `run_command` detects long-running
  commands (`--watch`, `tail -f`, `redis-server`, …) and launches them in a
  persistent Docker session instead of blocking the turn. The result returns a
  `sessionId` plus log/status/pid paths that a later `run_command` call can
  poll, inspect, or kill. Background work refuses the stateless WASM backend
  and still passes through the host-side write-path whitelist.
- **Package-install scanner** — `titanx.safety.package_scanner` adds static
  pre-install analysis of package sources (no runtime wiring; opt-in).
- **OpenAI-compatible provider adapter** — `OpenAIChatLlm` (OpenAI / Kimi /
  Moonshot) selectable at the entry points via `TITANX_LLM_PROVIDER`; the
  offline `EchoLlm` remains the default when no credentials are present.

### Changed

- **Approval protocol** — gateway approve/reject requests must return the
  `executionId` from the pending approval as well as `toolCallId`. The bundled UI
  displays the operation and sends both fields. Direct SDK calls retain the
  no-argument `approve_pending_tool()` API; async hosts should pass `execution_id`.
  `AgentState.approved_tool_call_ids` is now observation-only. Tool contracts and
  parameters must be bounded JSON, schemas are enforced, and runtime catalog
  drift is refused. This adds the `jsonschema` dependency.
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

### Fixed

- **Default factory now arms sandbox write isolation** — `create_sandboxed_runtime`
  shares a single `PolicyStore` between `SandboxedToolRuntime` and
  `AgentRuntime`, so the write-path whitelist and its Docker mount propagation
  are enforced in the default wiring (previously the tool layer saw `None` and
  skipped the host-side check entirely). An explicit empty whitelist (`[]`)
  fails closed instead of reading as "unrestricted"; `None` still means
  "no whitelist configured" for direct SDK construction.
- **Compaction summary accumulation and stale budget checks** — previous SDK
  summaries now merge into one replacement summary. Preflight sizes the current
  system prompt, tools, messages, arguments and results using a configurable
  estimator, then checks the rebuilt request before committing. Oversized or
  uncountable inputs stop before the model call with `compaction_blocked`;
  failed attempts preserve history and usage, and PTL keeps tool groups intact.
  See [the reproduction and repair report](docs/context-compaction.md).
- **SDK prompt admission during approval** — `run_prompt()` now rejects new
  input before changing state whenever an approval or uncleared tool batch
  remains. Approving or rejecting a tool still requires `resume()` before
  starting a new prompt, preserving message order, approvals, and iteration
  budgets. See [the issue and repair report](docs/runtime-prompt-admission.md).
- **Routed circuit-breaker recovery** — cooled-down backends can re-enter
  sandbox selection without reserving a recovery probe during availability
  checks. Execution still admits only one half-open probe at a time;
  cancelled probes release their slot without changing health counters.
  Reproduction conditions, failure evidence, and validation are recorded in
  [the recovery report](docs/circuit-breaker-routing-recovery.md).
- **Runtime protocol and at-most-once execution** — tool-call batches are
  detached from adapter, history, event, and dispatch objects; cancellation
  closes every declared call exactly once; and the execution cursor commits as
  soon as a tool returns. Validator, safety inspection, audit, or observer
  failures therefore cannot replay an external side effect. Tool exceptions
  and reported errors are recorded without persisting raw backend text, and
  optional escaped trust-boundary wrappers make tool output explicit to the
  model.
- **Policy and audit mutation bypasses** — `PolicyStore` no longer exposes live
  policies or internally stored snapshots through mutable return values, and
  `AuditLog` detaches caller, reader, secondary-sink, and JSONL-queue objects so
  append-only evidence cannot be rewritten through a shared reference.
- **Fail-closed sandbox routing** — explicit isolation floors can no longer
  weaken the floor derived from a tool's risk and capabilities. Browser/remote,
  network/package/filesystem, and WASM workloads refuse backends that do not
  satisfy their required isolation or advertised capabilities instead of
  silently downgrading.
- **Gateway approval and stream integrity** — each SSE/WebSocket run has
  task-local event hooks; approve/reject decisions must match the exact pending
  `toolCallId`; host rejection is audited and emitted as a terminal tool result;
  and active or approval-blocked sessions cannot be evicted by TTL/LRU. A full
  registry whose sessions are all active now rejects new sessions safely.

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
