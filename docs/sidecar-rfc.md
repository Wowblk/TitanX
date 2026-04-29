# RFC — TitanX WASM Sidecar (process-isolated WASM tool runtime)

Status: **draft, partially implemented (v0.2 component path in progress)**

Author: TitanX
Last updated: 2026-04-25

## Why this RFC exists

TitanX 0.3.x ships an in-process `WasmSandboxBackend` that loads tools
via the Python `wasmtime` binding. That works but has three structural
gaps the IronClaw / NemoClaw security models close natively:

1. **No capability-based security.** Tools see WASI preview1 — they
   get a stdin/stdout/argv view of the world, not capability handles.
   A tool's "I need `http:get`" declaration in
   `IronClawWasmToolSpec.http_allowlist` is metadata only; nothing in
   the WASM runtime knows what the tool *should* be allowed to do, so
   nothing can refuse `wasi-sockets` syscalls. We mitigate this today
   with `EgressGuard` (Python-side) and `--network=none` (Docker), but
   neither catches a WASM tool that opens a socket directly.

2. **No process isolation.** A bug in `wasmtime` (memory unsafety,
   miscompilation of a hostile module, fuel-budget bypass) propagates
   into the same Python process that runs the agent loop, the policy
   store, and the audit log. Even if we trust `wasmtime` (we do; it's
   high-quality Rust), defense-in-depth says don't share an address
   space with the thing executing untrusted code.

3. **No per-tool resource limits at the syscall layer.** Memory caps
   and CPU/fuel are theoretically available via the Python binding,
   but we can't impose a wall-clock timeout that survives a hostile
   WASM module pinning a host thread.

The sidecar pattern collapses all three into one structural change:
move the WASM execution into a separate Rust process. Communication
is a small JSON-RPC protocol over a unix socket pair (or stdio for
the simple case). Tools live in the sidecar's address space; the
agent process never touches WASM bytes directly.

## Non-goals

- **Replacing the in-process backend.** `WasmSandboxBackend` stays the
  default for development (no Rust toolchain required). The sidecar
  is opt-in via `SidecarSandboxBackend` and is recommended for
  production WASM tool deployments.
- **Reusing IronClaw's monorepo.** We deliberately do **not** depend
  on `ironclaw-staging` because that crate pulls in PostgreSQL,
  reqwest, the IronClaw orchestrator, and ~200 other deps. The
  sidecar is a standalone Rust binary with the smallest possible
  dependency closure: `wasmtime`, `wasmtime-wasi`, `serde`,
  `serde_json`, `tokio`.
- **Shipping prebuilt binaries.** v1 expects the operator to
  `cargo build --release` themselves. Cross-compiled prebuilds for
  Linux x86_64 / arm64 / macOS will follow once the protocol is
  stable.

## Trust boundary

```
                        TitanX Python process
        ┌─────────────────────────────────────────────────┐
        │  AgentRuntime → SandboxRouter → SidecarBackend  │
        │                                       │         │
        │                                       │ stdio   │
        │                                       │ (JSON)  │
        └───────────────────────────────────────┼─────────┘
                                                │
                                                ▼
                       titanx-sidecar (Rust, OS process)
        ┌─────────────────────────────────────────────────┐
        │  • wasmtime engine                              │
        │  • per-call memory + fuel limits                │
        │  • capability-keyed host functions only         │
        │  • no network, no /etc, no /proc                │
        │  • runs as same UID as agent (drop privs        │
        │    inside the supervising container)            │
        └─────────────────────────────────────────────────┘
```

Failure modes:

- **Sidecar OOM / panic.** Detected by `SidecarBackend` via the
  process exit code. The backend reports `exit_code=137` /
  `exit_code=139` to the runtime, which surfaces it as a tool error
  the LLM sees verbatim. Subsequent calls re-spawn the sidecar (or
  fail through the circuit breaker, depending on the wrapper).
- **Sidecar hang.** Each call has a wall-clock timeout enforced
  Python-side. A timeout sends `SIGKILL` to the sidecar; the next
  call gets a fresh process.
- **Sidecar exfil via stderr.** The sidecar writes structured JSON
  on stdout for protocol replies and unstructured text on stderr for
  diagnostics. The Python adapter forwards stderr to the audit log
  but never feeds it back to the LLM.

## IPC protocol

### Framing

Newline-delimited JSON (NDJSON) over the sidecar's stdin/stdout:
each request is one line, each response is one line. We use NDJSON
rather than length-prefixed framing because:

- The sidecar is run as a child process; reading line-buffered
  stdin/stdout requires no shared library on either side.
- The protocol is observable in `strace -f` / `dtruss` without a
  decoder. Operators debugging a hang see exactly what was sent.
- Both Python (`asyncio.subprocess`) and Rust (`tokio::io::Lines`)
  parse NDJSON in <10 lines.

For higher throughput we may move to a Unix domain socket later
(eliminates the parent's stdin contention) without changing the
on-the-wire format. The transport is documented as "newline-delimited
JSON over a bidirectional stream"; the choice of stream is an
implementation detail.

### Request envelope

```json
{
  "id": "uuid-v4-string",
  "method": "execute" | "ping" | "shutdown",
  "params": { ... }
}
```

`id` is opaque; the sidecar echoes it on the matching response. This
lets the Python side pipeline multiple requests if it wants, though
v1 is strictly synchronous (one request, await reply).

### `execute` params

```json
{
  "module_bytes_b64": "...",           // or "module_path": "/abs/path"
  "argv": ["tool-name", "arg1", "arg2"],
  "env": { "KEY": "VALUE" },
  "preopens": [
    { "host": "/host/abs/path", "guest": "/", "mode": "ro" }
  ],
  "stdin": "string passed on stdin",
  "limits": {
    "memory_bytes": 67108864,          // 64 MiB cap; rejected if
                                        // module imports more
    "fuel": 1000000000,                // wasmtime fuel — coarse
                                        // proxy for CPU time
    "wall_clock_ms": 5000              // hard kill timer
  },
  "capabilities": {
    "wasi_preview1": true,             // baseline
    "http_get": [],                    // future: per-host allowlist
    "filesystem_read": [],             // future: paths
    "filesystem_write": []             // future: paths
  }
}
```

`module_bytes_b64` and `module_path` are mutually exclusive. The
former is for ephemeral tools whose bytes the agent already has in
memory; the latter avoids a base64 round-trip when the tool is on
disk and the sidecar can read it. The path must be absolute and the
sidecar verifies it does not escape into `/etc`, `/proc`, or `/sys`
before opening (the existing PathGuard logic, in Rust).

### `execute` reply

```json
{
  "id": "uuid-v4-string",
  "result": {
    "exit_code": 0,
    "stdout": "...",
    "stderr": "...",
    "duration_ms": 42,
    "memory_bytes_peak": 1234567,
    "fuel_consumed": 12345
  }
}
```

`stdout` is the WASM tool's stdout (UTF-8, decoded with replacement).
`stderr` is the *sidecar's* diagnostic stream — which today is just
"the WASM module wrote N bytes to stderr"; protocol errors come back
as `error` instead.

### Error envelope

```json
{
  "id": "uuid-v4-string",
  "error": {
    "code": "module-load" | "capability-denied" | "limit-exceeded" |
            "wasm-trap" | "internal",
    "message": "human-readable detail",
    "details": { ... }                 // category-specific, optional
  }
}
```

Error codes are **stable**: a Python adapter that branches on
`code == "limit-exceeded"` to flip to a fallback path must keep
working across sidecar versions.

### `ping`

Liveness check: empty params, response is `{"id": ..., "result":
{"version": "0.1.0"}}`. The Python adapter calls this once on
spawn and uses the version string to refuse outright if the binary
is older than the adapter expects.

### `shutdown`

Graceful exit. The sidecar finishes any in-flight `execute` (if it
was unwise enough to handle one in parallel — v1 won't), closes
stdout, exits. The Python adapter follows up with `SIGKILL` after a
1s grace.

## Capability model — staged plan

v1 ships with **WASI preview1 + path preopens + no network**. That's
the baseline IronClaw exceeds, but it's already strictly better than
the in-process backend because:

- A miscompiled wasmtime cannot reach the agent's heap.
- The sidecar binary is built without `wasmtime-wasi-http`, so even
  a tool that *tries* to open a socket via the WASI 0.3 preview
  cannot import the symbol — the link fails at module instantiation.

v0.2 adds **WIT component model + capability handles**:

- Tools are component-model `.wasm` files, not preview1 modules.
- The sidecar imports a small WIT contract (`titanx:tool@0.2.0`)
  that declares `http-get(url: string) -> result<bytes, error>`,
  `read-file(path: string) -> result<bytes, error>`, etc.
- The agent passes a per-call `capabilities` object listing exactly
  which imports may resolve. Imports outside the list are bound to
  a stub that always returns `error("capability-denied")`.
- `http-get` is capability-gated and audited inside the sidecar. The first
  v0.2 implementation ships a small HTTP/1.1 transport for `http://` URLs.
  `https://` returns a TLS-unavailable transport error until an operator-selected
  TLS client is wired in.

The IPC envelope already reserves the `capabilities` field for v1 →
v2 forward compatibility.

## Build and ship

### Build

```bash
cd TitanX/sidecar
cargo build --release
# binary at target/release/titanx-sidecar
```

`cargo build` is documented in `sidecar/README.md` along with the
rust-toolchain pin (`rust-version = "1.92"`, matching IronClaw's
floor so a contributor with that toolchain installed for IronClaw
can build TitanX's sidecar with no extra setup).

### Locate

`SidecarSandboxBackend` finds the binary by, in order:

1. `binary_path=` kwarg.
2. `$TITANX_SIDECAR_PATH`.
3. `titanx-sidecar` on `$PATH`.
4. The build directory `<repo>/sidecar/target/release/titanx-sidecar`.

If none exists, `is_available()` returns `False` and the router
silently falls back to the in-process backend.

### Versioning

The sidecar's `Cargo.toml` `version` and the Python package's
`SIDECAR_PROTOCOL_VERSION` constant must agree on **major.minor**;
patch is free to drift. The adapter logs a warning and refuses to
spawn on mismatch.

## Open questions

- **Should the sidecar be one process per session or one per
  process?** v1 uses one per `SidecarBackend` instance — i.e. one
  per agent runtime. This is fine for single-tenant; multi-tenant
  needs per-session isolation (tools from tenant A and tenant B
  must not share a sidecar process). v2 will add a session manager.

- **Component-model recompilation cost.** WIT-componentified tools
  take longer to instantiate than preview1. Worth a benchmark before
  we declare v2 the default.

- **Should we publish prebuilds via PyPI as a binary wheel?** The
  Python world's expectation is "pip install titanx and it just
  works". A binary wheel that bundles a Rust sidecar per-platform
  is operationally heavy but solves the discoverability problem.

## Status

- [x] RFC drafted (this document).
- [x] Rust crate skeleton at `sidecar/`.
- [x] IPC envelope serde types in Rust.
- [x] Python `SidecarSandboxBackend` adapter + tests.
- [x] Wall-clock timeout + SIGKILL recovery.
- [x] Component-model + WIT capability handles.
- [x] Per-host `http-get` cleartext HTTP transport inside sidecar.
- [ ] TLS-enabled `https://` transport with EgressGuard inside sidecar.
- [ ] CI build matrix.
- [ ] PyPI binary wheel publishing.
