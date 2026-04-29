# titanx-sidecar — process-isolated WASM tool runtime

This crate is the Rust counterpart to `titanx.sandbox.backends.sidecar`.
It runs WASM tool modules in a separate OS process so a memory-corrupted
or fuel-exhausted module cannot reach the agent's heap.

See `../docs/sidecar-rfc.md` for the protocol specification, threat
model, and roadmap.

## Build

```bash
cd sidecar
cargo build --release
# binary at target/release/titanx-sidecar
```

A tiny `wasm32-wasip1` test module used by `../tests/test_sidecar_smoke.py` lives
under `wasm-smoke-hello/`. Rebuild the checked-in
`../tests/fixtures/wasm_hello.wasm` from that crate (see
`wasm-smoke-hello/README.md`).

The crate pins `wasmtime = 27` and `wasmtime-wasi = 27`; if your toolchain
disagrees update both pins together. The protocol envelope (`Request`,
`Response`, `ExecuteParams`, `ExecuteResult`) is decoupled from
wasmtime — only `handle_execute` calls into the engine.

Rust toolchain: `rustc 1.78` or newer (matches IronClaw's floor; a
contributor with that toolchain already installed for IronClaw can
build TitanX's sidecar with no extra setup).

## Run (manually, for debugging)

```bash
./target/release/titanx-sidecar
```

The binary reads newline-delimited JSON from stdin and writes the same
to stdout. Try a `ping`:

```bash
echo '{"id":"1","method":"ping","params":{}}' | ./target/release/titanx-sidecar
```

Expected response:

```json
{"id":"1","result":{"version":"0.1.0"}}
```

## Status

The preview1 path from **v0.1.0** remains available. What is in:

- IPC envelope (Request/Response with stable error codes).
- `ping`, `shutdown`, `execute` methods.
- WASI preview1 with captured stdout/stderr (no leak into the IPC
  channel).
- Per-call memory cap (via `StoreLimits`), fuel cap (via wasmtime
  `consume_fuel` + `set_fuel`), wall-clock cap (via tokio timeout).
- Hard ceilings on every limit so the caller can't ask for more than
  the operator considers reasonable.
- Privileged-prefix path validation (mirrors Python `PolicyValidator`).
- Network deny by construction: the linker only registers WASI
  preview1, so a module that imports `wasi-sockets` or `wasi-http`
  fails at instantiation.

The **v0.2.0 component-model path** is selected per command with
`component_model=True` in `SidecarCommandRegistration`. Component tools target
`sidecar/wit/titanx.wit` package `titanx:tool@0.2.0` and export:

```wit
world tool {
    import env
    import http
    import fs
    export run: func() -> result<string, string>
}
```

Per-call capability JSON is forwarded in the execute envelope:

```json
{
  "http_get": [
    {"scheme": "https", "host": "example.com", "path_prefix": "/api"}
  ],
  "read_file": [
    {"guest_path": "/data", "host_path": "/tmp/titanx-data"}
  ]
}
```

The sidecar enforces these grants inside the imported host functions and returns
`audit_events` with each execute result. The Python adapter appends those events
to `stderr` as `TITANX_SIDECAR_AUDIT ...` JSONL records.

The v0.2.0 HTTP transport intentionally starts small: allowed `http://` URLs are
fetched with a direct HTTP/1.1 GET, redirects are not followed, and every call is
still gated by the sidecar capability policy before the socket is opened.

What is **not** in v0.2.0:

- HTTPS/TLS transport. `https://` grants are parsed and authorized, but the
  transport returns an explicit TLS-unavailable error until the sidecar is built
  with a TLS HTTP client such as rustls.
- `fs.write-file`. Write grants need a separate policy review because they
  mutate host state.
- A Unix-domain-socket transport. Stdio works; UDS is a v0.2 task.
- Prebuilt binaries on PyPI / GitHub releases.

## Wiring up to TitanX

Once you have `target/release/titanx-sidecar`, wire it into a
runtime:

```python
from titanx.sandbox.backends.sidecar import SidecarSandboxBackend

backend = SidecarSandboxBackend(
    binary_path="./sidecar/target/release/titanx-sidecar",
    default_limits={"memory_bytes": 64 * 1024 * 1024,
                    "fuel": 1_000_000_000,
                    "wall_clock_ms": 5_000},
)
# pass via SandboxRouter as the wasm-tier backend
```

If `binary_path` is omitted the adapter looks at `$TITANX_SIDECAR_PATH`
then `$PATH`; if nothing resolves, `is_available()` returns False and
the router falls back to the in-process `WasmSandboxBackend`.
