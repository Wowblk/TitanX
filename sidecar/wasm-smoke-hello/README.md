# `wasm-hello` — fixed-output WASI module for `tests/test_sidecar_smoke.py`

Builds a `wasm32-wasip1` binary that prints `TITANX_SMOKE_OK` to stdout. The produced `.wasm` is copied into the Python tree so the smoke test does not need Cargo at runtime.

## Rebuild the committed fixture

From the `wasm-smoke-hello` directory (not the `sidecar` parent — this crate is standalone):

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/wasm-hello.wasm ../../tests/fixtures/wasm_hello.wasm
```

If your environment puts `CARGO_TARGET_DIR` outside this tree, copy from that `wasm32-wasip1/release/wasm-hello.wasm` instead.

## Crate layout

- `Cargo.toml` — `[[bin]] name = "wasm-hello"` (artifact `wasm-hello.wasm`).
