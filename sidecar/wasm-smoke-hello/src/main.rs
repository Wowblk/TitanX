//! Minimal `wasm32-wasip1` binary used by `tests/test_sidecar_smoke.py`.
//! Rebuild: `cd sidecar/wasm-smoke-hello && rustup target add wasm32-wasip1 && cargo build --release --target wasm32-wasip1` then copy `target/wasm32-wasip1/release/wasm-hello.wasm` to `tests/fixtures/wasm_hello.wasm`.
fn main() {
    // Marker string asserted by the Python smoke test (include newline like println).
    print!("TITANX_SMOKE_OK\n");
}
