"""Smoke test against the real ``titanx-sidecar`` binary.

Skipped unless the binary is found via ``$TITANX_SIDECAR_PATH`` or in
the source tree at ``sidecar/target/release/titanx-sidecar``. The
``execute`` test additionally requires ``tests/fixtures/wasm_hello.wasm``,
a checked-in ``wasm32-wasip1`` module (rebuild from
``sidecar/wasm-smoke-hello``, see that crate's `README`). Adapter
behaviour is still covered in depth by ``test_sidecar_adapter.py`` with
a fake process.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from titanx.sandbox.backends.sidecar import SidecarCommandRegistration, SidecarSandboxBackend
from titanx.sandbox.types import SandboxExecutionRequest


def _binary_candidate() -> str | None:
    explicit = os.environ.get("TITANX_SIDECAR_PATH")
    if explicit and os.path.exists(explicit):
        return explicit
    here = Path(__file__).resolve()
    candidate = here.parents[1] / "sidecar" / "target" / "release" / "titanx-sidecar"
    if candidate.exists():
        return str(candidate)
    return None


def _wasm_fixture() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "wasm_hello.wasm"


def _component_fixture() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "component_read_file.wasm"


pytestmark = pytest.mark.skipif(
    _binary_candidate() is None,
    reason="titanx-sidecar binary not built; run cargo build --release in sidecar/",
)


@pytest.mark.asyncio
async def test_real_sidecar_ping() -> None:
    backend = SidecarSandboxBackend(binary_path=_binary_candidate())
    try:
        available = await backend.is_available()
        if available is not True:
            pytest.skip(
                "titanx-sidecar binary is stale or unavailable; rebuild "
                "sidecar/ for the matching protocol version"
            )
    finally:
        await backend.aclose()


execute_smoke = pytest.mark.skipif(
    not _wasm_fixture().is_file(),
    reason="tests/fixtures/wasm_hello.wasm missing; build sidecar/wasm-smoke-hello and copy output (see that README)",
)


@execute_smoke
@pytest.mark.asyncio
async def test_real_sidecar_execute_hello() -> None:
    wasm = _wasm_fixture()
    assert wasm.is_file()
    abs_wasm = str(wasm.resolve())

    backend = SidecarSandboxBackend(binary_path=_binary_candidate())
    if not await backend.is_available():
        await backend.aclose()
        pytest.skip(
            "titanx-sidecar binary is stale or unavailable; rebuild sidecar/"
        )
    backend.register_command(
        "smoke-hello",
        SidecarCommandRegistration(module_path=abs_wasm, args=[]),
    )
    try:
        r = await backend.execute(
            SandboxExecutionRequest(command="smoke-hello", args=[], env={})
        )
    finally:
        await backend.aclose()

    assert r.exit_code == 0, f"expected exit 0, got {r.exit_code}: stderr={r.stderr!r}"
    assert "TITANX_SMOKE_OK" in r.stdout, f"stdout={r.stdout!r}"


component_smoke = pytest.mark.skipif(
    not _component_fixture().is_file(),
    reason=(
        "tests/fixtures/component_read_file.wasm missing; build a "
        "titanx:tool@0.2.0 component fixture from sidecar/wit/titanx.wit"
    ),
)


@component_smoke
@pytest.mark.asyncio
async def test_real_sidecar_component_read_file(tmp_path: Path) -> None:
    component = _component_fixture()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "config.txt").write_text("component-ok")

    backend = SidecarSandboxBackend(binary_path=_binary_candidate())
    if not await backend.is_available():
        await backend.aclose()
        pytest.skip(
            "titanx-sidecar binary is stale or unavailable; rebuild sidecar/"
        )
    backend.register_command(
        "component-read-file",
        SidecarCommandRegistration(
            module_path=str(component.resolve()),
            component_model=True,
        ),
    )
    try:
        r = await backend.execute(
            SandboxExecutionRequest(
                command="component-read-file",
                capabilities={
                    "read_file": [{
                        "guest_path": "/data",
                        "host_path": str(data_dir.resolve()),
                    }],
                },
            )
        )
    finally:
        await backend.aclose()

    assert r.exit_code == 0, f"expected exit 0, got {r.exit_code}: stderr={r.stderr!r}"
    assert "component-ok" in r.stdout
    assert "TITANX_SIDECAR_AUDIT" in r.stderr
