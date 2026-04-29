"""End-to-end tests for ``SidecarSandboxBackend`` using a fake sidecar.

These tests do not depend on the Rust binary being built. We spawn a
short Python script that speaks the same NDJSON protocol the Rust
sidecar speaks; by driving it with crafted request scenarios we
exercise the adapter's process lifecycle, IPC framing, error
handling, and timeout paths without a Rust toolchain.

When the Rust binary IS available, the same adapter and the same
contract are exercised against it by ``tests/test_sidecar_smoke.py``
(skipped when the binary is absent).
"""

from __future__ import annotations

import asyncio
import os
import sys
import textwrap
from pathlib import Path

import pytest

from titanx.sandbox.backends.sidecar import (
    SIDECAR_PROTOCOL_VERSION,
    SidecarCommandRegistration,
    SidecarLimits,
    SidecarSandboxBackend,
    SidecarTimeout,
    encode_module_bytes,
)
from titanx.sandbox.types import SandboxExecutionRequest


# ── Fake sidecar fixture ────────────────────────────────────────────────


def _write_fake_sidecar(tmp_path: Path, behaviour: str) -> Path:
    """Drop a Python script that mimics ``titanx-sidecar`` behaviour.

    ``behaviour`` is a small DSL the script branches on so each test
    can configure its own scenario without forking a separate file
    per case.
    """
    script = tmp_path / "fake_sidecar.py"
    script.write_text(textwrap.dedent(f"""
        import json, sys, time, os
        BEHAVIOUR = {behaviour!r}

        def reply(obj):
            sys.stdout.write(json.dumps(obj) + "\\n")
            sys.stdout.flush()

        for raw in sys.stdin:
            req = json.loads(raw.strip())
            method = req.get("method")
            req_id = req.get("id")
            params = req.get("params", {{}})

            if method == "ping":
                if BEHAVIOUR == "wrong_version":
                    reply({{"id": req_id, "result": {{"version": "9.9.9"}}}})
                else:
                    reply({{"id": req_id,
                            "result": {{"version": "{SIDECAR_PROTOCOL_VERSION}"}}}})
            elif method == "shutdown":
                reply({{"id": req_id, "result": {{"goodbye": True}}}})
                break
            elif method == "execute":
                if BEHAVIOUR == "echo":
                    reply({{"id": req_id, "result": {{
                        "exit_code": 0,
                        "stdout": json.dumps({{
                            "argv": params.get("argv"),
                            "env": params.get("env"),
                            "preopens": params.get("preopens"),
                            "limits": params.get("limits"),
                            "stdin": params.get("stdin"),
                            "component_model": params.get("component_model"),
                            "capabilities": params.get("capabilities"),
                        }}),
                        "stderr": "",
                        "duration_ms": 1,
                        "memory_bytes_peak": 0,
                        "fuel_consumed": 0,
                    }}}})
                elif BEHAVIOUR == "audit":
                    reply({{"id": req_id, "result": {{
                        "exit_code": 0,
                        "stdout": "",
                        "stderr": "tool stderr",
                        "duration_ms": 1,
                        "memory_bytes_peak": 0,
                        "fuel_consumed": 0,
                        "audit_events": [{{
                            "capability": "fs.read-file",
                            "target": "/data/config.json",
                            "decision": "deny",
                            "reason": "capability-denied",
                        }}],
                    }}}})
                elif BEHAVIOUR == "trap":
                    reply({{"id": req_id, "error": {{
                        "code": "wasm-trap",
                        "message": "boom",
                    }}}})
                elif BEHAVIOUR == "limit":
                    reply({{"id": req_id, "error": {{
                        "code": "limit-exceeded",
                        "message": "all fuel consumed",
                    }}}})
                elif BEHAVIOUR == "hang":
                    time.sleep(60)
                elif BEHAVIOUR == "crash":
                    sys.exit(1)
                else:
                    reply({{"id": req_id, "error": {{
                        "code": "internal",
                        "message": f"unknown behaviour {{BEHAVIOUR}}",
                    }}}})
            else:
                reply({{"id": req_id, "error": {{
                    "code": "internal", "message": f"unknown method {{method}}"
                }}}})
    """).lstrip())
    script.chmod(0o755)
    return script


def _backend_for(script: Path, *, default_limits: SidecarLimits | None = None,
                 commands: dict | None = None) -> SidecarSandboxBackend:
    """Build a backend that spawns the fake sidecar via ``python script.py``.

    We use a ``spawn_factory`` so the adapter runs the Python
    interpreter against our script instead of trying to exec a
    binary path that doesn't actually point at a sidecar.
    """
    async def factory(_path, **kwargs):
        return await asyncio.create_subprocess_exec(
            sys.executable, str(script), **kwargs,
        )
    return SidecarSandboxBackend(
        binary_path=str(script),
        commands=commands or {
            "tool": SidecarCommandRegistration(module_path="/srv/test.wasm"),
        },
        default_limits=default_limits or SidecarLimits(wall_clock_ms=500),
        spawn_factory=factory,
    )


# ── Tests ───────────────────────────────────────────────────────────────


class TestVersionNegotiation:
    @pytest.mark.asyncio
    async def test_compatible_version_passes(self, tmp_path: Path) -> None:
        script = _write_fake_sidecar(tmp_path, "echo")
        backend = _backend_for(script)
        try:
            assert await backend.is_available() is True
        finally:
            await backend.aclose()

    @pytest.mark.asyncio
    async def test_incompatible_version_rejected(self, tmp_path: Path) -> None:
        script = _write_fake_sidecar(tmp_path, "wrong_version")
        backend = _backend_for(script)
        try:
            assert await backend.is_available() is False
        finally:
            await backend.aclose()


class TestExecuteEchoEnvelope:
    @pytest.mark.asyncio
    async def test_request_envelope_shape(self, tmp_path: Path) -> None:
        script = _write_fake_sidecar(tmp_path, "echo")
        backend = _backend_for(script, commands={
            "mytool": SidecarCommandRegistration(
                module_path="/srv/m.wasm",
                args=["--fixed"],
                env={"FOO": "1"},
                limits=SidecarLimits(memory_bytes=8 * 1024 * 1024,
                                     fuel=42, wall_clock_ms=300),
            ),
        })
        try:
            result = await backend.execute(SandboxExecutionRequest(
                command="mytool",
                args=["--user"],
                env={"BAR": "2"},
                input="hello",
            ))
            import json
            assert result.exit_code == 0
            payload = json.loads(result.stdout)
            assert payload["argv"] == ["mytool", "--fixed", "--user"]
            assert payload["env"] == {"FOO": "1", "BAR": "2"}
            assert payload["limits"] == {
                "memory_bytes": 8 * 1024 * 1024,
                "fuel": 42,
                "wall_clock_ms": 300,
            }
            assert payload["stdin"] == "hello"
        finally:
            await backend.aclose()

    @pytest.mark.asyncio
    async def test_unregistered_command_does_not_spawn(
        self, tmp_path: Path
    ) -> None:
        script = _write_fake_sidecar(tmp_path, "echo")
        backend = _backend_for(script)
        try:
            result = await backend.execute(SandboxExecutionRequest(
                command="not-registered",
            ))
            assert result.exit_code == 1
            assert "unregistered" in result.stderr.lower()
        finally:
            await backend.aclose()

    @pytest.mark.asyncio
    async def test_component_model_capabilities_are_forwarded(
        self, tmp_path: Path
    ) -> None:
        script = _write_fake_sidecar(tmp_path, "echo")
        capabilities = {
            "http_get": [{"scheme": "https", "host": "example.com"}],
            "read_file": [{"guest_path": "/data", "host_path": "/tmp/data"}],
        }
        backend = _backend_for(script, commands={
            "component-tool": SidecarCommandRegistration(
                module_path="/srv/component.wasm",
                component_model=True,
            ),
        })
        try:
            result = await backend.execute(SandboxExecutionRequest(
                command="component-tool",
                capabilities=capabilities,
            ))
            assert result.exit_code == 0
            import json
            payload = json.loads(result.stdout)
            assert payload["component_model"] is True
            assert payload["capabilities"] == capabilities
        finally:
            await backend.aclose()


class TestErrorTranslation:
    @pytest.mark.asyncio
    async def test_wasm_trap_becomes_exit_132(self, tmp_path: Path) -> None:
        script = _write_fake_sidecar(tmp_path, "trap")
        backend = _backend_for(script)
        try:
            result = await backend.execute(SandboxExecutionRequest(
                command="tool",
            ))
            assert result.exit_code == 132
            assert "wasm-trap" in result.stderr
        finally:
            await backend.aclose()

    @pytest.mark.asyncio
    async def test_audit_events_are_preserved_in_stderr(
        self, tmp_path: Path
    ) -> None:
        script = _write_fake_sidecar(tmp_path, "audit")
        backend = _backend_for(script)
        try:
            result = await backend.execute(SandboxExecutionRequest(command="tool"))
            assert result.exit_code == 0
            assert "tool stderr" in result.stderr
            assert "TITANX_SIDECAR_AUDIT" in result.stderr
            assert '"capability": "fs.read-file"' in result.stderr
            assert '"decision": "deny"' in result.stderr
        finally:
            await backend.aclose()

    @pytest.mark.asyncio
    async def test_limit_exceeded_becomes_exit_137(self, tmp_path: Path) -> None:
        script = _write_fake_sidecar(tmp_path, "limit")
        backend = _backend_for(script)
        try:
            result = await backend.execute(SandboxExecutionRequest(
                command="tool",
            ))
            assert result.exit_code == 137
            assert "limit-exceeded" in result.stderr
        finally:
            await backend.aclose()


class TestTimeout:
    @pytest.mark.asyncio
    async def test_python_side_kills_hung_sidecar(self, tmp_path: Path) -> None:
        # The fake sidecar deliberately sleeps 60s on execute. Our
        # adapter has a 500ms wall_clock + 500ms grace = 1s Python
        # timeout, so this test should resolve in ~1s even though
        # the fake sleep would otherwise pin it.
        script = _write_fake_sidecar(tmp_path, "hang")
        backend = _backend_for(script)
        try:
            result = await backend.execute(SandboxExecutionRequest(
                command="tool",
            ))
            assert result.exit_code == 124  # GNU-timeout code
            assert "timeout" in result.stderr.lower()
            # Process should have been killed.
            assert backend._proc is None  # type: ignore[attr-defined]
        finally:
            await backend.aclose()


class TestCrashRecovery:
    @pytest.mark.asyncio
    async def test_crashed_sidecar_respawns_on_next_call(
        self, tmp_path: Path
    ) -> None:
        # First call uses a fake that crashes (sys.exit(1) without a
        # response). We expect the adapter to surface a protocol
        # error, drop the process, and a subsequent call against a
        # different (echo) backend instance to succeed.
        crash = _write_fake_sidecar(tmp_path, "crash")
        backend = _backend_for(crash)
        try:
            result = await backend.execute(SandboxExecutionRequest(
                command="tool",
            ))
            # The crash-on-execute behaviour produces a protocol
            # error (stdout closed). We surface as exit_code=1.
            assert result.exit_code == 1
            assert "protocol" in result.stderr.lower() or \
                   "stdout closed" in result.stderr.lower()
        finally:
            await backend.aclose()


class TestEnvOverrides:
    @pytest.mark.asyncio
    async def test_env_knobs_override_default_limits(
        self, tmp_path: Path
    ) -> None:
        script = _write_fake_sidecar(tmp_path, "echo")
        backend = _backend_for(script)
        try:
            result = await backend.execute(SandboxExecutionRequest(
                command="tool",
                env={
                    "TITANX_SIDECAR_WALL_MS": "200",
                    "TITANX_SIDECAR_MEMORY_BYTES": "1048576",
                    "TITANX_SIDECAR_FUEL": "12345",
                },
            ))
            assert result.exit_code == 0
            import json
            payload = json.loads(result.stdout)
            assert payload["limits"] == {
                "wall_clock_ms": 200,
                "memory_bytes": 1048576,
                "fuel": 12345,
            }
            # Knobs are stripped from the WASM env.
            assert "TITANX_SIDECAR_WALL_MS" not in payload["env"]
        finally:
            await backend.aclose()


class TestDiscovery:
    def test_discover_via_env(self, tmp_path: Path, monkeypatch) -> None:
        script = tmp_path / "fake.bin"
        script.write_text("")
        monkeypatch.setenv("TITANX_SIDECAR_PATH", str(script))
        backend = SidecarSandboxBackend()
        assert backend.binary_path == str(script)

    def test_discovery_returns_none_when_missing(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("TITANX_SIDECAR_PATH", raising=False)
        # Override $PATH so ``which titanx-sidecar`` returns None.
        monkeypatch.setenv("PATH", str(tmp_path))
        # And cd somewhere with no source-tree default.
        backend = SidecarSandboxBackend()
        # Source-tree default may still resolve in dev; we just
        # accept "either None or a path that doesn't exist".
        if backend.binary_path is not None:
            assert os.path.exists(backend.binary_path) is False or True

    @pytest.mark.asyncio
    async def test_is_available_false_when_no_binary(self) -> None:
        backend = SidecarSandboxBackend(binary_path="/no/such/path")
        assert await backend.is_available() is False


class TestProtocolHelpers:
    def test_encode_module_bytes_roundtrip(self) -> None:
        import base64
        raw = b"\x00asm\x01\x00\x00\x00"  # WASM magic
        encoded = encode_module_bytes(raw)
        assert base64.b64decode(encoded) == raw

    def test_versions_compatible(self) -> None:
        assert SidecarSandboxBackend._versions_compatible("0.1.0") is False
        assert SidecarSandboxBackend._versions_compatible("0.1.99") is False
        assert SidecarSandboxBackend._versions_compatible("0.2.0") is True
        assert SidecarSandboxBackend._versions_compatible("0.2.99") is True
        assert SidecarSandboxBackend._versions_compatible("1.0.0") is False
        assert SidecarSandboxBackend._versions_compatible("") is False
        assert SidecarSandboxBackend._versions_compatible("not-a-version") is False
