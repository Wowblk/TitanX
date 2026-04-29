"""SidecarSandboxBackend — out-of-process WASM tool runtime.

Drop-in replacement for :class:`WasmSandboxBackend` that delegates the
actual WASM execution to a separate Rust process (``titanx-sidecar``).
See ``docs/sidecar-rfc.md`` for the protocol spec, threat model, and
roadmap.

Why this is its own module
==========================

The existing :class:`WasmSandboxBackend` runs ``wasmtime`` directly in
the agent's Python process. That works fine for development, but in
production it shares an address space with the policy store, the
audit log, and the agent loop. A miscompiled hostile module that
trips a wasmtime memory bug would compromise all of them at once.

The sidecar moves the WASM execution into a separate OS process whose
**only** capabilities are the ones the linker registers — and the
sidecar's linker registers WASI preview1 and nothing else, so a
module trying to import ``wasi-sockets`` or ``wasi-http`` fails at
instantiation. That is the structural network-deny the in-process
backend cannot offer because the Python bindings link those
subsystems whether you want them or not.

Adapter responsibilities
========================

* **Process lifecycle.** Spawn the sidecar lazily on first use; shut
  it down on ``destroy_session`` / ``aclose``. A panicked or killed
  sidecar is detected via ``process.returncode != None`` and respawned
  on the next call. Hangs are handled by the per-call wall-clock kwarg
  which is enforced both Python-side (via ``asyncio.wait_for``) and
  Rust-side (via the sidecar's own ``wall_clock_ms`` limit).

* **NDJSON framing.** One JSON object per line, in both directions.
  We use a ``Lock`` to serialize requests so the protocol stays
  request/response without an explicit pipeline layer.

* **Translation.** The router speaks ``SandboxExecutionRequest``;
  the sidecar speaks a slightly richer envelope (memory/fuel limits,
  preopens with read/write modes). The adapter is the only place
  this translation happens, so the rest of the SDK is unaware of
  the sidecar's existence.

The adapter does NOT try to be an in-process fallback. If the binary
is missing, :meth:`is_available` returns False and the
:class:`SandboxRouter` will silently fall through to a different
backend tier. Operators who want an in-process backup should
construct both a :class:`WasmSandboxBackend` and this one and let the
router pick.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from ..types import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionRequest,
    SandboxExecutionResult,
)


# ── Public types ──────────────────────────────────────────────────────────

# major.minor must match the sidecar binary's ``PROTOCOL_VERSION``.
SIDECAR_PROTOCOL_VERSION = "0.2.0"


@dataclass
class SidecarLimits:
    """Per-call resource caps forwarded to the sidecar.

    ``memory_bytes`` is a hard cap on the WASM module's linear memory.
    ``fuel`` is a wasmtime fuel-counter ceiling — coarse but cheap CPU
    budget. ``wall_clock_ms`` is enforced both by the sidecar and by
    the Python adapter (the latter as a safety net in case the
    sidecar itself wedges).

    Defaults are conservative — 64 MiB memory, ~1 second of WASM
    execution before fuel runs out, 5 second wall clock. Tools that
    need more bump them per call.
    """

    memory_bytes: int = 64 * 1024 * 1024
    fuel: int = 1_000_000_000
    wall_clock_ms: int = 5_000


@dataclass
class SidecarPreopen:
    """One mount point exposed to the WASM module."""

    host: str
    guest: str
    mode: str = "ro"  # "ro" or "rw"


@dataclass
class SidecarCommandRegistration:
    """Registration entry for a tool the sidecar can execute by name.

    Mirrors :class:`WasmCommandRegistration` so callers swapping
    backends only have to change the constructor.
    """

    module_path: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    preopens: list[SidecarPreopen] = field(default_factory=list)
    limits: SidecarLimits | None = None
    component_model: bool = False


# ── Errors ───────────────────────────────────────────────────────────────


class SidecarError(RuntimeError):
    """Top-level error type for sidecar failures.

    Subclasses preserve the protocol error code so callers (and
    tests) can branch on the kind of failure without parsing
    free-form messages. The same codes appear in the sidecar's
    Rust source — they are part of the public protocol.
    """

    code: str = "sidecar"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class SidecarUnavailable(SidecarError):
    code = "unavailable"


class SidecarSpawnError(SidecarError):
    code = "spawn"


class SidecarTimeout(SidecarError):
    code = "timeout"


class SidecarProtocolError(SidecarError):
    code = "protocol"


# ── Backend ──────────────────────────────────────────────────────────────


class SidecarSandboxBackend(SandboxBackend):
    """:class:`SandboxBackend` implementation that talks to titanx-sidecar.

    The backend is process-per-instance: every
    :class:`SidecarSandboxBackend` instance owns at most one Rust
    subprocess, which is reused across calls. Operators who want
    per-session isolation construct one backend per session.
    """

    kind = "wasm"

    def __init__(
        self,
        *,
        binary_path: str | None = None,
        commands: dict[str, SidecarCommandRegistration] | None = None,
        default_limits: SidecarLimits | None = None,
        env: dict[str, str] | None = None,
        spawn_timeout_seconds: float = 5.0,
        # Test hook: when set, ``_spawn`` calls this instead of
        # ``asyncio.create_subprocess_exec``. The factory must return
        # an object exposing ``.stdin`` / ``.stdout`` (asyncio
        # StreamReader/Writer) and ``.returncode`` / ``.wait()``.
        spawn_factory: Callable[..., "asyncio.subprocess.Process"] | None = None,
    ) -> None:
        self._binary_path = binary_path or self._discover_binary()
        self._commands: dict[str, SidecarCommandRegistration] = commands or {}
        self._default_limits = default_limits or SidecarLimits()
        self._env = env
        self._spawn_timeout = spawn_timeout_seconds
        self._spawn_factory = spawn_factory
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._negotiated_version: str | None = None

    @property
    def binary_path(self) -> str | None:
        return self._binary_path

    def register_command(
        self, name: str, reg: SidecarCommandRegistration
    ) -> None:
        self._commands[name] = reg

    # ── SandboxBackend surface ───────────────────────────────────────────

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind="wasm",
            supports_persistence=False,
            supports_snapshots=False,
            supports_browser=False,
            supports_network=False,
            supports_package_install=False,
            supported_capabilities=["command-exec", "process-isolation"],
        )

    async def is_available(self) -> bool:
        """Return True if the sidecar binary exists and ``ping`` succeeds.

        Failures are treated as "not available" rather than raised so
        the router can fall through to a different tier without
        crashing the agent. We still attempt a ping (rather than
        just stat'ing the binary) because a binary that exists but
        crashes on startup is *less* available than one that doesn't
        exist — better to discover that here than at first execute.
        """
        if not self._binary_path:
            return False
        if not os.path.exists(self._binary_path):
            return False
        try:
            await self._ensure_proc()
            resp = await self._call("ping", {}, timeout=self._spawn_timeout)
            version = (resp.get("result") or {}).get("version", "")
            self._negotiated_version = str(version)
            return self._versions_compatible(version)
        except Exception:  # noqa: BLE001
            return False

    async def execute(
        self,
        request: SandboxExecutionRequest,
        session=None,
    ) -> SandboxExecutionResult:
        start = time.perf_counter()
        try:
            params = self._build_execute_params(request)
        except KeyError as exc:
            return SandboxExecutionResult(
                backend="wasm",
                exit_code=1,
                stdout="",
                stderr=f"unregistered sidecar command: {exc}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        wall = (
            params["limits"].get("wall_clock_ms")
            or self._default_limits.wall_clock_ms
        )
        # Add grace so the sidecar's own timeout fires first and
        # produces a structured ``limit-exceeded`` error rather than
        # the Python side killing the process out from under it. Keep
        # a small floor for subprocess scheduling / NDJSON IPC jitter;
        # the Rust sidecar still enforces the actual WASM wall-clock
        # limit.
        py_timeout = max(2.0, (wall + 500) / 1000.0)

        try:
            await self._ensure_proc()
            resp = await self._call("execute", params, timeout=py_timeout)
        except SidecarTimeout as exc:
            await self._kill_proc()
            return SandboxExecutionResult(
                backend="wasm",
                exit_code=124,  # GNU-timeout convention
                stdout="",
                stderr=f"sidecar wall-clock timeout: {exc}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except SidecarError as exc:
            return SandboxExecutionResult(
                backend="wasm",
                exit_code=1,
                stdout="",
                stderr=f"sidecar error ({exc.code}): {exc}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if "error" in resp and resp["error"] is not None:
            err = resp["error"]
            return SandboxExecutionResult(
                backend="wasm",
                exit_code=_exit_code_for(err.get("code", "internal")),
                stdout="",
                stderr=f"{err.get('code')}: {err.get('message')}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        result = resp.get("result") or {}
        stderr = str(result.get("stderr", ""))
        audit_events = result.get("audit_events") or []
        if audit_events:
            audit_lines = [
                "TITANX_SIDECAR_AUDIT " + json.dumps(event, ensure_ascii=False)
                for event in audit_events
            ]
            stderr = "\n".join([stderr, *audit_lines]) if stderr else "\n".join(audit_lines)
        return SandboxExecutionResult(
            backend="wasm",
            exit_code=int(result.get("exit_code", 0)),
            stdout=str(result.get("stdout", "")),
            stderr=stderr,
            duration_ms=float(
                result.get("duration_ms", (time.perf_counter() - start) * 1000)
            ),
        )

    async def aclose(self) -> None:
        """Send ``shutdown`` then wait for the sidecar to exit.

        Idempotent — calling on an already-closed adapter is a no-op.
        ``destroy_session`` is the public entry point most callers
        want; ``aclose`` is here so a backend that's wired without a
        session manager can still be torn down cleanly.
        """
        proc = self._proc
        if proc is None or proc.returncode is not None:
            self._proc = None
            return
        try:
            await asyncio.wait_for(
                self._call_locked("shutdown", {}),
                timeout=1.0,
            )
        except Exception:  # noqa: BLE001
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await proc.wait()
            except Exception:  # noqa: BLE001
                pass
        self._proc = None

    # The default ``SandboxBackend`` raises NotImplementedError for
    # session methods. The sidecar's WASM workloads are stateless;
    # we expose minimal session stubs so the session manager can
    # treat us uniformly without special-casing.

    async def create_session(  # type: ignore[override]
        self,
        metadata: dict[str, str] | None = None,
        *,
        allowed_write_paths: list[str] | None = None,
        allowed_read_paths: list[str] | None = None,
        image_digest: str | None = None,
    ):
        from ..types import SandboxSession  # local to avoid cycle

        # The sidecar doesn't keep per-session state — every execute
        # is a fresh wasmtime Store. The session here exists purely
        # for the session manager's accounting.
        del allowed_write_paths, allowed_read_paths, image_digest
        return SandboxSession(
            id=str(uuid.uuid4()),
            backend="wasm",
            metadata=metadata or {},
        )

    async def destroy_session(self, session_id: str) -> None:
        # Stateless backend; nothing to tear down per-session.
        del session_id

    # ── Internal: process management ─────────────────────────────────────

    @staticmethod
    def _discover_binary() -> str | None:
        # Order: env, $PATH, source-tree convention.
        explicit = os.environ.get("TITANX_SIDECAR_PATH")
        if explicit and os.path.exists(explicit):
            return explicit
        on_path = shutil.which("titanx-sidecar")
        if on_path:
            return on_path
        # Source-tree default — handy during development.
        try:
            here = os.path.dirname(os.path.abspath(__file__))
            candidate = os.path.normpath(
                os.path.join(here, "..", "..", "..", "sidecar",
                             "target", "release", "titanx-sidecar")
            )
            if os.path.exists(candidate):
                return candidate
        except Exception:  # noqa: BLE001
            pass
        return None

    async def _ensure_proc(self) -> None:
        """Spawn the sidecar if it isn't already running.

        Caller must hold ``self._lock`` for any subsequent IO. We
        check ``returncode`` — if the sidecar died (panic, OOM,
        signal) we re-spawn rather than reuse a half-broken process.
        """
        async with self._lock:
            if self._proc is not None and self._proc.returncode is None:
                return
            await self._spawn_locked()

    async def _spawn_locked(self) -> None:
        if not self._binary_path:
            raise SidecarUnavailable("titanx-sidecar binary not found")
        env = {**os.environ}
        if self._env:
            env.update(self._env)
        try:
            if self._spawn_factory is not None:
                proc = await self._spawn_factory(
                    self._binary_path,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    self._binary_path,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
        except FileNotFoundError as exc:
            raise SidecarSpawnError(
                f"failed to spawn {self._binary_path}: {exc}"
            ) from exc
        self._proc = proc

    async def _kill_proc(self) -> None:
        proc = self._proc
        if proc is None:
            return
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
        self._proc = None

    # ── Internal: protocol IO ────────────────────────────────────────────

    async def _call(
        self, method: str, params: dict[str, Any], *, timeout: float
    ) -> dict[str, Any]:
        async with self._lock:
            return await self._call_locked(method, params, timeout=timeout)

    async def _call_locked(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise SidecarProtocolError("sidecar process not running")
        request_id = str(uuid.uuid4())
        envelope = {"id": request_id, "method": method, "params": params}
        line = json.dumps(envelope, ensure_ascii=False) + "\n"
        try:
            proc.stdin.write(line.encode("utf-8"))
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise SidecarProtocolError(
                f"sidecar stdin closed unexpectedly: {exc}"
            ) from exc

        async def _read_response() -> dict[str, Any]:
            assert proc.stdout is not None
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    raise SidecarProtocolError(
                        "sidecar stdout closed before responding"
                    )
                try:
                    decoded = json.loads(raw.decode("utf-8").strip())
                except json.JSONDecodeError as exc:
                    raise SidecarProtocolError(
                        f"malformed sidecar response: {raw!r}"
                    ) from exc
                # Skip stray lines (shouldn't happen but be defensive).
                if not isinstance(decoded, dict):
                    continue
                if decoded.get("id") != request_id:
                    # Out-of-band line (sidecar spec doesn't allow
                    # this, but tolerating it costs nothing).
                    continue
                return decoded

        try:
            if timeout is not None:
                resp = await asyncio.wait_for(_read_response(), timeout=timeout)
            else:
                resp = await _read_response()
        except asyncio.TimeoutError as exc:
            raise SidecarTimeout(
                f"sidecar did not respond within {timeout:.2f}s"
            ) from exc
        return resp

    # ── Internal: envelope construction ──────────────────────────────────

    def _build_execute_params(
        self, request: SandboxExecutionRequest
    ) -> dict[str, Any]:
        reg = self._commands.get(request.command)
        if reg is None:
            raise KeyError(request.command)

        limits = reg.limits or self._default_limits
        # Per-request override via env (operator-friendly knob without
        # a separate API surface). Limits set via env take precedence
        # because they're typically used by tests / debugging.
        wall_override = request.env.get("TITANX_SIDECAR_WALL_MS")
        memory_override = request.env.get("TITANX_SIDECAR_MEMORY_BYTES")
        fuel_override = request.env.get("TITANX_SIDECAR_FUEL")

        env = {**reg.env, **request.env}
        # Strip our own knobs from the env we forward to WASM — the
        # tool doesn't need to see them.
        for k in (
            "TITANX_SIDECAR_WALL_MS",
            "TITANX_SIDECAR_MEMORY_BYTES",
            "TITANX_SIDECAR_FUEL",
        ):
            env.pop(k, None)

        params: dict[str, Any] = {
            "module_path": reg.module_path,
            "argv": [request.command, *reg.args, *request.args],
            "env": env,
            "preopens": [
                {"host": p.host, "guest": p.guest, "mode": p.mode}
                for p in reg.preopens
            ],
            "stdin": request.input or "",
            "component_model": reg.component_model,
            "limits": {
                "memory_bytes": int(memory_override) if memory_override else limits.memory_bytes,
                "fuel": int(fuel_override) if fuel_override else limits.fuel,
                "wall_clock_ms": int(wall_override) if wall_override else limits.wall_clock_ms,
            },
            "capabilities": request.capabilities or {"wasi_preview1": True},
        }
        return params

    # ── Internal: helpers ────────────────────────────────────────────────

    @staticmethod
    def _versions_compatible(version: str) -> bool:
        """Major.minor must match. Patch is free."""
        if not version or "." not in version:
            return False
        try:
            sidecar_major, sidecar_minor, *_ = version.split(".")
            adapter_major, adapter_minor, *_ = SIDECAR_PROTOCOL_VERSION.split(".")
        except ValueError:
            return False
        return (sidecar_major, sidecar_minor) == (adapter_major, adapter_minor)


# ── Module-level helpers ──────────────────────────────────────────────────


def _exit_code_for(error_code: str) -> int:
    """Translate a sidecar protocol error into a process-style exit code.

    These are conventions the runtime / LLM layer can branch on:
    137 = OOM-ish, 124 = timeout, 132 = trap, 1 = generic.
    """
    return {
        "limit-exceeded": 137,
        "wasm-trap": 132,
        "module-load": 126,
        "capability-denied": 126,
        "internal": 1,
    }.get(error_code, 1)


def encode_module_bytes(data: bytes) -> str:
    """Helper for callers that want to ship a module by value rather
    than by path. Returns base64-encoded bytes ready for the
    ``module_bytes_b64`` field of the ``execute`` envelope.
    """
    return base64.b64encode(data).decode("ascii")


__all__ = [
    "SIDECAR_PROTOCOL_VERSION",
    "SidecarCommandRegistration",
    "SidecarError",
    "SidecarLimits",
    "SidecarPreopen",
    "SidecarProtocolError",
    "SidecarSandboxBackend",
    "SidecarSpawnError",
    "SidecarTimeout",
    "SidecarUnavailable",
    "encode_module_bytes",
]
