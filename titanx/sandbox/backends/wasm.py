from __future__ import annotations

import asyncio
import hashlib
import os
import pickle
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..types import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionRequest,
    SandboxExecutionResult,
)


@dataclass
class WasmCommandRegistration:
    module_path: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    preopens: dict[str, str] = field(default_factory=dict)


WasmExecutorFn = Callable[[SandboxExecutionRequest], Any]


class WasmSandboxBackend(SandboxBackend):
    kind = "wasm"

    def __init__(
        self,
        available: bool = True,
        executor: WasmExecutorFn | None = None,
        commands: dict[str, WasmCommandRegistration] | None = None,
        log_dir: str | None = None,
        cache_dir: str | None = None,
    ) -> None:
        self._available = available
        self._executor = executor
        self._commands: dict[str, WasmCommandRegistration] = commands or {}
        self._log_dir = log_dir
        self._cache_dir = cache_dir
        self._module_cache: dict[str, Any] = {}

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind="wasm",
            supports_persistence=False,
            supports_snapshots=False,
            supports_browser=False,
            supports_network=False,
            supports_package_install=False,
            supported_capabilities=["command-exec"],
        )

    async def is_available(self) -> bool:
        return self._available

    def register_command(self, name: str, reg: WasmCommandRegistration) -> None:
        self._commands[name] = reg

    async def execute(
        self,
        request: SandboxExecutionRequest,
        session=None,
    ) -> SandboxExecutionResult:
        start = time.perf_counter()
        try:
            if self._executor:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._executor(request)  # type: ignore[misc]
                )
            else:
                result = await self._execute_registered(request)

            return SandboxExecutionResult(
                backend="wasm",
                exit_code=result.get("exit_code", 0),
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as exc:
            return SandboxExecutionResult(
                backend="wasm",
                exit_code=1,
                stdout="",
                stderr=str(exc),
                duration_ms=(time.perf_counter() - start) * 1000,
            )

    async def _execute_registered(self, request: SandboxExecutionRequest) -> dict:
        try:
            from wasmtime import Config, Engine, Linker, Module, Store, WasiConfig
        except ImportError:
            raise RuntimeError("wasmtime is not installed — pip install wasmtime")

        reg = self._commands.get(request.command)
        if not reg:
            raise ValueError(f"Unregistered WASI command: {request.command}")

        module = await self._load_module(reg.module_path)

        stdout_buf: list[str] = []
        stderr_buf: list[str] = []

        use_log_dir = self._log_dir is not None
        if use_log_dir:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            run_dir = os.path.join(self._log_dir, f"{ts}-{request.command}")
            os.makedirs(run_dir, exist_ok=True)
            stdout_path = os.path.join(run_dir, "stdout.log")
            stderr_path = os.path.join(run_dir, "stderr.log")
        else:
            tmp = tempfile.mkdtemp(prefix="titanx-wasm-")
            stdout_path = os.path.join(tmp, "stdout.log")
            stderr_path = os.path.join(tmp, "stderr.log")

        def _run() -> dict:
            wasi = WasiConfig()
            wasi.argv = [request.command, *reg.args, *request.args]
            env_items = {**reg.env, **request.env}
            wasi.set_env(list(env_items.keys()), list(env_items.values()))
            for host_path, guest_path in reg.preopens.items():
                wasi.preopen_dir(host_path, guest_path)
            wasi.stdout_file = stdout_path
            wasi.stderr_file = stderr_path

            cfg = Config()
            engine = Engine(cfg)
            linker = Linker(engine)
            linker.define_wasi()
            store = Store(engine)
            store.set_wasi(wasi)

            instance = linker.instantiate(store, module)
            start_fn = instance.exports(store).get("_start")
            if start_fn is None:
                raise RuntimeError(f"WASI module '{request.command}' does not export '_start'")

            exit_code = 0
            try:
                start_fn(store)
            except Exception as exc:
                import re
                m = re.search(r"exit code[: ]+(\d+)", str(exc), re.I)
                if m:
                    exit_code = int(m.group(1))
                else:
                    raise

            with open(stdout_path) as f:
                stdout = f.read()
            with open(stderr_path) as f:
                stderr = f.read()

            return {"exit_code": exit_code, "stdout": stdout, "stderr": stderr}

        return await asyncio.get_event_loop().run_in_executor(None, _run)

    async def _load_module(self, module_path: str) -> Any:
        if module_path in self._module_cache:
            return self._module_cache[module_path]

        try:
            from wasmtime import Config, Engine, Module
        except ImportError:
            raise RuntimeError("wasmtime is not installed — pip install wasmtime")

        with open(module_path, "rb") as f:
            module_bytes = f.read()

        if self._cache_dir:
            digest = hashlib.sha256(module_bytes).hexdigest()
            cache_path = os.path.join(self._cache_dir, f"{digest}.pkl")
            if os.path.exists(cache_path):
                with open(cache_path, "rb") as f:
                    module = pickle.load(f)
                self._module_cache[module_path] = module
                return module
            engine = Engine(Config())
            module = Module(engine, module_bytes)
            os.makedirs(self._cache_dir, exist_ok=True)
            with open(cache_path, "wb") as f:
                pickle.dump(module, f)
        else:
            engine = Engine(Config())
            module = Module(engine, module_bytes)

        self._module_cache[module_path] = module
        return module
