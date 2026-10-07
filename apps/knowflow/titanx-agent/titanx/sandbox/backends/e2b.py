from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from ..types import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionRequest,
    SandboxExecutionResult,
    SandboxFileEntry,
    SandboxSession,
    SandboxSnapshot,
)


@dataclass
class E2BSandboxBackendOptions:
    api_key: str | None = None
    available: bool = True
    executor: Callable | None = None
    file_writer: Callable | None = None
    file_reader: Callable | None = None


class E2BSandboxBackend(SandboxBackend):
    kind = "e2b"

    def __init__(self, options: E2BSandboxBackendOptions | None = None) -> None:
        self._opts = options or E2BSandboxBackendOptions()
        self._sandbox_instances: dict[str, Any] = {}

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind="e2b",
            supports_persistence=True,
            supports_snapshots=True,
            supports_browser=True,
            supports_network=True,
            supports_package_install=True,
            supported_capabilities=["command-exec", "filesystem", "network", "browser", "snapshot", "resume"],
        )

    async def is_available(self) -> bool:
        if not self._opts.available:
            return False
        try:
            from e2b import Sandbox  # noqa: F401
            return True
        except ImportError:
            return False

    async def execute(
        self,
        request: SandboxExecutionRequest,
        session: SandboxSession | None = None,
    ) -> SandboxExecutionResult:
        start = time.perf_counter()
        try:
            if self._opts.executor:
                res = await self._opts.executor(request, session)
                return SandboxExecutionResult(
                    backend="e2b",
                    exit_code=res.get("exit_code", 0),
                    stdout=res.get("stdout", ""),
                    stderr=res.get("stderr", ""),
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

            from e2b import Sandbox

            cmd_str = " ".join([request.command, *request.args])
            if session and session.id in self._sandbox_instances:
                sbx = self._sandbox_instances[session.id]
            else:
                kwargs: dict[str, Any] = {}
                if self._opts.api_key:
                    kwargs["api_key"] = self._opts.api_key
                sbx = await Sandbox.create(**kwargs)
                if session:
                    self._sandbox_instances[session.id] = sbx

            timeout_s = (request.timeout_ms / 1000) if request.timeout_ms else 60
            result = await sbx.commands.run(cmd_str, timeout=timeout_s, cwd=request.cwd or None)

            return SandboxExecutionResult(
                backend="e2b",
                exit_code=result.exit_code or 0,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as exc:
            return SandboxExecutionResult(
                backend="e2b", exit_code=1, stdout="", stderr=str(exc),
                duration_ms=(time.perf_counter() - start) * 1000,
            )

    async def create_session(self, metadata: dict[str, str] | None = None) -> SandboxSession:
        from e2b import Sandbox
        kwargs: dict[str, Any] = {}
        if self._opts.api_key:
            kwargs["api_key"] = self._opts.api_key
        sbx = await Sandbox.create(**kwargs)
        session = SandboxSession(id=sbx.sandbox_id, backend="e2b", metadata=metadata or {})
        self._sandbox_instances[session.id] = sbx
        return session

    async def destroy_session(self, session_id: str) -> None:
        sbx = self._sandbox_instances.pop(session_id, None)
        if sbx:
            try:
                await sbx.kill()
            except Exception:
                pass

    async def write_files(
        self, files: list[SandboxFileEntry], session: SandboxSession | None = None
    ) -> None:
        if self._opts.file_writer:
            await self._opts.file_writer(files, session)
            return
        if not session or session.id not in self._sandbox_instances:
            raise ValueError("write_files requires an active E2B session")
        sbx = self._sandbox_instances[session.id]
        for f in files:
            await sbx.files.write(f.path, f.content)

    async def read_file(self, path: str, session: SandboxSession | None = None) -> str:
        if self._opts.file_reader:
            return await self._opts.file_reader(path, session)
        if not session or session.id not in self._sandbox_instances:
            raise ValueError("read_file requires an active E2B session")
        sbx = self._sandbox_instances[session.id]
        return await sbx.files.read(path)

    async def snapshot(self, session: SandboxSession) -> SandboxSnapshot:
        sbx = self._sandbox_instances.get(session.id)
        if not sbx:
            raise ValueError("Cannot snapshot an unknown session")
        if hasattr(sbx, "create_snapshot"):
            result = await sbx.create_snapshot()
            snap_id = result.get("snapshotId", str(uuid4()))
        elif hasattr(sbx, "pause"):
            await sbx.pause()
            snap_id = session.id
        else:
            snap_id = session.id
        return SandboxSnapshot(
            id=snap_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            backend="e2b",
        )

    async def resume(self, snapshot_id: str) -> SandboxSession:
        from e2b import Sandbox
        kwargs: dict[str, Any] = {}
        if self._opts.api_key:
            kwargs["api_key"] = self._opts.api_key
        sbx = await Sandbox.connect(snapshot_id, **kwargs)
        session = SandboxSession(id=sbx.sandbox_id, backend="e2b")
        self._sandbox_instances[session.id] = sbx
        return session
