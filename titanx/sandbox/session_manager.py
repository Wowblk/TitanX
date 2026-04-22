from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

from .path_guard import is_path_allowed
from .router import SandboxRouter
from .types import (
    ManagedSandboxSession,
    SandboxBackend,
    SandboxExecutionRequest,
    SandboxExecutionResult,
    SandboxFileEntry,
    SandboxRouterInput,
    SandboxSession,
    SandboxSnapshot,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SandboxSessionManager:
    def __init__(
        self,
        router: SandboxRouter,
        workspace_dir: str | None = None,
        allowed_write_paths: list[str] | None = None,
    ) -> None:
        self._router = router
        self._workspace_dir = workspace_dir
        self._allowed_write_paths = allowed_write_paths
        self._sessions: dict[str, ManagedSandboxSession] = {}
        self._session_backends: dict[str, SandboxBackend] = {}
        self._workspace_paths: dict[str, str] = {}

    def list_sessions(self) -> list[ManagedSandboxSession]:
        return list(self._sessions.values())

    def get_session(self, session_id: str) -> ManagedSandboxSession | None:
        return self._sessions.get(session_id)

    def get_workspace_path(self, session_id: str) -> str | None:
        return self._workspace_paths.get(session_id)

    async def create(
        self,
        inp: SandboxRouterInput | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ManagedSandboxSession:
        selection = await self._router.select(inp or SandboxRouterInput())
        now = _now()
        if hasattr(selection.backend, "create_session"):
            base = await selection.backend.create_session(metadata)
        else:
            base = SandboxSession(
                id=f"{selection.backend.kind}-{uuid4()}",
                backend=selection.backend.kind,
                metadata=metadata or {},
            )

        session = ManagedSandboxSession(
            id=base.id,
            backend=base.backend,
            metadata=base.metadata,
            created_at=now,
            last_used_at=now,
            persistent=hasattr(selection.backend, "create_session"),
        )
        self._sessions[session.id] = session
        self._session_backends[session.id] = selection.backend

        if self._workspace_dir:
            ws_path = os.path.join(self._workspace_dir, session.id)
            os.makedirs(ws_path, exist_ok=True)
            self._workspace_paths[session.id] = ws_path

        return session

    async def execute(self, session_id: str, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        backend, session = self._require_session(session_id)
        result = await backend.execute(request, session)
        self._touch(session_id)
        return result

    async def write_files(self, session_id: str, files: list[SandboxFileEntry]) -> None:
        backend, _ = self._require_session(session_id)
        if not hasattr(backend, "write_files"):
            raise RuntimeError(f"Sandbox backend '{backend.kind}' does not support file uploads")
        if self._allowed_write_paths:
            for f in files:
                if not is_path_allowed(f.path, self._allowed_write_paths):
                    raise PermissionError(f"Write to '{f.path}' is not permitted by the path whitelist")
        await backend.write_files(files, self._sessions.get(session_id))
        self._touch(session_id)

    async def read_file(self, session_id: str, path: str) -> str:
        backend, _ = self._require_session(session_id)
        if not hasattr(backend, "read_file"):
            raise RuntimeError(f"Sandbox backend '{backend.kind}' does not support file downloads")
        content = await backend.read_file(path, self._sessions.get(session_id))
        self._touch(session_id)
        return content

    async def snapshot(self, session_id: str) -> SandboxSnapshot:
        backend, session = self._require_session(session_id)
        if not hasattr(backend, "snapshot"):
            raise RuntimeError(f"Sandbox backend '{backend.kind}' does not support snapshots")
        snap = await backend.snapshot(session)
        self._touch(session_id)
        return snap

    async def resume(self, snap: SandboxSnapshot) -> ManagedSandboxSession:
        backend = self._router.get_backend(snap.backend)
        if not backend or not hasattr(backend, "resume"):
            raise RuntimeError(f"Sandbox backend '{snap.backend}' does not support resume")
        base = await backend.resume(snap.id)
        now = _now()
        session = ManagedSandboxSession(
            id=base.id,
            backend=base.backend,
            metadata=base.metadata,
            created_at=now,
            last_used_at=now,
            persistent=True,
        )
        self._sessions[session.id] = session
        self._session_backends[session.id] = backend
        return session

    async def destroy(self, session_id: str) -> None:
        backend, session = self._require_session(session_id)
        if hasattr(backend, "destroy_session"):
            await backend.destroy_session(session.id)
        self._sessions.pop(session_id, None)
        self._session_backends.pop(session_id, None)
        self._workspace_paths.pop(session_id, None)

    def _require_session(self, session_id: str) -> tuple[SandboxBackend, SandboxSession]:
        session = self._sessions.get(session_id)
        if not session:
            raise KeyError(f"Unknown sandbox session: {session_id}")
        backend = self._session_backends.get(session_id)
        if not backend:
            raise KeyError(f"Missing backend for sandbox session: {session_id}")
        return backend, session

    def _touch(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.last_used_at = _now()
