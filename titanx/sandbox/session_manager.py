"""Bounded sandbox session lifecycle.

The historical implementation:

- never evicted sessions
- never cleaned up workspace dirs on the host filesystem
- ran ``os.makedirs`` synchronously, blocking the event loop on slow
  filesystems (NFS, fuse, EBS cold start)
- consulted ``self._allowed_write_paths`` at construction time only,
  so dynamic policy changes never reached new sessions

Hardenings (Q19):

1. **Bounded session count + idle TTL.** ``max_sessions`` caps total
   live sessions and ``idle_ttl_seconds`` evicts inactive ones on
   access. Eviction calls each backend's ``destroy_session`` so
   container / E2B resources are released.
2. **Workspace cleanup on destroy.** A session's host workspace dir
   is removed when the session is destroyed (best-effort; failure to
   clean is logged but not raised).
3. **Async makedirs.** ``os.makedirs`` runs in a worker thread to
   avoid pinning the event loop.
4. **Dynamic write-path resolution.** When a ``policy_store`` is
   provided, ``create`` and ``write_files`` consult the live policy
   instead of the constructor-time list, so a break-glass relaxation
   takes effect without reconstructing the manager.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
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


def _warn(msg: str) -> None:
    try:
        print(f"[titanx.sandbox] WARNING: {msg}", file=sys.stderr, flush=True)
    except Exception:
        pass


class SandboxSessionManager:
    def __init__(
        self,
        router: SandboxRouter,
        workspace_dir: str | None = None,
        allowed_write_paths: list[str] | None = None,
        *,
        policy_store=None,
        max_sessions: int = 256,
        idle_ttl_seconds: float = 1800.0,
    ) -> None:
        self._router = router
        self._workspace_dir = workspace_dir
        self._allowed_write_paths = allowed_write_paths
        self._policy_store = policy_store
        self._max_sessions = max(1, max_sessions)
        self._idle_ttl = max(0.0, idle_ttl_seconds)
        self._sessions: dict[str, ManagedSandboxSession] = {}
        self._session_backends: dict[str, SandboxBackend] = {}
        self._workspace_paths: dict[str, str] = {}
        self._last_used: dict[str, float] = {}
        self._lock = asyncio.Lock()

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
        async with self._lock:
            await self._sweep_idle_locked()
            if len(self._sessions) >= self._max_sessions:
                await self._evict_lru_locked()

            selection = await self._router.select(inp or SandboxRouterInput())
            now = _now()
            effective_paths = self._effective_write_paths()
            effective_read_paths = self._effective_read_paths()
            effective_image_digest = self._effective_image_digest()
            if hasattr(selection.backend, "create_session"):
                # The new ``allowed_read_paths`` / ``image_digest`` kwargs
                # were added in 0.3.x. Backends written against the
                # 0.2.x base class signature won't accept them; only
                # forward when the operator actually populated the
                # corresponding policy fields so legacy backends keep
                # working as long as nobody opts in.
                kwargs: dict = {"allowed_write_paths": effective_paths}
                if effective_read_paths:
                    kwargs["allowed_read_paths"] = effective_read_paths
                if effective_image_digest:
                    kwargs["image_digest"] = effective_image_digest
                base = await selection.backend.create_session(metadata, **kwargs)
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
            self._last_used[session.id] = time.monotonic()

            if self._workspace_dir:
                ws_path = os.path.join(self._workspace_dir, session.id)
                # Async makedirs so we don't pin the loop on slow FS.
                await asyncio.to_thread(os.makedirs, ws_path, exist_ok=True)
                self._workspace_paths[session.id] = ws_path

            return session

    async def execute(self, session_id: str, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        backend, session = self._require_session(session_id)
        # Late-bind the live policy's allowed_write_paths / read_paths /
        # image_digest if the caller didn't already populate them. The
        # Docker backend uses these for kernel-level mount enforcement
        # (Q5/Q11) and for digest verification. Without this
        # propagation, dynamic policy edits never reach a long-lived
        # session's per-call requests.
        if request.allowed_write_paths is None:
            effective = self._effective_write_paths()
            if effective:
                request.allowed_write_paths = list(effective)
        if request.allowed_read_paths is None:
            effective_read = self._effective_read_paths()
            if effective_read:
                request.allowed_read_paths = list(effective_read)
        if request.image_digest is None:
            request.image_digest = self._effective_image_digest()
        result = await backend.execute(request, session)
        self._touch(session_id)
        return result

    async def write_files(self, session_id: str, files: list[SandboxFileEntry]) -> None:
        backend, _ = self._require_session(session_id)
        if not hasattr(backend, "write_files"):
            raise RuntimeError(f"Sandbox backend '{backend.kind}' does not support file uploads")
        # Consult the LIVE policy here, not the constructor-time list,
        # so a break-glass relaxation actually takes effect.
        effective = self._effective_write_paths()
        if effective:
            for f in files:
                if not is_path_allowed(f.path, effective):
                    raise PermissionError(
                        f"Write to '{f.path}' is not permitted by the path whitelist"
                    )
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
        self._last_used[session.id] = time.monotonic()
        return session

    async def destroy(self, session_id: str) -> None:
        async with self._lock:
            await self._destroy_locked(session_id)

    async def aclose(self) -> None:
        """Destroy every live session. Safe to call multiple times."""
        async with self._lock:
            for sid in list(self._sessions.keys()):
                try:
                    await self._destroy_locked(sid)
                except Exception as exc:
                    _warn(f"aclose failed for session {sid}: {exc!r}")

    # ── internal ────────────────────────────────────────────────────────

    def _effective_write_paths(self) -> list[str] | None:
        # Live policy beats constructor-time list — a break-glass
        # relaxation must reach the backend without restart.
        if self._policy_store is not None:
            try:
                paths = self._policy_store.get_policy().allowed_write_paths
            except Exception:
                paths = None
            if paths:
                return list(paths)
        return self._allowed_write_paths

    def _effective_read_paths(self) -> list[str] | None:
        if self._policy_store is None:
            return None
        try:
            paths = self._policy_store.get_policy().allowed_read_paths
        except Exception:
            return None
        return list(paths) if paths else None

    def _effective_image_digest(self) -> str | None:
        if self._policy_store is None:
            return None
        try:
            return self._policy_store.get_policy().image_digest
        except Exception:
            return None

    async def _destroy_locked(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        backend = self._session_backends.get(session_id)
        ws_path = self._workspace_paths.get(session_id)

        if backend is not None and session is not None and hasattr(backend, "destroy_session"):
            try:
                await backend.destroy_session(session.id)
            except Exception as exc:
                _warn(f"destroy_session failed for {session_id}: {exc!r}")

        if ws_path:
            # Best-effort workspace cleanup. ``shutil.rmtree`` is sync
            # and can be slow for large dirs — push it off-loop.
            try:
                await asyncio.to_thread(shutil.rmtree, ws_path, ignore_errors=True)
            except Exception as exc:
                _warn(f"workspace cleanup failed for {session_id}: {exc!r}")

        self._sessions.pop(session_id, None)
        self._session_backends.pop(session_id, None)
        self._workspace_paths.pop(session_id, None)
        self._last_used.pop(session_id, None)

    async def _sweep_idle_locked(self) -> None:
        if self._idle_ttl <= 0:
            return
        cutoff = time.monotonic() - self._idle_ttl
        stale = [sid for sid, ts in self._last_used.items() if ts < cutoff]
        for sid in stale:
            try:
                await self._destroy_locked(sid)
            except Exception as exc:
                _warn(f"idle eviction failed for {sid}: {exc!r}")

    async def _evict_lru_locked(self) -> None:
        if not self._last_used:
            return
        victim = min(self._last_used.items(), key=lambda kv: kv[1])[0]
        try:
            await self._destroy_locked(victim)
        except Exception as exc:
            _warn(f"LRU eviction failed for {victim}: {exc!r}")

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
        if session_id in self._last_used:
            self._last_used[session_id] = time.monotonic()
