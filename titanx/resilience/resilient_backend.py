from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .circuit_breaker import CircuitBreaker, CircuitBreakerOptions, CircuitOpenError
from .retry import RetryOptions, with_retry
from ..sandbox.types import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxExecutionRequest,
    SandboxExecutionResult,
    SandboxFileEntry,
    SandboxSession,
    SandboxSnapshot,
)


@dataclass
class ResilientOptions:
    failure_threshold: int = 5
    success_threshold: int = 2
    cooldown_ms: int = 60_000
    window_ms: int = 60_000
    max_attempts: int = 3
    base_delay_ms: int = 100
    max_delay_ms: int = 10_000
    jitter: bool = True


def _is_retryable(exc: Exception) -> bool:
    return not isinstance(exc, CircuitOpenError)


class ResilientSandboxBackend(SandboxBackend):
    def __init__(self, backend: SandboxBackend, options: ResilientOptions | None = None) -> None:
        opts = options or ResilientOptions()
        self._backend = backend
        self._breaker = CircuitBreaker(
            backend.kind,
            CircuitBreakerOptions(
                failure_threshold=opts.failure_threshold,
                success_threshold=opts.success_threshold,
                cooldown_ms=opts.cooldown_ms,
                window_ms=opts.window_ms,
            ),
        )
        self._retry_opts = RetryOptions(
            max_attempts=opts.max_attempts,
            base_delay_ms=opts.base_delay_ms,
            max_delay_ms=opts.max_delay_ms,
            jitter=opts.jitter,
            retry_if=_is_retryable,
        )

    @property
    def kind(self) -> str:
        return self._backend.kind

    def get_circuit_state(self) -> str:
        return self._breaker.get_state()

    def capabilities(self) -> SandboxBackendCapabilities:
        return self._backend.capabilities()

    async def is_available(self) -> bool:
        if self._breaker.get_state() == "open":
            return False
        return await self._backend.is_available()

    async def execute(self, request: SandboxExecutionRequest, session: SandboxSession | None = None) -> SandboxExecutionResult:
        return await self._breaker.call(
            lambda: with_retry(lambda: self._backend.execute(request, session), self._retry_opts)
        )

    async def create_session(self, metadata: dict[str, str] | None = None) -> SandboxSession:
        if not hasattr(self._backend, "create_session"):
            raise NotImplementedError(f"{self.kind} does not support sessions")
        return await self._breaker.call(
            lambda: with_retry(lambda: self._backend.create_session(metadata), self._retry_opts)
        )

    async def destroy_session(self, session_id: str) -> None:
        if hasattr(self._backend, "destroy_session"):
            await self._backend.destroy_session(session_id)

    async def write_files(self, files: list[SandboxFileEntry], session: SandboxSession | None = None) -> None:
        if not hasattr(self._backend, "write_files"):
            raise NotImplementedError(f"{self.kind} does not support write_files")
        return await self._breaker.call(
            lambda: with_retry(lambda: self._backend.write_files(files, session), self._retry_opts)
        )

    async def read_file(self, path: str, session: SandboxSession | None = None) -> str:
        if not hasattr(self._backend, "read_file"):
            raise NotImplementedError(f"{self.kind} does not support read_file")
        return await self._breaker.call(
            lambda: with_retry(lambda: self._backend.read_file(path, session), self._retry_opts)
        )

    async def snapshot(self, session: SandboxSession) -> SandboxSnapshot:
        if not hasattr(self._backend, "snapshot"):
            raise NotImplementedError(f"{self.kind} does not support snapshot")
        return await self._breaker.call(
            lambda: with_retry(lambda: self._backend.snapshot(session), self._retry_opts)
        )

    async def resume(self, snapshot_id: str) -> SandboxSession:
        if not hasattr(self._backend, "resume"):
            raise NotImplementedError(f"{self.kind} does not support resume")
        return await self._breaker.call(
            lambda: with_retry(lambda: self._backend.resume(snapshot_id), self._retry_opts)
        )
