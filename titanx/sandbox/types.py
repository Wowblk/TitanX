from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

SandboxKind = Literal["wasm", "docker", "e2b"]
SandboxRiskLevel = Literal["low", "medium", "high"]


@dataclass
class SandboxExecutionRequest:
    command: str
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    timeout_ms: int | None = None
    input: str | None = None


@dataclass
class SandboxExecutionResult:
    backend: SandboxKind
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float


@dataclass
class SandboxFileEntry:
    path: str
    content: str


@dataclass
class SandboxSnapshot:
    id: str
    created_at: str
    backend: SandboxKind


@dataclass
class SandboxSession:
    id: str
    backend: SandboxKind
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class ManagedSandboxSession(SandboxSession):
    created_at: str = ""
    last_used_at: str = ""
    persistent: bool = False


@dataclass
class SandboxToolPolicy:
    preferred_backend: SandboxKind | None = None
    risk_level: SandboxRiskLevel | None = None
    requires_remote_isolation: bool = False
    needs_filesystem: bool = False
    needs_network: bool = False
    needs_browser: bool = False
    needs_package_install: bool = False


@dataclass
class SandboxBackendCapabilities:
    kind: SandboxKind
    supports_persistence: bool
    supports_snapshots: bool
    supports_browser: bool
    supports_network: bool
    supports_package_install: bool
    supported_capabilities: list[str]


@dataclass
class SandboxRouterInput:
    preferred_backend: SandboxKind | None = None
    risk_level: SandboxRiskLevel | None = None
    requires_remote_isolation: bool = False
    needs_filesystem: bool = False
    needs_network: bool = False
    needs_browser: bool = False
    needs_package_install: bool = False


@dataclass
class SandboxSelection:
    backend: SandboxBackend
    reason: str


@dataclass
class RuntimeDirectories:
    logs: str
    cache: str
    workspace: str


class SandboxBackend:
    kind: SandboxKind

    def capabilities(self) -> SandboxBackendCapabilities:
        raise NotImplementedError

    async def is_available(self) -> bool:
        raise NotImplementedError

    async def execute(
        self,
        request: SandboxExecutionRequest,
        session: SandboxSession | None = None,
    ) -> SandboxExecutionResult:
        raise NotImplementedError

    async def create_session(self, metadata: dict[str, str] | None = None) -> SandboxSession:
        raise NotImplementedError

    async def destroy_session(self, session_id: str) -> None:
        raise NotImplementedError

    async def write_files(self, files: list[SandboxFileEntry], session: SandboxSession | None = None) -> None:
        raise NotImplementedError

    async def read_file(self, path: str, session: SandboxSession | None = None) -> str:
        raise NotImplementedError

    async def snapshot(self, session: SandboxSession) -> SandboxSnapshot:
        raise NotImplementedError

    async def resume(self, snapshot_id: str) -> SandboxSession:
        raise NotImplementedError
