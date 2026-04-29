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
    # Absolute host paths the workload is permitted to write to. Backends are
    # expected to enforce this list at the kernel/sandbox level (e.g. read-only
    # root filesystem + bind-mounted writable paths for Docker, equivalent
    # mount overlays for E2B). The host-side PathGuard is defence-in-depth
    # only — this field is the authoritative boundary.
    allowed_write_paths: list[str] | None = None
    # Absolute host paths the workload may read but never write. Bind-mounted
    # ``:ro`` by the Docker backend; ignored by backends without a mount
    # surface (wasm). Mirrors NemoClaw's ``filesystem_policy.read_only``.
    # ``None`` = caller did not propagate from policy; ``[]`` = no host
    # reads allowed (the most restrictive setting).
    allowed_read_paths: list[str] | None = None
    # Optional OCI image digest the workload must run on. The backend
    # (Docker) compares this to the resolved image digest before launch
    # and refuses on mismatch. ``None`` = no pin requested. Set from
    # ``AgentPolicy.image_digest`` by the tool runtime.
    image_digest: str | None = None
    # Per-call capability envelope for sidecar component-model tools. The
    # Python process forwards this to the sidecar, but the Rust sidecar is the
    # enforcement boundary that allows or denies each imported capability.
    capabilities: dict[str, Any] | None = None


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
    # Hard floor on sandbox isolation. ``"docker"`` rejects ``"wasm"``
    # silently-fallback selections; ``"e2b"`` rejects everything except
    # remote isolation. The router refuses to satisfy the request
    # below this floor — failing closed beats leaking a high-risk
    # workload onto a low-isolation backend during a partial outage.
    # ``None`` (default) preserves legacy "best effort" behaviour:
    # the router will pick the highest-isolation backend it can find.
    min_isolation: SandboxKind | None = None


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

    async def create_session(
        self,
        metadata: dict[str, str] | None = None,
        *,
        allowed_write_paths: list[str] | None = None,
        allowed_read_paths: list[str] | None = None,
        image_digest: str | None = None,
    ) -> SandboxSession:
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
