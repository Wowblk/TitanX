from __future__ import annotations

from .types import SandboxBackend, SandboxKind, SandboxRouterInput, SandboxSelection


class SandboxRouter:
    def __init__(
        self,
        backends: list[SandboxBackend],
        default_backend: SandboxKind = "wasm",
    ) -> None:
        self._backends: dict[SandboxKind, SandboxBackend] = {b.kind: b for b in backends}
        self._default_backend = default_backend

    def list_backends(self) -> list[SandboxBackend]:
        return list(self._backends.values())

    def get_backend(self, kind: SandboxKind) -> SandboxBackend | None:
        return self._backends.get(kind)

    async def select(self, inp: SandboxRouterInput | None = None) -> SandboxSelection:
        candidates = self._rank_candidates(inp or SandboxRouterInput())
        for candidate in candidates:
            backend = self._backends.get(candidate["kind"])
            if backend and await backend.is_available():
                return SandboxSelection(backend=backend, reason=candidate["reason"])
        raise RuntimeError("No sandbox backend is available for the requested execution profile")

    def _rank_candidates(self, inp: SandboxRouterInput) -> list[dict]:
        if inp.preferred_backend:
            return [
                {"kind": inp.preferred_backend, "reason": f"preferred backend '{inp.preferred_backend}' requested"},
                *self._fallbacks_excluding(inp.preferred_backend),
            ]

        if inp.requires_remote_isolation or inp.risk_level == "high" or inp.needs_browser:
            return [
                {"kind": "e2b", "reason": "remote isolation selected for high-risk or browser workload"},
                {"kind": "docker", "reason": "docker fallback for isolated system workload"},
                {"kind": "wasm", "reason": "wasm fallback when stronger backends are unavailable"},
            ]

        if inp.needs_filesystem or inp.needs_network or inp.needs_package_install or inp.risk_level == "medium":
            return [
                {"kind": "docker", "reason": "docker selected for filesystem, network, or package workload"},
                {"kind": "e2b", "reason": "e2b fallback for remotely isolated system workload"},
                {"kind": "wasm", "reason": "wasm fallback for reduced-capability execution"},
            ]

        return [
            {"kind": self._default_backend, "reason": "default lightweight sandbox selected"},
            *self._fallbacks_excluding(self._default_backend),
        ]

    def _fallbacks_excluding(self, kind: SandboxKind) -> list[dict]:
        return [
            {"kind": k, "reason": f"fallback to '{k}' backend"}
            for k in ("wasm", "docker", "e2b")
            if k != kind
        ]
