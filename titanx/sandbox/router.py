"""Sandbox backend router.

Selects a ``SandboxBackend`` for a given workload's risk profile. The
historical implementation silently fell back to a lower-isolation
backend whenever the preferred one was unavailable — a workload
flagged ``risk_level="high"`` could end up on the WASI sandbox during
a Docker / microsandbox outage with zero observability.

Hardenings (Q18):

1. ``min_isolation`` — caller-supplied hard floor. The router refuses
   to satisfy a request that would have to drop below this floor,
   surfacing the constraint as a ``RuntimeError`` instead of quietly
   downgrading.
2. ``on_selection`` callback — observability hook fired on every
   selection so the host can audit *which* backend a tool actually
   ran on, including in fall-back paths. Without this, the audit log
   only records "tool ran" and leaves operators digging through
   per-backend logs to figure out which sandbox observed the call.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from .types import (
    SandboxBackend,
    SandboxBackendCapabilities,
    SandboxKind,
    SandboxRouterInput,
    SandboxSelection,
)


# Higher number = stronger isolation. Used to enforce ``min_isolation``
# and to build the candidate order. WASI < Docker < microVM is the
# project's default ordering; if you swap in a different runtime, override
# this map at construction time (the router never hard-codes kind names
# beyond this table).
_DEFAULT_ISOLATION_RANK: dict[SandboxKind, int] = {
    "wasm": 1,
    "docker": 2,
    "microsandbox": 3,
}


SelectionCallback = Callable[[SandboxSelection, SandboxRouterInput], Awaitable[None] | None]


class SandboxRouter:
    def __init__(
        self,
        backends: list[SandboxBackend],
        default_backend: SandboxKind = "wasm",
        *,
        isolation_rank: dict[SandboxKind, int] | None = None,
        on_selection: SelectionCallback | None = None,
    ) -> None:
        self._backends: dict[SandboxKind, SandboxBackend] = {b.kind: b for b in backends}
        self._default_backend = default_backend
        self._isolation_rank = isolation_rank or dict(_DEFAULT_ISOLATION_RANK)
        self._on_selection = on_selection

    def list_backends(self) -> list[SandboxBackend]:
        return list(self._backends.values())

    def get_backend(self, kind: SandboxKind) -> SandboxBackend | None:
        return self._backends.get(kind)

    async def select(self, inp: SandboxRouterInput | None = None) -> SandboxSelection:
        request = inp or SandboxRouterInput()
        candidates = self._rank_candidates(request)
        # Apply the isolation floor BEFORE walking the candidate list.
        # If no candidate clears the floor, reject the request — better
        # to surface "no acceptable backend" than to silently degrade.
        candidates = self._enforce_min_isolation(candidates, request.min_isolation)
        if not candidates:
            raise RuntimeError(
                f"No sandbox backend satisfies min_isolation={request.min_isolation!r}; "
                f"refusing rather than silently downgrading"
            )

        rejected: list[tuple[SandboxKind, str]] = []
        for candidate in candidates:
            kind: SandboxKind = candidate["kind"]
            backend = self._backends.get(kind)
            if backend is None:
                rejected.append((kind, "backend not registered"))
                continue
            try:
                capabilities = backend.capabilities()
            except Exception as exc:
                rejected.append((kind, f"capability probe raised: {exc!r}"))
                continue
            mismatch = self._capability_mismatch(capabilities, request)
            if mismatch is not None:
                rejected.append((kind, mismatch))
                continue
            try:
                available = await backend.is_available()
            except Exception as exc:
                # An ``is_available`` raise is treated as "not
                # available" rather than crashing the selection. The
                # exception surfaces in the rejection trail attached
                # to the eventual failure message so operators can
                # debug daemon misconfiguration.
                rejected.append((kind, f"availability probe raised: {exc!r}"))
                continue
            if not available:
                rejected.append((kind, "is_available=False"))
                continue
            selection = SandboxSelection(backend=backend, reason=candidate["reason"])
            await self._notify_selection(selection, request)
            return selection

        # Build a forensic-friendly error: the caller needs to know
        # which backends were considered and why each was rejected.
        trail = "; ".join(f"{k}: {why}" for k, why in rejected) or "none"
        raise RuntimeError(
            "No sandbox backend is available for the requested execution profile "
            f"(min_isolation={request.min_isolation!r}; rejected: {trail})"
        )

    @staticmethod
    def _capability_mismatch(
        capabilities: SandboxBackendCapabilities,
        request: SandboxRouterInput,
    ) -> str | None:
        """Return why a backend cannot satisfy the request, or ``None``.

        Candidate ranking is only a preference order.  It must never be used
        as proof that a backend actually implements the requested capability:
        the historical router ranked Docker/WASM as fallbacks for browser or
        strong-isolation workloads even though their capability descriptors
        explicitly said otherwise. Strong isolation is checked against the
        capability flag, never a concrete backend kind.
        """
        if request.requires_strong_isolation and not capabilities.supports_strong_isolation:
            return "does not provide required strong isolation"
        if request.needs_browser and not capabilities.supports_browser:
            return "supports_browser=False"
        if request.needs_network and not capabilities.supports_network:
            return "supports_network=False"
        if request.needs_package_install and not capabilities.supports_package_install:
            return "supports_package_install=False"
        if (
            request.needs_filesystem
            and "filesystem" not in capabilities.supported_capabilities
        ):
            return "filesystem capability not advertised"
        return None

    async def _notify_selection(
        self,
        selection: SandboxSelection,
        request: SandboxRouterInput,
    ) -> None:
        if self._on_selection is None:
            return
        try:
            result = self._on_selection(selection, request)
            if result is not None:
                await result  # type: ignore[misc]
        except Exception:
            # Never fail the selection because the observer raised.
            pass

    def _rank_candidates(self, inp: SandboxRouterInput) -> list[dict]:
        if inp.preferred_backend:
            return [
                {"kind": inp.preferred_backend, "reason": f"preferred backend '{inp.preferred_backend}' requested"},
                *self._fallbacks_excluding(inp.preferred_backend),
            ]

        if inp.requires_strong_isolation or inp.risk_level == "high" or inp.needs_browser:
            return self._candidate_order(
                self._strongest_kind(),
                "strong isolation selected for high-risk or browser workload",
            )

        if inp.needs_filesystem or inp.needs_network or inp.needs_package_install or inp.risk_level == "medium":
            return self._candidate_order(
                "docker",
                "docker selected for filesystem, network, or package workload",
            )

        return [
            {"kind": self._default_backend, "reason": "default lightweight sandbox selected"},
            *self._fallbacks_excluding(self._default_backend),
        ]

    def _kinds_by_rank_desc(self) -> list[SandboxKind]:
        return sorted(
            self._isolation_rank,
            key=lambda k: self._isolation_rank[k],
            reverse=True,
        )

    def _strongest_kind(self) -> SandboxKind:
        return self._kinds_by_rank_desc()[0]

    def _candidate_order(self, primary: SandboxKind, primary_reason: str) -> list[dict]:
        """``primary`` first, then the other kinds by ascending isolation rank.

        Ascending (cheapest-first) fallbacks preserve the previous behaviour:
        try the lighter backend before booting a heavier one. The isolation
        floor is applied separately (``_enforce_min_isolation``), so a
        higher-risk request still cannot fall back below its floor — the
        cheaper candidates are filtered out before they are ever tried.
        Derived from ``_isolation_rank`` so onboarding a new backend kind
        never requires editing a hard-coded name list here.
        """
        return [
            {"kind": primary, "reason": primary_reason},
            *self._fallbacks_excluding(primary),
        ]

    def _enforce_min_isolation(
        self,
        candidates: list[dict],
        min_isolation: SandboxKind | None,
    ) -> list[dict]:
        if min_isolation is None:
            return candidates
        floor = self._isolation_rank.get(min_isolation)
        if floor is None:
            # Unknown kind in the floor: refuse rather than guess.
            return []
        return [
            c for c in candidates
            if self._isolation_rank.get(c["kind"], 0) >= floor
        ]

    def _fallbacks_excluding(self, kind: SandboxKind) -> list[dict]:
        return [
            {"kind": k, "reason": f"fallback to '{k}' backend"}
            for k in sorted(self._isolation_rank, key=lambda k: self._isolation_rank[k])
            if k != kind
        ]
