"""Self-hosted microVM sandbox backend (libkrun via the ``microsandbox`` SDK).

This is the strong-isolation tier: a hardware-virtualisation boundary (its own
guest kernel) rather than a shared-kernel container.  It replaces the hosted
E2B backend, so the strongest tier runs entirely on the host — no cloud
service, no per-call remote sandbox.

The SDK contract is strictly better for untrusted input than a shell-based
backend: ``Sandbox.exec`` runs an **argv list with no shell**, so a ``;`` or
``$(...)`` inside an argument can never become a second command.  ``env`` and
``stdin`` are passed out-of-band (``env=`` / ``Stdin.bytes``) and never folded
into the command string.

Networking is **off by default**: the SDK's default network profile is
``public_only`` (live public-internet egress), so this backend passes
``Network.none()`` explicitly unless the operator opts in with
``network_enabled``.  ``capabilities().supports_network`` tracks that same flag,
so the router never routes a ``needs_network`` workload onto a networkless
microVM.

The SDK is imported lazily (inside the methods that need it) so a host without
microsandbox / KVM — or one where the operator has not configured an ``image``
— fails ``is_available`` closed instead of at import time, and so tests can
inject a fake module at ``sys.modules``.
"""

from __future__ import annotations

import asyncio
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
class MicrosandboxSandboxBackendOptions:
    # ``image`` has no default on purpose: microsandbox ships no default image
    # and the OCI image *is* the isolation envelope (which browser/runtime is
    # inside the microVM).  Selecting the right image is an operator decision.
    # Left unset, execution fails closed with a clear message rather than
    # silently running the wrong environment.
    image: str = ""
    available: bool = True
    cpus: int | None = None
    memory: int | None = None
    name_prefix: str = "titanx"
    # The SDK's default network profile is ``public_only``: egress to the public
    # internet is live out of the box. A security-first backend must not inherit
    # that silently, so the default here is no network; operators opt in.
    network_enabled: bool = False
    executor: Callable | None = None
    file_writer: Callable | None = None
    file_reader: Callable | None = None
    snapshotter: Callable | None = None


class MicrosandboxSandboxBackend(SandboxBackend):
    kind = "microsandbox"

    def __init__(self, options: MicrosandboxSandboxBackendOptions | None = None) -> None:
        self._opts = options or MicrosandboxSandboxBackendOptions()
        self._sandbox_instances: dict[str, Any] = {}
        # A session-less ``execute`` reuses one long-lived microVM rather than
        # booting a fresh one per call (booting a guest kernel is the whole
        # cost of this tier). The lock stops concurrent first-calls from each
        # booting a microVM and orphaning the loser.
        self._default_sandbox: Any | None = None
        self._default_lock = asyncio.Lock()

    def capabilities(self) -> SandboxBackendCapabilities:
        # Declaration must match the configured network: by default the microVM
        # boots with no egress, so advertising ``supports_network=True`` would
        # let the router start a ``needs_network`` workload that can reach
        # nothing. Derive the flag from the option so the two cannot drift.
        supported = ["command-exec", "filesystem", "browser", "snapshot", "resume"]
        if self._opts.network_enabled:
            supported.append("network")
        return SandboxBackendCapabilities(
            kind="microsandbox",
            supports_persistence=True,
            supports_snapshots=True,
            supports_browser=True,
            supports_network=self._opts.network_enabled,
            supports_package_install=True,
            supports_strong_isolation=True,
            supported_capabilities=supported,
        )

    async def is_available(self) -> bool:
        # The image *is* the isolation envelope, so "no image configured" is
        # not available: report it as such so the router rejects a
        # strong-isolation request with a clear forensic trail instead of
        # selecting this backend and only failing (as an opaque exit_code_1)
        # once the workload is dispatched.
        if not self._opts.available or not self._opts.image:
            return False
        try:
            import microsandbox  # noqa: F401
            return True
        except ImportError:
            return False

    def _image_kwargs(self) -> dict[str, Any]:
        if not self._opts.image:
            raise ValueError(
                "microsandbox image is not configured; set "
                "MicrosandboxSandboxBackendOptions.image to the OCI image the "
                "workload should run on"
            )
        kwargs: dict[str, Any] = {"image": self._opts.image}
        if self._opts.cpus is not None:
            kwargs["cpus"] = self._opts.cpus
        if self._opts.memory is not None:
            kwargs["memory"] = self._opts.memory
        return kwargs

    def _new_name(self) -> str:
        return f"{self._opts.name_prefix}-{uuid4().hex[:12]}"

    def _network_kwargs(self) -> dict[str, Any]:
        # No network by default: the SDK's own default lets a sandbox reach the
        # public internet, which a security-first backend must not inherit
        # silently. When disabled we pass ``Network.none()`` explicitly (rather
        # than relying on any SDK default); when enabled we pass nothing and let
        # the SDK apply its default egress policy.
        if self._opts.network_enabled:
            return {}
        from microsandbox import Network

        return {"network": Network.none()}

    async def _resolve_sandbox(self, session: SandboxSession | None) -> Any:
        if session is not None:
            if session.id in self._sandbox_instances:
                return self._sandbox_instances[session.id]
        elif self._default_sandbox is not None:
            return self._default_sandbox

        from microsandbox import Sandbox

        kwargs = {**self._image_kwargs(), **self._network_kwargs()}
        if session is not None:
            kwargs["detached"] = True
            sbx = await Sandbox.create(name=self._new_name(), **kwargs)
            self._sandbox_instances[session.id] = sbx
            return sbx

        # Session-less: create the shared default microVM under a lock so two
        # concurrent callers cannot each boot one and orphan the loser.
        async with self._default_lock:
            if self._default_sandbox is None:
                self._default_sandbox = await Sandbox.create(
                    name=self._new_name(), **kwargs
                )
            return self._default_sandbox

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
                    backend="microsandbox",
                    exit_code=res.get("exit_code", 0),
                    stdout=res.get("stdout", ""),
                    stderr=res.get("stderr", ""),
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

            from microsandbox import Stdin

            sbx = await self._resolve_sandbox(session)
            timeout_s = (request.timeout_ms / 1000) if request.timeout_ms else None
            stdin = (
                Stdin.bytes(request.input.encode())
                if request.input is not None
                else None
            )
            # ``command``/``args`` ride the SDK as an argv list — there is no
            # shell to quote against, so an argument is never re-parsed as
            # code.  ``env``/``stdin`` are out-of-band and never concatenated.
            result = await sbx.exec(
                request.command,
                request.args,
                cwd=request.cwd or None,
                env=dict(request.env) or None,
                timeout=timeout_s,
                stdin=stdin,
            )

            return SandboxExecutionResult(
                backend="microsandbox",
                exit_code=result.exit_code or 0,
                stdout=result.stdout_text or "",
                stderr=result.stderr_text or "",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as exc:
            return SandboxExecutionResult(
                backend="microsandbox", exit_code=1, stdout="", stderr=str(exc),
                duration_ms=(time.perf_counter() - start) * 1000,
            )

    async def create_session(
        self,
        metadata: dict[str, str] | None = None,
        *,
        allowed_write_paths: list[str] | None = None,
        allowed_read_paths: list[str] | None = None,
        image_digest: str | None = None,
    ) -> SandboxSession:
        # Path scoping / digest pinning inside a microVM is configured through
        # the OCI image (root filesystem contents, mounted volumes), not host
        # paths, so these are accepted for interface parity and ignored here.
        del allowed_write_paths, allowed_read_paths, image_digest
        from microsandbox import Sandbox

        kwargs = {**self._image_kwargs(), **self._network_kwargs()}
        name = self._new_name()
        sbx = await Sandbox.create(name=name, detached=True, **kwargs)
        session = SandboxSession(id=name, backend="microsandbox", metadata=metadata or {})
        self._sandbox_instances[name] = sbx
        return session

    async def destroy_session(self, session_id: str) -> None:
        sbx = self._sandbox_instances.pop(session_id, None)
        if sbx is not None:
            try:
                await sbx.stop()
            except Exception:
                pass

    async def write_files(
        self, files: list[SandboxFileEntry], session: SandboxSession | None = None
    ) -> None:
        if self._opts.file_writer:
            await self._opts.file_writer(files, session)
            return
        if not session or session.id not in self._sandbox_instances:
            raise ValueError("write_files requires an active microsandbox session")
        sbx = self._sandbox_instances[session.id]
        for f in files:
            await sbx.fs.write(f.path, f.content.encode())

    async def read_file(self, path: str, session: SandboxSession | None = None) -> str:
        if self._opts.file_reader:
            return await self._opts.file_reader(path, session)
        if not session or session.id not in self._sandbox_instances:
            raise ValueError("read_file requires an active microsandbox session")
        sbx = self._sandbox_instances[session.id]
        data = await sbx.fs.read(path)
        return data.decode() if isinstance(data, (bytes, bytearray)) else data

    async def snapshot(self, session: SandboxSession) -> SandboxSnapshot:
        sbx = self._sandbox_instances.get(session.id)
        if sbx is None:
            raise ValueError("Cannot snapshot an unknown session")
        snap_id = session.id
        if self._opts.snapshotter:
            snap_id = await self._opts.snapshotter(sbx)
        else:
            try:
                from microsandbox import Snapshot

                snap = await Snapshot.create(sbx)
                snap_id = getattr(snap, "name", None) or getattr(snap, "id", None) or session.id
            except Exception:
                snap_id = session.id
        return SandboxSnapshot(
            id=str(snap_id),
            created_at=datetime.now(timezone.utc).isoformat(),
            backend="microsandbox",
        )

    async def resume(self, snapshot_id: str) -> SandboxSession:
        # ``snapshot_id`` is the value ``snapshot()`` returned — a *snapshot*
        # artifact, not a sandbox name. The SDK boots from it via the
        # ``snapshot=`` config field (mutually exclusive with ``image=``); there
        # is no ``Sandbox.restore``. The network policy is re-applied here too,
        # or a restored microVM would inherit the SDK's ``public_only`` default
        # egress while ``capabilities()`` still declares no network.
        from microsandbox import Sandbox

        sbx = await Sandbox.create(
            name=self._new_name(),
            snapshot=snapshot_id,
            detached=True,
            **self._network_kwargs(),
        )
        session = SandboxSession(id=snapshot_id, backend="microsandbox")
        self._sandbox_instances[session.id] = sbx
        return session
