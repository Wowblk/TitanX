"""Microsandbox backend: data stays data, and stdin/env/cwd ride the SDK.

The microsandbox SDK (``Sandbox.exec``) runs a command as an **argv list**
with no shell.  That is a strictly better contract than E2B's
``/bin/bash -l -c <cmd>``: there is no shell to quote against, so a ``;``
or ``$(...)`` inside an argument can never become a second command.  These
tests pin the interface the backend hands the SDK — the seam where a bug
would let untrusted text (or a dropped field) slip through:

* the command/args are passed as an argv list, never a joined shell string;
* ``env`` rides the SDK's ``env=`` parameter and never the command;
* ``input`` (stdin) is forwarded via ``Stdin.bytes`` — unlike E2B, microsandbox
  supports it, so the backend must not drop it;
* ``cwd``/``timeout`` ride SDK parameters;
* a microVM backend advertises ``supports_strong_isolation``.

A fake ``microsandbox`` module is injected at ``sys.modules`` (the SDK is
imported lazily), so no real microVM — and no KVM / Apple-Silicon host — is
needed to run these. ``tests/test_microsandbox_sdk_contract.py`` checks the
fakes below against the installed SDK.
"""

from __future__ import annotations

import asyncio
import os
import sys
import types

import pytest

import titanx.sandbox.backends.microsandbox as microsandbox_backend
from titanx.sandbox.backends.microsandbox import (
    MicrosandboxSandboxBackend,
    MicrosandboxSandboxBackendOptions,
)
from titanx.sandbox.types import SandboxExecutionRequest, SandboxSession


class _RecordingFs:
    """Stand-in for ``microsandbox.SandboxFsOps`` (``Sandbox.fs``).

    ``write_files`` / ``read_file`` call ``fs.write`` / ``fs.read``. Parameter
    names match the SDK so ``tests/test_microsandbox_sdk_contract.py`` can
    bind them.
    """

    def __init__(self) -> None:
        self.writes: list[tuple[str, bytes]] = []
        self.reads: list[str] = []

    async def read(self, path: str) -> bytes:
        self.reads.append(path)
        return b""

    async def write(self, path: str, data: bytes) -> None:
        self.writes.append((path, data))


class _RecordingSandbox:
    """Stand-in for a running ``microsandbox.Sandbox`` / ``SandboxHandle``.

    ``exec`` / ``stop`` / ``fs`` mirror the ``Sandbox`` instance returned by
    ``Sandbox.create`` and ``Sandbox.restore``. ``snapshot`` mirrors
    ``SandboxHandle.snapshot`` (what ``Sandbox.get`` returns).
    """

    last: "_RecordingSandbox | None" = None
    snapshot_error: Exception | None = None
    last_snapshot_name: str | None = None

    def __init__(self) -> None:
        self.execs: list[dict] = []
        self.stopped = False
        self.snapshot_names: list[str] = []
        self.fs = _RecordingFs()

    async def snapshot(self, name: str):
        # ``SandboxHandle.snapshot`` is the live-capture API; ``Snapshot.create``
        # is the stopped-source variant. The backend must use the former.
        if _RecordingSandbox.snapshot_error is not None:
            raise _RecordingSandbox.snapshot_error
        self.snapshot_names.append(name)
        _RecordingSandbox.last_snapshot_name = name
        return types.SimpleNamespace(reference=f"ref:{name}", id=f"id:{name}")

    async def exec(
        self,
        cmd: str,
        args: list[str] | None = None,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        stdin=None,
    ):
        self.execs.append(
            {"cmd": cmd, "args": args, "cwd": cwd, "env": env,
             "timeout": timeout, "stdin": stdin}
        )
        return types.SimpleNamespace(exit_code=0, stdout_text="ok", stderr_text="")

    async def stop(self) -> None:
        self.stopped = True


class _FakeSandboxFactory:
    last_create_kwargs: dict | None = None
    last_restore_kwargs: dict | None = None
    last_get_name: str | None = None
    create_calls: int = 0
    # Optional admission gates: tests park one call inside create/restore to
    # exercise concurrency deterministically (no sleep-based races).
    create_started: asyncio.Event | None = None
    create_gate: asyncio.Event | None = None
    restore_started: asyncio.Event | None = None
    restore_gate: asyncio.Event | None = None

    @staticmethod
    async def create(**kwargs) -> _RecordingSandbox:
        _FakeSandboxFactory.create_calls += 1
        _FakeSandboxFactory.last_create_kwargs = kwargs
        if _FakeSandboxFactory.create_started is not None:
            _FakeSandboxFactory.create_started.set()
        if _FakeSandboxFactory.create_gate is not None:
            await _FakeSandboxFactory.create_gate.wait()
        # Yield so a concurrent first call gets a chance to observe the empty
        # cache; without this the fake completes synchronously and hides races.
        await asyncio.sleep(0)
        _RecordingSandbox.last = _RecordingSandbox()
        return _RecordingSandbox.last

    @staticmethod
    async def restore(snapshot, **kwargs) -> _RecordingSandbox:
        _FakeSandboxFactory.last_restore_kwargs = {"snapshot": snapshot, **kwargs}
        if _FakeSandboxFactory.restore_started is not None:
            _FakeSandboxFactory.restore_started.set()
        if _FakeSandboxFactory.restore_gate is not None:
            await _FakeSandboxFactory.restore_gate.wait()
        _RecordingSandbox.last = _RecordingSandbox()
        return _RecordingSandbox.last

    @staticmethod
    async def get(name: str) -> _RecordingSandbox:
        _FakeSandboxFactory.last_get_name = name
        assert _RecordingSandbox.last is not None, "Sandbox.get before Sandbox.create"
        return _RecordingSandbox.last


class _Stdin:
    last: object = None

    @staticmethod
    def bytes(data) -> tuple[str, object]:
        _Stdin.last = data
        return ("stdin-bytes", data)


class _Network:
    """Stand-in for ``microsandbox.Network``."""

    @staticmethod
    def none() -> str:
        return "network-none"


def _install_fake_microsandbox(monkeypatch) -> None:
    module = types.ModuleType("microsandbox")
    module.Sandbox = _FakeSandboxFactory  # type: ignore[attr-defined]
    module.Stdin = _Stdin  # type: ignore[attr-defined]
    module.Network = _Network  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "microsandbox", module)
    _RecordingSandbox.last = None
    _RecordingSandbox.snapshot_error = None
    _RecordingSandbox.last_snapshot_name = None
    _Stdin.last = None
    _FakeSandboxFactory.last_create_kwargs = None
    _FakeSandboxFactory.last_restore_kwargs = None
    _FakeSandboxFactory.last_get_name = None
    _FakeSandboxFactory.create_calls = 0
    _FakeSandboxFactory.create_started = None
    _FakeSandboxFactory.create_gate = None
    _FakeSandboxFactory.restore_started = None
    _FakeSandboxFactory.restore_gate = None
    # Keep tests hermetic on any CI host by presenting a supported host to the
    # real probe (Linux with KVM) rather than stubbing the probe itself.
    monkeypatch.setattr(microsandbox_backend.platform, "system", lambda: "Linux")
    monkeypatch.setattr(microsandbox_backend.os, "access", lambda *args: True)


def _backend() -> MicrosandboxSandboxBackend:
    return MicrosandboxSandboxBackend(
        MicrosandboxSandboxBackendOptions(available=True, image="python")
    )


def _exec() -> dict:
    assert _RecordingSandbox.last is not None, "Sandbox.create was never called"
    assert _RecordingSandbox.last.execs, "exec was never called"
    return _RecordingSandbox.last.execs[-1]


async def test_command_and_args_are_passed_as_argv_not_a_shell_string(monkeypatch):
    _install_fake_microsandbox(monkeypatch)
    payload = "safe; touch /tmp/pwned && echo $(id)"

    await _backend().execute(SandboxExecutionRequest(command="echo", args=[payload]))

    call = _exec()
    assert call["cmd"] == "echo"
    assert call["args"] == [payload]
    # No shell string is ever assembled: the payload stays one argv token.
    # The microVM is booted with the configured image (the isolation envelope)
    # and a name — a regression that dropped either would go unnoticed here.
    assert _FakeSandboxFactory.last_create_kwargs["image"] == "python"
    assert _FakeSandboxFactory.last_create_kwargs.get("name")


async def test_env_is_forwarded_out_of_band_never_in_the_command(monkeypatch):
    _install_fake_microsandbox(monkeypatch)
    env = {"PATH": "/opt/bin", "GREETING": "hi; touch /tmp/pwned"}

    await _backend().execute(
        SandboxExecutionRequest(command="echo", args=["hi"], env=env)
    )

    call = _exec()
    assert call["env"] == env
    assert call["cmd"] == "echo"
    assert call["args"] == ["hi"]
    assert "pwned" not in call["cmd"]
    assert "pwned" not in " ".join(call["args"] or [])


async def test_empty_env_is_passed_as_none(monkeypatch):
    _install_fake_microsandbox(monkeypatch)

    await _backend().execute(SandboxExecutionRequest(command="echo", args=["hi"]))

    assert _exec()["env"] is None


async def test_stdin_is_forwarded_via_stdin_bytes(monkeypatch):
    _install_fake_microsandbox(monkeypatch)

    await _backend().execute(
        SandboxExecutionRequest(command="cat", args=[], input="hello\nworld")
    )

    call = _exec()
    assert call["stdin"] is not None, "stdin must not be dropped (unlike E2B)"
    assert _Stdin.last == b"hello\nworld"


async def test_cwd_and_timeout_ride_sdk_parameters(monkeypatch, tmp_path):
    _install_fake_microsandbox(monkeypatch)

    await _backend().execute(
        SandboxExecutionRequest(
            command="echo", args=["hi"], cwd=str(tmp_path), timeout_ms=1500
        )
    )

    call = _exec()
    assert call["cwd"] == str(tmp_path)
    assert call["timeout"] == 1.5


async def test_exec_output_maps_to_execution_result(monkeypatch):
    _install_fake_microsandbox(monkeypatch)

    class _Output:
        exit_code = 3
        stdout_text = "out"
        stderr_text = "err"

    async def _exec_out(*a, **k):
        return _Output()

    backend = _backend()
    # First call boots (and caches) the default microVM; the fake returns
    # 0 / "ok" here. We then swap its ``exec`` to prove the output mapping.
    await backend.execute(SandboxExecutionRequest(command="false", args=[]))
    sbx = _RecordingSandbox.last
    sbx.exec = _exec_out
    result = await backend.execute(SandboxExecutionRequest(command="false", args=[]))
    assert result.backend == "microsandbox"
    assert result.exit_code == 3
    assert result.stdout == "out"
    assert result.stderr == "err"


async def test_capabilities_advertise_strong_isolation_and_browser(monkeypatch):
    _install_fake_microsandbox(monkeypatch)

    caps = _backend().capabilities()
    assert caps.kind == "microsandbox"
    assert caps.supports_strong_isolation is True
    assert caps.supports_browser is True
    assert caps.supports_package_install is True


async def test_network_is_disabled_by_default(monkeypatch):
    # The SDK default reaches the public internet; a security-first backend
    # must not inherit that silently. Default is no network, and the capability
    # declaration must say so.
    _install_fake_microsandbox(monkeypatch)
    backend = _backend()

    await backend.execute(SandboxExecutionRequest(command="echo", args=["hi"]))

    assert _FakeSandboxFactory.last_create_kwargs["network"] == "network-none"
    assert backend.capabilities().supports_network is False
    assert "network" not in backend.capabilities().supported_capabilities


async def test_network_can_be_enabled(monkeypatch):
    _install_fake_microsandbox(monkeypatch)
    backend = MicrosandboxSandboxBackend(
        MicrosandboxSandboxBackendOptions(available=True, image="python", network_enabled=True)
    )

    await backend.execute(SandboxExecutionRequest(command="echo", args=["hi"]))

    # Enabled = SDK default egress (public reachable, private/metadata blocked).
    assert "network" not in _FakeSandboxFactory.last_create_kwargs
    assert backend.capabilities().supports_network is True
    assert "network" in backend.capabilities().supported_capabilities


async def test_is_available_is_true_with_sdk_and_image(monkeypatch):
    _install_fake_microsandbox(monkeypatch)

    assert await _backend().is_available() is True


async def test_is_available_is_false_without_a_configured_image(monkeypatch):
    # The image is the isolation envelope; an image-less backend must not
    # advertise itself, or the router would "satisfy" a strong-isolation
    # request and only fail later as an opaque exit_code_1.
    _install_fake_microsandbox(monkeypatch)

    backend = MicrosandboxSandboxBackend(
        MicrosandboxSandboxBackendOptions(available=True)
    )
    assert await backend.is_available() is False


async def test_create_session_disables_network_by_default(monkeypatch):
    _install_fake_microsandbox(monkeypatch)

    await _backend().create_session()

    assert _FakeSandboxFactory.last_create_kwargs["network"] == "network-none"


async def test_session_execute_boots_with_network_disabled(monkeypatch):
    # The session (detached) boot path must carry the same network policy as the
    # session-less default; a session that silently inherited the SDK's
    # public-internet default would break the capability declaration.
    _install_fake_microsandbox(monkeypatch)
    session = SandboxSession(id="sess-1", backend="microsandbox")

    await _backend().execute(
        SandboxExecutionRequest(command="echo", args=["hi"]), session=session
    )

    assert _FakeSandboxFactory.last_create_kwargs["network"] == "network-none"


async def test_snapshot_captures_the_live_session_sandbox(monkeypatch):
    # ``Snapshot.create`` needs a stopped source; the backend snapshots a live
    # session, so it must resolve the handle by name and call the documented
    # live-capture API. The returned id must be the snapshot's reference, never
    # the live sandbox's name.
    _install_fake_microsandbox(monkeypatch)
    backend = _backend()
    session = await backend.create_session()
    sandbox_name = _FakeSandboxFactory.last_create_kwargs["name"]

    snap = await backend.snapshot(session)

    captured_name = _RecordingSandbox.last_snapshot_name
    assert _FakeSandboxFactory.last_get_name == sandbox_name
    assert captured_name.startswith("titanx-snap-")
    assert captured_name != session.id
    assert snap.backend == "microsandbox"
    assert snap.id == f"ref:{captured_name}"


async def test_snapshot_propagates_sdk_failure_instead_of_faking_an_id(monkeypatch):
    # The old implementation swallowed every exception and returned
    # ``session.id`` (the live sandbox name) as if the snapshot succeeded.
    # A later ``resume`` would then boot from a non-snapshot. Fail closed.
    _install_fake_microsandbox(monkeypatch)
    backend = _backend()
    session = await backend.create_session()
    _RecordingSandbox.snapshot_error = RuntimeError("snapshot failed")

    with pytest.raises(RuntimeError, match="snapshot failed"):
        await backend.snapshot(session)


async def test_snapshot_unknown_session_still_raises(monkeypatch):
    _install_fake_microsandbox(monkeypatch)
    session = SandboxSession(id="never-created", backend="microsandbox")

    with pytest.raises(ValueError, match="unknown session"):
        await _backend().snapshot(session)


async def test_snapshot_after_resume_targets_the_restored_sandbox(monkeypatch):
    # A resumed session keeps the snapshot reference as its session id, while
    # the live microVM has a fresh restore name. Snapshotting it must resolve
    # the *name*, not the snapshot id — this is the path the name map exists
    # for, and the only one where the two identifiers differ.
    _install_fake_microsandbox(monkeypatch)
    backend = _backend()
    session = await backend.resume("snap-123")
    restore_name = _FakeSandboxFactory.last_restore_kwargs["name"]

    snap = await backend.snapshot(session)

    assert _FakeSandboxFactory.last_get_name == restore_name
    assert _FakeSandboxFactory.last_get_name != session.id
    assert snap.id == f"ref:{_RecordingSandbox.last_snapshot_name}"


async def test_injected_snapshotter_empty_result_fails_closed(monkeypatch):
    # The injected hook must obey the same fail-closed contract as the SDK
    # path: an empty id is not a snapshot.
    _install_fake_microsandbox(monkeypatch)

    async def _empty_snapshotter(sbx):
        return None

    backend = MicrosandboxSandboxBackend(
        MicrosandboxSandboxBackendOptions(
            available=True, image="python", snapshotter=_empty_snapshotter
        )
    )
    session = await backend.create_session()

    with pytest.raises(RuntimeError, match="no reference"):
        await backend.snapshot(session)


async def test_resuming_an_already_active_snapshot_fails_closed(monkeypatch):
    # Session ids are snapshot references, so a second resume would overwrite
    # the tracked instance and orphan the first microVM.
    _install_fake_microsandbox(monkeypatch)
    backend = _backend()
    await backend.resume("snap-123")

    with pytest.raises(ValueError, match="already resumed"):
        await backend.resume("snap-123")


async def test_resume_restores_from_snapshot_with_network_disabled(monkeypatch):
    # The 0.7.x SDK restores via ``Sandbox.restore(snapshot, name=...,
    # disable_network=...)``; ``Sandbox.create`` has no ``snapshot=`` parameter.
    # The network policy must be re-applied or the restored microVM would
    # inherit the SDK's public-internet default.
    _install_fake_microsandbox(monkeypatch)

    session = await _backend().resume("snap-123")

    call = _FakeSandboxFactory.last_restore_kwargs
    assert call["snapshot"] == "snap-123"
    assert call["name"] != "snap-123"
    assert call["disable_network"] is True
    assert _FakeSandboxFactory.last_create_kwargs is None
    assert session.id == "snap-123"


async def test_resume_enables_network_when_configured(monkeypatch):
    _install_fake_microsandbox(monkeypatch)
    backend = MicrosandboxSandboxBackend(
        MicrosandboxSandboxBackendOptions(
            available=True, image="python", network_enabled=True
        )
    )

    await backend.resume("snap-123")

    assert _FakeSandboxFactory.last_restore_kwargs["disable_network"] is False


async def test_is_available_follows_the_host_probe(monkeypatch):
    # An installed SDK and a configured image are not enough: on a host with no
    # hypervisor the router would select the strong-isolation tier and only
    # fail later as an opaque execution error. Availability must fail closed.
    _install_fake_microsandbox(monkeypatch)
    backend = _backend()

    # macOS: Apple Silicon only.
    monkeypatch.setattr(microsandbox_backend.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(microsandbox_backend.platform, "machine", lambda: "x86_64")
    assert await backend.is_available() is False
    monkeypatch.setattr(microsandbox_backend.platform, "machine", lambda: "arm64")
    assert await backend.is_available() is True

    # Linux: both /dev/kvm access flags required.
    monkeypatch.setattr(microsandbox_backend.platform, "system", lambda: "Linux")
    probes: list[tuple[str, int]] = []

    def access(path, mode):
        probes.append((path, mode))
        return access.allowed

    access.allowed = False
    monkeypatch.setattr(microsandbox_backend.os, "access", access)
    assert await backend.is_available() is False
    access.allowed = True
    assert await backend.is_available() is True
    assert ("/dev/kvm", os.R_OK | os.W_OK) in probes

    # Anything else fails closed.
    monkeypatch.setattr(microsandbox_backend.platform, "system", lambda: "Windows")
    assert await backend.is_available() is False


async def test_is_available_is_false_without_the_sdk(monkeypatch):
    # The last fail-closed branch: a supported host with an image still cannot
    # run when the package is missing.
    _install_fake_microsandbox(monkeypatch)
    monkeypatch.setitem(sys.modules, "microsandbox", None)

    assert await _backend().is_available() is False


async def test_concurrent_session_execute_boots_only_one_microvm(monkeypatch):
    # Both callers miss the cache together; without a creation lock each boots
    # a detached microVM and the loser is orphaned (no handle, never stopped).
    _install_fake_microsandbox(monkeypatch)
    backend = _backend()
    session = SandboxSession(id="sess-1", backend="microsandbox")

    results = await asyncio.gather(
        backend.execute(
            SandboxExecutionRequest(command="echo", args=["a"]), session=session
        ),
        backend.execute(
            SandboxExecutionRequest(command="echo", args=["b"]), session=session
        ),
    )

    assert _FakeSandboxFactory.create_calls == 1
    assert [r.exit_code for r in results] == [0, 0]
    assert len(_RecordingSandbox.last.execs) == 2


async def test_first_boot_of_one_session_does_not_block_another(monkeypatch):
    # The double-boot guard is per session id. Booting is slow (image pull), so
    # one tenant's cold start must not serialize every other session's first
    # execute.
    _install_fake_microsandbox(monkeypatch)
    started, gate = asyncio.Event(), asyncio.Event()
    _FakeSandboxFactory.create_started = started
    _FakeSandboxFactory.create_gate = gate
    backend = _backend()

    first = asyncio.create_task(
        backend.execute(
            SandboxExecutionRequest(command="echo", args=["a"]),
            session=SandboxSession(id="sess-a", backend="microsandbox"),
        )
    )
    await asyncio.wait_for(started.wait(), timeout=1)
    second = asyncio.create_task(
        backend.execute(
            SandboxExecutionRequest(command="echo", args=["b"]),
            session=SandboxSession(id="sess-b", backend="microsandbox"),
        )
    )
    try:
        await asyncio.sleep(0.05)
        assert _FakeSandboxFactory.create_calls == 2
    finally:
        gate.set()

    results = await asyncio.wait_for(
        asyncio.gather(first, second), timeout=1
    )
    assert [r.exit_code for r in results] == [0, 0]


async def test_execute_waits_for_an_in_flight_resume(monkeypatch):
    # An execute carrying the snapshot id as its session id can arrive while
    # the restore is still running. Booting a new microVM here would be
    # overwritten by the resume and leak (no handle, never stopped), so the
    # execute must wait for the restore and use the restored sandbox.
    _install_fake_microsandbox(monkeypatch)
    started, gate = asyncio.Event(), asyncio.Event()
    _FakeSandboxFactory.restore_started = started
    _FakeSandboxFactory.restore_gate = gate
    backend = _backend()

    resume = asyncio.create_task(backend.resume("snap-123"))
    await asyncio.wait_for(started.wait(), timeout=1)
    execute = asyncio.create_task(
        backend.execute(
            SandboxExecutionRequest(command="echo", args=["hi"]),
            session=SandboxSession(id="snap-123", backend="microsandbox"),
        )
    )
    try:
        await asyncio.sleep(0.05)
        assert _FakeSandboxFactory.create_calls == 0
        assert not execute.done()
    finally:
        gate.set()

    session = await asyncio.wait_for(resume, timeout=1)
    result = await asyncio.wait_for(execute, timeout=1)
    assert session.id == "snap-123"
    assert result.exit_code == 0
    assert _FakeSandboxFactory.create_calls == 0
