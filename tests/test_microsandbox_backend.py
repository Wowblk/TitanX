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
needed to run these.
"""

from __future__ import annotations

import sys
import types

from titanx.sandbox.backends.microsandbox import (
    MicrosandboxSandboxBackend,
    MicrosandboxSandboxBackendOptions,
)
from titanx.sandbox.types import SandboxExecutionRequest


class _RecordingSandbox:
    """Stand-in for a running ``microsandbox.Sandbox``."""

    last: "_RecordingSandbox | None" = None

    def __init__(self) -> None:
        self.execs: list[dict] = []
        self.stopped = False

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

    @staticmethod
    async def create(**kwargs) -> _RecordingSandbox:
        _FakeSandboxFactory.last_create_kwargs = kwargs
        _RecordingSandbox.last = _RecordingSandbox()
        return _RecordingSandbox.last


class _Stdin:
    last: object = None

    @staticmethod
    def bytes(data) -> tuple[str, object]:
        _Stdin.last = data
        return ("stdin-bytes", data)


def _install_fake_microsandbox(monkeypatch) -> None:
    module = types.ModuleType("microsandbox")
    module.Sandbox = _FakeSandboxFactory  # type: ignore[attr-defined]
    module.Stdin = _Stdin  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "microsandbox", module)
    _RecordingSandbox.last = None
    _Stdin.last = None
    _FakeSandboxFactory.last_create_kwargs = None


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
    assert caps.supports_network is True
    assert caps.supports_package_install is True


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
