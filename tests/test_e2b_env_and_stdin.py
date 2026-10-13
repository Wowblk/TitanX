"""E2B must forward env out-of-band and never silently drop stdin.

Two gaps in the E2B backend, both the same class as the OpenClaw
``PATH``-injection bug (data treated as code / data silently lost):

1. ``request.env`` was *dropped* entirely. The fix is to forward it through
   the SDK's own ``envs=`` parameter — the out-of-band channel — so an env
   value containing ``;`` / ``$()`` is passed as data and can never become a
   second command. It must NOT be concatenated into the command string.

2. ``request.input`` (stdin) was dropped too. The E2B SDK exposes only
   ``send_stdin(pid, data)`` — there is no way to close stdin / signal EOF —
   so a workload that reads to EOF would hang. Dropping it silently makes the
   caller believe stdin was honoured. The backend must fail *loudly* instead.

The fake records what the backend hands the SDK, which is the seam: we assert
on the ``envs`` argument and on the absence of the env value inside ``cmd``,
not on any particular internal helper.
"""

from __future__ import annotations

import sys
import types

from titanx.sandbox.backends.e2b import E2BSandboxBackend, E2BSandboxBackendOptions
from titanx.sandbox.types import SandboxExecutionRequest


class _RecordingCommands:
    def __init__(self) -> None:
        # (cmd, cwd, envs)
        self.calls: list[tuple[str, str | None, dict[str, str] | None]] = []

    async def run(
        self,
        cmd: str,
        *,
        timeout: float = 60,
        cwd: str | None = None,
        envs: dict[str, str] | None = None,
    ):
        self.calls.append((cmd, cwd, envs))
        return types.SimpleNamespace(exit_code=0, stdout="ok", stderr="")


class _FakeSandbox:
    """Stand-in for ``e2b.Sandbox`` recording what would be executed."""

    last: _FakeSandbox | None = None

    def __init__(self) -> None:
        self.commands = _RecordingCommands()

    @classmethod
    async def create(cls, **kwargs) -> _FakeSandbox:
        cls.last = cls()
        return cls.last


def _install_fake_e2b(monkeypatch) -> None:
    module = types.ModuleType("e2b")
    module.Sandbox = _FakeSandbox  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "e2b", module)
    _FakeSandbox.last = None


def _backend() -> E2BSandboxBackend:
    return E2BSandboxBackend(E2BSandboxBackendOptions(available=True))


async def test_env_rides_the_sdk_param_not_the_command_string(monkeypatch):
    _install_fake_e2b(monkeypatch)
    env = {
        "PATH": "/opt/bin:/usr/bin",
        # A value that must stay data: if it were interpolated into the
        # command string it would be a second command.
        "GREETING": "hi; touch /tmp/pwned",
    }

    await _backend().execute(
        SandboxExecutionRequest(command="echo", args=["hi"], env=env)
    )

    cmd, _cwd, envs = _FakeSandbox.last.commands.calls[-1]
    assert envs == env, "env must be forwarded through the SDK's envs= parameter"
    # The env value must never appear in the shell string.
    assert "pwned" not in cmd
    assert "PATH" not in cmd
    assert cmd == "echo hi"


async def test_empty_env_is_passed_as_none_not_an_empty_mapping(monkeypatch):
    _install_fake_e2b(monkeypatch)

    await _backend().execute(SandboxExecutionRequest(command="echo", args=["hi"]))

    _cmd, _cwd, envs = _FakeSandbox.last.commands.calls[-1]
    assert envs is None


async def test_input_set_fails_loudly_and_never_runs_the_command(monkeypatch):
    _install_fake_e2b(monkeypatch)

    result = await _backend().execute(
        SandboxExecutionRequest(command="cat", args=[], input="hello\n")
    )

    assert result.exit_code != 0, "a dropped stdin must surface as a failure"
    assert "stdin" in result.stderr.lower()
    # The remote command must not run at all: it would hang or mislead.
    assert _FakeSandbox.last is None or not _FakeSandbox.last.commands.calls
