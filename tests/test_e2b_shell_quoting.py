"""E2B backend must pass the workload as data, not as shell code.

E2B's ``sandbox.commands.run(cmd)`` executes its argument through a shell
(the installed SDK sends ``cmd="/bin/bash", args=["-l", "-c", cmd]``). The
workload's ``command``/``args`` come from the model's tool call — text an
attacker can steer via prompt injection — so they must be shell-quoted
before being concatenated, exactly as the Docker backend
(``_build_shell_command`` → ``shlex.quote``) and the background runner do.

The Docker backend already quotes; E2B did not, so a ``;``/``$()``/backtick
in an argument was interpreted as a second command. These tests run the
exact string the backend hands to E2B through a real shell (the same
semantics E2B applies) and assert an injected side effect never happens —
a differential check that does not assume any particular quoting function,
covering the whole metacharacter class rather than just ``;``.
"""

from __future__ import annotations

import subprocess
import sys
import types

import pytest

from titanx.sandbox.backends.e2b import E2BSandboxBackend, E2BSandboxBackendOptions
from titanx.sandbox.types import SandboxExecutionRequest

# Each payload runs ``touch SENTINEL`` only if the raw text reaches the
# shell unquoted. ``SENTINEL`` is swapped for a tmp_path sentinel at runtime.
_INJECTIONS = {
    "semicolon": "safe; touch SENTINEL",
    "and": "safe && touch SENTINEL",
    "pipe": "safe | touch SENTINEL",
    "cmdsubst": "$(touch SENTINEL)",
    "backtick": "`touch SENTINEL`",
    "newline": "safe\ntouch SENTINEL",
}


class _RecordingCommands:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    async def run(self, cmd: str, *, timeout: float = 60, cwd: str | None = None):
        self.calls.append((cmd, cwd))
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


def _executed_cmd() -> str:
    assert _FakeSandbox.last is not None, "e2b Sandbox.create was never called"
    assert _FakeSandbox.last.commands.calls, "commands.run was never called"
    return _FakeSandbox.last.commands.calls[-1][0]


def _assert_payload_is_inert(cmd: str, sentinel) -> None:
    """Run the built command through a real shell; the injection must not fire."""
    real = cmd.replace("SENTINEL", str(sentinel))
    assert not sentinel.exists()
    subprocess.run(["sh", "-c", real], capture_output=True, text=True)
    assert not sentinel.exists(), f"payload was interpreted as shell code: {real!r}"


@pytest.mark.parametrize("payload", _INJECTIONS.values(), ids=_INJECTIONS.keys())
async def test_metacharacters_in_args_are_not_executed(tmp_path, monkeypatch, payload):
    _install_fake_e2b(monkeypatch)

    result = await _backend().execute(
        SandboxExecutionRequest(command="echo", args=[payload])
    )
    assert result.exit_code == 0

    _assert_payload_is_inert(_executed_cmd(), tmp_path / "pwned")


@pytest.mark.parametrize("payload", _INJECTIONS.values(), ids=_INJECTIONS.keys())
async def test_metacharacters_in_command_are_not_executed(tmp_path, monkeypatch, payload):
    _install_fake_e2b(monkeypatch)

    result = await _backend().execute(
        SandboxExecutionRequest(command=payload, args=[])
    )
    assert result.exit_code == 0

    _assert_payload_is_inert(_executed_cmd(), tmp_path / "pwned")


async def test_benign_command_is_passed_through_unchanged(monkeypatch):
    _install_fake_e2b(monkeypatch)

    await _backend().execute(SandboxExecutionRequest(command="echo", args=["hi"]))

    cmd, cwd = _FakeSandbox.last.commands.calls[-1]
    assert cmd == "echo hi"
    assert cwd is None
    assert subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout == "hi\n"


async def test_cwd_is_handed_to_the_sdk_not_shell_interpolated(tmp_path, monkeypatch):
    _install_fake_e2b(monkeypatch)

    await _backend().execute(
        SandboxExecutionRequest(command="echo", args=["hi"], cwd=str(tmp_path))
    )

    cmd, cwd = _FakeSandbox.last.commands.calls[-1]
    assert cwd == str(tmp_path)
    # cwd must ride the SDK's own parameter, never be concatenated into `<cmd>`.
    assert cmd == "echo hi"
