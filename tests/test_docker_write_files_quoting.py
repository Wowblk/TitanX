"""Docker ``write_files`` must not let a path become shell code.

``write_files`` builds a ``sh -c`` script that ``mkdir``s the file's parent
and redirects the content into the file. The *content* was escaped by hand,
but ``f.path`` was interpolated into that script raw — both in
``$(dirname '<path>')`` and in ``> '<path>'``. A path containing a single
quote closes the quote, and anything after it (``; touch …``, ``$(…)``,
backticks) is then executed inside the container by the shell.

The test runs the exact script the backend hands to ``docker exec`` through
a real shell and asserts an injected side effect never happens.
"""

from __future__ import annotations

import subprocess

from titanx.sandbox.backends import docker as docker_mod
from titanx.sandbox.types import SandboxFileEntry, SandboxSession


def _capture_exec(monkeypatch) -> list[list[str]]:
    recorded: list[list[str]] = []

    async def _fake_run(cmd, input_data=None):
        recorded.append(cmd)
        return (0, "", "")

    monkeypatch.setattr(docker_mod, "_run_process", _fake_run)
    return recorded


async def test_write_files_path_is_not_shell_interpolated(tmp_path, monkeypatch):
    recorded = _capture_exec(monkeypatch)
    backend = docker_mod.DockerSandboxBackend(docker_mod.DockerSandboxBackendOptions())
    session = SandboxSession(id="c1", backend="docker", metadata={})
    sentinel = tmp_path / "pwned-by-path"

    evil_path = f"{tmp_path}/note'; touch {sentinel}; true '"
    await backend.write_files(
        [SandboxFileEntry(path=evil_path, content="body")], session
    )

    assert recorded, "docker exec was never invoked"
    script = recorded[-1][-1]
    subprocess.run(["sh", "-c", script], capture_output=True, text=True, cwd=tmp_path)
    assert not sentinel.exists(), f"path was interpreted as shell code: {script!r}"


async def test_write_files_benign_path_writes_the_file(tmp_path, monkeypatch):
    recorded = _capture_exec(monkeypatch)
    backend = docker_mod.DockerSandboxBackend(docker_mod.DockerSandboxBackendOptions())
    session = SandboxSession(id="c1", backend="docker", metadata={})

    target = tmp_path / "sub" / "note.txt"
    await backend.write_files(
        [SandboxFileEntry(path=str(target), content="hello; not code")], session
    )

    script = recorded[-1][-1]
    subprocess.run(["sh", "-c", script], capture_output=True, text=True, cwd=tmp_path)
    assert target.read_text() == "hello; not code"
