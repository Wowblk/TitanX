from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
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
class DockerSandboxBackendOptions:
    available: bool = True
    docker_bin: str = "docker"
    image: str = "alpine:latest"
    network: str = "none"
    executor: Callable | None = None
    file_writer: Callable | None = None
    file_reader: Callable | None = None
    snapshot_creator: Callable | None = None
    snapshot_resumer: Callable | None = None


async def _run_process(cmd: list[str], input_data: str | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if input_data else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdin_bytes = input_data.encode() if input_data else None
    stdout, stderr = await proc.communicate(input=stdin_bytes)
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _quote(value: str) -> str:
    return shlex.quote(value)


def _build_shell_command(request: SandboxExecutionRequest) -> str:
    parts = []
    if request.cwd:
        parts.append(f"cd {_quote(request.cwd)}")
    argv = " ".join(_quote(a) for a in [request.command, *request.args])
    parts.append(argv)
    return " && ".join(parts)


class DockerSandboxBackend(SandboxBackend):
    kind = "docker"

    def __init__(self, options: DockerSandboxBackendOptions | None = None) -> None:
        self._opts = options or DockerSandboxBackendOptions()

    def capabilities(self) -> SandboxBackendCapabilities:
        return SandboxBackendCapabilities(
            kind="docker",
            supports_persistence=True,
            supports_snapshots=True,
            supports_browser=False,
            supports_network=True,
            supports_package_install=True,
            supported_capabilities=["command-exec", "filesystem", "network", "snapshot", "resume"],
        )

    async def is_available(self) -> bool:
        if not self._opts.available:
            return False
        try:
            rc, _, _ = await _run_process([self._opts.docker_bin, "info"])
            return rc == 0
        except Exception:
            return False

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
                    backend="docker",
                    exit_code=res.get("exit_code", 0),
                    stdout=res.get("stdout", ""),
                    stderr=res.get("stderr", ""),
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

            shell_cmd = _build_shell_command(request)
            env_flags: list[str] = []
            for k, v in request.env.items():
                env_flags += ["-e", f"{k}={v}"]

            timeout_s = (request.timeout_ms / 1000) if request.timeout_ms else None

            if session:
                cmd = [
                    self._opts.docker_bin, "exec",
                    *env_flags,
                    session.id,
                    "sh", "-c", shell_cmd,
                ]
            else:
                cmd = [
                    self._opts.docker_bin, "run", "--rm",
                    f"--network={self._opts.network}",
                    *env_flags,
                    self._opts.image,
                    "sh", "-c", shell_cmd,
                ]

            if timeout_s:
                rc, stdout, stderr = await asyncio.wait_for(
                    _run_process(cmd, request.input), timeout=timeout_s
                )
            else:
                rc, stdout, stderr = await _run_process(cmd, request.input)

            return SandboxExecutionResult(
                backend="docker",
                exit_code=rc,
                stdout=stdout,
                stderr=stderr,
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except asyncio.TimeoutError:
            return SandboxExecutionResult(
                backend="docker", exit_code=124, stdout="", stderr="timeout",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as exc:
            return SandboxExecutionResult(
                backend="docker", exit_code=1, stdout="", stderr=str(exc),
                duration_ms=(time.perf_counter() - start) * 1000,
            )

    async def create_session(self, metadata: dict[str, str] | None = None) -> SandboxSession:
        container_name = f"titanx-{uuid4().hex[:12]}"
        cmd = [
            self._opts.docker_bin, "run", "-d", "--name", container_name,
            f"--network={self._opts.network}",
            self._opts.image,
            "sh", "-c", "tail -f /dev/null",
        ]
        rc, stdout, stderr = await _run_process(cmd)
        if rc != 0:
            raise RuntimeError(f"Failed to start Docker container: {stderr}")
        container_id = stdout.strip()
        return SandboxSession(id=container_id, backend="docker", metadata=metadata or {})

    async def destroy_session(self, session_id: str) -> None:
        await _run_process([self._opts.docker_bin, "rm", "-f", session_id])

    async def write_files(
        self, files: list[SandboxFileEntry], session: SandboxSession | None = None
    ) -> None:
        if self._opts.file_writer:
            await self._opts.file_writer(files, session)
            return
        if not session:
            raise ValueError("write_files requires a session for Docker backend")
        for f in files:
            escaped = f.content.replace("'", "'\\''")
            cmd = [
                self._opts.docker_bin, "exec", session.id,
                "sh", "-c", f"mkdir -p $(dirname '{f.path}') && printf '%s' '{escaped}' > '{f.path}'",
            ]
            await _run_process(cmd)

    async def read_file(self, path: str, session: SandboxSession | None = None) -> str:
        if self._opts.file_reader:
            return await self._opts.file_reader(path, session)
        if not session:
            raise ValueError("read_file requires a session for Docker backend")
        rc, stdout, stderr = await _run_process(
            [self._opts.docker_bin, "exec", session.id, "cat", path]
        )
        if rc != 0:
            raise RuntimeError(f"Failed to read '{path}': {stderr}")
        return stdout

    async def snapshot(self, session: SandboxSession) -> SandboxSnapshot:
        if self._opts.snapshot_creator:
            return await self._opts.snapshot_creator(session)
        image_tag = f"titanx-snap-{uuid4().hex[:12]}"
        rc, _, stderr = await _run_process(
            [self._opts.docker_bin, "commit", session.id, image_tag]
        )
        if rc != 0:
            raise RuntimeError(f"Docker commit failed: {stderr}")
        return SandboxSnapshot(
            id=image_tag,
            created_at=datetime.now(timezone.utc).isoformat(),
            backend="docker",
        )

    async def resume(self, snapshot_id: str) -> SandboxSession:
        if self._opts.snapshot_resumer:
            return await self._opts.snapshot_resumer(snapshot_id)
        container_name = f"titanx-resume-{uuid4().hex[:12]}"
        cmd = [
            self._opts.docker_bin, "run", "-d", "--name", container_name,
            f"--network={self._opts.network}",
            snapshot_id,
            "sh", "-c", "tail -f /dev/null",
        ]
        rc, stdout, stderr = await _run_process(cmd)
        if rc != 0:
            raise RuntimeError(f"Failed to resume snapshot '{snapshot_id}': {stderr}")
        return SandboxSession(id=stdout.strip(), backend="docker")
