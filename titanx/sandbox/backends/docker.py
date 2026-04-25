from __future__ import annotations

import asyncio
import re
import shlex
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable
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


class ImageDigestMismatch(RuntimeError):
    """Raised when the resolved Docker image digest does not match the pin.

    Subclasses ``RuntimeError`` so existing ``except RuntimeError`` paths
    in callers keep working, but distinct enough that auditors can
    ``except ImageDigestMismatch`` to surface a tighter error to the
    LLM (and so the audit log can categorise the event).
    """

    def __init__(self, *, image: str, expected: str, actual: str | None) -> None:
        self.image = image
        self.expected = expected
        self.actual = actual
        actual_str = actual if actual else "<unresolved>"
        super().__init__(
            f"Docker image {image!r} digest mismatch: expected {expected!r}, "
            f"resolved {actual_str!r}"
        )


# Pattern for an OCI digest reference embedded in an image string, e.g.
# ``ghcr.io/foo/bar@sha256:abc...``. Captures the ``algo:hex`` portion.
_IMAGE_DIGEST_IN_REF_RE = re.compile(r"@([a-z0-9]+(?:[+._-][a-z0-9]+)*:[a-fA-F0-9]{32,})$")

DigestResolver = Callable[[str, str], "Awaitable[str | None]"]
"""Async callable ``(docker_bin, image) -> digest | None``.

Test harnesses replace this to avoid spawning a real ``docker inspect``.
"""


@dataclass
class DockerSandboxBackendOptions:
    available: bool = True
    docker_bin: str = "docker"
    image: str = "alpine:latest"
    network: str = "none"
    # Kernel-enforced filesystem hardening. When ``read_only_root`` is on,
    # the container's root filesystem is mounted read-only and only the paths
    # listed in ``SandboxExecutionRequest.allowed_write_paths`` are
    # bind-mounted writable. ``tmpfs_paths`` are always mounted as tmpfs so
    # programs that legitimately need scratch space (compiler temp dirs,
    # /var/tmp, etc.) don't break. This is the *real* write-path boundary —
    # the host-side ``path_guard`` is only an early-fail filter.
    read_only_root: bool = True
    tmpfs_paths: tuple[str, ...] = ("/tmp",)
    # Optional belt-and-braces digest pin. When set, the backend resolves
    # ``image`` via ``docker inspect`` (or the injected ``digest_resolver``)
    # before launch and refuses on mismatch. Setting ``image`` to a
    # ``repo@sha256:...`` reference is the OCI-native way to pin and is
    # already enforced by Docker itself; this field exists so operators
    # who use a tag-based reference get an explicit verification step,
    # mirroring NemoClaw blueprint's ``digest:`` lockstep field.
    expected_image_digest: str | None = None
    # Async hook for resolving the digest of ``image``. Defaults to
    # ``docker inspect``; tests pass a stub.
    digest_resolver: DigestResolver | None = None
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


def _filesystem_flags(
    *,
    read_only_root: bool,
    tmpfs_paths: tuple[str, ...],
    allowed_write_paths: list[str] | None,
    allowed_read_paths: list[str] | None = None,
) -> list[str]:
    """Build the docker flags that enforce the read/write boundary.

    When ``read_only_root`` is enabled, the root filesystem is mounted RO
    (kernel-enforced). ``tmpfs_paths`` are mounted as ephemeral tmpfs so
    writes to /tmp etc. still work without leaking out of the container.
    Each entry in ``allowed_write_paths`` is bind-mounted RW under the
    same path inside the container, so writes outside this set fail with
    EROFS no matter what shell trick the workload uses.

    Each entry in ``allowed_read_paths`` is bind-mounted ``:ro`` so the
    workload can read from a host path without being able to write back.
    NemoClaw's filesystem_policy makes the same split; we now match it.

    Defense in depth: ``validate_write_path`` is re-run on every entry
    here, even though ``PolicyStore.set`` already validates. The
    ``SandboxExecutionRequest`` is mutable and could be constructed
    directly by a future backend, a test harness, or a rogue caller that
    skips the policy plane entirely. The kernel boundary deserves its
    own gate. ``PolicyValidationError`` propagates up so the caller sees
    *why* the request was rejected; the resilient backend wrapper then
    reports the failure as a non-retryable error.
    """
    from ...policy.validation import validate_write_path

    flags: list[str] = []
    if not read_only_root:
        # Caller explicitly opted out — skip all hardening.
        return flags

    flags.append("--read-only")
    for tmp in tmpfs_paths:
        flags.extend(["--tmpfs", tmp])
    write_set = set(allowed_write_paths or [])
    for host_path in allowed_write_paths or []:
        validate_write_path(host_path)
        flags.extend(["-v", f"{host_path}:{host_path}:rw"])
    for host_path in allowed_read_paths or []:
        validate_write_path(host_path)
        # An entry that is also in the write list would shadow the RO
        # mount — Docker accepts both but only the *last* mount sticks,
        # which is implementation-defined and would produce a confusing
        # security posture. Drop duplicate read entries silently; the
        # write entry wins. The audit module flags this overlap.
        if host_path in write_set:
            continue
        flags.extend(["-v", f"{host_path}:{host_path}:ro"])
    return flags


async def _docker_inspect_digest(docker_bin: str, image: str) -> str | None:
    """Default digest resolver: ``docker inspect`` the image.

    Returns the resolved repo digest (e.g. ``sha256:b3d8...``) when
    Docker reports one, otherwise None. Network errors and missing
    images both surface as None — the caller treats None as "could not
    verify" and refuses, so the failure is fail-closed.
    """
    cmd = [
        docker_bin, "inspect",
        "--format", "{{range .RepoDigests}}{{println .}}{{end}}{{.Id}}",
        image,
    ]
    try:
        rc, stdout, _ = await _run_process(cmd)
    except Exception:
        return None
    if rc != 0 or not stdout.strip():
        return None
    # ``RepoDigests`` is the canonical OCI digest list (e.g.
    # ``ghcr.io/foo/bar@sha256:abc...``); ``.Id`` is the local content
    # hash. Prefer the first repo digest, fall back to .Id.
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Repo digest form: "name@sha256:...".
        if "@" in line:
            return line.rsplit("@", 1)[1]
        # Bare image-id form (already "sha256:...").
        if ":" in line:
            return line
    return None


class DockerSandboxBackend(SandboxBackend):
    kind = "docker"

    def __init__(self, options: DockerSandboxBackendOptions | None = None) -> None:
        self._opts = options or DockerSandboxBackendOptions()

    def _expected_digest(self, request_pin: str | None) -> str | None:
        """Determine the digest the image MUST resolve to, if any.

        Three sources are honoured, with this precedence:

        1. ``request_pin`` (per-call, set by ``SandboxedToolRuntime``
           from the live ``AgentPolicy.image_digest``).
        2. ``options.expected_image_digest`` (deployment-level pin).
        3. The digest embedded in ``options.image`` itself, e.g.
           ``ghcr.io/foo/bar@sha256:abc...``.

        Returning ``None`` means "no pin was requested by anyone";
        the verifier short-circuits and lets the launch proceed.
        """
        if request_pin:
            return request_pin
        if self._opts.expected_image_digest:
            return self._opts.expected_image_digest
        m = _IMAGE_DIGEST_IN_REF_RE.search(self._opts.image)
        if m:
            return m.group(1)
        return None

    async def _verify_image_digest(self, request_pin: str | None) -> None:
        """Refuse to proceed unless the image digest matches the pin.

        When ``options.image`` already contains an ``@sha256:...`` ref
        and *no other* pin is supplied, Docker's own resolver enforces
        the match and we skip the inspect call. When an explicit pin is
        supplied (per-request or per-deployment) we always inspect, so
        a tag-based image whose backing digest changed under us is
        caught here.
        """
        expected = self._expected_digest(request_pin)
        if not expected:
            return

        # If the only source is the inline ``image`` ref and there's no
        # explicit override, Docker itself enforces the match. Skip the
        # extra round-trip.
        inline_match = _IMAGE_DIGEST_IN_REF_RE.search(self._opts.image)
        if (
            request_pin is None
            and self._opts.expected_image_digest is None
            and inline_match
        ):
            return

        resolver = self._opts.digest_resolver or _docker_inspect_digest
        actual = await resolver(self._opts.docker_bin, self._opts.image)
        if actual != expected:
            raise ImageDigestMismatch(
                image=self._opts.image,
                expected=expected,
                actual=actual,
            )

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
            # Digest verification runs before any user-controllable code
            # path. ``ImageDigestMismatch`` propagates so the resilient
            # backend wrapper sees a non-retryable error and reports it
            # as a hard failure rather than burning retry budget.
            if not session:
                await self._verify_image_digest(request.image_digest)

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
                # Sessions inherit the mount layout fixed at create_session
                # time; per-call write-path changes don't re-mount. Document
                # this caveat for callers that mutate AgentPolicy mid-session.
                cmd = [
                    self._opts.docker_bin, "exec",
                    *env_flags,
                    session.id,
                    "sh", "-c", shell_cmd,
                ]
            else:
                fs_flags = _filesystem_flags(
                    read_only_root=self._opts.read_only_root,
                    tmpfs_paths=self._opts.tmpfs_paths,
                    allowed_write_paths=request.allowed_write_paths,
                    allowed_read_paths=request.allowed_read_paths,
                )
                cmd = [
                    self._opts.docker_bin, "run", "--rm",
                    f"--network={self._opts.network}",
                    *fs_flags,
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

    async def create_session(
        self,
        metadata: dict[str, str] | None = None,
        *,
        allowed_write_paths: list[str] | None = None,
        allowed_read_paths: list[str] | None = None,
        image_digest: str | None = None,
    ) -> SandboxSession:
        # Digest verification runs before the long-lived container is
        # created. A session that survives a registry compromise would
        # be the worst possible outcome — every subsequent ``execute``
        # silently lands on the swapped image.
        await self._verify_image_digest(image_digest)

        container_name = f"titanx-{uuid4().hex[:12]}"
        # Sessions are long-lived — bake the write-path boundary into the
        # mount layout at creation time. Mutations to AgentPolicy after the
        # session is up will not affect this session; destroy + recreate is
        # required to pick up new paths.
        fs_flags = _filesystem_flags(
            read_only_root=self._opts.read_only_root,
            tmpfs_paths=self._opts.tmpfs_paths,
            allowed_write_paths=allowed_write_paths,
            allowed_read_paths=allowed_read_paths,
        )
        cmd = [
            self._opts.docker_bin, "run", "-d", "--name", container_name,
            f"--network={self._opts.network}",
            *fs_flags,
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
