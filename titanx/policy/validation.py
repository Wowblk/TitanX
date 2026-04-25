"""Static validation for ``AgentPolicy`` instances.

The PolicyStore historically swallowed any ``AgentPolicy`` the host fed it
and propagated the values straight to the Docker bind-mount layer
(``-v {host_path}:{host_path}:rw``). With zero validation that path
allowed full container escape via ``["/"]``,
``["/var/run/docker.sock"]``, ``["/proc"]``, etc. — every classic Docker
breakout cheat in one shot. This module is the **single source of truth**
for what counts as a valid policy.

Invariants enforced here are the *kernel-impactful* ones; semantic checks
that depend on runtime state (e.g. "denied tool actually exists in the
registry") deliberately live elsewhere. The principle: validation here
must be safe to run with no I/O, no network, and no agent state.

Defense in depth: ``DockerSandboxBackend._filesystem_flags`` re-runs the
path validator before assembling Docker flags, so even a rogue caller
that bypasses ``PolicyStore.set`` (e.g. constructs
``SandboxExecutionRequest`` directly in a test or a future backend) gets
fail-closed at the kernel boundary too.
"""

from __future__ import annotations

import os

from .types import AgentPolicy


class PolicyValidationError(ValueError):
    """Raised when an ``AgentPolicy`` violates a kernel-impactful invariant.

    Subclassing ``ValueError`` keeps the existing ``except ValueError``
    handlers in callers working; the dedicated type lets observability /
    audit pipelines distinguish policy-rejected events from incidental
    ``ValueError``s elsewhere.
    """


# Exact paths that are NEVER allowed as bind-mount targets. Each entry is
# either a kernel/system control surface (``/proc``, ``/sys``, ``/dev``)
# or a privileged config / state directory whose write access yields host
# root or container escape (``/etc``, ``/var/run`` containing
# docker.sock, ``/root`` for SSH keys, ``/var/lib`` for other daemons'
# state including ``/var/lib/docker`` itself).
_FORBIDDEN_EXACT: frozenset[str] = frozenset({
    "/",
    "/etc", "/proc", "/sys", "/dev",
    "/boot", "/root",
    "/usr", "/lib", "/lib64", "/sbin", "/bin",
    "/var/run", "/var/lib", "/var/lib/docker",
    "/run",
})

# Path prefixes whose subtrees are also forbidden. Trailing slash is
# significant — ``/etc/`` blocks ``/etc/passwd`` but not a hypothetical
# top-level ``/etcaeon`` directory. Sub-paths of ``/var/lib/docker``
# (other containers' state) and ``/root/`` (SSH/keys/history) are
# blocked specifically because the parent directories are also blocked
# above; the prefix entry handles symlink/typosquat variants.
_FORBIDDEN_PREFIXES: tuple[str, ...] = (
    "/etc/", "/proc/", "/sys/", "/dev/", "/boot/",
    "/usr/", "/lib/", "/lib64/", "/sbin/", "/bin/",
    "/root/", "/var/run/", "/var/lib/", "/run/",
)

# Maximum sane iteration count. The runtime treats ``max_iterations``
# as a hard ceiling on agent-loop iterations; values above this would
# indicate either a misconfigured cap or an attempt to wedge the
# runtime into an effectively-unbounded loop. 10k is generous for any
# legitimate workflow and well below memory exhaustion territory.
_MAX_ITERATIONS_CEILING = 10_000

# Forbidden characters in path strings. ``:`` corrupts Docker's
# ``-v src:dst:opts`` parser, control characters can do nasty things to
# subprocess argv handling, NUL terminates strings prematurely in C-side
# parsers (Docker is Go but exec(2) is libc).
_FORBIDDEN_PATH_CHARS = (":", "\n", "\r", "\t", "\x00", "\x0b", "\x0c")


def _normalise_path(value: str) -> str:
    """Convention: callers must pass already-normalised absolute paths.

    We refuse to silently normalise on the caller's behalf because the
    audit log otherwise records a different string than what got mounted.
    Forcing the caller to pass the canonical form makes ``before`` and
    ``after`` policy diffs faithful.
    """
    return os.path.normpath(value)


def validate_write_path(value: object) -> None:
    """Public wrapper of the per-path validator.

    Re-exported so the sandbox backend can run a defense-in-depth check
    immediately before assembling Docker bind-mount flags. This way a
    rogue caller that bypasses ``PolicyStore.set`` (constructing
    ``SandboxExecutionRequest`` directly) still hits a fail-closed wall
    at the kernel boundary.
    """
    _validate_write_path(value)


def _validate_write_path(value: object) -> None:
    if not isinstance(value, str):
        raise PolicyValidationError(
            f"allowed_write_paths entries must be str, got "
            f"{type(value).__name__}: {value!r}"
        )
    if not value:
        raise PolicyValidationError(
            "allowed_write_paths entries must be non-empty"
        )
    for ch in _FORBIDDEN_PATH_CHARS:
        if ch in value:
            raise PolicyValidationError(
                f"allowed_write_paths entry contains forbidden character "
                f"{ch!r}: {value!r}"
            )
    if not value.startswith("/"):
        raise PolicyValidationError(
            f"allowed_write_paths entries must be absolute (start with '/'): "
            f"{value!r}"
        )
    if "//" in value:
        # POSIX implementation-defines two leading slashes; some tools
        # (and some Docker versions) treat ``//foo`` differently from
        # ``/foo``. Force callers to spell it canonically. ``normpath``
        # alone does not collapse the leading double-slash on POSIX.
        raise PolicyValidationError(
            f"allowed_write_paths entry must not contain '//': {value!r}"
        )

    norm = _normalise_path(value)
    if norm != value:
        raise PolicyValidationError(
            f"allowed_write_paths entry must be already-normalised: "
            f"{value!r} normalises to {norm!r}"
        )

    if norm in _FORBIDDEN_EXACT:
        raise PolicyValidationError(
            f"allowed_write_paths entry {norm!r} targets a privileged system "
            f"path (would enable container escape or host privilege "
            f"escalation)"
        )
    for prefix in _FORBIDDEN_PREFIXES:
        if norm.startswith(prefix):
            raise PolicyValidationError(
                f"allowed_write_paths entry {norm!r} is under a privileged "
                f"system subtree ({prefix!r})"
            )


def _validate_tool_denylist(values: object) -> None:
    if not isinstance(values, list):
        raise PolicyValidationError(
            f"tool_denylist must be a list of str, got {type(values).__name__}"
        )
    for entry in values:
        if not isinstance(entry, str):
            raise PolicyValidationError(
                f"tool_denylist entries must be str, got "
                f"{type(entry).__name__}: {entry!r}"
            )
        if not entry:
            raise PolicyValidationError("tool_denylist entries must be non-empty")


def _validate_max_iterations(value: object) -> None:
    # bool is an int subclass, but ``max_iterations=True`` (== 1) is
    # almost certainly a bug rather than intent. Reject explicitly.
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyValidationError(
            f"max_iterations must be int, got {type(value).__name__}: {value!r}"
        )
    if value < 1:
        raise PolicyValidationError(
            f"max_iterations must be >= 1, got {value}"
        )
    if value > _MAX_ITERATIONS_CEILING:
        raise PolicyValidationError(
            f"max_iterations exceeds ceiling {_MAX_ITERATIONS_CEILING}: {value}"
        )


def validate_policy(policy: object) -> None:
    """Raise ``PolicyValidationError`` if ``policy`` is unsafe to install.

    Callers can use this directly for pre-flight checks before passing a
    policy to ``PolicyStore.set``. The store itself runs this validator
    on every mutation path (``__init__``, ``set``, ``rollback``) so
    bypass via constructor or stored snapshot is impossible.
    """
    if not isinstance(policy, AgentPolicy):
        raise PolicyValidationError(
            f"expected AgentPolicy, got {type(policy).__name__}"
        )

    if not isinstance(policy.allowed_write_paths, list):
        raise PolicyValidationError(
            f"allowed_write_paths must be a list, got "
            f"{type(policy.allowed_write_paths).__name__}"
        )
    for entry in policy.allowed_write_paths:
        _validate_write_path(entry)

    _validate_tool_denylist(policy.tool_denylist)

    if not isinstance(policy.auto_approve_tools, bool):
        raise PolicyValidationError(
            f"auto_approve_tools must be bool, got "
            f"{type(policy.auto_approve_tools).__name__}"
        )

    _validate_max_iterations(policy.max_iterations)


__all__ = ["PolicyValidationError", "validate_policy", "validate_write_path"]
