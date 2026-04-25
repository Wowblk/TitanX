"""Host-side write-path guard.

This module is a *defense-in-depth* layer, **not** the security boundary.
Adversarial shell input can always evade pure userspace string parsing
(``eval``, base64-decoded payloads, ``LD_PRELOAD``, ``/proc/self/mem``,
heredocs, fork bombs that race the check, etc.). The actual enforcement
must live at the sandbox / OS layer:

    * mount the sandbox filesystem read-only;
    * bind-mount **only** the directories listed in
      ``AgentPolicy.allowed_write_paths`` as writable;
    * let the kernel reject every other write at ``open(O_WRONLY)``.

This is implemented in :mod:`titanx.sandbox.backends.docker` — see
``DockerSandboxBackendOptions.read_only_root`` and the ``-v`` mount flags
generated from ``SandboxExecutionRequest.allowed_write_paths``. The flow
is: ``tool_runtime`` reads the policy → fills the request →
``DockerSandboxBackend.execute`` translates it into ``--read-only
--tmpfs … -v /allowed:/allowed:rw`` → the kernel enforces it.

What this module does:

    1. Parse a tool-runtime command (``command`` + ``args`` from the LLM)
       with ``shlex`` instead of a space-join + regex hack so that
       quoting / escaping is handled correctly.
    2. Walk the token stream looking for write targets across a wide set
       of write-capable verbs (``>``, ``>>``, ``tee``, ``cp``, ``mv``,
       ``install``, ``rsync``, ``dd``, ``sed -i``, ``wget -O``,
       ``curl -o``, ``tar -cf``). Relative paths are resolved against
       the supplied sandbox ``cwd``, never the host process cwd.
    3. **Refuse** outright (``refuse_reason``) any command we cannot
       statically reason about — ``bash -c``, ``python -c``, ``eval``,
       command substitution ``$(…)``, backticks, process substitution
       ``<(…)`` / ``>(…)``, env-var expansion ``$X`` / ``${X}``.

The default posture is "fail closed": if the parser is unsure, the
caller (``SandboxedToolRuntime``) is told to drop the command.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable

# ── Public types ──────────────────────────────────────────────────────────


@dataclass
class ShellWriteScan:
    """Outcome of statically scanning a shell command for write targets."""

    targets: list[str] = field(default_factory=list)
    refuse_reason: str | None = None

    @property
    def safe_to_dispatch(self) -> bool:
        return self.refuse_reason is None


# ── Constants ─────────────────────────────────────────────────────────────

# Patterns that indicate the token contains shell features whose final
# write target cannot be determined without actually running the shell.
# Any token matching any of these triggers a hard refuse.
_INDETERMINATE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\$\("),        # command substitution: $(...)
    re.compile(r"`"),           # legacy command substitution: `...`
    re.compile(r"<\("),         # process substitution: <(...)
    re.compile(r">\("),         # process substitution: >(...)
    re.compile(r"\$\{"),        # parameter expansion: ${VAR}
    re.compile(r"\$[A-Za-z_]"), # variable expansion: $VAR
)

_SHELL_INTERPRETERS = {"sh", "bash", "zsh", "ksh", "dash", "ash", "fish"}
_SCRIPT_INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "node", "lua"}
_INLINE_DYNAMIC_VERBS = {"eval", "exec", "source", "."}

# Top-level shell separators — splitting on these gives us per-command segments.
_SEGMENT_SEPARATORS = {"&&", "||", ";", "|", "&"}

# Redirection token: optional fd prefix (`2`, `&`) + `>` or `>>`, optionally
# fused with the path (e.g. `>file` is one token). Captures (operator, suffix).
_REDIR_RE = re.compile(r"^(?:&|\d+)?(>>?)(.*)$")


# ── Public API ────────────────────────────────────────────────────────────


def is_path_allowed(file_path: str, allowed_paths: list[str]) -> bool:
    """Check whether ``file_path`` falls under any of ``allowed_paths``.

    Both sides are resolved with ``Path.resolve(strict=False)`` so symlinks
    are followed (preventing the classic ``ln -s /etc/passwd ...`` bypass).

    Notes:
      * The caller is responsible for passing in an *absolute* path. Relative
        path resolution against the sandbox cwd happens in
        :func:`scan_shell_write_targets` — host-process cwd would be wrong.
      * Tokens containing literal ``..`` are rejected before touching the
        filesystem. ``Path.resolve()`` would normalise them safely on its
        own, but rejecting early gives a tighter audit trail.
    """
    if ".." in PurePosixPath(file_path).parts:
        return False
    try:
        resolved = Path(file_path).resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    for allowed in allowed_paths:
        try:
            resolved_allowed = Path(allowed).resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        try:
            resolved.relative_to(resolved_allowed)
            return True
        except ValueError:
            continue
    return False


def scan_shell_write_targets(
    command: str,
    args: list[str] | None = None,
    *,
    cwd: str | None = None,
) -> ShellWriteScan:
    """Statically extract every filesystem write target from a command.

    Returns a :class:`ShellWriteScan`. If ``refuse_reason`` is set, the
    command MUST be dropped — it contains constructs whose write
    behaviour cannot be determined without execution.
    """
    try:
        cmd_tokens = shlex.split(command, posix=True) if command else []
    except ValueError as exc:
        return ShellWriteScan(refuse_reason=f"malformed shell quoting: {exc}")

    tokens = cmd_tokens + list(args or [])
    if not tokens:
        return ShellWriteScan()

    all_targets: list[str] = []
    for segment in _split_into_segments(tokens):
        seg = _scan_segment(segment, cwd=cwd)
        if seg.refuse_reason:
            return seg
        all_targets.extend(seg.targets)
    return ShellWriteScan(targets=all_targets)


def extract_shell_write_targets(
    command: str, args: list[str] | None = None
) -> list[str]:
    """Backward-compatible wrapper around :func:`scan_shell_write_targets`.

    Loses the ``refuse_reason`` distinction — new callers should use
    :func:`scan_shell_write_targets` directly so they can react to
    statically-unanalysable commands by refusing them outright.
    """
    return scan_shell_write_targets(command, args, cwd=None).targets


# ── Internals ─────────────────────────────────────────────────────────────


def _split_into_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = [[]]
    for tok in tokens:
        if tok in _SEGMENT_SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(tok)
    return [s for s in segments if s]


def _scan_segment(tokens: list[str], *, cwd: str | None) -> ShellWriteScan:
    if not tokens:
        return ShellWriteScan()

    # 1. Hard refuse: any token containing a shell construct we cannot resolve.
    for tok in tokens:
        for pat in _INDETERMINATE_PATTERNS:
            if pat.search(tok):
                return ShellWriteScan(refuse_reason=(
                    f"token {tok!r} contains shell expansion / substitution "
                    f"that cannot be statically resolved"
                ))

    verb = tokens[0]

    # 2. Hard refuse: dynamic-code verbs.
    if verb in _INLINE_DYNAMIC_VERBS:
        return ShellWriteScan(refuse_reason=(
            f"verb '{verb}' executes dynamic code that cannot be statically analysed"
        ))
    if verb in _SHELL_INTERPRETERS and "-c" in tokens[1:]:
        return ShellWriteScan(refuse_reason=(
            f"shell '{verb}' invoked with '-c' inline script — refusing"
        ))
    if verb in _SCRIPT_INTERPRETERS:
        if "-c" in tokens[1:] or "-e" in tokens[1:]:
            return ShellWriteScan(refuse_reason=(
                f"interpreter '{verb}' invoked with inline-code flag — refusing"
            ))

    # 3. Per-verb write-target extraction (returns its own targets / refuse).
    handler = _VERB_HANDLERS.get(verb)
    if handler is not None:
        targets, refuse = handler(tokens, cwd=cwd)
        if refuse:
            return ShellWriteScan(refuse_reason=refuse)
        verb_targets = targets
    else:
        verb_targets = []

    # 4. Always also scan for redirections — they can appear after any verb.
    redir = _scan_redirections(tokens, cwd=cwd)
    if redir.refuse_reason:
        return redir

    return ShellWriteScan(targets=[*verb_targets, *redir.targets])


def _scan_redirections(tokens: list[str], *, cwd: str | None) -> ShellWriteScan:
    targets: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        m = _REDIR_RE.match(tok)
        if m:
            suffix = m.group(2)
            if suffix:
                # Fused form: e.g. `>file`, `2>>log`.
                resolved = _resolve_path(suffix, cwd=cwd)
                if resolved is None:
                    return ShellWriteScan(refuse_reason=(
                        f"redirection target {suffix!r} cannot be statically resolved"
                    ))
                targets.append(resolved)
            elif i + 1 < len(tokens):
                # Separated form: `>` then `file`.
                target_tok = tokens[i + 1]
                # Skip if next token is itself an operator (malformed but be safe).
                if _REDIR_RE.match(target_tok) and not _REDIR_RE.match(target_tok).group(2):
                    i += 1
                    continue
                resolved = _resolve_path(target_tok, cwd=cwd)
                if resolved is None:
                    return ShellWriteScan(refuse_reason=(
                        f"redirection target {target_tok!r} cannot be statically resolved"
                    ))
                targets.append(resolved)
                i += 2
                continue
        i += 1
    return ShellWriteScan(targets=targets)


def _resolve_path(path: str, *, cwd: str | None) -> str | None:
    """Resolve a path token to an absolute filesystem path string.

    Returns ``None`` (signalling "unresolvable, refuse the command") when:
      * the path is empty;
      * the path starts with ``~`` (sandbox $HOME is unknown to the host);
      * the path is relative and no absolute ``cwd`` is provided.
    """
    if not path:
        return None
    if path.startswith("~"):
        return None
    if path.startswith("/"):
        return path
    if cwd is None or not os.path.isabs(cwd):
        return None
    return os.path.normpath(str(Path(cwd) / path))


# ── Per-verb handlers ─────────────────────────────────────────────────────
# Each returns (targets, refuse_reason). Returning a refuse_reason cancels
# the whole command; returning ([], None) means "this verb does not write".


VerbHandler = Callable[[list[str]], tuple[list[str], str | None]]


def _h_tee(tokens: list[str], *, cwd: str | None):
    j = 1
    while j < len(tokens) and tokens[j].startswith("-"):
        j += 1
    targets: list[str] = []
    while j < len(tokens):
        resolved = _resolve_path(tokens[j], cwd=cwd)
        if resolved is None:
            return [], f"tee target {tokens[j]!r} cannot be statically resolved"
        targets.append(resolved)
        j += 1
    return targets, None


def _h_cp_mv_install(tokens: list[str], *, cwd: str | None):
    positional = [t for t in tokens[1:] if not t.startswith("-")]
    if not positional:
        return [], None
    dst = positional[-1]
    resolved = _resolve_path(dst, cwd=cwd)
    if resolved is None:
        return [], f"copy/move destination {dst!r} cannot be statically resolved"
    return [resolved], None


def _h_dd(tokens: list[str], *, cwd: str | None):
    targets: list[str] = []
    for tok in tokens[1:]:
        if tok.startswith("of="):
            dst = tok[3:]
            resolved = _resolve_path(dst, cwd=cwd)
            if resolved is None:
                return [], f"dd of= destination {dst!r} cannot be statically resolved"
            targets.append(resolved)
    return targets, None


def _h_sed(tokens: list[str], *, cwd: str | None):
    inplace = any(t == "-i" or t.startswith("-i.") or
                  (t.startswith("-i") and len(t) > 2 and t[2:].isalnum())
                  for t in tokens[1:])
    if not inplace:
        return [], None

    # Strip flag tokens; -e/-f consume the next token (script / script-file).
    files: list[str] = []
    j = 1
    while j < len(tokens):
        tok = tokens[j]
        if tok in ("-e", "-f"):
            j += 2
            continue
        if tok.startswith("-"):
            j += 1
            continue
        files.append(tok)
        j += 1

    if not files:
        return [], None
    # Conservative: when -e was not used, the first positional is the sed
    # script and everything after it is files. We can't reliably tell which
    # form was used, so treat *all* positionals as candidate file targets
    # except when there's clearly more than one (then the first is the script).
    candidates = files[1:] if len(files) > 1 else files
    targets: list[str] = []
    for f in candidates:
        resolved = _resolve_path(f, cwd=cwd)
        if resolved is None:
            return [], f"sed -i target {f!r} cannot be statically resolved"
        targets.append(resolved)
    return targets, None


def _h_wget(tokens: list[str], *, cwd: str | None):
    targets: list[str] = []
    j = 1
    while j < len(tokens):
        tok = tokens[j]
        if tok in ("-O", "--output-document") and j + 1 < len(tokens):
            resolved = _resolve_path(tokens[j + 1], cwd=cwd)
            if resolved is None:
                return [], f"wget -O target {tokens[j + 1]!r} cannot be statically resolved"
            targets.append(resolved)
            j += 2
            continue
        j += 1
    return targets, None


def _h_curl(tokens: list[str], *, cwd: str | None):
    targets: list[str] = []
    j = 1
    while j < len(tokens):
        tok = tokens[j]
        if tok in ("-o", "--output") and j + 1 < len(tokens):
            resolved = _resolve_path(tokens[j + 1], cwd=cwd)
            if resolved is None:
                return [], f"curl -o target {tokens[j + 1]!r} cannot be statically resolved"
            targets.append(resolved)
            j += 2
            continue
        j += 1
    return targets, None


def _h_tar(tokens: list[str], *, cwd: str | None):
    # Extract operations write to either cwd or `-C dir` and can produce an
    # arbitrary tree. We can't bound them statically — refuse.
    is_extract = any(t in ("-x", "--extract", "--get") or
                     (t.startswith("-") and not t.startswith("--") and "x" in t)
                     for t in tokens[1:])
    if is_extract:
        return [], "tar extract operations write an unbounded tree — refusing"
    targets: list[str] = []
    j = 1
    while j < len(tokens):
        tok = tokens[j]
        if tok in ("-f", "--file") and j + 1 < len(tokens):
            resolved = _resolve_path(tokens[j + 1], cwd=cwd)
            if resolved is None:
                return [], f"tar archive {tokens[j + 1]!r} cannot be statically resolved"
            targets.append(resolved)
            j += 2
            continue
        j += 1
    return targets, None


_VERB_HANDLERS: dict[str, Callable[..., tuple[list[str], str | None]]] = {
    "tee": _h_tee,
    "cp": _h_cp_mv_install,
    "mv": _h_cp_mv_install,
    "install": _h_cp_mv_install,
    "rsync": _h_cp_mv_install,
    "dd": _h_dd,
    "sed": _h_sed,
    "wget": _h_wget,
    "curl": _h_curl,
    "tar": _h_tar,
}
