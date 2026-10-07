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
from functools import partial
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

# Verbs that merely *launch* another command. `env bash -c '…'` would
# otherwise hide the inline shell behind the wrapper's name — the -c
# refusal lives on the verb, so the wrapper has to be peeled off first.
_WRAPPER_VERBS = {"env", "nice", "nohup", "setsid", "time", "timeout",
                  "stdbuf", "xargs"}

# Short options that consume a *separate* argument for each wrapper
# (`env -u NAME`, `timeout -s SIG`, `xargs -a FILE`). Without these, the
# option's value is mistaken for the wrapped command and the real command
# (possibly an inline shell) is never examined.
_WRAPPER_VALUE_SHORTS: dict[str, frozenset[str]] = {
    "env": frozenset({"u", "C", "S"}),
    "nice": frozenset({"n"}),
    "timeout": frozenset({"s", "k"}),
    "stdbuf": frozenset({"i", "o", "e"}),
    "time": frozenset({"f", "o"}),
    "xargs": frozenset({"a", "E", "I", "L", "n", "P", "s", "d"}),
}
# Long options that consume a *separate* argument. Stored WITHOUT the
# leading dashes; resolution goes through :func:`_abbrev` so that
# getopt_long abbreviations (`--sig` for `--signal`) are honoured — matching
# the literal spelling only let `env --un X bash -c …` hide the inline shell.
# NOTE: GNU optional-argument options (`--eof[=X]`, `--replace[=X]`,
# `--max-lines[=X]`, env's `--block-signal[=SIG]`) do NOT consume a
# separate token in their bare form, so they belong in the boolean table.
_WRAPPER_VALUE_LONGS: dict[str, frozenset[str]] = {
    "env": frozenset({"unset", "chdir", "split-string", "argv0"}),
    "nice": frozenset({"adjustment"}),
    "timeout": frozenset({"signal", "kill-after"}),
    "stdbuf": frozenset({"input", "output", "error"}),
    "time": frozenset({"format", "output"}),
    "xargs": frozenset({"arg-file", "max-args", "max-procs", "max-chars",
                        "delimiter", "process-slot-var"}),
}

# Long options that take NO separate argument. Enumerated so a benign flag
# (`env --ignore-environment …`) still peels, while a wrapper long option
# that is unknown to us falls through to a hard refuse — the option's arity
# is exactly what we cannot determine, and guessing wrong is how a value
# gets mistaken for the wrapped command.
_WRAPPER_BOOL_LONGS: dict[str, frozenset[str]] = {
    "env": frozenset({"ignore-environment", "null", "debug",
                      "block-signal", "default-signal", "ignore-signal",
                      "list-signal-handling", "help", "version"}),
    "nice": frozenset({"help", "version"}),
    "nohup": frozenset({"help", "version"}),
    "setsid": frozenset({"fork", "ctty", "wait", "help", "version"}),
    "timeout": frozenset({"foreground", "preserve-status", "verbose",
                          "help", "version"}),
    "stdbuf": frozenset({"help", "version"}),
    "time": frozenset({"append", "verbose", "portability", "quiet",
                       "help", "version"}),
    "xargs": frozenset({"null", "show-limits", "interactive", "verbose",
                        "exit", "open-tty", "no-run-if-empty",
                        # optional-argument options: bare form takes no
                        # separate token.
                        "eof", "replace", "max-lines", "help", "version"}),
}


def _split_long(tok: str) -> tuple[str, str | None] | None:
    """Split a ``--name`` / ``--name=value`` token.

    Returns ``(name, inline_value_or_None)`` (name without dashes), or
    ``None`` when ``tok`` is not a long option.
    """
    if not tok.startswith("--") or len(tok) <= 2:
        return None
    body = tok[2:]
    name, sep, value = body.partition("=")
    return name, (value if sep else None)


def _abbrev(name: str, options: frozenset[str]) -> tuple[str | None, bool]:
    """Resolve a long-option ``name`` (dashless) against ``options``.

    Mirrors glibc ``getopt_long``: an exact match wins, otherwise an
    unambiguous prefix resolves. Returns ``(canonical, ambiguous)``;
    ``canonical`` is ``None`` when nothing matches and ``ambiguous`` is
    ``True`` when the prefix matches more than one option.
    """
    if not name:
        return None, False
    if name in options:
        return name, False
    hits = [o for o in options if o.startswith(name)]
    if len(hits) == 1:
        return hits[0], False
    if len(hits) > 1:
        return None, True
    return None, False

# A wrapper duration/argument operand (`timeout 5`, `timeout 5s`,
# `nice 10`). Skipped when locating the wrapped command.
_NUMERICISH_RE = re.compile(r"^\d+(\.\d+)?[smhd]?$")

# `NAME=value` environment assignment (`env PATH=/usr/bin …`). The value
# may contain slashes, so we validate the *name* shape, not the value.
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

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


def _basename(token: str) -> str:
    """Return the command word without any leading path (``/bin/cp`` → ``cp``)."""
    return token.rsplit("/", 1)[-1]


def _has_inline_code_flag(args: list[str], letters: str) -> bool:
    """True if any short-flag token carries one of ``letters``.

    Covers both the separated form (``bash -c code`` → token ``-c``) and the
    fused / clustered forms (``bash -ccmd`` → token ``-ccmd``; ``bash -lc x``
    → token ``-lc``). Long options (``--…``) are ignored: none of the inline
    code flags we care about are long options.
    """
    for tok in args:
        if not tok.startswith("-") or tok.startswith("--"):
            continue
        body = tok[1:]
        if any(ch in body for ch in letters):
            return True
    return False


def _cluster_value(
    tok: str, letter: str, value_letters: frozenset[str]
) -> tuple[bool, str | None]:
    """Find a value-taking short option inside a bundled flag cluster.

    ``-so /etc/x`` bundles the boolean ``-s`` with the value-taking ``-o``:
    the option letter is not at the start of the token, so a naive
    ``tok.startswith("-o")`` misses it. Returns ``(present, fused)`` where
    ``fused`` is the value attached to the letter (``-o/etc/x`` → ``/etc/x``)
    or ``None`` when the value is the *next* token (``-so /etc/x``).

    A cluster is only recognised when every letter before ``letter`` is a
    boolean option — i.e. no other value-taking option precedes it. That is
    what stops ``cp -St`` (``-S`` *suffix*, value ``t``) being read as
    ``-t DIR``.
    """
    if not tok.startswith("-") or tok.startswith("--") or len(tok) < 2:
        return (False, None)
    body = tok[1:]
    at = body.find(letter)
    if at == -1:
        return (False, None)
    if any(ch in value_letters and ch != letter for ch in body[:at]):
        return (False, None)
    suffix = body[at + 1:]
    return (True, suffix if suffix else None)


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

    # 2. Resolve the effective verb. Strip a leading path (`/bin/cp`, `./tee`)
    #    and peel the `busybox <applet>` and launcher-wrapper (`env`, `nice`,
    #    `timeout`, `xargs`, …) idioms, so an unknown-name wrapper cannot hide
    #    a write-capable verb or an inline shell. `cmd` keeps the verb token
    #    first so the per-verb handlers (which start at index 1) work unchanged.
    cmd = tokens
    while True:
        verb = _basename(cmd[0])
        if verb == "busybox":
            j = 1
            while j < len(cmd) and cmd[j].startswith("-"):
                j += 1
            if j < len(cmd):
                cmd = cmd[j:]
                continue
        if verb in _WRAPPER_VERBS:
            rest = cmd[1:]
            value_shorts = _WRAPPER_VALUE_SHORTS.get(verb, frozenset())
            value_longs = _WRAPPER_VALUE_LONGS.get(verb, frozenset())
            bool_longs = _WRAPPER_BOOL_LONGS.get(verb, frozenset())
            known_longs = value_longs | bool_longs
            i = 0
            after_ddash = False
            while i < len(rest):
                tok = rest[i]
                if tok == "--" and not after_ddash:
                    # End of wrapper options. `env` still accepts NAME=value
                    # assignments after it; for every other wrapper the next
                    # token is the wrapped command.
                    after_ddash = True
                    i += 1
                    continue
                if after_ddash:
                    if verb == "env" and _ENV_ASSIGN_RE.match(tok):
                        i += 1
                        continue
                    break  # the command starts here
                if tok == "-":
                    # GNU `env` treats a lone `-` as `-i`; it is an option,
                    # not the wrapped command.
                    i += 1
                    continue
                if tok.startswith("--"):
                    split = _split_long(tok)
                    assert split is not None
                    name, inline = split
                    canon, ambiguous = _abbrev(name, known_longs)
                    if ambiguous:
                        # getopt_long would reject this too; we cannot tell
                        # the arity, so fail closed.
                        return ShellWriteScan(refuse_reason=(
                            f"wrapper {verb!r} long option {tok!r} is an "
                            f"ambiguous abbreviation — refusing"
                        ))
                    if canon == "split-string":
                        return ShellWriteScan(refuse_reason=(
                            "env --split-string re-splits its argument into a "
                            "command that cannot be statically analysed"
                        ))
                    if canon in value_longs:
                        i += 1 if inline is not None else 2  # --opt[=]value
                    elif canon in bool_longs:
                        i += 1  # --flag
                    elif inline is not None:
                        i += 1  # --unknown=value, self-contained
                    else:
                        # An unrecognised long option on a wrapper: its arity
                        # is unknowable, and guessing "no value" would let the
                        # real command hide behind it.
                        return ShellWriteScan(refuse_reason=(
                            f"wrapper {verb!r} long option {tok!r} is not "
                            f"recognised — refusing"
                        ))
                    continue
                if tok.startswith("-") and len(tok) > 1:
                    body = tok[1:]
                    eats_next = False
                    first_value_letter: str | None = None
                    for k, ch in enumerate(body):
                        if ch in value_shorts:
                            first_value_letter = ch
                            eats_next = k == len(body) - 1
                            break
                    # `env -S` re-splits its value into a command we cannot
                    # see. Only the *option letter* counts — a value like
                    # `-uSSH_AUTH_SOCK` merely contains an `S`.
                    if verb == "env" and first_value_letter == "S":
                        return ShellWriteScan(refuse_reason=(
                            "env -S re-splits its argument into a command "
                            "that cannot be statically analysed"
                        ))
                    i += 2 if eats_next else 1
                    continue
                if verb == "env" and _ENV_ASSIGN_RE.match(tok):
                    i += 1  # NAME=value assignment
                    continue
                if verb != "env" and _NUMERICISH_RE.match(tok):
                    i += 1  # timeout/nice duration operand
                    continue
                break
            if i < len(rest):
                cmd = rest[i:]
                continue
        break
    verb = _basename(cmd[0])

    # 3. Hard refuse: dynamic-code verbs.
    if verb in _INLINE_DYNAMIC_VERBS:
        return ShellWriteScan(refuse_reason=(
            f"verb '{verb}' executes dynamic code that cannot be statically analysed"
        ))
    if verb in _SHELL_INTERPRETERS and _has_inline_code_flag(cmd[1:], "c"):
        return ShellWriteScan(refuse_reason=(
            f"shell '{verb}' invoked with an inline-script flag — refusing"
        ))
    if verb in _SCRIPT_INTERPRETERS and _has_inline_code_flag(cmd[1:], "ce"):
        return ShellWriteScan(refuse_reason=(
            f"interpreter '{verb}' invoked with inline-code flag — refusing"
        ))

    # 4. Per-verb write-target extraction (returns its own targets / refuse).
    handler = _VERB_HANDLERS.get(verb)
    if handler is not None:
        targets, refuse = handler(cmd, cwd=cwd)
        if refuse:
            return ShellWriteScan(refuse_reason=refuse)
        verb_targets = targets
    else:
        verb_targets = []

    # 5. Always also scan for redirections — they can appear after any verb.
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


VerbHandler = Callable[..., tuple[list[str], str | None]]

# Long options recognised by the per-verb handlers (dashless). Resolution
# goes through :func:`_abbrev`, so `cp --target-dir=/etc` or `sed --in-pl`
# are seen the same as the full spelling.
_TARGET_DIR_LONGS = frozenset({"target-directory"})
_IN_PLACE_LONGS = frozenset({"in-place"})
_TAR_LONG_OPTIONS = frozenset({
    "extract", "get", "create", "append", "update", "concatenate", "delete",
    "file",
})


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


def _h_cp_mv_install(
    tokens: list[str], *, cwd: str | None, value_letters: frozenset[str]
):
    targets: list[str] = []
    positional: list[str] = []
    has_target_dir = False
    j = 1
    while j < len(tokens):
        tok = tokens[j]
        dst: str | None = None
        next_j = j + 1
        if tok == "-t":
            if j + 1 >= len(tokens):
                return [], "-t requires a directory argument"
            dst, next_j = tokens[j + 1], j + 2
        else:
            split = _split_long(tok)
            canon = None
            if split is not None:
                canon, _ = _abbrev(split[0], _TARGET_DIR_LONGS)
            if canon is not None:
                inline = split[1] if split is not None else None
                if inline is not None:
                    dst, next_j = inline, j + 1
                elif j + 1 < len(tokens):
                    dst, next_j = tokens[j + 1], j + 2
                else:
                    return [], "--target-directory requires a directory argument"
            else:
                present, fused = _cluster_value(tok, "t", value_letters)
                if not present:
                    if tok.startswith("-"):
                        j += 1
                        continue
                    positional.append(tok)
                    j += 1
                    continue
                if fused is not None:
                    dst, next_j = fused, j + 1
                elif j + 1 < len(tokens):
                    dst, next_j = tokens[j + 1], j + 2
                else:
                    return [], "-t requires a directory argument"
        j = next_j
        # `-t DIR` (in any spelling) names the destination explicitly; the
        # positional operands are then sources only. Without this branch the
        # real destination is skipped and a source operand is checked as if
        # it were the target.
        has_target_dir = True
        resolved = _resolve_path(dst, cwd=cwd)
        if resolved is None:
            return [], f"copy/move destination {dst!r} cannot be statically resolved"
        targets.append(resolved)

    if not has_target_dir and positional:
        dst = positional[-1]
        resolved = _resolve_path(dst, cwd=cwd)
        if resolved is None:
            return [], f"copy/move destination {dst!r} cannot be statically resolved"
        targets.append(resolved)
    return targets, None


def _h_rsync(tokens: list[str], *, cwd: str | None):
    """rsync writes to its last operand; ``-t`` means ``--times`` here.

    rsync has no ``--target-directory``, so the cp/mv/install ``-t``
    handling must NOT apply — doing so recorded a source as the target and
    dropped the real destination. rsync takes its destination as the last
    operand; option *values* (``-e ssh``, ``--exclude foo``) precede it in
    the common form, so "last positional wins" holds there. (An option that
    trails the operands is a known limitation shared with the other verbs.)
    """
    positional = [t for t in tokens[1:] if not t.startswith("-")]
    if not positional:
        return [], None
    dst = positional[-1]
    resolved = _resolve_path(dst, cwd=cwd)
    if resolved is None:
        return [], f"rsync destination {dst!r} cannot be statically resolved"
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
    # In-place edit flags: `-i`, `-i.bak`, `-i~` (any fused suffix), the long
    # form `--in-place` / `--in-place=.bak`, AND the bundled cluster `-ni`
    # / `-Ei`. The long and bundled forms used to slip through, letting
    # `sed --in-place …` or `sed -ni …` write unguarded.
    # `-e`/`-f` consume the next token (script / script-file); skip those so
    # a script that happens to look like a flag is not misread.
    inplace = False
    files: list[str] = []
    j = 1
    while j < len(tokens):
        tok = tokens[j]
        if tok in ("-e", "-f"):
            j += 2
            continue
        if tok == "--":
            # End of options: every remaining token is a file operand
            # (even one that starts with `-`).
            files.extend(tokens[j + 1:])
            break
        if tok.startswith("--"):
            # `--in-place` / `--in-place=.bak`, and any unambiguous getopt
            # abbreviation (`--in-pl`) that GNU sed accepts.
            canon, _ = _abbrev(tok[2:].partition("=")[0], _IN_PLACE_LONGS)
            if canon is not None:
                inplace = True
            j += 1
            continue
        if tok.startswith("-"):
            # Every other option is a flag: short clusters (`-ni`, `-Ei`)
            # may also carry `-i`; long options were handled above and must
            # NOT be mistaken for file operands, which would shift the
            # script/file split.
            if "i" in tok[1:]:
                inplace = True
            j += 1
            continue
        files.append(tok)
        j += 1

    if not inplace or not files:
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


# Short options that take a *value* for each tool. Used by ``_cluster_value``
# so a bundled cluster (`-so`, `-qO`) is parsed without mistaking a value
# (``-xproxy``) for the option, and by the option-position walker. It must
# list value-taking options ONLY: putting a boolean flag here (e.g. curl's
# `-q`/`-R`) makes the walker swallow the *next* token, hiding a real `-O`.
_WGET_VALUE_SHORTS = frozenset("OoaiPUetTw")
_CURL_VALUE_SHORTS = frozenset("AbcdeEFHKmoPrTuUwxXyzY")

# Options whose write target is a *remote-derived* filename (curl -O/-J,
# wget's default). The name is chosen by the server, so it cannot be
# statically resolved — such a write is refused rather than passed.
_CURL_REMOTE_NAME_LONGS = frozenset({
    "remote-name", "remote-name-all", "remote-header-name",
})
_WGET_SPIDER_LONGS = frozenset({"spider"})
# The option that names the downloaded file / its destination directory.
_WGET_OUTPUT_LONGS = frozenset({"output-document"})
_WGET_DIR_LONGS = frozenset({"directory-prefix"})

# Best-effort sets of the long options that consume a following argument, so
# the option scan can skip a value that merely *looks* like a flag
# (`curl -d -O` passes `-O` as POST data). Incomplete by design: an
# unrecognised long option is assumed not to consume, which can only cause an
# over-refusal, never a missed write.
_CURL_VALUE_LONGS = frozenset({
    "data", "data-binary", "data-raw", "data-urlencode", "form",
    "form-string", "header", "user", "user-agent", "url", "request",
    "output", "output-dir", "cookie", "cookie-jar", "proxy", "referer",
    "upload-file", "interface", "cert", "key", "cacert", "capath", "config",
    "dump-header", "write-out", "connect-timeout", "max-time", "retry",
    "retry-delay", "retry-max-time", "range", "limit-rate", "resolve",
    "oauth2-bearer",
})
_WGET_VALUE_LONGS = frozenset({
    "output-document", "output-file", "directory-prefix", "user-agent",
    "header", "post-data", "post-file", "body-data", "body-file", "user",
    "password", "referer", "input-file", "tries", "timeout", "waitretry",
    "limit-rate", "bind-address", "ca-certificate", "certificate",
    "private-key", "execute", "load-cookies", "save-cookies", "warc-file",
    "include-directories", "exclude-directories",
})


def _iter_option_positions(
    tokens: list[str], value_shorts: frozenset[str], value_longs: frozenset[str],
):
    """Yield the tokens that sit in option position.

    A token that is the *argument* of a preceding value-taking option is
    skipped, so ``curl -d -O`` does not read the ``-O`` (it is POST data).
    Values of a short option are located via ``value_shorts``; a long option
    consumes a separate argument only when it resolves to a known
    ``value_longs`` entry.
    """
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        yield tok
        consumes_next = False
        split = _split_long(tok)
        if split is not None:
            if split[1] is None:
                consumes_next = _abbrev(split[0], value_longs)[0] is not None
        elif tok.startswith("-") and len(tok) > 1:
            body = tok[1:]
            for k, ch in enumerate(body):
                if ch in value_shorts:
                    consumes_next = k == len(body) - 1
                    break
        i += 2 if consumes_next else 1


def _has_short(
    tokens: list[str], letter: str, value_shorts: frozenset[str],
    value_longs: frozenset[str],
) -> bool:
    """True if short option ``letter`` appears (fused, bundled, or separate)."""
    return any(
        _cluster_value(tok, letter, value_shorts)[0]
        for tok in _iter_option_positions(tokens, value_shorts, value_longs)
    )


def _has_long(
    tokens: list[str], names: frozenset[str], value_shorts: frozenset[str],
    value_longs: frozenset[str],
) -> bool:
    """True if any long option in ``names`` appears, abbreviation-aware."""
    for tok in _iter_option_positions(tokens, value_shorts, value_longs):
        split = _split_long(tok)
        if split is not None and _abbrev(split[0], names)[0] is not None:
            return True
    return False


def _output_target(
    tokens: list[str], *, letter: str, long_name: str,
    value_shorts: frozenset[str], label: str, cwd: str | None,
    dash_is_stdout: bool = True, siblings: frozenset[str] = frozenset(),
):
    # `siblings` lets an abbreviation be resolved in context: `--output` is
    # the exact spelling of a *different* option, so the `--output-dir` pass
    # must not claim it (which would misread its value).
    long_options = frozenset({long_name}) | siblings
    targets: list[str] = []
    j = 1
    while j < len(tokens):
        tok = tokens[j]
        val: str | None = None
        next_j = j + 1
        # `--output` / `--output=.f`, and getopt abbreviations (`--out`,
        # `--output-doc`) that the tool accepts but exact matching missed.
        split = _split_long(tok)
        matched_long = False
        if split is not None:
            canon, _ = _abbrev(split[0], long_options)
            if canon == long_name:
                matched_long = True
                if split[1] is not None:
                    val = split[1]
                elif j + 1 < len(tokens):
                    val, next_j = tokens[j + 1], j + 2
        if not matched_long:
            present, fused = _cluster_value(tok, letter, value_shorts)
            if present:
                if fused is not None:
                    val = fused
                elif j + 1 < len(tokens):
                    val, next_j = tokens[j + 1], j + 2
        if val is not None and not (dash_is_stdout and val == "-"):
            # For a *file* output option a lone `-` means stdout (`curl -o -`,
            # `wget -O -`) — not a path. For a directory option (`-P`,
            # `--output-dir`) `-` is a literal relative directory, so it is
            # resolved (and refused when no cwd is known).
            resolved = _resolve_path(val, cwd=cwd)
            if resolved is None:
                return [], f"{label} target {val!r} cannot be statically resolved"
            targets.append(resolved)
        j = next_j
    return targets, None


def _h_wget(tokens: list[str], *, cwd: str | None):
    # wget's three output-ish long options share the `output-`/`output` prefix,
    # so every pass resolves an abbreviation against all of them: `--output`
    # is *ambiguous* (matches both `--output-document` and `--output-file`)
    # and must be claimed by neither.
    _wget_out_longs = frozenset(
        {"output-document", "output-file", "directory-prefix"}
    )
    # `-O`/`--output-document` names the downloaded file.
    targets, refuse = _output_target(
        tokens, letter="O", long_name="output-document",
        value_shorts=_WGET_VALUE_SHORTS, label="wget -O", cwd=cwd,
        siblings=_wget_out_longs - {"output-document"},
    )
    if refuse:
        return [], refuse
    # `-o`/`--output-file` (log) and `-P`/`--directory-prefix` (destination
    # directory) are write targets too.
    for letter, lname in (("o", "output-file"), ("P", "directory-prefix")):
        extra, refuse = _output_target(
            tokens, letter=letter, long_name=lname,
            value_shorts=_WGET_VALUE_SHORTS, label=f"wget -{letter}", cwd=cwd,
            dash_is_stdout=(letter != "P"),
            siblings=_wget_out_longs - {lname},
        )
        if refuse:
            return [], refuse
        targets.extend(extra)
    # Without `-O` (or a `-P` destination the write is confined to), wget
    # writes the server-chosen name into the sandbox cwd — unnamed, so
    # refuse. `-o` (a separate log file) does NOT name the download.
    named = _has_short(
        tokens, "O", _WGET_VALUE_SHORTS, _WGET_VALUE_LONGS
    ) or _has_long(
        tokens, _WGET_OUTPUT_LONGS, _WGET_VALUE_SHORTS, _WGET_VALUE_LONGS
    )
    confined = _has_short(
        tokens, "P", _WGET_VALUE_SHORTS, _WGET_VALUE_LONGS
    ) or _has_long(
        tokens, _WGET_DIR_LONGS, _WGET_VALUE_SHORTS, _WGET_VALUE_LONGS
    )
    spider = _has_long(
        tokens, _WGET_SPIDER_LONGS, _WGET_VALUE_SHORTS, _WGET_VALUE_LONGS
    )
    has_operand = any(not t.startswith("-") for t in tokens[1:])
    if not named and not confined and not spider and has_operand:
        return [], (
            "wget downloads to a remote-derived filename that cannot be "
            "statically named — refusing"
        )
    return list(dict.fromkeys(targets)), None


def _h_curl(tokens: list[str], *, cwd: str | None):
    targets, refuse = _output_target(
        tokens, letter="o", long_name="output",
        value_shorts=_CURL_VALUE_SHORTS, label="curl -o", cwd=cwd,
    )
    if refuse:
        return [], refuse
    # `-O`/`--remote-name[(-all)]`/`-J`/`--remote-header-name` write the
    # server-chosen filename — unnamed, so refuse. The scan skips values of
    # preceding value-taking options (`curl -d -O` passes `-O` as data).
    if _has_short(
        tokens, "O", _CURL_VALUE_SHORTS, _CURL_VALUE_LONGS
    ) or _has_short(
        tokens, "J", _CURL_VALUE_SHORTS, _CURL_VALUE_LONGS
    ) or _has_long(
        tokens, _CURL_REMOTE_NAME_LONGS, _CURL_VALUE_SHORTS, _CURL_VALUE_LONGS
    ):
        return [], (
            "curl writes to a remote-derived filename that cannot be "
            "statically named — refusing"
        )
    # `--output-dir DIR` is the directory the download lands in. `--output`
    # (the file option above) is a *different* option — with `siblings` set,
    # an exact `--output` resolves to itself, not to `--output-dir`.
    dir_targets, refuse = _output_target(
        tokens, letter="\x00", long_name="output-dir",
        value_shorts=frozenset(), label="curl --output-dir", cwd=cwd,
        dash_is_stdout=False, siblings=frozenset({"output"}),
    )
    if refuse:
        return [], refuse
    return list(dict.fromkeys([*targets, *dir_targets])), None


def _h_tar(tokens: list[str], *, cwd: str | None):
    # tar is the messiest verb: options arrive dash-prefixed (`-cf`, `-c -f`),
    # as long options (`--create --file=`), or in the traditional *old-style*
    # cluster with no dash (`tar cf ARCHIVE …`). The mode letter decides
    # whether tar writes (`c`/`r`/`u`/`A` → the `-f` archive is a write
    # target) or reads (`t` lists). Extract (`x`) writes an unbounded tree and
    # is refused. The old code only understood dash-prefixed `-x`/`-f`, so the
    # no-dash cluster forms slipped through both the extract refusal and the
    # archive-target extraction.
    args = tokens[1:]

    archive: str | None = None
    write_mode = False
    extract = False

    def _consume_cluster(cluster: str, index: int) -> int:
        """Interpret one short-option cluster; return the next unread arg index."""
        nonlocal archive, write_mode, extract
        k = 0
        while k < len(cluster):
            ch = cluster[k]
            if ch == "x":
                extract = True
            elif ch in ("c", "r", "u", "A"):
                write_mode = True
            elif ch == "f":
                tail = cluster[k + 1:]
                if tail:
                    archive = tail
                    return index
                if index < len(args):
                    archive = args[index]
                    return index + 1
                return index
            elif ch in ("C", "T", "X", "b", "N"):
                # These consume the following argument; skip it so the archive
                # operand after `-f` is located at the right offset.
                if k == len(cluster) - 1 and index < len(args):
                    return index + 1
            k += 1
        return index

    index = 0
    while index < len(args):
        tok = args[index]
        if tok == "--":
            break
        if tok.startswith("--"):
            name, _, value = tok.partition("=")
            # Prefix-resolve so getopt abbreviations (`--cre`, `--ext`)
            # behave like the full spelling.
            canon, _ = _abbrev(name[2:], _TAR_LONG_OPTIONS)
            if canon in ("extract", "get"):
                extract = True
            elif canon in ("create", "append", "update", "concatenate",
                           "delete"):
                write_mode = True
            elif canon == "file":
                if value:
                    archive = value
                elif index + 1 < len(args):
                    archive = args[index + 1]
                    index += 1
            index += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            index = _consume_cluster(tok[1:], index + 1)
            continue
        # No leading dash. In the old-style form ONLY the first argument can
        # be the option cluster (`cf`, `xf`, `tvf`, …); every later operand is
        # a file. Restricting to index 0 is what stops a source tree named
        # with an `x` (`tar -cf out.tar myxfile`) being re-parsed as an
        # extract cluster after a dash-prefixed cluster was already seen.
        if index == 0 and tok.isalpha():
            index = _consume_cluster(tok, index + 1)
            continue
        index += 1

    if extract:
        return [], "tar extract operations write an unbounded tree — refusing"

    targets: list[str] = []
    if write_mode and archive is not None:
        resolved = _resolve_path(archive, cwd=cwd)
        if resolved is None:
            return [], f"tar archive {archive!r} cannot be statically resolved"
        targets.append(resolved)
    return targets, None


_VERB_HANDLERS: dict[str, Callable[..., tuple[list[str], str | None]]] = {
    "tee": _h_tee,
    "cp": partial(_h_cp_mv_install, value_letters=frozenset({"S", "t"})),
    "mv": partial(_h_cp_mv_install, value_letters=frozenset({"S", "t"})),
    "install": partial(
        _h_cp_mv_install, value_letters=frozenset({"S", "t", "g", "m", "o"})
    ),
    "rsync": _h_rsync,
    "dd": _h_dd,
    "sed": _h_sed,
    "wget": _h_wget,
    "curl": _h_curl,
    "tar": _h_tar,
}
