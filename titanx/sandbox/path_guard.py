from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

WRITE_TARGET_RE = re.compile(r'(?:>{1,2}|tee(?:\s+-a)?)\s+["\']?(/[^"\'\s;|&<>]+)["\']?')


def is_path_allowed(file_path: str, allowed_paths: list[str]) -> bool:
    # Defense in depth: reject traversal syntax before hitting the filesystem.
    if ".." in PurePosixPath(file_path).parts:
        return False
    try:
        # strict=False so non-existent leaves still normalise; resolve() follows
        # any symlink along the path, which is what stops the symlink-bypass.
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


def extract_shell_write_targets(command: str, args: list[str] | None = None) -> list[str]:
    full = " ".join([command, *(args or [])])
    return [m.group(1) for m in WRITE_TARGET_RE.finditer(full)]
