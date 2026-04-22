from __future__ import annotations

import posixpath
import re

WRITE_TARGET_RE = re.compile(r'(?:>{1,2}|tee(?:\s+-a)?)\s+["\']?(\/[^"\'\\s;|&<>]+)["\']?')


def is_path_allowed(file_path: str, allowed_paths: list[str]) -> bool:
    normalized = posixpath.normpath(file_path)
    if ".." in normalized.split("/"):
        return False
    for allowed in allowed_paths:
        norm_allowed = posixpath.normpath(allowed)
        prefix = norm_allowed if norm_allowed.endswith("/") else norm_allowed + "/"
        if normalized == norm_allowed or normalized.startswith(prefix):
            return True
    return False


def extract_shell_write_targets(command: str, args: list[str] | None = None) -> list[str]:
    full = " ".join([command, *(args or [])])
    return [m.group(1) for m in WRITE_TARGET_RE.finditer(full)]
