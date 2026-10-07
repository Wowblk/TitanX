"""Tests for titanx.sandbox.path_guard.

Critical test: is_path_allowed MUST resolve symlinks before the allow-list check.
Without resolve, an attacker can place a symlink inside an allowed directory that
points to a forbidden location, bypassing the guard.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from titanx.sandbox.path_guard import (
    extract_shell_write_targets,
    is_path_allowed,
)


class TestIsPathAllowed:
    def test_exact_match_allowed(self, tmp_path: Path) -> None:
        assert is_path_allowed(str(tmp_path), [str(tmp_path)])

    def test_descendant_allowed(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b.txt"
        assert is_path_allowed(str(target), [str(tmp_path)])

    def test_sibling_not_allowed(self, tmp_path: Path) -> None:
        sibling = tmp_path.parent / "outside"
        assert not is_path_allowed(str(sibling), [str(tmp_path)])

    def test_traversal_rejected(self, tmp_path: Path) -> None:
        escape = f"{tmp_path}/../etc/passwd"
        assert not is_path_allowed(escape, [str(tmp_path)])

    def test_symlink_bypass_blocked(self, tmp_path: Path) -> None:
        """The regression test for the original vulnerability.

        An allow-listed directory contains a symlink that points at a forbidden
        location. The guard must refuse the write.
        """
        allowed = tmp_path / "workspace"
        allowed.mkdir()
        forbidden = tmp_path / "secret.txt"
        forbidden.write_text("classified")
        link = allowed / "link"
        os.symlink(forbidden, link)

        assert not is_path_allowed(str(link), [str(allowed)])

    def test_symlink_inside_allowed_ok(self, tmp_path: Path) -> None:
        """A symlink that resolves back inside the allow-list must be accepted."""
        allowed = tmp_path / "workspace"
        allowed.mkdir()
        real = allowed / "file.txt"
        real.write_text("ok")
        link = allowed / "link"
        os.symlink(real, link)

        assert is_path_allowed(str(link), [str(allowed)])

    def test_allow_path_is_symlink(self, tmp_path: Path) -> None:
        """If the allow-list entry is itself a symlink (e.g. /tmp on macOS),
        resolving both sides keeps the check consistent.
        """
        real = tmp_path / "real_workspace"
        real.mkdir()
        link = tmp_path / "link_workspace"
        os.symlink(real, link)
        target = real / "a.txt"
        target.write_text("x")

        assert is_path_allowed(str(target), [str(link)])
        assert is_path_allowed(str(link / "a.txt"), [str(real)])

    def test_empty_allowed_list_rejects(self, tmp_path: Path) -> None:
        assert not is_path_allowed(str(tmp_path / "x"), [])


class TestExtractShellWriteTargets:
    def test_redirect_gt(self) -> None:
        assert extract_shell_write_targets("echo x > /etc/passwd") == ["/etc/passwd"]

    def test_redirect_append(self) -> None:
        assert extract_shell_write_targets("echo x >> /var/log/app.log") == ["/var/log/app.log"]

    def test_tee(self) -> None:
        assert extract_shell_write_targets("echo x | tee /tmp/out.txt") == ["/tmp/out.txt"]

    def test_tee_append(self) -> None:
        assert extract_shell_write_targets("echo x | tee -a /tmp/out.txt") == ["/tmp/out.txt"]

    def test_no_write(self) -> None:
        assert extract_shell_write_targets("cat /etc/hosts") == []
