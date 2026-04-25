"""Read-only / read-write path split — policy + Docker bind mounts.

The split is the SDK equivalent of NemoClaw's filesystem_policy. We
need three things to hold:

1. ``allowed_read_paths`` is validated with the *same* forbidden list
   as ``allowed_write_paths`` — read-only mounts of /etc, /proc, etc.
   must still be rejected.
2. ``DockerSandboxBackend._filesystem_flags`` mounts the right entries
   ``:rw`` vs ``:ro`` and never ``:ro``-shadows a writable path.
3. The audit module reports overlap between the two lists.

These are pure-function tests — no Docker, no live sandboxes. They
guard the contract the rest of the system depends on.
"""

from __future__ import annotations

import pytest

from titanx.audit import audit_policy
from titanx.policy.types import AgentPolicy
from titanx.policy.validation import PolicyValidationError, validate_policy
from titanx.sandbox.backends.docker import _filesystem_flags


class TestPolicyValidation:
    def test_allowed_read_paths_default_empty(self):
        # New field must default to an empty list so existing
        # AgentPolicy() callers keep working.
        p = AgentPolicy()
        assert p.allowed_read_paths == []

    def test_allowed_read_paths_accepts_safe_path(self):
        validate_policy(AgentPolicy(allowed_read_paths=["/srv/titanx/refs"]))

    def test_allowed_read_paths_rejects_privileged_subtree(self):
        # /etc/ must never cross the boundary, even read-only.
        with pytest.raises(PolicyValidationError, match="privileged system"):
            validate_policy(AgentPolicy(allowed_read_paths=["/etc/passwd"]))

    def test_allowed_read_paths_rejects_proc(self):
        with pytest.raises(PolicyValidationError, match="privileged"):
            validate_policy(AgentPolicy(allowed_read_paths=["/proc/self"]))

    def test_allowed_read_paths_rejects_root(self):
        with pytest.raises(PolicyValidationError, match="privileged"):
            validate_policy(AgentPolicy(allowed_read_paths=["/"]))

    def test_allowed_read_paths_rejects_relative(self):
        with pytest.raises(PolicyValidationError, match="absolute"):
            validate_policy(AgentPolicy(allowed_read_paths=["refs/data"]))

    def test_allowed_read_paths_rejects_non_list(self):
        # The validator falls back to an empty list via ``getattr`` so
        # we have to set the attribute directly to provoke the type
        # error. dataclasses don't enforce types at runtime.
        bad = AgentPolicy()
        bad.allowed_read_paths = "/srv/titanx/refs"  # type: ignore[assignment]
        with pytest.raises(PolicyValidationError, match="must be a list"):
            validate_policy(bad)


class TestFilesystemFlags:
    def test_write_path_only_yields_rw_mount(self):
        flags = _filesystem_flags(
            read_only_root=True,
            tmpfs_paths=("/tmp",),
            allowed_write_paths=["/srv/titanx/work"],
            allowed_read_paths=None,
        )
        assert "/srv/titanx/work:/srv/titanx/work:rw" in " ".join(flags)
        assert ":ro" not in " ".join(flags)

    def test_read_path_only_yields_ro_mount(self):
        flags = _filesystem_flags(
            read_only_root=True,
            tmpfs_paths=("/tmp",),
            allowed_write_paths=None,
            allowed_read_paths=["/srv/titanx/refs"],
        )
        assert "/srv/titanx/refs:/srv/titanx/refs:ro" in " ".join(flags)
        assert ":rw" not in " ".join(flags)

    def test_both_lists_produce_separate_mounts(self):
        flags = _filesystem_flags(
            read_only_root=True,
            tmpfs_paths=("/tmp",),
            allowed_write_paths=["/srv/titanx/work"],
            allowed_read_paths=["/srv/titanx/refs"],
        )
        joined = " ".join(flags)
        assert "/srv/titanx/work:/srv/titanx/work:rw" in joined
        assert "/srv/titanx/refs:/srv/titanx/refs:ro" in joined

    def test_overlap_drops_ro_keeps_rw(self):
        # If the same path appears in both lists the read-only mount
        # would shadow the writable one (Docker keeps the last bind),
        # producing a confusing security posture. The flag builder
        # silently drops the duplicate :ro entry; the writable mount
        # wins.
        flags = _filesystem_flags(
            read_only_root=True,
            tmpfs_paths=("/tmp",),
            allowed_write_paths=["/srv/titanx/work"],
            allowed_read_paths=["/srv/titanx/work"],
        )
        joined = " ".join(flags)
        assert "/srv/titanx/work:/srv/titanx/work:rw" in joined
        assert "/srv/titanx/work:/srv/titanx/work:ro" not in joined

    def test_read_path_validation_runs_at_flag_layer(self):
        # Defense in depth: even if a rogue caller bypasses
        # PolicyStore.set and constructs a SandboxExecutionRequest
        # directly, the bind-mount layer must still refuse privileged
        # subtrees.
        with pytest.raises(PolicyValidationError, match="privileged"):
            _filesystem_flags(
                read_only_root=True,
                tmpfs_paths=(),
                allowed_write_paths=None,
                allowed_read_paths=["/etc/passwd"],
            )

    def test_read_only_root_off_returns_no_flags(self):
        # Opt-out: if the operator disables hardening we don't emit
        # any --read-only / -v flags. The audit module flags this as
        # a separate finding.
        flags = _filesystem_flags(
            read_only_root=False,
            tmpfs_paths=("/tmp",),
            allowed_write_paths=["/srv/titanx/work"],
            allowed_read_paths=["/srv/titanx/refs"],
        )
        assert flags == []


class TestAuditOverlapWarning:
    def test_overlap_between_read_and_write_is_flagged(self):
        # Real-world misconfig: an operator copy-pastes the same path
        # into both lists thinking it's "extra safe". The audit
        # surfaces this so they can pick one.
        policy = AgentPolicy(
            allowed_write_paths=["/srv/titanx/work"],
            allowed_read_paths=["/srv/titanx/work"],
        )
        report = audit_policy(policy)
        # Look for an explicit overlap finding rather than just any
        # warning so future warnings don't make the test pass for the
        # wrong reason.
        ids = {f.check_id for f in report.findings}
        assert any("overlap" in fid for fid in ids), (
            f"expected an overlap finding, got {ids}"
        )

    def test_no_overlap_no_warning(self):
        policy = AgentPolicy(
            allowed_write_paths=["/srv/titanx/work"],
            allowed_read_paths=["/srv/titanx/refs"],
        )
        report = audit_policy(policy)
        overlap = [
            f for f in report.findings if "overlap" in f.check_id
        ]
        assert overlap == []
