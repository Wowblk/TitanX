"""titanx.audit: programmatic security posture audit + CLI smoke.

Asserts:

- ``audit_policy`` flags privileged paths as critical, ``auto_approve_tools``
  and empty allowlist as warns, and clean policies as ``ok``.
- ``audit_gateway_options`` flags missing api_key as critical, CORS
  wildcard as warn.
- ``audit_audit_log_path`` catches world-writable / world-readable
  perms and ``apply_fixes`` repairs them.
- ``audit_egress_policy`` flags default-allow as critical and unconfigured
  egress as warn.
- The CLI exits with code 2 on critical findings and 0 on a clean run.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from titanx.audit import (
    apply_fixes,
    audit_audit_log_path,
    audit_egress_policy,
    audit_gateway_options,
    audit_policy,
    audit_runtime,
)
from titanx.gateway.types import GatewayOptions
from titanx.policy.types import AgentPolicy
from titanx.safety.egress import EgressPolicy, OutboundRule


# ── policy ────────────────────────────────────────────────────────────────


class TestAuditPolicy:
    def test_clean_policy_is_ok(self):
        report = audit_policy(AgentPolicy(
            allowed_write_paths=["/srv/titanx/work"],
            auto_approve_tools=False,
            max_iterations=10,
            tool_denylist=["shell"],
        ))
        assert not report.has_critical
        assert any(f.check_id == "policy.validate_policy" and f.severity == "ok"
                   for f in report.findings)
        assert any(f.check_id == "policy.auto_approve_tools.disabled"
                   for f in report.findings)

    def test_privileged_path_is_critical(self):
        report = audit_policy(AgentPolicy(allowed_write_paths=["/etc"]))
        assert report.has_critical
        assert any(f.check_id == "policy.validate_policy"
                   and f.severity == "critical"
                   for f in report.findings)

    def test_auto_approve_is_warn(self):
        report = audit_policy(AgentPolicy(
            allowed_write_paths=["/srv/titanx/work"],
            auto_approve_tools=True,
        ))
        assert any(f.check_id == "policy.auto_approve_tools.enabled"
                   and f.severity == "warn"
                   for f in report.findings)

    def test_empty_allowlist_is_warn(self):
        report = audit_policy(AgentPolicy())
        assert any(f.check_id == "policy.allowed_write_paths.empty"
                   for f in report.findings)

    def test_high_max_iterations_is_warn(self):
        report = audit_policy(AgentPolicy(
            allowed_write_paths=["/srv/titanx/work"],
            max_iterations=5_000,
        ))
        assert any(f.check_id == "policy.max_iterations.high"
                   for f in report.findings)


# ── gateway ───────────────────────────────────────────────────────────────


class TestAuditGateway:
    def test_missing_api_key_is_critical(self):
        opts = GatewayOptions(create_runtime=lambda *a, **k: None)  # type: ignore[arg-type]
        report = audit_gateway_options(opts)
        assert any(f.check_id == "gateway.api_key.unset"
                   and f.severity == "critical"
                   for f in report.findings)

    def test_cors_wildcard_is_warn(self):
        opts = GatewayOptions(
            api_key="secret",
            allowed_origins=["*"],
            create_runtime=lambda *a, **k: None,  # type: ignore[arg-type]
        )
        report = audit_gateway_options(opts)
        assert any(f.check_id == "gateway.cors.wildcard"
                   and f.severity == "warn"
                   for f in report.findings)

    def test_clean_gateway_no_warns(self):
        opts = GatewayOptions(
            api_key="x" * 32,
            allowed_origins=["https://app.example"],
            create_runtime=lambda *a, **k: None,  # type: ignore[arg-type]
        )
        report = audit_gateway_options(opts)
        assert not report.has_critical
        assert not report.has_warn


# ── audit-log file ────────────────────────────────────────────────────────


class TestAuditAuditLog:
    def test_unconfigured_is_warn(self):
        report = audit_audit_log_path(None)
        assert any(f.check_id == "audit_log.unconfigured"
                   and f.severity == "warn"
                   for f in report.findings)

    def test_world_writable_is_critical(self, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        log.write_text("{}\n")
        os.chmod(log, 0o666)
        report = audit_audit_log_path(str(log))
        assert any(f.check_id == "audit_log.world_writable"
                   and f.severity == "critical"
                   for f in report.findings)

    def test_world_readable_is_warn(self, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        log.write_text("{}\n")
        os.chmod(log, 0o644)
        report = audit_audit_log_path(str(log))
        assert any(f.check_id == "audit_log.world_readable"
                   for f in report.findings)

    def test_apply_fixes_chmods_log(self, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        log.write_text("{}\n")
        os.chmod(log, 0o666)
        report = audit_audit_log_path(str(log))
        actions = apply_fixes(report)
        # File must now be 0o600.
        mode = stat.S_IMODE(log.stat().st_mode)
        assert mode == 0o600
        assert any("applied" in a for a in actions)

    def test_apply_fixes_dry_run(self, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        log.write_text("{}\n")
        os.chmod(log, 0o666)
        report = audit_audit_log_path(str(log))
        actions = apply_fixes(report, dry_run=True)
        # File mode must be unchanged.
        assert stat.S_IMODE(log.stat().st_mode) == 0o666
        assert any("would chmod" in a for a in actions)


# ── egress ────────────────────────────────────────────────────────────────


class TestAuditEgress:
    def test_unconfigured_is_warn(self):
        report = audit_egress_policy(None)
        assert any(f.check_id == "egress.unconfigured"
                   for f in report.findings)

    def test_default_allow_is_critical(self):
        report = audit_egress_policy(EgressPolicy(rules=[], default_action="allow"))
        assert any(f.check_id == "egress.default_allow"
                   and f.severity == "critical"
                   for f in report.findings)

    def test_plaintext_rule_is_warn(self):
        policy = EgressPolicy(
            rules=[OutboundRule("api.example.com", allowed_schemes=("http", "https"))],
            default_action="deny",
        )
        report = audit_egress_policy(policy)
        assert any("allows_plaintext" in f.check_id for f in report.findings)


# ── composite ─────────────────────────────────────────────────────────────


class TestAuditRuntime:
    def test_composite_runs_every_supplied_check(self):
        report = audit_runtime(
            policy=AgentPolicy(allowed_write_paths=["/srv/titanx/work"]),
            gateway=GatewayOptions(
                api_key="x" * 32,
                create_runtime=lambda *a, **k: None,  # type: ignore[arg-type]
            ),
            audit_log_path=None,
            egress=None,
        )
        ids = {f.check_id for f in report.findings}
        assert "policy.validate_policy" in ids
        assert "gateway.api_key.set" in ids
        assert "audit_log.unconfigured" in ids
        assert "egress.unconfigured" not in ids  # only when egress supplied


# ── CLI smoke ────────────────────────────────────────────────────────────


class TestCli:
    def _run_cli(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "titanx.cli", *args],
            capture_output=True,
            text=True,
        )

    def test_clean_audit_exits_zero(self, tmp_path: Path):
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps({
            "allowed_write_paths": ["/srv/titanx/work"],
            "auto_approve_tools": False,
            "max_iterations": 10,
            "tool_denylist": [],
        }))
        log = tmp_path / "audit.jsonl"
        log.write_text("{}\n")
        os.chmod(log, 0o600)

        result = self._run_cli([
            "audit",
            "--policy", str(policy_path),
            "--audit-log", str(log),
        ])
        assert result.returncode == 0, result.stdout + result.stderr

    def test_critical_finding_exits_two(self, tmp_path: Path):
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps({
            "allowed_write_paths": ["/etc"],
            "auto_approve_tools": True,
        }))
        result = self._run_cli([
            "audit",
            "--policy", str(policy_path),
        ])
        assert result.returncode == 2

    def test_json_output_is_parseable(self, tmp_path: Path):
        result = self._run_cli(["audit", "--ironclaw", "--json"])
        # ironclaw alone should not be critical.
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert "findings" in payload
        assert "summary" in payload

    def test_fail_on_warn_promotes_warns(self, tmp_path: Path):
        # Empty policy → warn (allowed_write_paths empty), no critical.
        # With --fail-on=warn the CLI must exit 2.
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps({"allowed_write_paths": []}))
        result = self._run_cli([
            "audit",
            "--policy", str(policy_path),
            "--fail-on", "warn",
        ])
        assert result.returncode == 2
