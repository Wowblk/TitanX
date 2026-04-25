"""TitanX command-line entry point.

Currently exposes one subcommand:

    titanx audit
    titanx audit --policy policy.json --gateway gateway.json --audit-log /var/log/titanx/audit.jsonl
    titanx audit --json
    titanx audit --fix

The audit subcommand is the operator preflight from ``SECURITY.md``.
It loads JSON-formatted ``AgentPolicy`` and ``GatewayOptions``,
inspects on-disk audit-log permissions, and emits either a text table
or a JSON report. ``--fix`` applies the auto-fixable findings
(currently: file/directory permissions only).

Why JSON files instead of a Python config object? The CLI is meant to
be runnable in a deployment context where importing the host's Python
config would pull in side-effecting modules (a real LLM adapter, a
DB connection). Plain JSON keeps the audit a *static* operation.

Exit codes:

- ``0`` — no critical findings (warns / infos may still be present).
- ``2`` — at least one critical finding.
- ``1`` — usage error (file not found, malformed JSON, etc).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import audit as _audit


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="titanx",
        description="TitanX command-line tools (operator preflight).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser(
        "audit",
        help="Static security posture audit of policy/gateway/audit-log/egress.",
    )
    audit.add_argument(
        "--policy",
        type=str,
        help="Path to a JSON file representing an AgentPolicy.",
    )
    audit.add_argument(
        "--gateway",
        type=str,
        help="Path to a JSON file representing GatewayOptions.",
    )
    audit.add_argument(
        "--audit-log",
        type=str,
        help="Path to the JSONL audit log file (or its intended path).",
    )
    audit.add_argument(
        "--egress",
        type=str,
        help="Path to a JSON file representing an EgressPolicy "
             "(see titanx.safety.egress).",
    )
    audit.add_argument(
        "--ironclaw",
        action="store_true",
        help="Build an EgressPolicy from the bundled IronClaw WASM tool "
             "catalog and audit it.",
    )
    audit.add_argument(
        "--preset",
        action="append",
        default=None,
        metavar="NAME",
        help="Compose one or more bundled egress presets and audit the "
             "resulting EgressPolicy. May be repeated. Run with "
             "--preset=help to list the available presets.",
    )
    audit.add_argument(
        "--docker-image",
        type=str,
        help="Docker image string to audit for digest pinning.",
    )
    audit.add_argument(
        "--docker-image-digest",
        type=str,
        help="Optional expected digest (sha256:...) the Docker image "
             "must resolve to.",
    )
    audit.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a human-readable table.",
    )
    audit.add_argument(
        "--fix",
        action="store_true",
        help="Apply auto-fixable findings (currently file permissions). "
             "Pair with --dry-run to preview.",
    )
    audit.add_argument(
        "--dry-run",
        action="store_true",
        help="With --fix: print what would change without applying.",
    )
    audit.add_argument(
        "--fail-on",
        choices=("critical", "warn"),
        default="critical",
        help="Exit with non-zero status when findings of this severity "
             "or worse are present (default: critical).",
    )
    return parser


def _load_json_file(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"titanx audit: file not found: {path}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"titanx audit: invalid JSON in {path}: {exc}")


def _load_egress_policy(path: str):
    from .safety.egress import EgressPolicy, OutboundRule

    raw = _load_json_file(path)
    rules = []
    for entry in raw.get("rules", []):
        rules.append(OutboundRule(
            host_pattern=entry["host_pattern"],
            path_prefix=entry.get("path_prefix", "/"),
            methods=tuple(entry.get("methods", ())),
            allowed_schemes=tuple(entry.get("allowed_schemes", ("https",))),
            allowed_ports=tuple(entry.get("allowed_ports", ())),
            caller=entry.get("caller"),
        ))
    return EgressPolicy(
        rules=rules,
        default_action=raw.get("default_action", "deny"),
    )


def _format_text(report: _audit.AuditReport) -> str:
    summary = report.summary()
    rank = {"critical": 0, "warn": 1, "info": 2, "ok": 3}
    findings = sorted(report.findings, key=lambda f: (rank[f.severity], f.check_id))

    lines: list[str] = []
    badge = {
        "critical": "[CRIT]",
        "warn":     "[WARN]",
        "info":     "[INFO]",
        "ok":       "[ OK ]",
    }
    for f in findings:
        lines.append(f"{badge[f.severity]} {f.check_id}")
        lines.append(f"        {f.title}")
        for d in f.detail.splitlines():
            lines.append(f"        {d}")
        if f.fix_hint:
            lines.append(f"        fix: {f.fix_hint}")
        lines.append("")
    lines.append(
        f"Summary: {summary['critical']} critical, {summary['warn']} warn, "
        f"{summary['info']} info, {summary['ok']} ok ({len(findings)} checks)"
    )
    return "\n".join(lines)


def _run_audit(args: argparse.Namespace) -> int:
    policy = None
    if args.policy:
        policy = _audit.load_policy_from_json(_load_json_file(args.policy))

    gateway = None
    if args.gateway:
        gateway = _audit.load_gateway_options_from_json(_load_json_file(args.gateway))

    egress = None
    preset_names = args.preset or []
    if "help" in preset_names:
        from .safety import presets as _presets
        print("Available egress presets:")
        for name in _presets.available():
            print(f"  - {name}")
        return 0
    if args.egress:
        egress = _load_egress_policy(args.egress)
    elif preset_names:
        from .safety import presets as _presets
        try:
            egress = _presets.compose(preset_names)
        except KeyError as exc:
            raise SystemExit(f"titanx audit: {exc}")
    elif args.ironclaw:
        from .tools import IRONCLAW_WASM_TOOLS
        from .safety.egress import EgressGuard
        egress = EgressGuard.from_ironclaw_specs(IRONCLAW_WASM_TOOLS).policy

    report = _audit.audit_runtime(
        policy=policy,
        gateway=gateway,
        audit_log_path=args.audit_log,
        egress=egress,
    )

    if args.docker_image:
        # Construct a duck-typed options object so we don't have to
        # import the Docker backend (and its asyncio plumbing) at audit
        # time.
        class _DockerOpts:
            image = args.docker_image
            expected_image_digest = args.docker_image_digest
        report.merge(_audit.audit_docker_options(_DockerOpts()))

    if args.fix:
        actions = _audit.apply_fixes(report, dry_run=args.dry_run)
        if args.json:
            payload = json.loads(report.to_json())
            payload["fix_actions"] = actions
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(_format_text(report))
            print()
            print("Fix actions:")
            for action in actions:
                print(f"  - {action}")
            if not actions:
                print("  (no auto-fixable findings)")
    else:
        if args.json:
            print(report.to_json())
        else:
            print(_format_text(report))

    if args.fail_on == "critical" and report.has_critical:
        return 2
    if args.fail_on == "warn" and (report.has_critical or report.has_warn):
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        return _run_audit(args)
    parser.print_help(sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
