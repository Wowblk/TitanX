"""Static security scanner for externally sourced TitanX packages.

The scanner is the pre-install / pre-registration counterpart to the
runtime sandbox backends. It does not execute package code. Instead, it
looks for high-signal patterns that indicate a package may try to
exfiltrate secrets, inject instructions, persist across sessions, run
dangerous commands, or smuggle suspicious files.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


PackageTrustLevel = Literal["builtin", "trusted", "community", "agent-created"]
PackageVerdict = Literal["safe", "caution", "dangerous"]
PackageInstallDecision = Literal["allow", "block", "ask"]


TRUSTED_SOURCES: frozenset[str] = frozenset({
    "openai/skills",
    "anthropics/skills",
})

INSTALL_POLICY: dict[PackageTrustLevel, tuple[PackageInstallDecision, PackageInstallDecision, PackageInstallDecision]] = {
    #                    safe     caution  dangerous
    "builtin":       ("allow", "allow", "allow"),
    "trusted":       ("allow", "allow", "block"),
    "community":     ("allow", "block", "block"),
    "agent-created": ("allow", "allow", "ask"),
}

_VERDICT_INDEX: dict[PackageVerdict, int] = {"safe": 0, "caution": 1, "dangerous": 2}


@dataclass(frozen=True)
class ThreatPattern:
    regex: re.Pattern[str]
    pattern_id: str
    severity: Literal["critical", "high", "medium", "low"]
    category: str
    description: str


@dataclass(frozen=True)
class PackageFinding:
    pattern_id: str
    severity: Literal["critical", "high", "medium", "low"]
    category: str
    file: str
    line: int
    match: str
    description: str


@dataclass(frozen=True)
class PackageScanResult:
    package_name: str
    package_type: str
    source: str
    trust_level: PackageTrustLevel
    verdict: PackageVerdict
    findings: tuple[PackageFinding, ...] = field(default_factory=tuple)
    scanned_at: str = ""
    content_hash: str = ""
    summary: str = ""

    @property
    def hit(self) -> bool:
        return bool(self.findings)


@dataclass(frozen=True)
class PackageInstallCheck:
    allowed: bool | None
    decision: PackageInstallDecision
    reason: str


THREAT_PATTERNS: tuple[ThreatPattern, ...] = (
    # Exfiltration and secret access
    ThreatPattern(re.compile(r"curl\s+[^\n]*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API)", re.I), "env_exfil_curl", "critical", "exfiltration", "curl command interpolating secret environment variable"),
    ThreatPattern(re.compile(r"wget\s+[^\n]*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API)", re.I), "env_exfil_wget", "critical", "exfiltration", "wget command interpolating secret environment variable"),
    ThreatPattern(re.compile(r"requests\.(get|post|put|patch)\s*\([^\n]*(KEY|TOKEN|SECRET|PASSWORD)", re.I), "env_exfil_requests", "critical", "exfiltration", "requests call with secret variable"),
    ThreatPattern(re.compile(r"httpx?\.(get|post|put|patch)\s*\([^\n]*(KEY|TOKEN|SECRET|PASSWORD)", re.I), "env_exfil_httpx", "critical", "exfiltration", "HTTP client call with secret variable"),
    ThreatPattern(re.compile(r"\$HOME/\.(ssh|aws|kube|docker|gnupg)|~/\.(ssh|aws|kube|docker|gnupg)", re.I), "credential_dir_access", "high", "exfiltration", "references a user credential directory"),
    ThreatPattern(re.compile(r"\$HOME/\.titanx/\.env|~/\.titanx/\.env|\$HOME/\.hermes/\.env|~/\.hermes/\.env", re.I), "agent_env_access", "critical", "exfiltration", "directly references agent secrets file"),
    ThreatPattern(re.compile(r"cat\s+[^\n]*(\.env|credentials|\.netrc|\.pgpass|\.npmrc|\.pypirc)", re.I), "read_secrets_file", "critical", "exfiltration", "reads known secrets file"),
    ThreatPattern(re.compile(r"printenv|env\s*\|", re.I), "dump_all_env", "high", "exfiltration", "dumps all environment variables"),
    ThreatPattern(re.compile(r"os\.environ\b(?!\s*\.get\s*\(\s*['\"]PATH)", re.I), "python_os_environ", "high", "exfiltration", "accesses os.environ"),
    ThreatPattern(re.compile(r"os\.getenv\s*\(\s*[^\)]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.I), "python_getenv_secret", "critical", "exfiltration", "reads secret via os.getenv()"),
    ThreatPattern(re.compile(r"process\.env\[", re.I), "node_process_env", "high", "exfiltration", "accesses Node.js environment"),
    ThreatPattern(re.compile(r"\b(dig|nslookup|host)\s+[^\n]*\$", re.I), "dns_exfil", "critical", "exfiltration", "DNS lookup with variable interpolation"),
    ThreatPattern(re.compile(r"(send|post|upload|transmit)\s+.*\s+(to|at)\s+https?://", re.I), "send_to_url", "high", "exfiltration", "instructs agent to send data to a URL"),
    ThreatPattern(re.compile(r"(include|output|print|send|share)\s+(?:\w+\s+)*(conversation|chat\s+history|previous\s+messages|context)", re.I), "context_exfil", "high", "exfiltration", "instructs agent to output/share conversation history"),

    # Prompt injection
    ThreatPattern(re.compile(r"ignore\s+(?:\w+\s+)*(previous|all|above|prior)\s+instructions", re.I), "prompt_injection_ignore", "critical", "injection", "prompt injection: ignore previous instructions"),
    ThreatPattern(re.compile(r"disregard\s+(?:\w+\s+)*(your|all|any)\s+(?:\w+\s+)*(instructions|rules|guidelines)", re.I), "disregard_rules", "critical", "injection", "instructs agent to disregard rules"),
    ThreatPattern(re.compile(r"do\s+not\s+(?:\w+\s+)*tell\s+(?:\w+\s+)*the\s+user", re.I), "deception_hide", "critical", "injection", "instructs agent to hide information from user"),
    ThreatPattern(re.compile(r"output\s+(?:\w+\s+)*(system|initial)\s+prompt", re.I), "leak_system_prompt", "high", "injection", "attempts to extract the system prompt"),
    ThreatPattern(re.compile(r"system\s+prompt\s+override", re.I), "sys_prompt_override", "critical", "injection", "attempts to override the system prompt"),
    ThreatPattern(re.compile(r"\bDAN\s+mode\b|Do\s+Anything\s+Now|developer\s+mode.*enabled?", re.I), "jailbreak", "critical", "injection", "jailbreak attempt"),
    ThreatPattern(re.compile(r"<!--[^>]*(ignore|override|system|secret|hidden)[^>]*-->", re.I), "html_comment_injection", "high", "injection", "hidden instructions in HTML comments"),
    ThreatPattern(re.compile(r"<\s*div\s+style\s*=\s*['\"][\s\S]*?display\s*:\s*none", re.I), "hidden_div", "high", "injection", "hidden HTML div"),

    # Destructive operations and persistence
    ThreatPattern(re.compile(r"rm\s+-rf\s+/", re.I), "destructive_root_rm", "critical", "destructive", "recursive delete from root"),
    ThreatPattern(re.compile(r"rm\s+(-[^\s]*)?r.*\$HOME|\brmdir\s+.*\$HOME", re.I), "destructive_home_rm", "critical", "destructive", "recursive delete targeting home directory"),
    ThreatPattern(re.compile(r"\bmkfs\b", re.I), "format_filesystem", "critical", "destructive", "formats a filesystem"),
    ThreatPattern(re.compile(r"\bdd\s+.*if=.*of=/dev/", re.I), "disk_overwrite", "critical", "destructive", "raw disk write operation"),
    ThreatPattern(re.compile(r"shutil\.rmtree\s*\(\s*['\"/]", re.I), "python_rmtree", "high", "destructive", "Python rmtree on absolute or root-relative path"),
    ThreatPattern(re.compile(r"\bcrontab\b", re.I), "persistence_cron", "medium", "persistence", "modifies cron jobs"),
    ThreatPattern(re.compile(r"\.(bashrc|zshrc|profile|bash_profile|zprofile)\b", re.I), "shell_rc_mod", "medium", "persistence", "references shell startup file"),
    ThreatPattern(re.compile(r"authorized_keys", re.I), "ssh_backdoor", "critical", "persistence", "modifies SSH authorized keys"),
    ThreatPattern(re.compile(r"systemd.*\.service|systemctl\s+(enable|start)", re.I), "systemd_service", "medium", "persistence", "references or enables systemd service"),
    ThreatPattern(re.compile(r"launchctl\s+load|LaunchAgents|LaunchDaemons", re.I), "macos_launchd", "medium", "persistence", "macOS launch agent/daemon persistence"),
    ThreatPattern(re.compile(r"/etc/sudoers|visudo|NOPASSWD", re.I), "sudoers_mod", "critical", "persistence", "sudoers modification"),
    ThreatPattern(re.compile(r"AGENTS\.md|CLAUDE\.md|\.cursorrules|\.clinerules|\.codex/config|\.titanx/config|\.hermes/config\.yaml", re.I), "agent_config_mod", "critical", "persistence", "references agent configuration files"),

    # Network backdoors and tunnels
    ThreatPattern(re.compile(r"\bnc\s+-[lp]|ncat\s+-[lp]|\bsocat\b", re.I), "reverse_shell", "critical", "network", "potential reverse shell listener"),
    ThreatPattern(re.compile(r"\bngrok\b|\blocaltunnel\b|\bserveo\b|\bcloudflared\b", re.I), "tunnel_service", "high", "network", "uses tunneling service for external access"),
    ThreatPattern(re.compile(r"/bin/(ba)?sh\s+-i\s+.*>/dev/tcp/", re.I), "bash_reverse_shell", "critical", "network", "bash interactive reverse shell via /dev/tcp"),
    ThreatPattern(re.compile(r"python[23]?\s+-c\s+['\"]import\s+socket", re.I), "python_socket_oneliner", "critical", "network", "Python one-liner socket connection"),
    ThreatPattern(re.compile(r"socket\.connect\s*\(\s*\(", re.I), "python_socket_connect", "high", "network", "Python socket connect to arbitrary host"),
    ThreatPattern(re.compile(r"webhook\.site|requestbin\.com|pipedream\.net|hookbin\.com", re.I), "exfil_service", "high", "network", "known webhook/exfiltration service"),
    ThreatPattern(re.compile(r"pastebin\.com|hastebin\.com|ghostbin\.", re.I), "paste_service", "medium", "network", "paste service reference"),

    # Obfuscation, execution, and supply chain
    ThreatPattern(re.compile(r"base64\s+(-d|--decode)\s*\|", re.I), "base64_decode_pipe", "high", "obfuscation", "base64 decodes and pipes to execution"),
    ThreatPattern(re.compile(r"\beval\s*\(\s*['\"]", re.I), "eval_string", "high", "obfuscation", "eval() with string argument"),
    ThreatPattern(re.compile(r"\bexec\s*\(\s*['\"]", re.I), "exec_string", "high", "obfuscation", "exec() with string argument"),
    ThreatPattern(re.compile(r"echo\s+[^\n]*\|\s*(bash|sh|python|perl|ruby|node)", re.I), "echo_pipe_exec", "critical", "obfuscation", "echo piped to interpreter"),
    ThreatPattern(re.compile(r"subprocess\.(run|call|Popen|check_output)\s*\(", re.I), "python_subprocess", "medium", "execution", "Python subprocess execution"),
    ThreatPattern(re.compile(r"os\.system\s*\(", re.I), "python_os_system", "high", "execution", "os.system() shell execution"),
    ThreatPattern(re.compile(r"child_process\.(exec|spawn|fork)\s*\(", re.I), "node_child_process", "high", "execution", "Node.js child_process execution"),
    ThreatPattern(re.compile(r"curl\s+[^\n]*\|\s*(ba)?sh", re.I), "curl_pipe_shell", "critical", "supply_chain", "curl piped to shell"),
    ThreatPattern(re.compile(r"wget\s+[^\n]*-O\s*-\s*\|\s*(ba)?sh", re.I), "wget_pipe_shell", "critical", "supply_chain", "wget piped to shell"),
    ThreatPattern(re.compile(r"pip\s+install\s+(?!-r\s)(?!.*==)", re.I), "unpinned_pip_install", "medium", "supply_chain", "pip install without version pinning"),
    ThreatPattern(re.compile(r"npm\s+install\s+(?!.*@\d)", re.I), "unpinned_npm_install", "medium", "supply_chain", "npm install without version pinning"),
    ThreatPattern(re.compile(r"git\s+clone\s+", re.I), "git_clone", "medium", "supply_chain", "clones a git repository at runtime"),
    ThreatPattern(re.compile(r"docker\s+pull\s+", re.I), "docker_pull", "medium", "supply_chain", "pulls a Docker image at runtime"),

    # Privilege escalation and embedded credentials
    ThreatPattern(re.compile(r"^allowed-tools\s*:", re.I | re.M), "allowed_tools_field", "high", "privilege_escalation", "package declares pre-approved tool access"),
    ThreatPattern(re.compile(r"\bsudo\b", re.I), "sudo_usage", "high", "privilege_escalation", "uses sudo"),
    ThreatPattern(re.compile(r"setuid|setgid|cap_setuid", re.I), "setuid_setgid", "critical", "privilege_escalation", "setuid/setgid privilege escalation"),
    ThreatPattern(re.compile(r"chmod\s+[u+]?s", re.I), "suid_bit", "critical", "privilege_escalation", "sets SUID/SGID bit"),
    ThreatPattern(re.compile(r"(api[_-]?key|token|secret|password)\s*[=:]\s*['\"][A-Za-z0-9+/=_-]{20,}", re.I), "hardcoded_secret", "critical", "credential_exposure", "possible hardcoded secret"),
    ThreatPattern(re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----", re.I), "embedded_private_key", "critical", "credential_exposure", "embedded private key"),
    ThreatPattern(re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,}", re.I), "github_token_leaked", "critical", "credential_exposure", "GitHub token in package content"),
    ThreatPattern(re.compile(r"sk-ant-[A-Za-z0-9_-]{40,}", re.I), "anthropic_key_leaked", "critical", "credential_exposure", "possible Anthropic API key"),
    ThreatPattern(re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_leaked", "critical", "credential_exposure", "AWS access key ID"),
)


SCANNABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".md", ".txt", ".py", ".sh", ".bash", ".js", ".ts", ".rb",
    ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf",
    ".html", ".css", ".xml", ".tex", ".r", ".jl", ".pl", ".php",
})

SUSPICIOUS_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".com",
    ".msi", ".dmg", ".app", ".deb", ".rpm",
})

INVISIBLE_CHARS: frozenset[str] = frozenset({
    "\u200b", "\u200c", "\u200d", "\u2060", "\u2062", "\u2063",
    "\u2064", "\ufeff", "\u202a", "\u202b", "\u202c", "\u202d",
    "\u202e", "\u2066", "\u2067", "\u2068", "\u2069",
})

MAX_FILE_COUNT = 50
MAX_TOTAL_SIZE_BYTES = 1024 * 1024
MAX_SINGLE_FILE_BYTES = 256 * 1024


def scan_package(
    package_path: str | Path,
    *,
    source: str = "community",
    package_type: str = "package",
) -> PackageScanResult:
    """Scan a package directory or single package file.

    ``package_type`` is metadata for audit and policy callers. Examples:
    ``"skill"``, ``"mcp"``, ``"wasm_tool"``, and ``"script_tool"``.
    """
    path = Path(package_path)
    trust_level = resolve_trust_level(source)
    findings: list[PackageFinding] = []

    if path.is_dir():
        findings.extend(_check_structure(path))
        for item in path.rglob("*"):
            if item.is_file():
                findings.extend(scan_file(item, item.relative_to(path).as_posix()))
    elif path.is_file():
        findings.extend(scan_file(path, path.name))
    else:
        findings.append(PackageFinding(
            pattern_id="missing_package",
            severity="critical",
            category="structural",
            file=str(path),
            line=0,
            match="path does not exist",
            description="package path does not exist",
        ))

    verdict = determine_verdict(findings)
    return PackageScanResult(
        package_name=path.name,
        package_type=package_type,
        source=source,
        trust_level=trust_level,
        verdict=verdict,
        findings=tuple(findings),
        scanned_at=datetime.now(timezone.utc).isoformat(),
        content_hash=content_hash(path),
        summary=_build_summary(path.name, package_type, verdict, findings),
    )


def scan_file(file_path: str | Path, rel_path: str | None = None) -> list[PackageFinding]:
    """Scan one text file for threat patterns and invisible Unicode."""
    path = Path(file_path)
    rel = rel_path or path.name
    if path.suffix.lower() not in SCANNABLE_EXTENSIONS and path.name not in {"SKILL.md", "AGENTS.md"}:
        return []
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[PackageFinding] = []
    lines = content.splitlines()
    seen: set[tuple[str, int]] = set()
    for threat in THREAT_PATTERNS:
        for idx, line in enumerate(lines, start=1):
            key = (threat.pattern_id, idx)
            if key in seen or not threat.regex.search(line):
                continue
            seen.add(key)
            match = line.strip()
            if len(match) > 120:
                match = match[:117] + "..."
            findings.append(PackageFinding(
                pattern_id=threat.pattern_id,
                severity=threat.severity,
                category=threat.category,
                file=rel,
                line=idx,
                match=match,
                description=threat.description,
            ))

    for idx, line in enumerate(lines, start=1):
        for char in INVISIBLE_CHARS:
            if char in line:
                findings.append(PackageFinding(
                    pattern_id="invisible_unicode",
                    severity="high",
                    category="injection",
                    file=rel,
                    line=idx,
                    match=f"U+{ord(char):04X}",
                    description="invisible unicode character that can hide instructions",
                ))
                break
    return findings


def check_package_install(result: PackageScanResult, *, force: bool = False) -> PackageInstallCheck:
    """Return the trust-aware install decision for a package scan."""
    policy = INSTALL_POLICY.get(result.trust_level, INSTALL_POLICY["community"])
    decision = policy[_VERDICT_INDEX.get(result.verdict, 2)]
    if decision == "allow":
        return PackageInstallCheck(True, decision, f"Allowed ({result.trust_level} source, {result.verdict} verdict)")
    if force:
        return PackageInstallCheck(True, "allow", f"Force-installed despite {result.verdict} verdict ({len(result.findings)} findings)")
    if decision == "ask":
        return PackageInstallCheck(None, decision, f"Requires confirmation ({result.trust_level} source, {result.verdict} verdict, {len(result.findings)} findings)")
    return PackageInstallCheck(False, decision, f"Blocked ({result.trust_level} source, {result.verdict} verdict, {len(result.findings)} findings)")


def format_scan_report(result: PackageScanResult) -> str:
    """Format a compact human-readable scan report."""
    lines = [
        f"Scan: {result.package_name} ({result.package_type}, {result.source}/{result.trust_level}) Verdict: {result.verdict.upper()}",
    ]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for finding in sorted(result.findings, key=lambda f: severity_order.get(f.severity, 4)):
        lines.append(
            f"  {finding.severity.upper().ljust(8)} "
            f"{finding.category.ljust(20)} "
            f"{finding.file}:{finding.line} "
            f"\"{finding.match[:60]}\""
        )
    install = check_package_install(result)
    status = "ALLOWED" if install.allowed is True else "NEEDS CONFIRMATION" if install.allowed is None else "BLOCKED"
    lines.append(f"Decision: {status} - {install.reason}")
    return "\n".join(lines)


def resolve_trust_level(source: str) -> PackageTrustLevel:
    """Map a source identifier to a trust level."""
    if source == "agent-created":
        return "agent-created"
    if source == "builtin" or source == "official" or source.startswith("official/"):
        return "builtin"
    if any(source == trusted or source.startswith(f"{trusted}/") for trusted in TRUSTED_SOURCES):
        return "trusted"
    return "community"


def determine_verdict(findings: list[PackageFinding]) -> PackageVerdict:
    """Collapse findings into a package verdict."""
    if not findings:
        return "safe"
    if any(f.severity == "critical" for f in findings):
        return "dangerous"
    return "caution"


def content_hash(package_path: str | Path) -> str:
    """Return a short stable SHA-256 hash for package contents."""
    path = Path(package_path)
    digest = hashlib.sha256()
    if path.is_dir():
        for item in sorted(path.rglob("*")):
            if item.is_file() and not item.is_symlink():
                try:
                    digest.update(item.relative_to(path).as_posix().encode())
                    digest.update(b"\0")
                    digest.update(item.read_bytes())
                except OSError:
                    continue
    elif path.is_file():
        try:
            digest.update(path.read_bytes())
        except OSError:
            pass
    else:
        digest.update(str(path).encode())
    return f"sha256:{digest.hexdigest()[:16]}"


def _check_structure(package_dir: Path) -> list[PackageFinding]:
    findings: list[PackageFinding] = []
    file_count = 0
    total_size = 0
    root = package_dir.resolve()

    for item in package_dir.rglob("*"):
        if not item.is_file() and not item.is_symlink():
            continue
        rel = item.relative_to(package_dir).as_posix()
        file_count += 1
        if item.is_symlink():
            try:
                resolved = item.resolve()
                if not resolved.is_relative_to(root):
                    findings.append(PackageFinding("symlink_escape", "critical", "traversal", rel, 0, f"symlink -> {resolved}", "symlink points outside the package directory"))
            except OSError:
                findings.append(PackageFinding("broken_symlink", "medium", "traversal", rel, 0, "broken symlink", "broken or circular symlink"))
            continue
        try:
            size = item.stat().st_size
        except OSError:
            continue
        total_size += size
        if size > MAX_SINGLE_FILE_BYTES:
            findings.append(PackageFinding("oversized_file", "medium", "structural", rel, 0, f"{size // 1024}KB", "file exceeds package scanner single-file limit"))
        ext = item.suffix.lower()
        if ext in SUSPICIOUS_BINARY_EXTENSIONS:
            findings.append(PackageFinding("binary_file", "critical", "structural", rel, 0, f"binary: {ext}", "binary/executable artifact should not be in a package"))
        if ext not in {".sh", ".bash", ".py", ".rb", ".pl"} and item.stat().st_mode & 0o111:
            findings.append(PackageFinding("unexpected_executable", "medium", "structural", rel, 0, "executable bit set", "non-script file has executable permission"))

    if file_count > MAX_FILE_COUNT:
        findings.append(PackageFinding("too_many_files", "medium", "structural", "(directory)", 0, f"{file_count} files", "package has too many files"))
    if total_size > MAX_TOTAL_SIZE_BYTES:
        findings.append(PackageFinding("oversized_package", "high", "structural", "(directory)", 0, f"{total_size // 1024}KB total", "package exceeds total size limit"))
    return findings


def _build_summary(name: str, package_type: str, verdict: PackageVerdict, findings: list[PackageFinding]) -> str:
    if not findings:
        return f"{name}: clean {package_type} scan, no threats detected"
    categories = ", ".join(sorted({finding.category for finding in findings}))
    return f"{name}: {verdict} - {len(findings)} finding(s) in {categories}"
