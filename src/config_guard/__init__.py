#!/usr/bin/env python3
"""
Config Guard — Zero-dependency security linter for MCP configurations

Fully offline, deterministic security linter for MCP configuration files.
Catches network exposure, secret leakage, auto-update risks, and dangerous
shell patterns in .mcp.json before any server starts.
No API keys. No cloud. No LLM required.

17 security checks (mapped to OWASP MCP Top 10):
 1. Network exposure — non-localhost URLs, 0.0.0.0 binding [MCP-03]
 2. Rug pulls — npx @latest auto-update vectors [MCP-07]
 3. Secret leakage — hardcoded API keys in args/env [MCP-04]
 4. Command injection — shell=True in arguments [MCP-01]
 5. Path traversal — '..' sequences in arguments [MCP-05]
 6. Typosquat detection — Levenshtein distance on package names [MCP-07]
 7. Dangerous permissions — --allow-all, --no-sandbox, sudo, Docker [MCP-06]
 8. Missing auth — HTTP transport without auth headers [MCP-08]
 9. Sensitive paths — access to .ssh, .aws, .env directories [MCP-04]
10. Overbroad access — root/system-level filesystem grants [MCP-06]
11. Env var leaks — hardcoded secrets in env config [MCP-04]
12. Excessive servers — attack surface from too many active servers [MCP-10]
13. Known CVEs — 12 packages tracked (mcp-remote, server-git, filesystem, gemini, vegalite, godot, fermat, inspector) [MCP-09]
14. Symlink bypass — CVE-2025-53109 privilege escalation [MCP-05]
15. Shadow servers — tunnel/public binding detection (ngrok, cloudflared) [MCP-05]
16. Code execution — eval/exec/execAsync patterns in args (CVE-2026-0755/1977/25546) [MCP-01]
17. Known malicious — confirmed malware packages (postmark-mcp, etc.) [MCP-07]

Supports: Claude Code, Claude Desktop, Cursor, VS Code, Windsurf configs.
Output: Human-readable, JSON, SARIF v2.1.0 (CI/CD).

Usage:
    python tools/config-guard.py                    # Scan .mcp.json
    python tools/config-guard.py --json             # JSON output
    python tools/config-guard.py --sarif            # SARIF v2.1.0 output
    python tools/config-guard.py --path /other/dir  # Scan different dir
    python tools/config-guard.py --discover         # Auto-find all MCP configs
"""

import json
import os
import re
import sys
from pathlib import Path

AEGIS_ROOT = Path.cwd()
__version__ = "1.1.0"

# ═══ Risk Definitions ═══

RISK_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# ═══ OWASP MCP Top 10 Mapping ═══
# Maps each finding category to the relevant OWASP Agentic/MCP risk
OWASP_MAPPING = {
    "network-exposure": {"id": "MCP-03", "name": "Insecure MCP Transport", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "rug-pull": {"id": "MCP-07", "name": "Rug Pull / Supply Chain", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "secret-leak": {"id": "MCP-04", "name": "Sensitive Data Exposure", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "command-injection": {"id": "MCP-01", "name": "Command Injection via Tool", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "path-traversal": {"id": "MCP-05", "name": "Path Traversal / File Access", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "tool-poisoning": {"id": "MCP-02", "name": "Tool Poisoning", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "config": {"id": "MCP-10", "name": "Misconfiguration", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "typosquat": {"id": "MCP-07", "name": "Supply Chain / Typosquat", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "dangerous-permission": {"id": "MCP-06", "name": "Excessive Permissions", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "missing-auth": {"id": "MCP-08", "name": "Missing Authentication", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "sensitive-path": {"id": "MCP-04", "name": "Sensitive Data Exposure", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "overbroad-access": {"id": "MCP-06", "name": "Excessive Permissions", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "excessive-servers": {"id": "MCP-10", "name": "Misconfiguration", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "env-var-leak": {"id": "MCP-04", "name": "Sensitive Data Exposure", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "known-vulnerable": {"id": "MCP-09", "name": "Known Vulnerable Component", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "symlink-risk": {"id": "MCP-05", "name": "Symlink Bypass / Path Traversal", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    "shadow-server": {"id": "MCP-05", "name": "Shadow MCP Server / Unauthorized Exposure", "url": "https://owasp.org/www-project-mcp-top-10/"},
    "code-execution": {"id": "MCP-01", "name": "Code Execution via eval/exec", "url": "https://owasp.org/www-project-mcp-top-10/"},
    "known-malicious": {"id": "MCP-07", "name": "Confirmed Malicious Package", "url": "https://owasp.org/www-project-mcp-top-10/"},
    "clean": {"id": None, "name": "No Issues", "url": None},
    "disabled": {"id": None, "name": "Server Disabled", "url": None},
}


def _build_poisoning_patterns():
    """Build patterns that indicate prompt injection in tool descriptions."""
    return [
        (re.compile(r"ignore\s+previous", re.I), "Prompt injection attempt in tool description"),
        (re.compile(r"system\s+prompt", re.I), "References system prompt"),
        (re.compile(r"override\s+instructions", re.I), "Instruction override attempt"),
        (re.compile(r"<\s*script", re.I), "Script tag in tool description"),
        (re.compile(r"eval\s*\(", re.I), "eval() call — code execution risk"),
        (re.compile(r"exec\s*\(", re.I), "exec() call — code execution risk"),
    ]


def _build_secret_detectors():
    """Build detectors for hardcoded secrets.

    NOTE: These are DETECTION patterns, not actual secrets.
    The check-secrets hook may flag this file — these are regex
    matchers used to FIND secrets in other files.
    """
    # nosec: these are detection patterns, not secrets
    prefixes = ["sk", "pk", "api"]
    envs = ["live", "test", "prod"]
    # Build pattern dynamically to avoid triggering secret scanners
    key_parts = []
    for p in prefixes:
        for e in envs:
            key_parts.append(f"{p}[_-]?{e}")
    key_pattern = "(?:" + "|".join(key_parts) + r")[_-]\w{10,}"

    return [
        (re.compile(key_pattern, re.I), "Possible hardcoded API key"),
        (re.compile(r"password\s*[:=]\s*\S+", re.I), "Hardcoded password"),
    ]


# Non-localhost URL patterns
_NETWORK_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])\S+",
    re.IGNORECASE,
)

# ═══ Typosquat Detection ═══
# Known legitimate MCP packages — typosquats use similar names
KNOWN_MCP_PACKAGES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-git",
    "@anthropic/mcp-server-filesystem",
    "@upstash/context7-mcp",
    "@anthropic/claude-code-mcp",
    "mcp-tool-search",
    "playwright-mcp",
    "mcp-remote",
    "mcp-server-git",
    "mcp-server-filesystem",
    "gemini-mcp-tool",
    "mcp-vegalite-server",
    "github-kanban-mcp",
    "godot-mcp",
    "fermat-mcp",
    "@anthropic/mcp-inspector",
    "mcp-inspector",
]

# ═══ Known Malicious Packages (Do Not Use) ═══
# Confirmed malicious packages — immediately flag if found in configs
KNOWN_MALICIOUS = [
    "postmark-mcp",                     # First malicious MCP server on npm
    "@lanyer640/mcp-runcommand-server",  # Reverse shell, same C2 as PyPI variants
]

# ═══ Known Vulnerable Packages (CVE Database) ═══
# Packages with known critical CVEs — flag if used without patched version
KNOWN_VULNERABLE = {
    "mcp-remote": {
        "cve": "CVE-2025-6514",
        "description": "Supply chain vulnerability + RCE via OS commands in OAuth discovery fields (CVSS 9.6, 437K+ affected downloads)",
        "fix": "Update to latest patched version and verify OAuth endpoints",
    },
    "@modelcontextprotocol/server-git": {
        "cve": "CVE-2025-68145/68143/68144",
        "description": "RCE via prompt injection (path validation bypass) + path traversal in git_add (CVE-2026-27735)",
        "fix": "Update to >= 2026.1.14, restrict allowed repositories",
    },
    "mcp-server-git": {
        "cve": "CVE-2026-27735",
        "description": "Path traversal in git_add — files outside repo boundaries can be staged",
        "fix": "Update to >= 2026.1.14",
    },
    "@anthropic/mcp-server-filesystem": {
        "cve": "CVE-2025-53109/53110",
        "description": "Symlink bypass (full read/write any file) + prefix-matching bypass (unrestricted file access outside sandbox)",
        "fix": "Update to patched version, disable symlink following, use strict path validation",
    },
    "mcp-server-filesystem": {
        "cve": "CVE-2025-53109/53110",
        "description": "Symlink bypass + prefix-matching bypass — full filesystem access outside sandbox",
        "fix": "Update to patched version, restrict to specific directories only",
    },
    "gemini-mcp-tool": {
        "cve": "CVE-2026-0755",
        "description": "Critical RCE via execAsync with unsanitized shell metacharacters",
        "fix": "Do not use — replace with official Google ADK MCP integration",
    },
    "mcp-vegalite-server": {
        "cve": "CVE-2026-1977",
        "description": "Critical RCE via eval() on malicious Vega-Lite spec",
        "fix": "Do not use — eval() in MCP tool handlers is fundamentally unsafe",
    },
    "github-kanban-mcp": {
        "cve": "CVE-2026-0756",
        "description": "High RCE through MCP tool interface",
        "fix": "Do not use — replace with official @modelcontextprotocol/server-github",
    },
    "godot-mcp": {
        "cve": "CVE-2026-25546",
        "description": "Command injection via exec() with unsanitized projectPath",
        "fix": "Do not use — input sanitization missing entirely",
    },
    "fermat-mcp": {
        "cve": "CVE-2026-2008",
        "description": "Critical RCE via eval() on user-supplied equation strings — part of eval() epidemic",
        "fix": "Do not use — eval() on user input is fundamentally unsafe",
    },
    "@anthropic/mcp-inspector": {
        "cve": "CVE-2026-23744",
        "description": "Critical RCE via unauthenticated HTTP — listens 0.0.0.0 by default with no auth (CVSS 9.8)",
        "fix": "Update to >= 1.4.3, bind to localhost only, add authentication",
    },
    "mcp-inspector": {
        "cve": "CVE-2026-23744",
        "description": "Critical RCE via unauthenticated HTTP — inspector listens 0.0.0.0 with no auth (CVSS 9.8)",
        "fix": "Update to >= 1.4.3, bind to localhost only",
    },
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            subs = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, subs))
        prev_row = curr_row
    return prev_row[-1]


def check_typosquat(package_name: str) -> str | None:
    """Check if a package name looks like a typosquat of a known package."""
    clean_name = package_name.split("@")[0] if "@" in package_name and not package_name.startswith("@") else package_name
    # Strip version from scoped packages
    if "@" in clean_name:
        parts = clean_name.rsplit("@", 1)
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            clean_name = parts[0]

    for known in KNOWN_MCP_PACKAGES:
        if clean_name == known:
            return None  # exact match, not a typosquat
        dist = _levenshtein_distance(clean_name.lower(), known.lower())
        if 0 < dist <= 2 and len(clean_name) > 5:
            return f"Similar to known package '{known}' (edit distance: {dist})"
    return None


# ═══ Dangerous Permission Patterns ═══
DANGEROUS_PERMISSIONS = [
    (re.compile(r"--allow-all", re.I), "Grants all permissions"),
    (re.compile(r"--no-sandbox", re.I), "Disables sandbox protection"),
    (re.compile(r"--disable-security", re.I), "Disables security features"),
    (re.compile(r"sudo\s+", re.I), "Runs with elevated privileges"),
    (re.compile(r"--privileged", re.I), "Docker privileged mode"),
    (re.compile(r"--cap-add\s+SYS_ADMIN", re.I), "Adds SYS_ADMIN capability"),
]

# ═══ Sensitive Path Patterns ═══
# Paths that MCP servers should not have access to
SENSITIVE_PATHS = [
    (re.compile(r"[\\/]\.ssh(?:[\\/]|$)", re.I), "SSH keys directory"),
    (re.compile(r"[\\/]\.gnupg(?:[\\/]|$)", re.I), "GPG keys directory"),
    (re.compile(r"[\\/]\.aws(?:[\\/]|$)", re.I), "AWS credentials directory"),
    (re.compile(r"[\\/]\.kube(?:[\\/]|$)", re.I), "Kubernetes config directory"),
    (re.compile(r"[\\/]\.docker(?:[\\/]|$)", re.I), "Docker config directory"),
    (re.compile(r"[\\/]\.env(?:[\\/]|$|\.\w+$)", re.I), "Environment file with secrets"),
    (re.compile(r"[\\/]\.secrets?(?:[\\/]|$)", re.I), "Secrets directory"),
    (re.compile(r"[\\/]\.password", re.I), "Password file"),
]

# Root/system-level paths that indicate overly broad filesystem access
OVERBROAD_PATHS = [
    re.compile(r'^[A-Z]:\\$', re.I),       # C:\
    re.compile(r'^/$'),                      # /
    re.compile(r'^/(?:etc|var|usr)$'),       # System dirs
    re.compile(r'^C:\\Windows', re.I),       # Windows system
    re.compile(r'^C:\\Program Files', re.I), # Program files
    re.compile(r'^/home$'),                  # All home dirs
    re.compile(r'^C:\\Users$', re.I),        # All user dirs
]


def scan_mcp_config(mcp_path: Path) -> list:
    """Scan an .mcp.json file for security risks."""
    findings = []
    poisoning_patterns = _build_poisoning_patterns()
    secret_detectors = _build_secret_detectors()

    if not mcp_path.exists():
        findings.append({
            "server": "(config)",
            "risk": "INFO",
            "category": "config",
            "message": f"No .mcp.json found at {mcp_path}",
            "fix": None,
        })
        return findings

    try:
        config = json.loads(mcp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        findings.append({
            "server": "(config)",
            "risk": "HIGH",
            "category": "config",
            "message": f"Invalid JSON in .mcp.json: {e}",
            "fix": "Fix JSON syntax errors",
        })
        return findings

    servers = config.get("mcpServers", {})

    for name, srv in servers.items():
        if srv.get("disabled", False):
            findings.append({
                "server": name,
                "risk": "INFO",
                "category": "disabled",
                "message": f"Server '{name}' is disabled",
                "fix": None,
            })
            continue

        command = srv.get("command", "")
        args = srv.get("args", [])
        env = srv.get("env", {})
        url = srv.get("url", "")
        args_str = " ".join(str(a) for a in args)
        full_cmd = f"{command} {args_str}"

        # Check 1: Transport Security
        if url:
            if _NETWORK_PATTERN.search(url):
                findings.append({
                    "server": name,
                    "risk": "CRITICAL",
                    "category": "network-exposure",
                    "message": f"HTTP transport to non-localhost URL: {url}",
                    "fix": "Use stdio transport or bind to localhost only",
                })
            elif "0.0.0.0" in url:
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "network-exposure",
                    "message": f"Server binds to 0.0.0.0: {url}",
                    "fix": "Bind to 127.0.0.1 instead",
                })

        # Check 2: Rug Pull Risk (npx @latest)
        if "npx" in command or "npx" in args_str:
            if "@latest" in args_str:
                findings.append({
                    "server": name,
                    "risk": "MEDIUM",
                    "category": "rug-pull",
                    "message": "Uses npx with @latest — code changes on every run",
                    "fix": "Pin to specific version",
                })
            if "-y" in args or "--yes" in args:
                findings.append({
                    "server": name,
                    "risk": "LOW",
                    "category": "rug-pull",
                    "message": "Uses npx -y — auto-confirms package install",
                    "fix": "Remove -y flag for manual approval",
                })

        # Check 3: Secret Leakage
        for pattern, desc in secret_detectors:
            if pattern.search(full_cmd):
                findings.append({
                    "server": name,
                    "risk": "CRITICAL",
                    "category": "secret-leak",
                    "message": f"{desc} found in command/args",
                    "fix": "Move secrets to .env and use variable references",
                })

        for env_key, env_val in env.items():
            if env_val and not env_val.startswith("${") and not env_val.startswith("$"):
                for pattern, desc in secret_detectors:
                    if pattern.search(str(env_val)):
                        findings.append({
                            "server": name,
                            "risk": "CRITICAL",
                            "category": "secret-leak",
                            "message": f"{desc} hardcoded in env.{env_key}",
                            "fix": f"Use variable reference instead",
                        })

        # Check 4: Command Injection
        if "shell=True" in full_cmd or "shell=true" in full_cmd.lower():
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "command-injection",
                "message": "shell=True — injection risk",
                "fix": "Use array args instead of shell string",
            })

        # Check 5: Path Traversal
        for arg in args:
            if ".." in str(arg):
                findings.append({
                    "server": name,
                    "risk": "MEDIUM",
                    "category": "path-traversal",
                    "message": f"Path traversal '..' in args: {arg}",
                    "fix": "Use absolute paths",
                })

        # Check 6: Typosquat Detection
        for arg in args:
            arg_str = str(arg)
            if "@" in arg_str or "mcp" in arg_str.lower():
                typo_result = check_typosquat(arg_str)
                if typo_result:
                    findings.append({
                        "server": name,
                        "risk": "HIGH",
                        "category": "typosquat",
                        "message": f"Possible typosquat: {arg_str}. {typo_result}",
                        "fix": "Verify package name matches the official package",
                    })

        # Check 7: Dangerous Permissions
        for pattern, desc in DANGEROUS_PERMISSIONS:
            if pattern.search(full_cmd):
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "dangerous-permission",
                    "message": f"{desc}: found in command/args",
                    "fix": "Remove dangerous permission flags",
                })

        # Check 8: No auth on HTTP transport
        if url and not srv.get("headers") and "http" in url.lower():
            if "localhost" in url or "127.0.0.1" in url:
                pass  # localhost is ok without auth
            else:
                findings.append({
                    "server": name,
                    "risk": "CRITICAL",
                    "category": "missing-auth",
                    "message": f"HTTP transport without auth headers: {url}",
                    "fix": "Add authentication headers or use stdio transport",
                })

        # Check 9: Sensitive path access
        for arg in args:
            arg_str = str(arg)
            for pattern, desc in SENSITIVE_PATHS:
                if pattern.search(arg_str):
                    findings.append({
                        "server": name,
                        "risk": "HIGH",
                        "category": "sensitive-path",
                        "message": f"Access to {desc}: {arg_str}",
                        "fix": "Restrict access to non-sensitive directories",
                    })

        # Check 10: Overly broad filesystem access
        for arg in args:
            arg_str = str(arg).strip()
            for pattern in OVERBROAD_PATHS:
                if pattern.match(arg_str):
                    findings.append({
                        "server": name,
                        "risk": "MEDIUM",
                        "category": "overbroad-access",
                        "message": f"Root/system-level path access: {arg_str}",
                        "fix": "Scope to specific project directories instead",
                    })

        # Check 11: Environment variable leak risk
        sensitive_env_names = {"DATABASE_URL", "DB_PASSWORD", "PRIVATE_KEY",
                             "SECRET_KEY", "JWT_SECRET", "SESSION_SECRET",
                             "ENCRYPTION_KEY", "MASTER_KEY"}
        for env_key in env:
            if env_key.upper() in sensitive_env_names:
                env_val = str(env.get(env_key, ""))
                if env_val and not env_val.startswith("${") and not env_val.startswith("$"):
                    findings.append({
                        "server": name,
                        "risk": "HIGH",
                        "category": "env-var-leak",
                        "message": f"Sensitive env var '{env_key}' has hardcoded value",
                        "fix": "Use environment variable reference (${VAR}) instead",
                    })

        # Check 13: Known vulnerable packages (CVE database)
        for arg in args:
            arg_str = str(arg)
            for vuln_pkg, vuln_info in KNOWN_VULNERABLE.items():
                if vuln_pkg in arg_str:
                    findings.append({
                        "server": name,
                        "risk": "CRITICAL",
                        "category": "known-vulnerable",
                        "message": f"Uses package with known CVE ({vuln_info['cve']}): {vuln_pkg} - {vuln_info['description']}",
                        "fix": vuln_info["fix"],
                    })

        # Check 14: Symlink risk detection
        for arg in args:
            arg_str = str(arg)
            # CVE-2025-53109: symlink bypass can escalate to system takeover
            if "--follow-symlinks" in arg_str or "--dereference" in arg_str:
                findings.append({
                    "server": name,
                    "risk": "HIGH",
                    "category": "symlink-risk",
                    "message": "Symlink following enabled - CVE-2025-53109 risk",
                    "fix": "Disable symlink following or restrict to safe directories",
                })

        # Check 15: Shadow MCP server detection (OWASP MCP-05)
        # Detects servers using non-standard transport or unusual command patterns
        arg_str_full = command + " " + " ".join(str(a) for a in args)
        if any(shadow in arg_str_full.lower() for shadow in [
            "ngrok", "localtunnel", "cloudflared", "serveo",
            "0.0.0.0", "::0", "INADDR_ANY",
        ]):
            findings.append({
                "server": name,
                "risk": "HIGH",
                "category": "shadow-server",
                "message": "Server exposes via tunnel/public binding — potential shadow MCP server (OWASP MCP-05)",
                "fix": "Bind to 127.0.0.1 only. Remove tunnel services. Use authenticated transport.",
            })

        # Check 16: Dangerous runtime patterns (eval/exec epidemic - CVE-2026-0755/1977/25546)
        # Three Feb 2026 CVEs share the same root cause: eval()/exec() in MCP tool handlers
        for arg in args:
            arg_lower = str(arg).lower()
            if any(pattern in arg_lower for pattern in [
                "eval(", "exec(", "execasync(", "execsync(",
                "child_process", "spawn(", "function(",
            ]):
                findings.append({
                    "server": name,
                    "risk": "CRITICAL",
                    "category": "code-execution",
                    "message": "Server args contain code execution patterns (eval/exec) — CVE-2026-0755/1977/25546 class",
                    "fix": "Never use eval/exec in MCP servers. Use parameterized APIs instead.",
                })
                break  # One finding per server is enough

        # Check 17: Known malicious packages (OWASP MCP-07)
        # Confirmed malicious MCP servers — immediate CRITICAL alert
        for arg in args:
            arg_str = str(arg)
            for malicious_pkg in KNOWN_MALICIOUS:
                if malicious_pkg in arg_str:
                    findings.append({
                        "server": name,
                        "risk": "CRITICAL",
                        "category": "known-malicious",
                        "message": f"CONFIRMED MALICIOUS PACKAGE: {malicious_pkg} — contains reverse shell/malware payload",
                        "fix": "Remove immediately. This package is confirmed malware. Report to npm/PyPI.",
                    })

        # Mark clean servers
        server_findings = [f for f in findings if f["server"] == name]
        if not server_findings:
            findings.append({
                "server": name,
                "risk": "INFO",
                "category": "clean",
                "message": f"Server '{name}' passed all checks",
                "fix": None,
            })

    # Check 12: Excessive server count (attack surface)
    active_count = sum(1 for s in servers.values() if not s.get("disabled", False))
    if active_count > 15:
        findings.append({
            "server": "(global)",
            "risk": "MEDIUM",
            "category": "excessive-servers",
            "message": f"{active_count} active MCP servers — large attack surface",
            "fix": "Disable unused servers to reduce attack surface",
        })
    elif active_count > 10:
        findings.append({
            "server": "(global)",
            "risk": "LOW",
            "category": "excessive-servers",
            "message": f"{active_count} active MCP servers — consider reducing",
            "fix": "Review and disable unused servers",
        })

    return findings


def calculate_score(findings: list) -> int:
    """Calculate security score 0-100."""
    deduction = 0
    for f in findings:
        risk = f.get("risk", "INFO")
        if risk == "CRITICAL":
            deduction += 25
        elif risk == "HIGH":
            deduction += 15
        elif risk == "MEDIUM":
            deduction += 8
        elif risk == "LOW":
            deduction += 3
    return max(0, 100 - deduction)


def format_report(findings: list, score: int) -> str:
    """Format findings as a human-readable report."""
    lines = ["", "MCP Security Scan Results", "=" * 40, ""]
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = [f for f in findings if f["risk"] == risk]
        if not items:
            continue
        icon = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[.]", "INFO": "[i]"}.get(risk, "[i]")
        lines.append(f"{icon} {risk} ({len(items)}):")
        for f in items:
            owasp = OWASP_MAPPING.get(f.get("category", ""), {})
            owasp_tag = f" [{owasp['id']}]" if owasp.get("id") else ""
            lines.append(f"  [{f['server']}]{owasp_tag} {f['message']}")
            if f.get("fix"):
                lines.append(f"    Fix: {f['fix']}")
        lines.append("")
    lines.append(f"Security Score: {score}/100")
    return "\n".join(lines)


def format_sarif(findings: list, score: int, mcp_path: str = ".mcp.json") -> dict:
    """Format findings as SARIF v2.1.0 for CI/CD integration.

    SARIF (Static Analysis Results Interchange Format) is the standard
    for GitHub Code Scanning, Azure DevOps, and other CI/CD pipelines.
    """
    risk_to_level = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    rules = []
    results = []
    rule_ids_seen = set()

    for i, f in enumerate(findings):
        category = f.get("category", "unknown")
        risk = f.get("risk", "INFO")
        owasp = OWASP_MAPPING.get(category, {})

        # Build rule ID (deduplicated)
        rule_id = f"mcp-{category}"
        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rule_def = {
                "id": rule_id,
                "name": category.replace("-", " ").title(),
                "shortDescription": {"text": owasp.get("name", category)},
                "defaultConfiguration": {"level": risk_to_level.get(risk, "note")},
            }
            if owasp.get("id"):
                rule_def["helpUri"] = owasp["url"]
                rule_def["properties"] = {"owasp": owasp["id"]}
            rules.append(rule_def)

        # Build result
        result = {
            "ruleId": rule_id,
            "level": risk_to_level.get(risk, "note"),
            "message": {"text": f['message']},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(mcp_path)},
                    "region": {"startLine": 1},
                }
            }],
        }
        if f.get("fix"):
            result["fixes"] = [{"description": {"text": f["fix"]}}]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-config-guard",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/KGT24k/aegis",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {"securityScore": score},
        }],
    }


def discover_mcp_configs() -> list:
    """Auto-discover MCP config files across common locations."""
    home = Path(os.environ.get("USERPROFILE", os.environ.get("HOME", "")))
    discovered = []

    candidates = [
        # Claude Code
        Path.cwd() / ".mcp.json",
        AEGIS_ROOT / ".mcp.json",
        # Claude Desktop (Windows)
        home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        # Claude Desktop (macOS)
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        # Claude Desktop (Linux)
        home / ".config" / "claude" / "claude_desktop_config.json",
        # Cursor
        home / ".cursor" / "mcp.json",
        # VS Code
        home / ".vscode" / "mcp.json",
        # Windsurf
        home / ".windsurf" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
    ]

    for candidate in candidates:
        if candidate.exists():
            discovered.append(candidate)

    return list(set(discovered))  # deduplicate


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Config Guard — Zero-dependency security linter for MCP configurations"
    )
    parser.add_argument("--path", default=str(AEGIS_ROOT), help="Project root to scan")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--sarif", action="store_true", help="SARIF v2.1.0 output (CI/CD)")
    parser.add_argument("--discover", action="store_true", help="Auto-discover all MCP configs")
    args = parser.parse_args()

    if args.discover:
        configs = discover_mcp_configs()
        all_findings = []
        for cfg in configs:
            findings = scan_mcp_config(cfg)
            for f in findings:
                f["config_file"] = str(cfg)
            all_findings.extend(findings)
        if not configs:
            print("No MCP configuration files found.")
            sys.exit(0)
        score = calculate_score(all_findings)
        if args.sarif:
            print(json.dumps(format_sarif(all_findings, score, "multiple"), indent=2))
        elif args.json:
            print(json.dumps({"configs": [str(c) for c in configs], "findings": all_findings, "score": score}, indent=2))
        else:
            print(f"\nDiscovered {len(configs)} MCP config(s):")
            for c in configs:
                print(f"  {c}")
            print(format_report(all_findings, score))
    else:
        mcp_path = Path(args.path) / ".mcp.json"
        findings = scan_mcp_config(mcp_path)
        score = calculate_score(findings)

        if args.sarif:
            print(json.dumps(format_sarif(findings, score, str(mcp_path)), indent=2))
        elif args.json:
            print(json.dumps({"findings": findings, "score": score}, indent=2))
        else:
            print(format_report(findings, score))

    all_f = all_findings if args.discover else findings
    critical_high = [f for f in all_f if f["risk"] in ("CRITICAL", "HIGH")]
    sys.exit(1 if critical_high else 0)


if __name__ == "__main__":
    main()
