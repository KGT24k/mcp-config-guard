# Config Guard

**Zero-dependency security linter for MCP configurations.**

Scans your `.mcp.json` for 20 types of security vulnerabilities before any MCP server starts. No API keys. No cloud. No LLM required.

[![PyPI version](https://badge.fury.io/py/config-guard.svg)](https://pypi.org/project/config-guard/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://pypi.org/project/config-guard/)

## Why?

**43% of public MCP servers have command injection flaws** (BlueRock TechReport 2026). Every MCP config you use is a trust boundary — and most developers never audit them.

Config Guard catches what humans miss:

- Typosquatted packages that look like real ones
- Servers with known CVEs (22 CVEs across 20 packages)
- 44 confirmed malicious packages (JFrog, Kaspersky, Lazarus APT, SANDWORM_MODE)
- Secret leakage in environment variables
- Rug-pull vectors (`npx @latest` auto-updates)
- Shadow servers exposing via tunnels

## Install

```bash
pip install config-guard
```

## Quick Start

```bash
# Scan your current directory's .mcp.json
config-guard

# Scan a specific project
config-guard --path /my/project

# Auto-discover all MCP configs on your system
config-guard --discover

# CI/CD integration (SARIF output for GitHub Code Scanning)
config-guard --sarif > results.sarif

# JSON output for scripting
config-guard --json
```

## 20 Security Checks

Every check is mapped to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/). See [docs/OWASP-MAPPING.md](docs/OWASP-MAPPING.md) for full CWE mappings.

| # | Check | Risk | OWASP |
|---|-------|------|-------|
| 1 | Network exposure (non-localhost URLs) | HIGH | MCP-03 |
| 2 | Rug pulls (`npx @latest` auto-update) | HIGH | MCP-07 |
| 3 | Secret leakage (API keys in args/env) | HIGH | MCP-04 |
| 4 | Command injection (`shell=True`) | CRITICAL | MCP-01 |
| 5 | Path traversal (`..` in arguments) | MEDIUM | MCP-05 |
| 6 | Typosquat detection (Levenshtein distance) | HIGH | MCP-07 |
| 7 | Dangerous permissions (`--no-sandbox`, `sudo`) | HIGH | MCP-06 |
| 8 | Missing authentication on HTTP transport | MEDIUM | MCP-08 |
| 9 | Sensitive path access (`.ssh`, `.aws`, `.env`) | HIGH | MCP-04 |
| 10 | Overbroad filesystem access (`/`, `C:\`) | MEDIUM | MCP-06 |
| 11 | Environment variable leaks (hardcoded secrets) | MEDIUM | MCP-04 |
| 12 | Excessive server count (attack surface) | LOW | MCP-10 |
| 13 | Known CVEs (22 CVEs across 20 packages) | CRITICAL | MCP-09 |
| 14 | Symlink bypass (CVE-2025-53109) | HIGH | MCP-05 |
| 15 | Shadow servers (ngrok, cloudflared, `0.0.0.0`) | HIGH | MCP-05 |
| 16 | Code execution (`eval`/`exec` patterns) | CRITICAL | MCP-01 |
| 17 | Known malicious packages (44 confirmed malware) | CRITICAL | MCP-07 |
| 18 | Deprecated SSE transport (no per-request auth) | MEDIUM | MCP-03 |
| 19 | Shell servers (raw shell as MCP server) | CRITICAL | MCP-01 |
| 20 | Unpinned packages (npx/uvx without version) | MEDIUM | MCP-04 |

## CVE Database

Config Guard tracks known vulnerable MCP packages:

| Package | CVE | Severity |
|---------|-----|----------|
| `mcp-remote` | CVE-2025-6514 | Critical (CVSS 9.6) |
| `@modelcontextprotocol/server-git` | CVE-2025-68145 | Critical |
| `mcp-server-git` | CVE-2026-27735 | Medium |
| `@anthropic/mcp-server-filesystem` | CVE-2025-53109 | High |
| `gemini-mcp-tool` | CVE-2026-0755 | Critical |
| `mcp-vegalite-server` | CVE-2026-1977 | Critical |
| `github-kanban-mcp` | CVE-2026-0756 | High |
| `godot-mcp` | CVE-2026-25546 | High |
| `fermat-mcp` | CVE-2026-2008 | Critical |
| `@anthropic/mcp-inspector` | CVE-2026-23744 | Critical (CVSS 9.8) |

Config Guard also detects **confirmed malicious packages** (e.g., `postmark-mcp`, `@lanyer640/mcp-runcommand-server`) that contain reverse shells or malware payloads.

## Output Formats

### Human-readable (default)
```
MCP Security Scan Results
========================================

[!] CRITICAL (1):
  [my-server] [MCP-09] Uses package with known CVE (CVSS-9.6): mcp-remote
    Fix: Update to latest patched version

[i] INFO (1):
  [safe-server] Server 'safe-server' passed all checks

Security Score: 85/100
```

### SARIF (CI/CD)
```bash
config-guard --sarif > results.sarif
```

Upload to GitHub Code Scanning, Azure DevOps, or any SARIF-compatible tool.

### JSON
```bash
config-guard --json | jq '.score'
```

## GitHub Actions Integration

```yaml
- name: MCP Config Security Scan
  run: |
    pip install config-guard
    config-guard --sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Supported Configs

Config Guard scans these MCP configuration formats:

- **Claude Code** / **Claude Desktop** (`.mcp.json`, `claude_desktop_config.json`)
- **Cursor** (`.cursor/mcp.json`)
- **VS Code** (`.vscode/mcp.json`)
- **Windsurf** (`.windsurf/mcp.json`)

Use `--discover` to auto-find all configs on your system.

## Scoring

Config Guard calculates a security score from 0-100:

| Finding | Deduction |
|---------|-----------|
| CRITICAL | -25 points |
| HIGH | -15 points |
| MEDIUM | -5 points |
| LOW | -3 points |

**100/100** = no findings. **0/100** = critical issues found.

Exit code is `1` if any CRITICAL or HIGH findings exist (useful for CI gates).

## Comparison: Config Guard vs Agent Scan (Snyk)

| Feature | Config Guard | Agent Scan (Snyk/Invariant Labs) |
|---------|-------------|--------------------------------|
| **Approach** | Deterministic regex + CVE database | LLM-based judges + deterministic rules |
| **Dependencies** | Zero (stdlib only) | Requires API calls to invariantlabs.ai |
| **Offline** | Fully offline | Requires internet (sends tool descriptions to cloud) |
| **Privacy** | No data leaves your machine | Tool names/descriptions sent to Snyk for analysis |
| **Checks** | 20 static config checks | Prompt injection + tool poisoning + toxic flows |
| **CVE database** | 22 CVEs across 20 packages | Dynamic (cloud-updated) |
| **Malicious packages** | 44 confirmed (JFrog, Kaspersky, Lazarus, SANDWORM) | Dynamic detection |
| **OWASP mapping** | All 20 checks mapped to MCP Top 10 + CWE IDs | Not documented |
| **SARIF output** | Native SARIF v2.1.0 with CWE tags + fingerprints | Not available |
| **CI/CD** | GitHub Actions, any SARIF tool | Background mode (MDM/CrowdStrike) |
| **Speed** | <100ms (no network) | Seconds (API round-trip) |
| **Install** | `pip install config-guard` | `uvx mcp-scan@latest` |
| **Scope** | Config files only (pre-start) | Config + runtime tool descriptions |
| **License** | MIT (open source) | Proprietary (Snyk) |

**When to use Config Guard:** CI/CD pipelines, air-gapped environments, privacy-sensitive setups, pre-commit hooks. Config Guard runs instantly with zero network access.

**When to use Agent Scan:** Runtime tool description analysis, prompt injection detection in live MCP servers, enterprise environments with Snyk Evo integration.

**Best practice:** Use both. Config Guard catches config-level issues before servers start. Agent Scan catches runtime tool poisoning after servers are running.

## Zero Dependencies

Config Guard uses only Python standard library modules (`json`, `os`, `re`, `sys`, `pathlib`, `argparse`). No `pip install` surprises. No supply chain risk from transitive dependencies.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Issues and PRs welcome at [github.com/KGT24k/config-guard](https://github.com/KGT24k/config-guard).
