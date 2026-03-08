# OWASP MCP Top 10 Mapping

**Config Guard v2.0.0** — 54 checks mapped to OWASP MCP Top 10

This document maps every Config Guard security check to its corresponding OWASP MCP Top 10 category and CWE identifier. Use this as a reference for understanding what threats Config Guard detects, where coverage is strong, and where complementary runtime protections are needed.

---

## Coverage Matrix

| OWASP Category | Description | Checks Mapped | Coverage Level |
|---|---|---|---|
| MCP-01 | Command Injection via Tool | 3 | Full |
| MCP-02 | Tool Poisoning | 0 | Gap (runtime only) |
| MCP-03 | Insecure MCP Transport | 2 | Full |
| MCP-04 | Sensitive Data Exposure | 4 | Full |
| MCP-05 | Path Traversal / File Access | 3 | Full |
| MCP-06 | Excessive Permissions | 2 | Full |
| MCP-07 | Supply Chain / Rug Pull | 3 | Full |
| MCP-08 | Missing Authentication | 1 | Full |
| MCP-09 | Known Vulnerable Component | 1 | Full |
| MCP-10 | Misconfiguration | 1 | Partial |

**Legend:**
- **Full** — Config Guard actively detects this threat class through static configuration analysis.
- **Partial** — Config Guard covers some aspects; additional runtime or manual review recommended.
- **Gap** — This threat class operates at runtime and cannot be caught by static config scanning alone.

---

## MCP-01: Command Injection via Tool

Attackers inject shell commands through MCP tool arguments or server configurations that invoke system shells without proper sanitization.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 4 | `command-injection` | Detects `shell=True` and unquoted argument expansion in server commands | CWE-78 | Critical |
| 16 | `code-execution` | Flags `eval()`, `exec()`, and similar dynamic code execution patterns in tool arguments | CWE-95 | Critical |
| 19 | `shell-server` | Identifies raw shell processes (`cmd.exe`, `bash`, `sh`) configured as MCP servers | CWE-78 | Critical |

**What Config Guard catches:** Server configurations that pass unsanitized input to shell interpreters, use dynamic code evaluation, or expose a raw shell as an MCP server endpoint.

---

## MCP-02: Tool Poisoning

A malicious or compromised MCP server returns crafted tool descriptions or responses designed to manipulate the LLM into performing unintended actions (e.g., prompt injection via tool metadata).

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| — | `tool-poisoning` | Not directly checked | CWE-94 | — |

**Coverage gap:** Tool poisoning is a runtime attack that occurs when the LLM processes responses from an already-running MCP server. Static configuration scanning cannot detect manipulated tool descriptions or poisoned responses. Mitigation requires runtime monitoring, tool description validation, and output filtering at the MCP client layer.

---

## MCP-03: Insecure MCP Transport

MCP communication occurs over unencrypted or improperly secured transport channels, exposing commands and data to interception.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 1 | `network-exposure` | Flags non-localhost URLs (HTTP endpoints exposed to the network) in server configurations | CWE-319 | High |
| 18 | `deprecated-transport` | Detects SSE (Server-Sent Events) transport without per-request authentication headers | CWE-477 | Medium |

**What Config Guard catches:** Server URLs bound to non-localhost addresses that expose MCP traffic to the network, and use of the deprecated SSE transport mechanism which lacks per-request authentication support.

---

## MCP-04: Sensitive Data Exposure

API keys, tokens, credentials, or sensitive file contents are leaked through MCP server configurations, environment variables, or tool arguments.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 3 | `secret-leak` | Detects API keys, tokens, and credentials hardcoded in server arguments or environment blocks | CWE-798 | Critical |
| 9 | `sensitive-path` | Flags access to sensitive directories and files (`.ssh/`, `.aws/`, `.env`, credential stores) | CWE-538 | High |
| 11 | `env-var-leak` | Identifies hardcoded secrets in environment variable definitions within MCP configs | CWE-798 | High |
| 20 | `unpinned-package` | Detects unpinned package versions that risk pulling compromised releases containing data exfiltration code | CWE-1104 | Medium |

**What Config Guard catches:** Credentials embedded directly in configuration files, server access to sensitive credential directories, hardcoded secrets in environment blocks, and version drift that could introduce data-leaking supply chain compromises.

---

## MCP-05: Path Traversal / File Access

MCP tools or server configurations allow access to files and directories outside intended boundaries through path manipulation or symlink exploitation.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 5 | `path-traversal` | Detects `..` directory traversal sequences in configured paths and arguments | CWE-22 | High |
| 14 | `symlink-risk` | Flags symlink-based file access bypass vulnerabilities (CVE-2025-53109) | CWE-59 | High |
| 15 | `shadow-server` | Identifies tunnel bindings and network exposure that could allow unauthorized file system access | CWE-284 | High |

**What Config Guard catches:** Path traversal sequences in server arguments, symlink-based sandbox escape vulnerabilities, and shadow server configurations that tunnel access to the file system from external networks.

---

## MCP-06: Excessive Permissions

MCP servers are granted more permissions than necessary, violating the principle of least privilege and expanding the blast radius of any compromise.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 7 | `dangerous-permission` | Detects `--allow-all`, `sudo`, `--no-sandbox`, and similar overly permissive flags | CWE-250 | Critical |
| 10 | `overbroad-access` | Flags root filesystem access (`/`) or home directory access as working directories | CWE-732 | High |

**What Config Guard catches:** Server configurations that request blanket permissions or disable security sandboxes, and configurations that grant access to the entire filesystem or overly broad directory trees.

---

## MCP-07: Supply Chain / Rug Pull

Attackers compromise MCP servers through supply chain attacks — malicious packages, typosquatting, auto-updating dependencies, or known malware.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 2 | `rug-pull` | Detects `npx @latest` and similar patterns that pull unreviewed code on every invocation | CWE-494 | Critical |
| 6 | `typosquat` | Uses Levenshtein distance analysis to identify package names suspiciously similar to popular packages | CWE-506 | High |
| 17 | `known-malicious` | Matches against a database of 44 confirmed malicious MCP packages | CWE-506 | Critical |

**What Config Guard catches:** Auto-update patterns that bypass version pinning, typosquatted package names that impersonate legitimate MCP servers, and known malicious packages identified through community threat intelligence.

---

## MCP-08: Missing Authentication

MCP servers communicate over HTTP transport without authentication headers, allowing any network-adjacent attacker to send commands.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 8 | `missing-auth` | Flags HTTP-based MCP transport configurations that lack authentication headers | CWE-306 | Critical |

**What Config Guard catches:** Server configurations using HTTP/SSE transport without `Authorization`, `X-API-Key`, or equivalent authentication headers.

---

## MCP-09: Known Vulnerable Component

MCP server packages with published CVEs are in use, exposing the system to known exploits.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 13 | `known-vulnerable` | Checks installed MCP packages against a database of 22 CVEs across 20 packages | CWE-1395 | Critical |

**What Config Guard catches:** MCP server packages with known CVEs, including version-range matching to determine if the installed version falls within the affected range.

---

## MCP-10: Misconfiguration

General configuration weaknesses that increase attack surface without falling neatly into other categories.

| Check # | Check ID | Description | CWE | Severity |
|---|---|---|---|---|
| 12 | `excessive-servers` | Warns when a large number of MCP servers are configured, increasing overall attack surface | CWE-1059 | Low |

**What Config Guard catches:** Configurations with an unusually high number of MCP servers, which increases the probability that at least one server is misconfigured, outdated, or compromised.

**Note:** This category has partial coverage. Additional misconfiguration patterns (e.g., conflicting settings, redundant servers, debug mode left enabled) could be added in future releases.

---

## Complete Check Reference

The table below lists the core 20 Config Guard checks with their OWASP MCP Top 10 mapping, CWE identifier, and a brief description. v2.0.0 adds 34 additional checks across all categories — see the source code for the complete list.

| # | Check ID | OWASP Category | CWE | Description |
|---|---|---|---|---|
| 1 | `network-exposure` | MCP-03 | CWE-319 | Non-localhost URLs exposing MCP to the network |
| 2 | `rug-pull` | MCP-07 | CWE-494 | `npx @latest` and auto-update patterns |
| 3 | `secret-leak` | MCP-04 | CWE-798 | API keys and tokens in arguments or env |
| 4 | `command-injection` | MCP-01 | CWE-78 | `shell=True` and unquoted argument expansion |
| 5 | `path-traversal` | MCP-05 | CWE-22 | `..` sequences in paths and arguments |
| 6 | `typosquat` | MCP-07 | CWE-506 | Levenshtein-based package name detection |
| 7 | `dangerous-permission` | MCP-06 | CWE-250 | `--allow-all`, `sudo`, `--no-sandbox` flags |
| 8 | `missing-auth` | MCP-08 | CWE-306 | HTTP transport without auth headers |
| 9 | `sensitive-path` | MCP-04 | CWE-538 | Access to `.ssh/`, `.aws/`, `.env` paths |
| 10 | `overbroad-access` | MCP-06 | CWE-732 | Root or home directory as working directory |
| 11 | `env-var-leak` | MCP-04 | CWE-798 | Hardcoded secrets in environment variables |
| 12 | `excessive-servers` | MCP-10 | CWE-1059 | High server count increasing attack surface |
| 13 | `known-vulnerable` | MCP-09 | CWE-1395 | 28 CVEs across MCP packages |
| 14 | `symlink-risk` | MCP-05 | CWE-59 | Symlink-based file access bypass (CVE-2025-53109) |
| 15 | `shadow-server` | MCP-05 | CWE-284 | Tunnel/binding network exposure |
| 16 | `code-execution` | MCP-01 | CWE-95 | `eval()` / `exec()` dynamic code execution |
| 17 | `known-malicious` | MCP-07 | CWE-506 | 56 confirmed malicious MCP packages |
| 18 | `deprecated-transport` | MCP-03 | CWE-477 | SSE transport without per-request auth |
| 19 | `shell-server` | MCP-01 | CWE-78 | Raw shell process as MCP server |
| 20 | `unpinned-package` | MCP-04 | CWE-1104 | Unpinned versions risking supply chain drift |

---

## Coverage Summary

```
MCP-01  Command Injection       [###] 3 checks   FULL
MCP-02  Tool Poisoning          [   ] 0 checks   GAP (runtime attack)
MCP-03  Insecure Transport      [## ] 2 checks   FULL
MCP-04  Sensitive Data          [####] 4 checks  FULL
MCP-05  Path Traversal          [###] 3 checks   FULL
MCP-06  Excessive Permissions   [## ] 2 checks   FULL
MCP-07  Supply Chain            [###] 3 checks   FULL
MCP-08  Missing Authentication  [#  ] 1 check    FULL
MCP-09  Known Vulnerable        [#  ] 1 check    FULL
MCP-10  Misconfiguration        [#  ] 1 check    PARTIAL

Total: 54 checks across 9 of 10 OWASP MCP Top 10 categories
```

**9/10 categories covered** through static configuration analysis. MCP-02 (Tool Poisoning) requires runtime protections outside the scope of config-file scanning.