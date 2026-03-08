# Changelog

All notable changes to Config Guard will be documented in this file.

## [2.0.0] - 2026-03-04

### Added
- **32 new security checks** (22 → 54 total) covering expanded threat landscape
- **CWE tags** on all checks for standards compliance
- **SARIF v2.1.0 enhancements** — richer rule metadata, help URIs, CWE references
- **Pre-commit hook integration** — `.pre-commit-hooks.yaml` for automated config scanning
- **Expanded CVE database** — 28 CVEs across MCP packages
- **Expanded malicious package database** — 56 confirmed malicious MCP packages
- **New check categories:** deprecated API patterns, insecure defaults, privilege escalation paths
- **`--sarif` output improvements** — full rule help text, markdown descriptions

### Changed
- Package renamed from `config-guard` to `mcp-config-guard` on PyPI
- Repository URLs updated to `github.com/KGT24k/mcp-config-guard`
- Author updated to "AEGIS Forge Team"
- Minimum Python version remains 3.9+
- All check IDs now include CWE mapping

### Fixed
- Python 3.9 compatibility — replaced `str | None` type hints with string annotations
- CI matrix covers Python 3.9-3.13 (3.14 classified but not yet in CI)

## [1.4.0] - 2026-03-01

### Added
- **Policy-as-code system** — YAML/JSON policy files for custom check configuration
  - Enable/disable individual checks
  - Override severity levels per check
  - Ignore specific servers, categories, or message patterns
  - CI/CD exit code thresholds (fail on critical, high, medium)
  - Minimum passing score threshold
- **`--policy` CLI flag** — load custom policy file
- **`--init-policy` CLI flag** — generate default policy template
- **`--fix` CLI flag** — show auto-fix suggestions for actionable findings
- **Auto-fix suggestion engine** — generates concrete fix instructions for:
  - Version pinning (unpinned packages)
  - HTTP to HTTPS transport upgrade
  - 0.0.0.0 to localhost binding
  - @latest to pinned version
  - Secret/env var to variable reference
  - Dangerous permission removal
- **GitHub Actions workflow template** — `.github/workflows/config-guard.yml`
- **Zero-dependency YAML parser** — policy files work without PyYAML installed

### Changed
- Version constants centralized via `VERSION` variable
- Exit code logic now respects policy thresholds instead of hardcoded CRITICAL/HIGH check
- SARIF output version field now reads from VERSION constant

## [1.3.0] - 2026-03-01

### Added
- Check 21: Version pinning — detects unpinned MCP server packages (supply chain risk)
- Check 22: Transport security — stdio vs SSE vs Streamable HTTP risk assessment
- `--summary` flag for one-line output
- OWASP MCP Top 10 mapping for all 22 checks

### Changed
- Version bump from 1.2.0 to 1.3.0
- Improved transport security detection for SSE and Streamable HTTP

## [1.2.0] - 2026-02-28

### Added
- 20 security checks with OWASP mapping
- CVE database (22 CVEs across 12 packages)
- Known malicious package detection (44 packages)
- SARIF v2.1.0 output for CI/CD integration
- Auto-discovery of MCP configs across Claude, Cursor, VS Code, Windsurf
- Typosquat detection via Levenshtein distance
- Shadow server detection (ngrok, cloudflared, etc.)
- Code execution pattern detection (eval/exec epidemic)

## [1.1.0] - 2026-02-25

### Added
- Initial 15 security checks
- JSON output mode
- Secret detection patterns
- Network exposure detection

## [1.0.0] - 2026-02-20

### Added
- Initial release with 10 core security checks
- Human-readable output
- Zero-dependency design
