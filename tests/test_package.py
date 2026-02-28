"""Tests for config-guard as standalone PyPI package.

Verifies:
1. Package imports correctly
2. Version is set
3. Core API functions exist
4. CLI entry point works
5. Zero dependencies (only stdlib)
"""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

# Load from package source
PKG_SRC = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(PKG_SRC))

import config_guard


class TestPackageMetadata:
    def test_version_set(self):
        assert hasattr(config_guard, "__version__")
        assert config_guard.__version__ == "1.1.0"

    def test_no_external_dependencies(self):
        """Config Guard must be zero-dependency (stdlib only)."""
        import ast
        source = (PKG_SRC / "config_guard" / "__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module.split(".")[0])

        stdlib_modules = {
            "json", "os", "re", "sys", "pathlib", "argparse",
            "importlib", "collections", "typing", "abc", "functools",
            "itertools", "math", "string", "textwrap", "hashlib",
        }
        for imp in imports:
            assert imp in stdlib_modules, f"Non-stdlib import: {imp}"


class TestCoreAPI:
    def test_scan_mcp_config_exists(self):
        assert callable(config_guard.scan_mcp_config)

    def test_calculate_score_exists(self):
        assert callable(config_guard.calculate_score)

    def test_format_report_exists(self):
        assert callable(config_guard.format_report)

    def test_format_sarif_exists(self):
        assert callable(config_guard.format_sarif)

    def test_discover_mcp_configs_exists(self):
        assert callable(config_guard.discover_mcp_configs)

    def test_main_exists(self):
        assert callable(config_guard.main)


class TestCoreScanning:
    def test_clean_config_scores_100(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["dist/index.js"]}
            }}), encoding="utf-8")
            findings = config_guard.scan_mcp_config(p)
            score = config_guard.calculate_score(findings)
            assert score == 100

    def test_rug_pull_detected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "risky": {"command": "npx", "args": ["-y", "@some/pkg@latest"]}
            }}), encoding="utf-8")
            findings = config_guard.scan_mcp_config(p)
            rugs = [f for f in findings if f["category"] == "rug-pull"]
            assert len(rugs) >= 1

    def test_sarif_output_valid(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "test": {"command": "node", "args": ["server.js"]}
            }}), encoding="utf-8")
            findings = config_guard.scan_mcp_config(p)
            score = config_guard.calculate_score(findings)
            sarif = config_guard.format_sarif(findings, score)
            assert "sarif-schema-2.1.0" in sarif["$schema"]
            assert sarif["version"] == "2.1.0"

    def test_known_vulnerable_db(self):
        assert len(config_guard.KNOWN_VULNERABLE) >= 5
        assert "mcp-remote" in config_guard.KNOWN_VULNERABLE

    def test_owasp_mapping_complete(self):
        required = ["network-exposure", "rug-pull", "secret-leak", "command-injection",
                     "typosquat", "dangerous-permission", "known-vulnerable", "shadow-server"]
        for cat in required:
            assert cat in config_guard.OWASP_MAPPING


class TestCLI:
    def test_main_clean_exit(self):
        """Clean config should exit 0."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "safe": {"command": "node", "args": ["index.js"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "--json"]
            try:
                config_guard.main()
            except SystemExit as e:
                assert e.code == 0

    def test_main_critical_exit_1(self):
        """Critical findings should exit 1."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".mcp.json"
            p.write_text(json.dumps({"mcpServers": {
                "bad": {"command": "npx", "args": ["mcp-remote", "--transport", "http://evil.com"]}
            }}), encoding="utf-8")
            sys.argv = ["config-guard", "--path", td, "--json"]
            try:
                config_guard.main()
            except SystemExit as e:
                assert e.code == 1
