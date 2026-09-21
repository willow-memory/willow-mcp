"""Tests for the pre-exec install CVE gate (P3).

The subprocess is faked at the runner seam — a hand-written double passed in,
not a patched-out module — so `_audit_pip`'s own parsing, tempfile handling and
threshold logic all run for real. No test here invokes pip-audit or the network.
"""

from __future__ import annotations

import json

import pytest

from willow_mcp import install_audit


def _runner_returning(payload: dict, rc: int = 1):
    """A runner double that returns `payload` as pip-audit JSON on stdout."""
    def runner(argv, timeout):
        return rc, json.dumps(payload), ""
    return runner


def _vuln_payload(name="evilpkg", version="1.0.0", severity="high", vid="CVE-2024-0001"):
    return {"dependencies": [{"name": name, "version": version,
                              "vulns": [{"id": vid, "severity": severity}]}]}


# ── detection ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("command,manager", [
    ("pip install requests", "pip"),
    ("pip3 install numpy==1.0", "pip"),
    ("npm install left-pad", "npm"),
    ("npm i react", "npm"),
    ("yarn add lodash", "yarn"),
    ("pnpm add vue", "pnpm"),
])
def test_detects_install_commands(command, manager):
    assert install_audit.detect_install_command(command) == manager


@pytest.mark.parametrize("command", [
    "echo hello",
    "python -c 'print(1)'",
    "grep install file.txt",       # 'install' as data, not a manager verb
    "./configure && make install",  # make install is not a package manager
])
def test_ignores_non_install_commands(command):
    assert install_audit.detect_install_command(command) is None


# ── pip package extraction ───────────────────────────────────────────────────


def test_extracts_pip_specs_and_drops_flags():
    pkgs = install_audit.extract_pip_packages(
        "pip install --upgrade requests==2.0 flask -i https://pypi.org/simple numpy")
    assert pkgs == ["requests==2.0", "flask", "numpy"]


def test_extracts_across_chained_installs():
    pkgs = install_audit.extract_pip_packages("pip install a && pip3 install b c")
    assert pkgs == ["a", "b", "c"]


def test_requirements_install_yields_no_named_specs():
    assert install_audit.extract_pip_packages("pip install -r requirements.txt") == []


# ── audit_command decisions ──────────────────────────────────────────────────


def test_a_high_vuln_at_threshold_blocks():
    result = install_audit.audit_command(
        "pip install evilpkg==1.0.0",
        block_severity="high",
        runner=_runner_returning(_vuln_payload(severity="high")))
    assert result.action == "block"
    assert result.vulnerabilities[0].vuln_id == "CVE-2024-0001"


def test_a_vuln_below_threshold_allows():
    result = install_audit.audit_command(
        "pip install mildpkg",
        block_severity="high",
        runner=_runner_returning(_vuln_payload(severity="low")))
    assert result.action == "allow"
    assert result.vulnerabilities  # the finding is still recorded, just not blocking


def test_no_vulns_allows():
    result = install_audit.audit_command(
        "pip install cleanpkg", block_severity="high",
        runner=_runner_returning({"dependencies": [{"name": "cleanpkg",
                                                     "version": "1", "vulns": []}]}))
    assert result.action == "allow"
    assert result.vulnerabilities == []


def test_absent_tool_degrades_to_a_warning_not_a_block():
    def missing(argv, timeout):
        return -1, "", "tool not found: pip-audit"

    result = install_audit.audit_command(
        "pip install anything", runner=missing)
    assert result.action == "warn"
    assert result.vulnerabilities == []


def test_a_requirements_install_is_allowed_with_caution():
    calls = []

    def runner(argv, timeout):
        calls.append(argv)
        return 0, "{}", ""

    result = install_audit.audit_command("pip install -r reqs.txt", runner=runner)
    assert result.action == "warn"
    assert calls == []  # nothing to audit, so pip-audit was never invoked


def test_an_npm_install_is_detected_but_not_audited_at_submit_time():
    result = install_audit.audit_command("npm install left-pad")
    assert result.manager == "npm"
    assert result.action == "warn"


def test_a_non_install_command_is_not_audited():
    assert install_audit.audit_command("python train.py") is None


def test_threshold_comes_from_the_env(monkeypatch):
    monkeypatch.setenv("WILLOW_INSTALL_AUDIT_SEVERITY", "critical")
    # A HIGH vuln does not clear a CRITICAL threshold.
    result = install_audit.audit_command(
        "pip install x", runner=_runner_returning(_vuln_payload(severity="high")))
    assert result.action == "allow"


# ── gate_task (the submit-time contract) ─────────────────────────────────────


def test_gate_task_returns_a_refusal_on_a_blocking_vuln():
    refusal = install_audit.gate_task(
        "pip install evilpkg", block_severity="high",
        runner=_runner_returning(_vuln_payload(severity="critical")))
    assert refusal is not None
    assert refusal["error"].startswith("INSTALL-AUDIT:")
    assert refusal["install_audit"]["action"] == "block"


def test_gate_task_allows_a_clean_or_unauditable_install():
    assert install_audit.gate_task("pip install -r reqs.txt") is None
    assert install_audit.gate_task("echo not an install") is None


# ── wiring into task_submit ──────────────────────────────────────────────────


def test_task_submit_blocks_a_vulnerable_pip_install(monkeypatch):
    """The gate runs at submit time, before any queue work, so a vulnerable
    install never occupies a slot. `__wrapped__` bypasses the permission guard,
    which is exercised elsewhere."""
    from willow_mcp import server

    monkeypatch.setattr(install_audit, "_default_runner",
                        _runner_returning(_vuln_payload(severity="high")))
    # If the DB were reached the test would still pass, but assert it is not:
    monkeypatch.setattr(server, "get_pg",
                        lambda: pytest.fail("reached the queue for a blocked install"))

    fn = getattr(server.task_submit, "__wrapped__", server.task_submit)
    out = fn(app_id="tester", task="pip install evilpkg==1.0.0")
    assert "INSTALL-AUDIT" in out["error"]
    assert out["install_audit"]["action"] == "block"
