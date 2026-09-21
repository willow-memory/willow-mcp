"""Pre-exec CVE gate for package-install commands in Kart task bodies.

P3 of the ShibaClaw safety-adoption spec (design ported from
`shibaclaw/security/install_audit.py`, Apache-2.0; rewritten sync, stdlib-only,
with an injectable runner seam so the tests use a hand-written double rather
than module mocking, per willow's test policy).

Kart tasks run arbitrary shell through kartikeya's `sandbox.run_shell`. A task
body can carry `pip install <pkg>`; when the task also holds an egress lease
that install reaches an index. This gate runs at SUBMIT time (in the broker,
alongside `check_kart_task`), where the environment to run `pip-audit` exists —
not inside the network-isolated sandbox, which could not query an advisory DB.

Shape mirrors `check_kart_task`: `gate_task` returns a refusal dict
(`{"error": "INSTALL-AUDIT: ...", "install_audit": {...}}`) when a resolved
package carries a vulnerability at or above the configured severity, and None
otherwise. It **degrades open**: if the audit tool is absent, times out, or
cannot resolve the packages, the install is allowed with a logged warning
rather than hard-failed — an audit that cannot run is not a verdict, and the
worker re-checks every host gate at execution regardless.

Scope: pip is audited for real (`pip-audit -r` over the extracted specs).
npm/yarn/pnpm installs are detected and allowed-with-caution — auditing them
needs a project/lockfile context that does not exist for a bare
`npm install <pkg>` at submit time; the detection is here so the follow-on can
close it without re-plumbing the seam.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess  # nosec B404 — used only to invoke pip-audit with a fixed argv, never a shell
import tempfile
from dataclasses import dataclass, field

log = logging.getLogger("willow_mcp.install_audit")

#: Severity rank, most severe first. UNKNOWN sorts below LOW so an
#: unclassified finding never trips a threshold on its own.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
_DEFAULT_BLOCK_SEVERITY = "high"
_AUDIT_TIMEOUT_SECONDS = 120
_ENV_SEVERITY = "WILLOW_INSTALL_AUDIT_SEVERITY"

#: pip flags that consume the following token, so it is not a package spec.
_PIP_ARG_FLAGS = frozenset({
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-t", "--target", "--prefix", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links",
})

_INSTALL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pip", re.compile(r"\bpip3?\s+install\b", re.IGNORECASE)),
    ("npm", re.compile(r"\bnpm\s+(?:install|add|i)\b", re.IGNORECASE)),
    ("yarn", re.compile(r"\byarn\s+(?:add|install)\b", re.IGNORECASE)),
    ("pnpm", re.compile(r"\bpnpm\s+(?:install|add)\b", re.IGNORECASE)),
]
_PIP_INSTALL_RE = re.compile(r"\bpip3?\s+install\s+([^&;|\n]+)", re.IGNORECASE)


def _severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get((sev or "unknown").lower().strip(), 0)


@dataclass
class Vulnerability:
    package: str
    version: str
    vuln_id: str
    severity: str = "unknown"
    description: str = ""

    def as_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "id": self.vuln_id,
            "severity": self.severity,
        }


@dataclass
class AuditResult:
    """Outcome of auditing one install command.

    `action` is one of allow / block / warn. `warn` allows the install but
    records why the audit could not stand behind it (tool absent, unparseable
    package list, timeout).
    """

    manager: str
    action: str = "allow"
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "manager": self.manager,
            "action": self.action,
            "vulnerabilities": [v.as_dict() for v in self.vulnerabilities],
            "warnings": self.warnings,
            "summary": self.summary,
        }


def detect_install_command(command: str) -> str | None:
    """The package manager an install command names, or None if it is not one."""
    for manager, pattern in _INSTALL_PATTERNS:
        if pattern.search(command or ""):
            return manager
    return None


def extract_pip_packages(command: str) -> list[str]:
    """Package specs from every `pip install ...` clause in a (possibly chained)
    command, with flags and their consumed arguments dropped."""
    packages: list[str] = []
    for match in _PIP_INSTALL_RE.finditer(command or ""):
        skip_next = False
        for token in match.group(1).strip().split():
            if skip_next:
                skip_next = False
                continue
            if token.startswith("-"):
                if token in _PIP_ARG_FLAGS:
                    skip_next = True
                continue
            packages.append(token)
    return packages


def _default_runner(argv: list[str], timeout: int) -> tuple[int, str, str]:
    """Invoke an audit tool with a fixed argv (never a shell).

    The seam the tests replace with a hand-written double. Returns
    ``(returncode, stdout, stderr)``; a missing tool comes back as
    ``(-1, "", "tool not found: ...")`` so the caller degrades to a warning
    instead of raising.
    """
    try:
        proc = subprocess.run(  # nosec B603 — fixed argv, shell=False, no user-interpolated tokens
            argv, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"tool not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", "audit timed out"


def _parse_pip_audit_json(output: str) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError, TypeError):
        return vulns
    deps = data if isinstance(data, list) else data.get("dependencies", [])
    if not isinstance(deps, list):
        return vulns
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name", "unknown")
        version = dep.get("version", "?")
        for v in dep.get("vulns", []) or []:
            if not isinstance(v, dict):
                continue
            aliases = v.get("aliases") or []
            vuln_id = v.get("id") or (aliases[0] if aliases else "UNKNOWN")
            vulns.append(Vulnerability(
                package=name,
                version=version,
                vuln_id=vuln_id,
                severity=(v.get("severity") or "unknown").lower(),
                description=(v.get("description") or "")[:200],
            ))
    return vulns


def _audit_pip(command: str, *, block_severity: str, runner, timeout: int) -> AuditResult:
    result = AuditResult(manager="pip")
    packages = extract_pip_packages(command)
    if not packages:
        # `pip install -r reqs.txt` or an editable/source install — nothing to
        # audit by name. Allow with caution rather than block on absence.
        result.action = "warn"
        result.summary = "no explicit pip packages to audit (e.g. -r/-e install)"
        result.warnings.append(result.summary)
        return result

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(packages))
        reqs_path = fh.name
    try:
        rc, stdout, stderr = runner(
            ["pip-audit", "--format", "json", "--progress-spinner=off",
             "-r", reqs_path],
            timeout)
    finally:
        try:
            os.unlink(reqs_path)
        except OSError:
            pass

    if rc < 0:
        # Tool absent or timed out — degrade to a warning, never a hard block.
        result.action = "warn"
        result.summary = f"pip-audit could not run ({stderr.strip() or 'unknown'})"
        result.warnings.append(result.summary)
        return result

    result.vulnerabilities = _parse_pip_audit_json(stdout)
    threshold = _severity_rank(block_severity)
    blocking = [v for v in result.vulnerabilities
                if _severity_rank(v.severity) >= threshold]
    if blocking:
        result.action = "block"
        result.summary = (
            f"{len(blocking)} vulnerability(ies) at/above {block_severity} in "
            + ", ".join(sorted({v.package for v in blocking})))
    else:
        result.summary = (
            f"no vulnerabilities at/above {block_severity} in "
            + ", ".join(packages))
    return result


def audit_command(command: str, *, block_severity: str | None = None,
                  runner=None, timeout: int = _AUDIT_TIMEOUT_SECONDS) -> AuditResult | None:
    """Audit a single install command, or None when it is not an install.

    `runner` is the injectable subprocess seam (defaults to `_default_runner`).
    `block_severity` defaults to the `WILLOW_INSTALL_AUDIT_SEVERITY` env value,
    then `high`.
    """
    manager = detect_install_command(command)
    if manager is None:
        return None
    block_severity = (block_severity
                      or os.environ.get(_ENV_SEVERITY)
                      or _DEFAULT_BLOCK_SEVERITY).lower().strip()
    runner = runner or _default_runner
    if manager == "pip":
        return _audit_pip(command, block_severity=block_severity,
                          runner=runner, timeout=timeout)
    # npm/yarn/pnpm: detected, but a bare `npm install <pkg>` has no lockfile to
    # audit at submit time. Allow with caution; the follow-on can close it.
    result = AuditResult(manager=manager, action="warn")
    result.summary = f"{manager} install detected; not audited at submit time"
    result.warnings.append(result.summary)
    return result


def gate_task(task: str, *, block_severity: str | None = None,
              runner=None) -> dict | None:
    """A refusal dict when the task's install command carries a blocking CVE,
    else None. Warnings (tool absent, unaudited manager) allow the task and are
    logged — the same degrade-open contract `check_kart_task` has.
    """
    result = audit_command(task or "", block_severity=block_severity, runner=runner)
    if result is None:
        return None
    if result.warnings:
        log.warning("install audit could not fully vet a %s install: %s",
                    result.manager, "; ".join(result.warnings))
    if result.action == "block":
        return {
            "error": f"INSTALL-AUDIT: {result.summary}",
            "install_audit": result.as_dict(),
        }
    return None
