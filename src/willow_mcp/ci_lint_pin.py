"""ci_lint_pin — which linter version does this repo's CI actually run?

Sealed pair 11ccb0f7 (seat-inbound-channel-2026-09-21), part (4): a green
claim names the linter version it was measured under. Measured 2026-09-21
on ratatosk PR #48: the builder ran ruff 0.15.0 clean, CI pins
``ruff==0.16.7``, the lint job went red; gap afc3e12c9e17 (2026-09-11) is
the same defect one version earlier (pytest green, ruff never run). A
"lint clean" that does not say which binary measured it is an assertion,
not a measurement.

This module only *reads* the pin. It never runs a linter — the Stop-hook
green-claim gate (bundle/hooks/stop_lint_gate.py) measures; verify_handoff
judges a claim against what this module returns.

Three states, never collapsed:

* ``populated`` — a pin was found; ``version`` and ``source`` say which.
* ``empty``     — the workflows (and pyproject) were readable and pin
                  nothing; any named version is acceptable.
* ``unreachable`` — the workflow directory could not be read; ``reason``
                  says why. Callers treat this as advisory, never a refusal.

Sources, in the order they are trusted — the workflow is what CI runs;
pyproject is what a developer installs, and the two can disagree (willow-
mcp itself: tests.yml ``pip install ruff==0.15.0`` beside a pyproject test
extra ``ruff==0.16.7``). When they disagree, ``version`` is the workflow's
and ``conflicts`` names the other so the drift is legible rather than
silently resolved.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

_VERSION = r"(\d+(?:\.\d+){1,3}(?:[a-zA-Z0-9.+-]*)?)"

# `pip install ruff==0.16.7`, `pip install "ruff==0.16.7"`, `uv pip install ruff==0.16.7 bandit`
_PIP_PIN_RE = re.compile(r"\bruff\s*==\s*['\"]?" + _VERSION, re.IGNORECASE)
# `uses: astral-sh/ruff-action@v3` + `version: 0.16.7` / `version: "0.16.7"`
_ACTION_USES_RE = re.compile(r"uses:\s*['\"]?astral-sh/ruff-action@", re.IGNORECASE)
_ACTION_VERSION_RE = re.compile(r"^\s*version:\s*['\"]?" + _VERSION, re.IGNORECASE | re.MULTILINE)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _workflow_pins(workflows_dir: Path) -> list[dict[str, str]]:
    """Every ruff pin named by a workflow file, with its source."""
    pins: list[dict[str, str]] = []
    for path in sorted(workflows_dir.glob("*.y*ml")):
        text = _read_text(path)
        if text is None:
            continue
        rel = f".github/workflows/{path.name}"
        for m in _PIP_PIN_RE.finditer(text):
            pins.append({"version": m.group(1), "source": f"{rel}: pip install ruff=={m.group(1)}"})
        if _ACTION_USES_RE.search(text):
            for m in _ACTION_VERSION_RE.finditer(text):
                pins.append({"version": m.group(1), "source": f"{rel}: ruff-action version {m.group(1)}"})
    return pins


def _pyproject_pins(repo_root: Path) -> list[dict[str, str]]:
    """`[tool.ruff] required-version = "0.16.7"` (or `==0.16.7`), plus a
    `ruff==X` in any dependency group / extra — the developer-side pin."""
    pyproject = repo_root / "pyproject.toml"
    text = _read_text(pyproject)
    if text is None:
        return []
    pins: list[dict[str, str]] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        data = {}
    tool = data.get("tool") if isinstance(data, dict) else None
    ruff = tool.get("ruff") if isinstance(tool, dict) else None
    if isinstance(ruff, dict):
        req = ruff.get("required-version")
        if isinstance(req, str):
            m = re.search(_VERSION, req)
            if m:
                pins.append({"version": m.group(1), "source": f"pyproject.toml: [tool.ruff] required-version = {req!r}"})
    # Dependency specs, from the PARSED document — a comment that quotes
    # `pip install ruff==X` is prose, not a pin (Loki 15D211C7).
    project = data.get("project") if isinstance(data, dict) else None
    groups: list[tuple[str, Any]] = []
    if isinstance(project, dict):
        groups.append(("[project] dependencies", project.get("dependencies")))
        extras = project.get("optional-dependencies")
        if isinstance(extras, dict):
            groups.extend((f"[project.optional-dependencies] {k}", v) for k, v in extras.items())
    dep_groups = data.get("dependency-groups") if isinstance(data, dict) else None
    if isinstance(dep_groups, dict):
        groups.extend((f"[dependency-groups] {k}", v) for k, v in dep_groups.items())
    for where, specs in groups:
        if not isinstance(specs, list):
            continue
        for spec in specs:
            if isinstance(spec, str):
                m = _PIP_PIN_RE.search(spec)
                if m:
                    pins.append({"version": m.group(1), "source": f"pyproject.toml: {where}: {spec}"})
    return pins


def ci_lint_pin(repo_root: str | Path) -> dict[str, Any]:
    """Resolve the ruff version this repo's CI pins.

    Returns ``{"state", "tool", "version", "source", "conflicts", "reason"}``.
    ``conflicts`` lists every other pin found (version + source) when they
    disagree with the chosen one — empty when all sources agree.
    """
    root = Path(repo_root).expanduser()
    workflows_dir = root / ".github" / "workflows"
    out: dict[str, Any] = {
        "state": "empty",
        "tool": "ruff",
        "version": None,
        "source": None,
        "conflicts": [],
        "reason": "",
    }
    if not root.is_dir():
        out["state"] = "unreachable"
        out["reason"] = f"repo root not a directory: {root}"
        return out

    workflow_pins: list[dict[str, str]] = []
    if workflows_dir.exists():
        if not workflows_dir.is_dir():
            out["state"] = "unreachable"
            out["reason"] = f"{workflows_dir} is not a directory"
            return out
        try:
            workflow_pins = _workflow_pins(workflows_dir)
        except OSError as exc:
            out["state"] = "unreachable"
            out["reason"] = f"could not read {workflows_dir}: {exc}"
            return out

    project_pins = _pyproject_pins(root)
    ordered = workflow_pins + project_pins
    if not ordered:
        return out

    chosen = ordered[0]
    out["state"] = "populated"
    out["version"] = chosen["version"]
    out["source"] = chosen["source"]
    out["conflicts"] = [p for p in ordered[1:] if p["version"] != chosen["version"]]
    return out


# ── judging a lint claim ───────────────────────────────────────────────────

# What this gate judges is a CLAIM OF LINT-CLEAN — a linter word and a clean
# word in the same clause. It must never fire on a mention of the tool
# (`ruff-action`, a file named test_ci_lint_pin.py), a disclaimer ("ruff:
# not installed … no ruff run"), a disclosure of drift ("ruff 0.16.7: 29
# errors … CI measures 0.15.0"), or a test count ("21 passed"). Loki
# 15D211C7 ran the first cut over this branch's own handoff and it refused
# three honest lines; the shape below is built from those four strings.
#
# Evidence is judged clause by clause (split on ; . — | and newlines), and
# the version a claim names is the `ruff <ver>` INSIDE that clause — so
# "CI pins ruff==0.16.7; measured with ruff 0.15.0: All checks passed" is
# a 0.15.0 measurement, whichever version is written first.
_CLAUSE_SPLIT_RE = re.compile(r"(?:;|\||—|–|\n|\.\s+|\.$)")
# The linter word. `ruff` followed by `-`/`_`/`.` is a name (ruff-action,
# ruff_cache, ruff.toml), not the tool being run.
_LINTER_WORD_RE = re.compile(
    r"\bruff\b(?![-_.]\w)|\blint(?:er|ing)?\b|\bformat(?:ter|ting)?\b(?=[^\n]{0,30}\b(?:check|clean|ok|pass))",
    re.IGNORECASE,
)
# The clean word, tied to a check rather than a test count: "clean", "All
# checks passed", "no/0 errors|violations|findings", "green", "ok", "already
# formatted", "checks passed". A bare "N passed" is a test count and is NOT
# here on purpose.
_CLEAN_WORD_RE = re.compile(
    r"\bclean\b|\ball checks? passed\b|\bchecks? passed\b|\bgreen\b|\bok\b"
    r"|\b(?:no|0|zero)\s+(?:errors?|violations?|findings?|issues?|warnings?)\b"
    r"|\balready formatted\b|\bno (?:changes|files) would be reformatted\b|\bpasses\b",
    re.IGNORECASE,
)
# Honest non-claims: the tool was not run, or the line reports what was NOT
# measured. Never judged.
_DISCLAIMER_RE = re.compile(
    r"\b(?:not|never|no)\s+(?:installed|run|ran|executed|measured|available|found)\b"
    r"|\bno ruff (?:run|binary|executable)\b|\bunmeasured\b|\bnot re-?run\b|\bskipped\b|\bcould not\b|\bcannot\b",
    re.IGNORECASE,
)
# `ruff 0.16.7`, `ruff==0.16.7`, `ruff (0.16.7)`, `ruff v0.16.7`, `ruff/0.16.7`
_NAMED_VERSION_RE = re.compile(r"\bruff\b[\s=(/]*v?" + _VERSION, re.IGNORECASE)


def _clauses(text: str) -> list[str]:
    return [c.strip() for c in _CLAUSE_SPLIT_RE.split(text or "") if c and c.strip()]


def lint_claims(text: str) -> list[dict[str, Any]]:
    """Every clause of ``text`` that claims lint-clean, with the ruff
    versions that clause names. A clause is a claim when it carries a linter
    word AND a clean word AND no disclaimer."""
    out: list[dict[str, Any]] = []
    for clause in _clauses(text):
        if not _LINTER_WORD_RE.search(clause) or not _CLEAN_WORD_RE.search(clause):
            continue
        if _DISCLAIMER_RE.search(clause):
            continue
        versions = [m.group(1) for m in _NAMED_VERSION_RE.finditer(clause)]
        out.append({"clause": clause, "versions": versions})
    return out


def is_lint_claim(text: str) -> bool:
    """Does this evidence string claim lint-clean anywhere?"""
    return bool(lint_claims(text))


def named_ruff_version(text: str) -> str | None:
    """The version the FIRST lint-clean claim in ``text`` names (or, with no
    claim, the first `ruff <ver>` anywhere — for callers that only want a
    version out of a line)."""
    claims = lint_claims(text)
    if claims:
        vs = claims[0]["versions"]
        return vs[0] if vs else None
    m = _NAMED_VERSION_RE.search(text or "")
    return m.group(1) if m else None


def judge_lint_claim(evidence: str, pin: dict[str, Any]) -> dict[str, Any]:
    """Judge ONE evidence string against the resolved pin.

    Returns ``{"verdict": "accept"|"refuse"|"advisory"|"none", "reason",
    "named", "pinned"}``. ``none`` means the string makes no lint-clean
    claim and is not judged.

    * pin ``unreachable`` → ``advisory`` (never refuse on what could not be read).
    * a claim naming no version → ``refuse`` (with the pin in the message).
    * pin ``empty`` → ``accept`` any named version.
    * any claim's named version == pinned → ``accept``; else ``refuse`` naming both.
    """
    claims = lint_claims(evidence)
    pinned = pin.get("version")
    state = pin.get("state")
    if not claims:
        return {"verdict": "none", "reason": "no lint-clean claim", "named": None, "pinned": pinned}
    named_all = [v for c in claims for v in c["versions"]]
    named = named_all[0] if named_all else None
    if state == "unreachable":
        return {
            "verdict": "advisory",
            "reason": f"lint pin unreachable ({pin.get('reason') or 'unknown'}); claim not judged: {evidence!r}",
            "named": named,
            "pinned": None,
        }
    if not named:
        where = f" — CI pins ruff {pinned} ({pin.get('source')})" if pinned else ""
        return {
            "verdict": "refuse",
            "reason": (
                f"lint claim names no linter version: {claims[0]['clause']!r}{where}. "
                "A green that does not say which binary measured it is an assertion, not a measurement."
            ),
            "named": None,
            "pinned": pinned,
        }
    if state == "empty" or not pinned:
        return {"verdict": "accept", "reason": "repo pins no linter version; named version accepted", "named": named, "pinned": None}
    if pinned in named_all:
        return {"verdict": "accept", "reason": f"ruff {pinned} matches the CI pin ({pin.get('source')})", "named": pinned, "pinned": pinned}
    return {
        "verdict": "refuse",
        "reason": (
            f"lint measured with ruff {named} but CI pins ruff {pinned} ({pin.get('source')}) — "
            "different default rule sets; re-measure with the pinned binary"
        ),
        "named": named,
        "pinned": pinned,
    }


def judge_findings(findings: list, pin: dict[str, Any]) -> list[dict[str, Any]]:
    """Every lint-claiming evidence string across the findings, judged.
    Findings that make no lint claim contribute nothing."""
    from .handoff import _finding_evidence  # local: handoff imports this module

    verdicts: list[dict[str, Any]] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        for ev in _finding_evidence(f):
            v = judge_lint_claim(ev, pin)
            if v["verdict"] == "none":
                continue
            v["finding_index"] = i
            v["evidence"] = ev
            verdicts.append(v)
    return verdicts
