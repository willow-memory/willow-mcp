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

Scope of the prose judge (Loki AB9564DB, five audit passes): it judges the
ordinary report shapes; it refuses the ones it can see. It has converged on
its shapes and will never converge on prose — each pass found a new edge
by construction, and that is what a regex over prose is. A structured lint
field on a finding — ``{tool, version, outcome, source}`` — that
verify_handoff reads directly is the durable answer; this judge is the
fallback for findings that carry no such field. Gap:
handoff/lint-claim-is-a-field-not-prose. ``tests/test_ci_lint_pin.py::
test_adversarial_set`` holds every string from the five passes with its
verdict, so an edit that reopens any pass is caught by name.
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
    r"\bruff\b(?![-_.]\w|['’]s\b)|\blint(?:er|ing)?\b|\bformat(?:ter|ting)?\b(?=[^\n]{0,30}\b(?:check|clean|ok|pass))",
    re.IGNORECASE,
)
# The clean word is a LINT-OUTCOME phrase: ruff's own output ("All checks
# passed", "N files already formatted", "no/0 errors|violations|findings")
# or `clean` adjacent to the linter word ("ruff clean", "lint clean",
# "format --check clean"). Never a bare colour or mood word — `green`/`ok`
# turned "the green-claim gate reads the ruff pin" into a refused claim
# (Loki 7AA9F436). A bare "N passed" is a test count and is not here.
# `ruff's` (possessive) is a reference to the tool, not the tool being run.
_LINTER_TOKEN = r"(?:ruff\b(?![-_.]\w|['’]s\b)|lint(?:er|ing)?\b|format(?:ter|ting)?\b)"
_CLEAN_WORD_RE = re.compile(
    r"\ball checks? passed\b|\bchecks? passed\b"
    r"|\b(?:no|0|zero)\s+(?:errors?|violations?|findings?|issues?|warnings?)\b"
    r"|\balready formatted\b|\bno (?:changes|files) would be reformatted\b"
    r"|\b" + _LINTER_TOKEN + r"[^\n;|]{0,40}?\bclean\b"
    r"|\bclean\b[^\n;|]{0,20}?\b" + _LINTER_TOKEN,
    re.IGNORECASE,
)
# Honest non-claims: the tool was not run, or the line reports what was NOT
# measured. Never judged.
_DISCLAIMER_RE = re.compile(
    r"\b(?:not|never|no)\s+(?:installed|run|ran|executed|measured|available|found)\b"
    r"|\bno ruff (?:run|binary|executable)\b|\bunmeasured\b|\bnot re-?run\b"
    r"|\b(?:ruff|lint\w*|format\w*)\s+(?:was\s+)?skipped\b|\bskipped\s+(?:ruff|lint\w*)\b"
    r"|\bcould not\b|\bcannot\b",
    re.IGNORECASE,
)
# `ruff 0.16.7`, `ruff==0.16.7`, `ruff (0.16.7)`, `ruff v0.16.7`, `ruff/0.16.7`
_NAMED_VERSION_RE = re.compile(r"\bruff\b[\s=(/]*v?" + _VERSION, re.IGNORECASE)
# Any version token at all. A claim clause that carries one — anywhere —
# names it; it never inherits (Loki AC8CBA02 I2/I5: `ruff format --check
# 0.15.0: clean` is a 0.15.0 measurement, not an unnamed half). An
# interpreter/runtime version is never a ruff version: "format --check
# under python 3.12" names 3.12 as Python's, not ruff's (Loki AB9564DB X3).
_ANY_VERSION_RE = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+){0,2})(?![\w.])")
_RUNTIME_BEFORE_RE = re.compile(
    r"\b(?:python|py|cpython|pypy|node|nodejs|java|jdk|gradle|go|rust|ubuntu|macos|windows)\s*[-=:v]?\s*$",
    re.IGNORECASE,
)
# A statement of the pin is not a run: `CI pins ruff 0.16.7; ruff check:
# clean` says which binary CI uses, not which one measured (I6/I7).
_PIN_WORDING_RE = re.compile(
    r"\bpin(?:s|ned|ning)?\b|\brequired-version\b|\bCI\s+(?:measures|runs|uses|installs|wants)\b",
    re.IGNORECASE,
)
# Another tool's outcome is never a ruff claim, and never gets a ruff
# version attached (I11 and its mirror).
_OTHER_TOOL_RE = re.compile(
    r"\b(?:bandit|mypy|pyright|pytest|black|flake8|pylint|isort|codeql|semgrep|tox|nox|coverage)\b",
    re.IGNORECASE,
)


# Quoted spans are descriptions, never measurements: a builder writing
# "the clean word is `clean` adjacent to the linter word" is quoting the
# rule, not claiming a run. Real claims carry no quotes (Loki C63A2C48).
# Single quotes are stripped only when the span opens after whitespace, a
# colon or a bracket and runs ≥ 8 chars — an apostrophe (`it's`, `ruff's`)
# never opens there (Loki AC8CBA02 Q3/Q5).
_QUOTED_SPAN_RE = re.compile(
    r"`[^`\n]*`|\"[^\"\n]*\"|“[^”\n]*”|‘[^’\n]*’"
    r"|(?<=[\s:(\[])'[^'\n]{8,}?'(?=[\s.,;:)\]]|$)"
)
_QUOTE_RULE = "quote a transcript in backticks or double quotes so it is read as a description, not a claim"
# How far back an outcome-only clause may look for its linter word. A
# report habitually puts a test count between the tool line and the
# outcome line ("ruff 0.15.0. Tests: 81 passed. All checks passed."), so
# one clause is the wrong boundary; three covers the ordinary shape.
_LOOKBACK_CLAUSES = 3


def _clauses(text: str) -> list[str]:
    stripped = _QUOTED_SPAN_RE.sub(" ", text or "")
    return [c.strip() for c in _CLAUSE_SPLIT_RE.split(stripped) if c and c.strip()]


def lint_claims(text: str) -> list[dict[str, Any]]:
    """Every clause of ``text`` that claims lint-clean, with the ruff
    versions that clause names. A clause is a claim when it carries a linter
    word AND a clean word AND no disclaimer. A clause that carries only the
    outcome looks back up to ``_LOOKBACK_CLAUSES`` for the nearest clause
    with a linter word, stopping at a disclaimer or at a clause that itself
    carries an outcome — "ruff 0.15.0 was used. Tests: 81 passed. All checks
    passed." is the #48 shape as a report and must not walk past the gate
    (Loki 7AA9F436, C63A2C48)."""
    out: list[dict[str, Any]] = []
    clauses = _clauses(text)

    def _versions_in(clause: str) -> list[str]:
        """Versions a clause names AS THE BINARY: `ruff <ver>` first, then
        any version token in a clause that carries the linter word — except
        a runtime version ("python 3.12") and, in a clause with pin wording,
        any version that follows the pin words: "ruff check: All checks
        passed (CI pins 0.16.7)" names the pin, not the binary (Loki
        AB9564DB X1/X1b); "ruff 0.16.7 (tests.yml pin) check" names the
        binary before the annotation and stays named."""
        pin_at = None
        pm = _PIN_WORDING_RE.search(clause)
        if pm:
            pin_at = pm.start()

        def _before_pin(m: re.Match) -> bool:
            return pin_at is None or m.start() < pin_at

        named = [m.group(1) for m in _NAMED_VERSION_RE.finditer(clause) if _before_pin(m)]
        if named:
            return named
        if _LINTER_WORD_RE.search(clause):
            out: list[str] = []
            for m in _ANY_VERSION_RE.finditer(clause):
                if not _before_pin(m):
                    continue
                if _RUNTIME_BEFORE_RE.search(clause[max(0, m.start() - 12) : m.start()]):
                    continue
                out.append(m.group(1))
            return out
        return []

    def _lookahead(i: int) -> tuple[str, list[str]] | None:
        """Outcome written before the tool: "All checks passed; ruff 0.15.0
        was the binary" — one forward step to a same-tool line that names a
        version and is not itself an outcome, a disclaimer or a pin
        statement (Loki AB9564DB X2)."""
        if i + 1 >= len(clauses):
            return None
        nxt = clauses[i + 1]
        if _DISCLAIMER_RE.search(nxt) or _CLEAN_WORD_RE.search(nxt) or _OTHER_TOOL_RE.search(nxt):
            return None
        if not _LINTER_WORD_RE.search(nxt) or (_PIN_WORDING_RE.search(nxt) and not _CLEAN_WORD_RE.search(nxt)):
            return None
        vs = _versions_in(nxt)
        return (nxt, vs) if vs else None

    def _inherit(i: int) -> tuple[str, list[str]] | None:
        """The nearest earlier clause (≤ _LOOKBACK_CLAUSES) that is a RUN of
        the linter — carries the linter word and a version, no disclaimer,
        no pin wording — or None. Stops at a disclaimer, and past the first
        step at any clause that carries its own outcome (Loki AC8CBA02:
        a mention of the pin is not a run)."""
        unnamed_run: tuple[str, list[str]] | None = None
        for back in range(1, _LOOKBACK_CLAUSES + 1):
            j = i - back
            if j < 0:
                break
            prev = clauses[j]
            if _DISCLAIMER_RE.search(prev):
                break
            if _LINTER_WORD_RE.search(prev):
                # A pin statement with no outcome is a mention, not a run
                # ("CI pins ruff 0.16.7"). An outcome-bearing clause that
                # also names the pin is a run that says so ("ruff 0.16.7
                # (tests.yml pin) check: All checks passed").
                if _PIN_WORDING_RE.search(prev) and not _CLEAN_WORD_RE.search(prev):
                    break
                vs = _versions_in(prev)
                if vs:
                    return prev, vs
                # A same-tool run with no version of its own ("ruff format
                # --check: clean") is part of the same report: keep walking
                # for the clause that named the binary.
                unnamed_run = unnamed_run or (prev, [])
                continue
            if back > 1 and _CLEAN_WORD_RE.search(prev):
                break  # someone else's outcome: not this report
        return unnamed_run

    for i, clause in enumerate(clauses):
        if not _CLEAN_WORD_RE.search(clause) or _DISCLAIMER_RE.search(clause):
            continue
        if _LINTER_WORD_RE.search(clause):
            versions = _versions_in(clause)
            if not versions and not _OTHER_TOOL_RE.search(clause):
                # "ruff 0.16.7 check: All checks passed; format --check: 232
                # files already formatted" — one run, two clauses: the
                # unnamed half inherits from the run the same line named.
                # Only when it carries no version token of its own and
                # names no other tool.
                found = _inherit(i)
                if found and found[1]:
                    out.append({"clause": f"{found[0]} / {clause}", "versions": found[1]})
                    continue
            out.append({"clause": clause, "versions": versions})
            continue
        if _OTHER_TOOL_RE.search(clause) or _ANY_VERSION_RE.search(clause):
            # Another tool's outcome, or an outcome with its own version and
            # no linter word — neither is a ruff claim (I11 and its mirror).
            continue
        found = _inherit(i) or _lookahead(i)
        if found:
            out.append({"clause": f"{found[0]} / {clause}", "versions": found[1]})
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
    * pin ``empty`` → ``accept`` when every claim names some version.
    * judged PER CLAIM: every claim must name the pin; one claim naming
      another version refuses, naming it (a half-measured tree does not
      pass beside a measured one — Loki C63A2C48).
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
    unnamed = [c for c in claims if not c["versions"]]
    if unnamed:
        where = f" — CI pins ruff {pinned} ({pin.get('source')})" if pinned else ""
        return {
            "verdict": "refuse",
            "reason": (
                f"lint claim names no linter version: {unnamed[0]['clause']!r}{where}. "
                "A green that does not say which binary measured it is an assertion, not a measurement "
                f"(if this line is a quoted transcript, {_QUOTE_RULE})."
            ),
            "named": None,
            "pinned": pinned,
        }
    if state == "empty" or not pinned:
        return {"verdict": "accept", "reason": "repo pins no linter version; named versions accepted", "named": named, "pinned": None}
    wrong = [c for c in claims if pinned not in c["versions"]]
    if wrong:
        bad = wrong[0]["versions"][0]
        return {
            "verdict": "refuse",
            "reason": (
                f"lint measured with ruff {bad} but CI pins ruff {pinned} ({pin.get('source')}) "
                f"in {wrong[0]['clause']!r} — different default rule sets; re-measure with the pinned binary"
            ),
            "named": bad,
            "pinned": pinned,
        }
    return {"verdict": "accept", "reason": f"ruff {pinned} matches the CI pin ({pin.get('source')}) in every claim", "named": pinned, "pinned": pinned}


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
