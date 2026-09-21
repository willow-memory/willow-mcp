"""Sealed pair 11ccb0f7 part (4): a green claim names its linter, judged
against the version the repo's CI pins.

ratatosk #48 (2026-09-21): builder measured ruff 0.15.0 clean, CI pinned
0.16.7, lint went red. These tests pin the resolver's three shapes and
three states, and verify_handoff's judgement of a lint claim.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from willow_mcp import ci_lint_pin as clp
from willow_mcp.handoff import verify_handoff


# ── the adversarial set: every string from the five audit passes ────────────
#
# One labelled list so an edit that reopens any pass is caught by name.
# Strings are verbatim from Loki's handoffs (15D211C7, 7AA9F436, C63A2C48,
# AC8CBA02, AB9564DB) where the handoff quoted them; the ones Loki only
# described (I4, I8, I9, C8, C9, X5, X6) are Hanuman's reconstructions of
# the described shape and are marked `~`. Verdict is (verdict, named) at
# pin 0.16.7 unless the row names another pin.
_P167 = {"state": "populated", "version": "0.16.7", "source": "tests.yml"}
_P150 = {"state": "populated", "version": "0.15.0", "source": "tests.yml"}
_PEMPTY = {"state": "empty", "version": None, "source": None}

ADVERSARIAL_SET = [
    # pass 1 — 15D211C7
    ("N1", "tests/test_ci_lint_pin.py: 21 passed — pip pin, ruff-action, required-version", "none", None, _P167),
    ("N2", "ruff: not installed in any venv on the box and not a dev dep — no ruff run", "none", None, _P167),
    ("N3", "ruff 0.16.7 check on the six changed files: 29 errors (UP045, PLW1510) — 20 pre-existing; not fixed: CI measures 0.15.0", "none", None, _P167),
    ("R2@150", "CI pins ruff==0.16.7 in tests.yml; measured with ruff 0.15.0: All checks passed", "accept", "0.15.0", _P150),
    ("R2", "CI pins ruff==0.16.7 in tests.yml; measured with ruff 0.15.0: All checks passed", "refuse", "0.15.0", _P167),
    # pass 2 — 7AA9F436
    ("E2", "the green claim gate reads the ruff pin", "none", None, _P167),
    ("E3", "the lint job went green on CI (ruff 0.16.7)", "none", None, _P167),
    ("E4", "passes; ruff 0.15.0 not run", "none", None, _P167),
    ("E5", "81 passed; ruff 0.15.0 check clean", "refuse", "0.15.0", _P167),
    ("E8", "bandit 1.7: no issues found; lint clean", "refuse", None, _P167),
    ("R1", "ruff 0.15.0 check src tests: All checks passed", "refuse", "0.15.0", _P167),
    ("R3", "lint clean, format clean", "refuse", None, _P167),
    ("S1", "ruff 0.15.0 was used. All checks passed.", "refuse", "0.15.0", _P167),
    ("S1n", "ruff 0.15.0\nAll checks passed", "refuse", "0.15.0", _P167),
    ("S1d", "Ruff v0.15.0 — All checks passed!", "refuse", "0.15.0", _P167),
    ("V1", "0.16.7 clean", "none", None, _P167),
    ("V2", "0.15.0: All checks passed", "none", None, _P167),
    ("C1", "37 conformance checks passed", "none", None, _P167),
    ("C2", "ruff-action@v3 pinned; checks passed on CI", "none", None, _P167),
    ("C4", "232 files already formatted (ruff 0.16.7)", "accept", "0.16.7", _P167),
    ("C5", "no findings from bandit; ruff not run", "none", None, _P167),
    ("C6", "lint: no errors (ruff 0.16.7)", "accept", "0.16.7", _P167),
    # pass 3 — C63A2C48
    ("C7", "ruff 0.15.0 clean on src; ruff 0.16.7 clean on tests", "refuse", "0.15.0", _P167),
    ("~C8", "ruff 0.16.7 clean on src; ruff 0.16.7 clean on tests; ruff 0.15.0 clean on scripts", "refuse", "0.15.0", _P167),
    ("~C9", "ruff 0.16.7 check src: All checks passed; ruff format --check: clean; 232 files already formatted", "accept", "0.16.7", _P167),
    ("Q1", "src/ci_lint_pin.py: the clean word is ruff's own outcome phrase (\"All checks passed\") or `clean` adjacent to the linter word", "none", None, _P167),
    ("Q2", "judge: a clean word is `clean` adjacent to the linter word — described, not claimed", "none", None, _P167),
    ("L1", "ruff 0.15.0. All checks passed.", "refuse", "0.15.0", _P167),
    ("L2", "ruff 0.15.0. Tests: 81 passed. All checks passed.", "refuse", "0.15.0", _P167),
    # pass 4 — AC8CBA02
    ("I1", "ruff 0.16.7 check: All checks passed; format --check: 232 files already formatted", "accept", "0.16.7", _P167),
    ("I2", "ruff 0.16.7 check: All checks passed; ruff format --check: 0.15.0 was used, clean", "refuse", "0.15.0", _P167),
    ("I3", "ruff 0.16.7 --version; ruff check: clean", "accept", "0.16.7", _P167),
    ("~I4", "pytest: 81 passed; format --check clean", "refuse", None, _P167),
    ("I5", "ruff 0.16.7 check: All checks passed; ruff format --check 0.15.0: clean", "refuse", "0.15.0", _P167),
    ("I6", "CI pins ruff 0.16.7; ruff check: clean", "refuse", None, _P167),
    ("I7", "the pin is ruff==0.16.7; lint clean", "refuse", None, _P167),
    ("~I8", "ruff 0.16.7 check: All checks passed. ruff not run on tests. format --check: clean", "refuse", None, _P167),
    ("~I9", "ruff 0.15.0: 29 errors. ruff 0.16.7 check: All checks passed", "accept", "0.16.7", _P167),
    ("I10", "ruff 0.16.7\nAll checks passed", "accept", "0.16.7", _P167),
    ("I11", "ruff 0.16.7 check: All checks passed; bandit: no findings", "accept", "0.16.7", _P167),
    ("I11m", "ruff 0.15.0 check: 3 errors. mypy: no errors", "none", None, _P167),
    ("L2p", "ruff 0.16.7. Tests: 81 passed. 2 skipped. All checks passed.", "accept", "0.16.7", _P167),
    ("L4", "ruff 0.15.0. a. b. c. All checks passed.", "none", None, _P167),
    ("SK", "Tests: 81 passed. 2 skipped.", "none", None, _P167),
    ("Q3@150", "adversarial: '81 passed; ruff 0.16.7 check clean' accept 0.16.7", "none", None, _P150),
    ("Q4", "ruff 0.16.7 check: All checks passed; it's clean", "accept", "0.16.7", _P167),
    ("Q5", "over the transcript 'ruff 0.15.0 check: All checks passed' the gate said refuse", "none", None, _P167),
    ("PA", "ruff 0.16.7 (tests.yml pin) check: All checks passed; format --check: 232 files already formatted; 41 passed", "accept", "0.16.7", _P167),
    # pass 5 — AB9564DB
    ("X1", "ruff check: All checks passed (CI pins 0.16.7)", "refuse", None, _P167),
    ("X1b", "ruff check (tests.yml pins ruff==0.16.7): All checks passed", "refuse", None, _P167),
    ("X2", "All checks passed; ruff 0.15.0 was the binary", "refuse", "0.15.0", _P167),
    ("X2b", "All checks passed\nruff 0.15.0", "refuse", "0.15.0", _P167),
    ("X3", "ruff 0.16.7 check: All checks passed; format --check under python 3.12: 232 files already formatted", "accept", "0.16.7", _P167),
    ("X3b", "ruff 0.16.7 check on Python 3.14.4: All checks passed", "accept", "0.16.7", _P167),
    ("X3c", "ruff check: All checks passed on python 3.12", "refuse", None, _P167),
    ("X4", "ruff-check 0.15.0 clean", "none", None, _P167),
    ("~X5@empty", "ruff 0.15.0 check: All checks passed", "accept", "0.15.0", _PEMPTY),
    ("~X6@empty", "lint clean", "refuse", None, _PEMPTY),
]


def test_adversarial_set():
    """Every string from the five audit passes, by name. A failure here names
    the pass it reopened."""
    failures = []
    for label, text, want_verdict, want_named, pin in ADVERSARIAL_SET:
        v = clp.judge_lint_claim(text, pin)
        got = (v["verdict"], v["named"] if v["verdict"] != "none" else None)
        if got != (want_verdict, want_named):
            failures.append(f"{label}: want {(want_verdict, want_named)}, got {got} — {text!r}")
    assert not failures, "\n".join(failures)


# ── resolver ───────────────────────────────────────────────────────────────


def _repo(tmp_path: Path, workflow: str | None = None, pyproject: str | None = None) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    if workflow is not None:
        wf = root / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "tests.yml").write_text(workflow, encoding="utf-8")
    if pyproject is not None:
        (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    return root


def test_pin_from_pip_install_in_workflow(tmp_path):
    root = _repo(tmp_path, workflow="steps:\n  - run: pip install ruff==0.16.7 bandit\n  - run: ruff check .\n")
    pin = clp.ci_lint_pin(root)
    assert pin["state"] == "populated"
    assert pin["version"] == "0.16.7"
    assert pin["source"].startswith(".github/workflows/tests.yml")
    assert pin["conflicts"] == []


def test_pin_from_ruff_action_version(tmp_path):
    root = _repo(
        tmp_path,
        workflow="steps:\n  - uses: astral-sh/ruff-action@v3\n    with:\n      version: \"0.15.0\"\n",
    )
    pin = clp.ci_lint_pin(root)
    assert pin["state"] == "populated"
    assert pin["version"] == "0.15.0"
    assert "ruff-action" in pin["source"]


def test_pin_from_pyproject_required_version(tmp_path):
    root = _repo(tmp_path, pyproject='[tool.ruff]\nrequired-version = "==0.14.2"\n')
    pin = clp.ci_lint_pin(root)
    assert pin["state"] == "populated"
    assert pin["version"] == "0.14.2"
    assert "required-version" in pin["source"]


def test_workflow_pin_wins_and_pyproject_disagreement_is_named(tmp_path):
    """willow-mcp's own shape on 2026-09-21: tests.yml installs 0.15.0 while
    the pyproject test extra pins 0.16.7. CI runs the workflow; the other is
    reported, never silently resolved."""
    root = _repo(
        tmp_path,
        workflow="  - run: pip install ruff==0.15.0\n",
        pyproject='[project.optional-dependencies]\ntest = ["ruff==0.16.7"]\n',
    )
    pin = clp.ci_lint_pin(root)
    assert pin["version"] == "0.15.0"
    assert [c["version"] for c in pin["conflicts"]] == ["0.16.7"]


def test_no_pin_is_empty_not_unreachable(tmp_path):
    root = _repo(tmp_path, workflow="steps:\n  - run: pytest -q\n", pyproject="[tool.ruff]\nline-length = 100\n")
    pin = clp.ci_lint_pin(root)
    assert pin["state"] == "empty"
    assert pin["version"] is None


def test_missing_repo_root_is_unreachable(tmp_path):
    pin = clp.ci_lint_pin(tmp_path / "nowhere")
    assert pin["state"] == "unreachable"
    assert "not a directory" in pin["reason"]


def test_workflows_path_that_is_a_file_is_unreachable(tmp_path):
    root = tmp_path / "repo"
    (root / ".github").mkdir(parents=True)
    (root / ".github" / "workflows").write_text("not a dir", encoding="utf-8")
    pin = clp.ci_lint_pin(root)
    assert pin["state"] == "unreachable"


# ── claim detection ────────────────────────────────────────────────────────


def test_lint_claim_detection_is_a_claim_not_a_mention():
    assert clp.is_lint_claim("ruff check src tests: All checks passed!")
    assert clp.is_lint_claim("lint clean")
    assert clp.is_lint_claim("ruff format --check: 63 files already formatted")
    assert not clp.is_lint_claim("tests/test_lint_pin.py: 7 passed")
    assert not clp.is_lint_claim("360 passed, 2 skipped in 10.1s")


def test_honest_non_claims_are_not_judged():
    """Loki 15D211C7: the first cut refused this branch's own handoff on
    these. A mention, a disclaimer, a drift disclosure and a test count are
    not claims of lint-clean."""
    _pin = {"state": "populated", "version": "0.15.0", "source": "tests.yml"}
    for text in [
        "tests/test_ci_lint_pin.py: 21 passed — pip pin, ruff-action, required-version",
        "ruff: not installed in any venv on the box and not a dev dep — no ruff run",
        "ruff 0.16.7 check on the six changed files: 29 errors (UP045, PLW1510) — 20 pre-existing; not fixed: CI measures 0.15.0",
        "ci_lint_pin(willow-mcp) → version 0.15.0, conflicts [{0.16.7, pyproject.toml: ruff==0.16.7}]",
        "ruff 0.15.0 check: 3 errors, 2 fixable",
    ]:
        assert not clp.is_lint_claim(text), text
        assert clp.judge_lint_claim(text, _pin)["verdict"] == "none", text


def test_prose_with_a_colour_word_is_not_a_claim():
    """Loki 7AA9F436 E2/E3: a bare `green`/`ok` beside the tool's name is
    prose, not a measurement — the sentence describing this feature must
    not be refused by it."""
    _pin = {"state": "populated", "version": "0.15.0", "source": "tests.yml"}
    for text in [
        "the green claim gate reads the ruff pin",
        "the green-claim gate now reads the ruff pin via ci_lint_pin",
        "the lint job went green on CI (ruff 0.16.7)",
        "ruff is ok to bump; lint job untouched",
    ]:
        assert clp.judge_lint_claim(text, _pin)["verdict"] == "none", text


def test_clean_claim_split_across_a_clause_looks_back_for_the_linter():
    """Loki 7AA9F436 S1: the #48 shape written as two sentences, a newline,
    or an em-dash must still be judged — and refused on the wrong version."""
    _pin = {"state": "populated", "version": "0.16.7", "source": "tests.yml"}
    for text in [
        "ruff 0.15.0 was used. All checks passed.",
        "ruff 0.15.0\nAll checks passed",
        "Ruff v0.15.0 — All checks passed!",
    ]:
        v = clp.judge_lint_claim(text, _pin)
        assert v["verdict"] == "refuse", text
        assert v["named"] == "0.15.0" and "0.16.7" in v["reason"], text
    assert clp.judge_lint_claim("ruff 0.16.7 was used. All checks passed.", _pin)["verdict"] == "accept"
    assert clp.judge_lint_claim("pytest -q. All checks passed.", _pin)["verdict"] == "none"
    assert clp.judge_lint_claim("ruff 0.15.0 not run. All checks passed.", _pin)["verdict"] == "none"


def test_every_claim_must_name_the_pin():
    """Loki C63A2C48 C7: a wrong-version clean claim riding beside a
    pinned-version one must refuse — a half-measured tree does not pass."""
    _pin = {"state": "populated", "version": "0.16.7", "source": "tests.yml"}
    v = clp.judge_lint_claim("ruff 0.15.0 clean on src; ruff 0.16.7 clean on tests", _pin)
    assert v["verdict"] == "refuse"
    assert v["named"] == "0.15.0" and "0.16.7" in v["reason"] and "src" in v["reason"]
    v = clp.judge_lint_claim("ruff 0.16.7 clean on src; ruff 0.16.7 format --check clean", _pin)
    assert v["verdict"] == "accept"
    # One run reported as two clauses: the unnamed half inherits the
    # version the same line named (the ordinary "check; format --check" shape).
    v = clp.judge_lint_claim("ruff 0.16.7 check: All checks passed; format --check: 232 files already formatted", _pin)
    assert v["verdict"] == "accept"
    v = clp.judge_lint_claim("ruff 0.15.0 check clean; format --check clean", _pin)
    assert v["verdict"] == "refuse" and v["named"] == "0.15.0"
    # An unnamed claim with nothing to inherit from still refuses.
    v = clp.judge_lint_claim("pytest: 81 passed; format --check clean", _pin)
    assert v["verdict"] == "refuse" and "names no linter version" in v["reason"]


def test_inheritance_never_hides_a_version_and_never_reads_a_pin_as_a_run():
    """Loki AC8CBA02 I2/I5/I6/I7: a version token anywhere in the
    inheriting clause names it; a statement of the pin is not a run."""
    _pin = {"state": "populated", "version": "0.16.7", "source": "tests.yml"}
    for text in [
        "ruff 0.16.7 check: All checks passed; ruff format --check 0.15.0: clean",  # I5
        "ruff 0.16.7 check: All checks passed; ruff format --check: 0.15.0 was used, clean",  # I2
    ]:
        v = clp.judge_lint_claim(text, _pin)
        assert v["verdict"] == "refuse" and v["named"] == "0.15.0", text
    for text in [
        "CI pins ruff 0.16.7; ruff check: clean",  # I6
        "the pin is ruff==0.16.7; lint clean",  # I7
        "required-version = 0.16.7 in pyproject; ruff check clean",
    ]:
        v = clp.judge_lint_claim(text, _pin)
        assert v["verdict"] == "refuse" and "names no linter version" in v["reason"], text
    # The honest one-run shapes still accept (I1, C9, I3, and a run that
    # names the pin beside its outcome).
    for text in [
        "ruff 0.16.7 check: All checks passed; format --check: 232 files already formatted",
        "ruff 0.16.7 (tests.yml pin) check: All checks passed; format --check: 232 files already formatted; 41 passed",
        "ruff 0.16.7 check src: All checks passed; ruff format --check: clean; 232 files already formatted",
        "ruff 0.16.7 --version; ruff check: clean",
    ]:
        assert clp.judge_lint_claim(text, _pin)["verdict"] == "accept", text


def test_other_tools_never_share_a_ruff_version():
    """Loki AC8CBA02 I11 and its mirror: another tool's outcome is not a
    ruff claim, and a ruff version is never attached to it."""
    _pin = {"state": "populated", "version": "0.16.7", "source": "tests.yml"}
    claims = clp.lint_claims("ruff 0.16.7 check: All checks passed; bandit: no findings")
    assert [c["clause"] for c in claims] == ["ruff 0.16.7 check: All checks passed"]
    # Mirror: a wrong ruff version must not make a mypy outcome refuse.
    v = clp.judge_lint_claim("ruff 0.15.0 check: 3 errors. mypy: no errors", _pin)
    assert v["verdict"] == "none"
    assert clp.judge_lint_claim("pytest: 81 passed; mypy: no issues found", _pin)["verdict"] == "none"


def test_quoted_spans_are_descriptions_not_claims():
    """Loki C63A2C48 Q1/Q2 and AC8CBA02 Q3/Q5: evidence that quotes a rule
    or a transcript is describing it; the quoted span is stripped first.
    An apostrophe never opens a quoted span (Q4)."""
    _pin = {"state": "populated", "version": "0.16.7", "source": "tests.yml"}
    for text in [
        "src/ci_lint_pin.py: the clean word is ruff's own outcome phrase (\"All checks passed\") or `clean` adjacent to the linter word",
        "judge: a clean word is `clean` adjacent to the linter word — described, not claimed",
        "_CLEAN_WORD_RE matches “All checks passed” after `ruff`",
        "over the transcript 'ruff 0.15.0 check: All checks passed' the gate said refuse",  # Q5
        "adversarial: '81 passed; ruff 0.15.0 check clean' accept 0.15.0",  # Q3
    ]:
        assert clp.judge_lint_claim(text, _pin)["verdict"] == "none", text
    assert clp.judge_lint_claim("ruff 0.16.7 check: All checks passed; it's clean", _pin)["verdict"] == "accept"  # Q4
    assert clp.judge_lint_claim("ruff 0.15.0 check src: All checks passed", _pin)["verdict"] == "refuse"
    # The refusal for an unnamed claim names the quoting rule.
    v = clp.judge_lint_claim("lint clean", _pin)
    assert v["verdict"] == "refuse" and "backticks" in v["reason"]


def test_lookback_spans_a_test_count_but_stops_at_a_disclaimer_or_an_outcome():
    """Loki C63A2C48 L2: 'ruff 0.15.0. Tests: 81 passed. All checks passed.'
    is the ordinary report shape and must be judged."""
    _pin = {"state": "populated", "version": "0.16.7", "source": "tests.yml"}
    v = clp.judge_lint_claim("ruff 0.15.0. Tests: 81 passed. All checks passed.", _pin)
    assert v["verdict"] == "refuse" and v["named"] == "0.15.0"
    assert clp.judge_lint_claim("ruff 0.16.7. Tests: 81 passed. 2 skipped. All checks passed.", _pin)["verdict"] == "accept"
    assert clp.judge_lint_claim("ruff 0.15.0. a. b. c. All checks passed.", _pin)["verdict"] == "none"
    assert clp.judge_lint_claim("ruff 0.15.0. ruff not run. All checks passed.", _pin)["verdict"] == "none"
    claims = clp.lint_claims("ruff 0.15.0. All checks passed. pytest. All checks passed.")
    assert len(claims) == 1 and claims[0]["versions"] == ["0.15.0"]


def test_version_is_the_one_adjacent_to_the_clean_claim():
    """'CI pins ruff==0.16.7; measured with ruff 0.15.0: All checks passed'
    is a 0.15.0 measurement — order in the string must not decide."""
    _pin = {"state": "populated", "version": "0.15.0", "source": "tests.yml"}
    text = "CI pins ruff==0.16.7 in tests.yml; measured with ruff 0.15.0: All checks passed"
    assert clp.named_ruff_version(text) == "0.15.0"
    assert clp.judge_lint_claim(text, _pin)["verdict"] == "accept"
    text2 = "measured with ruff 0.15.0: All checks passed; CI pins ruff==0.16.7 in tests.yml"
    assert clp.judge_lint_claim(text2, _pin)["verdict"] == "accept"
    bad = "CI pins ruff==0.15.0; measured with ruff 0.16.7: All checks passed"
    v = clp.judge_lint_claim(bad, _pin)
    assert v["verdict"] == "refuse" and "0.16.7" in v["reason"] and "0.15.0" in v["reason"]


def test_named_version_shapes():
    for text, want in [
        ("ruff 0.16.7 check clean", "0.16.7"),
        ("ruff==0.15.0: All checks passed", "0.15.0"),
        ("ruff (0.16.7) clean", "0.16.7"),
        ("ruff v0.16.7 clean", "0.16.7"),
        ("ruff clean", None),
    ]:
        assert clp.named_ruff_version(text) == want, text


def test_pyproject_comment_is_not_a_pin(tmp_path):
    """willow-mcp pyproject.toml:193 quotes `pip install ruff==0.16.7` in a
    comment; the parsed document, not the text, is what pins."""
    root = _repo(
        tmp_path,
        workflow="  - run: pip install ruff==0.15.0\n",
        pyproject='# ruff is pinned here to match the lint job\'s `pip install ruff==0.16.7`\n'
        '[project.optional-dependencies]\ntest = ["ruff==0.16.7"]\n',
    )
    pin = clp.ci_lint_pin(root)
    assert pin["version"] == "0.15.0"
    assert [c["version"] for c in pin["conflicts"]] == ["0.16.7"]
    assert "optional-dependencies" in pin["conflicts"][0]["source"]


# ── judgement ──────────────────────────────────────────────────────────────

_PIN_0167 = {"state": "populated", "version": "0.16.7", "source": ".github/workflows/tests.yml: pip install ruff==0.16.7"}
_PIN_EMPTY = {"state": "empty", "version": None, "source": None}
_PIN_DOWN = {"state": "unreachable", "version": None, "source": None, "reason": "no repo root"}


def test_matching_version_is_accepted():
    v = clp.judge_lint_claim("ruff 0.16.7 check + format --check clean", _PIN_0167)
    assert v["verdict"] == "accept"
    assert v["named"] == v["pinned"] == "0.16.7"


def test_mismatched_version_is_refused_naming_both():
    v = clp.judge_lint_claim("ruff 0.15.0: All checks passed!", _PIN_0167)
    assert v["verdict"] == "refuse"
    assert "0.15.0" in v["reason"] and "0.16.7" in v["reason"]


def test_unnamed_version_is_refused_with_the_pin_in_the_message():
    v = clp.judge_lint_claim("ruff clean", _PIN_0167)
    assert v["verdict"] == "refuse"
    assert "names no linter version" in v["reason"]
    assert "0.16.7" in v["reason"]


def test_no_pin_repo_accepts_any_named_version_but_still_wants_a_name():
    assert clp.judge_lint_claim("ruff 0.15.0 clean", _PIN_EMPTY)["verdict"] == "accept"
    assert clp.judge_lint_claim("lint clean", _PIN_EMPTY)["verdict"] == "refuse"


def test_unreachable_pin_is_advisory_never_a_refusal():
    v = clp.judge_lint_claim("ruff clean", _PIN_DOWN)
    assert v["verdict"] == "advisory"
    assert "not judged" in v["reason"]


# ── verify_handoff wiring ──────────────────────────────────────────────────


def _verify(handoff_data: dict) -> dict:
    pkt = {"meta": {}, "status": {"status": "complete"}}
    hr = {"dispatch_id": "d1", "handoff": handoff_data, "closeout_md": ""}
    with patch("willow_mcp.handoff.dispatch_read", return_value=pkt), \
         patch("willow_mcp.handoff.handoff_read", return_value=hr), \
         patch("willow_mcp.handoff.dispatch_set_status"):
        return verify_handoff("d1")


def _handoff(evidence: str, **extra) -> dict:
    return {
        "checklist_resolved": True,
        "envelope_clean": True,
        "findings": [{"text": "built it", "evidence": ["360 passed, 2 skipped", evidence], **extra}],
        "narrative": "",
    }


def test_verify_refuses_a_lint_claim_measured_off_the_pin(tmp_path, monkeypatch):
    """The #48 shape: '0.15.0 clean' against a CI pin of 0.16.7 → not verified,
    and the reason names both versions and the finding."""
    root = _repo(tmp_path, workflow="  - run: pip install ruff==0.16.7\n")
    monkeypatch.delenv("WILLOW_PROJECT_ROOT", raising=False)
    result = _verify(_handoff("ruff 0.15.0 check: All checks passed!", repo_root=str(root)))
    assert result["verified"] is False
    assert "0.15.0" in result["reason"] and "0.16.7" in result["reason"]
    assert result["lint_claims"][0]["verdict"] == "refuse"
    assert result["lint_claims"][0]["finding_index"] == 0


def test_verify_accepts_a_lint_claim_on_the_pin(tmp_path, monkeypatch):
    root = _repo(tmp_path, workflow="  - run: pip install ruff==0.16.7\n")
    monkeypatch.delenv("WILLOW_PROJECT_ROOT", raising=False)
    result = _verify(_handoff("ruff 0.16.7 check + format --check clean", repo_root=str(root)))
    assert result["verified"] is True
    assert result["lint_claims"][0]["verdict"] == "accept"


def test_verify_refuses_an_unnamed_lint_claim(tmp_path, monkeypatch):
    root = _repo(tmp_path, workflow="  - run: pip install ruff==0.16.7\n")
    monkeypatch.delenv("WILLOW_PROJECT_ROOT", raising=False)
    result = _verify(_handoff("ruff clean", repo_root=str(root)))
    assert result["verified"] is False
    assert "names no linter version" in result["reason"]


def test_verify_uses_the_broker_project_root_when_the_finding_names_none(tmp_path, monkeypatch):
    root = _repo(tmp_path, workflow="  - run: pip install ruff==0.16.7\n")
    monkeypatch.setenv("WILLOW_PROJECT_ROOT", str(root))
    result = _verify(_handoff("ruff 0.16.7 clean"))
    assert result["verified"] is True
    assert result["lint_claims"][0]["repo_root"] == str(root)


def test_verify_with_no_root_at_all_is_advisory_not_refusal(monkeypatch):
    monkeypatch.delenv("WILLOW_PROJECT_ROOT", raising=False)
    result = _verify(_handoff("ruff clean"))
    assert result["verified"] is True
    assert "not judged" in result["advisory"]
    assert result["lint_claims"][0]["verdict"] == "advisory"


def test_verify_ignores_findings_that_make_no_lint_claim(tmp_path, monkeypatch):
    root = _repo(tmp_path, workflow="  - run: pip install ruff==0.16.7\n")
    monkeypatch.setenv("WILLOW_PROJECT_ROOT", str(root))
    result = _verify(_handoff("tests/test_ci_lint_pin.py: 21 passed"))
    assert result["verified"] is True
    assert "lint_claims" not in result


def test_verify_does_not_judge_lint_when_checklist_is_unresolved(tmp_path, monkeypatch):
    """An honest partial report is not a claim; a wrong-version lint line in
    it is recorded but never the reason it is unverified."""
    root = _repo(tmp_path, workflow="  - run: pip install ruff==0.16.7\n")
    monkeypatch.setenv("WILLOW_PROJECT_ROOT", str(root))
    data = _handoff("ruff 0.15.0 clean")
    data["checklist_resolved"] = False
    result = _verify(data)
    assert result["reason"] == "checklist not resolved"
    assert result["lint_claims"][0]["verdict"] == "refuse"
