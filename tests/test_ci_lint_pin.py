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
    assert clp.is_lint_claim("format --check: 63 files already formatted; formatter ok")
    assert not clp.is_lint_claim("tests/test_lint_pin.py: 7 passed")
    assert not clp.is_lint_claim("360 passed, 2 skipped in 10.1s")


def test_named_version_shapes():
    for text, want in [
        ("ruff 0.16.7 check clean", "0.16.7"),
        ("ruff==0.15.0: All checks passed", "0.15.0"),
        ("ruff-0.16.7 format --check clean", "0.16.7"),
        ("ruff (0.16.7) clean", "0.16.7"),
        ("ruff v0.16.7 clean", "0.16.7"),
        ("ruff clean", None),
    ]:
        assert clp.named_ruff_version(text) == want, text


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
