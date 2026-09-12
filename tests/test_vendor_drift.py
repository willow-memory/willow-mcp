"""The cross-repo guards must say WHICH WAY a vendored copy drifted.

A byte comparison reports "these differ" for two opposite situations — upstream
advanced while the copy stood still (fatal, and how the stance_friction block
went missing), and the copy carrying a change whose canonical half is an open
upstream PR (a merge order, not a fault). Telling them apart is the whole point
of scripts/vendor_drift.py, so it is tested against a real git repository
rather than a mock: the classifier's evidence IS git history, and a fake would
only assert that the fake was consulted.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

# Loaded by path, matching tests/test_mcp_entry_toggle.py: scripts/ is not an
# importable package, and a sys.path insert would put the import below the
# statement that enables it.
#
# The sys.modules registration is not optional here, though that test does not
# need it: @dataclass looks its class's module up in sys.modules while the
# module is still executing, so a Verdict defined in an unregistered module
# raises AttributeError on None during exec_module.
_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "vendor_drift.py"
_spec = importlib.util.spec_from_file_location("vendor_drift", _MODULE_PATH)
vendor_drift = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = vendor_drift
_spec.loader.exec_module(vendor_drift)

AHEAD, BEHIND = vendor_drift.AHEAD, vendor_drift.BEHIND
DIVERGED, UNKNOWN = vendor_drift.DIVERGED, vendor_drift.UNKNOWN
OVERRIDDEN, STALE_OVERRIDE = vendor_drift.OVERRIDDEN, vendor_drift.STALE_OVERRIDE
classify = vendor_drift.classify
Verdict, annotate = vendor_drift.Verdict, vendor_drift.annotate
load_overrides, override_for = vendor_drift.load_overrides, vendor_drift.override_for
stale_override = vendor_drift.stale_override

MODULE = '"""Canonical module."""\n\nVALUE = {version!r}\n'


def body(text: str) -> str:
    """Same slice the real guards use: module docstring onward."""
    return text[text.index('"""'):]


def git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, check=True)
    return p.stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> Path:
    """An upstream repo with two landed versions and one open 'PR'."""
    repo = tmp_path / "upstream"
    (repo / "src").mkdir(parents=True)
    git(repo.parent, "init", "--quiet", "-b", "master", str(repo))
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "test")

    f = repo / "src" / "mod.py"
    f.write_text(MODULE.format(version="v1"))
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "v1")
    v1 = git(repo, "rev-parse", "HEAD")

    f.write_text(MODULE.format(version="v2"))
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "v2")

    # An open pull request: a commit reachable only from a PR head ref, exactly
    # the shape `git fetch origin +refs/pull/*/head:refs/remotes/pr/*` produces.
    git(repo, "checkout", "--quiet", "-b", "pr-branch", v1)
    f.write_text(MODULE.format(version="v3-unmerged"))
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "v3 (open PR)")
    git(repo, "update-ref", "refs/remotes/pr/217", git(repo, "rev-parse", "HEAD"))
    git(repo, "checkout", "--quiet", "master")
    return repo


def test_behind_is_fatal(upstream: Path):
    # The vendored copy still holds v1 while upstream landed v2. This is the
    # stance_friction failure and it must stay a hard error.
    v = classify(upstream / "src" / "mod.py",
                 body(MODULE.format(version="v1")), body)
    assert v.kind == BEHIND
    assert v.fatal
    assert "upstream commit" in v.detail


def test_ahead_of_an_open_pr_is_not_fatal(upstream: Path):
    # The vendored copy carries the change that is still open upstream as a PR.
    # Nothing is wrong; the two halves merge in an order.
    v = classify(upstream / "src" / "mod.py",
                 body(MODULE.format(version="v3-unmerged")), body)
    assert v.kind == AHEAD
    assert not v.fatal
    assert v.detail == "upstream PR #217"


def test_local_edit_matching_nothing_stays_fatal(upstream: Path):
    # The guard must not be weakened into forgiving hand-edits: a body that is
    # neither an upstream version nor any open PR head is still an error.
    v = classify(upstream / "src" / "mod.py",
                 body(MODULE.format(version="edited-by-hand")), body)
    assert v.kind == DIVERGED
    assert v.fatal


def test_non_git_upstream_is_unknown_and_fatal(tmp_path: Path):
    # A plain directory (no history to reason from) must fail closed rather
    # than guess a direction.
    f = tmp_path / "mod.py"
    f.write_text(MODULE.format(version="v1"))
    v = classify(f, body(MODULE.format(version="other")), body)
    assert v.kind == UNKNOWN
    assert v.fatal


# ── a named override: forgives one body, and only while it is still true ─────


def _sha(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_a_recorded_override_catches_the_body_it_names_and_no_other():
    """Planted: the vendored copy carries a deliberate change (the shape of the
    nest secret-scan hardening), recorded with its hash. That body is forgiven
    as OVERRIDDEN and not fatal; the record's reason travels with the verdict.
    A later edit to the same file matches nothing — the record is not a
    blanket permission — and an empty record forgives nothing."""
    mine = body(MODULE.format(version="fleet-only-hardening"))
    overrides = {"mod.py": {"why": "boundary evasion fix, not yet upstream",
                            "sha256": _sha(mine)}}
    v = override_for(overrides, "mod.py", mine)
    assert v is not None
    assert v.kind == OVERRIDDEN
    assert not v.fatal
    assert v.detail == "boundary evasion fix, not yet upstream"

    edited_again = body(MODULE.format(version="edited-once-more"))
    assert override_for(overrides, "mod.py", edited_again) is None, (
        "the record excuses the body it hashes and no other"
    )
    assert override_for({}, "mod.py", mine) is None
    assert override_for(overrides, "other.py", mine) is None


def test_an_override_stays_fatal_once_upstream_has_caught_up():
    """Planted: bodies equal, record still present. The record is now a false
    claim about the tree, and STALE_OVERRIDE is fatal so it cannot linger."""
    v = stale_override({"mod.py": {"why": "landed upstream since", "sha256": "0" * 64}}, "mod.py")
    assert v is not None
    assert v.kind == STALE_OVERRIDE
    assert v.fatal
    assert stale_override({}, "mod.py") is None


def test_the_override_annotations_say_which_and_where(upstream: Path):
    """Planted: the OVERRIDDEN annotation is a warning that names the record
    file and the reason; STALE_OVERRIDE is an error that says to remove it.
    Neither is the DIVERGED text, which is what a reader saw before."""
    forgiven = annotate("nest-pipeline", "src/x.py", Verdict(OVERRIDDEN, "why it differs."), "hint")
    assert forgiven.startswith("::warning")
    assert "why it differs." in forgiven and "vendor_overrides.json" in forgiven
    stale = annotate("nest-pipeline", "src/x.py", Verdict(STALE_OVERRIDE, "why it differed."), "hint")
    assert stale.startswith("::error")
    assert "Remove that record" in stale
    # and the guard is not weakened: an unrecorded hand-edit is still DIVERGED
    v = classify(upstream / "src" / "mod.py", body(MODULE.format(version="hand-edit")), body)
    assert v.kind == DIVERGED and v.fatal


def test_load_overrides_reads_one_guards_records_and_tolerates_absence(tmp_path: Path):
    """Planted: a record file with two guards; each guard sees only its own,
    a guard with no entry sees {}, and a missing file is {} rather than a
    traceback in the CI job."""
    record = tmp_path / "vendor_overrides.json"
    record.write_text('{"$comment": "x", "nest-pipeline": {"secrets.py": {"why": "w", "sha256": "s"}}, '
                      '"friction": null}', encoding="utf-8")
    assert load_overrides("nest-pipeline", record) == {"secrets.py": {"why": "w", "sha256": "s"}}
    assert load_overrides("friction", record) == {}
    assert load_overrides("subject-consent", record) == {}
    assert load_overrides("nest-pipeline", tmp_path / "absent.json") == {}
