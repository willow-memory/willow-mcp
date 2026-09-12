"""This tree is held to the fleet's published conventions (G2-conventions).

Fleet plan decision 4: every repo carries a `tests/test_fleet_conventions.py`
whose rules are READ from the published document, never restated. The document
has one home — willow-reconciler's `reconciler.conventions` (published as
`reconciler conventions --json`) — and this file consumes it the way the
reconciler's own consumer test does: `from reconciler.conventions import
conventions`. A vendored copy with a hash pin was the other defensible shape;
it was not taken here because this repo is the fleet's hub, already depends on
five fleet packages, and spent Wave 2 on what a vendored copy costs when its
drift-guard is soft (`vendor-sync` red on master for a copy nobody re-synced).
A copy that is only compared against its source when the source happens to be
installed is that failure with a different file name.

What is held, per rule:

* `required_when_release_please_arms_automerge` — release-please.yml here arms
  `gh pr merge --auto`, so `pr-title.yml` must exist (it is the guard that
  keeps a `fix(ci):` title from cutting a release; willow-mcp v2.1.1).
* `hidden_types` — release-please-config.json's hidden set must equal the
  published one, exactly.
* `required_config_comments` — the two reasoning comments must be in the
  config file. They live at the file's top level here, beside the four other
  `$comment-*` keys this repo keeps there; the reconciler's own test looks
  under `packages["."]`. The published rule names the keys and the file, not
  a level, so the check here accepts either level and is planted both ways.
  Moving six comment keys inside a release-please package block to satisfy a
  test's path choice would be bending the tree to the test.
* `contributing_must_name_test_command` — CONTRIBUTING.md must name the exact
  command a contributor runs. docs/AGENTS.md names none, so CONTRIBUTING's is
  the one: `.venv/bin/python3 -m pytest tests/ -q`.
* `required_when_pile_exists` — this repo keeps a numbered pile
  (`docs/ideas.md`), so `trailers.yml` is required. It does not exist yet;
  that is Wave 3's E3-trailers, and the test is `xfail(strict=True)` so it
  flips to a hard failure the day the workflow lands and the mark goes stale.

Every helper that scans is planted below, in the same file, as the meta-scan
(`tests/test_scans_fire.py`, G2-meta-scans) requires.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

try:
    from reconciler.conventions import conventions
except ImportError as exc:  # a skip here would make every rule below vacuous
    raise ImportError(
        "willow-reconciler is not installed; it is in the `test` extra — "
        "`pip install -e '.[test]'`"
    ) from exc

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES = conventions()

#: The contract this file consumes, pinned here rather than as a version: the
#: reconciler promises a `/1` document stays readable across additions and
#: bumps only on a removal or a meaning change.
SCHEMA = "willow-fleet-conventions/1"

RELEASE_PLEASE = ".github/workflows/release-please.yml"
RELEASE_CONFIG = "release-please-config.json"
CONTRIBUTING = "CONTRIBUTING.md"
#: This repo's numbered pile. Its presence is what makes `trailers.yml` required.
PILE = "docs/ideas.md"
ARMS_AUTOMERGE = "gh pr merge --auto"
#: The exact command CONTRIBUTING.md names under "Running tests".
TEST_COMMAND = ".venv/bin/python3 -m pytest tests/ -q"


def _arms_automerge(root: Path) -> bool:
    """Does this tree's release-please.yml arm auto-merge on the release PR?"""
    workflow = root / RELEASE_PLEASE
    return workflow.exists() and ARMS_AUTOMERGE in workflow.read_text(encoding="utf-8")


def _missing_when_armed(root: Path, required: list[str]) -> list[str]:
    """The required files a tree lacks — only when it arms auto-merge."""
    if not _arms_automerge(root):
        return []
    return [f for f in required if not (root / f).exists()]


def _config_hidden_types(config_text: str) -> set[str]:
    """The types release-please-config.json hides."""
    sections = json.loads(config_text)["packages"]["."]["changelog-sections"]
    return {s["type"] for s in sections if s.get("hidden")}


def _config_missing_comments(config_text: str, required: list[str]) -> list[str]:
    """The required reasoning comments the config carries at neither level.

    The published rule names keys and a file. This repo keeps every
    `$comment-*` key at the file's top level; the reconciler's own config
    keeps them under `packages["."]`. Either is "in the config file itself".
    """
    config = json.loads(config_text)
    present = set(config) | set(config["packages"]["."])
    return [c for c in required if c not in present]


def _missing_when_pile_exists(root: Path, required: list[str]) -> list[str]:
    """The required files a tree lacks — only when it keeps a pile."""
    if not (root / PILE).exists():
        return []
    return [f for f in required if not (root / f).exists()]


def _names_test_command(contributing_text: str) -> bool:
    """Does CONTRIBUTING name the exact command, so a PR can quote it?"""
    return TEST_COMMAND in contributing_text


# ── the document itself ──────────────────────────────────────────────────────


def test_the_published_document_is_the_schema_this_file_reads():
    """The contract, not the version: a `/2` document must fail here loudly
    rather than be read as a `/1`."""
    assert RULES["schema"] == SCHEMA
    assert set(RULES["hidden_types"]).isdisjoint(RULES["release_cutting_types"]), (
        "the two type sets partition what a config may list"
    )


# ── the five real-tree checks ────────────────────────────────────────────────


def test_pr_title_guard_is_present_wherever_automerge_is_armed():
    assert _arms_automerge(REPO_ROOT), "release-please.yml no longer arms auto-merge; re-read the rule"
    assert _missing_when_armed(REPO_ROOT, RULES["required_when_release_please_arms_automerge"]) == []


def test_the_configs_hidden_set_equals_the_published_set():
    text = (REPO_ROOT / RELEASE_CONFIG).read_text(encoding="utf-8")
    assert _config_hidden_types(text) == set(RULES["hidden_types"])


def test_the_config_carries_every_required_reasoning_comment():
    text = (REPO_ROOT / RELEASE_CONFIG).read_text(encoding="utf-8")
    assert _config_missing_comments(text, RULES["required_config_comments"]) == []


def test_contributing_names_the_test_command():
    assert RULES["contributing_must_name_test_command"] is True
    assert _names_test_command((REPO_ROOT / CONTRIBUTING).read_text(encoding="utf-8"))


@pytest.mark.xfail(strict=True, reason="E3-trailers (fleet plan Wave 3) adds trailers.yml")
def test_trailers_workflow_is_present_because_a_pile_exists():
    """This repo keeps `docs/ideas.md`, so the rule applies in full; the
    workflow it requires is Wave 3's. `strict=True`: the day trailers.yml lands
    this test passes, the xfail becomes an XPASS failure, and the mark comes
    off — the rule is never weakened, only dated."""
    assert (REPO_ROOT / PILE).exists()
    assert _missing_when_pile_exists(REPO_ROOT, RULES["required_when_pile_exists"]) == []


# ── the plants: each scan shown to fire on a tree written to be caught ───────


def _tree(tmp_path: Path, label: str, *, arms: bool, files: tuple[str, ...] = ()) -> Path:
    """A staged tree whose release-please.yml does or does not arm auto-merge,
    with `files` planted as empty markers."""
    root = tmp_path / label
    (root / ".github" / "workflows").mkdir(parents=True)
    body = "jobs:\n  release-please:\n    steps:\n      - run: |\n"
    body += f"          {ARMS_AUTOMERGE} --merge \"$pr\"\n" if arms else "          gh pr list\n"
    (root / RELEASE_PLEASE).write_text(body, encoding="utf-8")
    for f in files:
        (root / f).parent.mkdir(parents=True, exist_ok=True)
        (root / f).write_text("# planted\n", encoding="utf-8")
    return root


def test_the_armed_tree_check_fires_on_a_planted_tree_missing_the_guard(tmp_path):
    required = RULES["required_when_release_please_arms_automerge"]
    assert _missing_when_armed(_tree(tmp_path, "bare", arms=True), required) == required
    assert _missing_when_armed(_tree(tmp_path, "guarded", arms=True, files=tuple(required)), required) == []
    assert _missing_when_armed(_tree(tmp_path, "manual", arms=False), required) == [], (
        "a tree that merges its release PR by hand owes no guard"
    )


def test_the_hidden_set_check_catches_a_planted_config_that_unhides_ci():
    planted = json.dumps({"packages": {".": {"changelog-sections": [
        {"type": "feat", "section": "Added"},
        {"type": "docs", "section": "Docs", "hidden": True},
        {"type": "test", "section": "Tests", "hidden": True},
        {"type": "ci", "section": "CI"},
        {"type": "chore", "section": "Chores", "hidden": True},
    ], "$comment-what-cuts-a-release": "kept"}}})
    assert _config_hidden_types(planted) == {"chore", "docs", "test"}
    assert _config_hidden_types(planted) != set(RULES["hidden_types"]), "ci was un-hidden; the set must differ"
    assert _config_missing_comments(planted, RULES["required_config_comments"]) == ["$comment-hidden-rule"]


def test_the_comment_check_reads_both_levels_and_catches_a_planted_absence():
    """Planted both ways for the adaptation this repo needed: the required
    keys at the top level (this repo), under the package (the reconciler's
    own), and at neither — only the last is reported."""
    required = RULES["required_config_comments"]
    top = json.dumps({"$comment-hidden-rule": "why", "$comment-what-cuts-a-release": "why",
                      "packages": {".": {"changelog-sections": []}}})
    package = json.dumps({"packages": {".": {"changelog-sections": [],
                                              "$comment-hidden-rule": "why",
                                              "$comment-what-cuts-a-release": "why"}}})
    neither = json.dumps({"$comment-tag-format": "unrelated",
                          "packages": {".": {"changelog-sections": []}}})
    assert _config_missing_comments(top, required) == []
    assert _config_missing_comments(package, required) == []
    assert sorted(_config_missing_comments(neither, required)) == sorted(required)


def test_the_pile_check_fires_on_a_planted_tree_with_a_pile_and_no_verify_gate(tmp_path):
    required = RULES["required_when_pile_exists"]
    with_pile = _tree(tmp_path, "pile", arms=False, files=(PILE,))
    assert _missing_when_pile_exists(with_pile, required) == required
    gated = _tree(tmp_path, "gated", arms=False, files=(PILE, *required))
    assert _missing_when_pile_exists(gated, required) == []
    assert _missing_when_pile_exists(_tree(tmp_path, "no_pile", arms=False), required) == [], (
        "a tree with no pile owes no verify gate"
    )


def test_the_contributing_check_catches_a_planted_contributing_without_the_command():
    assert not _names_test_command("# Contributing\n\nRun the tests before pushing.\n")
    assert not _names_test_command("```sh\npython -m pytest\n```\n"), "a different command is not the command"
    assert _names_test_command(f"```sh\n{TEST_COMMAND}\n```\n")
