"""`tools/changelog_dedup.py` must reproduce the corrections that were made by hand.

The two real failures it exists for, both from merging with merge commits rather
than squashing (GitHub writes the PR title into the merge commit body, and
release-please parses it):

    2.1.2  the same fix twice — merge commit eddaf85 and the commit it merged,
           49b95fe. Noise.
    2.1.3  the merge commit 3e9af9d listed, and 0073767 dropped entirely — a
           shipped fix missing from the changelog with a synthetic entry in its
           place. That one is not noise.

Both sections below are the exact text release-please emitted. The tool has to
turn them into what a person turned them into, deriving it from git rather than
from these strings — which is the whole claim being tested.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "tools"))

changelog_dedup = pytest.importorskip("changelog_dedup")

_BASE = "https://github.com/willow-memory/willow-mcp"


def _has(*revs: str) -> bool:
    """Are these objects in the clone running the tests? Shallow CI clones."""
    return all(
        subprocess.run(["git", "-C", str(_REPO), "rev-parse", "--verify", f"{r}^{{commit}}"],
                       capture_output=True).returncode == 0
        for r in revs
    )


needs_history = pytest.mark.skipif(
    not _has("v2.1.1", "v2.1.2", "0073767", "d0bd516", "49b95fe"),
    reason="needs full history and tags (shallow clone)",
)


@needs_history
def test_it_drops_the_duplicate_release_please_emitted_for_2_1_2():
    """The exact text that shipped, and the single entry it should have been."""
    broken = f"""## [2.1.2]({_BASE}/compare/v2.1.1...v2.1.2) (2026-08-03)


### Fixed

* **web_search:** stop a lookalike domain inheriting institutional trust ([eddaf85]({_BASE}/commit/eddaf85d87b06990f6bbc506cc49b507ff77ba35))
* **web_search:** stop a lookalike domain inheriting institutional trust ([49b95fe]({_BASE}/commit/49b95fe20b5d764c62e7db85b80e427dbcd0a677))

## [2.1.1]({_BASE}/compare/v2.1.0...v2.1.1) (2026-08-03)
"""
    fixed, summary = changelog_dedup.rebuild(broken)
    section = fixed.split("## [2.1.1]")[0]
    bullets = [ln for ln in section.splitlines() if ln.startswith("* ")]

    assert len(bullets) == 1, bullets
    assert "49b95fe" in bullets[0], "kept the wrong one — 49b95fe is the real commit"
    assert "eddaf85" not in section, "the merge commit survived"
    assert summary


@needs_history
def test_it_restores_the_commit_release_please_dropped_for_2_1_3():
    """The failure that matters. `0073767` shipped and was undocumented."""
    broken = f"""## [2.1.3]({_BASE}/compare/v2.1.2...v2.1.3) (2026-08-04)


### Fixed

* **web_search:** five reproduced defects — misattributed snippets, a HALF_OPEN herd, a leaky trusted_only ([3e9af9d]({_BASE}/commit/3e9af9d3908eddb88c5ff8c73ed7d0762cdc291f))
* **web_search:** stop attributing a result's snippet to the wrong URL ([d0bd516]({_BASE}/commit/d0bd516bd0a1f57f473b12c88054984ccce18eed))

## [2.1.2]({_BASE}/compare/v2.1.1...v2.1.2) (2026-08-03)
"""
    fixed, _ = changelog_dedup.rebuild(broken)
    section = fixed.split("## [2.1.2]")[0]

    assert "0073767" in section, "the dropped commit was not restored"
    assert "admit one probe in HALF_OPEN" in section
    assert "d0bd516" in section, "the entry that was already right got lost"
    assert "3e9af9d" not in section, "the merge commit survived"


@needs_history
def test_it_links_the_full_sha_like_release_please_does():
    """Caught a real slip: the hand correction linked `commit/0073767` while
    release-please links the full 40-char sha. A short-sha link works today and
    is the kind of thing that rots."""
    broken = f"""## [2.1.3]({_BASE}/compare/v2.1.2...v2.1.3) (2026-08-04)


### Fixed

* **web_search:** admit one probe in HALF_OPEN, not the whole backlog ([0073767]({_BASE}/commit/0073767))

## [2.1.2]({_BASE}/compare/v2.1.1...v2.1.2) (2026-08-03)
"""
    fixed, summary = changelog_dedup.rebuild(broken)
    assert "commit/00737672a79b3d422afff80fabce7e38531f18b9" in fixed
    assert summary, "a short-sha link should be corrected, not accepted"


def test_the_repo_changelog_is_already_correct():
    """Idempotence, against the real file. If this fails, either the changelog
    drifted or a release landed without the workflow step running."""
    text = (_REPO / "CHANGELOG.md").read_text()
    try:
        _, summary = changelog_dedup.rebuild(text)
    except changelog_dedup.Bail as exc:
        pytest.skip(f"cannot verify in this checkout: {exc}")
    assert summary == "", f"CHANGELOG.md disagrees with the commits: {summary}"


def test_it_refuses_a_section_it_cannot_regenerate():
    """A breaking change renders as '⚠ BREAKING CHANGES', which this tool does
    not model. Rewriting a release note it had misread would be worse than the
    bug it fixes, so it stops."""
    text = f"""## [3.0.0]({_BASE}/compare/v2.1.2...v3.0.0) (2026-08-04)


### ⚠ BREAKING CHANGES

* the thing changed


### Fixed

* **x:** y ([abc1234]({_BASE}/commit/abc1234))
"""
    with pytest.raises(changelog_dedup.Bail, match="BREAKING CHANGES"):
        changelog_dedup.rebuild(text)


def test_print_section_emits_exactly_what_a_release_body_should_be():
    """`--print-section` feeds the GitHub Release body, which release-please
    generates from its own parse rather than from CHANGELOG.md — so correcting
    the file leaves the release *page* still wrong. v2.1.4's page carried the
    duplicate entry after the changelog had been fixed.

    The shape matters: release-please's body starts with the `## [x.y.z](…)`
    header, so the extracted section must include it or every release would be
    'updated' to something structurally different."""
    text = (_REPO / "CHANGELOG.md").read_text()
    section = changelog_dedup.section_for(text, "2.1.4")
    assert section is not None
    lines = section.splitlines()
    assert lines[0].startswith("## [2.1.4]("), lines[0]
    assert "### Fixed" in section
    assert "4f3b6de" in section
    assert "376930c" not in section, "the merge commit is back in the changelog"
    # Stops at the next release, rather than swallowing the rest of the file.
    assert "## [2.1.3]" not in section
    assert not section.endswith("\n"), "trailing whitespace is stripped for comparison"


def test_print_section_is_none_for_a_version_that_has_no_section():
    """The workflow warns and leaves the release alone in this case rather than
    writing an empty body."""
    text = (_REPO / "CHANGELOG.md").read_text()
    assert changelog_dedup.section_for(text, "99.99.99") is None


def test_it_refuses_a_range_it_cannot_read():
    """An unknown previous tag means the range is unreadable — so the entries
    cannot be derived, and guessing is not an option."""
    text = f"""## [9.9.9]({_BASE}/compare/v9.9.8...v9.9.9) (2026-08-04)


### Fixed

* **x:** y ([abc1234]({_BASE}/commit/abc1234))
"""
    with pytest.raises(changelog_dedup.Bail, match="not in this repository"):
        changelog_dedup.rebuild(text)


def test_hidden_types_stay_out():
    """`docs:`/`ci:`/`test:`/`chore:` are hidden in release-please-config.json.
    The rebuild reads that config rather than restating the list, so hiding or
    un-hiding a type moves this with it."""
    visible, order = changelog_dedup.sections_from_config()
    assert "docs" not in visible and "ci" not in visible
    assert "chore" not in visible and "test" not in visible
    assert visible["fix"] == "Fixed" and visible["feat"] == "Added"
    assert order.index("Added") < order.index("Fixed")
