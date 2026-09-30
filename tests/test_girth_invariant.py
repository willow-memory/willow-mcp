"""The story's one checkable joke: "Girth erupted." lives in exactly one
place in this repository's Python.

docs/story/README.md tells a reader to grep for it and promises a single hit;
src/willow_mcp/tree_view.py's comment makes the same promise. For a while
nothing held either promise: a quotation of the joke in
docs/repatriation/engine/voices_seed.py made it two. This test holds them.

The literal is assembled here in pieces, for the same reason
tests/test_tree_view.py spells it letter by letter: a test that guards the
single hit must not become a second one.

It walks the tracked Python files (``git ls-files``), not the working tree, so
local worktrees, virtualenvs and build output are not "the repository".

Chapter 8 adds a second joke to the same catalogue, a shebang that is never
made executable ("technically polite"), and it is pinned here too.
"""
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ERUPTED = "Girth" + " " + "erupted."
HOME = "src/willow_mcp/tree_view.py"


def _tracked_python_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "*.py"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        pytest.skip(f"git ls-files unavailable here: {e}")
    return [line for line in out.splitlines() if line]


def test_girth_erupts_in_exactly_one_python_file():
    hits = {}
    for rel in _tracked_python_files():
        text = (REPO / rel).read_text(encoding="utf-8", errors="replace")
        count = text.count(ERUPTED)
        if count:
            hits[rel] = count

    assert hits == {HOME: 1}, (
        f"The story promises one hit for the log line, in {HOME}. Found: {hits}. "
        "A quotation may remember the joke; split its literal the way "
        "tests/test_tree_view.py does."
    )


POLITE = "docs/repatriation/engine/voices_seed.py"


def test_the_catalogue_of_voices_waits_to_be_asked():
    """Chapter 8's second joke: the voices catalogue carries a shebang but is
    not executable. Known issue; Won't Fix; technically polite. Making it
    executable (or dropping the shebang) breaks the story, so it is pinned."""
    first_line = (REPO / POLITE).read_text(encoding="utf-8").splitlines()[0]
    assert first_line.startswith("#!"), "the catalogue no longer introduces itself"

    try:
        staged = subprocess.run(
            ["git", "ls-files", "-s", POLITE],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError) as e:
        pytest.skip(f"git ls-files unavailable here: {e}")
    assert staged and staged[0] == "100644", (
        f"{POLITE} is tracked as {staged[:1]}; it must wait to be asked (100644)"
    )
