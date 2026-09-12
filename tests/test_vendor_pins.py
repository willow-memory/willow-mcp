"""Hash pins for vendored files whose body is owned elsewhere (G2-vendor-pins-willow-mcp).

The elder sibling is `tests/test_stance_friction.py::EXPECTED_BODY_SHA256`,
which pins the friction scorer's body to willow-gate's: "the copy is not a
place to edit". That pin stays where it is — Forge is keeping that body
unchanged this wave — and this file is the same rule for the next vendored
copy, `tools/changelog_dedup.py`.

Why a pin and not trust: that copy's body sat 45 lines behind Forge's with
two latent defects in it (a section end matched on `## [` alone, and a `main()`
unguarded against a changelog with nothing generated in it) and nothing
noticed, because nothing compared. A hash makes the comparison run on every
suite: the body either IS Forge's, or the divergence is recorded here under a
name and a reason. A silent fork is the one outcome this file forbids.

The body is everything from the line `from __future__ import annotations` to
EOF — matched at column 0, on purpose. The docstring above it is local and
mentions that line in backticks, and a substring search lands there instead
(it did, while this pin was being written). The docstring is not pinned: it is
where this repo says why the copy exists, and it moves with this repo.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
CHANGELOG_DEDUP = _REPO / "tools" / "changelog_dedup.py"

#: forge-play/Forge `tools/changelog_dedup.py`, body from `from __future__` to
#: EOF, as of Forge merge 5e55e0e (2026-09-11), 284 lines.
FORGE_CHANGELOG_DEDUP_BODY_SHA256 = (
    "e3f31ef11105ae37c495c1745a94c6992ceb587c549cd016f24e83c778fd1320"
)

#: A named local override: ("why this body deliberately differs from Forge's",
#: sha256 of the overridden body). None means the body is Forge's. Filling this
#: in is a recorded decision that shows up in the diff; editing the copy and
#: bumping the constant above is a silent fork, and the constant's name says
#: whose hash it is.
CHANGELOG_DEDUP_LOCAL_OVERRIDE: tuple[str, str] | None = None

_BODY_START = re.compile(r"^from __future__ import annotations$", re.MULTILINE)


def _body(text: str) -> str:
    """The vendored contract: the `from __future__` LINE onward, at column 0."""
    m = _BODY_START.search(text)
    assert m is not None, "no `from __future__ import annotations` line — not a vendored body"
    return text[m.start():]


def _body_sha256(text: str) -> str:
    return hashlib.sha256(_body(text).encode()).hexdigest()


def _expected(override: tuple[str, str] | None) -> tuple[str, str]:
    """(what the body must hash to, whose hash that is)."""
    if override is None:
        return FORGE_CHANGELOG_DEDUP_BODY_SHA256, "forge-play/Forge tools/changelog_dedup.py"
    why, sha = override
    return sha, f"the named local override ({why})"


def test_changelog_dedup_body_is_forges():
    """The pin. Fails on any byte of the body — that is the point."""
    expected, whose = _expected(CHANGELOG_DEDUP_LOCAL_OVERRIDE)
    got = _body_sha256(CHANGELOG_DEDUP.read_text(encoding="utf-8"))
    assert got == expected, (
        f"tools/changelog_dedup.py's body no longer matches {whose}.\n"
        f"  got:      {got}\n  expected: {expected}\n"
        "re-sync from forge-play/Forge tools/changelog_dedup.py (body from "
        "`from __future__` to EOF), or record a named local override here"
    )


# ── planted: the pin fires on one byte, and only on the body ────────────────


def test_the_pin_catches_a_one_byte_change_to_the_body():
    """Planted: the real file with one byte of its body changed — a second
    space after `## ` in the section-end rule, the exact site of defect (a).
    The hash must move, or this pin would clear the drift it exists to catch."""
    text = CHANGELOG_DEDUP.read_text(encoding="utf-8")
    body = _body(text)
    site = 'startswith("## ")'
    assert site in body, "the fixture edits the section-end rule; it must be there to edit"
    planted = text.replace(site, 'startswith("##  ")', 1)
    assert len(planted) == len(text) + 1, "one byte, no more"
    assert _body_sha256(planted) != _body_sha256(text)
    assert _body_sha256(planted) != FORGE_CHANGELOG_DEDUP_BODY_SHA256


def test_the_pin_ignores_the_local_docstring_even_when_it_names_the_body_start():
    """Planted, both ways. A docstring edit must not move the pin — the
    docstring is this repo's, and pinning it would make every local
    explanation a "drift". And a docstring that mentions the
    `from __future__ import annotations` line in prose must not become the
    body's start: the body begins at that line at column 0, not at the first
    time the words appear. A substring rule failed exactly this way while
    this file was being written."""
    text = CHANGELOG_DEDUP.read_text(encoding="utf-8")
    body = _body(text)
    prose = ('"""A local note: the body starts at the line '
             '`from __future__ import annotations`.\n"""\n')
    reworded = prose + body

    naive_start = reworded.index("from __future__ import annotations")
    assert naive_start < _BODY_START.search(reworded).start(), (
        "the planted docstring must be where a substring rule would cut"
    )
    assert _body_sha256(reworded) == _body_sha256(text), (
        "a docstring edit — even one naming the body-start line — is not a body edit"
    )


def test_a_named_override_moves_the_pin_and_names_itself():
    """Planted: an override is a recorded decision, so the pin follows it and
    the failure message says whose hash it is comparing against."""
    forged_body = "from __future__ import annotations\n\nOVERRIDDEN = True\n"
    sha = hashlib.sha256(forged_body.encode()).hexdigest()
    expected, whose = _expected(("this repo needs X until Forge#N lands", sha))
    assert expected == sha
    assert "named local override" in whose and "Forge#N" in whose
    assert _expected(None) == (FORGE_CHANGELOG_DEDUP_BODY_SHA256,
                               "forge-play/Forge tools/changelog_dedup.py")
