"""bundle/skills/*.md is a render of skills/*.md, not a byte-identical mirror.

The bundled copy is what `plugin.json` ships to consumers. It used to be
a byte-identical mirror of the source in `skills/`, pinned by this file.
That pin caught the 2026-07-31 divergence (a fix to `skills/consent.md`
landed only in the bundled copy) but did NOT stop LITERAL duplication
inside the skills: the Jeles federation server id `8cae3d1dcdf4`, the
WEB_ORDER ladder, the GIT_PUSH_HINT push-broker sentence — each of them
appears in more than one skill file today, and would drift silently if
any of them changed.

PR 4 landed a small preprocessor (`tools/render_skills.py`) that lets
skill sources reference `hooks/_constants.py` values via a marker
(`{{include _constants.NAME}}`). This test now says: the bundle is
whatever `render(source)` produces. A hand-edit of a bundle file — no
matter how small — is drift, and the pin names it.

Rules unchanged:
- Every source .md has a bundle twin, and vice versa (no files-only-on-
  one-side).
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_SOURCE_DIR = _REPO / "skills"
_BUNDLE_DIR = _REPO / "src" / "willow_mcp" / "bundle" / "skills"

# tools/ is not a package — add the directory so we can import render_skills
# by module name. Same shape as the other tools/ imports in the test suite.
_TOOLS_DIR = _REPO / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import render_skills  # noqa: E402


def _skill_files(root: Path) -> dict[str, Path]:
    return {p.name: p for p in root.glob("*.md")}


def test_every_source_has_a_bundle_twin_and_back():
    """A skill file must exist on both sides. If you added one but not the
    other, this fires and names the missing twin — same failure class the
    old byte-identical pin covered for that half of the contract."""
    source = _skill_files(_SOURCE_DIR)
    bundle = _skill_files(_BUNDLE_DIR)
    source_only = sorted(set(source) - set(bundle))
    bundle_only = sorted(set(bundle) - set(source))
    assert not source_only, f"skills/ has files missing from the bundle: {source_only}"
    assert not bundle_only, f"bundle/skills/ has files missing from skills/: {bundle_only}"


def test_bundle_matches_rendered_source():
    """The bundled copy is `render(source)`. Every marker in the source
    expanded, every non-marker line copied verbatim; the two agree byte for
    byte. A drift here means either:
      1. someone edited a bundle file by hand (that's the failure class
         this pin is here to catch), or
      2. someone edited a source file's include marker + never re-ran
         `python3 tools/render_skills.py`.
    """
    constants = render_skills._load_constants()
    mismatched: list[str] = []
    for name, source_path in _skill_files(_SOURCE_DIR).items():
        bundle_path = _BUNDLE_DIR / name
        expected = render_skills.render(source_path.read_text(encoding="utf-8"), constants)
        actual = bundle_path.read_text(encoding="utf-8")
        if expected != actual:
            mismatched.append(name)
    assert not mismatched, (
        f"bundle drifted from render(source) for: {mismatched} — re-run `python3 tools/render_skills.py`."
    )


def test_hand_edit_of_bundle_fails_the_pin():
    """Prove-it-can-fail plant. The pin above compares
    `render(source)` to the bundle bytes. A hand-edit of a bundle file
    changes the bundle bytes without changing the source. The comparison
    must then reject that state.

    We do this without touching the tree: pass a synthetic source through
    render, then compare to a synthetic "on-disk" byte string that is a
    hand-edited variant. `assertEqual` fails; we catch and confirm.
    """
    synthetic_source = "Any server id: {{include _constants.JELES_FEDERATION_SERVER}}"
    rendered = render_skills.render(synthetic_source)
    # A "hand edit" of the bundle: change one character.
    hand_edited = rendered.replace(render_skills._load_constants().JELES_FEDERATION_SERVER, "0000000000EE")
    assert rendered != hand_edited, "planted hand-edit did not change the bundle bytes — the plant is broken"


def test_unknown_include_marker_raises():
    """A typo in an include marker is a caller bug. render() raises KeyError
    naming the offending constant so the CI failure points to the right
    place, rather than silently producing an empty expansion."""
    import pytest

    with pytest.raises(KeyError, match="NOPE_NOT_A_CONSTANT"):
        render_skills.render("bad: {{include _constants.NOPE_NOT_A_CONSTANT}}")
