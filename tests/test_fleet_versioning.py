"""What a version number promises, held in place — see docs/design/fleet-versioning.md.

The mechanics of releasing are covered by `test_release_wiring.py`. This file
covers the other half: whether the versions we *consume* are bounded the way the
packages producing them actually behave.

It exists because they were not. `pyproject.toml` pinned `jeles>=0.5.0,<1.0.0`
while jeles' `release-please-config.json` set `bump-minor-pre-major: true` —
which, as that config's own comment put it, made "a breaking change -> minor
rather than 1.0.0". So the cap accepted every version jeles was capable of
producing. jeles and kartikeya both set the flag **false** now, which is what
made `<1.0.0` mean something; that is the fix, not a reason to drop the test —
the flag is a line in a file someone can flip back, and this file is what
notices.

The part worth remembering is that both halves were already written down, one of
them in *this repo* — `test_release_wiring.py`'s
`test_this_package_is_past_1_0_so_no_pre_major_flags` explains that the flag
"would cap every breaking change at a minor bump". Two correct comments, in the
same tree, and nothing joined them. That is what a test is for.

**On strictness.** A fleet requirement must be spelled exactly
`name>=FLOOR,<CAP`. Env markers, extras, `~=`, `==`, a third clause and a
reversed clause order are all rejected even where they express the same or a
tighter intent. That is a deliberate house-style lock, not an oversight: the
rule being enforced is about the shape of the bound, and admitting every legal
PEP 508 spelling would mean reimplementing a specifier parser to re-derive it.
The failure message says which shape is required.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_PYPROJECT = _REPO / "pyproject.toml"
_DOC = _REPO / "docs" / "design" / "fleet-versioning.md"
_SELF = "willow-mcp"

_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r">=\s*(?P<floor>\d[\d.]*)\s*,\s*<\s*(?P<cap>\d[\d.]*)\s*$")


def _pyproject() -> dict:
    return tomllib.loads(_PYPROJECT.read_text())


def _canon(name: str) -> str:
    """PEP 503 normalisation. `willow_gate` and `willow-gate` are the same
    package to pip, and were two different strings to an earlier version of
    this file — which would have mis-fired on the first fleet package with a
    hyphen in its name."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _fleet() -> set[str]:
    """The roster, read from its one home rather than restated here.

    A hardcoded set was the largest gap in the first version of this file: it
    could go stale in the direction that matters. Adding a fourth fleet package
    to `[project.dependencies]` with the original `<1.0.0` bug passed, because
    the oracle did not know the package existed.
    """
    packages = _pyproject()["tool"]["willow"]["fleet"]["packages"]
    return {_canon(p) for p in packages}


def _version(text: str) -> tuple[int, ...]:
    """Pad to three components, but never truncate. Truncating read
    `<0.6.0.1` — a cap that admits the breaking 0.6.0 — as though it were
    `<0.6.0`, and passed."""
    parts = [int(p) for p in text.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def _requirements() -> list[str]:
    # `.get`, because declaring `dependencies` dynamic raised a bare KeyError
    # from inside the helper instead of reaching the assertion below — a
    # traceback where this file otherwise gives an explanation.
    proj = _pyproject().get("project", {})
    reqs = list(proj.get("dependencies", []) or [])
    for extras in (proj.get("optional-dependencies", {}) or {}).values():
        reqs.extend(extras)
    return reqs


def _fleet_pins() -> dict[str, list[tuple[str, str]]]:
    """Every occurrence per package, not the last one.

    `found[name] = ...` overwrote, so a correct pin listed after a buggy one
    hid it and the result depended on declaration order — the worst property a
    lint can have.
    """
    found: dict[str, list[tuple[str, str]]] = {}
    for raw in _requirements():
        m = _PIN_RE.match(raw.strip())
        if m:
            name = _canon(m.group("name"))
            if name in _fleet():
                found.setdefault(name, []).append((m.group("floor"), m.group("cap")))
    return found


def _expected_cap(floor: str) -> tuple[int, ...]:
    """The next major above the floor. Pre-1.0 packages cap at 1.0.0.

    A revision of this file capped pre-1.0 fleet packages at their next *minor*,
    on the reasoning that they ship breaking changes as minors. Withdrawn: the
    cap is also what carries a producer's security patch to users, and jeles is
    where `willow_institutional_search`'s SSRF defence lives. It could not catch
    the realistic break either — an unlabelled breaking `refactor:` bumps a
    patch and clears both caps. `test_the_installed_jeles_still_has_the_surface_
    we_use` is the instrument that replaces it. See fleet-versioning.md Rule 1.
    """
    return (_version(floor)[0] + 1, 0, 0)


def _rule_two_rows() -> dict[str, list[str]]:
    """The Rule 2 table, as {package: [surface, not-surface]}.

    Scoped to that section and read as cells, because the first version matched
    any bolded name at the start of any pipe-line anywhere in the file. That
    proved a *label* existed, not a *classification*: moving a row into an
    unrelated table, emptying both of its cells, or deleting the whole section
    and leaving one stray line inside a code fence all passed. It also broke on
    cosmetic edits — dropping the bold, using a code span, title-casing — which
    is how a test about dependency pins gets deleted by someone running a
    markdown formatter.
    """
    text = _DOC.read_text()
    start = text.find("## Rule 2")
    assert start != -1, f"{_DOC.name} has no Rule 2 section"
    end = text.find("\n## ", start + 1)
    section = text[start:end if end != -1 else len(text)]

    rows: dict[str, list[str]] = {}
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        label = _canon(re.sub(r"[*`_]", "", cells[0]))
        if not label or set(cells[0]) <= set("-: "):   # separator row
            continue
        rows[label] = cells[1:3]
    return rows


def test_every_fleet_package_is_pinned_with_both_bounds():
    """An unbounded fleet dependency is the same bug with the cap missing, and
    the regex would simply not match it — so check the roster, not just the
    entries that parsed. This package is excluded: it does not depend on
    itself, but it does need a row in the doc (below)."""
    want = _fleet() - {_SELF}
    missing = want - set(_fleet_pins())
    assert not missing, (
        f"{sorted(missing)} must appear in [project.dependencies] spelled "
        f"'name>=FLOOR,<CAP'. Found: {_requirements()}")


def test_no_fleet_package_is_declared_twice():
    """Two declarations mean one of them is unenforced, and which one wins is a
    detail of pip's specifier intersection rather than anything stated here."""
    dupes = {n: v for n, v in _fleet_pins().items() if len(v) > 1}
    assert not dupes, f"declared more than once: {dupes}"


def test_fleet_pins_track_the_producers_bump_policy():
    """Rule 1 of docs/design/fleet-versioning.md.

    The cap is the producer's next major — for a pre-1.0 package, 1.0.0. A
    narrower cap is not a stricter version of this rule, it is a different and
    worse one: it blocks the producer's security patches and creates
    unresolvable installs, which this fleet has already hit once from the other
    direction (see jeles' `dependencies = []` comment).
    """
    for name, pins in sorted(_fleet_pins().items()):
        for floor_s, cap_s in pins:
            want = _expected_cap(floor_s)
            want_s = ".".join(str(p) for p in want)
            assert _version(cap_s) == want, (
                f"{name}>={floor_s} should be capped at <{want_s}, found "
                f"<{cap_s}. See docs/design/fleet-versioning.md, Rule 1.")


@pytest.mark.parametrize(("floor", "cap"), [
    ("0.5.1", (1, 0, 0)),
    ("0.0.9", (1, 0, 0)),
    # Not reachable from the real pins today — both fleet dependencies are 0.x —
    # so without this it is untested logic that would first run during the
    # jeles 1.0 migration the doc's OPEN 2 section plans.
    ("1.0.0", (2, 0, 0)),
    ("2.2.1", (3, 0, 0)),
])
def test_the_cap_rule_itself_covers_both_sides_of_1_0(floor, cap):
    assert _expected_cap(floor) == cap


def test_the_installed_jeles_still_has_the_surface_we_use():
    """The instrument that replaces a tight version cap.

    Rule 1 says a fleet dependency is caught in CI, not in the range — so there
    has to be something in CI that would actually catch it. This is it, and it
    runs against whatever jeles is really installed rather than a stub.

    It is needed because every test in `test_institutional_search.py`
    monkeypatches `search_institutional`. jeles could delete that function
    outright and nothing else in this suite would notice.

    Deliberately narrow: willow-mcp's entire runtime use of jeles is one call in
    `server.py`, so this asserts that call and no more. `list_sources` and
    `describe_remote` exist and are unused; pinning them would be pinning a
    surface we do not hold.
    """
    institutional = pytest.importorskip(
        "jeles.institutional", reason="jeles is a declared runtime dependency")

    fn = getattr(institutional, "search_institutional", None)
    assert callable(fn), "jeles.institutional.search_institutional is gone"

    import inspect

    params = inspect.signature(fn).parameters
    assert list(params)[0] == "query", f"first parameter moved: {list(params)}"
    for name in ("sources_filter", "limit_per_source"):
        assert name in params, f"server.py passes {name}= and it is gone"
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, (
            f"{name} is no longer keyword-only; server.py passes it by keyword")


def test_the_convention_classifies_every_fleet_package():
    """Rule 2 assigns each package a public surface — the thing whose breakage
    forces a major — and they differ: willow-mcp's is its tool contract and not
    its modules, jeles' is the reverse. A fleet package with no row has had that
    question skipped rather than answered, which is the state this file exists
    to end. Both cells must be filled: a row with an empty surface is a skipped
    question wearing the shape of an answered one."""
    rows = _rule_two_rows()
    missing = _fleet() - set(rows)
    assert not missing, (
        f"no surface defined in {_DOC.name} Rule 2 for {sorted(missing)}")
    for name in sorted(_fleet()):
        surface, not_surface = rows[name]
        assert surface and not_surface, (
            f"{name}'s Rule 2 row has an empty cell: {rows[name]}")
