"""G2-meta-scans-willow-mcp — the meta-scan: every AST/grep-guard helper this
suite carries has been shown to catch something, by a test that *calls it*.

*A scan that has never fired has not been shown to check anything.* This file
is that rule turned into a test that reads the *other* test files: it finds
every module-level helper in ``tests/`` that is shaped like a violation-scanner
and asserts that some planted-violation test in the *same file* runs that
helper — directly, or through another helper it calls. A second half does the
same for scans written inline in a test's own body.

This file is not a fresh design: it is homestead-ledger's
`tests/test_scans_fire.py` (itself the sibling drift sweeps' meta-scan, from
homestead-health and the engine's `claude/engine-drift`), copied for its shape
and re-grounded against this repo's own test files. The discovery rule and the
plant rule are theirs, verified here rather than re-derived, because a
meta-scan that disagreed between repos about what counts as "planted" would be
exactly the kind of drift this sweep exists to close. Where this copy differs,
the difference is named below and planted, because each one was found by
running the original over this suite and reading what it reported.

**Discovery is structural, not a naming convention.** The rule is what a scan
*does*:

* it parses or walks source (`ast.parse`, `ast.walk`), **or**
* it matches text with a pattern (`re.search`/`findall`/`finditer`/`match`/
  `fullmatch`/`compile`, or a module-level compiled pattern's `.search(…)`),
  **or**
* it reads a file's text (`.read_text()`/`.read_bytes()`, `open(…).read()`,
  `inspect.getsource(…)`) *and* asks a membership question of it (`x in text`),
  **or**
* it walks a **module-level list of forbidden words** and asks membership of
  each — `any(c in text for c in NON_SUPPRESSED_CREDENTIALS)`, which is
  `tests/test_release_wiring.py`'s credential guard exactly, **or**
* it filters the *caller's* terms by membership in a haystack it was handed —
  `[term for term in terms if term in haystack]`.

**Re-grounding ①: no naming half.** homestead's copy also counted a helper by
name (`_is_…`, or a stem like `check`/`guard`/`scan` in its name), kept on top
of the structural rule for helpers that hand their work to a caller. Run over
this suite, that half reported only wrappers and classifiers:
`test_binding_enforcement.py::_check_in` registers an agent and checks it in,
`test_governance_continuity.py::_check_with` stages a charter and calls the
authority, `test_annotation_consistency.py::_is_write_group` classifies a
permission-group name by suffix. None reads, walks or matches anything. Three
false positives and no true one is a rule with nothing to keep it, so this copy
is structural only. What that costs is named in the last section.

**Re-grounding ②: the haystack must be a name.** `[f for f in [...] if f not
in (unmapped or [])]` (`tests/test_kb_verify.py::_mock_query`) filters a literal
list against a list built in place — it builds a mock, and it is not a grep.
The caller's-terms rule now requires the right side of the `in` to be a bare
name: the text, or the haystack, the helper was handed.

**Re-grounding ③: an inline scan reads the tree, not a file the test made.**
The inline half exists for guards written directly in a test body, where there
is nothing to name and nothing to plant. In this suite a third of what the
original reported was a behaviour test reading back a file the code under test
had just written into `tmp_path` or a `home` fixture (`test_activation_rail.py`
reads the wake log it drove `activate()` to write; `test_handoff.py` reads the
closeout it drove `handoff_write_v4` to write). Those assert a *behaviour*, and
they fire the day the behaviour breaks; a scan of the *tree* asserts a property
of a file that ships, and is the one that can rot silently. So a read counts
toward an inline scan only when its path is rooted in the tree: a module-level
name, `__file__` or a module's `__file__`, a string literal, or
`inspect.getsource`. A path rooted at a function parameter (a fixture), or a
local built from one, is the test's own file. A path that comes out of a bare
call the rule cannot see through (`personas_dir() / "x.md"`) is *unknown* and
is cleared, and that is a boundary, not a promise.

**Having a plant means a plant test calls the scan.** A test called
`test_the_guard_fires` that never touches the guard has not fired it. A helper
counts as planted only when a `test_*` function whose name carries `plant`,
`fires` or `catches` (or whose docstring carries `plant`) reaches it — through
the module's own helpers as well as directly.

**The inline half is a ratchet, not an allowlist.** This suite carries inline
tree scans that predate this file — each named in `KNOWN_INLINE_SCANS` below,
each a follow-up to factor into a helper with a plant. The test asserts the
reported set *equals* that list: a new inline scan fails it, and so does a
listed one that has since been factored out and not struck from the list. The
list can only shrink and can never go stale, which is the difference between a
ratchet and the allowlist homestead's docstring warns "gets bolted on and stops
meaning anything".

**Honest about what it still cannot see.** A helper that reaches `ast.parse`
through an alias (`from ast import parse as p`), one that shells out to `grep`,
one whose whole check is a comparison of two already-read strings, or one that
hands all of its work to a caller under a scan-shaped name (re-grounding ①):
outside the rule. Closing those needs an interpreter, not a reader.
"""
from __future__ import annotations

import ast
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

#: The convention for "this scan was shown to fire on a planted violation".
#: The word is necessary; calling the scan is what makes it count.
_PLANT_NAME_WORDS = ("plant", "fires", "catches")

#: In a *docstring*, only "plant" counts. "fires" and "catches" are ordinary
#: prose about the thing under test — homestead found a docstring reading "no
#: tag workflow fires, nothing publishes" clearing a credential scan that had
#: no plant at all. A word that common in a repo's own subject matter cannot
#: also be its evidence of a plant.
_PLANT_DOC_WORDS = ("plant",)

#: Pattern-matching methods. Matched on the attribute name alone, so both
#: `re.search(...)` and a module-level `_GUARDED_NAME_RE.findall(...)` count —
#: a compiled pattern is the same scan with the compile hoisted.
_MATCH_CALLS = frozenset(
    {"search", "findall", "finditer", "match", "fullmatch", "compile"}
)

#: Reading a file's text through `pathlib`.
_TEXT_READS = frozenset({"read_text", "read_bytes"})

#: The same read through an already-open handle — `open(p).read()` and the
#: `with open(p) as f: f.read()` spelling of it.
_HANDLE_READS = frozenset({"read", "readlines", "readline"})

#: Wrappers a read may be decoded or normalised through before the
#: membership question is asked — `p.read_text().lower()` is the same read of
#: the same file, and the text it yields is the text actually read.
_TEXT_WRAPPERS = frozenset({"decode", "strip", "lower", "upper", "casefold"})

#: Reading a module's source without naming a path. `inspect.getsource(obj)`
#: returns the real file's text — this suite has several of those.
_SOURCE_READS = frozenset({"getsource", "getsourcelines"})


def _is_open_call(expr: ast.AST) -> bool:
    """A builtin `open(...)`, however its mode and encoding are spelled."""
    return (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "open"
    )


def _open_handles(node: ast.AST) -> dict[str, ast.AST | None]:
    """Every local name bound to an `open(...)` — `with open(p) as f` and
    `f = open(p)` alike — mapped to the path expression it opened (None when
    `open` was called with no positional argument), so `f.read()` is
    recognised as the file read it is, of the file it is."""
    names: dict[str, ast.AST | None] = {}
    for sub in ast.walk(node):
        if isinstance(sub, ast.withitem) and _is_open_call(sub.context_expr):
            if isinstance(sub.optional_vars, ast.Name):
                args = sub.context_expr.args
                names[sub.optional_vars.id] = args[0] if args else None
        elif isinstance(sub, ast.Assign) and _is_open_call(sub.value):
            args = sub.value.args
            for t in sub.targets:
                if isinstance(t, ast.Name):
                    names[t.id] = args[0] if args else None
    return names


def _is_read_call(expr: ast.AST, handles: dict[str, ast.AST | None] | None = None) -> bool:
    """True if `expr` itself reads a real file's text — `.read_text()`/
    `.read_bytes()`, `open(...).read()` or an open handle's `.read()`, or
    `inspect.getsource(...)` — through any number of decoding wrappers."""
    handles = handles or {}
    if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Attribute):
        return False
    attr = expr.func.attr
    if attr in _TEXT_READS or attr in _SOURCE_READS:
        return True
    if attr in _HANDLE_READS:
        return _is_open_call(expr.func.value) or (
            isinstance(expr.func.value, ast.Name) and expr.func.value.id in handles
        )
    if attr in _TEXT_WRAPPERS:
        return _is_read_call(expr.func.value, handles)
    return False


def _calls_in(node: ast.AST):
    """Every `Call` anywhere inside `node`."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            yield sub


def _walks_source(node: ast.AST) -> bool:
    """True if the body calls `ast.parse(...)` or `ast.walk(...)` — the shape
    of a scan that reads source rather than trusting an already-parsed tree."""
    return any(
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "ast"
        and call.func.attr in ("parse", "walk")
        for call in _calls_in(node)
    )


def _matches_text(node: ast.AST) -> bool:
    """True if the body runs a pattern over text — `re.search(...)`, a
    compiled pattern's `.finditer(...)`, or a bare `compile(...)`."""
    for call in _calls_in(node):
        if isinstance(call.func, ast.Attribute) and call.func.attr in _MATCH_CALLS:
            return True
        if isinstance(call.func, ast.Name) and call.func.id == "compile":
            return True
    return False


def _reads_file_text(node: ast.AST) -> bool:
    """True if the body reads a file's text itself, in any of the spellings
    `_is_read_call` knows."""
    handles = _open_handles(node)
    return any(_is_read_call(call, handles) for call in _calls_in(node))


def _tests_membership(node: ast.AST) -> bool:
    """True if the body asks `x in y` / `x not in y` anywhere — the grep
    question, once the text is in hand."""
    return any(
        isinstance(sub, ast.Compare)
        and any(isinstance(op, (ast.In, ast.NotIn)) for op in sub.ops)
        for sub in ast.walk(node)
    )


def _module_collection_constants(tree: ast.Module) -> frozenset[str]:
    """Every module-level `ALL_CAPS` name bound to a collection literal (or to
    `frozenset(...)`/`set(...)`/`tuple(...)`/`list(...)`) — the shape a
    forbidden-word list is written in, in this repo and its siblings."""
    found: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (isinstance(target, ast.Name) and target.id.isupper()):
                continue
            value = node.value
            if isinstance(value, (ast.Set, ast.List, ast.Tuple)) or (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in ("frozenset", "set", "tuple", "list")
            ):
                found.add(target.id)
    return frozenset(found)


def _scans_a_word_list(node: ast.AST, constants: frozenset[str]) -> bool:
    """True if the body iterates one of `constants` and asks a membership
    question inside that iteration — the forbidden-word-list scan."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.For):
            iterables, body = [sub.iter], sub.body
        elif isinstance(sub, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            iterables, body = [g.iter for g in sub.generators], [sub]
        else:
            continue
        if not any(
            isinstance(it, ast.Name) and it.id in constants for it in iterables
        ):
            continue
        if any(_tests_membership(part) for part in body):
            return True
    return False


def _decorator_name(dec: ast.AST) -> str:
    """A decorator's own terminal name: `pytest.fixture` -> "fixture",
    `pytest.mark.usefixtures(...)` -> "usefixtures"."""
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return ""


def _filters_by_membership(node: ast.AST) -> bool:
    """True if the body loops over something and keeps the items that are
    (or are not) *in* a haystack held in a name — `[term for term in terms if
    term in haystack]`.

    `_scans_a_word_list` above wants the iterable to be a module-level
    constant, which is right for a helper owning its own forbidden list. A
    helper handed the terms as an argument is the same grep with the list
    hoisted to the caller. Narrow the same way, twice: the membership question
    must be asked *of the loop variable itself*, so iterating a table and
    asserting something about a result is still not a scan; and the haystack
    must be a bare name (re-grounding ②) — `f not in (unmapped or [])` filters
    a literal against a list built in place, which is a mock being assembled,
    not text being searched.
    """
    for sub in ast.walk(node):
        if isinstance(sub, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            targets = {
                gen.target.id for gen in sub.generators
                if isinstance(gen.target, ast.Name)
            }
            conditions = [cond for gen in sub.generators for cond in gen.ifs]
        elif isinstance(sub, ast.For) and isinstance(sub.target, ast.Name):
            targets, conditions = {sub.target.id}, list(sub.body)
        else:
            continue
        for condition in conditions:
            for inner in ast.walk(condition):
                if (
                    isinstance(inner, ast.Compare)
                    and any(isinstance(op, (ast.In, ast.NotIn)) for op in inner.ops)
                    and isinstance(inner.left, ast.Name)
                    and inner.left.id in targets
                    and all(isinstance(c, ast.Name) for c in inner.comparators)
                ):
                    return True
    return False


def _is_fixture(node: ast.FunctionDef) -> bool:
    """`@pytest.fixture` — setup, not a scan, whatever it reads.

    Matched on the decorator's *own terminal name*, not on the word
    "fixture" appearing anywhere in its dump: `@pytest.mark.usefixtures(...)`
    carries that word and is not a fixture.
    """
    return any(_decorator_name(dec) == "fixture" for dec in node.decorator_list)


def _is_scan_helper(
    node: ast.FunctionDef, constants: frozenset[str] = frozenset()
) -> bool:
    """A module-level helper counts as a scan/guard if it is shaped like one:
    walks source, matches a pattern, reads a file and asks a membership
    question of it, walks a module-level word list asking membership of each,
    or filters the caller's terms by membership in a named haystack.

    Deliberately *not* conditioned on a leading underscore, and (re-grounding
    ①) not on the name at all: a public `check_payload_reach` is the same scan
    with a different name, and a `_check_in` that checks an agent in is not a
    scan with a matching one.
    """
    name = node.name
    if name.startswith("test_") or name.startswith("__"):
        return False
    if _is_fixture(node):
        return False
    return (
        _walks_source(node)
        or _matches_text(node)
        or (_reads_file_text(node) and _tests_membership(node))
        or _scans_a_word_list(node, constants)
        or _filters_by_membership(node)
    )


def _is_plant_test(node: ast.FunctionDef) -> bool:
    """True if `node` is a planted-violation test by this repo's convention:
    a plant word in its name, or the narrower "plant" in its docstring."""
    name = node.name.lower()
    doc = (ast.get_docstring(node) or "").lower()
    return any(word in name for word in _PLANT_NAME_WORDS) or any(
        word in doc for word in _PLANT_DOC_WORDS
    )


def _module_helpers(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    """Every module-level, non-test function in one tests module, by name."""
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("test_")
    }


def _scan_helpers(source: str) -> list[str]:
    """Every module-level scan-helper function name in one tests module."""
    tree = ast.parse(source)
    constants = _module_collection_constants(tree)
    return sorted(
        name
        for name, node in _module_helpers(tree).items()
        if _is_scan_helper(node, constants)
    )


def _direct_calls(node: ast.AST, known: dict[str, ast.FunctionDef]) -> set[str]:
    """The module's own helpers this node calls by bare name."""
    return {
        call.func.id
        for call in _calls_in(node)
        if isinstance(call.func, ast.Name) and call.func.id in known
    }


def _helpers_the_plants_exercise(source: str) -> set[str]:
    """Every helper reachable from a planted-violation test in this module.

    A test counts as a plant test when its **name** carries one of
    `_PLANT_NAME_WORDS`, or its docstring carries one of the narrower
    `_PLANT_DOC_WORDS`; from there the reach is transitive through the
    module's own helpers, because a plant that calls a wrapper has exercised
    the helper underneath it just as surely as if it had called it by hand.
    """
    tree = ast.parse(source)
    helpers = _module_helpers(tree)
    reached: set[str] = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef) and node.name.startswith("test_")):
            continue
        if not _is_plant_test(node):
            continue
        pending = list(_direct_calls(node, helpers))
        while pending:
            name = pending.pop()
            if name in reached:
                continue
            reached.add(name)
            pending.extend(_direct_calls(helpers[name], helpers))
    return reached


def _unplanted_scan_helpers(source: str) -> list[str]:
    """The scan helpers in one tests module that no planted-violation test in
    the same module ever calls."""
    exercised = _helpers_the_plants_exercise(source)
    return [name for name in _scan_helpers(source) if name not in exercised]


#: A shared scan module, if this suite ever grows one (homestead keeps
#: `tests/_scans.py`). Not a `test_*.py` file, so it would hold no plant tests
#: of its own and the same-file rule could not reach it — and a helper that can
#: excuse an inline scan elsewhere but can never be made to fire is the exact
#: asymmetry this file exists to forbid. So it is swept too, against plants
#: anywhere in the suite. This repo has none today; the sweep is planted
#: against a staged one so the day it appears it is already held.
SHARED_SCANS_NAME = "_scans.py"


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """`from _scans import terms_found as tf` -> `{"tf": "terms_found"}`,
    for imports anywhere in the module, function bodies included."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
    return aliases


def _called_names(node: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Every name `node` calls: bare (resolved through `aliases`) or through
    an attribute — `helper(...)`, `tf(...)`, `module.helper(...)` are one
    delegation by three routes."""
    names: set[str] = set()
    for call in _calls_in(node):
        if isinstance(call.func, ast.Name):
            names.add(aliases.get(call.func.id, call.func.id))
        elif isinstance(call.func, ast.Attribute):
            names.add(call.func.attr)
    return names


def _names_the_plants_call(source: str) -> frozenset[str]:
    """Every name a planted-violation test in this module calls — directly,
    or through the module's own helpers, whichever module actually defines
    the name it calls."""
    tree = ast.parse(source)
    helpers = _module_helpers(tree)
    aliases = _import_aliases(tree)
    called: set[str] = set()
    walked: set[str] = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef) and node.name.startswith("test_")):
            continue
        if not _is_plant_test(node):
            continue
        called |= _called_names(node, aliases)
        pending = list(_direct_calls(node, helpers))
        while pending:
            name = pending.pop()
            if name in walked:
                continue
            walked.add(name)
            called |= _called_names(helpers[name], aliases)
            pending.extend(_direct_calls(helpers[name], helpers))
    return frozenset(called)


def _unplanted_shared_scan_helpers(tests_dir: Path = TESTS_DIR) -> list[str]:
    """The scan helpers in `tests/_scans.py` that no planted-violation test
    anywhere in `tests/` ever calls. Cross-module by construction: the
    shared module has no plant tests of its own, and the plant that proves a
    shared helper belongs with the caller that relies on it. Empty when there
    is no shared module."""
    shared = tests_dir / SHARED_SCANS_NAME
    if not shared.exists():
        return []
    exercised: set[str] = set()
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        exercised |= _names_the_plants_call(path.read_text(encoding="utf-8"))
    return [
        name
        for name in _scan_helpers(shared.read_text(encoding="utf-8"))
        if name not in exercised
    ]


def _offenders(tests_dir: Path = TESTS_DIR) -> list[str]:
    """Every tests/*.py file that defines a scan helper no plant test in the
    same file calls — and `tests/_scans.py` if there is one, whose helpers are
    shared and so are held to a plant anywhere in `tests/`."""
    offenders = []
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue  # this file's own helpers are proven below, not here
        unplanted = _unplanted_scan_helpers(path.read_text(encoding="utf-8"))
        if unplanted:
            offenders.append(f"{path.name}: {unplanted}")
    shared_unplanted = _unplanted_shared_scan_helpers(tests_dir)
    if shared_unplanted:
        offenders.append(f"{SHARED_SCANS_NAME}: {shared_unplanted}")
    return offenders


def test_every_scan_helper_has_a_planted_violation_test():
    """The house rule, run for real: no `tests/*.py` file may carry an
    AST/grep-guard helper that no planted-violation test in the same file
    actually runs."""
    offenders = _offenders()
    assert not offenders, (
        "these test files define a scan helper (it walks source, matches a "
        "pattern, reads a file and asks a membership question of it, or walks "
        "a word list asking membership of each) that no test naming "
        "plant/fires/catches ever calls — a scan that has never fired has not "
        f"been shown to check anything: {offenders}"
    )


# ── the discovery half, planted: AST-shaped, grep-shaped, regex, word lists ──


def _write(tmp_path: Path, name: str, body: str) -> str:
    """A fake tests module on disk, read back the way `_offenders()` reads a
    real one."""
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path.read_text(encoding="utf-8")


def test_the_meta_scan_finds_an_ast_shaped_scan_whatever_it_is_named(tmp_path):
    """Planted: a scan that walks `ast` under a **public** name. A rule that
    required a leading underscore would miss `check_payload_reach` — the same
    scan, spelled the way a helper meant to be imported is spelled — and its
    missing plant would go unreported."""
    source = _write(
        tmp_path,
        "test_planted_ast_shaped_scan.py",
        "import ast\n"
        "\n"
        "def check_payload_reach(source):\n"
        "    return [n for n in ast.walk(ast.parse(source))\n"
        "            if isinstance(n, ast.Attribute) and n.attr == 'payload']\n"
        "\n"
        "def test_nothing_reaches_a_payload():\n"
        "    assert not check_payload_reach('x = 1\\n')\n",
    )

    assert _scan_helpers(source) == ["check_payload_reach"], (
        "an ast.parse/ast.walk scan must be found under any name, public or "
        f"private; got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["check_payload_reach"], (
        "and with no planted-violation test in the file it must be reported"
    )


def test_the_meta_scan_finds_a_grep_shaped_scan(tmp_path):
    """Planted: a scan with no `ast` in it at all — `path.read_text()` and an
    `in`. The repo has this shape already (`test_operator_onboard_script.py`'s
    hardcoded-path guard), and a discovery rule that only knew about `ast`
    would clear a file whose only guard is this shape."""
    source = _write(
        tmp_path,
        "test_planted_grep_shaped_scan.py",
        "def forbidden_word_hits(path):\n"
        "    return 'payload' in path.read_text(encoding='utf-8')\n"
        "\n"
        "def test_no_module_says_payload(tmp_path):\n"
        "    probe = tmp_path / 'm.py'\n"
        "    probe.write_text('x = 1\\n', encoding='utf-8')\n"
        "    assert not forbidden_word_hits(probe)\n",
    )

    assert _scan_helpers(source) == ["forbidden_word_hits"], (
        "a read_text()+`in` scan is a scan; the name carries none of the "
        f"usual stems, which is the point. Got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["forbidden_word_hits"]


def test_a_fixture_is_not_mistaken_for_a_scan(tmp_path):
    """The other side of the same honesty: `@pytest.fixture` setup that reads
    a file must not be reported, or the meta-scan cries wolf on every suite
    that stages a tmp home."""
    source = _write(
        tmp_path,
        "test_planted_fixture_only.py",
        "import pytest\n"
        "\n"
        "@pytest.fixture\n"
        "def home(tmp_path):\n"
        "    (tmp_path / 'seed').write_text('x', encoding='utf-8')\n"
        "    return 'seed' in (tmp_path / 'seed').read_text(encoding='utf-8')\n"
        "\n"
        "def test_it(home):\n"
        "    assert home\n",
    )
    assert _scan_helpers(source) == []


def test_the_meta_scan_finds_a_regex_shaped_scan(tmp_path):
    """Planted: a scan whose whole body is a module-level compiled pattern run
    over text — no `ast`, no `read_text`, and a name carrying none of the
    usual stems. `tests/test_tier_policy.py::_guarded_tools` is this shape."""
    source = _write(
        tmp_path,
        "test_planted_regex_shaped_scan.py",
        "import re\n"
        "\n"
        "_BANNED = re.compile(r'innerHTML')\n"
        "\n"
        "def banned_spellings(page):\n"
        "    return _BANNED.findall(page)\n"
        "\n"
        "def test_the_page_builds_no_markup():\n"
        "    assert not banned_spellings('x')\n",
    )

    assert _scan_helpers(source) == ["banned_spellings"], (
        f"a compiled-pattern scan is a scan; got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["banned_spellings"]


def test_the_meta_scan_finds_a_forbidden_word_list_scan(tmp_path):
    """Planted: a scan that walks a module-level word list asking membership
    of text its caller hands it — it reads no file, compiles no pattern,
    parses no source. `tests/test_release_wiring.py::
    _names_a_non_suppressed_credential` is this shape, and it is the guard
    that keeps a workflow from arming a step with a real credential."""
    source = _write(
        tmp_path,
        "test_planted_word_list_scan.py",
        "NON_SUPPRESSED = ('GH_TOKEN', 'FLEET_RO_TOKEN')\n"
        "\n"
        "def names_a_credential(value):\n"
        "    return any(c in str(value) for c in NON_SUPPRESSED)\n"
        "\n"
        "def test_the_step_names_none_of_them():\n"
        "    assert not names_a_credential('secrets.GITHUB_TOKEN')\n",
    )

    assert _scan_helpers(source) == ["names_a_credential"], (
        "a scan that walks a module-level word list asking membership of each "
        f"is a scan; got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["names_a_credential"]


def test_the_word_list_rule_does_not_fire_on_ordinary_constant_use(tmp_path):
    """The control the narrow rule exists for. A behaviour test that iterates
    a module-level table and asserts membership of a *result* is not a scan,
    and a rule loose enough to call it one gets itself allowlisted into
    silence."""
    source = _write(
        tmp_path,
        "test_planted_ordinary_constant_use.py",
        "CADENCES = ('monthly', 'weekly')\n"
        "\n"
        "def detect(rows):\n"
        "    return rows[0]\n"
        "\n"
        "def test_every_cadence_round_trips():\n"
        "    for c in CADENCES:\n"
        "        assert c in ('monthly', 'weekly', 'yearly')\n",
    )
    assert _scan_helpers(source) == []


def test_the_meta_scan_finds_a_scan_handed_its_word_list_by_the_caller(tmp_path):
    """Planted: `terms_found(haystack, terms)` walks the *caller's* list
    asking membership of each — no module-level constant, no regex, no read,
    no stem in its name — so every other rule clears it."""
    source = _write(
        tmp_path,
        "test_planted_caller_word_list.py",
        "def terms_found(haystack, terms):\n"
        "    return [term for term in terms if term in haystack]\n"
        "\n"
        "def test_the_log_carries_none_of_them():\n"
        "    assert not terms_found('a reference only', ('1234',))\n",
    )
    assert _scan_helpers(source) == ["terms_found"], (
        "a helper that filters the caller's terms by membership is a scan; "
        f"got {_scan_helpers(source)}"
    )
    assert _unplanted_scan_helpers(source) == ["terms_found"]


def test_the_caller_word_list_rule_does_not_fire_on_an_ordinary_filter(tmp_path):
    """The control the narrow half exists for, planted both ways. The
    membership question must be asked *of the loop variable itself* — a
    helper that filters rows by a field is ordinary code. And (re-grounding
    ②) the haystack must be a bare name: `tests/test_kb_verify.py::
    _mock_query` filters a literal list against `(unmapped or [])`, which is
    a mock being assembled, and the original rule reported it."""
    by_field = _write(
        tmp_path,
        "test_planted_ordinary_filter.py",
        "KNOWN = ('checking', 'savings')\n"
        "\n"
        "def due_rows(rows):\n"
        "    return [row for row in rows if row[1] in KNOWN]\n"
        "\n"
        "def test_it():\n"
        "    assert due_rows([]) == []\n",
    )
    assert _scan_helpers(by_field) == []

    mock_builder = _write(
        tmp_path,
        "test_planted_mock_builder.py",
        "def _mock_query(records, unmapped=None):\n"
        "    return {'present': [f for f in ['id', 'content'] if f not in (unmapped or [])]}\n"
        "\n"
        "def test_it():\n"
        "    assert _mock_query([])['present']\n",
    )
    assert _scan_helpers(mock_builder) == [], (
        "a membership test against a haystack built in place is not a grep"
    )


def test_a_scan_shaped_name_alone_is_not_a_scan(tmp_path):
    """Re-grounding ①, planted. homestead's copy counted `_check_in` by its
    name; here `_check_in` registers an agent and checks it in, and
    `_is_write_group` classifies a permission-group name by suffix. Neither
    reads, walks or matches, so neither may be reported — and a real scan
    with the same kind of name still must be, by what it does."""
    named_only = _write(
        tmp_path,
        "test_planted_scan_shaped_names.py",
        "_WRITE_GROUP_SUFFIXES = ('_write', '_admin')\n"
        "\n"
        "def _check_in(app_id, trust):\n"
        "    return register(app_id, trust)\n"
        "\n"
        "def _is_write_group(name):\n"
        "    return any(name.endswith(s) for s in _WRITE_GROUP_SUFFIXES)\n"
        "\n"
        "def test_it():\n"
        "    assert _is_write_group('store_write')\n",
    )
    assert _scan_helpers(named_only) == [], (
        "a name is not evidence of a scan; what the body does is"
    )

    named_and_real = _write(
        tmp_path,
        "test_planted_scan_shaped_name_real.py",
        "import re\n"
        "\n"
        "def _check_source(text):\n"
        "    return re.findall(r'innerHTML', text)\n"
        "\n"
        "def test_it():\n"
        "    assert not _check_source('x')\n",
    )
    assert _scan_helpers(named_and_real) == ["_check_source"]
    assert _unplanted_scan_helpers(named_and_real) == ["_check_source"]


# ── the plant half: naming a test "fires" is not having fired ────────────────


def test_the_plant_check_requires_the_plant_test_to_call_the_scan(tmp_path):
    """The counter-example, planted. A file whose only "plant" is a test
    *named* `test_the_scan_fires` and whose body never touches the scan must
    still be reported — a plant word in a name is not a plant."""
    source = _write(
        tmp_path,
        "test_planted_name_only_plant.py",
        "import ast\n"
        "\n"
        "def _payload_reaches(tree):\n"
        "    return [n for n in ast.walk(tree)\n"
        "            if isinstance(n, ast.Attribute) and n.attr == 'payload']\n"
        "\n"
        "def test_the_scan_fires_on_a_planted_violation():\n"
        "    '''Says it plants. Plants nothing.'''\n"
        "    assert True\n",
    )

    assert _scan_helpers(source) == ["_payload_reaches"]
    assert _unplanted_scan_helpers(source) == ["_payload_reaches"], (
        "a plant test that never calls the scan has not fired it; the word in "
        "the test's name is not the evidence"
    )


def test_a_plant_that_calls_the_scan_through_a_helper_clears_it(tmp_path):
    """And not over-strict: a real plant might call a wrapper rather than the
    parser underneath it. Reaching a helper through another helper is having
    exercised it, so neither may be reported."""
    source = _write(
        tmp_path,
        "test_planted_indirect_plant.py",
        "import ast\n"
        "\n"
        "def _payload_reaches(tree):\n"
        "    return [n for n in ast.walk(tree)\n"
        "            if isinstance(n, ast.Attribute) and n.attr == 'payload']\n"
        "\n"
        "def _offenders_in(source):\n"
        "    return _payload_reaches(ast.parse(source))\n"
        "\n"
        "def test_the_scan_catches_a_planted_reach():\n"
        "    assert _offenders_in('y = r.payload\\n')\n",
    )

    assert _scan_helpers(source) == ["_offenders_in", "_payload_reaches"]
    assert _unplanted_scan_helpers(source) == [], (
        "both the wrapper and the helper it calls were exercised by the plant"
    )


def test_a_docstring_saying_fires_about_something_else_does_not_clear_a_scan(tmp_path):
    """Planted: a test whose docstring says "no tag workflow fires" — prose
    about GitHub's event suppression, not about a plant — must not clear the
    scan it happens to call. Only "plant" counts in a docstring; "fires" and
    "catches" count in a test's name, where they are deliberate."""
    source = _write(
        tmp_path,
        "test_planted_prose_fires.py",
        "import ast\n"
        "\n"
        "def _reaches(tree):\n"
        "    return [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)]\n"
        "\n"
        "def test_the_workflow_publishes():\n"
        "    '''No tag workflow fires, so nothing publishes and nothing catches it.'''\n"
        "    assert _reaches(ast.parse('a.b\\n'))\n",
    )

    assert _scan_helpers(source) == ["_reaches"]
    assert _unplanted_scan_helpers(source) == ["_reaches"], (
        "prose using the word 'fires' is not a plant; the scan is still "
        "unproven and must still be reported"
    )


def test_a_docstring_that_says_planted_does_clear_the_scan(tmp_path):
    """And the other side, so the tightening cannot be a blanket refusal: a
    test whose name carries no plant word but whose docstring says it plants,
    and which calls the scan, has fired it."""
    source = _write(
        tmp_path,
        "test_planted_docstring_plant.py",
        "import ast\n"
        "\n"
        "def _reaches(tree):\n"
        "    return [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)]\n"
        "\n"
        "def test_a_reach_is_reported():\n"
        "    '''Planted: a module that does reach an attribute.'''\n"
        "    assert _reaches(ast.parse('a.b\\n'))\n",
    )
    assert _scan_helpers(source) == ["_reaches"]
    assert _unplanted_scan_helpers(source) == []


def test_a_plant_reaches_a_shared_helper_through_an_import_alias(tmp_path):
    """The shared module's proof is cross-module, so the reach has to follow
    the routes a cross-module call actually takes: a bare name, an attribute
    (`module.helper(...)`), and the `import ... as` alias a caller may bind
    it to. A rule that only matched the bare original name would read this
    plant as calling nothing."""
    source = _write(
        tmp_path,
        "test_planted_aliased_plant.py",
        "from _scans import terms_found as tf\n"
        "import _scans\n"
        "\n"
        "def test_the_shared_scan_catches_a_planted_leak():\n"
        "    assert tf('a line naming 1234', ('1234',)) == ['1234']\n"
        "    assert _scans.other_helper('x') == []\n",
    )
    reached = _names_the_plants_call(source)
    assert "terms_found" in reached, "an aliased call is still a call"
    assert "other_helper" in reached, "and so is `module.helper(...)`"

    quiet = _write(
        tmp_path,
        "test_planted_quiet_plant.py",
        "from _scans import terms_found as tf\n"
        "\n"
        "def test_the_shared_scan_catches_a_planted_leak():\n"
        "    assert True\n",
    )
    assert _names_the_plants_call(quiet) == frozenset(), (
        "importing a helper is not calling it; the plant word in the name is "
        "not the evidence here either"
    )


def test_a_shared_scan_module_is_swept_against_plants_anywhere(tmp_path):
    """Planted: a staged `tests/` with a `_scans.py` whose helper no plant
    anywhere calls must be reported under the shared module's name; add a
    plant in any test file and it clears. This repo has no shared module yet,
    so the real sweep is empty — this is what holds the day one appears."""
    (tmp_path / SHARED_SCANS_NAME).write_text(
        "def terms_found(haystack, terms):\n"
        "    return [term for term in terms if term in haystack]\n",
        encoding="utf-8",
    )
    (tmp_path / "test_uses_it.py").write_text(
        "from _scans import terms_found\n"
        "\n"
        "def test_the_export_is_clean():\n"
        "    assert terms_found('x', ('1234',)) == []\n",
        encoding="utf-8",
    )
    assert _unplanted_shared_scan_helpers(tmp_path) == ["terms_found"]
    assert _offenders(tmp_path) == [f"{SHARED_SCANS_NAME}: ['terms_found']"]

    (tmp_path / "test_plants_it.py").write_text(
        "from _scans import terms_found\n"
        "\n"
        "def test_the_shared_scan_catches_a_planted_leak():\n"
        "    assert terms_found('a line naming 1234', ('1234',)) == ['1234']\n",
        encoding="utf-8",
    )
    assert _unplanted_shared_scan_helpers(tmp_path) == []
    assert _offenders(tmp_path) == []


def test_this_file_holds_itself_to_its_own_rule():
    """`_offenders()` skips this file, so nothing above would report a helper
    here that no plant reaches. Run the same rule over this file's own
    source: every scan-shaped helper it defines (most of them walk `ast`)
    must be reached from a test naming plant/fires/catches, or this file
    would be the one scan in the suite exempt from itself."""
    source = Path(__file__).read_text(encoding="utf-8")
    assert _scan_helpers(source), "this file is expected to define scan helpers"
    assert _unplanted_scan_helpers(source) == []


def test_the_plant_check_does_not_fire_on_real_guarded_files():
    """The whole thing against real files of this repo's, one per half of
    the vendor bite this file shipped with: `tests/test_vendor_pins.py`
    defines `_body` (a compiled pattern run over the vendored file) and
    plants it; `tests/test_annotation_consistency.py` defines two regex
    scans over server.py and plants both. The meta-scan must clear them, or
    it would be crying wolf on the very files it exists to clear."""
    for name in ("test_vendor_pins.py", "test_annotation_consistency.py"):
        source = (TESTS_DIR / name).read_text(encoding="utf-8")
        assert _scan_helpers(source), f"{name} is expected to define scan helpers"
        assert _unplanted_scan_helpers(source) == [], name


# ── the inline half: a scan written directly in a test's own body ───────────
#
# Everything above reads *module-level helpers*. A guard written inline, in a
# test's own body, with nothing to name and nothing to plant, is invisible to
# it. This half walks every `test_*` function's own body for the same shapes,
# holds it to "reads a file of the TREE" (re-grounding ③), and clears a test
# that delegates to a scan helper already defined (and already required to be
# planted) somewhere in `tests/` — recognised by name, whichever module
# actually owns it.
#
# "A membership question of it" is held to the text actually read, not to
# anything built from it: a name bound directly to a read (one level, or
# through a `str` method that only narrows the text) counts; a dict key or a
# `json.loads` result several steps removed does not.


#: String operations that narrow text without turning it into something
#: else: `source.split("def _route_post")[1]` is still the file's own text.
#: The list is deliberately all `str`/`bytes` methods — `json.loads(...)` is
#: a bare call to a *name*, not one of these, so a dict built from a read is
#: several steps removed and still not a scan.
_TEXT_SLICERS = _TEXT_WRAPPERS | frozenset(
    {"split", "rsplit", "splitlines", "partition", "rpartition", "replace",
     "lstrip", "rstrip", "removeprefix", "removesuffix"}
)

#: Calls whose first argument IS the path — `Path(p)`, `pathlib.Path(p)`,
#: `open(p)`, `str(p)`.
_PATH_WRAPPERS = frozenset({"Path", "open", "str"})

# Where a path is rooted (re-grounding ③).
_TREE = "tree"          # a module-level name, __file__, a literal: a file that ships
_FIXTURE = "fixture"    # a function parameter, or a local built from one: the test's own file
_UNKNOWN = "unknown"    # came out of a bare call the rule cannot see through


def _path_kind(expr: ast.AST | None, kinds: dict[str, str]) -> str:
    """Where the path `expr` ultimately comes from. `kinds` is what is known
    about the function's own names; a name not in it is a module-level one,
    which is the tree."""
    if expr is None:
        return _UNKNOWN
    if isinstance(expr, ast.Name):
        return kinds.get(expr.id, _TREE)
    if isinstance(expr, ast.Constant):
        return _TREE
    if isinstance(expr, ast.JoinedStr):
        parts = [v.value for v in expr.values if isinstance(v, ast.FormattedValue)]
        found = [_path_kind(p, kinds) for p in parts]
        return _FIXTURE if _FIXTURE in found else _TREE
    if isinstance(expr, ast.BinOp):
        return _path_kind(expr.left, kinds)
    if isinstance(expr, ast.Subscript):
        return _path_kind(expr.value, kinds)
    if isinstance(expr, ast.Attribute):
        return _path_kind(expr.value, kinds)
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Name) and func.id in _PATH_WRAPPERS and expr.args:
            return _path_kind(expr.args[0], kinds)
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id == "pathlib" and func.attr == "Path" and expr.args):
            return _path_kind(expr.args[0], kinds)
        if any(_path_kind(a, kinds) == _FIXTURE for a in expr.args):
            return _FIXTURE
        if isinstance(func, ast.Attribute):
            # a method call: `Path(__file__).resolve()`, `_SCRIPT.with_suffix(...)`
            kind = _path_kind(func.value, kinds)
            return kind if kind == _TREE else _UNKNOWN
        return _UNKNOWN
    return _UNKNOWN


def _name_kinds(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    """What each of the function's own names is rooted in: every parameter is
    a fixture, and every local takes the kind of what it was bound from —
    `log_path = tmp_path / "wake.log"` is a fixture, `unit_file = cfg / ...`
    where `cfg = tmp_path / "config"` is one two steps removed, and
    `path = personas_dir() / "x.md"` is unknown — to a fixed point. A local
    never bound from a path at all (a counter, a dict) reads as the tree, and
    nothing reads it, so it never matters."""
    args = func.args
    kinds: dict[str, str] = {
        a.arg: _FIXTURE for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]
    }
    for extra in (args.vararg, args.kwarg):
        if extra:
            kinds[extra.arg] = _FIXTURE
    params = frozenset(kinds)
    bindings: list[tuple[list[str], ast.AST]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            bindings.append(([t.id for t in node.targets if isinstance(t, ast.Name)], node.value))
        elif isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
            bindings.append(([node.optional_vars.id], node.context_expr))
        elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            bindings.append(([node.target.id], node.iter))
    for _ in range(len(bindings) + 1):
        changed = False
        for targets, value in bindings:
            kind = _path_kind(value, kinds)
            for target in targets:
                if target not in params and kinds.get(target) != kind:
                    kinds[target] = kind
                    changed = True
        if not changed:
            break
    return kinds


def _read_path(expr: ast.AST, handles: dict[str, ast.AST | None]) -> ast.AST | None:
    """The path expression a read call reads — the receiver of `.read_text()`,
    the argument of the `open(...)` behind a `.read()`, or the object handed to
    `inspect.getsource` (a module or function, which lives in the tree)."""
    while isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr in _TEXT_WRAPPERS:
        expr = expr.func.value
    if not (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)):
        return None
    attr, receiver = expr.func.attr, expr.func.value
    if attr in _TEXT_READS:
        return receiver
    if attr in _SOURCE_READS:
        return ast.Constant(value="<source>")
    if attr in _HANDLE_READS:
        if _is_open_call(receiver):
            return receiver.args[0] if receiver.args else None
        if isinstance(receiver, ast.Name) and receiver.id in handles:
            return handles[receiver.id]
    return None


def _is_tree_read(expr: ast.AST, handles: dict[str, ast.AST | None], kinds: dict[str, str]) -> bool:
    """A read call of a file that ships — not the test's own, not unknown."""
    return _is_read_call(expr, handles) and _path_kind(_read_path(expr, handles), kinds) == _TREE


def _text_root(expr: ast.AST) -> ast.AST:
    """Peel subscripts and `_TEXT_SLICERS` calls off `expr` and return what
    the text ultimately came from."""
    while True:
        if isinstance(expr, ast.Subscript):
            expr = expr.value
        elif (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr in _TEXT_SLICERS
        ):
            expr = expr.func.value
        else:
            return expr


def _direct_text_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Local names holding the text of a tree file this function read —
    bound straight from the read, or from a slice of one such name through
    `_TEXT_SLICERS` alone. Nothing that turns the text into another kind of
    object (`json.loads`, `tomllib.loads`) is traced, so `"x" in
    pyproject["project"]` stays the ordinary assertion it is."""
    handles = _open_handles(func)
    kinds = _name_kinds(func)
    names: set[str] = set()
    assigns = [
        (
            [t.id for t in node.targets if isinstance(t, ast.Name)],
            _text_root(node.value),
        )
        for node in ast.walk(func)
        if isinstance(node, ast.Assign)
    ]
    for _ in range(len(assigns) + 1):  # to a fixed point; each pass adds ≥1 or stops
        grew = False
        for targets, root in assigns:
            if not targets or set(targets) <= names:
                continue
            if _is_tree_read(root, handles, kinds) or (
                isinstance(root, ast.Name) and root.id in names
            ):
                names.update(targets)
                grew = True
        if not grew:
            break
    return frozenset(names)


def _membership_on_read_text(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A membership test whose text side is a tree-file read — directly, or
    through a name `_direct_text_names` traces back to one."""
    direct_names = _direct_text_names(node)
    handles = _open_handles(node)
    kinds = _name_kinds(node)
    for sub in ast.walk(node):
        if isinstance(sub, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in sub.ops):
            for operand in (sub.left, *sub.comparators):
                root = _text_root(operand)
                if _is_tree_read(root, handles, kinds) or (
                    isinstance(root, ast.Name) and root.id in direct_names
                ):
                    return True
    return False


def _isinstance_against_ast_type(node: ast.AST) -> bool:
    """True if the body itself calls `isinstance(x, ast.SomeType)` (or a
    tuple containing one) — the direct judgment of a source walk, as against
    a test that merely calls `ast.parse()` and hands the tree to a scan
    helper already defined (and already planted) elsewhere."""
    for call in _calls_in(node):
        if isinstance(call.func, ast.Name) and call.func.id == "isinstance" and len(call.args) == 2:
            type_arg = call.args[1]
            candidates = type_arg.elts if isinstance(type_arg, ast.Tuple) else [type_arg]
            for candidate in candidates:
                if (
                    isinstance(candidate, ast.Attribute)
                    and isinstance(candidate.value, ast.Name)
                    and candidate.value.id == "ast"
                ):
                    return True
    return False


def _global_scan_helper_names(tests_dir: Path = TESTS_DIR) -> frozenset[str]:
    """Every scan-helper name defined anywhere in `tests/` — every
    `test_*.py` file (this one excluded — its own helpers are proven above,
    not by this rule) plus the shared `tests/_scans.py`, if there is one. A
    test that calls one of these by name — bare, or through
    `module.helper(...)` — is delegating to a helper the module-helper half
    already holds to its own plant, wherever that helper actually lives."""
    names: set[str] = set()
    paths = sorted(tests_dir.glob("test_*.py"))
    shared = tests_dir / SHARED_SCANS_NAME
    if shared.exists():
        paths.append(shared)
    for path in paths:
        if path.name == Path(__file__).name:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants = _module_collection_constants(tree)
        for name, fn in _module_helpers(tree).items():
            if _is_scan_helper(fn, constants):
                names.add(name)
    return frozenset(names)


def _imported_names(tree: ast.Module) -> frozenset[str]:
    """Every name this module binds with `from ... import name` (or `as`),
    anywhere — function-body imports included, which is how most of this
    suite reaches another module's helper."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
    return frozenset(names)


def _calls_any_by_name(
    node: ast.AST, bare: frozenset[str], attrs: frozenset[str] | None = None
) -> bool:
    """True if `node` delegates to a known scan helper: a bare call to one of
    `bare`, or `module.helper(...)` for one of `attrs`.

    The two sets differ on purpose. An attribute call names the module it
    comes from, so matching the attribute alone is safe. A *bare* name is
    only that helper if this module actually has it — imported, or defined
    here — otherwise a local function that happens to share a name with some
    other module's scan helper would clear every inline scan beside it.
    """
    attrs = bare if attrs is None else attrs
    for call in _calls_in(node):
        if isinstance(call.func, ast.Name) and call.func.id in bare:
            return True
        if isinstance(call.func, ast.Attribute) and call.func.attr in attrs:
            return True
    return False


def _resolvable_helpers(source: str, global_helpers: frozenset[str]) -> frozenset[str]:
    """The known scan helpers this module can reach by a *bare* name: the
    ones it imports, and the ones it defines itself."""
    tree = ast.parse(source)
    return global_helpers & (
        _imported_names(tree) | frozenset(_scan_helpers(source))
    )


def _reads_tree_text(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if the body reads a file of the tree itself (re-grounding ③)."""
    handles = _open_handles(node)
    kinds = _name_kinds(node)
    return any(_is_tree_read(call, handles, kinds) for call in _calls_in(node))


def _is_inline_scan(
    node: ast.AST,
    global_helpers: frozenset[str],
    bare_helpers: frozenset[str] | None = None,
) -> bool:
    """A test body counts as an inline scan when it reads a file of the tree
    and, in its own body — not by calling a scan helper `tests/` already
    defines somewhere — walks source and judges it directly (`ast.parse`/
    `ast.walk` plus an `isinstance` against an `ast.*` type), matches a
    pattern, or asks a membership question of the text it read.

    **Delegation clears the whole test, deliberately.** A test that calls a
    known scan helper is not reported even if it also asks its own `in`
    question of the text it read, because that second question is usually
    the fixture precondition of the first ("the file really does carry the
    thing I am about to plant"). The cost is real and named: an unplanted
    inline `in` hidden behind a delegated call is not seen.
    """
    if not (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ):
        return False
    if _is_fixture(node):
        return False
    if not _reads_tree_text(node):
        return False  # not reading a file that ships — the test's own, or a string it built
    bare = global_helpers if bare_helpers is None else bare_helpers
    if _calls_any_by_name(node, bare, global_helpers):
        return False  # delegates to a helper already held to its own plant
    return (
        (_walks_source(node) and _isinstance_against_ast_type(node))
        or _matches_text(node)
        or _membership_on_read_text(node)
    )


def _test_functions(tree: ast.Module):
    """Every test function in a module, by the name a failure would report
    it as: module-level `def test_*`/`async def test_*`, and the methods of
    a `class Test*`."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}::{method.name}", method


def _inline_scan_tests(source: str, global_helpers: frozenset[str]) -> list[str]:
    """Every test function in one tests module whose own body is itself a
    scan by the rule above."""
    tree = ast.parse(source)
    bare = _resolvable_helpers(source, global_helpers)
    return sorted(
        name
        for name, node in _test_functions(tree)
        if _is_inline_scan(node, global_helpers, bare)
    )


def _inline_scan_offenders(tests_dir: Path = TESTS_DIR) -> list[str]:
    """Every `file::test_name` in `tests/*.py` whose own body is itself an
    unfactored scan."""
    global_helpers = _global_scan_helper_names(tests_dir)
    offenders = []
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        for name in _inline_scan_tests(path.read_text(encoding="utf-8"), global_helpers):
            offenders.append(f"{path.name}::{name}")
    return offenders


#: The inline tree scans this suite carried before this file existed. Each is
#: a follow-up: factor the scan into a module-level helper and plant it in the
#: same file, then strike the line. The set is asserted EXACTLY — see the
#: module docstring on why that is a ratchet and not an allowlist.
KNOWN_INLINE_SCANS: frozenset[str] = frozenset([
    "test_counts_in_prose.py::test_the_readme_mcp_badge_matches_the_sdk_this_package_pins",
    "test_egress_pause.py::test_the_module_offers_no_way_to_authorize",
    "test_fleet_wiring.py::test_fleet_standup_does_not_export_a_fleet_wide_app_id",
    "test_fleet_wiring.py::test_frank_ledger_ddl_defines_every_column_the_code_uses",
    "test_fleet_wiring.py::test_frank_ledger_ddl_is_fork_proof_from_the_first_row",
    "test_governance_continuity.py::test_every_errno_check_emits_is_registered_in_the_table",
    "test_hook_wiring_sync.py::test_pre_tool_use_web_matcher_does_not_swallow_unrelated_mcp_tools",
    "test_hook_wiring_sync.py::test_pre_tool_use_web_matcher_selects_willow_web_search",
    "test_idp_rename_compat.py::test_apples_own_iss_check_is_untouched",
    "test_idp_rename_compat.py::test_the_gate_reads_idp_not_iss",
    "test_lanes.py::test_there_is_no_table_of_store_names",
    "test_mai_directive_gate.py::test_no_second_host_guard_lives_in_the_parser",
    "test_native_startup.py::test_session_start_hook_has_no_fylgja_imports",
    "test_nest_intake.py::test_seed_is_pii_free_and_generic",
    "test_operator_onboard_script.py::test_no_hardcoded_personal_or_fleet_paths_remain",
    "test_operator_onboard_script.py::test_sync_hint_uses_the_callers_app_id_not_a_literal",
    "test_pre_tool_use_hook.py::test_design_doc_states_guardrail_not_control",
    "test_server.py::test_postgres_unavailable_call_sites_all_use_the_shared_helper",
    "test_subject_consent.py::test_core_has_no_network_or_subprocess_imports",
    "test_subject_consent.py::test_core_imports_stdlib_only",
    "test_subject_consent.py::test_deidentify_error_never_carries_the_value",
    "test_tier_policy.py::test_every_guarded_decorator_uses_a_string_literal_name",
    "test_web_search.py::test_the_search_module_makes_no_unguarded_network_call",
    "test_willow_serve_worker.py::test_worker_template_has_journal_and_postgres",
    "test_worker_drain.py::test_deploy_kart_worker_units_are_willow_mcp_successors",
])


def test_no_new_test_body_is_itself_a_scan():
    """The inline half of the house rule: a guard written directly in a
    test's body, with no helper to name and plant, is invisible to the scan
    above and can never be shown to fire. Every `tests/*.py` test must either
    not be a scan by the shapes above, delegate to a scan helper `tests/`
    already defines and plants, or be one of the named follow-ups in
    `KNOWN_INLINE_SCANS` — and that list must be exactly what is left."""
    offenders = frozenset(_inline_scan_offenders())
    new = sorted(offenders - KNOWN_INLINE_SCANS)
    assert not new, (
        "these tests are themselves a scan (read a file of the tree, then walk "
        "its source and judge it, match a pattern, or ask a membership question "
        "of the text) with no scan helper behind them anywhere in tests/, so "
        f"the scan can never be shown to fire: {new}. Factor the scan into a "
        "helper and plant it in the same file."
    )
    stale = sorted(KNOWN_INLINE_SCANS - offenders)
    assert not stale, (
        "these KNOWN_INLINE_SCANS entries no longer report as inline scans — "
        f"strike them, so the list stays exactly what is left to factor: {stale}"
    )


def test_the_inline_scan_check_finds_a_scan_written_directly_in_a_test_body(tmp_path):
    """Planted: a test file whose only guard is written inline — `ast.parse`
    plus a direct `isinstance` walk, on a file rooted at a module-level
    constant (`TARGET`). No helper exists anywhere for it to delegate to, so
    it must be reported."""
    target = tmp_path / "target.py"
    target.write_text("import banned\n", encoding="utf-8")
    source = _write(
        tmp_path,
        "test_planted_inline_scan.py",
        "import ast\n"
        "from pathlib import Path\n"
        f"TARGET = Path({str(target)!r})\n"
        "\n"
        "def test_no_banned_import_at_module_scope():\n"
        "    tree = ast.parse(TARGET.read_text('utf-8'))\n"
        "    for node in tree.body:\n"
        "        if isinstance(node, ast.Import):\n"
        "            assert 'banned' not in {a.name for a in node.names}\n",
    )
    assert _inline_scan_tests(source, frozenset()) == ["test_no_banned_import_at_module_scope"]


def test_the_inline_scan_check_knows_every_spelling_of_reading_a_tree_file(tmp_path):
    """Planted, one per spelling: the builtin `open` on a module's
    `__file__` (`test_idp_rename_compat.py` reads `oauth.__file__` this way),
    a `with` block, `read_bytes().decode()`, `pathlib.Path("literal")`
    (`test_lanes.py`), `Path(__file__).resolve().parents[1] / ...`
    (`test_worker_drain.py`), and `inspect.getsource` (`test_server.py`,
    `test_egress_pause.py`). Each must be reported."""
    spellings = {
        "open_module_file": "    text = open(oauth.__file__, encoding='utf-8').read()\n",
        "open_with": (
            "    with open(SCRIPT, encoding='utf-8') as handle:\n"
            "        text = handle.read()\n"
        ),
        "read_bytes_decode": "    text = SCRIPT.read_bytes().decode()\n",
        "literal_path": "    text = pathlib.Path('src/willow_mcp/lanes.py').read_text()\n",
        "dunder_file": "    text = (Path(__file__).resolve().parents[1] / 'deploy' / 'x.service').read_text()\n",
        "getsource": "    text = inspect.getsource(oauth)\n",
    }
    for label, read in spellings.items():
        source = _write(
            tmp_path,
            f"test_planted_read_{label}.py",
            "import inspect\n"
            "import pathlib\n"
            "from pathlib import Path\n"
            "from willow_mcp import oauth\n"
            "SCRIPT = Path('x')\n"
            "\n"
            "def test_no_banned_word():\n"
            f"{read}"
            "    assert 'banned' not in text\n",
        )
        assert _inline_scan_tests(source, frozenset()) == ["test_no_banned_word"], (
            f"reading a tree file via {label} is reading a tree file"
        )


def test_the_inline_scan_check_does_not_fire_on_a_file_the_test_made(tmp_path):
    """Re-grounding ③, planted. A behaviour test that drives the code to
    write a file under `tmp_path` (or a `home` fixture) and reads it back is
    asserting the behaviour, not scanning the tree — `test_activation_rail.py`
    reads the wake log `activate()` wrote, through a local built from the
    fixture, and `test_willow_serve_worker.py` reads a unit file two locals
    deep. None may be reported; the same read of a module-level path must be."""
    behaviour = _write(
        tmp_path,
        "test_planted_behaviour_readback.py",
        "def test_build_activate_writes_a_wake_line(tmp_path, home):\n"
        "    cfg = tmp_path / 'config'\n"
        "    unit_file = cfg / 'systemd' / 'unit.service'\n"
        "    log_path = home / 'wake.log'\n"
        "    run(unit_file, log_path)\n"
        "    assert '[WAKE]' in log_path.read_text(encoding='utf-8')\n"
        "    body = unit_file.read_text(encoding='utf-8')\n"
        "    assert '-m willow_mcp.worker' in body\n"
        "    assert 'pid=' in lock_path(tmp_path).read_text()\n",
    )
    assert _inline_scan_tests(behaviour, frozenset()) == [], (
        "a file the test drove the code to write is the test's own, not the tree's"
    )

    tree_read = _write(
        tmp_path,
        "test_planted_tree_readback.py",
        "TEMPLATE = Path('deploy/unit.service')\n"
        "\n"
        "def test_the_template_names_the_worker(tmp_path):\n"
        "    body = TEMPLATE.read_text(encoding='utf-8')\n"
        "    assert '-m willow_mcp.worker' in body\n",
    )
    assert _inline_scan_tests(tree_read, frozenset()) == ["test_the_template_names_the_worker"], (
        "and the same read of a module-level path is a scan of the tree"
    )


def test_the_inline_scan_check_clears_a_path_it_cannot_see_through(tmp_path):
    """The boundary, planted so it is a boundary and not a bug: a path that
    comes out of a bare call (`personas_dir() / "hanuman.md"`) is unknown to
    the rule — it may be the tree or the test's home — and is cleared, not
    guessed. Closing this needs an interpreter."""
    source = _write(
        tmp_path,
        "test_planted_unknown_root.py",
        "def test_compile_persona_writes_file(home):\n"
        "    path = personas_dir() / 'hanuman.md'\n"
        "    assert 'Hanuman' in path.read_text()\n",
    )
    assert _inline_scan_tests(source, frozenset()) == []


def test_the_inline_scan_check_follows_a_slice_of_the_text_but_not_a_parse_of_it(tmp_path):
    """The boundary the one-level rule draws, planted both ways. A `.split()`
    of the text read is still that text, but a dict `json.loads` built from
    it is another kind of object, and asking membership of *that* is the
    ordinary assertion this rule must not cry wolf on."""
    sliced = _write(
        tmp_path,
        "test_planted_sliced_text.py",
        "from pathlib import Path\n"
        "SERVER = Path('x')\n"
        "\n"
        "def test_the_post_router_names_no_export():\n"
        "    source = SERVER.read_text(encoding='utf-8')\n"
        "    block = source.split('def _route_post')[1].split('def _field')[0]\n"
        "    assert 'export' not in block\n",
    )
    assert _inline_scan_tests(sliced, frozenset()) == ["test_the_post_router_names_no_export"]

    parsed = _write(
        tmp_path,
        "test_planted_parsed_text.py",
        "import json\n"
        "from pathlib import Path\n"
        "PYPROJECT = Path('x')\n"
        "\n"
        "def test_the_document_declares_a_version():\n"
        "    loaded = json.loads(PYPROJECT.read_text(encoding='utf-8'))\n"
        "    assert 'version' in loaded['project']\n",
    )
    assert _inline_scan_tests(parsed, frozenset()) == [], (
        "a dict parsed out of the text is not the text; a rule that reported "
        "this gets an allow-list bolted to it and stops meaning anything"
    )


def test_the_inline_scan_check_does_not_fire_on_a_string_the_test_built(tmp_path):
    """Planted: a test that matches a pattern, but only against a string
    literal it built itself — no read anywhere. Not a scan of the tree, so it
    must not be reported."""
    source = _write(
        tmp_path,
        "test_planted_string_literal_match.py",
        "import re\n"
        "\n"
        "def test_the_greeting_has_no_banned_word():\n"
        "    assert not re.search(r'banned', 'a fleet keeps its own books')\n",
    )
    assert _inline_scan_tests(source, frozenset()) == []


def test_a_usefixtures_marker_does_not_exempt_a_test_from_either_half(tmp_path):
    """Planted: `@pytest.mark.usefixtures` carries the word "fixture", and a
    rule that looked for that word anywhere in the decorator would clear
    every test wearing it. The marker must not exempt; a real
    `@pytest.fixture` beside it still must."""
    marked = _write(
        tmp_path,
        "test_planted_usefixtures.py",
        "import pytest\n"
        "from pathlib import Path\n"
        "SCRIPT = Path('x')\n"
        "\n"
        "@pytest.mark.usefixtures('_home')\n"
        "def test_no_banned_word():\n"
        "    text = SCRIPT.read_text(encoding='utf-8')\n"
        "    assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(marked, frozenset()) == ["test_no_banned_word"], (
        "a usefixtures marker is not a fixture and must not exempt the test"
    )

    real = _write(
        tmp_path,
        "test_planted_real_fixture.py",
        "import pytest\n"
        "from pathlib import Path\n"
        "SCRIPT = Path('x')\n"
        "\n"
        "@pytest.fixture(autouse=True)\n"
        "def staged():\n"
        "    return 'banned' in SCRIPT.read_text(encoding='utf-8')\n",
    )
    assert _scan_helpers(real) == [], "a real @pytest.fixture is still setup"


def test_the_inline_scan_check_clears_a_test_that_delegates_to_a_known_helper(tmp_path):
    """And not over-strict: a test that reads a tree file and calls a scan
    helper already known to `tests/` (wherever it actually lives — bare name
    or `module.helper(...)`) is delegating, not scanning inline, so it must
    not be reported even though it still asks a membership question of the
    result."""
    source = _write(
        tmp_path,
        "test_planted_delegating_test.py",
        "from pathlib import Path\n"
        "from test_authority_surface import _mcp_tool_names\n"
        "SERVER = Path('x')\n"
        "\n"
        "def test_every_tool_is_named():\n"
        "    names = _mcp_tool_names(SERVER.read_text(encoding='utf-8'))\n"
        "    assert 'store_put' in names\n",
    )
    assert _inline_scan_tests(source, frozenset({"_mcp_tool_names"})) == []


def test_the_inline_scan_check_reads_class_methods_and_async_tests_too(tmp_path):
    """Planted: the two shapes a `tree.body`-only walk cannot see — a scan in
    a `class Test*` method, and in an `async def test_*`."""
    in_a_class = _write(
        tmp_path,
        "test_planted_class_scan.py",
        "from pathlib import Path\n"
        "SCRIPT = Path('x')\n"
        "\n"
        "class TestTheTree:\n"
        "    def test_no_banned_word(self):\n"
        "        text = SCRIPT.read_text(encoding='utf-8')\n"
        "        assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(in_a_class, frozenset()) == [
        "TestTheTree::test_no_banned_word"
    ], "a scan in a test class's method is still a scan, and is named as one"

    awaited = _write(
        tmp_path,
        "test_planted_async_scan.py",
        "from pathlib import Path\n"
        "SCRIPT = Path('x')\n"
        "\n"
        "async def test_no_banned_word():\n"
        "    text = SCRIPT.read_text(encoding='utf-8')\n"
        "    assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(awaited, frozenset()) == ["test_no_banned_word"]


def test_delegating_clears_a_test_that_also_asks_its_own_question(tmp_path):
    """The boundary this rule draws, pinned rather than left to be
    rediscovered: a test that calls a known scan helper is cleared *whole*,
    including an `in` of its own on the same text — the precondition that
    keeps a plant honest."""
    source = _write(
        tmp_path,
        "test_planted_delegate_and_check.py",
        "from pathlib import Path\n"
        "from test_tier_policy import _guarded_tools\n"
        "SERVER = Path('x')\n"
        "\n"
        "def test_the_planted_tool_is_reported():\n"
        "    source = SERVER.read_text(encoding='utf-8')\n"
        "    assert '@_guarded(' in source\n"
        "    assert _guarded_tools(source)\n",
    )
    assert _inline_scan_tests(source, frozenset({"_guarded_tools"})) == []
    assert _inline_scan_tests(source, frozenset()) == [
        "test_the_planted_tool_is_reported"
    ], "and with no helper behind it, the same body is an inline scan"


def test_a_local_function_sharing_a_helpers_name_does_not_clear_a_scan(tmp_path):
    """Planted: the shadow. Delegation is recognised by *name*, across the
    whole of `tests/`, so a module with a local function that happens to
    share a scan helper's name would have every inline scan beside it
    cleared by a call to something else entirely. A bare name only counts
    when this module imports it or defines it."""
    shadow = _write(
        tmp_path,
        "test_planted_shadowed_helper.py",
        "from pathlib import Path\n"
        "SCRIPT = Path('x')\n"
        "\n"
        "def _sections(text):\n"
        "    return text\n"
        "\n"
        "def test_no_banned_word():\n"
        "    text = SCRIPT.read_text(encoding='utf-8')\n"
        "    assert _sections(text)\n"
        "    assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(shadow, frozenset({"_sections"})) == [
        "test_no_banned_word"
    ], "a local `_sections` is not another module's `_sections`"

    imported = _write(
        tmp_path,
        "test_planted_imported_helper.py",
        "from pathlib import Path\n"
        "from test_docs_drift import _sections\n"
        "SCRIPT = Path('x')\n"
        "\n"
        "def test_no_banned_word():\n"
        "    text = SCRIPT.read_text(encoding='utf-8')\n"
        "    assert _sections(text)\n"
        "    assert 'banned' not in text\n",
    )
    assert _inline_scan_tests(imported, frozenset({"_sections"})) == [], (
        "and the same call, of the helper this module really imported, is "
        "the delegation it looks like"
    )


def test_the_ratchet_reports_both_a_new_scan_and_a_stale_entry(tmp_path):
    """Planted, both directions. A staged `tests/` with one inline tree scan:
    reported when the known list is empty (new), and the known list is stale
    the moment the scan is factored into a helper and planted. Either way the
    list and the tree disagree, and the test above says which way."""
    (tmp_path / "test_lanes.py").write_text(
        "import pathlib\n"
        "\n"
        "def test_there_is_no_table_of_store_names():\n"
        "    src = pathlib.Path('src/willow_mcp/lanes.py').read_text()\n"
        "    assert 'willow_20' not in src\n",
        encoding="utf-8",
    )
    reported = frozenset(_inline_scan_offenders(tmp_path))
    assert reported == {"test_lanes.py::test_there_is_no_table_of_store_names"}
    assert sorted(reported - frozenset()) == ["test_lanes.py::test_there_is_no_table_of_store_names"], (
        "with an empty known list the scan is new"
    )

    (tmp_path / "test_lanes.py").write_text(
        "import pathlib\n"
        "\n"
        "def _store_names_in(text):\n"
        "    return [n for n in ('willow_20', 'dev_kb') if n in text]\n"
        "\n"
        "def test_the_guard_catches_a_planted_name():\n"
        "    assert _store_names_in('lane = \"willow_20\"') == ['willow_20']\n"
        "\n"
        "def test_there_is_no_table_of_store_names():\n"
        "    src = pathlib.Path('src/willow_mcp/lanes.py').read_text()\n"
        "    assert not _store_names_in(src)\n",
        encoding="utf-8",
    )
    factored = frozenset(_inline_scan_offenders(tmp_path))
    assert factored == frozenset(), "delegating to the planted helper clears it"
    assert sorted(reported - factored) == ["test_lanes.py::test_there_is_no_table_of_store_names"], (
        "and the old entry is now stale — the list must shrink with the tree"
    )
