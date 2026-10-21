"""Trust-owner code never reaches the one script (operator ruling, 2026-10-21,
"1 yes").

The trust owner's root-owned venv loads a fixed set of willow_mcp modules.
``onescript_reach`` inserts an operator-writable checkout into ``sys.path``, so
nothing in that set, and nothing it imports (lazily too), may import an
``onescript_*`` module or the ``onescript`` package. Their code stays local and
is held byte-for-byte to the one script's by tests that live outside the trust
path (test_sign_parity.py, test_canon_goldens.py, test_onescript_clock.py).

This walks the AST from the seeds, following every import statement wherever it
sits (module level, inside a function, in a try block) and every
``importlib.import_module`` / ``__import__`` call with a literal name.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PKG = "willow_mcp"
SRC = Path(__file__).resolve().parents[1] / "src" / PKG

#: The traced set the operator named (a package name stands for its modules).
SEEDS = [
    "cli_manifest_grant",
    "envelope_authoring",
    "envelopes",
    "governance_ledger",
    "human_session",
    "keyring",
    "manifest_grant_executor",
    "mcp_federation",
    "paths",
    "pgp",
    "trust_identity",
    "trust_marker",
    "trust_owner_verbs",
    "session_signing",
]


def _file_for(mod: str) -> Path | None:
    """``willow_mcp.x.y`` -> its file, or None when it is not ours."""
    parts = mod.split(".")
    if parts[0] != PKG:
        return None
    base = SRC.joinpath(*parts[1:])
    if base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return None


def _is_package(path: Path) -> bool:
    return path.name == "__init__.py"


def _imports(path: Path, mod: str) -> list[str]:
    """Absolute dotted names a module imports (every nesting), plus literal
    names handed to import_module / __import__."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    here = mod.split(".") if _is_package(path) else mod.split(".")[:-1]
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = here[: len(here) - (node.level - 1)]
                prefix = ".".join(base + ([node.module] if node.module else []))
            else:
                prefix = node.module or ""
            out.append(prefix)
            out += [f"{prefix}.{a.name}" for a in node.names if a.name != "*"]
        elif isinstance(node, ast.Call):
            fn = node.func
            name = getattr(fn, "attr", getattr(fn, "id", ""))
            if name in ("import_module", "__import__") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    out.append(arg.value)
    return out


def _closure() -> dict[str, list[str]]:
    """module -> the names it imports, for every willow_mcp module reachable
    from the seeds (and every module under install_steps/)."""
    todo = [f"{PKG}.{s}" for s in SEEDS]
    todo += [
        f"{PKG}.install_steps.{p.stem}"
        for p in (SRC / "install_steps").glob("*.py")
        if p.stem != "__init__"
    ]
    todo.append(f"{PKG}.install_steps")
    seen: dict[str, list[str]] = {}
    while todo:
        mod = todo.pop()
        if mod in seen:
            continue
        path = _file_for(mod)
        if path is None:
            continue
        names = _imports(path, mod)
        seen[mod] = names
        for n in names:
            # a name may be a module or a symbol of one: try the name, then its parent
            for cand in (n, n.rsplit(".", 1)[0]):
                if _file_for(cand) is not None:
                    todo.append(cand)
        # importing willow_mcp.a.b runs willow_mcp/__init__ and a/__init__
        parts = mod.split(".")
        for i in range(1, len(parts)):
            todo.append(".".join(parts[:i]))
    return seen


def test_every_seed_exists():
    missing = [s for s in SEEDS if _file_for(f"{PKG}.{s}") is None]
    assert not missing, f"the traced trust set names modules that are gone: {missing}"


def test_the_closure_is_not_trivially_small():
    # a broken walk would pass the real test by finding nothing.
    assert len(_closure()) >= len(SEEDS)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "OPEN, for the operator: F12 put scrub_reach (-> onescript_reach) into "
        "push_executor and secret_scan, and both sit in the lazy closure "
        "keyring -> net_signer -> unit_install_executor -> pull_executor -> "
        "push_executor, and -> unit_status -> secret_scan. Cut those edges or "
        "give the trust path a local scrub held by a parity test; strict, so "
        "the fix flips this to a pass and the marker must then be removed."
    ),
)
def test_no_trust_closure_module_imports_the_one_script():
    bad: dict[str, list[str]] = {}
    for mod, names in _closure().items():
        hit = [n for n in names if "onescript" in n.lower()]
        if hit:
            bad[mod] = hit
    assert not bad, (
        "trust-owner code (and what it imports) must not reach the one script: "
        f"{bad}"
    )
    # and no onescript_* module is itself inside the closure
    inside = [m for m in _closure() if "onescript" in m.rsplit(".", 1)[-1]]
    assert not inside, f"onescript_* module is on the trust path: {inside}"


def test_the_walk_catches_a_lazy_import(tmp_path):
    """The forbidden act: a function-local ``from . import onescript_reach``
    must be seen by the walk."""
    f = tmp_path / "m.py"
    f.write_text(
        "def f():\n    from . import onescript_reach\n"
        "    import importlib\n    importlib.import_module('willow_mcp.onescript_canon')\n"
    )
    names = _imports(f, f"{PKG}.m")
    assert f"{PKG}.onescript_reach" in names
    assert f"{PKG}.onescript_canon" in names
