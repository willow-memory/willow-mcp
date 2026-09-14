"""Render source skills/ into bundle/skills/ with `{{include}}` expansion.

The bundled copy of the skill markdown (`src/willow_mcp/bundle/skills/*.md`)
is what `plugin.json` ships to consumers. It used to be a byte-identical
mirror of `skills/*.md`, pinned by `tests/test_skills_sync.py`. That pin
kept the two copies aligned but did not stop LITERAL duplication *inside*
them: the Jeles federation server id `8cae3d1dcdf4`, the WEB_ORDER ladder,
and the GIT_PUSH_HINT push-broker sentence all appear in multiple skill
files, and would drift silently if any changed.

This module is the small preprocessor that lets a skill source reference
a value from `hooks/_constants.py` — the same module PR 1 extracted for
the hook reason strings — via a marker:

    {{include _constants.JELES_FEDERATION_SERVER}}

The marker's expansion is `str(getattr(constants, NAME))`. Anything not
matching the marker passes through unchanged.

Deliberately tight scope: constants only. No `.md#anchor` cross-file
includes, no template globals, no Jinja. If you want a preprocessor with
more surface, write a different one.

## CLI

    python3 tools/render_skills.py           # write bundle/skills/*.md
    python3 tools/render_skills.py --check   # exit 1 on drift; name the file(s)
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_SOURCE_DIR = _REPO / "skills"
_BUNDLE_DIR = _REPO / "src" / "willow_mcp" / "bundle" / "skills"
_CONSTANTS_PATH = _REPO / "hooks" / "_constants.py"

#: Marker shape: {{include _constants.NAME}} where NAME is [A-Z_][A-Z0-9_]*.
_INCLUDE_RE = re.compile(r"\{\{\s*include\s+_constants\.([A-Z_][A-Z0-9_]*)\s*\}\}")


def _load_constants():
    """Import hooks/_constants.py by path, without polluting sys.path.

    `hooks/` is not a package (no __init__.py needed for hook file
    discovery), so a plain `import hooks._constants` won't work from
    every entry point. Loading by spec sidesteps the packaging question.
    """
    spec = importlib.util.spec_from_file_location("willow_mcp_render_skills_constants", _CONSTANTS_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"render_skills: cannot load {_CONSTANTS_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render(source_text: str, constants=None) -> str:
    """Expand `{{include _constants.NAME}}` markers in `source_text`.

    An unknown constant name raises `KeyError` with the offending name so a
    typo fails loud rather than silently rendering an empty string.
    """
    constants = constants or _load_constants()

    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        if not hasattr(constants, name):
            raise KeyError(
                f"render_skills: {_CONSTANTS_PATH.name} has no constant {name!r} referenced by an include marker"
            )
        return str(getattr(constants, name))

    return _INCLUDE_RE.sub(_sub, source_text)


def _pairs() -> list[tuple[Path, Path]]:
    """(source, bundle) file pairs for every .md in the source dir.

    Errors on missing bundle counterparts and vice versa — the tree
    should have one bundle twin per source, always. `test_skills_sync.py`
    also enforces this.
    """
    source_files = {p.name: p for p in _SOURCE_DIR.glob("*.md")}
    bundle_files = {p.name: p for p in _BUNDLE_DIR.glob("*.md")}
    source_only = sorted(set(source_files) - set(bundle_files))
    bundle_only = sorted(set(bundle_files) - set(source_files))
    if source_only:
        raise RuntimeError(f"render_skills: no bundle twin for {source_only}")
    if bundle_only:
        raise RuntimeError(f"render_skills: no source for {bundle_only}")
    return [(source_files[name], bundle_files[name]) for name in sorted(source_files)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 on drift between source render and bundle on disk",
    )
    args = parser.parse_args()

    constants = _load_constants()
    drift: list[str] = []
    for source_path, bundle_path in _pairs():
        rendered = render(source_path.read_text(encoding="utf-8"), constants)
        on_disk = bundle_path.read_text(encoding="utf-8")
        if rendered == on_disk:
            continue
        if args.check:
            drift.append(bundle_path.relative_to(_REPO).as_posix())
            continue
        bundle_path.write_text(rendered, encoding="utf-8")

    if args.check:
        if drift:
            print(
                "render_skills --check: bundle drifted from render(source):\n  - "
                + "\n  - ".join(drift)
                + "\nRe-run: python3 tools/render_skills.py",
                file=sys.stderr,
            )
            return 1
        print("render_skills --check: ok")
        return 0
    print(f"render_skills: rendered {len(_pairs())} skill file(s) → {_BUNDLE_DIR.relative_to(_REPO).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
