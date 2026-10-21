"""hooks/ is a byte mirror of src/willow_mcp/bundle/hooks/, the packaged source.

The wheel ships the bundle tree; the repo-level hooks/ is the copy these tests
and tools/render_skills.py load by path. The mirror stays a standalone file
(not a thin import): hooks run by path under a bare interpreter, and
pre_tool_use.py resolves its config relative to its own location, so a wrapper
would change behaviour. Instead this one test pins every file in both trees
identical. Fix drift with `scripts/sync_repo_hooks.sh`.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "src/willow_mcp/bundle/hooks"
MIRROR = ROOT / "hooks"


def _py(d: Path) -> dict[str, Path]:
    return {p.name: p for p in d.glob("*.py")}


def test_repo_hooks_mirror_is_byte_identical_to_the_bundle():
    bundle, mirror = _py(BUNDLE), _py(MIRROR)
    assert bundle, "bundle hooks tree is empty"
    assert set(bundle) == set(mirror), "file sets differ; run scripts/sync_repo_hooks.sh"
    for name, path in bundle.items():
        assert path.read_bytes() == mirror[name].read_bytes(), (
            f"{name} differs between bundle/hooks and hooks/; run scripts/sync_repo_hooks.sh"
        )
