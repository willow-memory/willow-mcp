"""B-65 — WILLOW_ROOT must be read-only inside the Kart sandbox.

B-14 overlaid `mcp_apps/` read-only and B-33 overlaid the consent kill switch,
but neither covered the *code that reads them*: WILLOW_ROOT was bound
read-write, so a sandboxed task could edit `gate.py` — the manifest ACL that
decides what every app may do — along with `pyproject.toml`, `.git` and `.venv`.
Kartikeya 0.0.12 binds WILLOW_ROOT read-only and makes
``{WILLOW_ROOT}/worktrees`` the writable lane.

This pins the contract from willow-mcp's side, the way
`test_b33_consent_sandbox.py` does for B-33, so a kartikeya regression or a
config edit cannot reopen the sandbox lane silently. The pin in pyproject.toml
is the floor; this is the check that the floor delivered what it promises.
"""

from __future__ import annotations

import pytest

pytest.importorskip("kartikeya")

from kartikeya import sandbox


@pytest.fixture
def repo(tmp_path):
    """A tree that kartikeya recognises as a willow-mcp checkout."""
    root = tmp_path / "willow-mcp"
    (root / "src" / "willow_mcp").mkdir(parents=True)
    (root / "src" / "willow_mcp" / "gate.py").write_text("# the manifest ACL\n")
    (root / "pyproject.toml").write_text("[project]\nname = 'willow-mcp'\n")
    return root


def _modes(root):
    return {str(host): read_only for host, _container, read_only in
            sandbox.collect_bind_mounts(root)}


def test_kartikeya_floor_ships_the_work_root(repo):
    # The pin (kartikeya>=0.0.12) is load-bearing: on an older kartikeya the
    # writable lane is never created, and every task fails with what reads like
    # a permissions bug. Fail loudly here rather than at 3am in a task.
    assert hasattr(sandbox, "ensure_work_root"), (
        "installed kartikeya predates 0.0.12 — WILLOW_ROOT read-only has no "
        "work root to go with it; raise the floor in pyproject.toml"
    )


def test_willow_root_is_read_only(repo, monkeypatch):
    monkeypatch.setenv("WILLOW_ROOT", str(repo))
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    assert _modes(repo)[str(repo)] is True, (
        "WILLOW_ROOT is bound read-write — a sandboxed task can edit gate.py"
    )


def test_work_root_is_the_writable_lane(repo, monkeypatch):
    monkeypatch.setenv("WILLOW_ROOT", str(repo))
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    modes = _modes(repo)
    assert modes[str(repo / "worktrees")] is False, "the work root must be writable"
    # And it exists: a bind target that does not exist is dropped, not created,
    # and nothing inside a read-only root can make it.
    assert (repo / "worktrees").is_dir()


def test_the_product_code_is_not_writable(repo, monkeypatch):
    # The specific files measured writable on a live box, 2026-09-02.
    monkeypatch.setenv("WILLOW_ROOT", str(repo))
    monkeypatch.delenv("KART_SANDBOX_CONFIG", raising=False)
    modes = _modes(repo)
    writable = {p for p, ro in modes.items() if not ro}
    for path in (repo / "src" / "willow_mcp" / "gate.py",
                 repo / "pyproject.toml",
                 repo / "src"):
        assert str(path) not in writable, f"{path} is writable inside the sandbox"
        # and no writable ancestor other than the work root covers it
        covering = [w for w in writable
                    if str(path).startswith(w.rstrip("/") + "/")]
        assert not covering, f"{path} is covered by writable bind(s): {covering}"
