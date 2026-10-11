"""Broker pip_sync_execute — allowlisted editable install into a vault venv."""
from __future__ import annotations

import subprocess

import pytest

from willow_mcp import pip_sync_executor as psx
from willow_mcp import server


class _Ledger:
    def __init__(self):
        self.rows = []

    def append(self, project, event_type, content):
        rid = f"rec-{len(self.rows) + 1}"
        self.rows.append(
            {"id": rid, "project": project, "event_type": event_type, "content": content}
        )
        return rid


class _FakeRunner:
    """Routes git probes + pip install; records mutating argv."""

    def __init__(
        self,
        *,
        remote_url="https://github.com/hornbook-knowledge/Jeles.git",
        branch="master",
        dirty="",
        default_branch="master",
        pip_rc=0,
        pip_err="",
        version_before=None,
        version_after="1.2.3",
    ):
        self.remote_url = remote_url
        self.branch = branch
        self.dirty = dirty
        self.default_branch = default_branch
        self.pip_rc = pip_rc
        self.pip_err = pip_err
        self.version_before = version_before
        self.version_after = version_after
        self.calls: list[list[str]] = []
        self._pip_ran = False

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        cp = lambda rc, out="", err="": subprocess.CompletedProcess(argv, rc, out, err)  # noqa: E731

        # git -C <path> ...
        if len(argv) >= 3 and argv[0] == "git" and argv[1] == "-C":
            rest = argv[3:]
            if rest[:2] == ["remote", "get-url"]:
                return cp(0, self.remote_url + "\n")
            if rest[:2] == ["status", "--porcelain"]:
                return cp(0, self.dirty)
            if rest[:3] == ["rev-parse", "--abbrev-ref", "HEAD"]:
                return cp(0, self.branch + "\n")
            if rest[:2] == ["symbolic-ref", "--short"]:
                return cp(0, f"origin/{self.default_branch}\n")
            raise AssertionError(f"unexpected git {rest}")

        # python -m pip install ...
        if len(argv) >= 4 and argv[1:3] == ["-m", "pip"]:
            self._pip_ran = True
            return cp(self.pip_rc, "", "" if self.pip_rc == 0 else self.pip_err)

        # python -c importlib.metadata version
        if len(argv) >= 3 and argv[1] == "-c" and "importlib.metadata" in argv[2]:
            ver = self.version_after if self._pip_ran else self.version_before
            if ver is None:
                return cp(1, "", "PackageNotFoundError")
            return cp(0, ver + "\n")

        raise AssertionError(f"unexpected call {argv}")


ALLOWLIST = {
    "extras": ["connectors", "dev", "mcp", "nestor"],
    "pairs": {
        "hornbook-knowledge/Jeles": {"venv": "willow-mcp", "extras": ["connectors"]},
        "willow-memory/willow-bot": {"venv": "willow-bot", "extras": []},
    },
}


@pytest.fixture
def layout(tmp_path):
    github = tmp_path / "github"
    checkout = github / "hornbook-knowledge" / "Jeles"
    checkout.mkdir(parents=True)
    (checkout / ".git").mkdir()
    (checkout / "pyproject.toml").write_text(
        '[project]\nname = "jeles"\nversion = "0.0.0"\n', encoding="utf-8"
    )
    venvs = tmp_path / "venvs"
    venv = venvs / "willow-mcp"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    (venv / "bin" / "python").chmod(0o755)
    return {
        "github": github,
        "checkout": checkout,
        "venvs": venvs,
        "venv": venv,
    }


def _sync(layout, runner, ledger=None, **kw):
    args = dict(
        checkout=layout["checkout"],
        project="jeles",
        ledger=ledger,
        runner=runner,
        allowlist=ALLOWLIST,
        venvs_root=layout["venvs"],
        github_root=layout["github"],
    )
    args.update(kw)
    return psx.execute_pip_sync("willow", **args)


def test_happy_path_leaves_pip_sync_receipt(layout):
    runner, ledger = _FakeRunner(version_before="1.0.0", version_after="1.2.3"), _Ledger()
    out = _sync(layout, runner, ledger, extras=["connectors"])
    assert out["ok"] and out["synced"], out
    assert out["venv"] == "willow-mcp"
    assert out["extras"] == ["connectors"]
    assert out["before"] == "1.0.0" and out["after"] == "1.2.3"
    assert out["receipt_id"] == "rec-1"
    assert ledger.rows[0]["event_type"] == "pip_sync"
    pip_calls = [c for c in runner.calls if len(c) >= 3 and c[1:3] == ["-m", "pip"]]
    assert pip_calls and "-e" in pip_calls[0]
    assert any("connectors" in a for a in pip_calls[0])


def test_venv_inferred_from_allowlist_when_omitted(layout):
    out = _sync(layout, _FakeRunner(), venv="")
    assert out["ok"] and out["venv"] == "willow-mcp"


def test_wrong_venv_for_pair_is_enoallow(layout):
    out = _sync(layout, _FakeRunner(), venv="willow-bot")
    assert not out["ok"] and out["error"] == "ENOALLOW"


def test_unknown_extra_is_enoallow(layout):
    out = _sync(layout, _FakeRunner(), extras=["evil"])
    assert not out["ok"] and out["error"] == "ENOALLOW"


def test_dirty_tracked_tree_is_edirty(layout):
    out = _sync(layout, _FakeRunner(dirty=" M pyproject.toml\n"))
    assert not out["ok"] and out["error"] == "EDIRTY"


def test_feature_branch_is_ebranch(layout):
    out = _sync(layout, _FakeRunner(branch="feat/x", default_branch="master"))
    assert not out["ok"] and out["error"] == "EBRANCH"


def test_checkout_outside_github_root_is_enoallow(layout, tmp_path):
    other = tmp_path / "elsewhere" / "Jeles"
    other.mkdir(parents=True)
    (other / ".git").mkdir()
    (other / "pyproject.toml").write_text('[project]\nname = "jeles"\n', encoding="utf-8")
    out = _sync(layout, _FakeRunner(), checkout=other)
    assert not out["ok"] and out["error"] == "ENOALLOW"


def test_unknown_remote_is_enoallow(layout):
    out = _sync(
        layout,
        _FakeRunner(remote_url="https://github.com/other/thing.git"),
    )
    assert not out["ok"] and out["error"] == "ENOALLOW"


def test_pip_failure_leaves_failed_receipt(layout):
    runner, ledger = _FakeRunner(pip_rc=1, pip_err="Errno 30 Read-only file system"), _Ledger()
    out = _sync(layout, runner, ledger)
    assert not out["ok"] and out["error"] == "EINSTALL"
    assert ledger.rows[0]["event_type"] == "pip_sync_failed"
    assert "Errno 30" in out["reason"]


def test_missing_venv_is_evenv(layout):
    out = _sync(layout, _FakeRunner(), venvs_root=layout["venvs"] / "nope")
    # venvs_root itself missing → resolve fails
    bogus = layout["github"].parent / "empty_venvs"
    bogus.mkdir()
    out = _sync(layout, _FakeRunner(), venvs_root=bogus)
    assert not out["ok"] and out["error"] == "EVENV"


def test_tool_is_gated_on_own_name():
    catalogue = server._gate_tool_catalogue()
    assert catalogue["pip_sync_execute"] == "pip_sync_execute"
    from willow_mcp import gate
    assert "pip_sync_execute" in gate.PERMISSION_GROUPS["orchestrator"]
    assert "pip_sync_execute" in gate.PERMISSION_GROUPS["steward_sweep"]
    assert "pip_sync_execute" in gate.PERMISSION_GROUPS["full_access"]
    assert "pip_sync_execute" not in gate.PERMISSION_GROUPS["envelope_apply"]


# ── D2: the venv root is resolved by paths.resolve_venv, one root only ──────

def _mk_venv(root, name="willow-mcp"):
    py = root / name / "bin" / "python"
    py.parent.mkdir(parents=True)
    py.write_text("#!/bin/sh\n", encoding="utf-8")
    py.chmod(0o755)
    return root / name


def _d2_sync(layout, runner, new, old, **kw):
    return _sync(layout, runner, venvs_root=None, venv_roots=(new, old), **kw)


def test_d2_new_home_wins_and_installs_there(layout, tmp_path, caplog):
    new, old = tmp_path / "willow-bot" / "venvs", tmp_path / "venvs-old"
    chosen = _mk_venv(new)
    _mk_venv(old)
    runner = _FakeRunner(version_after="1.2.3")
    with caplog.at_level("WARNING"):
        out = _d2_sync(layout, runner, new, old)
    assert out["ok"], out
    installs = [c for c in runner.calls if "pip" in c and "install" in c]
    assert installs and installs[0][0] == str(chosen / "bin" / "python")
    assert not caplog.records


def test_d2_legacy_used_with_one_warning(layout, tmp_path, caplog):
    new, old = tmp_path / "willow-bot" / "venvs", tmp_path / "venvs-old"
    chosen = _mk_venv(old)
    runner = _FakeRunner(version_after="1.2.3")
    with caplog.at_level("WARNING"):
        out = _d2_sync(layout, runner, new, old)
    assert out["ok"], out
    installs = [c for c in runner.calls if "pip" in c and "install" in c]
    assert installs[0][0] == str(chosen / "bin" / "python")
    assert len(caplog.records) == 1 and str(new / "willow-mcp") in caplog.records[0].getMessage()


def test_d2_neither_home_is_evenv_naming_both(layout, tmp_path):
    new, old = tmp_path / "n", tmp_path / "o"
    new.mkdir()
    old.mkdir()
    out = _d2_sync(layout, _FakeRunner(), new, old)
    assert out["error"] == "EVENV"
    assert str(new / "willow-mcp") in out["reason"] and str(old / "willow-mcp") in out["reason"]


def test_d2_new_home_symlink_into_legacy_is_refused_never_both(layout, tmp_path):
    """Containment runs against the chosen root: a new-home name that is a
    symlink into the legacy root resolves outside it and is refused."""
    new, old = tmp_path / "willow-bot" / "venvs", tmp_path / "venvs-old"
    target = _mk_venv(old)
    new.mkdir(parents=True)
    (new / "willow-mcp").symlink_to(target)
    out = _d2_sync(layout, _FakeRunner(), new, old)
    assert out["error"] == "EVENV" and "outside" in out["reason"]
