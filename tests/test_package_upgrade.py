"""The brokered package upgrade (verb 25 `package.upgrade`, UNSEALED — see
syscall-table.json row 25's own note and tests/test_syscall_row_25_package_upgrade.py
for the bounds-signature proof).

Rework 3 (dispatch C2EB023A, closing Loki's re-check 3CBE8D7E — R1, R2,
R3): everything the broker verifies, installs, or restores from lives
under a broker-private directory (`_private_root`, `$WILLOW_HOME/
package_upgrade/<sha>/` in production, injectable via `private_root` in
tests) that Kart cannot see. The sha is resolved from origin via
`git ls-remote` against the clone's own remote URL, never from the local
clone's Kart-writable `refs/tags/*`, and reachability is checked against a
broker-private bare mirror fetched from origin — the local clone is used
only to read its own remote URL. Rollback only ever acts on a COMPLETE
backup manifest (`_load_backup_manifest`/`_write_backup_manifest`); no
manifest means no-op, never a destructive guess. Every act-phase exception
is caught by a final `except Exception`, rolled back through the same
manifest-guarded path, and cited with the exception's own type recorded.

No real venv, build python, or network is ever touched — every git/python/
pip/systemctl call goes through a fake runner, `run_kart_build` and
`verify_wheel_against_source` are monkeypatched for the "happy path" tests
(each has its OWN dedicated, unmocked test elsewhere), and the backup/
rollback tests exercise real filesystem copies (and a real, minimal wheel
zip) under tmp_path only.
"""
from __future__ import annotations

import json
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from willow_mcp import package_upgrade_executor as pux
from willow_mcp import server as server_mod

# ── a fake frank ledger, same shape as test_unit_install.py ──────────────────

class _FakeGovernancePg:
    def __init__(self):
        self.rows = []

    def cursor(self):
        return _FakeGovernanceCursor(self)

    def commit(self):
        pass


class _FakeGovernanceCursor:
    def __init__(self, pg):
        self.pg = pg
        self._result = []

    def execute(self, sql, params=None):
        params = params or ()
        s = sql.strip()
        if "pg_advisory" in s:
            return
        if s.startswith("SELECT COUNT(*)"):
            envelope_id = params[0]
            self._result = [(sum(
                1 for r in self.pg.rows
                if r["event_type"] == "envelope_citation"
                and r["content"].get("envelope_id") == envelope_id
                and r["content"].get("outcome") == "granted"
            ),)]
            return
        if s.startswith("SELECT hash FROM"):
            self._result = [(self.pg.rows[-1]["hash"],)] if self.pg.rows else []
            return
        if s.startswith("SELECT id, content, created_at FROM"):
            event_type = params[0]
            matches = [r for r in self.pg.rows if r["event_type"] == event_type]
            self._result = [(r["id"], r["content"], r.get("created_at")) for r in matches]
            return
        if s.startswith("INSERT INTO"):
            record_id, project, event_type, content, prev_hash, digest = params
            self.pg.rows.append({
                "id": record_id, "project": project, "event_type": event_type,
                "content": getattr(content, "adapted", content),
                "prev_hash": prev_hash, "hash": digest,
                "created_at": datetime.now(UTC),
            })
            return
        raise AssertionError(f"unexpected SQL: {sql!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result

    def close(self):
        pass


def _ledger(pg):
    from willow_mcp.governance_ledger import GovernanceLedger
    return GovernanceLedger(pg)


def _receipts(pg, event=pux.EVENT):
    return [r for r in pg.rows if r["event_type"] == event]


def _granted_citations(pg, envelope_id):
    return [
        r for r in pg.rows
        if r["event_type"] == "envelope_citation"
        and r["content"].get("envelope_id") == envelope_id
        and r["content"].get("outcome") == "granted"
    ]


# ── registry with one package.upgrade grant ──────────────────────────────────

REPO = "willow-memory/kartikeya"
TAG = "v0.3.4"
VENV = "willow-mcp"
PKG = "kartikeya"
TAG_SHA = "deadbeef1234"


def _charter(tmp_path, monkeypatch, *, grantee="hanuman", repo=REPO, tags=(TAG,),
             venv=VENV, extra=None, expires="2027-01-01", max_count=None):
    active = [{
        "id": "env-package.upgrade-test",
        "verb_id": 25,
        "verb": "package.upgrade",
        "grantee": grantee,
        "bounds": {"repo": repo, "tags": list(tags), "venv": venv},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": expires,
        "max_count": max_count,
        "use_count_source": "frank",
        "status": "active",
    }] + list(extra or [])
    table = {"verbs": [{"id": 25, "verb": "package.upgrade",
                        "bounds": {"repo": "r", "tags": "l", "venv": "v"}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))


class _NeverRun:
    def __call__(self, argv, **kw):
        raise AssertionError(f"unexpected call — refusal should precede it: {argv}")


@pytest.fixture
def github_root(tmp_path):
    clone = tmp_path / "gh" / "willow-memory" / "kartikeya"
    (clone / ".git").mkdir(parents=True)
    return tmp_path / "gh"


@pytest.fixture
def venvs_root(tmp_path):
    root = tmp_path / "venvs"
    venv = root / VENV
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n")
    return root


def _write_dist(site: Path, name: str, version: str, marker: str):
    pkg_dir = site / name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "VERSION").write_text(marker, encoding="utf-8")
    dist = site / f"{name}-{version}.dist-info"
    dist.mkdir(exist_ok=True)
    (dist / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n", encoding="utf-8")


def _make_wheel(path: Path, name: str, version: str, scripts=None, *,
                 pure=True, extra_files=None, pth=False, record=True) -> Path:
    """A real, minimal wheel zip — good enough for the wheel_* readers and
    verify_wheel_against_source to read for real, no mocking."""
    dist_info = f"{name}-{version}.dist-info"
    scripts = scripts or {}
    members: dict[str, str] = {}
    members[f"{dist_info}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    purelib = "true" if pure else "false"
    tag = "py3-none-any" if pure else "cp312-cp312-linux_x86_64"
    members[f"{dist_info}/WHEEL"] = f"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: {purelib}\nTag: {tag}\n"
    if scripts:
        body = "[console_scripts]\n" + "\n".join(f"{k} = {v}" for k, v in scripts.items()) + "\n"
        members[f"{dist_info}/entry_points.txt"] = body
    init_rel = f"{name}/__init__.py"
    extra_files = dict(extra_files or {})
    if init_rel not in extra_files:
        members[init_rel] = ""
    members.update(extra_files)
    if record:
        record_lines = "\n".join(f"{p},," for p in members) + f"\n{dist_info}/RECORD,,\n"
        members[f"{dist_info}/RECORD"] = record_lines
    with zipfile.ZipFile(path, "w") as zf:
        for rel, content in members.items():
            zf.writestr(rel, content)
        if pth:
            zf.writestr(f"{name}-injected.pth", "/tmp\n")
    return path


def _real_wheel_name(name: str, version: str) -> str:
    return f"{name}-{version}-py3-none-any.whl"


def _standard_git_runner(*, tag_sha=TAG_SHA, default_branch="master",
                          ancestor_ok=True, symlinks="", pyproject=None, extra=None,
                          local_tag_sha=None, tag_on_origin=True, repo=REPO):
    pyproject = pyproject or '[project]\ndependencies = []\n\n[build-system]\nrequires = ["hatchling"]\n'
    local_tag_sha = tag_sha if local_tag_sha is None else local_tag_sha
    remote_url = f"https://github.com/{repo}.git\n"

    def runner(argv, **kw):
        if argv[0] == "git":
            rest = argv[3:]
            if rest[:2] == ["remote", "get-url"]:
                return subprocess.CompletedProcess(argv, 0, remote_url, "")
            if rest[:1] == ["ls-remote"]:
                if not tag_on_origin and "--symref" not in rest:
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if "--symref" in rest:
                    return subprocess.CompletedProcess(
                        argv, 0, f"ref: refs/heads/{default_branch}\tHEAD\n{tag_sha}\tHEAD\n", "")
                return subprocess.CompletedProcess(argv, 0, f"{tag_sha}\trefs/tags/{TAG}\n", "")
            if rest[:2] == ["init", "--bare"]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if rest[:1] == ["fetch"]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if rest == ["rev-parse", "--abbrev-ref", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, "master\n", "")
            if rest == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
            if rest == ["branch", "-r", "--contains", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, "  origin/master\n", "")
            if rest[:2] == ["rev-parse", "--verify"] and "refs/tags" in " ".join(rest):
                if local_tag_sha is None:
                    return subprocess.CompletedProcess(argv, 1, "", "fatal: no such ref")
                return subprocess.CompletedProcess(argv, 0, f"{local_tag_sha}\n", "")
            if rest[:2] == ["rev-parse", "--verify"]:
                return subprocess.CompletedProcess(argv, 0, f"{tag_sha}\n", "")
            if rest[:2] == ["symbolic-ref", "--short"]:
                return subprocess.CompletedProcess(argv, 0, f"origin/{default_branch}\n", "")
            if rest[:2] == ["merge-base", "--is-ancestor"]:
                return subprocess.CompletedProcess(argv, 0 if ancestor_ok else 1, "", "")
            if rest[:2] == ["ls-tree", "-r"]:
                return subprocess.CompletedProcess(argv, 0, symlinks, "")
            if rest[:1] == ["show"]:
                return subprocess.CompletedProcess(argv, 0, pyproject, "")
            if rest[:1] == ["archive"]:
                Path(argv[-1]).write_bytes(b"fake-archive")
                return subprocess.CompletedProcess(argv, 0, "", "")
            if extra is not None:
                hit = extra(argv, rest)
                if hit is not None:
                    return hit
            raise AssertionError(f"unexpected git call {rest}")
        if argv[0] == "tar":
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "systemctl" and argv[2] == "show" and "--value" in argv:
            return subprocess.CompletedProcess(argv, 0, "/no/such/venv/bin/python\n", "")
        if str(argv[0]).endswith("python") and argv[1:2] == ["-c"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected call {argv}")
    return runner


def _patch_kart_build(monkeypatch, wheel_path: Path, *, task_id="FAKE1"):
    """The N1/N2 seam every 'happy path' / rollback / reload test decouples
    from: a fake but real build result, and a real-shaped verify result."""
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    monkeypatch.setattr(server_mod, "_lane_running_task_ids", lambda app_id, agent, lane: [])

    def fake_run_kart_build(app_id, src_dir, wheel_dir, *, version, import_names, lane,
                             submit_fn=None, status_fn=None, sleeper=None, timeout=None):
        Path(wheel_dir).mkdir(parents=True, exist_ok=True)
        dest = Path(wheel_dir) / wheel_path.name
        if not dest.exists():
            import shutil as _sh
            _sh.copy2(wheel_path, dest)
        return {"ok": True, "wheel": dest, "task_id": task_id}

    monkeypatch.setattr(pux, "run_kart_build", fake_run_kart_build)
    monkeypatch.setattr(
        pux, "verify_wheel_against_source",
        lambda wheel, src_dir, *, package, version, declared_scripts, package_roots=None:
            {"ok": True, "sha256": pux.wheel_sha256(wheel)},
    )


def _upgrade(pg, *, runner, github_root, venvs_root, tmp_path, **kw):
    return pux.execute_package_upgrade(
        "hanuman", repo=REPO, tag=TAG, venv=VENV, project="willow-mcp",
        ledger=_ledger(pg), runner=runner, github_root=github_root, venvs_root=venvs_root,
        private_root=tmp_path / "private", **kw,
    )


# ── EINVAL — malformed input, before any call ─────────────────────────────────

@pytest.mark.parametrize("repo,tag,venv", [
    ("not-a-repo", TAG, VENV),
    ("", TAG, VENV),
    (REPO, "", VENV),
    (REPO, TAG, ""),
])
def test_einval_refuses_before_any_call(home, tmp_path, monkeypatch, repo, tag, venv):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = pux.execute_package_upgrade(
        "hanuman", repo=repo, tag=tag, venv=venv, project="willow-mcp",
        ledger=_ledger(pg), runner=_NeverRun(),
    )
    assert out["ok"] is False and out["error"] == "EINVAL", out


# ── ENOSRC — clone / origin sha resolution / symlink ──────────────────────────

def test_enosrc_when_no_verified_clone(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    empty_root = tmp_path / "gh-empty"
    empty_root.mkdir()
    out = pux.execute_package_upgrade(
        "hanuman", repo=REPO, tag=TAG, venv=VENV, project="willow-mcp",
        ledger=_ledger(pg), runner=_NeverRun(), github_root=empty_root,
    )
    assert out["ok"] is False and out["error"] == "ENOSRC", out


def test_enosrc_when_tag_missing_on_origin(home, tmp_path, monkeypatch, github_root):
    """R1: the sha comes from origin's ls-remote, not the local clone."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    runner = _standard_git_runner(tag_on_origin=False)
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=None, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "ENOSRC", out
    assert "origin" in out["reason"]


def test_enosrc_when_local_tag_disagrees_with_origin(home, tmp_path, monkeypatch, github_root, venvs_root):
    """R1: origin governs, but a disagreeing LOCAL tag is refused rather
    than silently overridden."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    runner = _standard_git_runner(tag_sha="originsha000", local_tag_sha="localsha000000")
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "ENOSRC", out
    assert "disagrees" in out["reason"]


def test_enosrc_when_tag_not_reachable_from_default_branch(home, tmp_path, monkeypatch, github_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    runner = _standard_git_runner(ancestor_ok=False)
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=None, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "ENOSRC", out
    assert "does not point at a commit reachable" in out["reason"]


def test_enosrc_when_tree_contains_a_symlink(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    runner = _standard_git_runner(symlinks="120000 blob abc123\tevil-link\n100644 blob def456\tpyproject.toml\n")
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "ENOSRC", out
    assert out["symlinks"] == ["evil-link"]


# ── EVENV ──────────────────────────────────────────────────────────────────────

def test_evenv_when_venv_missing(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch, venv="does-not-exist")
    pg = _FakeGovernancePg()
    runner = _standard_git_runner()
    out = pux.execute_package_upgrade(
        "hanuman", repo=REPO, tag=TAG, venv="does-not-exist", project="willow-mcp",
        ledger=_ledger(pg), runner=runner, github_root=github_root, venvs_root=venvs_root,
        private_root=tmp_path / "private",
    )
    assert out["ok"] is False and out["error"] == "EVENV", out


def test_evenv_refuses_path_traversal():
    root = Path("/tmp/does-not-need-to-exist-venvs-root")
    out = pux._resolve_venv("../escape", venvs_root=root)
    assert out["ok"] is False and out["error"] == "EVENV", out


def test_evenv_refuses_a_symlinked_venv_escaping_containment(tmp_path):
    venvs_root = tmp_path / "venvs"
    venvs_root.mkdir()
    outside = tmp_path / "outside"
    (outside / "bin").mkdir(parents=True)
    (outside / "bin" / "python").write_text("#!/bin/sh\n")
    escape = venvs_root / "escape"
    escape.symlink_to(outside, target_is_directory=True)
    out = pux._resolve_venv("escape", venvs_root=venvs_root)
    assert out["ok"] is False and out["error"] == "EVENV", out


# ── EPERM ──────────────────────────────────────────────────────────────────────

def test_eperm_when_venv_not_writable(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(pux.os, "access", lambda path, mode: False)
    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "EPERM", out
    assert "owner_uid" in out


# ── ENOIMPORTERS ───────────────────────────────────────────────────────────────

def test_enoimporters_when_package_has_no_importer_row(home, tmp_path, monkeypatch, venvs_root):
    clone = tmp_path / "gh" / "willow-memory" / "unknown-pkg"
    (clone / ".git").mkdir(parents=True)
    github_root_local = tmp_path / "gh"
    _charter(tmp_path, monkeypatch, repo="willow-memory/unknown-pkg")
    pg = _FakeGovernancePg()
    runner = _standard_git_runner(repo="willow-memory/unknown-pkg")
    out = pux.execute_package_upgrade(
        "hanuman", repo="willow-memory/unknown-pkg", tag=TAG, venv=VENV, project="willow-mcp",
        ledger=_ledger(pg), runner=runner, github_root=github_root_local, venvs_root=venvs_root,
        private_root=tmp_path / "private",
    )
    assert out["ok"] is False and out["error"] == "ENOIMPORTERS", out


# ── EDEPS ────────────────────────────────────────────────────────────────────

def test_edeps_when_declared_dependency_unsatisfied(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    runner = _standard_git_runner(pyproject='[project]\ndependencies = ["psutil"]\n\n[build-system]\nrequires = ["hatchling"]\n')

    def wrapped(argv, **kw):
        if str(argv[0]).endswith("python") and argv[1:2] == ["-c"]:
            return subprocess.CompletedProcess(argv, 1, "", "ModuleNotFoundError")
        return runner(argv, **kw)

    out = _upgrade(pg, runner=wrapped, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "EDEPS", out
    assert out["missing"] == ["psutil"]


# ── EBUILD — N2: static requirement/candidate checks, no execution ───────────

def test_ebuild_when_requirement_unrecognised(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    runner = _standard_git_runner(pyproject='[project]\ndependencies = []\n\n[build-system]\nrequires = ["some-unknown-backend"]\n')
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert out["requirement"] == "some-unknown-backend"


def test_ebuild_when_no_build_python_configured(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    monkeypatch.delenv("WILLOW_PACKAGE_BUILD_PYTHON", raising=False)
    monkeypatch.delenv("WILLOW_PACKAGE_BUILD_PYTHONS", raising=False)
    assert pux._build_python_candidates() == []
    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert "WILLOW_PACKAGE_BUILD_PYTHON" in out["reason"]


def test_ebuild_when_kart_build_task_fails(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    monkeypatch.setattr(server_mod, "_lane_running_task_ids", lambda a, b, c: [])

    def failing_run_kart_build(app_id, src_dir, wheel_dir, *, version, import_names, lane,
                                submit_fn=None, status_fn=None, sleeper=None, timeout=None):
        return {"ok": False, "error": "EBUILD", "upgraded": False,
                "reason": "Kart build task ABC failed: no backend importable", "task_id": "ABC"}

    monkeypatch.setattr(pux, "run_kart_build", failing_run_kart_build)
    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work")
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert out["citation_id"], "act-phase failure must be CITED (N3)"
    assert out["build_task_id"] == "ABC"
    assert _receipts(pg, f"{pux.EVENT}_act_failed")


# ── run_kart_build — the N1 submit-and-await seam, unit tested directly ──────

def test_run_kart_build_refuses_on_non_dict_status(tmp_path):
    """R3/3CBE8D7E P3: a non-dict task_status result is now refused by name
    inside run_kart_build itself, never left to raise AttributeError."""
    def submit_fn(**kw):
        return {"task_id": "T1"}

    def status_fn(app_id, task_id):
        return "not-a-dict"

    out = pux.run_kart_build(
        "hanuman", tmp_path / "src", tmp_path / "wheel", version="0.4.0",
        import_names=["hatchling"], submit_fn=submit_fn, status_fn=status_fn,
        sleeper=lambda s: None, timeout=10, poll_interval=1,
    )
    assert out["ok"] is False and out["error"] == "EBUILD"
    assert "non-dict" in out["reason"]


def test_run_kart_build_times_out():
    def submit_fn(**kw):
        return {"task_id": "SLOW1"}

    def status_fn(app_id, task_id):
        return {"status": "running"}

    slept = []
    out = pux.run_kart_build(
        "hanuman", Path("/src"), Path("/wheel"), version="0.4.0",
        import_names=["hatchling"], submit_fn=submit_fn, status_fn=status_fn,
        sleeper=lambda s: slept.append(s), timeout=3, poll_interval=1,
    )
    assert out["ok"] is False and out["error"] == "ETIMEDOUT"
    assert len(slept) == 3


def test_build_task_script_uses_scrubbed_env_not_os_environ():
    """3CBE8D7E M35: the picked interpreter and pip must see ONLY the
    hard-coded scrub dict, never os.environ."""
    text = pux._build_task_script(
        Path("/src"), Path("/wheel"), version="1.2.3",
        candidates=["/a/python3"], import_names=["hatchling"],
    )
    assert "env=os.environ" not in text
    assert "**os.environ" not in text
    assert "env = dict(scrub)" in text


# ── EBUILDROOT ─────────────────────────────────────────────────────────────

def test_ebuildroot_when_no_scratch_root_and_no_work_dir(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    monkeypatch.setattr(pux, "_default_build_scratch_root", lambda: None)
    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "EBUILDROOT", out


# ── verify_wheel_against_source — N2/3CBE8D7E, dedicated and unmocked ───────

def test_verify_wheel_ok_when_byte_identical(tmp_path):
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, PKG, "0.4.0", scripts={"kartikeya": "kartikeya.cli:main"})
    out = pux.verify_wheel_against_source(
        wheel, src, package=PKG, version="0.4.0",
        declared_scripts={"kartikeya": "kartikeya.cli:main"},
    )
    assert out["ok"] is True, out
    assert out["sha256"] == pux.wheel_sha256(wheel)


def test_verify_wheel_enotpure_refuses_a_platform_wheel(tmp_path):
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    wheel = tmp_path / f"{PKG}-0.4.0-cp312-cp312-linux_x86_64.whl"
    _make_wheel(wheel, PKG, "0.4.0", pure=False)
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "ENOTPURE", out


def test_verify_wheel_everify_on_version_mismatch(tmp_path):
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, PKG, "0.4.0")
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="9.9.9", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EVERIFY", out


def test_verify_wheel_everify_on_name_mismatch(tmp_path):
    """3CBE8D7E M32."""
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, "totally-different-name", "0.4.0")
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EVERIFY", out
    assert "METADATA name" in out["reason"]


def test_verify_wheel_ebuild_on_pth_file(tmp_path):
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, PKG, "0.4.0", pth=True)
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert "pth_files" in out


def test_verify_wheel_ebuild_on_repo_root_file_outside_package_roots(tmp_path):
    """3CBE8D7E gap: a byte-identical repo-root file (tests/*.py) must NOT
    match just because the bytes happen to agree — it is outside every
    declared package root."""
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    (src / "tests").mkdir(parents=True)
    (src / "tests" / "test_x.py").write_text("SHARED = 1\n", encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, PKG, "0.4.0", extra_files={"tests/test_x.py": "SHARED = 1\n"})
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert "tests/test_x.py" in out["extra"]


def test_verify_wheel_everify_on_omitted_module(tmp_path):
    """3CBE8D7E gap: a source module missing from the wheel must refuse,
    not silently pass because wheel-to-source found nothing to complain
    about."""
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    (src / PKG / "extra_module.py").write_text("X = 1\n", encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, PKG, "0.4.0")  # only __init__.py
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EVERIFY", out
    assert f"{PKG}/extra_module.py" in out["omitted"]


def test_verify_wheel_ebuild_on_console_script_target_mismatch(tmp_path):
    """3CBE8D7E: the entry-point TARGET must match, not just the name."""
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, PKG, "0.4.0", scripts={"kart": "kartikeya.evil:main"})
    out = pux.verify_wheel_against_source(
        wheel, src, package=PKG, version="0.4.0",
        declared_scripts={"kart": "kartikeya.worker:main"},
    )
    assert out["ok"] is False and out["error"] == "EBUILD", out


def test_verify_wheel_ebuild_on_gui_scripts_group(tmp_path):
    """3CBE8D7E: gui_scripts (or any group besides console_scripts) is
    refused outright."""
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    dist_info = f"{PKG}-0.4.0.dist-info"
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(f"{dist_info}/METADATA", f"Metadata-Version: 2.1\nName: {PKG}\nVersion: 0.4.0\n")
        zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        zf.writestr(f"{dist_info}/entry_points.txt", "[gui_scripts]\nkart-gui = kartikeya.gui:main\n")
        zf.writestr(f"{PKG}/__init__.py", "")
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert "gui_scripts" in str(out.get("extra_groups"))


def test_verify_wheel_ebuild_on_traversal_path(tmp_path):
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    dist_info = f"{PKG}-0.4.0.dist-info"
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(f"{dist_info}/METADATA", f"Metadata-Version: 2.1\nName: {PKG}\nVersion: 0.4.0\n")
        zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        zf.writestr(f"{PKG}/__init__.py", "")
        zf.writestr(f"{PKG}/../../etc/evil.py", "evil\n")
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert "traversal" in out


def test_verify_wheel_ebuild_on_record_mismatch(tmp_path):
    """3CBE8D7E: RECORD must match the wheel's actual contents."""
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    dist_info = f"{PKG}-0.4.0.dist-info"
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(f"{dist_info}/METADATA", f"Metadata-Version: 2.1\nName: {PKG}\nVersion: 0.4.0\n")
        zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        zf.writestr(f"{PKG}/__init__.py", "")
        zf.writestr(f"{dist_info}/RECORD", f"{PKG}/__init__.py,,\n{PKG}/phantom_not_in_wheel.py,,\n")
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert f"{PKG}/phantom_not_in_wheel.py" in out["extra_in_record"]


# ── F8d — EBUSY before any restart, preflight-class ───────────────────────────

def test_ebusy_refuses_when_the_units_own_lane_is_running(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    monkeypatch.setattr(server_mod, "_lane_running_task_ids",
                         lambda app_id, agent, lane: ["OTHERTASK"] if lane == "fast" else [])
    git_runner = _standard_git_runner()

    def runner(argv, **kw):
        if argv[0] == "systemctl" and argv[2] == "show" and "--value" in argv:
            return subprocess.CompletedProcess(argv, 0, str(venvs_root / VENV) + "\n", "")
        return git_runner(argv, **kw)

    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "EBUSY", out
    assert _granted_citations(pg, "env-package.upgrade-test") == []


def test_lane_busy_refusal_fails_closed_when_queue_unreadable(monkeypatch):
    monkeypatch.setattr(server_mod, "_lane_running_task_ids", lambda app_id, agent, lane: None)
    out = pux._lane_busy_refusal("hanuman", "fast")
    assert out["ok"] is False and out["error"] == "EBUSY"


# ── offline invariants ────────────────────────────────────────────────────────

def test_pip_install_is_offline():
    argv = pux.pip_install_offline_argv(Path("/v/bin/python"), Path("/tmp/x.whl"))
    assert "--no-index" in argv
    assert "--no-deps" in argv
    assert "--isolated" in argv


def test_install_env_is_scrubbed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-appear")
    monkeypatch.setenv("NESTOR_SEAL_KEY", "also-should-not-appear")
    env = pux.scrubbed_install_env()
    assert "ANTHROPIC_API_KEY" not in env
    assert "NESTOR_SEAL_KEY" not in env
    assert env.get("PIP_CONFIG_FILE") == "/dev/null"


def test_private_root_is_a_named_child_of_willow_home(monkeypatch, tmp_path):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    p = pux._private_root("deadbeef")
    assert p == tmp_path / "package_upgrade" / "deadbeef"


# ── no citation is ever spent by a preflight refusal ──────────────────────────

def test_preflight_refusal_leaves_no_granted_citation(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    runner = _standard_git_runner(pyproject='[project]\ndependencies = ["psutil"]\n\n[build-system]\nrequires = ["hatchling"]\n')

    def wrapped(argv, **kw):
        if str(argv[0]).endswith("python") and argv[1:2] == ["-c"]:
            return subprocess.CompletedProcess(argv, 1, "", "ModuleNotFoundError")
        return runner(argv, **kw)

    out = _upgrade(pg, runner=wrapped, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path)
    assert out["ok"] is False and out["error"] == "EDEPS"
    assert _granted_citations(pg, "env-package.upgrade-test") == []


# ── citation failure happens before any mutation ──────────────────────────────

def test_citation_failure_refuses_before_any_mutation(home, tmp_path, monkeypatch, github_root, venvs_root):
    import willow_mcp.envelopes as envelopes_mod

    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    calls = {"check": 0, "cite": 0}

    class _FakeAuthority:
        def __init__(self, ledger):
            pass

        def check(self, *a, **kw):
            calls["check"] += 1
            return {"ok": True}

        def authorize_and_cite(self, *a, **kw):
            calls["cite"] += 1
            return {"ok": False, "errno": "EDQUOT", "reason": "race on max_count", "citation_id": None}

    monkeypatch.setattr(envelopes_mod, "EnvelopeAuthority", _FakeAuthority)
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work")
    assert calls["check"] == 1 and calls["cite"] == 1
    assert out["ok"] is False
    assert out["error"] == "EDQUOT"
    assert out["upgraded"] is False
    assert _granted_citations(pg, "env-package.upgrade-test") == []


# ── granted: full install + verify + reload ───────────────────────────────────

def test_granted_upgrade_installs_verifies_and_restarts(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()

    wheel_path = tmp_path / "prebuilt" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4", scripts={"kartikeya": "kartikeya.cli:main"})
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_pip_install_wheel", lambda python, wheel, *, runner:
                         subprocess.CompletedProcess([], 0, "", ""))

    versions = iter(["0.3.2", "0.3.4"])
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: next(versions))
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: None)

    git_runner = _standard_git_runner()

    def runner(argv, **kw):
        if argv[0] == "systemctl":
            sub = argv[2]
            if sub == "show" and "--value" in argv:
                return subprocess.CompletedProcess(argv, 0, str(venvs_root / VENV) + "\n", "")
            if sub == "show":
                return subprocess.CompletedProcess(
                    argv, 0, "ActiveState=active\nSubState=running\nNRestarts=0\n", "")
            if sub == "restart":
                return subprocess.CompletedProcess(argv, 0, "", "")
        return git_runner(argv, **kw)

    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] and out["upgraded"], out
    assert out["before_version"] == "0.3.2" and out["after_version"] == "0.3.4"
    assert out["pkg"] == PKG
    assert out["serve_reload_required"] is True
    assert out["build_task_id"] == "FAKE1"
    restarted_units = {r["unit"] for r in out["restarted"]}
    assert restarted_units == {
        "willow-mcp-worker-fast.service", "willow-mcp-worker-batch.service",
    }
    assert all(r["restart_ok"] and r["live"] for r in out["restarted"])
    assert _receipts(pg), "expected a package_upgrade FRANK receipt"
    assert out["citation_id"]
    assert len(_granted_citations(pg, "env-package.upgrade-test")) == 1
    # R1: the installed wheel path is the broker-PRIVATE copy.
    assert "private" in out["wheel"]


def test_reload_skips_units_not_running_from_the_named_venv(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    wheel_path = tmp_path / "prebuilt2" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_pip_install_wheel", lambda python, wheel, *, runner:
                         subprocess.CompletedProcess([], 0, "", ""))
    versions = iter(["0.3.2", "0.3.4"])
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: next(versions))
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: None)

    git_runner = _standard_git_runner()

    def runner(argv, **kw):
        if argv[0] == "systemctl" and argv[2] == "show" and "--value" in argv:
            return subprocess.CompletedProcess(argv, 0, "/some/other/venv/bin/python\n", "")
        return git_runner(argv, **kw)

    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"], out
    assert out["restarted"] == []
    assert set(out["skipped_units"]) == {
        "willow-mcp-worker-fast.service", "willow-mcp-worker-batch.service",
    }


def test_dead_worker_after_restart_reports_ok_false(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    wheel_path = tmp_path / "prebuilt3" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_pip_install_wheel", lambda python, wheel, *, runner:
                         subprocess.CompletedProcess([], 0, "", ""))
    versions = iter(["0.3.2", "0.3.4"])
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: next(versions))
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: None)

    git_runner = _standard_git_runner()

    def runner(argv, **kw):
        if argv[0] == "systemctl":
            sub = argv[2]
            if sub == "show" and "--value" in argv:
                return subprocess.CompletedProcess(argv, 0, str(venvs_root / VENV) + "\n", "")
            if sub == "show":
                return subprocess.CompletedProcess(
                    argv, 0, "ActiveState=inactive\nSubState=dead\nNRestarts=0\n", "")
            if sub == "restart":
                return subprocess.CompletedProcess(argv, 0, "", "")
        return git_runner(argv, **kw)

    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False, out
    assert out["error"] == "EDEAD"
    assert out["upgraded"] is True


# ── R2: rollback only ever acts on a COMPLETE backup manifest ────────────────

def test_backup_entries_writes_manifest_only_after_every_copy_succeeds(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    pkg_dir = site / "kartikeya"
    pkg_dir.mkdir()
    (pkg_dir / "x.py").write_text("x", encoding="utf-8")
    backup_dir = tmp_path / "backup"
    pairs = pux._backup_entries([pkg_dir], backup_dir)
    assert pairs is not None
    assert (backup_dir / pux._BACKUP_MANIFEST_NAME).is_file()
    loaded = pux._load_backup_manifest(backup_dir)
    assert loaded == pairs


def test_backup_entries_returns_none_and_writes_no_manifest_on_failure(tmp_path, monkeypatch):
    site = tmp_path / "site"
    site.mkdir()
    pkg_dir = site / "kartikeya"
    pkg_dir.mkdir()
    backup_dir = tmp_path / "backup"

    def boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(pux.shutil, "copytree", boom)
    result = pux._backup_entries([pkg_dir], backup_dir)
    assert result is None
    assert not (backup_dir / pux._BACKUP_MANIFEST_NAME).exists()


def test_backup_entries_clears_a_preexisting_backup_dir(tmp_path):
    """R2 should-fix: a pre-existing file at a backup slot (from an earlier
    attempt) must not collide — the broker-owned backup dir is cleared."""
    site = tmp_path / "site"
    site.mkdir()
    pkg_dir = site / "kartikeya"
    pkg_dir.mkdir()
    (pkg_dir / "x.py").write_text("x", encoding="utf-8")
    backup_dir = tmp_path / "backup"
    (backup_dir / "0").mkdir(parents=True)
    (backup_dir / "0" / "kartikeya").write_text("stale planted file", encoding="utf-8")
    pairs = pux._backup_entries([pkg_dir], backup_dir)
    assert pairs is not None
    assert (backup_dir / "0" / "kartikeya").is_dir()


def test_rollback_from_manifest_is_a_noop_with_no_manifest(tmp_path):
    """R2 (P1/P2 shape): no manifest at all -> nothing is touched."""
    site = tmp_path / "site"
    live = site / "kartikeya"
    live.mkdir(parents=True)
    (live / "VERSION").write_text("still-here", encoding="utf-8")
    pux._rollback_from_manifest(tmp_path / "no-such-backup-dir",
                                 python=Path("/fake/python"), pkg="kartikeya",
                                 runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", ""))
    assert (live / "VERSION").read_text(encoding="utf-8") == "still-here"


def test_site_packages_timeout_after_verify_leaves_the_install_untouched(home, tmp_path, monkeypatch, github_root, venvs_root):
    """R2 (Loki's P1 shape): a TimeoutExpired between verify and the
    backup — nothing was ever backed up, so rollback must be a no-op, not
    a deletion of whatever happens to exist on disk right now."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-p1"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")
    bin_dir = venvs_root / VENV / "bin"
    (bin_dir / "kartikeya").write_text("#!/bin/sh\necho original\n")

    wheel_path = tmp_path / "prebuilt-p1" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4", scripts={"kartikeya": "kartikeya.cli:main"})
    _patch_kart_build(monkeypatch, wheel_path)

    def timeout_site_packages(python, *, runner):
        raise subprocess.TimeoutExpired(cmd=["python"], timeout=30)

    monkeypatch.setattr(pux, "_site_packages", timeout_site_packages)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "ETIMEDOUT", out
    assert out["citation_id"]
    # nothing was ever backed up — the live entries must be UNTOUCHED.
    assert (site / f"{PKG}-0.3.2.dist-info").exists()
    assert (site / PKG / "VERSION").read_text(encoding="utf-8") == "original"
    assert (bin_dir / "kartikeya").read_text() == "#!/bin/sh\necho original\n"


def test_backup_entries_oserror_leaves_the_install_untouched(home, tmp_path, monkeypatch, github_root, venvs_root):
    """R2 (Loki's P2 shape): _backup_entries itself raises OSError partway
    through — the live entries must remain exactly as they were."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-p2"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")
    bin_dir = venvs_root / VENV / "bin"
    (bin_dir / "kartikeya").write_text("#!/bin/sh\necho original\n")

    wheel_path = tmp_path / "prebuilt-p2" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4", scripts={"kartikeya": "kartikeya.cli:main"})
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: site)

    def boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(pux.shutil, "copytree", boom)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "EIO", out
    assert out["citation_id"]
    assert (site / f"{PKG}-0.3.2.dist-info").exists()
    assert (site / PKG / "VERSION").read_text(encoding="utf-8") == "original"
    assert (bin_dir / "kartikeya").read_text() == "#!/bin/sh\necho original\n"


# ── EVERIFY + rollback (real filesystem backup/restore, incl. console scripts) ─

def test_everify_mismatch_rolls_back_real_files_and_console_scripts(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-packages"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")
    bin_dir = venvs_root / VENV / "bin"
    (bin_dir / "kartikeya").write_text("#!/bin/sh\necho original\n")

    wheel_path = tmp_path / "prebuilt4" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4", scripts={"kartikeya": "kartikeya.cli:main"})
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: site)

    def fake_pip_install_wheel(python, wheel, *, runner):
        _write_dist(site, PKG, "9.9.9", "broken")
        (bin_dir / "kartikeya").write_text("#!/bin/sh\necho broken\n")
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(pux, "_pip_install_wheel", fake_pip_install_wheel)
    versions = iter(["0.3.2", "9.9.9", "0.3.2"])
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: next(versions))

    runner = _standard_git_runner(
        pyproject='[project]\ndependencies = []\nscripts = {kartikeya = "kartikeya.cli:main"}\n\n'
                  '[build-system]\nrequires = ["hatchling"]\n')
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "EVERIFY", out
    assert out["declared_version"] == "0.3.4"
    assert out["attempted_version"] == "9.9.9"
    assert out["rolled_back_to"] == "0.3.2"
    assert out["citation_id"]
    assert not (site / f"{PKG}-9.9.9.dist-info").exists()
    assert (site / f"{PKG}-0.3.2.dist-info").exists()
    assert (site / PKG / "VERSION").read_text(encoding="utf-8") == "original"
    assert (bin_dir / "kartikeya").read_text() == "#!/bin/sh\necho original\n"
    assert _receipts(pg, f"{pux.EVENT}_act_failed")


def test_install_timeout_rolls_back_and_is_a_cited_failure(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-packages-timeout"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")

    wheel_path = tmp_path / "prebuilt5" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: site)
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: "0.3.2")

    def timeout_install(python, wheel, *, runner):
        raise subprocess.TimeoutExpired(cmd=["pip"], timeout=180)

    monkeypatch.setattr(pux, "_pip_install_wheel", timeout_install)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "ETIMEDOUT", out
    assert out["citation_id"]
    assert (site / f"{PKG}-0.3.2.dist-info").exists()
    assert _receipts(pg, f"{pux.EVENT}_act_failed")


def test_einstall_rolls_back_using_the_backup(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-packages-einstall"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")

    wheel_path = tmp_path / "prebuilt6" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: site)
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: "0.3.2")

    def fake_pip_install_wheel(python, wheel, *, runner):
        _write_dist(site, PKG, "9.9.9", "half-installed")
        return subprocess.CompletedProcess([], 1, "", "error: could not install")

    monkeypatch.setattr(pux, "_pip_install_wheel", fake_pip_install_wheel)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "EINSTALL", out
    assert out["citation_id"]
    assert not (site / f"{PKG}-9.9.9.dist-info").exists()
    assert (site / f"{PKG}-0.3.2.dist-info").exists()
    assert (site / PKG / "VERSION").read_text(encoding="utf-8") == "original"


# ── AC918C4D F6 — a failure INSIDE rollback itself is never silent ───────────

def test_rollback_restore_raises_leaves_the_install_intact(home, tmp_path, monkeypatch, github_root, venvs_root):
    """F6 repro (rollback_restore_raises): a failure partway through the
    restore swap must NEVER leave site-packages empty -- stage-then-swap
    means every not-yet-swapped entry's live content (old or the broken
    new install) survives untouched -- and the failure is cited
    EROLLBACK, never silently folded into the original error or left to
    escape uncited."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-rollback-raises"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")

    wheel_path = tmp_path / "prebuilt-rbf6" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: site)
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: "0.3.2")

    def fake_pip_install_wheel(python, wheel, *, runner):
        _write_dist(site, PKG, "9.9.9", "broken")
        return subprocess.CompletedProcess([], 1, "", "error: could not install")

    monkeypatch.setattr(pux, "_pip_install_wheel", fake_pip_install_wheel)

    real_replace = pux.os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst, *a, **kw):
        calls["n"] += 1
        # Fail on the VERY FIRST os.replace of the restore -- the
        # earliest possible failure point. With stage-then-swap (fixed),
        # this is the "move the live entry aside" step, which the
        # not-yet-touched original survives untouched. With
        # remove-before-stage (the bug/mutation), the live entry was
        # ALREADY deleted before this call, so this is the swap-in
        # itself failing with nothing to fall back to -- the entry is
        # simply gone.
        if calls["n"] == 1:
            raise OSError("disk full mid-swap")
        return real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(pux.os, "replace", flaky_replace)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "EROLLBACK", out
    assert out["original_errno"] == "EINSTALL"
    assert out["citation_id"]
    assert _receipts(pg, f"{pux.EVENT}_act_failed")
    # never emptied: the FIRST related entry processed (the kartikeya
    # package directory, sorted before its dist-info) must survive the
    # very first os.replace failing -- either untouched or restored,
    # never simply gone.
    assert (site / PKG).is_dir() and any((site / PKG).iterdir()), \
        "the kartikeya package directory must never simply vanish or go empty"


def test_rollback_venv_version_raises_is_cited(home, tmp_path, monkeypatch, github_root, venvs_root):
    """F6: _venv_version raising AFTER the restore (the final call inside
    _rollback_from_manifest) must not escape either -- caught by
    _rollback()'s own guard and cited EROLLBACK, same as a failure
    during the restore itself."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-rollback-vv"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")

    wheel_path = tmp_path / "prebuilt-rbf6b" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: site)

    calls = {"n": 0}

    def flaky_venv_version(python, pkg, runner):
        calls["n"] += 1
        if calls["n"] == 1:
            return "0.3.2"
        raise RuntimeError("venv introspection broke")

    monkeypatch.setattr(pux, "_venv_version", flaky_venv_version)

    def fake_pip_install_wheel(python, wheel, *, runner):
        return subprocess.CompletedProcess([], 1, "", "error: could not install")

    monkeypatch.setattr(pux, "_pip_install_wheel", fake_pip_install_wheel)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "EROLLBACK", out
    assert out["original_errno"] == "EINSTALL"
    assert out["citation_id"]
    assert _receipts(pg, f"{pux.EVENT}_act_failed")


# ── ML8 — the pre-install rehash check, LOKIREHASH shape ─────────────────────

def test_rehash_mismatch_between_verify_and_install_refuses_everify(
        home, tmp_path, monkeypatch, github_root, venvs_root):
    """3CBE8D7E/AC918C4D ML8: deleting the pre-install rehash check
    survived every prior test. If the private wheel's bytes change
    between verify and install (LOKIREHASH), the install must refuse
    EVERIFY, cited, with pip install never even attempted."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    wheel_path = tmp_path / "prebuilt-ml8" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: None)

    install_calls = {"n": 0}

    def never_install(python, wheel, *, runner):
        install_calls["n"] += 1
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(pux, "_pip_install_wheel", never_install)

    def tampering_verify(wheel, src_dir, *, package, version, declared_scripts, package_roots=None):
        # Tampers with the PRIVATE wheel copy's bytes AFTER wheel_digest
        # was computed but BEFORE the pre-install rehash re-reads it --
        # exactly the LOKIREHASH injection shape.
        with open(wheel, "ab") as f:
            f.write(b"LOKIREHASH-tamper")
        return {"ok": True, "sha256": pux.wheel_sha256(wheel)}

    monkeypatch.setattr(pux, "verify_wheel_against_source", tampering_verify)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "EVERIFY", out
    assert "changed between verify and install" in out["reason"]
    assert out["citation_id"]
    assert install_calls["n"] == 0, "pip install must never be attempted after a rehash mismatch"


# ── N3/R3 — every act-phase exception, not just three classes ────────────────

def test_archive_timeout_is_a_cited_rollback(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    monkeypatch.setattr(server_mod, "_lane_running_task_ids", lambda a, b, c: [])
    git_runner = _standard_git_runner()

    def timing_out_runner(argv, **kw):
        if argv[0] == "git" and argv[3:4] == ["archive"]:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=30)
        return git_runner(argv, **kw)

    out = _upgrade(pg, runner=timing_out_runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work")
    assert out["ok"] is False and out["error"] == "ETIMEDOUT", out
    assert out["citation_id"]
    assert _receipts(pg, f"{pux.EVENT}_act_failed")


def test_systemctl_restart_timeout_is_cited_and_rolled_back(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-packages-systemctl-timeout"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")

    wheel_path = tmp_path / "prebuilt7" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: site)
    monkeypatch.setattr(pux, "_pip_install_wheel", lambda python, wheel, *, runner:
                         subprocess.CompletedProcess([], 0, "", ""))
    versions = iter(["0.3.2", "0.3.4", "0.3.2"])
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: next(versions))

    git_runner = _standard_git_runner()

    def runner(argv, **kw):
        if argv[0] == "systemctl":
            sub = argv[2]
            if sub == "show" and "--value" in argv:
                return subprocess.CompletedProcess(argv, 0, str(venvs_root / VENV) + "\n", "")
            if sub == "restart":
                raise subprocess.TimeoutExpired(cmd=argv, timeout=30)
            if sub == "show":
                return subprocess.CompletedProcess(
                    argv, 0, "ActiveState=active\nSubState=running\nNRestarts=0\n", "")
        return git_runner(argv, **kw)

    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "ETIMEDOUT", out
    assert out["citation_id"]
    assert _receipts(pg, f"{pux.EVENT}_act_failed")
    assert (site / f"{PKG}-0.3.2.dist-info").exists()


def test_partial_restart_is_recorded_on_the_failure_receipt(home, tmp_path, monkeypatch, github_root, venvs_root):
    """P6 should-fix: a restart that got partway through before a later
    failure must still name `restarted` on the failure receipt."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    site = tmp_path / "site-p6"
    site.mkdir()
    _write_dist(site, PKG, "0.3.2", "original")

    wheel_path = tmp_path / "prebuilt-p6" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: site)
    monkeypatch.setattr(pux, "_pip_install_wheel", lambda python, wheel, *, runner:
                         subprocess.CompletedProcess([], 0, "", ""))
    versions = iter(["0.3.2", "0.3.4", "0.3.2"])
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: next(versions))

    git_runner = _standard_git_runner()
    calls = {"restart": 0}

    def runner(argv, **kw):
        if argv[0] == "systemctl":
            sub = argv[2]
            if sub == "show" and "--value" in argv:
                return subprocess.CompletedProcess(argv, 0, str(venvs_root / VENV) + "\n", "")
            if sub == "show":
                return subprocess.CompletedProcess(
                    argv, 0, "ActiveState=active\nSubState=running\nNRestarts=0\n", "")
            if sub == "restart":
                calls["restart"] += 1
                if calls["restart"] == 2:
                    raise subprocess.TimeoutExpired(cmd=argv, timeout=30)
                return subprocess.CompletedProcess(argv, 0, "", "")
        return git_runner(argv, **kw)

    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"] is False and out["error"] == "ETIMEDOUT", out
    assert len(out["restarted"]) == 1, "the FIRST unit's restart must be on the receipt"


def test_bad_zip_file_from_verify_is_cited_and_rolled_back(home, tmp_path, monkeypatch, github_root, venvs_root):
    """R3/3CBE8D7E P4: an exception raised inside the act phase that is
    NEITHER _CitedActFailure, TimeoutExpired, NOR OSError (a malformed
    wheel raising zipfile.BadZipFile, in production) must be caught by the
    final `except Exception`, cite, and roll back — never escape."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    monkeypatch.setattr(server_mod, "_lane_running_task_ids", lambda a, b, c: [])

    def fake_run_kart_build(app_id, src_dir, wheel_dir, *, version, import_names, lane,
                             submit_fn=None, status_fn=None, sleeper=None, timeout=None):
        Path(wheel_dir).mkdir(parents=True, exist_ok=True)
        wheel = Path(wheel_dir) / _real_wheel_name(PKG, "0.3.4")
        wheel.write_bytes(b"x")
        return {"ok": True, "wheel": wheel, "task_id": "BADZIP1"}

    monkeypatch.setattr(pux, "run_kart_build", fake_run_kart_build)

    import zipfile as _zipfile

    def raising_verify(wheel, src_dir, *, package, version, declared_scripts, package_roots=None):
        raise _zipfile.BadZipFile("File is not a zip file")

    monkeypatch.setattr(pux, "verify_wheel_against_source", raising_verify)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work")
    assert out["ok"] is False and out["error"] == "EUNEXPECTED", out
    assert out["exception_type"] == "BadZipFile"
    assert out["citation_id"]
    assert _receipts(pg, f"{pux.EVENT}_act_failed")


# ── EAMBIG — no ledger ────────────────────────────────────────────────────────

def test_no_ledger_refuses(home, tmp_path, monkeypatch, github_root, venvs_root):
    _charter(tmp_path, monkeypatch)
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    runner = _standard_git_runner()
    out = pux.execute_package_upgrade(
        "hanuman", repo=REPO, tag=TAG, venv=VENV, project="willow-mcp",
        ledger=None, runner=runner, github_root=github_root, venvs_root=venvs_root,
        private_root=tmp_path / "private", work_dir=tmp_path / "work",
    )
    assert out["ok"] is False and out["error"] == "EAMBIG", out


# ── F6/3CBE8D7E M18, M19 — archive and show are pinned to the resolved sha ───

def test_archive_and_show_calls_use_the_resolved_sha_never_the_tag_name(
        home, tmp_path, monkeypatch, github_root, venvs_root):
    """3CBE8D7E M18 (archive by tag name) / M19 (deps by tag name): every
    `git archive`/`git show <ref>:pyproject.toml` call must be pinned to
    the resolved sha, never the caller-supplied tag — the tag is
    Kart-writable in the local clone and can move (F6)."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    wheel_path = tmp_path / "prebuilt-m18" / _real_wheel_name(PKG, "0.3.4")
    wheel_path.parent.mkdir(parents=True)
    _make_wheel(wheel_path, PKG, "0.3.4")
    _patch_kart_build(monkeypatch, wheel_path)
    monkeypatch.setattr(pux, "_pip_install_wheel", lambda python, wheel, *, runner:
                         subprocess.CompletedProcess([], 0, "", ""))
    versions = iter(["0.3.2", "0.3.4"])
    monkeypatch.setattr(pux, "_venv_version", lambda python, pkg, runner: next(versions))
    monkeypatch.setattr(pux, "_site_packages", lambda python, runner: None)

    git_runner = _standard_git_runner()
    calls: list[list[str]] = []

    def runner(argv, **kw):
        calls.append(list(argv))
        if argv[0] == "systemctl":
            sub = argv[2]
            if sub == "show" and "--value" in argv:
                return subprocess.CompletedProcess(argv, 0, str(venvs_root / VENV) + "\n", "")
            if sub == "show":
                return subprocess.CompletedProcess(
                    argv, 0, "ActiveState=active\nSubState=running\nNRestarts=0\n", "")
            if sub == "restart":
                return subprocess.CompletedProcess(argv, 0, "", "")
        return git_runner(argv, **kw)

    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work", sleeper=lambda s: None)
    assert out["ok"], out
    assert out["tag_sha"] == TAG_SHA

    pinned = [c for c in calls if c[0] == "git" and c[3:4] in (["archive"], ["show"])]
    assert pinned, "expected at least one git archive/show call to inspect"
    for c in pinned:
        ref = c[4] if c[3] == "archive" else c[4].split(":", 1)[0]
        assert ref == TAG_SHA, c
        assert ref != TAG, c


# ── 500FCEFB item 1 / 3CBE8D7E gap — every matched file, byte-for-byte ───────

def test_verify_wheel_everify_on_matched_non_py_content_mismatch(tmp_path):
    """Every file under a declared package root is compared byte-for-byte,
    not only .py — a package DATA file that exists in both trees but
    differs in content must still refuse (was previously checked for
    existence only)."""
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    (src / PKG / "data").mkdir()
    (src / PKG / "data" / "policy.json").write_text('{"safe": true}', encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, PKG, "0.4.0",
                extra_files={f"{PKG}/data/policy.json": '{"safe": false}'})
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EVERIFY", out
    assert f"{PKG}/data/policy.json" in out["mismatched"]


def test_verify_wheel_ebuild_on_extra_non_py_file_in_package_root(tmp_path):
    """3CBE8D7E M28b: an extra NON-.py file under a declared package root
    with no matching source file must be refused as an unmatched extra,
    same as an extra .py file already is."""
    src = tmp_path / "src"
    (src / PKG).mkdir(parents=True)
    (src / PKG / "__init__.py").write_text("", encoding="utf-8")
    wheel = tmp_path / _real_wheel_name(PKG, "0.4.0")
    _make_wheel(wheel, PKG, "0.4.0",
                extra_files={f"{PKG}/data/injected.dat": "not in source"})
    out = pux.verify_wheel_against_source(wheel, src, package=PKG, version="0.4.0", declared_scripts={})
    assert out["ok"] is False and out["error"] == "EBUILD", out
    assert f"{PKG}/data/injected.dat" in out["extra"]


# ── 3CBE8D7E M33 — a raw OSError outside _backup_entries is still cited ─────

def test_wheel_copy_oserror_is_cited_as_eio(home, tmp_path, monkeypatch, github_root, venvs_root):
    """3CBE8D7E M33: an OSError that escapes from somewhere OTHER than
    _backup_entries (here: copying the Kart-built wheel into the private
    dir) must still be caught by the dedicated `except OSError` branch and
    cited EIO — not merely absorbed by the generic catch-all with a
    different errno."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(pux, "_build_python_candidates", lambda: ["fake-python"])
    monkeypatch.setattr(server_mod, "_lane_running_task_ids", lambda a, b, c: [])

    def fake_run_kart_build(app_id, src_dir, wheel_dir, *, version, import_names, lane,
                             submit_fn=None, status_fn=None, sleeper=None, timeout=None):
        Path(wheel_dir).mkdir(parents=True, exist_ok=True)
        wheel = Path(wheel_dir) / _real_wheel_name(PKG, "0.3.4")
        _make_wheel(wheel, PKG, "0.3.4")
        return {"ok": True, "wheel": wheel, "task_id": "COPYOSERR1"}

    monkeypatch.setattr(pux, "run_kart_build", fake_run_kart_build)

    real_copy2 = pux.shutil.copy2

    def boom_on_whl(src, dst, *a, **kw):
        if str(src).endswith(".whl"):
            raise OSError("disk full copying wheel")
        return real_copy2(src, dst, *a, **kw)

    monkeypatch.setattr(pux.shutil, "copy2", boom_on_whl)

    runner = _standard_git_runner()
    out = _upgrade(pg, runner=runner, github_root=github_root, venvs_root=venvs_root, tmp_path=tmp_path,
                   work_dir=tmp_path / "work")
    assert out["ok"] is False and out["error"] == "EIO", out
    assert out["citation_id"]
    assert _receipts(pg, f"{pux.EVENT}_act_failed")


# ── 500FCEFB item 3 — the generated build script, actually executed ─────────

def test_build_task_script_executes_against_a_real_fixture_package(tmp_path):
    """Run the ACTUAL text _build_task_script generates against a tiny,
    real fixture package, using whichever offline build backend happens
    to be importable in this interpreter. No other test in this file
    touches the generated script's own bytes -- everywhere else
    run_kart_build is monkeypatched. Skips, with a named reason, when no
    local backend is importable at all."""
    import sys as _sys

    backend = None
    for requires, build_backend in (
        ("setuptools>=61", "setuptools.build_meta"),
        ("hatchling", "hatchling.build"),
        ("flit_core>=3.2,<4", "flit_core.buildapi"),
    ):
        top_level = build_backend.split(".", 1)[0]
        try:
            __import__(top_level)
        except ImportError:
            continue
        backend = (requires, build_backend, top_level)
        break
    if backend is None:
        pytest.skip(
            "no offline build backend importable in this test interpreter "
            "(checked setuptools, hatchling, flit_core) -- cannot execute "
            "the generated build script against a real fixture package here"
        )
    requires, build_backend, import_name = backend

    fixture_pkg = "upgradefixture"
    src = tmp_path / "src"
    (src / fixture_pkg).mkdir(parents=True)
    (src / fixture_pkg / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (src / "pyproject.toml").write_text(
        f'[build-system]\nrequires = ["{requires}"]\nbuild-backend = "{build_backend}"\n\n'
        f'[project]\nname = "{fixture_pkg}"\nversion = "0.0.1"\n',
        encoding="utf-8",
    )
    wheel_dir = tmp_path / "wheel"
    script = pux._build_task_script(
        src, wheel_dir, version="0.0.1",
        candidates=[_sys.executable], import_names=[import_name],
    )
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    built = list(wheel_dir.glob("*.whl"))
    assert built, (proc.stdout, proc.stderr)
    assert built[0].name.startswith(fixture_pkg)
