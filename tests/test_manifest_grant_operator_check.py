"""install.sh refuses an operator that is not a real, regular user (Loki R2).

`OPERATOR=${SUDO_USER:-sean-campbell}` names whose vault, uid and systemd
manager root acts on. The real shell function `mg_operator_problems`
(between `# BEGIN operator-check` / `# END operator-check`) is run here with a
fake `id` on PATH (so uids need no real accounts) and a temp dir as the home base.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

_INSTALL = Path(__file__).resolve().parents[1] / "deploy" / "manifest-grant" / "install.sh"
_TEXT = _INSTALL.read_text(encoding="utf-8")
_BLOCK = re.search(r"^# BEGIN operator-check\n(.*?)^# END operator-check\n", _TEXT, re.S | re.M).group(1)
_UID = os.getuid()
_MINE = _UID if _UID >= 1000 else 1500   # a fake regular uid; chowned to when running as root
_USERS = {"root": 0, "daemon": 1, "low": 999, "nobody": 65534, "opx": 1000, "mine": _MINE}


@pytest.fixture
def env(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    cases = "\n".join(f"  {n}) echo {u};;" for n, u in _USERS.items())
    fake = bin_ / "id"
    fake.write_text(f'#!/bin/sh\n[ "$1" = "-u" ] && shift\n[ "$1" = "--" ] && shift\ncase "$1" in\n{cases}\n  *) exit 1;;\nesac\n')
    fake.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    return {"PATH": f"{bin_}:{os.environ['PATH']}", "LC_ALL": "C"}, home


def _problems(env, name: str, home: Path) -> str:
    e, _ = env
    r = subprocess.run(["bash", "-c", _BLOCK + '\nmg_operator_problems "$1" "$2"', "x", name, str(home)],
                       capture_output=True, text=True, env=e)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _mkhome(home: Path, name: str) -> None:
    (home / name).mkdir()
    if name == "mine" and _UID != _MINE:
        try:
            os.chown(home / name, _MINE, -1)
        except PermissionError:
            pytest.skip("cannot chown the fixture home (not root)")


def test_normal_user_with_own_home_passes(env):
    _, home = env
    _mkhome(home, "mine")
    assert _problems(env, "mine", home) == ""


@pytest.mark.parametrize("name,why", [("root", "uid 0"), ("daemon", "uid 1"), ("low", "uid 999"), ("nobody", "uid 65534")])
def test_system_uids_are_refused(env, name, why):
    _, home = env
    _mkhome(home, name)
    assert "not a regular user" in _problems(env, name, home), why


@pytest.mark.parametrize("name", ["Bad", "a b", "-x", "a/../b", "9lives", "", "x;y", "a\nroot"])
def test_bad_names_are_refused(env, name):
    _, home = env
    assert "not a plain login name" in _problems(env, name, home)


def test_unknown_user_is_refused(env):
    _, home = env
    assert "not a known user" in _problems(env, "ghost", home)


def test_missing_home_is_refused(env):
    _, home = env
    assert "not a real directory" in _problems(env, "mine", home)


def test_symlinked_home_is_refused(env, tmp_path):
    _, home = env
    (tmp_path / "elsewhere").mkdir()
    (home / "mine").symlink_to(tmp_path / "elsewhere")
    assert "not a real directory" in _problems(env, "mine", home)


def test_home_owned_by_another_uid_is_refused(env):
    _, home = env
    _mkhome(home, "opx")          # fake uid 1000; the dir is owned by the test's uid
    if _UID == 1000:
        pytest.skip("test uid equals the fake uid")
    assert "is owned by uid" in _problems(env, "opx", home)


def test_the_check_runs_before_any_use_of_operator_and_dry_run_is_exempt():
    call = _TEXT.index('out=$(mg_operator_problems "$OPERATOR")')
    assert _TEXT.index("OPERATOR=${SUDO_USER:-sean-campbell}") < call < _TEXT.index('OPERATOR_UID=$(id -u "$OPERATOR")')
    assert call < _TEXT.index('H=/home/$OPERATOR/')
    guard = _TEXT[:call].rsplit("\n", 2)[-2]
    assert guard == 'if [ "${1:-}" != "--dry-run-sign" ]; then'
    assert 'stop "operator check failed' in _TEXT[call:call + 200]


def test_dry_run_sign_still_works_for_a_system_account(tmp_path):
    r = subprocess.run(["bash", str(_INSTALL), "--dry-run-sign"], capture_output=True, text=True,
                       env={"PATH": os.environ["PATH"], "SUDO_USER": "root", "LC_ALL": "C"}, cwd=tmp_path)
    assert r.returncode == 0 and "--dry-run-sign" in r.stdout, (r.stdout, r.stderr)
