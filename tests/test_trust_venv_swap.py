"""`--provision-venv` swaps the trust-owner venv atomically (Q50, 2026-10-11).

Observed on the operator box during the 8b53488 deploy: the manifest-grant timer
ticked while provision_trust_venv was deleting and rebuilding
/opt/willow-operator/venv in place, and one tick failed `No module named
willow_mcp`. Now the venv is built in a sibling release directory
(`venv.rel.<random>`, at its own permanent path, so the path baked into
pyvenv.cfg and the shebangs never changes) and `$TRUST_VENV` becomes a
root-owned symlink to it, swapped with ONE renameat2(2).

These tests run the REAL shell functions (tvc_build_stage, tvc_publish,
tvc_rename, tvc_report) against a tmp tree as an unprivileged user (the test
user stands in for root through the uid argument), with a fake base interpreter.
What they cannot exercise (real root, the network build of the wheel) is covered
by the real-root run recorded in the commit report.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from test_trust_venv_preflight import _BLOCK, _INSTALL_SH, _UID, _Tree

_GID = os.getgid()
_TOOLS = ("bash", "awk", "find", "stat", "readlink", "sed", "head", "grep", "cat", "dirname", "env", "sh",
          "sort", "touch", "mktemp", "rm", "ln", "cp", "chown", "chmod", "id", "mkdir", "mv", "true", "false", "tr")


def _fn(name: str) -> str:
    m = re.search(rf"^{name}\(\) {{\n.*?^}}\n", _INSTALL_SH, re.S | re.M)
    assert m, name
    return m.group(0)


_FUNCS = "\n".join(_fn(n) for n in ("tvc_stop", "tvc_rename", "tvc_build_stage", "tvc_publish"))

_GENERIC_PY = """#!/bin/sh
case "$1 $2 $3" in
  "-I -m pip")
    d=$(dirname "$0")/..
    case "$*" in
      *--require-hashes*) [ ! -e "$CTL/fail_reqs" ] || exit 1 ;;
      *) [ ! -e "$CTL/fail_wheel" ] || exit 1
         echo new > "$d/marker"
         [ ! -e "$CTL/dirty" ] || echo "include-system-site-packages = true" >> "$d/pyvenv.cfg" ;;
    esac
    exit 0 ;;
esac
touch "$CTL/interpreter-ran"
d=$(dirname "$0")/..
echo "SYSPATH @ANCHOR@/usr/lib/python313.zip"
echo "SYSPATH @ANCHOR@/usr/lib/python3.13"
echo "SYSPATH @ANCHOR@/usr/lib/python3.13/lib-dynload"
echo "SYSPATH $d/lib/python3.13/site-packages"
echo "$d/lib/python3.13/site-packages/willow_mcp/__init__.py"
"""

_FAKE_BASE = """#!/bin/sh
# fake base interpreter: only `-I -m venv DIR` is ever run on it by the build
[ ! -e "$CTL/fail_venv" ] || exit 1
[ "$1 $2 $3" = "-I -m venv" ] || exit 9
mkdir -p "$4" && cp -a "$TPL/." "$4/"
"""


class _Box:
    """A live venv (anchor/opt/venv, marker=old), a template the fake base copies
    into every new venv, and the shell harness around them."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.tree = _Tree(tmp_path)
        t = self.tree
        self.live = t.venv
        self.opt = self.live.parent
        self.ctl = tmp_path / "ctl"
        self.ctl.mkdir()
        t.py.write_text(_GENERIC_PY.replace("@ANCHOR@", str(t.anchor)))
        t.py.chmod(0o755)
        self.tpl = tmp_path / "tpl"
        shutil.copytree(self.live, self.tpl, symlinks=True)
        (self.live / "marker").write_text("old\n")
        self.base_script = t.base  # replaced below; tvc_report only reads its NAME and path
        t.base.write_text(_FAKE_BASE)
        t.base.chmod(0o755)
        self.bin = tmp_path / "_bin"
        self.bin.mkdir()
        for tool in _TOOLS:
            real = shutil.which(tool)
            assert real, tool
            (self.bin / tool).symlink_to(real)
        g = self.bin / "getfacl"
        g.write_text('#!/bin/sh\necho "$@" >> "$CTL/getfacl-args"\nexit 0\n')
        g.chmod(0o755)
        (tmp_path / "reqs.txt").write_text("x\n")
        (tmp_path / "w.whl").write_text("x\n")

    def sh(self, body: str, *, swap_py: str | None = None, instrument: bool = False,
           pre: str = "") -> subprocess.CompletedProcess:
        t = self.tree
        inv = ""
        if instrument:
            inv = (
                f'INV_LOG={self.tmp}/inv.log; : > "$INV_LOG"\n'
                'inv() { if [ ! -x "$TRUST_VENV/bin/python" ] || [ ! -f "$TRUST_VENV/lib/python3.13/site-packages/willow_mcp/__init__.py" ] '
                '|| [ ! -d "$TRUST_VENV/lib/python3.13/site-packages/willow_mcp-1.2.3.dist-info" ]; then '
                'echo "MISSING before: $BASH_COMMAND" >> "$INV_LOG"; fi; echo . >> "$INV_LOG.n"; }\n'
                'set -T; trap inv DEBUG\n'
            )
        script = self.tmp / "_swap.sh"
        script.write_text(
            "set -euo pipefail\n" + _BLOCK + "\n" + _FUNCS + "\n"
            'say() { echo "SAY: $*"; }\nstop() { echo "STOP: $*" >&2; exit 1; }\n'
            f'TRUST_VENV={self.live}; TRUST_PY_BASE={t.base}; TVC_STAMP=.built-from-head; HEAD_SHA=abc123def\n'
            f'TVC_BUILD={self.tmp}/build; TVC_STAGE=""; TVC_SWAP_PY={swap_py or sys.executable}; TVC_OWNER={_UID}:{_GID}\n'
            f'export CTL={self.ctl} TPL={self.tpl}\n'
            + pre + inv + body + "\n")
        env = {"PATH": str(self.bin), "LC_ALL": "C"}
        return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)

    def build_and_publish(self, **kw) -> subprocess.CompletedProcess:
        return self.sh(
            f'TVC_STAGE=$(mktemp -d "$TRUST_VENV.rel.XXXXXXXX")\n'
            f'tvc_build_stage "$TVC_STAGE" {self.tmp}/reqs.txt {self.tmp}/w.whl\n'
            f'tvc_publish "$TVC_STAGE" {_UID} {self.tree.anchor}\n', **kw)

    def siblings(self) -> list[str]:
        return sorted(p.name for p in self.opt.iterdir())

    def live_ok(self, marker: str) -> bool:
        return ((self.live / "bin" / "python").exists()
                and (self.live / "lib/python3.13/site-packages/willow_mcp/__init__.py").exists()
                and (self.live / "marker").read_text().strip() == marker)


@pytest.fixture
def box(tmp_path):
    return _Box(tmp_path)


def _intact(box: _Box) -> None:
    assert not box.live.is_symlink() and box.live.is_dir()
    assert box.live_ok("old")
    assert box.siblings() == ["venv"], box.siblings()   # no release directory left behind


# ---- failures leave the existing venv untouched -------------------------------------

@pytest.mark.parametrize("flag,where", [("fail_venv", "could not create the venv"),
                                        ("fail_reqs", "pip could not install the hash-pinned dependencies"),
                                        ("fail_wheel", "could not install w.whl")])
def test_a_build_failure_leaves_the_old_venv_intact(box, flag, where):
    (box.ctl / flag).write_text("")
    r = box.build_and_publish()
    assert r.returncode != 0 and "STOP:" in r.stderr, (r.stdout, r.stderr)
    assert where in r.stderr
    _intact(box)


def test_a_failed_preflight_of_the_new_venv_leaves_the_old_venv_intact(box):
    (box.ctl / "dirty").write_text("")          # the build leaves a pyvenv.cfg that pulls in the system site-packages
    r = box.build_and_publish()
    assert r.returncode != 0 and "failed its own preflight" in r.stderr and "unchanged" in r.stderr, (r.stdout, r.stderr)
    assert "[FAIL]" in r.stdout
    _intact(box)


def test_a_failed_swap_rename_leaves_the_old_venv_intact_and_does_not_copy(box):
    r = box.build_and_publish(swap_py="/bin/false")
    assert r.returncode != 0 and "could not swap" in r.stderr, (r.stdout, r.stderr)
    _intact(box)


def test_the_fresh_stage_alone_never_replaces_anything(box):
    """build_stage on its own (no publish) changes nothing at the final path."""
    r = box.sh(f'TVC_STAGE=$(mktemp -d "$TRUST_VENV.rel.XXXXXXXX")\ntvc_build_stage "$TVC_STAGE" {box.tmp}/reqs.txt {box.tmp}/w.whl\n')
    assert r.returncode == 0, r.stderr
    assert box.live_ok("old") and not box.live.is_symlink()
    stage = [p for p in box.opt.iterdir() if p.name.startswith("venv.rel.")]
    assert len(stage) == 1 and (stage[0] / "marker").read_text().strip() == "new"
    assert (stage[0] / ".built-from-head").read_text().strip() == "abc123def"   # stamp semantics kept


_ROLLBACK = (
    'eval "$(declare -f tvc_report | sed "1s/tvc_report/tvc_report_real/")"\n'
    'tvc_report() { if [ "$1" = "$TRUST_VENV" ]; then echo "  [FAIL] forced at the live path"; return 1; fi; tvc_report_real "$@"; }\n'
)


def test_a_failed_check_at_the_live_path_rolls_back_to_the_old_venv(box):
    r = box.build_and_publish(pre=_ROLLBACK)
    assert r.returncode != 0 and "put back" in r.stderr, (r.stdout, r.stderr)
    _intact(box)


def test_a_failed_check_at_the_live_path_after_a_previous_swap_restores_the_previous_release(box):
    assert box.build_and_publish().returncode == 0
    prev = os.path.realpath(box.live)
    r = box.build_and_publish(pre=_ROLLBACK)
    assert r.returncode != 0
    assert os.path.realpath(box.live) == prev and box.live.is_symlink() and box.live_ok("new")
    assert box.siblings() == ["venv", Path(prev).name]


# ---- success -----------------------------------------------------------------------

def test_success_swaps_removes_the_old_directory_and_passes_the_preflight(box):
    r = box.build_and_publish()
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert box.live.is_symlink() and os.readlink(box.live).startswith("venv.rel.")
    assert box.live_ok("new")
    assert box.siblings() == ["venv", os.readlink(box.live)]           # the old directory is gone
    assert (box.live / ".built-from-head").read_text().strip() == "abc123def"
    # the unit's exact interpreter path is the live path, and the full preflight passes on it
    rep = box.sh(f'tvc_report "$TRUST_VENV" "$TRUST_VENV/bin/python" {_UID} {box.tree.anchor} "$TRUST_PY_BASE"')
    assert rep.returncode == 0 and "[FAIL]" not in rep.stdout, rep.stdout
    assert os.access(box.live / "bin" / "python", os.X_OK)


def test_a_second_swap_replaces_the_symlink_and_deletes_the_previous_release(box):
    assert box.build_and_publish().returncode == 0
    first = os.readlink(box.live)
    assert box.build_and_publish().returncode == 0
    second = os.readlink(box.live)
    assert first != second and box.siblings() == ["venv", second]


def test_a_box_with_no_venv_yet_gets_one_without_an_exchange(box):
    shutil.rmtree(box.live)
    assert box.build_and_publish().returncode == 0
    assert box.live.is_symlink() and box.live_ok("new") and len(box.siblings()) == 2


def test_stale_release_directories_are_pruned_but_unrelated_siblings_are_not(box):
    (box.opt / "venv.rel.crashed1").mkdir()
    (box.opt / "venv.rel.crashed1" / "x").write_text("")
    (box.opt / "venvs").mkdir()
    (box.opt / "venv.keep").mkdir()
    assert box.build_and_publish().returncode == 0
    assert box.siblings() == sorted(["venv", os.readlink(box.live), "venvs", "venv.keep"])


def test_the_release_directory_is_the_one_the_symlink_names_and_is_not_relocated(box):
    """The path baked into the venv is the release directory's own: nothing is
    moved after the build, only the symlink."""
    assert box.build_and_publish().returncode == 0
    rel = box.opt / os.readlink(box.live)
    assert rel.is_dir() and not rel.is_symlink() and stat.S_IMODE(rel.stat().st_mode) == 0o755


# ---- the final path never lacks bin/python + willow_mcp ----------------------------

@pytest.mark.parametrize("scenario", ["migrate", "second", "rollback", "stage-check-fails"])
def test_at_no_step_does_the_final_path_lack_python_and_willow_mcp(box, scenario):
    """A DEBUG trap (functrace) checks bin/python, willow_mcp/__init__.py and the
    dist-info at $TRUST_VENV before EVERY shell command of the build and swap."""
    if scenario == "second":
        assert box.build_and_publish().returncode == 0
    pre = _ROLLBACK if scenario == "rollback" else ""
    if scenario == "stage-check-fails":
        (box.ctl / "dirty").write_text("")
    r = box.build_and_publish(instrument=True, pre=pre)
    log = (box.tmp / "inv.log").read_text()
    steps = (box.tmp / "inv.log.n").read_text().count(".")
    assert steps > 100, steps                 # the trap really ran across the whole build + swap
    assert log == "", log
    assert (r.returncode == 0) == (scenario in ("migrate", "second")), (r.stdout, r.stderr)


def test_a_concurrent_reader_never_sees_a_missing_interpreter_across_the_swap(box):
    """A thread hammers stat() + read of the live path while the swap runs, twice
    (directory -> symlink, then symlink -> symlink)."""
    bad: list[str] = []
    stop = threading.Event()
    py = box.live / "bin" / "python"
    pkg = box.live / "lib/python3.13/site-packages/willow_mcp/__init__.py"
    hits = [0]

    def poll():
        while not stop.is_set():
            try:
                os.stat(py)
                pkg.read_text()
                hits[0] += 1
            except OSError as e:
                bad.append(repr(e))

    th = threading.Thread(target=poll)
    th.start()
    try:
        for _ in range(2):
            assert box.build_and_publish().returncode == 0
    finally:
        stop.set()
        th.join()
    assert hits[0] > 100 and bad == [], (hits[0], bad[:3])


# ---- the checks follow the symlink -------------------------------------------------

def test_the_tree_check_walks_a_symlinked_venv(box):
    assert box.build_and_publish().returncode == 0
    rel = box.opt / os.readlink(box.live)
    (rel / "lib/python3.13/site-packages/bad.py").write_text("")
    os.chmod(rel / "lib/python3.13/site-packages/bad.py", 0o666)
    r = box.sh(f'tvc_tree_problems "$TRUST_VENV" {_UID}')
    assert "bad.py" in r.stdout, r.stdout
    rep = box.sh(f'tvc_report "$TRUST_VENV" "$TRUST_VENV/bin/python" {_UID} {box.tree.anchor} "$TRUST_PY_BASE"')
    assert rep.returncode == 1 and "[FAIL] everything inside" in rep.stdout


def test_the_acl_check_walks_the_directory_the_symlink_names(box):
    assert box.build_and_publish().returncode == 0
    (box.ctl / "getfacl-args").unlink(missing_ok=True)
    rel = box.opt / os.readlink(box.live)
    r = box.sh(f'tvc_acl_problems {box.tree.anchor} "$TRUST_VENV/bin/python" "$TRUST_VENV"')
    assert r.returncode == 0
    args = (box.ctl / "getfacl-args").read_text().splitlines()
    assert any(a.startswith("-R -p -s -- ") and a.endswith(str(rel)) for a in args), args


# ---- the script itself --------------------------------------------------------------

def test_provision_builds_beside_the_live_venv_and_never_deletes_it():
    body = _fn("provision_trust_venv")
    code = re.sub(r"(?m)^\s*#.*$", "", body)
    assert 'rm -rf -- "$TRUST_VENV"' not in code and "rm -rf" not in code
    assert code.index("-name 'willow_mcp-*.whl'") < code.index("mktemp -d") < code.index("tvc_build_stage") < code.index("tvc_publish")
    assert 'mktemp -d "$TRUST_VENV.rel.XXXXXXXX"' in code
    assert code.count("tvc_publish") == 1 and 'tvc_publish "$TVC_STAGE" 0 /' in code


def test_the_swap_is_one_renameat2_and_never_a_copy_or_a_delete_first():
    pub = re.sub(r"(?m)^\s*#.*$", "", _fn("tvc_publish"))
    assert "tvc_rename exchange" in pub and "tvc_rename noreplace" in pub
    assert not re.search(r"\b(cp|mv|rsync)\b", pub) and "ln -sf" not in pub
    # the old venv is removed only after the live-path check passed
    assert pub.index("tvc_report \"$live\"") < pub.index('rm -rf -- "$old"') and pub.index("tvc_report \"$live\"") < pub.index('rm -rf -- "$link"\n    fi\n  fi')
    ren = _fn("tvc_rename")
    assert "renameat2" in ren and '"exchange": 2' in ren and '"noreplace": 1' in ren


def test_unit_interpreter_path_is_unchanged():
    assert re.search(r"^TRUST_VENV=/opt/willow-operator/venv$", _INSTALL_SH, re.M)
    assert 'PY="$TRUST_VENV/bin/python"' in _INSTALL_SH


def test_the_function_extractor_catches_a_name_install_sh_does_not_define():
    """`_fn` is the scan these tests stand on: a missing function is an
    AssertionError, never an empty body that every static check would pass."""
    with pytest.raises(AssertionError):
        _fn("tvc_no_such_function")
    assert _fn("tvc_publish").startswith("tvc_publish() {")
