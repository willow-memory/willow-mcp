"""install.sh builds and installs only the commit named by --expect-head, and runs only that commit's own copy of itself.

Loki pre-deploy audit of 4d7ccbf..8963929, findings F1 and F2.

F1 (HIGH): nothing pinned WHICH commit root built, and install.sh itself (with its
inline python heredocs) was read from the operator-writable working tree. The
checkout's `.git` is read-write to Kart tasks and to the operator uid, so HEAD,
branches and packed-refs can be moved to an attacker commit. Now every mode takes
`--expect-head <40-hex sha>`; the clone is made to BE that commit; and the
clone's own copy of install.sh is exec'd before any privileged action.

F2 (MED): the root clone consulted operator-writable git configuration. Now every
root git call is `mg_git` (a neutral environment), and the clone is
`--no-local --no-checkout` followed by an explicit detached checkout of the sha.

The pre-reexec section of install.sh is plain shell between two markers, so
these tests run the REAL code: a fixture install.sh is the real section plus a
three-line tail, committed into a real git repo as the "checkout"; the
uncommitted working-tree copy differs from the committed one by a marker, which
is how "the copy that ran is the clone's, and no step ran from the tree" is shown.
(Real root, real sudo and the network wheel build are not exercised here; the
INSTALL.md procedure and the report say what a root run showed.)
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_DEPLOY = _REPO / "deploy" / "manifest-grant"
_INSTALL_PATH = _DEPLOY / "install.sh"
_INSTALL_SH = _INSTALL_PATH.read_text(encoding="utf-8")
_UNIT = (_DEPLOY / "willow-mcp-manifest-grant.service").read_text(encoding="utf-8")

_CALL = 'if [ "${1:-}" != "--dry-run-sign" ]; then\n  mg_pre_reexec 0 "$@"\nfi\n'
_SECTION = "say()  { printf" + _INSTALL_SH.split("say()  { printf", 1)[1].split(_CALL, 1)[0]
_PRE_BLOCK = _INSTALL_SH.split("# BEGIN pre-reexec\n", 1)[1].split("# END pre-reexec\n", 1)[0]
_BEFORE_CALL = _INSTALL_SH.split("set -euo pipefail\n", 1)[1].split(_CALL, 1)[0]

_BLOCK = _INSTALL_SH.split("# BEGIN trust-venv-check\n", 1)[1].split("# END trust-venv-check\n", 1)[0]

_REL = "deploy/manifest-grant/install.sh"
_ID = {"PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "LC_ALL": "C"}
_MODES = [[], ["--check"], ["--provision-venv"], ["--rotate"], ["--rotate", "--retire", "ABCDEF"], ["--check-signatures"]]
_TMP_GLOB = "/tmp/willow-mg-install.*"


def _git(cwd: Path, *a: str) -> str:
    r = subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *a],
                       cwd=cwd, capture_output=True, text=True, check=True, env=_ID)
    return r.stdout.strip()


def _harness(marker: str, tail: str = "") -> str:
    """The real pre-reexec section + a tail standing in for 'everything privileged'."""
    return f"""#!/usr/bin/env bash
set -euo pipefail
{_SECTION}
eval "$(declare -f ensure_head_clone | sed '1s/^ensure_head_clone/ensure_head_clone_real/')"
ensure_head_clone() {{ echo clone >> "$CLONE_LOG"; ensure_head_clone_real "$@"; }}
eval "$(declare -f mg_git | sed '1s/^mg_git/mg_git_real/')"
mg_git() {{ printf '%s\\n' "$*" >> "$GIT_LOG"; mg_git_real "$@"; }}
mg_pre_reexec "$(id -u)" "$@"
echo "REACHED {marker}"
echo "HEAD_SHA=$HEAD_SHA"
echo "BUILD=$TVC_BUILD"
echo "SELF=$(readlink -f "$0")"
echo "FILE=$(cat "$HEAD_CLONE/marker.txt")"
echo "MARKER_ENV=${{MG_REEXEC:-unset}}"
{tail}
"""


class _Repo:
    """A checkout with commit A, then B (HEAD, master); install.sh is the harness."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.co = tmp / "checkout"
        self.script = self.co / _REL
        self.log = tmp / "clone.log"
        self.gitlog = tmp / "git.log"
        _git(tmp, "init", "-q", "-b", "master", str(self.co))
        self.a = self.commit("committed-A", "A")
        self.b = self.commit("committed-B", "B")

    def commit(self, marker: str, content: str) -> str:
        self.script.parent.mkdir(parents=True, exist_ok=True)
        self.script.write_text(_harness(marker))
        (self.co / "marker.txt").write_text(content)
        _git(self.co, "add", "-A")
        _git(self.co, "commit", "-q", "-m", content)
        return _git(self.co, "rev-parse", "HEAD")

    def dirty_worktree_copy(self) -> Path:
        """The unpinned copy that gets typed: differs from every committed copy and,
        if it ever ran past the call, would touch `worktree-ran`."""
        self.script.write_text(_harness("WORKTREE", f'touch "{self.tmp}/worktree-ran"'))
        return self.script

    def run(self, *args: str, env: dict | None = None, script: Path | None = None) -> subprocess.CompletedProcess:
        e = {**_ID, "CLONE_LOG": str(self.log), "GIT_LOG": str(self.gitlog), **(env or {})}
        return subprocess.run(["bash", str(script or self.script), *args], capture_output=True, text=True, env=e, cwd=self.tmp)

    def clones(self) -> int:
        return len(self.log.read_text().split()) if self.log.exists() else 0

    def git_clone_calls(self) -> int:
        """`git clone` invocations made through mg_git, in either phase."""
        return sum(" clone " in f" {ln} " for ln in self.gitlog.read_text().splitlines()) if self.gitlog.exists() else 0


@pytest.fixture
def repo(tmp_path):
    return _Repo(tmp_path)


def _kv(out: str) -> dict[str, str]:
    return dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)


def _tmp_dirs() -> set[str]:
    return set(glob.glob(_TMP_GLOB))


# ---- --expect-head: required, full 40-hex, in EVERY mode ---------------------------------

def _bad_values(sha: str) -> list[str]:
    return ["", "abc1234", sha[:7], sha[:39], sha + "0", "g" * 40, "z" + sha[1:], "HEAD", "master", "HEAD~0",
            sha + "\n", " " + sha, sha[:20] + " " + sha[21:], "0x" + sha[:38], sha[:-1] + "-"]


@pytest.mark.parametrize("mode", _MODES, ids=lambda m: " ".join(m) or "plain install")
def test_every_mode_refuses_a_missing_short_or_non_hex_expect_head(repo, mode):
    before = _tmp_dirs()
    attempts = [mode]                                                       # missing
    attempts += [[*mode, "--expect-head", v] for v in _bad_values(repo.b)]
    attempts += [[*mode, "--expect-head"]]                                  # no value
    attempts += [[*mode, f"--expect-head={repo.b}"]]                        # only the two-argument form exists
    attempts += [[*mode, "--expect-head", repo.b, "--expect-head", repo.b]]  # twice
    for args in attempts:
        r = repo.run(*args)
        assert r.returncode == 2 and "STOP:" in r.stderr and "--expect-head" in r.stderr, (args, r.stdout, r.stderr)
        assert "REACHED" not in r.stdout, args
    assert repo.clones() == 0, "a clone was made although --expect-head was refused"
    assert _tmp_dirs() == before


@pytest.mark.parametrize("mode", _MODES, ids=lambda m: " ".join(m) or "plain install")
def test_every_mode_accepts_the_full_sha_and_lowercases_it(repo, mode):
    r = repo.run(*mode, "--expect-head", repo.b.upper())
    assert r.returncode == 0 and "REACHED committed-B" in r.stdout, (r.stdout, r.stderr)
    assert _kv(r.stdout)["HEAD_SHA"] == repo.b


def test_a_caller_who_is_not_root_is_refused_even_with_a_valid_pin(repo):
    """The uid is checked before anything else (production passes 0; here the caller's uid is 'wrong')."""
    script = repo.tmp / "notroot.sh"
    script.write_text(f'#!/usr/bin/env bash\nset -euo pipefail\n{_SECTION}\nmg_pre_reexec "$(( $(id -u) + 1 ))" "$@"\necho REACHED\n')
    r = repo.run("--expect-head", repo.b, script=script)
    assert r.returncode == 2 and "run as root" in r.stderr and "REACHED" not in r.stdout, (r.stdout, r.stderr)
    assert repo.git_clone_calls() == 0


def test_retire_cannot_swallow_the_flag(repo):
    """`--retire` takes the next word as its value (as the real parser does), so
    `--retire --expect-head <sha>` has NO expect-head: refused."""
    r = repo.run("--rotate", "--retire", "--expect-head", repo.b)
    assert r.returncode == 2 and "--expect-head" in r.stderr and "REACHED" not in r.stdout


@pytest.mark.parametrize("mode", _MODES, ids=lambda m: " ".join(m) or "plain install")
def test_the_real_install_sh_refuses_every_mode_without_a_valid_pin(mode, tmp_path):
    """Run the REAL file. It stops before any clone or change: either at the root
    check (an unprivileged runner) or at the pin (root)."""
    for pin in ([], ["--expect-head", "abc1234"], ["--expect-head", "HEAD"]):
        r = subprocess.run(["bash", str(_INSTALL_PATH), *mode, *pin], capture_output=True, text=True,
                           env={**_ID, "SUDO_USER": "root"}, cwd=tmp_path)
        assert r.returncode == 2 and "STOP:" in r.stderr, (mode, pin, r.stdout, r.stderr)
        assert "--expect-head" in r.stderr or "run as root" in r.stderr


def test_dry_run_sign_needs_neither_root_nor_a_pin(tmp_path):
    me = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
    r = subprocess.run(["bash", str(_INSTALL_PATH), "--dry-run-sign"], capture_output=True, text=True,
                       env={**_ID, "SUDO_USER": me}, cwd=tmp_path)
    assert r.returncode == 0 and "--dry-run-sign: the sign sequence" in r.stdout, r.stderr


# ---- a moved ref cannot redirect the build ---------------------------------------------------

def test_expect_a_builds_a_when_head_and_the_branch_are_at_b(repo):
    r = repo.run("--expect-head", repo.a)
    kv = _kv(r.stdout)
    assert r.returncode == 0 and "REACHED committed-A" in r.stdout, (r.stdout, r.stderr)
    assert kv["HEAD_SHA"] == repo.a and kv["FILE"] == "A", kv


def test_a_branch_moved_to_an_attacker_commit_does_not_redirect_it(repo):
    repo.script.write_text(_harness("EVIL"))
    (repo.co / "marker.txt").write_text("EVIL")
    _git(repo.co, "add", "-A")
    _git(repo.co, "commit", "-q", "-m", "evil")
    evil = _git(repo.co, "rev-parse", "HEAD")
    assert evil not in (repo.a, repo.b)
    (repo.co / ".git" / "packed-refs").write_text(f"{evil} refs/heads/master\n")
    for expect, marker, content in ((repo.a, "committed-A", "A"), (repo.b, "committed-B", "B")):
        r = repo.run("--expect-head", expect)
        kv = _kv(r.stdout)
        assert r.returncode == 0 and f"REACHED {marker}" in r.stdout and kv["FILE"] == content, (r.stdout, r.stderr)
        assert "EVIL" not in r.stdout


def test_a_head_pointing_somewhere_else_does_not_redirect_it(repo):
    _git(repo.co, "checkout", "-q", "--detach", repo.a)
    (repo.co / ".git" / "HEAD").write_text(repo.a + "\n")
    r = repo.run("--expect-head", repo.b)
    assert r.returncode == 0 and _kv(r.stdout)["FILE"] == "B" and _kv(r.stdout)["HEAD_SHA"] == repo.b


def test_an_expect_head_that_is_not_in_the_repo_stops(repo):
    before = _tmp_dirs()
    r = repo.run("--expect-head", "1" * 40)
    assert r.returncode == 2 and "is not a commit in" in r.stderr and "REACHED" not in r.stdout, (r.stdout, r.stderr)
    assert _tmp_dirs() == before, "the temp clone was not removed after the stop"


def test_an_expect_head_no_ref_reaches_stops(repo):
    """Every ref gone: the objects are still on disk, but nothing advertises them,
    so the pack transport sends nothing and the commit cannot be built."""
    _git(repo.co, "checkout", "-q", "--orphan", "unrelated")
    (repo.co / "marker.txt").write_text("C")
    _git(repo.co, "add", "-A")
    _git(repo.co, "commit", "-q", "-m", "unrelated root")
    _git(repo.co, "branch", "-D", "master")
    assert _git(repo.co, "for-each-ref", "--format=%(refname)") == "refs/heads/unrelated"
    r = repo.run("--expect-head", repo.a)
    assert r.returncode == 2 and "REACHED" not in r.stdout and "STOP:" in r.stderr, (r.stdout, r.stderr)


def test_a_tag_object_sha_is_not_a_commit_sha(repo):
    _git(repo.co, "tag", "-a", "-m", "t", "v1", repo.a)
    tag = _git(repo.co, "rev-parse", "v1")
    assert tag != repo.a
    r = repo.run("--expect-head", tag)
    assert r.returncode == 2 and "REACHED" not in r.stdout, (r.stdout, r.stderr)


def test_an_object_forged_under_the_expected_name_is_not_built(repo):
    """The checkout's objects/ is writable too: put B's bytes in A's file. A plain
    local clone copies the file verbatim and then `rev-parse A` still names it;
    the pack transport re-hashes on receipt, so A is simply not there."""
    a = repo.co / ".git" / "objects" / repo.a[:2] / repo.a[2:]
    b = repo.co / ".git" / "objects" / repo.b[:2] / repo.b[2:]
    assert a.exists() and b.exists()
    a.chmod(0o644)
    a.write_bytes(b.read_bytes())
    r = repo.run("--expect-head", repo.a)
    assert r.returncode == 2 and "REACHED" not in r.stdout, (r.stdout, r.stderr)


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to give the checkout to another uid")
def test_a_checkout_owned_by_another_uid_clones_through_safe_directory(repo):
    """Root cloning the operator's checkout: upload-pack runs inside the other uid's
    repository, so the one -c safe.directory must reach it (and nothing wider)."""
    for p in [repo.co, *repo.co.rglob("*")]:
        os.lchown(p, 4242, 4242)
    r = repo.run("--expect-head", repo.b)
    assert r.returncode == 0 and "REACHED committed-B" in r.stdout, (r.stdout, r.stderr)


# ---- the re-exec ------------------------------------------------------------------------------

def test_the_clones_own_copy_runs_and_the_working_tree_copy_never_gets_past_the_call(repo):
    typed = repo.dirty_worktree_copy()
    before = _tmp_dirs()
    r = repo.run("--check", "--expect-head", repo.b, script=typed)
    kv = _kv(r.stdout)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "REACHED committed-B" in r.stdout and "WORKTREE" not in r.stdout, r.stdout
    assert not (repo.tmp / "worktree-ran").exists(), "a line of the working-tree copy ran after the call"
    build = Path(kv["BUILD"])
    assert kv["SELF"] == str(build / "src" / _REL) and kv["SELF"] != str(typed.resolve())
    assert kv["MARKER_ENV"] == "unset", "the marker leaks into the privileged steps' environment"
    assert not build.exists(), "the EXIT trap was not re-installed after the exec"
    assert _tmp_dirs() == before


def test_the_clone_is_made_once_and_the_reexecd_copy_does_not_clone_again(repo):
    r = repo.run("--expect-head", repo.b)
    assert r.returncode == 0 and "REACHED committed-B" in r.stdout, (r.stdout, r.stderr)
    assert repo.clones() == 1 and repo.git_clone_calls() == 1, (repo.log.read_text(), repo.gitlog.read_text())
    # phase 2 did use git (to verify the clone) -- through mg_git, without cloning
    assert any("status" in ln for ln in repo.gitlog.read_text().splitlines())


def test_a_stale_marker_in_the_typed_copy_stops_instead_of_looping(repo):
    r = repo.run("--expect-head", repo.b, env={"MG_REEXEC": repo.b, "MG_REEXEC_BUILD": str(repo.tmp)})
    assert r.returncode == 2 and "re-exec check failed" in r.stderr and "REACHED" not in r.stdout, (r.stdout, r.stderr)
    assert repo.clones() == 0


def test_a_marker_for_another_sha_stops(repo):
    r = repo.run("--expect-head", repo.b, env={"MG_REEXEC": repo.a})
    assert r.returncode == 2 and "re-exec check failed" in r.stderr and "REACHED" not in r.stdout


def test_a_marker_without_a_build_dir_stops(repo):
    r = repo.run("--expect-head", repo.b, env={"MG_REEXEC": repo.b})
    assert r.returncode == 2 and "re-exec check failed" in r.stderr and repo.clones() == 0


# -- what the re-exec'd copy verifies about itself, one thing at a time

def _phase1_clone(repo: _Repo) -> Path:
    """Run ensure_head_clone for repo.b in a throwaway shell that keeps the dir."""
    body = f"""set -euo pipefail
{_SECTION}
CHECKOUT="{repo.co}"
ensure_head_clone "{repo.b}"
trap - EXIT
echo "$TVC_BUILD"
"""
    r = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=_ID)
    assert r.returncode == 0, r.stderr
    return Path(r.stdout.strip())


@pytest.fixture
def clone(repo):
    build = _phase1_clone(repo)
    yield repo, build
    shutil.rmtree(build, ignore_errors=True)


def _verify(repo: _Repo, build: Path, *, expect: str | None = None, marker: str | None = None,
            self_path: Path | None = None, uid: int | None = None, build_env: Path | None = None) -> list[str]:
    expect = expect or repo.b
    self_path = self_path or (build / "src" / _REL)
    env = {**_ID, "MG_REEXEC": marker if marker is not None else expect, "MG_REEXEC_BUILD": str(build_env or build)}
    body = f'set -euo pipefail\n{_SECTION}\nmg_reexec_problems "{uid if uid is not None else os.getuid()}" "{expect}" "{self_path}"\n'
    r = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return [ln for ln in r.stdout.splitlines() if ln]


def test_a_clean_clone_passes_its_own_verification(clone):
    repo, build = clone
    assert _verify(repo, build) == []


@pytest.mark.parametrize("what", ["marker differs", "not the clones file", "tracked file modified", "untracked file",
                                  "ignored file", "head moved", "clone dir group-writable", "file in clone writable",
                                  "other uid is root", "no src dir", "install.sh edited"])
def test_the_reexecd_copy_refuses_to_trust_anything_else(clone, what):
    repo, build = clone
    kw: dict = {}
    if what == "marker differs":
        kw["marker"] = repo.a
    elif what == "not the clones file":
        kw["self_path"] = repo.script
    elif what == "tracked file modified":
        (build / "src" / "marker.txt").write_text("tampered")
    elif what == "untracked file":
        (build / "src" / "extra.py").write_text("")
    elif what == "ignored file":
        (build / "src" / ".gitignore").write_text("x\n")      # a tracked-file edit as well; the ignored file below is the point
        subprocess.run(["git", "-C", str(build / "src"), "checkout", "--", ".gitignore"], env=_ID, capture_output=True)
        (build / "src" / ".git" / "info" / "exclude").write_text("ignored.txt\n")
        (build / "src" / "ignored.txt").write_text("")
    elif what == "head moved":
        _git(build / "src", "checkout", "-q", "--detach", repo.a)
    elif what == "clone dir group-writable":
        build.chmod(0o775)
    elif what == "file in clone writable":
        (build / "src" / "marker.txt").chmod(0o666)
    elif what == "other uid is root":
        kw["uid"] = os.getuid() + 1
    elif what == "no src dir":
        kw["build_env"] = build / "nope"
    elif what == "install.sh edited":
        (build / "src" / _REL).write_text("echo pwned\n")
    out = _verify(repo, build, **kw)
    assert out, f"{what}: the re-exec'd copy accepted it"


def test_the_clone_dirs_parent_must_be_root_owned_and_unwritable_or_sticky(tmp_path):
    def probe(mode: int, uid: int | None = None) -> list[str]:
        par = tmp_path / f"par{mode:o}{uid}"
        build = par / "b"
        build.mkdir(parents=True)
        par.chmod(mode)
        body = f'{_SECTION}\nmg_clone_problems "{build}" "{uid if uid is not None else os.getuid()}"\n'
        r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + body], capture_output=True, text=True, env=_ID)
        assert r.returncode == 0, r.stderr
        return [ln for ln in r.stdout.splitlines() if ln]
    assert probe(0o755) == []
    assert probe(0o1777) == []                                   # /tmp
    assert any("group/other-writable" in ln for ln in probe(0o777))
    assert any("group/other-writable" in ln for ln in probe(0o775))
    assert any("is owned by uid" in ln for ln in probe(0o755, uid=os.getuid() + 1))


# ---- the pre-reexec section is small, and nothing privileged precedes the call ---------------

def _toplevel_commands(prefix: str) -> list[str]:
    """Column-0 lines that are neither comments, blanks, function definitions nor a
    function's closing brace -- the commands the unpinned copy runs on its own."""
    out = []
    in_fn = False
    for ln in prefix.splitlines():
        if in_fn:
            in_fn = ln != "}"
        elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*\(\)\s+\{", ln):
            in_fn = not ln.rstrip().endswith("}")
        elif ln.strip() and not ln.lstrip().startswith("#"):
            out.append(ln)
    return out


def test_plant_toplevel_scan_catches_a_command_before_the_call():
    assert _toplevel_commands("f() {\n  chown x y\n}\nx=1\n# c\n\nchown root file\n") == ["x=1", "chown root file"]
    assert _toplevel_commands("f() { :; }\ng() {\n  a\n  b\n}\n") == []
    assert _toplevel_commands("if true; then\n  rm -rf /\nfi\n") == ["if true; then", "  rm -rf /", "fi"]


def test_only_assignments_and_definitions_run_before_the_call():
    assert _toplevel_commands(_BEFORE_CALL) == [
        'HEAD_CLONE=""', 'HEAD_SHA=""', 'TVC_BUILD=""',
        'MG_GIT_GLOBAL=/dev/null   # the "global" git config mg_git points at; only ensure_head_clone ever changes it, for one call',
        'MG_INSTALL_REL=deploy/manifest-grant/install.sh   # the file this is, inside the clone',
    ]


def test_the_call_is_the_first_thing_that_runs_and_is_skipped_only_for_the_dry_run():
    code = [ln for ln in _INSTALL_SH.splitlines() if not ln.lstrip().startswith("#")]
    assert sum("mg_pre_reexec 0" in ln for ln in code) == 1 and _INSTALL_SH.count(_CALL) == 1
    after = _INSTALL_SH.split(_CALL, 1)[1]
    first_commands = _toplevel_commands(after)[:2]
    assert all(re.match(r"^[A-Z_]+=", c) for c in first_commands), first_commands   # variable assignments follow
    assert _INSTALL_SH.index(_CALL) < _INSTALL_SH.index("provision_trust_venv() {") < _INSTALL_SH.index("# ---- gap 18affe49e198")


def test_the_exec_names_the_clones_install_sh_and_carries_the_marker_after_the_clone():
    body = _PRE_BLOCK.split("mg_pre_reexec() {", 1)[1].split("\n}\n", 1)[0]
    exec_text = body.split("  exec ", 1)[1]
    assert 'MG_REEXEC="$HEAD_SHA"' in exec_text and 'MG_REEXEC_BUILD="$TVC_BUILD"' in exec_text
    assert '"$BASH" "$HEAD_CLONE/$MG_INSTALL_REL" "$@"' in exec_text and 'PATH="$orig_path"' in exec_text
    assert body.index("ensure_head_clone") < body.index("  exec ")


# ---- F2: every root git call is neutral -----------------------------------------------------------

_GIT_AT_COMMAND = re.compile(
    r"(?:^|[;&|(]|\$\(|\b(?:if|then|else|elif|do|while|until)\b|\benv\b[^|;&\n]*?)\s*git\s")


def _bare_git_calls(text: str) -> list[str]:
    """Executable lines, outside mg_git's own definition, that run `git` directly."""
    body = text.split("set -euo pipefail", 1)[-1]
    body = re.sub(r"^mg_git\(\) \{.*?^\}\n", "", body, flags=re.S | re.M)
    return [ln.strip() for ln in body.splitlines() if not ln.lstrip().startswith("#") and _GIT_AT_COMMAND.search(ln)]


def _missing_from_mg_git(text: str, needles: tuple[str, ...]) -> list[str]:
    fn = text.split("mg_git() {", 1)[1].split("\n}\n", 1)[0] if "mg_git() {" in text else ""
    return [n for n in needles if n not in fn]


_NEUTRAL = ("/usr/bin/env -i", "PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1",
            "GIT_CONFIG_GLOBAL=\"$MG_GIT_GLOBAL\"", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0", "--no-pager",
            "core.fsmonitor=false", "core.hooksPath=/dev/null", "protocol.allow=never", "protocol.file.allow=always")


def test_plant_bare_git_scan_catches_its_violation():
    pre = "set -euo pipefail\n"
    for bad in ("git clone a b", "x=$(git rev-parse HEAD)", "a && git status", "/usr/bin/env -i PATH=x git clone a",
                "if git foo; then", "  git -C d log", "a | git hash-object --stdin", "( git fetch )"):
        assert _bare_git_calls(pre + bad + "\n"), bad
    for good in ("mg_git clone a b", "command -v git >/dev/null 2>&1 || stop x", "# git clone a b",
                 'stop "git is required to read the commit"', 'x=$(mg_git -C d rev-parse HEAD)', "echo digit status"):
        assert _bare_git_calls(pre + good + "\n") == [], good
    assert _bare_git_calls(pre + "mg_git() {\n  git --no-pager \"$@\"\n}\nmg_git ok\n") == []
    assert _bare_git_calls(pre + "mg_git() {\n  :\n}\ngit clone x\n") == ["git clone x"]


def test_plant_mg_git_flag_scan_catches_a_dropped_neutralizer():
    full = "mg_git() {\n  " + " ".join(_NEUTRAL) + '\n}\n'
    assert _missing_from_mg_git(full, _NEUTRAL) == []
    assert _missing_from_mg_git(full.replace("core.fsmonitor=false", ""), _NEUTRAL) == ["core.fsmonitor=false"]
    assert _missing_from_mg_git("echo nothing", _NEUTRAL) == list(_NEUTRAL)
    assert _missing_from_mg_git("x() {\n  " + " ".join(_NEUTRAL) + "\n}\n", _NEUTRAL) == list(_NEUTRAL)  # not in mg_git


def test_every_root_git_call_goes_through_mg_git():
    assert _bare_git_calls(_INSTALL_SH) == []
    assert _missing_from_mg_git(_INSTALL_SH, _NEUTRAL) == []


def test_the_clone_flags_are_the_pack_transport_without_a_checkout_then_an_explicit_detached_checkout():
    fn = _PRE_BLOCK.split("ensure_head_clone() {", 1)[1].split("\n}\n", 1)[0]
    clone = re.search(r"mg_git clone ([^\\\n]*)", fn).group(1)
    assert "--no-local" in clone and "--no-checkout" in clone and "--quiet" in clone and "--shared" not in clone
    assert "--no-hardlinks" not in clone              # meaningless with --no-local; its absence is deliberate
    assert 'checkout --quiet --detach "$expect"' in fn
    assert fn.index("clone") < fn.index("rev-parse") < fn.index("checkout --quiet --detach") < fn.index('HEAD_SHA=$(')
    # safe.directory names exactly the checkout, through a root-written file for this one call (never `*`)
    assert 'MG_GIT_GLOBAL="$TVC_BUILD/safe.gitconfig" mg_git clone' in fn and "directory = *" not in _INSTALL_SH
    assert re.search(r"^MG_GIT_GLOBAL=/dev/null\b", _INSTALL_SH, re.M)


def _hostile_world(tmp: Path) -> tuple[dict, Path]:
    """Every place git reads configuration from that something other than root can write, each naming a
    program that records itself in `m/`."""
    m = tmp / "m"
    m.mkdir()
    prog = tmp / "prog.sh"
    prog.write_text(f'#!/bin/sh\ntouch "{m}/$(basename "$0").$$"\nexit 1\n')
    prog.chmod(0o755)
    hooks = tmp / "hooks"
    hooks.mkdir()
    for h in ("post-checkout", "post-merge", "reference-transaction"):
        shutil.copy(prog, hooks / h)
    tpl = tmp / "tpl"
    (tpl / "hooks").mkdir(parents=True)
    shutil.copy(prog, tpl / "hooks" / "post-checkout")
    cfg = (f"[core]\n\tfsmonitor = {prog}\n\tpager = {prog}\n\thooksPath = {hooks}\n\tsshCommand = {prog}\n"
           f"[init]\n\ttemplateDir = {tpl}\n[uploadpack]\n\tpackObjectsHook = {prog}\n"
           f"[filter \"x\"]\n\tsmudge = {prog}\n[protocol \"ext\"]\n\tallow = always\n")
    home = tmp / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(cfg)
    (home / ".config" / "git").mkdir(parents=True)
    (home / ".config" / "git" / "config").write_text(cfg)
    for name in ("system.cfg", "global.cfg"):
        (tmp / name).write_text(cfg)
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_GLOBAL": str(tmp / "global.cfg"),
           "GIT_CONFIG_SYSTEM": str(tmp / "system.cfg"), "XDG_CONFIG_HOME": str(home / ".config"),
           "GIT_TEMPLATE_DIR": str(tpl), "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
           "GIT_CONFIG_VALUE_0": str(prog), "GIT_EXEC_PATH": "/nonexistent-exec-path", "GIT_PAGER": str(prog),
           "GIT_SSH_COMMAND": str(prog), "LC_ALL": "C"}
    return env, m


def _poison_source(repo: _Repo, m: Path) -> None:
    """The checkout's own .git/config is operator-writable too."""
    prog = m.parent / "prog.sh"
    with (repo.co / ".git" / "config").open("a") as f:
        f.write(f"[core]\n\tfsmonitor = {prog}\n\tpager = {prog}\n\thooksPath = {m.parent / 'hooks'}\n"
                f"[uploadpack]\n\tpackObjectsHook = {prog}\n[include]\n\tpath = {m.parent / 'global.cfg'}\n")


def _clone_script(repo: _Repo, git: str) -> str:
    if git == "mg_git":      # the real function, then the calls the re-exec'd copy makes
        return f"""set -euo pipefail
{_SECTION}
CHECKOUT="{repo.co}"
ensure_head_clone "{repo.b}"
mg_git -C "$HEAD_CLONE" status --porcelain --untracked-files=all --ignored >/dev/null
mg_git -C "$HEAD_CLONE" rev-parse --verify "HEAD^{{commit}}" >/dev/null
"""
    return f"""set -euo pipefail
d=$(mktemp -d)
git -c safe.directory="{repo.co}" clone --quiet --no-local --no-checkout "{repo.co}" "$d/src"
git -C "$d/src" checkout --quiet --detach "{repo.b}"
git -C "$d/src" status --porcelain >/dev/null
rm -rf "$d"
"""


def test_the_hostile_world_really_does_run_a_plain_git(repo, tmp_path):
    """Control: the same clone and checkout with a bare git DOES run the planted programs -- so the
    absence below is a result, not an artefact of the fixture."""
    env, m = _hostile_world(tmp_path)
    r = subprocess.run(["bash", "-c", _clone_script(repo, "git")], capture_output=True, text=True, env=env)
    assert list(m.iterdir()), ("nothing fired", r.stdout, r.stderr)


def test_mg_git_runs_none_of_the_planted_programs(repo, tmp_path):
    env, m = _hostile_world(tmp_path)
    _poison_source(repo, m)
    r = subprocess.run(["bash", "-c", _clone_script(repo, "mg_git")], capture_output=True, text=True, env=env)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert list(m.iterdir()) == [], [p.name for p in m.iterdir()]


def test_the_whole_pre_reexec_path_runs_none_of_them_either(repo, tmp_path):
    env, m = _hostile_world(tmp_path)
    _poison_source(repo, m)
    r = repo.run("--expect-head", repo.a, env=env)
    assert r.returncode == 0 and "REACHED committed-A" in r.stdout, (r.stdout, r.stderr)
    assert list(m.iterdir()) == [], [p.name for p in m.iterdir()]


def _clone_with_local_config(repo: _Repo, tmp: Path, config: str) -> Path:
    """A finished clone whose OWN .git/config has been made hostile (the clone dir is root's and 0700 in
    production; this is what the -c flags would still have to stop)."""
    build = _phase1_clone(repo)
    with (build / "src" / ".git" / "config").open("a") as f:
        f.write(config)
    return build


@pytest.mark.parametrize("key", ["fsmonitor", "hooksPath"])
def test_the_core_flags_override_a_hostile_config_inside_the_clone_itself(repo, tmp_path, key):
    env, m = _hostile_world(tmp_path)
    prog = tmp_path / "prog.sh"
    value = str(prog) if key == "fsmonitor" else str(tmp_path / "hooks")
    build = _clone_with_local_config(repo, tmp_path, f"[core]\n\t{key} = {value}\n")
    try:
        steps = f"""set -euo pipefail
{_SECTION}
@G@ -C "{build}/src" checkout --quiet --detach "{repo.a}"
@G@ -C "{build}/src" checkout --quiet --detach "{repo.b}"
@G@ -C "{build}/src" status --porcelain >/dev/null || true
"""
        clean = {"PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
        r = subprocess.run(["bash", "-c", steps.replace("@G@", "git")], capture_output=True, text=True, env=clean)
        assert list(m.iterdir()), ("control: a bare git ignored the clone's own hostile config", r.stderr)   # the control fires
        for p in m.iterdir():
            p.unlink()
        r = subprocess.run(["bash", "-c", steps.replace("@G@", "mg_git")], capture_output=True, text=True, env=clean)
        assert r.returncode == 0 and list(m.iterdir()) == [], (r.stderr, [p.name for p in m.iterdir()])
    finally:
        shutil.rmtree(build, ignore_errors=True)


def test_the_planted_source_config_runs_nothing_even_for_a_bare_local_clone_but_the_world_does(repo, tmp_path):
    """Where the exposure is: the environment and the home/global/system config of whoever
    runs git as root. (The source repo's own config is read by upload-pack and runs nothing.)"""
    env, m = _hostile_world(tmp_path)
    _poison_source(repo, m)
    clean = {"PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    r = subprocess.run(["bash", "-c", _clone_script(repo, "git")], capture_output=True, text=True, env=clean)
    assert r.returncode == 0 and list(m.iterdir()) == [], r.stderr


# ---- F4: the deployed unit runs python -I ----------------------------------------------------------

_EXEC = [ln for ln in _UNIT.splitlines() if ln.startswith("ExecStart=")]
_ALLOWLISTED = re.findall(r"mg_line R '\[Service\]' \"(ExecStart=[^\"]*)\"", _INSTALL_SH)


def test_the_unit_and_the_allowlist_both_say_python_dash_i():
    assert _EXEC == ["ExecStart=/opt/willow-operator/venv/bin/python -I -m willow_mcp manifest-grant apply"]
    assert _ALLOWLISTED == ["ExecStart=$py -I -m willow_mcp manifest-grant apply"]


def _service_problems(unit_text: str, tmp_path: Path) -> list[str]:
    f = tmp_path / "u.service"
    f.write_text(unit_text)
    body = (f'{_BLOCK}\nmg_service_problems "{f}" /opt/willow-operator/venv/bin/python willow-operator '
            '/home/sean-campbell/sean-data-vault/willow-operator-box /var/lib/willow-mcp/manifest-grant/gnupg /etc/willow-mcp')
    r = subprocess.run(["bash", "-c", "set -euo pipefail\n" + body], capture_output=True, text=True, env=_ID)
    assert r.returncode == 0, r.stderr
    return [ln for ln in r.stdout.splitlines() if ln]


@pytest.mark.parametrize("old, new", [
    ("python -I -m willow_mcp", "python -m willow_mcp"),
    ("python -I -m willow_mcp", "python -E -m willow_mcp"),
    ("python -I -m willow_mcp", "python -I -s -m willow_mcp"),
    ("python -I -m willow_mcp", "python -Im willow_mcp"),
    ("python -I -m willow_mcp", "python -I -c 'import x' -m willow_mcp"),
])
def test_the_allowlist_refuses_a_unit_without_exactly_python_dash_i(old, new, tmp_path):
    assert _service_problems(_UNIT, tmp_path) == []
    assert _service_problems(_UNIT.replace(old, new), tmp_path), new


# ---- the docs say so -------------------------------------------------------------------------------

_MD = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
_DOC = (_REPO / "docs" / "design" / "d2-venvs-move.md").read_text(encoding="utf-8")
_MD_NEEDS = ("git ls-remote https://github.com/willow-memory/willow-mcp", "git rev-parse HEAD", "not** a trustworthy source",
             "THE PRE-REEXEC SECTION", "--no-local", "sha256sum", "include-system-site-packages", "sitecustomize")
_DOC_NEEDS = ("Loki re-audit (REVISE 88%): F1–F4 closed", "Loki re-audit question (after REVISE 88%)", "pre-reexec section",
              "`mg_expect_head`", "`mg_git`", "`tvc_stdlib_problems`")


def _unpinned_commands(md: str) -> list[str]:
    """Lines documenting `sudo bash install.sh` with no --expect-head (a mode flag may follow on the next line)."""
    lines = md.splitlines()
    return [ln.strip() for i, ln in enumerate(lines)
            if re.search(r"sudo bash install\.sh(?!\.)", ln) and "--expect-head" not in ln + " " + (lines[i + 1] if i + 1 < len(lines) else "")]


def _docs_missing(md: str, doc: str) -> list[str]:
    return ([f"INSTALL.md: {n}" for n in _MD_NEEDS if n not in md] + [f"design doc: {n}" for n in _DOC_NEEDS if n not in doc]
            + [f"unpinned command: {c}" for c in _unpinned_commands(md)])


def test_plant_docs_scan_catches_its_violation():
    assert len(_docs_missing("", "")) == len(_MD_NEEDS) + len(_DOC_NEEDS)
    assert _unpinned_commands("    sudo bash install.sh --check\n") == ["sudo bash install.sh --check"]
    assert _unpinned_commands("    sudo bash install.sh --check --expect-head <sha>\n") == []
    assert _unpinned_commands("`sudo bash install.sh --expect-head <sha>\n--provision-venv` x\n") == []
    assert _unpinned_commands("see sudo bash install.sh.sig\n") == []


def test_install_md_and_the_design_doc_record_the_pin_and_the_stdlib_checks():
    assert _docs_missing(_MD, _DOC) == []
