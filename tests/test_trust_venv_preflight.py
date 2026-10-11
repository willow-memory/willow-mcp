"""The trust owner runs its OWN root-owned, non-editable venv (operator
rulings Q7=A "split" and Q13, 2026-10-11; Loki audit BFCC5C79 F7 lineage).

Live finding that motivated it: the trust owner (`willow-operator`) ran
`$H/venvs/willow-mcp/bin/python`, a tree owned and writable by the operator
uid -- the uid the operator shell, the bot and agents run as -- and that venv
held an EDITABLE willow-mcp pointing at the operator's checkout. Anything that
could write there could rewrite code that then ran as the trust owner.

`deploy/manifest-grant/install.sh` carries the checks between
`# BEGIN trust-venv-check` and `# END trust-venv-check`. They take the uid that
counts as "root" and the directory the walk starts at as arguments (production:
0 and `/`), so these tests run the REAL shell functions against a tmp tree as an
unprivileged user. What they cannot exercise (real root, real sudo, the
network build of the wheel) is named in INSTALL.md.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_DEPLOY = _REPO / "deploy" / "manifest-grant"
_INSTALL_SH = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
_UNIT = _DEPLOY / "willow-mcp-manifest-grant.service"
_BLOCK = re.search(
    r"^# BEGIN trust-venv-check\n(.*?)^# END trust-venv-check\n", _INSTALL_SH, re.S | re.M
).group(1)

_UID = os.getuid()
_TOOLS = ("bash", "awk", "find", "stat", "readlink", "sed", "head", "grep", "cat", "dirname", "env", "sh")


def _tool_dir(tmp_path: Path, *, getfacl: str | None) -> Path:
    """A PATH holding only the tools the block needs, plus (optionally) a fake
    getfacl -- so 'getfacl absent' is testable on a box that has it."""
    d = tmp_path / "_bin"
    d.mkdir(exist_ok=True)
    for t in _TOOLS:
        real = shutil.which(t)
        assert real, t
        if not (d / t).exists():
            (d / t).symlink_to(real)
    if getfacl is not None:
        g = d / "getfacl"
        g.write_text(f"#!/bin/sh\n{getfacl}\n")
        g.chmod(0o755)
    return d


def _run(tmp_path: Path, call: str, *, getfacl: str | None = "exit 0") -> subprocess.CompletedProcess:
    script = tmp_path / "_call.sh"
    script.write_text("set -euo pipefail\n" + _BLOCK + "\n" + call + "\n")
    env = {"PATH": str(_tool_dir(tmp_path, getfacl=getfacl)), "LC_ALL": "C"}
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)


def _problems(tmp_path, fn: str, *args: str, getfacl: str | None = "exit 0") -> list[str]:
    quoted = " ".join(f"'{a}'" for a in args)
    r = _run(tmp_path, f"{fn} {quoted}", getfacl=getfacl)
    assert r.returncode == 0, r.stderr
    return [ln for ln in r.stdout.splitlines() if ln]


class _Tree:
    """anchor/opt/venv with a fake interpreter, a willow_mcp dist-info and the
    package directory. Everything is 755/644 and owned by the test user, who
    stands in for root via the ROOT_UID argument."""

    def __init__(self, tmp_path: Path):
        self.anchor = tmp_path / "anchor"
        self.venv = self.anchor / "opt" / "venv"
        self.sp = self.venv / "lib" / "python3.13" / "site-packages"
        self.py = self.venv / "bin" / "python"
        (self.venv / "bin").mkdir(parents=True)
        self.sp.mkdir(parents=True)
        (self.sp / "willow_mcp-1.2.3.dist-info").mkdir()
        (self.sp / "willow_mcp").mkdir()
        (self.sp / "willow_mcp" / "__init__.py").write_text("")
        self.py.write_text(f"#!/bin/sh\necho {self.sp}/willow_mcp/__init__.py\n")
        self.py.chmod(0o755)
        for d in [self.anchor, *self.anchor.rglob("*")]:
            if d.is_dir() and not d.is_symlink():
                d.chmod(0o755)
            elif d.is_file() and d != self.py:
                d.chmod(0o644)

    def chain(self, tmp_path, getfacl="exit 0"):
        return _problems(tmp_path, "tvc_chain_problems", str(self.anchor), str(self.py), str(_UID))


@pytest.fixture
def tree(tmp_path):
    return _Tree(tmp_path)


# ---- install.sh, the unit and INSTALL.md agree --------------------------------

def _trust_venv_in(text: str) -> str | None:
    m = re.search(r"^TRUST_VENV=(\S+)", text, re.M)
    return m.group(1) if m else None


def _trust_venv_from_install_sh() -> str:
    venv = _trust_venv_in(_INSTALL_SH)
    assert venv, "install.sh must define TRUST_VENV once"
    return venv


def _deps_not_in_pyproject(install_text: str, pyproject_text: str) -> list[str]:
    """The TRUST_VENV_DEPS specifiers pyproject.toml does not carry verbatim
    (an empty or missing array also reports, as a sentinel)."""
    m = re.search(r"^TRUST_VENV_DEPS=\((.*?)\)$", install_text, re.M)
    deps = re.findall(r'"([^"]+)"', m.group(1)) if m else []
    if not deps:
        return ["<no TRUST_VENV_DEPS>"]
    return [d for d in deps if f'"{d}"' not in pyproject_text]


def _editable_pip_lines(install_text: str) -> list[str]:
    """Executable (non-comment) lines that pip-install editable."""
    code = [ln for ln in install_text.split("set -euo pipefail", 1)[-1].splitlines() if not ln.lstrip().startswith("#")]
    return [ln for ln in code if re.search(r"pip\s+install[^\n]*\s-e\b|--editable", ln)]


def test_plant_the_trust_venv_scans_catch_their_violation():
    assert _trust_venv_in("PY=x\n") is None
    assert _trust_venv_in("TRUST_VENV=/opt/a/venv\n") == "/opt/a/venv"
    assert _deps_not_in_pyproject("nothing\n", '"x"') == ["<no TRUST_VENV_DEPS>"]
    assert _deps_not_in_pyproject('TRUST_VENV_DEPS=("a>=1" "b>=2")\n', '"a>=1"') == ["b>=2"]
    assert _deps_not_in_pyproject('TRUST_VENV_DEPS=("a>=1")\n', '"a>=1"') == []
    assert _editable_pip_lines('set -euo pipefail\n"$PY" -m pip install -e /src\n') != []
    assert _editable_pip_lines('set -euo pipefail\n# never pip install -e\n"$PY" -m pip install x\n') == []


def test_py_is_one_variable_and_lives_outside_every_operator_writable_tree():
    venv = _trust_venv_from_install_sh()
    assert re.search(r'^PY="\$TRUST_VENV/bin/python"$', _INSTALL_SH, re.M)
    assert len(re.findall(r"^PY=", _INSTALL_SH, re.M)) == 1
    assert venv.startswith("/opt/") and "$H" not in venv and "/home/" not in venv
    # the old operator-writable interpreter is not assigned or exec'd anywhere
    code = [ln for ln in _INSTALL_SH.splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if "venvs/willow-mcp" in ln], "an executable line still names $H/venvs"


def test_the_unit_and_install_sh_name_the_same_interpreter():
    venv = _trust_venv_from_install_sh()
    execs = [ln for ln in _UNIT.read_text().splitlines() if ln.startswith("ExecStart=")]
    assert execs == [f"ExecStart={venv}/bin/python -m willow_mcp manifest-grant apply"]
    assert _problems_unit(str(_UNIT), f"{venv}/bin/python") == []


def _problems_unit(unit: str, py: str) -> list[str]:
    r = subprocess.run(
        ["bash", "-c", _BLOCK + f'\ntvc_unit_problems "{unit}" "{py}"'], capture_output=True, text=True
    )
    return [ln for ln in r.stdout.splitlines() if ln]


def test_the_unit_check_refuses_a_unit_that_runs_another_interpreter(tmp_path):
    u = tmp_path / "u.service"
    u.write_text("ExecStart=/home/x/venvs/willow-mcp/bin/python -m willow_mcp manifest-grant apply\n")
    assert _problems_unit(str(u), "/opt/willow-operator/venv/bin/python")


def test_the_preflight_is_called_with_root_uid_0_and_anchor_slash():
    """The test seam must not weaken production: every real call site passes
    uid 0 and `/`, and nothing reads either from the environment."""
    calls = re.findall(r"tvc_report [^\n]*", _INSTALL_SH.split("# END trust-venv-check", 1)[1])
    assert calls and all(c.startswith('tvc_report "$TRUST_VENV" "$PY" 0 /') for c in calls), calls
    assert "ROOT_UID=${" not in _INSTALL_SH and "ANCHOR=${" not in _INSTALL_SH


def test_dependencies_mirror_pyproject_and_the_install_is_not_editable():
    assert _deps_not_in_pyproject(_INSTALL_SH, (_REPO / "pyproject.toml").read_text()) == []
    assert _editable_pip_lines(_INSTALL_SH) == []
    body = _INSTALL_SH.split("set -euo pipefail", 1)[1]
    assert "-m pip wheel" in body and "--no-deps" in body


def test_install_sh_wires_check_provision_and_enforce():
    body = _INSTALL_SH
    assert "--provision-venv" in body
    assert "enforce_trust_interpreter\n" in body.split("# END trust-venv-check", 1)[1]
    # --check reports instead of stopping, and exits non-zero on a failed line
    assert 'tvc_report "$TRUST_VENV" "$PY" 0 / || CHECK_FAILED=1' in body
    assert "exit 2" in body.split("check-only: stopping before any change --", 1)[1][:400]
    # the original F7 marker text survives
    assert "trust-owner python interpreter" in body


_INSTALL_MD_NEEDS = (
    "--provision-venv", "user:willow-operator:--x", "other::r-x", "_editable_impl_willow_mcp.pth",
    "direct_url.json", "/usr/bin/python3.14",
)


def _install_md_missing(text: str, venv: str) -> list[str]:
    """What INSTALL.md must say about the new venv and the measured box state,
    and the false claim it must no longer make (`venvs/` among the unreachable
    subtrees)."""
    missing = [n for n in (venv, *_INSTALL_MD_NEEDS) if n not in text]
    if "`store/`, `venvs/`" in text:
        missing.append("still lists venvs/ as NOT reachable")
    return missing


def test_plant_install_md_scan_catches_its_violation():
    assert _install_md_missing("nothing", "/opt/x/venv")[0] == "/opt/x/venv"
    assert "still lists venvs/ as NOT reachable" in _install_md_missing("`store/`, `venvs/`", "v")
    assert _install_md_missing(" ".join(("/opt/x/venv", *_INSTALL_MD_NEEDS)), "/opt/x/venv") == []


def test_install_md_describes_the_new_venv_and_the_box_state():
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing(text, _trust_venv_from_install_sh()) == []


# ---- path chain -----------------------------------------------------------------

def test_a_clean_chain_reports_nothing(tree, tmp_path):
    assert tree.chain(tmp_path) == []


def test_chain_refuses_a_group_writable_component(tree, tmp_path):
    (tree.anchor / "opt").chmod(0o775)
    out = tree.chain(tmp_path)
    assert any(str(tree.anchor / "opt") in ln and "group/other-writable" in ln and "775" in ln for ln in out), out


def test_chain_refuses_an_other_writable_component(tree, tmp_path):
    tree.venv.chmod(0o757)
    out = tree.chain(tmp_path)
    assert any(ln.startswith(str(tree.venv)) and "group/other-writable" in ln for ln in out), out


def test_chain_refuses_a_writable_interpreter_file(tree, tmp_path):
    tree.py.chmod(0o775)
    assert any(str(tree.py) in ln for ln in tree.chain(tmp_path))


def test_chain_refuses_every_component_when_the_owner_is_not_the_trusted_uid(tree, tmp_path):
    out = _problems(tmp_path, "tvc_chain_problems", str(tree.anchor), str(tree.py), str(_UID + 1))
    assert any("is owned by uid" in ln and f"not {_UID + 1}" in ln for ln in out), out


@pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
def test_chain_names_exactly_the_one_non_root_owned_component(tree, tmp_path):
    os.chown(tree.anchor / "opt", 4242, 4242)
    out = tree.chain(tmp_path)
    assert out == [f"{tree.anchor / 'opt'} is owned by uid 4242, not {_UID}"], out


def test_chain_follows_a_symlink_to_its_writable_target(tree, tmp_path):
    """The lexical path is clean; the symlink's real target lives under a
    group-writable directory. readlink -f must catch it."""
    shared = tree.anchor / "shared"
    shared.mkdir()
    shared.chmod(0o775)
    real = shared / "python"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    tree.py.unlink()
    tree.py.symlink_to(real)
    assert tree.chain(tmp_path) and any(str(shared) in ln and "group/other-writable" in ln for ln in tree.chain(tmp_path))


def test_chain_accepts_a_symlink_whose_target_is_clean(tree, tmp_path):
    real = tree.anchor / "usr" / "bin" / "python3"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    for d in (tree.anchor / "usr", tree.anchor / "usr" / "bin"):
        d.chmod(0o755)
    tree.py.unlink()
    tree.py.symlink_to(real)
    assert tree.chain(tmp_path) == []


def test_chain_refuses_a_missing_interpreter(tree, tmp_path):
    tree.py.unlink()
    assert tree.chain(tmp_path) == [f"no such file: {tree.py}"]


# ---- ACLs -------------------------------------------------------------------------

def test_acl_check_refuses_a_non_root_write_entry(tree, tmp_path):
    fake = f"printf '# file: {tree.venv}\\nuser::rwx\\nuser:mallory:rwx\\ngroup::r-x\\nmask::rwx\\nother::r-x\\n'"
    out = _problems(tmp_path, "tvc_acl_problems", str(tree.anchor), str(tree.py), str(tree.venv), getfacl=fake)
    assert out and "non-root write ACL" in out[0] and "user:mallory:rwx" in out[0], out


def test_acl_check_refuses_a_default_group_entry_too(tree, tmp_path):
    fake = f"printf '# file: {tree.venv}\\ndefault:group:agents:rw-\\n'"
    out = _problems(tmp_path, "tvc_acl_problems", str(tree.anchor), str(tree.py), str(tree.venv), getfacl=fake)
    assert out and "group:agents" in out[0], out


def test_acl_check_ignores_read_only_and_root_entries(tree, tmp_path):
    fake = (f"printf '# file: {tree.venv}\\nuser:willow-operator:--x\\nuser:other:r-x\\n"
            f"group:wheel:r--\\nuser:root:rwx\\n'")
    assert _problems(tmp_path, "tvc_acl_problems", str(tree.anchor), str(tree.py), str(tree.venv), getfacl=fake) == []


def test_acl_check_fails_closed_without_getfacl(tree, tmp_path):
    out = _problems(tmp_path, "tvc_acl_problems", str(tree.anchor), str(tree.py), str(tree.venv), getfacl=None)
    assert out and "cannot be performed" in out[0] and "getfacl" in out[0]


def test_acl_check_fails_closed_when_getfacl_errors(tree, tmp_path):
    out = _problems(tmp_path, "tvc_acl_problems", str(tree.anchor), str(tree.py), str(tree.venv),
                    getfacl="echo boom >&2; exit 1")
    assert out and "getfacl failed" in out[0]


# ---- the venv tree ------------------------------------------------------------------

def test_tree_check_refuses_a_world_writable_file_inside_the_venv(tree, tmp_path):
    f = tree.sp / "willow_mcp" / "__init__.py"
    f.chmod(0o666)
    out = _problems(tmp_path, "tvc_tree_problems", str(tree.venv), str(_UID))
    assert out == [f"not root-owned or writable by others: {f}"]


def test_tree_check_accepts_a_clean_tree_and_a_symlink(tree, tmp_path):
    (tree.venv / "lib64").symlink_to("lib")
    assert _problems(tmp_path, "tvc_tree_problems", str(tree.venv), str(_UID)) == []


# ---- editable installs ---------------------------------------------------------------

def _editable(tree, tmp_path):
    return _problems(tmp_path, "tvc_editable_problems", str(tree.venv))


def test_a_regular_install_is_clean(tree, tmp_path):
    assert _editable(tree, tmp_path) == []


def test_editable_refuses_an_editable_marker_for_any_package(tree, tmp_path):
    (tree.sp / "__editable__.nestor-0.1.0.pth").write_text(str(tree.anchor.parent / "nestor") + "\n")
    out = _editable(tree, tmp_path)
    assert any("editable-install marker" in ln and "nestor" in ln for ln in out), out


def test_editable_refuses_the_pip_editable_impl_marker(tree, tmp_path):
    (tree.sp / "_editable_impl_willow_mcp.pth").write_text("/elsewhere/src\n")
    assert any("_editable_impl_willow_mcp.pth" in ln for ln in _editable(tree, tmp_path))


def test_editable_refuses_direct_url_json_with_editable_true(tree, tmp_path):
    (tree.sp / "willow_mcp-1.2.3.dist-info" / "direct_url.json").write_text(
        '{"dir_info": {"editable": true}, "url": "file:///home/sean-campbell/github/willow-mcp"}'
    )
    assert any("direct_url.json" in ln for ln in _editable(tree, tmp_path))


def test_editable_accepts_a_non_editable_direct_url(tree, tmp_path):
    (tree.sp / "willow_mcp-1.2.3.dist-info" / "direct_url.json").write_text(
        '{"archive_info": {"hash": "sha256=x"}, "url": "file:///tmp/w.whl"}'
    )
    assert _editable(tree, tmp_path) == []


def test_editable_refuses_an_egg_link(tree, tmp_path):
    (tree.sp / "willow-mcp.egg-link").write_text("/elsewhere\n")
    assert any("egg-link" in ln for ln in _editable(tree, tmp_path))


def test_editable_refuses_a_pth_pointing_outside_the_venv(tree, tmp_path):
    (tree.sp / "a1_coverage.pth").write_text("/home/sean-campbell/github/x\n")
    out = _editable(tree, tmp_path)
    assert any("a1_coverage.pth" in ln and "outside the venv" in ln for ln in out), out


def test_editable_accepts_a_pth_inside_the_venv_and_an_import_line(tree, tmp_path):
    (tree.sp / "inside.pth").write_text(f"{tree.sp}/extra\nimport sys\n# comment\n")
    assert _editable(tree, tmp_path) == []


def test_editable_refuses_when_willow_mcp_is_absent(tree, tmp_path):
    shutil.rmtree(tree.sp / "willow_mcp-1.2.3.dist-info")
    assert any("willow_mcp is not installed" in ln for ln in _editable(tree, tmp_path))


# ---- the report (what --check prints) ---------------------------------------------------

def _report(tree, tmp_path, getfacl="exit 0"):
    r = _run(tmp_path, f"tvc_report '{tree.venv}' '{tree.py}' {_UID} '{tree.anchor}'", getfacl=getfacl)
    return r.returncode, r.stdout


def test_report_has_a_line_per_check_and_passes_a_clean_tree(tree, tmp_path):
    rc, out = _report(tree, tmp_path)
    assert rc == 0, out
    lines = out.splitlines()
    assert len(lines) == 6 and all(ln.startswith("  [ok]") for ln in lines), out
    for needle in ("executable", "path component", "ACL", "inside", "regular install", "imports from inside"):
        assert needle in out


@pytest.mark.parametrize("breaker, needle", [
    (lambda t: (t.anchor / "opt").chmod(0o775), "path component"),
    (lambda t: (t.sp / "willow_mcp" / "__init__.py").chmod(0o666), "inside"),
    (lambda t: (t.sp / "__editable__.x.pth").write_text("/x\n"), "regular install"),
])
def test_report_fails_and_skips_the_import_check_when_a_check_fails(tree, tmp_path, breaker, needle):
    breaker(tree)
    rc, out = _report(tree, tmp_path)
    assert rc == 1
    fail = [ln for ln in out.splitlines() if ln.startswith("  [FAIL]")]
    assert fail and needle in fail[0], out
    assert "[skip] the apply-path import check" in out


def test_report_without_an_interpreter_fails_every_line_visibly(tree, tmp_path):
    tree.py.unlink()
    rc, out = _report(tree, tmp_path)
    assert rc == 1 and out.splitlines()[0].startswith("  [FAIL] interpreter exists")
    assert "[skip]" in out


def test_report_import_check_catches_a_willow_mcp_loaded_from_outside_the_venv(tree, tmp_path):
    tree.py.write_text("#!/bin/sh\necho /home/sean-campbell/github/willow-mcp/src/willow_mcp/__init__.py\n")
    rc, out = _report(tree, tmp_path)
    assert rc == 1 and "outside the venv" in out


def test_report_fails_closed_without_getfacl(tree, tmp_path):
    rc, out = _report(tree, tmp_path, getfacl=None)
    assert rc == 1 and "[FAIL] no non-root write ACL" in out


def test_non_executable_interpreter_is_refused(tree, tmp_path):
    tree.py.chmod(0o644)
    rc, out = _report(tree, tmp_path)
    assert rc == 1 and "not executable" in out


def test_real_world_writable_stat_bits_are_what_we_test(tree):
    """Guard for the helpers above: the tree really is 755 before any breaker."""
    assert stat.S_IMODE((tree.anchor / "opt").stat().st_mode) == 0o755
