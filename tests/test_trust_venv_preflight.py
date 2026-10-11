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


def _spec_lines(in_text: str) -> list[str]:
    """The requirement specifiers of a pip-compile .in file (comments and blanks dropped)."""
    return [ln.strip() for ln in in_text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _specs_not_in_pyproject(in_text: str, pyproject_text: str) -> list[str]:
    """The .in specifiers pyproject.toml does not carry verbatim as a dependency
    (an empty file also reports, as a sentinel)."""
    specs = _spec_lines(in_text)
    if not specs:
        return ["<no specifiers>"]
    return [d for d in specs if f'"{d}"' not in pyproject_text]


def _build_requires(pyproject_text: str) -> list[str]:
    m = re.search(r"^\[build-system\]\nrequires = \[(.*?)\]", pyproject_text, re.M | re.S)
    return re.findall(r'"([^"]+)"', m.group(1)) if m else []


def _pins(txt: str) -> dict[str, str]:
    """name -> pinned version from a pip-compile --generate-hashes file."""
    return {m.group(1).lower(): m.group(2) for m in re.finditer(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+) \\$", txt, re.M)}


def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _violates(version: str, spec: str) -> bool:
    """True when VERSION breaks a `>=a,<b` style range (only those operators are used)."""
    for part in spec.split(","):
        m = re.fullmatch(r"\s*(>=|<=|<|>|==)\s*([\w.]+)\s*", part)
        assert m, f"unsupported specifier {part!r}"
        op, bound = m.groups()
        a, b = _vkey(version), _vkey(bound)
        n = max(len(a), len(b)); a += (0,) * (n - len(a)); b += (0,) * (n - len(b))
        if not {">=": a >= b, "<=": a <= b, "<": a < b, ">": a > b, "==": a == b}[op]:
            return True
    return False


def _pin_problems(in_text: str, txt: str) -> list[str]:
    """Pinned versions that break a range of the .in file, ranges with no pin, and
    any requirement / hash line that is not a plain `name==ver \\` + sha256 hashes."""
    pins, out = _pins(txt), []
    for spec in _spec_lines(in_text):
        m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)", spec)
        name, rng = m.group(1).lower(), m.group(2)
        if name not in pins:
            out.append(f"{name} has no pin")
        elif rng and _violates(pins[name], rng):
            out.append(f"{name}=={pins[name]} violates {rng}")
    for ln in txt.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*==[\w.+!-]+ \\", ln):
            continue
        elif re.fullmatch(r"    --hash=sha256:[0-9a-f]{64}( \\)?", ln):
            continue
        else:
            out.append(f"not a pin or sha256 hash line: {ln[:60]}")
    # every requirement block must carry a hash line right after it
    for m in re.finditer(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==[\w.+!-]+ \\\n((?:    --hash=sha256:\S+.*\n?)*)", txt, re.M):
        if not m.group(2).strip():
            out.append(f"{m.group(1)} has no hash")
    return out


def _editable_pip_lines(install_text: str) -> list[str]:
    """Executable (non-comment) lines that pip-install editable."""
    code = [ln for ln in install_text.split("set -euo pipefail", 1)[-1].splitlines() if not ln.lstrip().startswith("#")]
    return [ln for ln in code if re.search(r"pip\s+install[^\n]*\s-e\b|--editable", ln)]


def test_plant_the_trust_venv_scans_catch_their_violation():
    assert _trust_venv_in("PY=x\n") is None
    assert _trust_venv_in("TRUST_VENV=/opt/a/venv\n") == "/opt/a/venv"
    assert _specs_not_in_pyproject("# c\n", '"x"') == ["<no specifiers>"]
    assert _specs_not_in_pyproject("a>=1\nb>=2\n", '"a>=1"') == ["b>=2"]
    assert _specs_not_in_pyproject("# c\na>=1\n", '"a>=1"') == []
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
    pyproject = (_REPO / "pyproject.toml").read_text()
    assert _specs_not_in_pyproject((_DEPLOY / "trust-venv.requirements.in").read_text(), pyproject) == []
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


def test_editable_accepts_a_pth_inside_the_venv_and_comments(tree, tmp_path):
    (tree.sp / "inside.pth").write_text(f"{tree.sp}/extra\n\n# comment\n")
    assert _editable(tree, tmp_path) == []


# Live finding (operator box, 2026-10-11): the old trust venv held
# _ratatosk_checkout.pth = `import ratatosk_path_hook`, and that module did
# sys.path.insert(0, "<ratatosk checkout>") -- a checkout Kart tasks can write,
# ahead of the standard library, run at every interpreter start. site.py
# executes any .pth line that starts with `import ` or `import<TAB>`.

@pytest.mark.parametrize("name, content", [
    ("plain_import.pth", "import sys\n"),
    ("_ratatosk_checkout.pth", "import ratatosk_path_hook\n"),
    ("tab_import.pth", "import\tsys\n"),
    ("after_a_path.pth", "/inside/ok\nimport os; os.system('x')\n"),
    # a stock setuptools file is also refused: a clean build of this venv has no
    # setuptools and creates no .pth at all, so there is no allowlist
    ("distutils-precedence.pth", "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"),
])
def test_editable_refuses_an_executable_pth_line(tree, tmp_path, name, content):
    (tree.sp / name).write_text(content)
    out = _editable(tree, tmp_path)
    assert any(name in ln and "executable line" in ln for ln in out), out


def test_editable_refuses_a_sys_path_inserting_hook_module(tree, tmp_path):
    (tree.sp / "ratatosk_path_hook.py").write_text('import sys\nsys.path.insert(0, "/home/x/github/ratatosk")\n')
    (tree.sp / "_ratatosk_checkout.pth").write_text("import ratatosk_path_hook\n")
    out = _editable(tree, tmp_path)
    assert any("_ratatosk_checkout.pth" in ln and "executable line" in ln for ln in out), out


def test_report_fails_on_an_executable_pth_line(tree, tmp_path):
    (tree.sp / "hook.pth").write_text("import hook\n")
    rc, out = _report(tree, tmp_path)
    assert rc == 1 and "executable line" in out and "regular install" in out, out

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


# ---- privileged steps run only code from the root-owned venv ------------------
# Gap 1 (operator-approved follow-up to the venv split): install.sh used to run
# deploy/manifest-grant/{rotate_resign,sync_constitutional,seed_envelope_ratify}.py
# from $HERE -- the operator-writable checkout -- with $PY, as root or (as_to)
# as the trust owner. Whoever could edit those files got code run as root/trust
# owner, the same hole as the editable install. They now ship in the wheel as
# willow_mcp.install_steps.* and run as `$PY -I -m ...` from /opt/willow-operator/venv.

_STEPS_DIR = _REPO / "src" / "willow_mcp" / "install_steps"
_MOVED_STEPS = ("rotate_resign", "sync_constitutional", "seed_envelope_ratify")


def _code_lines(install_text: str) -> list[str]:
    body = install_text.split("set -euo pipefail", 1)[-1]
    return [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]


# A checkout path (or a script file) handed to an interpreter / shell, sourced,
# or put on PYTHONPATH. Unit/env templates that are only read (`sed`, `install`,
# `[ -f ]`, grep) are data and deliberately do not match.
_CHECKOUT_REF = r'\$\{?(?:HERE|CHECKOUT)\}?'
_CHECKOUT_EXEC = re.compile(
    r'(?:"\$\{?PY\}?"|"\$\{?TRUST_PY_BASE\}?"|\bpython3?[\d.]*|\bbash|\bsh)(?:\s+-\S+)*\s+"?' + _CHECKOUT_REF
    + r'|' + _CHECKOUT_REF + r'[^\s"]*\.(?:py|sh)\b'
    + r'|(?:^\s*|[;&|(]\s*)"?' + _CHECKOUT_REF + r'[^\s"]*"?\s*(?:$|[;&|)])'
    + r'|PYTHONPATH=[^\n]*' + _CHECKOUT_REF
    + r'|\b(?:source|\.)\s+"?' + _CHECKOUT_REF
)


def _checkout_code_executed(install_text: str) -> list[str]:
    return [ln.strip() for ln in _code_lines(install_text) if _CHECKOUT_EXEC.search(ln)]


def _py_calls_without_isolation(install_text: str) -> list[str]:
    """Interpreter calls that would put the cwd / user site / PYTHON* on sys.path
    (root runs install.sh from whatever directory the operator is in)."""
    return [
        ln.strip() for ln in _code_lines(install_text)
        if re.search(r'"\$(?:PY|TRUST_PY_BASE)"\s+(?!-I\b)-', ln) or re.search(r'"\$PY"\s+(?!-I\b)"', ln)
    ]


def test_plant_checkout_code_scans_catch_their_violation():
    pre = "set -euo pipefail\n"
    assert _checkout_code_executed(pre + '"$PY" "$HERE/rotate_resign.py" --check\n')
    assert _checkout_code_executed(pre + 'as_to FOO=1 "$PY" -I "$HERE/seed_envelope_ratify.py"\n')
    assert _checkout_code_executed(pre + 'as_op "$PY" "$CHECKOUT/x.py"\n')
    assert _checkout_code_executed(pre + 'bash "$HERE/helper.sh"\n')
    assert _checkout_code_executed(pre + 'source "$HERE/lib.sh"\n')
    assert _checkout_code_executed(pre + '. "$HERE/lib.sh"\n')
    assert _checkout_code_executed(pre + '"$HERE/helper"\n')
    assert _checkout_code_executed(pre + 'PYTHONPATH="$CHECKOUT/src" "$PY" -m x\n')
    assert _checkout_code_executed(pre + 'python3 "$CHECKOUT/x.py"\n')
    # data reads are not code
    assert _checkout_code_executed(
        pre + 'install -m 644 "$HERE/willow-mcp-manifest-grant.service" /etc/\n'
        'sed -e s/a/b/ "$HERE/manifest-grant.env" > "$T"\n'
        '[ -f "$HERE/$f" ] || stop x\n'
        'up=$(tvc_unit_problems "$HERE/willow-mcp-manifest-grant.service" "$PY")\n'
        '# "$PY" "$HERE/rotate_resign.py"\n'
    ) == []
    assert _py_calls_without_isolation(pre + '"$PY" -m pip install x\n')
    assert _py_calls_without_isolation(pre + '"$PY" - "$s" <<EOF\n')
    assert _py_calls_without_isolation(pre + '"$TRUST_PY_BASE" -m venv v\n')
    assert _py_calls_without_isolation(pre + '"$PY" -I -m pip install x\n') == []
    assert _py_calls_without_isolation(pre + '"$PY" -I - "$s" <<EOF\n') == []


def test_install_sh_runs_no_code_from_the_operator_writable_checkout():
    assert _checkout_code_executed(_INSTALL_SH) == []
    # the three steps, by name, run only as modules of the installed package
    for name in _MOVED_STEPS:
        assert not re.search(rf'"\$PY"[^\n]*{name}\.py', "\n".join(_code_lines(_INSTALL_SH))), name
        assert re.search(rf'"\$PY" -I -m willow_mcp\.install_steps\.{name}\b', _INSTALL_SH), name


def test_every_privileged_interpreter_call_is_isolated():
    assert _py_calls_without_isolation(_INSTALL_SH) == []


def _steps_layout_problems(steps_dir: Path, deploy_dir: Path, pyproject_text: str) -> list[str]:
    """The three steps must be modules of the wheel's package and absent beside install.sh."""
    out = [f"{n}.py missing from install_steps" for n in _MOVED_STEPS if not (steps_dir / f"{n}.py").is_file()]
    out += [f"{n}.py is still beside install.sh" for n in _MOVED_STEPS if (deploy_dir / f"{n}.py").exists()]
    if not (steps_dir / "__init__.py").is_file():
        out.append("install_steps/__init__.py missing")
    # the wheel takes the whole willow_mcp package, subpackages included
    if 'packages = ["src/willow_mcp"]' not in pyproject_text:
        out.append("the wheel no longer packages src/willow_mcp")
    return out


def test_plant_steps_layout_scan_catches_its_violation(tmp_path):
    steps, deploy = tmp_path / "steps", tmp_path / "deploy"
    steps.mkdir(); deploy.mkdir()
    assert len(_steps_layout_problems(steps, deploy, "")) == len(_MOVED_STEPS) + 2
    for n in _MOVED_STEPS:
        (steps / f"{n}.py").write_text("")
    (steps / "__init__.py").write_text("")
    assert _steps_layout_problems(steps, deploy, 'packages = ["src/willow_mcp"]') == []
    (deploy / "rotate_resign.py").write_text("")
    assert _steps_layout_problems(steps, deploy, 'packages = ["src/willow_mcp"]') == ["rotate_resign.py is still beside install.sh"]


def test_the_moved_steps_ship_in_the_wheel_not_in_deploy():
    assert _steps_layout_problems(_STEPS_DIR, _DEPLOY, (_REPO / "pyproject.toml").read_text(encoding="utf-8")) == []


def test_the_constitutional_seed_bundle_comes_from_the_installed_package():
    assert re.search(r'^BUNDLE_CONSTITUTIONAL="\$WILLOW_PKG_DIR/bundle/constitutional"$', _INSTALL_SH, re.M)
    assert re.search(r'^WILLOW_PKG_DIR=\$\("\$PY" -I -c ', _INSTALL_SH, re.M)
    assert not [ln for ln in _code_lines(_INSTALL_SH) if re.search(r'BUNDLE_CONSTITUTIONAL=.*CHECKOUT', ln)]


def test_the_venv_is_rebuilt_when_it_was_built_from_another_commit():
    body = _INSTALL_SH.split("provision_trust_venv() {", 1)[1].split("\n}\n", 1)[0]
    assert re.search(r'^TVC_STAMP=', _INSTALL_SH, re.M)
    assert 'rev-parse HEAD > "$TRUST_VENV/$TVC_STAMP"' in body
    skip = body.split('if [ -z "$force" ]', 1)[1].split("return 0", 1)[0]
    assert '"$head_now" = "$head_built"' in skip and '[ -n "$head_now" ]' in skip


def test_the_moved_steps_still_run_as_modules_from_an_installed_tree(tmp_path):
    """-I -m resolves each step from a package directory, with no checkout path."""
    import sys
    for name in _MOVED_STEPS:
        r = subprocess.run(
            [sys.executable, "-I", "-m", f"willow_mcp.install_steps.{name}", "--help"],
            capture_output=True, text=True, cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(_REPO / "src")},
        )
        # -I ignores PYTHONPATH: the editable install of this repo supplies the
        # package; what matters is that the module is found and its argparse runs.
        assert "No module named" not in r.stderr, (name, r.stderr)


# ---- hash-pinned dependencies and build tools -------------------------------------
# Gap 2/3: provision_trust_venv used to install psycopg2-binary / cryptography by
# range and let the wheel build pull hatchling / hatch-vcs from the index as root.
# Now both sets come from hash-pinned files (generated with uv pip compile
# --generate-hashes) and pip runs with --require-hashes --no-deps.

_RUNTIME_IN = _DEPLOY / "trust-venv.requirements.in"
_RUNTIME_TXT = _DEPLOY / "trust-venv.requirements.txt"
_BUILD_IN = _DEPLOY / "trust-venv.build-requirements.in"
_BUILD_TXT = _DEPLOY / "trust-venv.build-requirements.txt"
_H = "a" * 64


def _pip_lines(install_text: str) -> list[str]:
    """Executable lines (and their `\\` continuations) that run pip."""
    code = "\n".join(_code_lines(install_text)).replace("\\\n", " ")
    return [ln.strip() for ln in code.splitlines() if re.search(r"-m pip (?:install|wheel|download)\b", ln)]


def _unhashed_pip_lines(install_text: str) -> list[str]:
    """pip install/wheel/download calls that can fetch or install something not
    pinned by hash: a dependency install without --require-hashes /
    --only-binary / --no-deps / -r FILE, a wheel build that isolates (and so
    fetches its own backend) or may reach the index, a local-wheel install that
    may reach the index, or any version range on a pip line."""
    bad = []
    for ln in _pip_lines(install_text):
        if re.search(r"[<>]=?\d|==\d|~=", ln):
            bad.append(ln)
        elif " pip wheel " in ln:
            if not all(f in ln for f in ("--no-build-isolation", "--no-index", "--no-deps")):
                bad.append(ln)
        elif re.search(r'-r "\$', ln):
            if not all(f in ln for f in ("--require-hashes", "--only-binary=:all:", "--no-deps")):
                bad.append(ln)
        elif '"${wheels[0]}"' in ln:
            if not all(f in ln for f in ("--no-deps", "--no-index")):
                bad.append(ln)
        else:
            bad.append(ln)
    return bad


def test_the_pinned_files_are_complete_hash_pinned_and_satisfy_pyproject():
    pyproject = (_REPO / "pyproject.toml").read_text(encoding="utf-8")
    run_in, run_txt = _RUNTIME_IN.read_text(), _RUNTIME_TXT.read_text()
    assert _pin_problems(run_in, run_txt) == []
    # psycopg2-binary + cryptography and the transitive deps (cffi, pycparser), nothing else
    assert set(_pins(run_txt)) == {"psycopg2-binary", "cryptography", "cffi", "pycparser"}
    # every line that is not a comment, blank, pin or sha256 hash is a failure (above); and
    # every hash line really is sha256
    assert "--hash=sha256:" in run_txt and "--hash=md5" not in run_txt
    build_in, build_txt = _BUILD_IN.read_text(), _BUILD_TXT.read_text()
    assert _pin_problems(build_in, build_txt) == []
    assert sorted(_spec_lines(build_in)) == sorted(_build_requires(pyproject))
    assert {"hatchling", "hatch-vcs"} <= set(_pins(build_txt))
    assert _specs_not_in_pyproject(run_in, pyproject) == []


def test_plant_pin_scans_catch_their_violation():
    assert _build_requires('[build-system]\nrequires = ["a", "b>=1"]\nx = 1\n') == ["a", "b>=1"]
    assert _build_requires("nothing") == []
    pin = f"x==1.2 \\\n    --hash=sha256:{_H}\n"
    assert _pin_problems("x>=1,<2\n", pin) == []
    assert _pin_problems("x>=1,<2\n", pin.replace("1.2", "2.0")) == ["x==2.0 violates >=1,<2"]
    assert _pin_problems("x>=1,<2\n", pin.replace("1.2", "0.9")) == ["x==0.9 violates >=1,<2"]
    assert _pin_problems("y>=1\n", pin) == ["y has no pin"]
    assert _pin_problems("x\n", "x==1.2 \\\n    # via z\n") == ["x has no hash"]
    assert _pin_problems("x\n", f"x==1.2\n    --hash=sha256:{_H}\n")  # not `name==ver \\`
    assert _pin_problems("x\n", pin.replace("sha256", "md5"))
    assert _pin_problems("x\n", pin + "evil @ https://h/e.whl\n")
    assert _pin_problems("x\n", pin + "--index-url https://h/\n")
    assert _pin_problems("x\n", pin.replace(_H, "ab" * 5))
    ok = ('( umask 022; "$PY" -I -m pip install --quiet --require-hashes --only-binary=:all: --no-deps -r "$reqs" ) \\\n  || stop x\n'
          '"$X" -I -m pip wheel --quiet --no-deps --no-build-isolation --no-index --wheel-dir w s\n'
          '"$PY" -I -m pip install --quiet --no-deps --no-index "${wheels[0]}"\n')
    pre = "set -euo pipefail\n"
    assert _unhashed_pip_lines(pre + ok) == []
    assert len(_pip_lines(pre + ok)) == 3
    assert _unhashed_pip_lines(pre + '"$PY" -m pip install "psycopg2-binary>=2.9,<3.0"\n')
    assert _unhashed_pip_lines(pre + '"$PY" -m pip install psycopg2-binary\n')
    assert _unhashed_pip_lines(pre + ok.replace("--require-hashes ", ""))
    assert _unhashed_pip_lines(pre + ok.replace("--only-binary=:all: ", ""))
    assert _unhashed_pip_lines(pre + ok.replace("--no-build-isolation ", ""))
    assert _unhashed_pip_lines(pre + ok.replace("--no-index ", ""))
    assert _unhashed_pip_lines(pre + ok.replace("--no-deps --no-index", "--no-index"))
    assert _unhashed_pip_lines(pre + '"$PY" -m pip install x==1.0\n')
    assert _unhashed_pip_lines(pre + "# pip install x\n") == []


def test_install_sh_installs_only_hash_pinned_things():
    assert "TRUST_VENV_DEPS" not in _INSTALL_SH
    assert _unhashed_pip_lines(_INSTALL_SH) == []
    lines = _pip_lines(_INSTALL_SH)
    # four pip calls: build tools (hashed), wheel build, dependencies (hashed), local wheel
    assert len(lines) == 4, lines
    assert sum("--require-hashes" in ln for ln in lines) == 2
    assert 'TRUST_REQS_REL=deploy/manifest-grant/trust-venv.requirements.txt' in _INSTALL_SH
    assert 'TRUST_BUILD_REQS_REL=deploy/manifest-grant/trust-venv.build-requirements.txt' in _INSTALL_SH
    # the pinned files are read from the committed HEAD in the root-owned clone, not the working tree
    assert 'reqs="$TVC_BUILD/src/$TRUST_REQS_REL"' in _INSTALL_SH
    assert 'build_reqs="$TVC_BUILD/src/$TRUST_BUILD_REQS_REL"' in _INSTALL_SH
    assert "$HERE/trust-venv" not in _INSTALL_SH and "$CHECKOUT/deploy" not in _INSTALL_SH
    # the backend is installed before the wheel is built, the wheel built before the trust venv is touched
    body = _INSTALL_SH.split("provision_trust_venv() {", 1)[1]
    order = [body.index(k) for k in ('-r "$build_reqs"', "pip wheel", 'rm -rf -- "$TRUST_VENV"', '-r "$reqs"', '"${wheels[0]}"')]
    assert order == sorted(order), order
    # a requirements file is vetted before pip sees it
    assert body.index("tvc_requirements_problems") < body.index('-r "$build_reqs"')


def _req_problems(tmp_path: Path, content: str) -> list[str]:
    f = tmp_path / "r.txt"
    f.write_text(content)
    return _problems(tmp_path, "tvc_requirements_problems", str(f))


def test_the_requirements_guard_accepts_the_committed_files_and_refuses_redirects(tmp_path):
    for committed in (_RUNTIME_TXT, _BUILD_TXT):
        assert _req_problems(tmp_path, committed.read_text()) == [], committed
    pin = f"x==1.2 \\\n    --hash=sha256:{_H}\n"
    assert _req_problems(tmp_path, pin) == []
    for bad in (
        pin + "--index-url https://evil.example/simple\n",
        pin + "--extra-index-url https://evil.example/simple\n",
        pin + "-f https://evil.example/\n",
        pin + "-r other.txt\n",
        pin + "-e /home/x/checkout\n",
        pin + f"evil @ https://evil.example/e.whl \\\n    --hash=sha256:{_H}\n",
        pin + "y>=1 \\\n",
        f"x==1.2 \\\n    --hash=sha256:{'a' * 63}\n",
        f"x==1.2 \\\n    --hash=md5:{'a' * 32}\n",
        "x==1.2\n",
        "x==1.2 \\\n",
        f"    --hash=sha256:{_H}\n",
        "# only a comment\n",
        "",
    ):
        assert _req_problems(tmp_path, bad), bad
    assert _problems(tmp_path, "tvc_requirements_problems", str(tmp_path / "missing"))


def _install_md_pin_gaps(text: str) -> list[str]:
    need = ("uv pip compile --generate-hashes --python-version 3.14", "--python-platform x86_64-manylinux_2_28",
            "trust-venv.requirements.txt", "trust-venv.build-requirements.txt", "reviewed change",
            "--require-hashes", "--no-build-isolation")
    return [n for n in need if n not in text]


def test_plant_install_md_pin_scan_catches_its_violation():
    assert len(_install_md_pin_gaps("nothing")) == 7
    assert _install_md_pin_gaps("reviewed change") != []


def test_install_md_documents_regenerating_the_pinned_files():
    assert _install_md_pin_gaps((_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")) == []
