"""The unit, the timer and manifest-grant.env install ONLY from the committed HEAD, validated whole.

`deploy/manifest-grant/install.sh` installs `willow-mcp-manifest-grant.service`,
`.timer` and `manifest-grant.env` into /etc as root; the service then runs as
the trust owner, so the three are code. They used to be copied from `$HERE`
(the operator-writable working tree -- writable by the operator uid, the bot and
the agents) with only `ExecStart=` checked. Now they come from the same
root-owned clone of the committed HEAD the trust venv is built from
(`ensure_head_clone`, one per run), the clone's commit must equal the venv's
`.built-from-head` stamp, and the whole unit / timer / env is checked against an
allowlist (`mg_*`, inside the `trust-venv-check` block). After the install the
files in /etc are compared to the render (`--check` reports drift).

The shell functions run here against tmp trees, as an unprivileged user, the way
tests/test_trust_venv_preflight.py runs the venv checks. What they cannot
exercise (real root, real /etc, real systemd) is named in INSTALL.md.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_DEPLOY = _REPO / "deploy" / "manifest-grant"
_INSTALL_SH = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
_BLOCK = re.search(
    r"^# BEGIN trust-venv-check\n(.*?)^# END trust-venv-check\n", _INSTALL_SH, re.S | re.M
).group(1)
_CLONE_FN = _INSTALL_SH.split("# ensure_head_clone --", 1)[1].split("# provision_trust_venv [force]", 1)[0]
_CLONE_FN = "# ensure_head_clone --" + _CLONE_FN
_ENFORCE_FN = "enforce_trust_interpreter() {" + _INSTALL_SH.split("enforce_trust_interpreter() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"

_ME = subprocess.run(["id", "-gn"], capture_output=True, text=True).stdout.strip()
_H = "/home/sean-campbell/sean-data-vault/willow-operator-box"
_GNUPG = "/var/lib/willow-mcp/manifest-grant/gnupg"
_NAMES = ("willow-mcp-manifest-grant.service", "willow-mcp-manifest-grant.timer", "manifest-grant.env")
_REL = "deploy/manifest-grant"


def _sh(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    script = tmp_path / "_t.sh"
    script.write_text("set -euo pipefail\n" + _BLOCK + "\n" + body + "\n")
    env = {"PATH": os.environ["PATH"], "LC_ALL": "C", "HOME": str(tmp_path), "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null"}
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)


def _fixture_text(venv: str, etc: str) -> dict[str, str]:
    """The committed files, with the trust owner swapped for the test user (so the
    owner/group comparisons can run unprivileged) and the venv for a tmp one."""
    out = {}
    for n in _NAMES:
        t = (_DEPLOY / n).read_text(encoding="utf-8")
        t = t.replace("User=willow-operator", f"User={_ME}").replace("Group=willow-operator", f"Group={_ME}")
        t = t.replace("WILLOW_PG_USER=willow-operator", f"WILLOW_PG_USER={_ME}")
        t = t.replace("/opt/willow-operator/venv", venv).replace("/etc/willow-mcp", etc)
        out[n] = t
    return out


def _write_files(d: Path, texts: dict[str, str]) -> None:
    d.mkdir(parents=True, exist_ok=True)
    for n, t in texts.items():
        (d / n).write_text(t, encoding="utf-8")


def _git(cwd: Path, *a: str) -> str:
    r = subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *a],
        cwd=cwd, capture_output=True, text=True, check=True,
        env={"PATH": os.environ["PATH"], "HOME": str(cwd), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )
    return r.stdout.strip()


class _Box:
    """checkout (a real git repo with the three files committed) + the tmp venv,
    /etc and systemd dirs the shell functions are pointed at."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.venv = tmp_path / "opt" / "venv"
        self.venv.mkdir(parents=True)
        self.checkout = tmp_path / "checkout"
        self.src = self.checkout / _REL
        self.etc = tmp_path / "etc"
        self.texts = _fixture_text(str(self.venv), str(self.etc))
        self.py = f"{self.venv}/bin/python"
        _write_files(self.src, self.texts)
        _git(tmp_path, "init", "-q", str(self.checkout))
        _git(self.checkout, "add", "-A")
        _git(self.checkout, "commit", "-q", "-m", "fixture")
        self.sha = _git(self.checkout, "rev-parse", "HEAD")
        self.sysd = tmp_path / "sysd"
        self.etc.mkdir()
        self.sysd.mkdir()
        self.stamp = self.venv / ".built-from-head"
        self.stamp.write_text(self.sha + "\n")

    def committed_dir(self, name: str = "clone", texts: dict[str, str] | None = None) -> Path:
        """A plain directory standing in for the HEAD clone (no git needed)."""
        d = self.tmp / name
        _write_files(d / _REL, texts or self.texts)
        return d

    def install_into_etc(self, clone: Path, pgdb: str) -> None:
        shutil.copy(clone / _REL / _NAMES[0], self.sysd / _NAMES[0])
        shutil.copy(clone / _REL / _NAMES[1], self.sysd / _NAMES[1])
        r = _sh(self.tmp, f'mg_render_env "{clone}/{_REL}/manifest-grant.env" "{pgdb}" > "{self.etc}/manifest-grant.env"')
        assert r.returncode == 0, r.stderr
        for p in (self.sysd / _NAMES[0], self.sysd / _NAMES[1]):
            p.chmod(0o644)
        (self.etc / "manifest-grant.env").chmod(0o640)

    def report(self, clone: Path, *, sha: str | None = None, pgdb: str = "willow_db") -> subprocess.CompletedProcess:
        me = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
        return _sh(
            self.tmp,
            f'mg_report "{clone}" "{self.py}" "{_ME}" "{_H}" "{_GNUPG}" "{self.etc}" "{self.sysd}" '
            f'"{self.stamp}" "{sha or self.sha}" "{pgdb}" "{me}" "{_ME}"',
        )

    def enforce(self, clone: Path, sha: str | None = None) -> subprocess.CompletedProcess:
        body = f"""
say() {{ :; }}
stop() {{ printf 'STOP: %s\\n' "$*" >&2; exit 2; }}
tvc_report() {{ return 0; }}
ensure_head_clone() {{ HEAD_CLONE="{clone}"; HEAD_SHA="{sha or self.sha}"; }}
TRUST_VENV="{self.venv}"; PY="{self.py}"; TVC_STAMP=.built-from-head
TRUST_OWNER="{_ME}"; H="{_H}"; GNUPGHOME_TO="{_GNUPG}"; ETC="{self.etc}"
{_ENFORCE_FN}
enforce_trust_interpreter
echo ENFORCED
"""
        return _sh(self.tmp, body)


@pytest.fixture
def box(tmp_path):
    return _Box(tmp_path)


def _problems(tmp_path: Path, call: str) -> list[str]:
    r = _sh(tmp_path, call)
    assert r.returncode == 0, r.stderr
    return [ln for ln in r.stdout.splitlines() if ln]


def _service_problems(box: _Box, text: str) -> list[str]:
    f = box.tmp / "u.service"
    f.write_text(text)
    return _problems(box.tmp, f'mg_service_problems "{f}" "{box.py}" "{_ME}" "{_H}" "{_GNUPG}" "{box.etc}"')


# ---- units and env come from the HEAD clone, not $HERE -----------------------------

def test_the_head_clone_holds_the_commit_not_the_working_tree(box):
    """An uncommitted edit to the unit, the timer and the env is in the working
    tree ($HERE) and NOT in the clone: it is neither validated as if installed
    nor installed."""
    (box.src / _NAMES[0]).write_text(box.texts[_NAMES[0]].replace("[Service]\n", "[Service]\nExecStartPre=/tmp/evil\n"))
    (box.src / _NAMES[1]).write_text(box.texts[_NAMES[1]] + "OnCalendar=daily\n")
    (box.src / _NAMES[2]).write_text(box.texts[_NAMES[2]] + "PYTHONPATH=/tmp/x\n")
    stage = box.tmp / "stage"
    body = f"""
say() {{ :; }}
stop() {{ printf 'STOP: %s\\n' "$*" >&2; exit 2; }}
CHECKOUT="{box.checkout}"
{_CLONE_FN}
ensure_head_clone
[ "$HEAD_SHA" = "{box.sha}" ] || {{ echo "sha mismatch $HEAD_SHA" >&2; exit 1; }}
case "$HEAD_CLONE" in "{box.checkout}"*) echo "clone is inside the checkout" >&2; exit 1 ;; esac
src="$HEAD_CLONE/{_REL}"
echo "clone-unit:$(mg_service_problems "$src/{_NAMES[0]}" "{box.py}" "{_ME}" "{_H}" "{_GNUPG}" "{box.etc}" | wc -l)"
echo "here-unit:$(mg_service_problems "{box.src}/{_NAMES[0]}" "{box.py}" "{_ME}" "{_H}" "{_GNUPG}" "{box.etc}" | wc -l)"
echo "clone-timer:$(mg_timer_problems "$src/{_NAMES[1]}" | wc -l)"
echo "here-timer:$(mg_timer_problems "{box.src}/{_NAMES[1]}" | wc -l)"
echo "clone-env:$(mg_env_problems "$src/{_NAMES[2]}" "{_ME}" "{box.etc}" "" | wc -l)"
echo "here-env:$(mg_env_problems "{box.src}/{_NAMES[2]}" "{_ME}" "{box.etc}" "" | wc -l)"
# what step 4 installs: from "$src", never from the working tree
mkdir -p "{stage}"
mg_render_env "$src/{_NAMES[2]}" db > "{stage}/env"
install -m 644 "$src/{_NAMES[0]}" "{stage}/unit"
install -m 644 "$src/{_NAMES[1]}" "{stage}/timer"
"""
    r = _sh(box.tmp, body)
    assert r.returncode == 0, r.stderr
    got = dict(ln.split(":") for ln in r.stdout.split())
    assert got["clone-unit"] == got["clone-timer"] == got["clone-env"] == "0", got
    assert int(got["here-unit"]) and int(got["here-timer"]) and int(got["here-env"]), got
    assert "ExecStartPre" not in (stage / "unit").read_text()
    assert "OnCalendar" not in (stage / "timer").read_text()
    assert "PYTHONPATH" not in (stage / "env").read_text()
    assert (stage / "unit").read_text() == box.texts[_NAMES[0]]  # exactly the committed bytes


def test_install_sh_reads_the_three_files_only_from_the_head_clone():
    code = [ln for ln in _INSTALL_SH.split("set -euo pipefail", 1)[1].splitlines() if not ln.lstrip().startswith("#")]
    here = [ln.strip() for ln in code if "$HERE" in ln or "${HERE" in ln]
    assert here == ['CHECKOUT=$(cd "$HERE/../.." && pwd)   # deploy/manifest-grant/ -> checkout root'], here
    step4 = _INSTALL_SH.split('say "== 4. $ETC and system units"', 1)[1].split("systemctl daemon-reload", 1)[0]
    assert 'MG_SRC="$HEAD_CLONE/$MG_DEPLOY_REL"' in step4
    for n in ("$MG_SERVICE", "$MG_TIMER", "$MG_ENV"):
        assert f'"$MG_SRC/{n}"' in step4, n
    assert "sed " not in "\n".join(ln for ln in step4.splitlines() if not ln.lstrip().startswith("#"))  # the env is rendered without sed (no replacement-string injection)


def test_one_git_read_path_for_the_venv_and_the_units():
    assert len(re.findall(r"\bclone --quiet\b", _INSTALL_SH)) == 1
    assert len(re.findall(r"^ensure_head_clone\(\) \{", _INSTALL_SH, re.M)) == 1
    prov = _INSTALL_SH.split("provision_trust_venv() {", 1)[1].split("\n}\n", 1)[0]
    assert "ensure_head_clone" in prov and "git " not in re.sub(r"#.*", "", prov).replace("git is required", "")
    assert '"$HEAD_CLONE/' in _INSTALL_SH.split("enforce_trust_interpreter() {", 1)[1].split("\n}\n", 1)[0]


def test_ensure_head_clone_runs_once_and_survives_a_later_commit(box):
    body = f"""
say() {{ :; }}
stop() {{ printf 'STOP: %s\\n' "$*" >&2; exit 2; }}
CHECKOUT="{box.checkout}"
{_CLONE_FN}
ensure_head_clone; first="$HEAD_SHA"; dir="$HEAD_CLONE"
git -c user.email=t@t -c user.name=t -C "{box.checkout}" commit -q --allow-empty -m later
ensure_head_clone
[ "$HEAD_SHA" = "$first" ] && [ "$HEAD_CLONE" = "$dir" ] && echo SAME
"""
    r = _sh(box.tmp, body)
    assert r.returncode == 0 and "SAME" in r.stdout, r.stderr


# ---- HEAD clone sha vs the venv stamp ------------------------------------------------

def test_a_stamp_that_differs_from_the_head_clone_is_refused(box):
    clone = box.committed_dir()
    assert "ENFORCED" in box.enforce(clone).stdout
    r = box.enforce(clone, sha="0" * 40)
    assert r.returncode == 2 and "built from" in r.stderr and "same commit" in r.stderr, r.stderr
    box.stamp.unlink()
    r = box.enforce(clone)
    assert r.returncode == 2 and "records no build commit" in r.stderr, r.stderr
    box.stamp.write_text("")
    assert box.enforce(clone).returncode == 2


def test_stamp_problems_function(box):
    q = lambda sha: _problems(box.tmp, f'mg_stamp_problems "{box.stamp}" "{sha}"')  # noqa: E731
    assert q(box.sha) == []
    assert q("1" * 40) and q("")


# ---- the whole service unit ----------------------------------------------------------

def _insert(text: str, after: str, line: str) -> str:
    assert after in text
    return text.replace(after, after + line + "\n", 1)


_SERVICE_MUTATIONS = {
    "ExecStartPre": lambda t: _insert(t, "[Service]\n", "ExecStartPre=/usr/bin/touch /tmp/x"),
    "ExecStartPost": lambda t: _insert(t, "[Service]\n", "ExecStartPost=/bin/true"),
    "ExecStop": lambda t: _insert(t, "[Service]\n", "ExecStop=/bin/true"),
    "ExecStopPost": lambda t: _insert(t, "[Service]\n", "ExecStopPost=/bin/true"),
    "ExecReload": lambda t: _insert(t, "[Service]\n", "ExecReload=/bin/true"),
    "ExecCondition": lambda t: _insert(t, "[Service]\n", "ExecCondition=/bin/true"),
    "extra Environment": lambda t: _insert(t, "[Service]\n", 'Environment="PYTHONPATH=/home/x/src"'),
    "extra EnvironmentFile": lambda t: _insert(t, "[Service]\n", "EnvironmentFile=-/home/x/env"),
    "wrong User": lambda t: t.replace(f"User={_ME}\n", "User=nobody\n"),
    "wrong Group": lambda t: t.replace(f"Group={_ME}\n", "Group=sean-campbell\n"),
    "no User": lambda t: t.replace(f"User={_ME}\n", ""),
    "changed ExecStart": lambda t: re.sub(r"^ExecStart=.*$", "ExecStart=/usr/bin/python3 -m evil", t, flags=re.M),
    "other interpreter": lambda t: re.sub(r"^ExecStart=\S+", "ExecStart=/home/x/venv/bin/python", t, flags=re.M),
    "second ExecStart": lambda t: _insert(t, "[Service]\n", "ExecStart=/bin/true"),
    "indented directive": lambda t: _insert(t, "[Service]\n", "  ExecStartPre=/bin/true"),
    "continuation": lambda t: t.replace("Type=oneshot\n", "Type=oneshot\nUMask=0027 \\\n", 1),
    "comment swallows hardening": lambda t: t.replace("NoNewPrivileges=true\n", "# note \\\nNoNewPrivileges=true\n"),
    "hardening removed": lambda t: t.replace("NoNewPrivileges=true\n", ""),
    "hardening weakened": lambda t: t.replace("ProtectSystem=strict", "ProtectSystem=full"),
    "extra ReadWritePaths": lambda t: _insert(t, "[Service]\n", "ReadWritePaths=/etc"),
    "wrong section": lambda t: _insert(t, "[Unit]\n", "ExecStartPre=/bin/true"),
    "extra section": lambda t: t + "\n[Install]\nWantedBy=multi-user.target\n",
    "new hardening-off knob": lambda t: _insert(t, "[Service]\n", "CapabilityBoundingSet="),
    "other WILLOW_HOME": lambda t: re.sub(r'^Environment="WILLOW_HOME=.*$', 'Environment="WILLOW_HOME=/home/x/box"', t, flags=re.M),
}


def test_the_committed_service_unit_is_clean(box):
    assert _service_problems(box, box.texts[_NAMES[0]]) == []


@pytest.mark.parametrize("name", sorted(_SERVICE_MUTATIONS))
def test_each_forbidden_service_directive_is_refused(box, name):
    mutated = _SERVICE_MUTATIONS[name](box.texts[_NAMES[0]])
    assert mutated != box.texts[_NAMES[0]]
    assert _service_problems(box, mutated), name
    # and install.sh's own preflight stops on it (the real enforce function, stubbed around the uid-0 checks)
    texts = dict(box.texts)
    texts[_NAMES[0]] = mutated
    r = box.enforce(box.committed_dir("mutated", texts))
    assert r.returncode == 2 and "is not the expected unit" in r.stderr and "ENFORCED" not in r.stdout, (name, r.stderr)


# ---- the timer -----------------------------------------------------------------------

def _timer_problems(box: _Box, text: str) -> list[str]:
    f = box.tmp / "t.timer"
    f.write_text(text)
    return _problems(box.tmp, f'mg_timer_problems "{f}"')


_TIMER_MUTATIONS = {
    "Unit mismatch": lambda t: t.replace("Unit=willow-mcp-manifest-grant.service", "Unit=evil.service"),
    "second Unit": lambda t: _insert(t, "[Timer]\n", "Unit=evil.service"),
    "extra OnCalendar": lambda t: _insert(t, "[Timer]\n", "OnCalendar=*:*:0/5"),
    "Persistent": lambda t: _insert(t, "[Timer]\n", "Persistent=true"),
    "missing OnBootSec": lambda t: t.replace("OnBootSec=2min\n", ""),
    "comment swallows a key": lambda t: t.replace("OnBootSec=2min\n", "# note \\\nOnBootSec=2min\n"),
    "other cadence": lambda t: t.replace("OnUnitActiveSec=60s", "OnUnitActiveSec=1s"),
    "Also in Install": lambda t: _insert(t, "[Install]\n", "Also=evil.service"),
    "other WantedBy": lambda t: t.replace("WantedBy=timers.target", "WantedBy=multi-user.target"),
    "Exec in Timer": lambda t: _insert(t, "[Timer]\n", "ExecStart=/bin/true"),
}


def test_the_committed_timer_is_clean_and_unit_is_optional(box):
    assert _timer_problems(box, box.texts[_NAMES[1]]) == []
    assert _timer_problems(box, box.texts[_NAMES[1]].replace("Unit=willow-mcp-manifest-grant.service\n", "")) == []


@pytest.mark.parametrize("name", sorted(_TIMER_MUTATIONS))
def test_each_unexpected_timer_key_is_refused(box, name):
    mutated = _TIMER_MUTATIONS[name](box.texts[_NAMES[1]])
    assert mutated != box.texts[_NAMES[1]]
    assert _timer_problems(box, mutated), name
    texts = dict(box.texts)
    texts[_NAMES[1]] = mutated
    r = box.enforce(box.committed_dir("mutated", texts))
    assert r.returncode == 2 and "is not the expected timer" in r.stderr, (name, r.stderr)


# ---- the env file --------------------------------------------------------------------

def _env_problems(box: _Box, text: str, pgdb: str = "") -> list[str]:
    f = box.tmp / "e.env"
    f.write_text(text)
    return _problems(box.tmp, f'mg_env_problems "{f}" "{_ME}" "{box.etc}" "{pgdb}"')


_ENV_MUTATIONS = {
    "unexpected key": lambda t: t + "PYTHONPATH=/home/x/src\n",
    "LD_PRELOAD": lambda t: t + "LD_PRELOAD=/tmp/x.so\n",
    "pgp fingerprint": lambda t: t + "WILLOW_PGP_FINGERPRINT=ABCD\n",
    "wrong user": lambda t: t.replace(f"WILLOW_PG_USER={_ME}", "WILLOW_PG_USER=sean-campbell"),
    "other keyring": lambda t: re.sub(r"^WILLOW_KEYRING=.*$", "WILLOW_KEYRING=/home/x/ring.json", t, flags=re.M),
    "strict removed": lambda t: t.replace("WILLOW_MCP_STRICT_TRUST_ROOT=1\n", ""),
    "strict off": lambda t: t.replace("WILLOW_MCP_STRICT_TRUST_ROOT=1", "WILLOW_MCP_STRICT_TRUST_ROOT=0"),
    "duplicate key": lambda t: t + "WILLOW_PG_USER=other\n",
    "export form": lambda t: t + "export FOO=1\n",
    "section header": lambda t: t + "[Service]\n",
    "continuation": lambda t: t + "WILLOW_X=a\\\n",
    "comment swallows a key": lambda t: t.replace("WILLOW_MCP_STRICT_TRUST_ROOT=1", "# note \\\nWILLOW_MCP_STRICT_TRUST_ROOT=1"),
}


def test_the_committed_env_is_clean(box):
    assert _env_problems(box, box.texts[_NAMES[2]]) == []


@pytest.mark.parametrize("name", sorted(_ENV_MUTATIONS))
def test_each_unexpected_env_line_is_refused(box, name):
    mutated = _ENV_MUTATIONS[name](box.texts[_NAMES[2]])
    assert mutated != box.texts[_NAMES[2]]
    assert _env_problems(box, mutated), name
    texts = dict(box.texts)
    texts[_NAMES[2]] = mutated
    r = box.enforce(box.committed_dir("mutated", texts))
    assert r.returncode == 2 and "is not the expected env file" in r.stderr, (name, r.stderr)


def test_the_render_drops_the_fingerprint_and_sets_the_db_without_interpreting_it(box):
    src = box.tmp / "src.env"
    src.write_text(box.texts[_NAMES[2]])
    out = box.tmp / "out.env"

    def render(pgdb: str) -> str:
        r = _sh(box.tmp, f'mg_render_env "{src}" \'{pgdb}\' > "{out}"')
        assert r.returncode == 0, r.stderr
        return out.read_text()

    assert "WILLOW_PG_DB=willow_db\n" in render("willow_db")
    assert _env_problems(box, render("willow_db"), "willow_db") == []
    # sed metacharacters are literal, not interpreted
    tricky = "a|b&c\\\\d"
    assert f"WILLOW_PG_DB={tricky}\n" in render(tricky)
    # a newline in $H/env's value (it is operator-writable) renders extra lines: refused
    smuggled = render("db\nPYTHONPATH=/home/x/src")
    assert "PYTHONPATH=/home/x/src" in smuggled
    assert _env_problems(box, smuggled, "db\nPYTHONPATH=/home/x/src") != []
    # a fingerprint line in the template is dropped by the render
    src.write_text(box.texts[_NAMES[2]] + "WILLOW_PGP_FINGERPRINT=ABCD\n")
    assert "WILLOW_PGP_FINGERPRINT=ABCD" not in render("db")


# ---- drift: what is in /etc against what HEAD renders ---------------------------------

def test_a_clean_install_reports_no_drift(box):
    clone = box.committed_dir()
    box.install_into_etc(clone, "willow_db")
    r = box.report(clone)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[ok]   installed unit matches committed HEAD" in r.stdout
    assert "[ok]   installed timer matches committed HEAD" in r.stdout
    assert "[ok]   installed env matches the render of committed HEAD" in r.stdout
    assert "FAIL" not in r.stdout


def test_drift_in_the_installed_unit_is_reported(box):
    clone = box.committed_dir()
    box.install_into_etc(clone, "willow_db")
    unit = box.sysd / _NAMES[0]
    unit.write_text(unit.read_text() + "ExecStartPre=/bin/true\n")
    r = box.report(clone)
    assert r.returncode == 1
    assert "[FAIL] installed unit differs from committed HEAD" in r.stdout


def test_drift_in_the_installed_timer_and_env_is_reported(box):
    clone = box.committed_dir()
    box.install_into_etc(clone, "willow_db")
    (box.sysd / _NAMES[1]).write_text("[Timer]\nOnBootSec=1s\n")
    (box.etc / "manifest-grant.env").write_text((box.etc / "manifest-grant.env").read_text() + "FOO=1\n")
    r = box.report(clone)
    assert r.returncode == 1
    assert "[FAIL] installed timer differs from committed HEAD" in r.stdout
    assert "[FAIL] installed env differs from the render of committed HEAD" in r.stdout


def test_drift_in_mode_or_a_symlink_is_reported(box):
    clone = box.committed_dir()
    box.install_into_etc(clone, "willow_db")
    (box.sysd / _NAMES[0]).chmod(0o666)
    r = box.report(clone)
    assert r.returncode == 1 and "[FAIL] installed unit differs from committed HEAD" in r.stdout
    (box.sysd / _NAMES[0]).unlink()
    (box.sysd / _NAMES[0]).symlink_to(clone / _REL / _NAMES[0])
    r = box.report(clone)
    assert r.returncode == 1 and "is a symlink" in r.stdout


def test_an_env_rendered_for_another_database_is_drift(box):
    clone = box.committed_dir()
    box.install_into_etc(clone, "another_db")
    r = box.report(clone, pgdb="willow_db")
    assert r.returncode == 1 and "[FAIL] installed env differs" in r.stdout


def test_not_yet_installed_is_info_not_a_failure(box):
    r = box.report(box.committed_dir())
    assert r.returncode == 0, r.stdout
    assert r.stdout.count("[info]") == 3 and "FAIL" not in r.stdout


def test_the_report_fails_on_a_bad_committed_file_or_stamp(box):
    texts = dict(box.texts)
    texts[_NAMES[0]] = _SERVICE_MUTATIONS["ExecStartPre"](texts[_NAMES[0]])
    r = box.report(box.committed_dir("bad", texts))
    assert r.returncode == 1 and "[FAIL] committed willow-mcp-manifest-grant.service is not the expected unit" in r.stdout
    r = box.report(box.committed_dir(), sha="f" * 40)
    assert r.returncode == 1 and "[FAIL] the venv and the units come from different commits" in r.stdout


def test_check_mode_and_step_4_are_wired_to_the_checks():
    check = _INSTALL_SH.split('if [ -n "$CHECK_ONLY" ]; then\n  say "== trust-owner interpreter', 1)[1].split("\nelse\n", 1)[0]
    assert 'mg_report "$HEAD_CLONE"' in check and "|| CHECK_FAILED=1" in check
    step4 = _INSTALL_SH.split('say "== 4. $ETC and system units"', 1)[1].split("systemctl daemon-reload", 1)[0]
    assert step4.index("mg_env_problems") < step4.index('install -o root -g "$TRUST_OWNER" -m 640')
    assert step4.index('install -o root -g root -m 644 "$MG_SRC/$MG_TIMER"') < step4.index("mg_installed_problems")
    assert "differs from the committed HEAD" in step4 and "stop " in step4
    enforce = _INSTALL_SH.split("enforce_trust_interpreter() {", 1)[1].split("\n}\n", 1)[0]
    assert enforce.index("mg_stamp_problems") < enforce.index("mg_service_problems") < enforce.index("mg_timer_problems") < enforce.index("mg_env_problems")


# ---- the docs say so ---------------------------------------------------------------------

_MD_NEEDS = ("committed HEAD", "commit before you install", "installed unit differs from committed HEAD",
             "mg_service_problems", "ExecStartPre")


def _docs_missing(md: str, doc: str) -> list[str]:
    """What INSTALL.md and the design doc's section 0 must say about the closure."""
    out = [n for n in _MD_NEEDS if n.lower() not in md.lower()]
    section0 = doc.split("## §1", 1)[0]
    if "Gap 4, closed" not in section0:
        out.append("design doc: Gap 4, closed")
    loki = section0.split("Narrow Loki re-audit question", 1)[-1].split("\n", 1)[0]
    if "unit, timer and env provenance" not in loki:
        out.append("design doc: Loki question lacks unit, timer and env provenance")
    return out


def test_plant_docs_scan_catches_its_violation():
    assert len(_docs_missing("", "")) == len(_MD_NEEDS) + 2
    good_doc = "Gap 4, closed\nNarrow Loki re-audit question | unit, timer and env provenance\n## §1"
    assert _docs_missing(" ".join(_MD_NEEDS), good_doc) == []


def test_install_md_and_the_design_doc_record_the_closure():
    md = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    doc = (_REPO / "docs" / "design" / "d2-venvs-move.md").read_text(encoding="utf-8")
    assert _docs_missing(md, doc) == []
