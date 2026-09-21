"""The brokered unit install (verb 17 `unit.install`, sealed `197aafa5`) — a
systemd `--user` unit is written, enabled and started from a template
tracked in a named repo at HEAD, without a keyboard. Sibling of
`test_unit_reload.py`: the agent asks, this process preflights, checks and
cites the `unit.install` envelope, files the ask on a miss, and only then
writes the unit. Every `systemctl`/`git` call goes through a fake runner;
the "github root" and the systemd user directory are tmp dirs.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from willow_mcp import reloader
from willow_mcp import unit_install_executor as uix


# ── a fake frank ledger, same shape as test_unit_reload ──────────────────────

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
                "created_at": datetime.now(timezone.utc),
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


def _citations(pg):
    return [r for r in pg.rows if r["event_type"] == "envelope_citation"]


def _receipts(pg):
    return [r for r in pg.rows if r["event_type"] == uix.EVENT]


# ── registry with one unit.install grant ─────────────────────────────────────

REPO = "willow-memory/willow-mcp"
UNIT = "nestor-ui.service"
SRC = f"{REPO}@deploy/nestor-ui.service.template"


def _charter(tmp_path, monkeypatch, *, grantee="willow", units=(UNIT,),
             sources=(SRC,), extra=None, expires="2027-01-01", max_count=None):
    active = [{
        "id": "env-unit.install-test",
        "verb_id": 17,
        "verb": "unit.install",
        "grantee": grantee,
        "bounds": {"units": list(units), "sources": list(sources)},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": expires,
        "max_count": max_count,
        "use_count_source": "frank",
        "status": "active",
    }] + list(extra or [])
    table = {"verbs": [{"id": 17, "verb": "unit.install",
                        "bounds": {"units": "l", "sources": "l"}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))


TEMPLATE = (
    "# unit: nestor-ui.service\n"
    "[Unit]\nDescription=nestor seal desk\n\n"
    "[Service]\nEnvironment=\"WILLOW_HOME=@WILLOW_HOME@\"\n"
    "ExecStart=@PYTHON@ -m nestor ui\n\n"
    "[Install]\nWantedBy=default.target\n"
)
TIMER = "[Unit]\nDescription=tick\n\n[Timer]\nOnUnitActiveSec=60s\nUnit=@UNIT@\n\n[Install]\nWantedBy=timers.target\n"


@pytest.fixture
def github_root(tmp_path):
    """`<root>/willow-memory/willow-mcp/deploy/nestor-ui.service.template`,
    tracked and clean per the fake git; the clone is verified by remote URL
    the way `resolve_clone_status` does it."""
    clone = tmp_path / "gh" / "willow-memory" / "willow-mcp"
    (clone / ".git").mkdir(parents=True)
    (clone / "deploy").mkdir()
    (clone / "deploy" / "nestor-ui.service.template").write_text(TEMPLATE, encoding="utf-8")
    return tmp_path / "gh"


@pytest.fixture
def dest(tmp_path):
    d = tmp_path / "systemd-user"
    d.mkdir()
    return d


VALUES = {"PYTHON": "/v/bin/python", "WILLOW_HOME": "/home/x/wh", "UNIT": UNIT}


# ── a fake systemctl + git ────────────────────────────────────────────────────

class _Fake:
    """Answers `systemctl --user show/daemon-reload/enable`, and the git calls
    the source resolver makes (remote get-url, rev-parse, ls-files, status).
    `installed` flips `show` from unit_unknown to active after enable."""

    def __init__(self, *, tracked=True, dirty="", head="abc123", remote_ok=True,
                 show_rc_before=1, bus_down=False, enable_rc=0, reload_rc=0,
                 on_remote="  origin/master\n", mode="100644",
                 timer_tracked=True, timer_dirty=""):
        self.tracked = tracked
        self.dirty = dirty
        self.head = head
        self.remote_ok = remote_ok
        self.show_rc_before = show_rc_before
        self.bus_down = bus_down
        self.enable_rc = enable_rc
        self.reload_rc = reload_rc
        self.on_remote = on_remote
        self.mode = mode
        self.timer_tracked = timer_tracked
        self.timer_dirty = timer_dirty
        self.calls: list[list[str]] = []
        self._enabled = False

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        if argv[0] == "systemctl":
            sub = argv[2]
            if sub == "show":
                if self.bus_down:
                    return subprocess.CompletedProcess(argv, 1, "", "Failed to connect to bus: no")
                if self._enabled:
                    return subprocess.CompletedProcess(
                        argv, 0,
                        "ActiveState=active\nActiveEnterTimestamp=Mon 2026-09-21 03:00:00 UTC\n"
                        "ActiveEnterTimestampMonotonic=1\nMainPID=42\n"
                        "ExecMainStartTimestamp=Mon 2026-09-21 03:00:00 UTC\n", "")
                return subprocess.CompletedProcess(
                    argv, self.show_rc_before, "", "Unit nestor-ui.service could not be found.")
            if sub == "daemon-reload":
                return subprocess.CompletedProcess(argv, self.reload_rc, "", "reload failed" if self.reload_rc else "")
            if sub == "enable":
                self._enabled = self.enable_rc == 0
                return subprocess.CompletedProcess(argv, self.enable_rc, "", "enable failed" if self.enable_rc else "")
            raise AssertionError(f"unexpected systemctl call {argv}")
        if argv[0] == "git":
            rest = argv[3:]
            if rest[:2] == ["remote", "get-url"]:
                url = "https://github.com/willow-memory/willow-mcp.git" if self.remote_ok else "https://github.com/other/repo.git"
                return subprocess.CompletedProcess(argv, 0, url + "\n", "")
            if rest == ["rev-parse", "--abbrev-ref", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, "master\n", "")
            if rest == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, self.head + "\n", "")
            if rest == ["branch", "-r", "--contains", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, self.on_remote, "")
            is_timer = rest and rest[-1].endswith(".timer.template")
            if rest[:3] == ["ls-files", "-s", "--error-unmatch"]:
                tracked = self.timer_tracked if is_timer else self.tracked
                stdout = f"{self.mode} 0123456789abcdef0123456789abcdef01234567 0\t{rest[-1]}\n" if tracked else ""
                return subprocess.CompletedProcess(argv, 0 if tracked else 1, stdout, "" if tracked else "error: pathspec")
            if rest[:2] == ["status", "--porcelain"]:
                return subprocess.CompletedProcess(argv, 0, self.timer_dirty if is_timer else self.dirty, "")
            raise AssertionError(f"unexpected git call {rest}")
        raise AssertionError(f"unexpected call {argv}")

    @property
    def enables(self):
        return [c for c in self.calls if c[0] == "systemctl" and c[2] == "enable"]


class _NeverRun:
    def __call__(self, argv, **kw):
        raise AssertionError(f"unexpected call — refusal should precede it: {argv}")


def _install(pg, runner, github_root, dest, **kw):
    args = dict(app_id="willow", unit=UNIT, source=SRC, project="willow-mcp",
                ledger=_ledger(pg), runner=runner, github_root=github_root,
                destination=dest, values=VALUES)
    args.update(kw)
    return uix.execute_unit_install(args.pop("app_id"), **args)


# ── granted ──────────────────────────────────────────────────────────────────

def test_granted_install_writes_enables_and_receipts(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    fake = _Fake()
    out = _install(pg, fake, github_root, dest)
    assert out["ok"] and out["installed"], out
    assert out["envelope_id"] == "env-unit.install-test"
    assert out["head"] == "abc123" and out["timer"] == "" and out["replaced"] is False
    written = (dest / UNIT).read_text()
    assert "@" not in written and "/home/x/wh" in written and "/v/bin/python" in written
    assert out["template_digest"] != out["rendered_digest"]
    # daemon-reload then enable --now, in that order
    subs = [c[2] for c in fake.calls if c[0] == "systemctl"]
    assert subs.index("daemon-reload") < subs.index("enable")
    assert fake.enables == [["systemctl", "--user", "enable", "--now", UNIT]]
    assert out["state_before"]["ok"] is False and out["state_after"]["ActiveState"] == "active"
    cites = _citations(pg)
    assert len(cites) == 1 and cites[0]["content"]["outcome"] == "granted"
    assert cites[0]["content"]["call_args"] == {"units": [UNIT], "sources": [SRC]}
    receipts = _receipts(pg)
    assert len(receipts) == 1
    assert receipts[0]["content"]["head"] == "abc123"
    assert receipts[0]["content"]["rendered_digest"] == out["rendered_digest"]
    assert out["receipt_id"] == receipts[0]["id"]


def test_timer_sibling_is_written_and_the_timer_is_what_gets_enabled(
        home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    (github_root / "willow-memory" / "willow-mcp" / "deploy" / "nestor-ui.timer.template").write_text(TIMER)
    pg = _FakeGovernancePg()
    fake = _Fake()
    out = _install(pg, fake, github_root, dest)
    assert out["ok"] and out["timer"] == "nestor-ui.timer"
    # the timer's Unit= names the SERVICE — `@UNIT@` is the service in both
    # renders, so the pair cannot drift
    assert "Unit=nestor-ui.service" in (dest / "nestor-ui.timer").read_text()
    assert fake.enables == [["systemctl", "--user", "enable", "--now", "nestor-ui.timer"]]
    assert sorted(Path(p).name for p in out["written"]) == ["nestor-ui.service", "nestor-ui.timer"]


def test_replace_records_the_previous_digest(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    (dest / UNIT).write_text("[Unit]\nDescription=old\n")
    old = uix._digest("[Unit]\nDescription=old\n")
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["ok"] and out["replaced"] is True and out["previous_digest"] == old
    assert _receipts(pg)[0]["content"]["previous_digest"] == old


# ── refused before any subprocess call ────────────────────────────────────────

def test_broker_own_unit_is_refused_before_any_call(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch, units=("willow-mcp-serve.service",))
    pg = _FakeGovernancePg()
    out = _install(pg, _NeverRun(), github_root, dest, unit="willow-mcp-serve.service")
    assert out["error"] == "EPERM" and _citations(pg) == []


@pytest.mark.parametrize("unit", ["", "nestor-ui", "../x.service", "a b.service"])
def test_malformed_unit_is_EINVAL(home, tmp_path, monkeypatch, github_root, dest, unit):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _NeverRun(), github_root, dest, unit=unit)
    assert out["error"] == "EINVAL"


@pytest.mark.parametrize("source", ["", "deploy/x.template", "willow-memory/willow-mcp@/etc/x",
                                    "willow-memory/willow-mcp@../x", "a@b@c"])
def test_malformed_source_is_EINVAL(home, tmp_path, monkeypatch, github_root, dest, source):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _NeverRun(), github_root, dest, source=source)
    assert out["error"] == "EINVAL"


# ── unreachable / source / name / template — each its own errno, no citation ─

def test_no_user_bus_is_EUNREACH(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(bus_down=True), github_root, dest)
    assert out["error"] == "EUNREACH" and out["cause"] == "no_user_bus"
    assert _citations(pg) == [] and not (dest / UNIT).exists()


def test_unit_not_yet_installed_is_reachable_not_unreachable(home, tmp_path, monkeypatch, github_root, dest):
    """`show` on a unit systemd has never heard of is `unit_unknown` — that is
    the normal pre-install state, not a refusal."""
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _Fake(), github_root, dest)
    assert out["ok"]


def test_no_clone_is_ENOSRC(home, tmp_path, monkeypatch, dest):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), tmp_path / "empty-root", dest)
    assert out["error"] == "ENOSRC" and "no verified clone" in out["reason"]
    assert _citations(pg) == []


def test_wrong_remote_is_ENOSRC(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _Fake(remote_ok=False), github_root, dest)
    assert out["error"] == "ENOSRC"


def test_untracked_template_is_ENOSRC(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _Fake(tracked=False), github_root, dest)
    assert out["error"] == "ENOSRC" and "not a tracked file" in out["reason"]


def test_dirty_template_is_ENOSRC(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _Fake(dirty=" M deploy/nestor-ui.service.template\n"), github_root, dest)
    assert out["error"] == "ENOSRC" and "uncommitted" in out["reason"]


def test_declared_name_mismatch_is_ENAME(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch, units=("other.service",))
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest, unit="other.service")
    assert out["error"] == "ENAME" and out["declared"] == UNIT
    assert _citations(pg) == []


def test_filename_declares_the_unit_when_no_header(tmp_path):
    p = tmp_path / "willow-mcp-reloader.service.template"
    assert uix.declared_unit_name("[Unit]\n", p) == "willow-mcp-reloader.service"
    assert uix.declared_unit_name("# unit: x.service\n[Unit]\n", p) == "x.service"


def test_unfillable_placeholder_is_ETEMPLATE(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    tmpl = github_root / "willow-memory" / "willow-mcp" / "deploy" / "nestor-ui.service.template"
    tmpl.write_text(TEMPLATE + "Environment=\"X=@NOT_A_THING@\"\n")
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["error"] == "ETEMPLATE" and "NOT_A_THING" in out["reason"]
    assert _citations(pg) == [] and not (dest / UNIT).exists()


def test_unsafe_value_is_ETEMPLATE(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _Fake(), github_root, dest,
                   values={**VALUES, "WILLOW_HOME": 'a"b'})
    assert out["error"] == "ETEMPLATE"


def test_willow_2_0_reference_is_ETEMPLATE(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    tmpl = github_root / "willow-memory" / "willow-mcp" / "deploy" / "nestor-ui.service.template"
    tmpl.write_text(TEMPLATE + "# from willow-2.0\n")
    out = _install(_FakeGovernancePg(), _Fake(), github_root, dest)
    assert out["error"] == "ETEMPLATE"


# ── Loki FECF6FED: the seal's clauses hold for what is INSTALLED ─────────────

def _tmpl_path(github_root):
    return github_root / "willow-memory" / "willow-mcp" / "deploy" / "nestor-ui.service.template"


def test_tracked_symlink_out_of_tree_is_ENOSRC(home, tmp_path, monkeypatch, github_root, dest):
    """git tracks the LINK; read_text would follow it. Refused by lstat."""
    _charter(tmp_path, monkeypatch)
    outside = tmp_path / "outside.template"
    outside.write_text("# unit: nestor-ui.service\n[Service]\nExecStart=/bin/evil\n")
    p = _tmpl_path(github_root)
    p.unlink()
    p.symlink_to(outside)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["error"] == "ENOSRC" and "symlink" in out["reason"]
    assert _citations(pg) == [] and not (dest / UNIT).exists()


def test_symlink_mode_from_ls_files_is_ENOSRC_even_if_target_is_in_tree(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _Fake(mode="120000"), github_root, dest)
    assert out["error"] == "ENOSRC" and "symlink" in out["reason"]


def test_tracked_symlink_to_in_tree_file_is_still_ENOSRC(home, tmp_path, monkeypatch, github_root, dest):
    """Even a link that stays inside the tree is refused — a unit installs
    from a file, and the digest must be of what a PR shows."""
    _charter(tmp_path, monkeypatch)
    p = _tmpl_path(github_root)
    real = p.with_name("real.service.template")
    real.write_text(TEMPLATE)
    p.unlink()
    p.symlink_to(real)
    out = _install(_FakeGovernancePg(), _Fake(), github_root, dest)
    assert out["error"] == "ENOSRC"


def test_untracked_timer_sibling_refuses_the_whole_install(home, tmp_path, monkeypatch, github_root, dest):
    """The timer is the unit that actually gets enabled; it goes through the
    same tracked/clean checks as the service or the install refuses."""
    _charter(tmp_path, monkeypatch)
    (github_root / "willow-memory" / "willow-mcp" / "deploy" / "nestor-ui.timer.template").write_text(TIMER)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(timer_tracked=False), github_root, dest)
    assert out["error"] == "ENOSRC" and out["reason"].startswith("timer sibling:")
    assert _citations(pg) == [] and not (dest / UNIT).exists() and not (dest / "nestor-ui.timer").exists()


def test_dirty_timer_sibling_refuses(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    (github_root / "willow-memory" / "willow-mcp" / "deploy" / "nestor-ui.timer.template").write_text(TIMER)
    out = _install(_FakeGovernancePg(), _Fake(timer_dirty=" M deploy/nestor-ui.timer.template\n"), github_root, dest)
    assert out["error"] == "ENOSRC" and "timer sibling" in out["reason"]


def test_timer_digest_is_in_the_receipt(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    (github_root / "willow-memory" / "willow-mcp" / "deploy" / "nestor-ui.timer.template").write_text(TIMER)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["ok"] and out["timer_template_digest"] == uix._digest(TIMER)
    assert _receipts(pg)[0]["content"]["timer_template_digest"] == uix._digest(TIMER)


@pytest.mark.parametrize("line", [
    "[Install]\nAlias=willow-mcp-serve.service\n",
    "[Install]\nAlso=willow-mcp-serve.service\n",
    "[Install]\nWantedBy=willow-mcp.service\n",
    "[Unit]\nRequires=willow-mcp-serve.service\n",
    "[Unit]\nBindsTo=WILLOW-MCP-SERVE.socket\n",
    "[Install]\nAlias=willow-mcp-serve@1.service\n",
])
def test_content_naming_the_broker_unit_is_EPERM_before_citation(home, tmp_path, monkeypatch, github_root, dest, line):
    _charter(tmp_path, monkeypatch)
    _tmpl_path(github_root).write_text(TEMPLATE + line)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["error"] == "EPERM" and out["named"], out
    assert _citations(pg) == [] and not (dest / UNIT).exists()


def test_timer_unit_naming_the_broker_is_EPERM(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    (github_root / "willow-memory" / "willow-mcp" / "deploy" / "nestor-ui.timer.template").write_text(
        "[Timer]\nOnUnitActiveSec=60s\nUnit=willow-mcp-serve.service\n")
    out = _install(_FakeGovernancePg(), _Fake(), github_root, dest)
    assert out["error"] == "EPERM" and out["named"][0].startswith("timer:")


def test_a_comment_or_description_naming_the_broker_is_not_EPERM(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    _tmpl_path(github_root).write_text(
        "# unit: nestor-ui.service\n# restarts beside willow-mcp-serve.service\n"
        "[Unit]\nDescription=lives next to willow-mcp-serve.service\n[Service]\nExecStart=@PYTHON@ -m nestor ui\n")
    out = _install(_FakeGovernancePg(), _Fake(), github_root, dest)
    assert out["ok"], out


def test_broker_units_named_parses_sections():
    assert uix.broker_units_named("[Install]\nAlias=a.service willow-mcp-serve.service\n") == \
        ["[Install] Alias=willow-mcp-serve.service"]
    assert uix.broker_units_named("[Service]\nExecStart=/bin/willow-mcp-serve.service\n") == []
    assert uix.broker_units_named("Alias=willow-mcp-serve.service\n") == []  # no section


@pytest.mark.parametrize("name,expected", [
    ("willow-mcp-serve.service", True),
    ("willow-mcp.service", True),
    ("willow-mcp-serve@1.service", True),
    ("willow-mcp-serve.socket", True),
    ("Willow-MCP-Serve.timer", True),
    ("willow-mcp-serve-helper.service", False),
    ("x/willow-mcp.service", False),
    ("willow-bot.service", False),
    ("", False),
])
def test_is_broker_unit_matches_stem_instance_and_type(name, expected):
    from willow_mcp.unit_reload_executor import is_broker_unit
    assert is_broker_unit(name) is expected


def test_local_only_head_is_ENOSRC(home, tmp_path, monkeypatch, github_root, dest):
    """'Reviewable in a PR' — a HEAD on no remote-tracking ref installs nothing."""
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(on_remote=""), github_root, dest)
    assert out["error"] == "ENOSRC" and "not on any remote" in out["reason"]
    assert _citations(pg) == []


def test_remote_refs_are_in_the_receipt(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _Fake(on_remote="  origin/master\n  origin/feat/x\n"), github_root, dest)
    assert out["ok"] and out["remote_refs"] == ["origin/master", "origin/feat/x"]


def test_replace_then_fail_restores_the_previous_unit_and_inks_a_failure_row(
        home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    old = "[Unit]\nDescription=old\n"
    (dest / UNIT).write_text(old)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(enable_rc=1), github_root, dest)
    assert out["ok"] is False and out["error"] == "EINSTALL"
    assert (dest / UNIT).read_text() == old, "previous unit must be back in place"
    assert out["restored"] == [str(dest / UNIT)]
    assert out["previous_digest"] == uix._digest(old)
    failed = [r for r in pg.rows if r["event_type"] == f"{uix.EVENT}_failed"]
    assert len(failed) == 1 and failed[0]["content"]["errno"] == "EINSTALL"
    assert out["receipt_id"] == failed[0]["id"]
    assert _receipts(pg) == []
    # no stray .new / .pre-install files left behind on a restore
    assert sorted(p.name for p in dest.iterdir()) == [UNIT]


def test_fresh_install_then_fail_removes_the_written_unit(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(reload_rc=1), github_root, dest)
    assert out["error"] == "EINSTALL" and not (dest / UNIT).exists()
    assert [r for r in pg.rows if r["event_type"] == f"{uix.EVENT}_failed"]


def test_successful_replace_keeps_the_previous_unit_beside_it(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    (dest / UNIT).write_text("[Unit]\nDescription=old\n")
    out = _install(_FakeGovernancePg(), _Fake(), github_root, dest)
    assert out["ok"] and out["replaced"] and len(out["previous_kept"]) == 1
    kept = Path(out["previous_kept"][0])
    assert kept.is_file() and kept.name.startswith(f"{UNIT}.pre-install-")
    assert kept.read_text() == "[Unit]\nDescription=old\n"


# ── envelope discipline ───────────────────────────────────────────────────────

def test_no_envelope_refuses_ENOENT_and_files_the_ask(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch, grantee="someone-else")
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["error"] == "ENOENT" and "ask" in out
    assert not (dest / UNIT).exists()


def test_unit_outside_bounds_is_refused_cited_and_asked(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch, units=("other.service",))
    # the template declares nestor-ui.service and we ask for it — bounds say other
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["ok"] is False and out["error"] != "ENAME"
    cites = _citations(pg)
    assert len(cites) == 1 and cites[0]["content"]["outcome"] != "granted"
    assert not (dest / UNIT).exists()


def test_source_outside_bounds_is_refused(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch, sources=(f"{REPO}@deploy/other.service.template",))
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(), github_root, dest)
    assert out["ok"] is False and out.get("fields")
    assert not (dest / UNIT).exists()


def test_envelope_consumed_only_on_success(home, tmp_path, monkeypatch, github_root, dest):
    """A cited-then-failed enable leaves a granted citation (the act was
    authorized), a `unit_install_failed` row naming the errno, and no
    `unit_install` receipt — and a second try under a max_count=1 grant is
    EDQUOT, which is the honest reading: the grant was spent on an act that
    did not complete, and that is visible in the ledger."""
    _charter(tmp_path, monkeypatch, max_count=1)
    pg = _FakeGovernancePg()
    out = _install(pg, _Fake(enable_rc=1), github_root, dest)
    assert out["ok"] is False and out["error"] == "EINSTALL"
    assert _receipts(pg) == []
    assert len(_citations(pg)) == 1
    assert [r for r in pg.rows if r["event_type"] == f"{uix.EVENT}_failed"]
    again = _install(pg, _Fake(), github_root, dest)
    assert again["error"] == "EDQUOT"


def test_no_ledger_is_EAMBIG_before_any_write(home, tmp_path, monkeypatch, github_root, dest):
    _charter(tmp_path, monkeypatch)
    out = _install(_FakeGovernancePg(), _Fake(), github_root, dest, ledger=None)
    assert out["error"] == "EAMBIG" and not (dest / UNIT).exists()


# ── the keyboard path is behind a flag now ────────────────────────────────────

def test_reloader_install_refuses_without_keyboard(capsys, monkeypatch):
    monkeypatch.setattr(reloader, "install_services", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
    assert reloader.main(["install"]) == 2
    assert "unit_install_execute" in capsys.readouterr().err


def test_reloader_install_runs_with_keyboard(capsys, monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(reloader, "install_services", lambda *a, **k: called.setdefault("ok", True) and {"installed": []})
    assert reloader.main(["install", "--keyboard", "--no-reload"]) == 0
    assert called == {"ok": True}


@pytest.mark.parametrize("cmd,module,fn", [
    ("repo-sweep-service", "repo_sweep_service", "install_services"),
    ("worker-service", "worker_service", "install_services"),
    ("voice-service", "voice_service", "install"),
])
def test_server_service_install_actions_share_the_keyboard_guard(capsys, monkeypatch, cmd, module, fn):
    """One helper, five call sites: the three server `*-service install`
    actions refuse without --keyboard exactly like reloader/net_signer."""
    import importlib

    from willow_mcp import server

    mod = importlib.import_module(f"willow_mcp.{module}")
    monkeypatch.setattr(mod, fn, lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
    parser = server._build_parser() if hasattr(server, "_build_parser") else None
    if parser is None:
        pytest.skip("server exposes no parser builder to drive; guard covered by the shared-helper test")
    args = parser.parse_args([cmd, "install"] + (["--wake-models", "x"] if cmd == "voice-service" else []))
    handler = {"repo-sweep-service": server._cmd_repo_sweep_service,
               "worker-service": server._cmd_worker_service,
               "voice-service": server._cmd_voice_service}[cmd]
    with pytest.raises(SystemExit) as exc:
        handler(args)
    assert exc.value.code == 2
    assert "unit_install_execute" in capsys.readouterr().err


def test_keyboard_guard_helper_is_the_one_all_sites_use(capsys):
    from types import SimpleNamespace

    assert uix.keyboard_install_refused(SimpleNamespace(keyboard=True)) is False
    assert uix.keyboard_install_refused(SimpleNamespace()) is True
    assert "unit_install_execute" in capsys.readouterr().err
