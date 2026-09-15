"""The brokered push (operator ruling 2026-09-10, gap 5ecb87cfdf56 slice 1).

The agent asks; this process checks and cites the git.push envelope, files the
ask on a miss, and only then runs git. No subprocess before the citation. The
git calls are captured by a fake runner so nothing here touches a remote.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from willow_mcp import push_executor as px
from willow_mcp import server


# ── a fake frank ledger, same shape as test_verb_envelope_gate ───────────────

class _FakeGovernancePg:
    def __init__(self):
        self.rows = []
        self.commits = 0

    def cursor(self):
        return _FakeGovernanceCursor(self)

    def commit(self):
        self.commits += 1


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
        if s.startswith("INSERT INTO"):
            record_id, project, event_type, content, prev_hash, digest = params
            self.pg.rows.append({
                "id": record_id, "project": project, "event_type": event_type,
                "content": getattr(content, "adapted", content),
                "prev_hash": prev_hash, "hash": digest,
            })
            return
        raise AssertionError(f"unexpected SQL: {sql!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def close(self):
        pass


def _ledger(pg):
    from willow_mcp.governance_ledger import GovernanceLedger
    return GovernanceLedger(pg)


def _citations(pg):
    return [r for r in pg.rows if r["event_type"] == "envelope_citation"]


# ── registry with one git.push grant ────────────────────────────────────────

def _charter(tmp_path, monkeypatch, *, grantee="willow", branches=("feat/*",),
             force=False, extra=None, expires="2027-01-01"):
    active = [{
        "id": "env-git.push-test",
        "verb_id": 3,
        "verb": "git.push",
        "grantee": grantee,
        "bounds": {"repo": "willow-memory/willow-mcp", "branches": list(branches),
                   "remote": "origin", "force": force},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": expires,
        "max_count": None,
        "use_count_source": "frank",
        "status": "active",
    }] + list(extra or [])
    table = {"verbs": [{"id": 3, "verb": "git.push",
                        "bounds": {"repo": "s", "branches": "l", "remote": "s", "force": "b"}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))


# ── a fake git ──────────────────────────────────────────────────────────────

class _FakeGit:
    """Answers the read verbs the executor asks and records every push.

    Gap ``bc9945dd47da`` added a remote-base ancestry preflight that runs
    before the envelope citation: ``symbolic-ref`` resolves the default
    base, ``fetch`` refreshes the remote-tracking ref, ``rev-parse`` on
    ``refs/remotes/<remote>/<base>`` reads its sha, and ``rev-list
    --left-right --count`` reports ahead/behind. The defaults below make
    the preflight report ``state="current"`` so existing tests continue to
    pass without changing their assertions; the preflight-specific tests
    pass a runner whose ``ahead``/``behind`` numbers exercise the stale
    and diverged paths.
    """

    def __init__(self, *, remote_url="https://github.com/willow-memory/willow-mcp.git",
                 branches=("feat/x", "master"), push_rc=0, push_err="",
                 default_base="master", fetch_rc=0, fetch_err="",
                 remote_base_sha="base-sha", preflight_ahead=3, preflight_behind=0):
        self.remote_url = remote_url
        self.branches = set(branches)
        self.push_rc = push_rc
        self.push_err = push_err
        self.default_base = default_base
        self.fetch_rc = fetch_rc
        self.fetch_err = fetch_err
        self.remote_base_sha = remote_base_sha
        self.preflight_ahead = preflight_ahead
        self.preflight_behind = preflight_behind
        self.calls: list[list[str]] = []

    @staticmethod
    def _after_config(sub: list[str]) -> list[str]:
        i = 0
        while i + 1 < len(sub) and sub[i] == "-c":
            i += 2
        return sub[i:]

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        sub = argv[3:]  # git -C <path> ...
        rest = self._after_config(sub)
        if rest[:2] == ["remote", "get-url"]:
            return subprocess.CompletedProcess(argv, 0, self.remote_url + "\n", "")
        if rest[:3] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, "feat/x\n", "")
        if rest == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
        if rest[:3] == ["rev-parse", "--verify", "--quiet"]:
            ref = rest[3]
            if ref.startswith("refs/heads/") and ref.removeprefix("refs/heads/") in self.branches:
                return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
            if ref.startswith("refs/remotes/") and self.default_base and ref.endswith(f"/{self.default_base}"):
                return subprocess.CompletedProcess(argv, 0, self.remote_base_sha + "\n", "")
            return subprocess.CompletedProcess(argv, 1, "", "")
        if rest[:2] == ["symbolic-ref", "--short"] and rest[2:] and rest[2].startswith("refs/remotes/"):
            remote = rest[2].split("/", 3)[2]
            if not self.default_base:
                return subprocess.CompletedProcess(argv, 1, "", "not a valid ref")
            return subprocess.CompletedProcess(argv, 0, f"{remote}/{self.default_base}\n", "")
        if rest[:1] == ["fetch"]:
            return subprocess.CompletedProcess(
                argv, self.fetch_rc, "", self.fetch_err or "done",
            )
        if rest[:3] == ["rev-list", "--left-right", "--count"]:
            return subprocess.CompletedProcess(
                argv, 0, f"{self.preflight_ahead}\t{self.preflight_behind}\n", "",
            )
        if rest and rest[0] == "push":
            return subprocess.CompletedProcess(argv, self.push_rc, "", self.push_err or "done")
        raise AssertionError(f"unexpected git call {sub}")

    @property
    def pushes(self):
        out = []
        for c in self.calls:
            sub = c[3:]
            rest = self._after_config(sub)
            if rest and rest[0] == "push":
                out.append(sub)
        return out


@pytest.fixture(autouse=True)
def _default_host_push_auth(monkeypatch):
    """Existing tests assume the host credential helper; App mint is opt-in."""
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": False, "mode": "host", "reason": "test default host helper"},
    )


@pytest.fixture
def checkout(tmp_path):
    d = tmp_path / "repo"
    (d / ".git").mkdir(parents=True)
    return d


def _push(checkout, pg, git, **kw):
    args = dict(app_id="willow", checkout=checkout, repo="willow-memory/willow-mcp",
                branch="feat/x", project="willow-mcp", ledger=_ledger(pg), runner=git)
    args.update(kw)
    return px.execute_push(args.pop("app_id"), **args)


# ── granted ──────────────────────────────────────────────────────────────────

def test_granted_push_cites_then_runs_git(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg, git = _FakeGovernancePg(), _FakeGit()
    out = _push(checkout, pg, git)
    assert out["ok"] and out["pushed"], out
    assert out["sha"] == "abc123"
    assert out["envelope_id"] == "env-git.push-test"
    assert out.get("auth_mode") == "host"
    assert git.pushes == [["push", "origin", "feat/x:feat/x"]]
    cites = _citations(pg)
    assert len(cites) == 1 and cites[0]["content"]["outcome"] == "granted"
    assert cites[0]["content"]["call_args"] == {
        "repo": "willow-memory/willow-mcp", "branches": ["feat/x"],
        "remote": "origin", "force": False}
    assert out["citation_id"] == cites[0]["id"]


def test_app_token_push_uses_extraheader_not_host_remote(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {
            "ok": True, "mode": "app", "token": "ghs_test_token",
            "permissions": {"contents": "write"}, "installation_id": 1,
        },
    )
    pg, git = _FakeGovernancePg(), _FakeGit()
    out = _push(checkout, pg, git)
    assert out["ok"] and out["pushed"], out
    assert out.get("auth_mode") == "app"
    assert len(git.pushes) == 1
    push = git.pushes[0]
    assert push[0] == "-c"
    assert "AUTHORIZATION: basic" in push[1]
    assert "ghs_test_token" not in " ".join(push)  # token only inside basic blob
    assert push[2:] == ["push", "origin", "feat/x:feat/x"]


def test_app_token_refuses_when_contents_is_read_only(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {
            "ok": True, "mode": "app", "token": "ghs_test_token",
            "permissions": {"contents": "read"}, "installation_id": 1,
        },
    )
    pg, git = _FakeGovernancePg(), _FakeGit()
    out = _push(checkout, pg, git)
    assert not out["ok"] and out["error"] == "EPERM"
    assert "write" in out["reason"]
    assert git.pushes == []


def test_git_terminal_prompt_is_off_so_a_missing_credential_fails_not_hangs(
        home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    seen = {}

    class _Git(_FakeGit):
        def __call__(self, argv, **kw):
            seen.setdefault("env", kw.get("env"))
            return super().__call__(argv, **kw)

    _push(checkout, _FakeGovernancePg(), _Git())
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"


# ── refused before any subprocess push ───────────────────────────────────────

def test_branch_outside_bounds_is_refused_cited_and_asked(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, branches=("release/*",))
    pg, git = _FakeGovernancePg(), _FakeGit()
    out = _push(checkout, pg, git)
    assert out["ok"] is False and out["pushed"] is False
    assert out["error"] == "EAMBIG"
    assert "branches" in out["fields"]
    assert git.pushes == []
    assert _citations(pg)[0]["content"]["outcome"] == "EAMBIG"
    assert out["ask"]["queued"] is True
    from willow_mcp import human_loop
    from willow_mcp.db import Store
    rows = human_loop.list_queue(Store())
    assert any("feat/x" in (r.get("title") or "") for r in rows)


def test_force_is_refused_unless_the_envelope_grants_it(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, force=False)
    pg, git = _FakeGovernancePg(), _FakeGit()
    out = _push(checkout, pg, git, force=True)
    assert out["error"] == "EAMBIG" and "force" in out["fields"]
    assert git.pushes == []


def test_force_granted_uses_force_with_lease(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, force=True)
    pg, git = _FakeGovernancePg(), _FakeGit()
    out = _push(checkout, pg, git, force=True)
    assert out["pushed"] is True
    assert git.pushes == [["push", "--force-with-lease", "origin", "feat/x:feat/x"]]


def test_no_governing_envelope_refuses_and_files_the_ask(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, grantee="loki")
    pg, git = _FakeGovernancePg(), _FakeGit()
    out = _push(checkout, pg, git)
    assert out["error"] == "ENOENT"
    assert out["ask"]["queued"] is True
    assert git.pushes == [] and _citations(pg) == []


def test_named_envelope_must_be_one_the_actor_holds(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    out = _push(checkout, _FakeGovernancePg(), _FakeGit(), envelope_id="env-someone-elses")
    assert out["error"] == "ENOENT"
    assert out["envelope_ids"] == ["env-git.push-test"]


def test_two_governing_envelopes_is_ambiguous_until_named(home, tmp_path, monkeypatch, checkout):
    second = {"id": "env-git.push-two", "verb_id": 3, "verb": "git.push", "grantee": "willow",
              "bounds": {"repo": "willow-memory/willow-mcp", "branches": ["feat/*"],
                         "remote": "origin", "force": False},
              "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
              "max_count": None, "use_count_source": "frank", "status": "active"}
    _charter(tmp_path, monkeypatch, extra=[second])
    pg, git = _FakeGovernancePg(), _FakeGit()
    assert _push(checkout, pg, git)["error"] == "EAMBIG"
    assert _push(checkout, pg, git, envelope_id="env-git.push-two")["pushed"] is True


def test_expired_envelope_is_refused_and_asked(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch, expires="2020-01-01")
    pg, git = _FakeGovernancePg(), _FakeGit()
    out = _push(checkout, pg, git)
    assert out["error"] == "EEXPIRED" and out["ask"]["queued"] is True
    assert git.pushes == []


# ── the checkout must be the repo the envelope names ─────────────────────────

def test_checkout_pointing_at_another_repo_is_refused_before_the_envelope(
        home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    git = _FakeGit(remote_url="git@github.com:willow-memory/willow-mcp-archive.git")
    out = _push(checkout, pg, git)
    assert out["error"] == "EINVAL" and "not 'willow-memory/willow-mcp'" in out["reason"]
    assert _citations(pg) == [] and git.pushes == []


@pytest.mark.parametrize("url", [
    "https://github.com/willow-memory/willow-mcp.git",
    "https://github.com/willow-memory/willow-mcp",
    "git@github.com:willow-memory/willow-mcp.git",
    "ssh://git@github.com/willow-memory/willow-mcp/",
])
def test_remote_url_forms_that_name_the_repo(url):
    assert px._repo_matches_remote(url, "willow-memory/willow-mcp")


@pytest.mark.parametrize("url", [
    "https://github.com/willow-memory/willow-mcp-archive.git",
    "https://github.com/other-org/willow-mcp.git",
    "",
])
def test_remote_url_forms_that_do_not(url):
    assert not px._repo_matches_remote(url, "willow-memory/willow-mcp")


def test_missing_branch_and_bad_args_are_einval(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg, git = _FakeGovernancePg(), _FakeGit()
    assert _push(checkout, pg, git, branch="nope")["error"] == "EINVAL"
    assert _push(checkout, pg, git, branch="--upload-pack=x")["error"] == "EINVAL"
    assert _push(checkout, pg, git, repo="")["error"] == "EINVAL"
    assert _citations(pg) == [] and git.pushes == []


def test_not_a_checkout_is_einval(home, tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch)
    out = _push(tmp_path / "nothing", _FakeGovernancePg(), _FakeGit())
    assert out["error"] == "EINVAL" and "no .git" in out["reason"]


# ── git's own failure is reported, after the citation ────────────────────────

def test_git_push_failure_is_reported_with_the_citation(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    git = _FakeGit(push_rc=128, push_err="fatal: could not read Username")
    out = _push(checkout, pg, git)
    assert out["error"] == "EPUSH" and "Username" in out["reason"]
    assert out["citation_id"] == _citations(pg)[0]["id"]


def test_no_ledger_means_no_push(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    git = _FakeGit()
    out = px.execute_push("willow", checkout=checkout, repo="willow-memory/willow-mcp",
                          branch="feat/x", project="p", ledger=None, runner=git)
    assert out["error"] == "EAMBIG" and git.pushes == []


# ── the MCP tool ─────────────────────────────────────────────────────────────

def _manifest(home, app_id, permissions):
    d = home / "mcp_apps" / app_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps({"app_id": app_id, "permissions": permissions}))


def test_tool_is_gated_as_envelope_apply(home, tmp_path, monkeypatch, checkout):
    server._buckets.clear()
    _manifest(home, "scribe", ["store_read"])
    out = server.git_push_execute("scribe", str(checkout), "willow-memory/willow-mcp", "feat/x")
    assert "error" in out and "envelope_apply" in out["error"]


def test_tool_runs_the_executor_with_the_live_ledger(home, tmp_path, monkeypatch, checkout):
    """A specialist seat (loki) holding envelope_apply and a git.push grant —
    the shape a dispatched agent has after a Kart task commits in a worktree."""
    server._buckets.clear()
    _manifest(home, "loki", ["envelope_apply"])
    _charter(tmp_path, monkeypatch, grantee="loki")
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)
    git = _FakeGit()
    monkeypatch.setattr(px.subprocess, "run", git)
    out = server.git_push_execute("loki", str(checkout), "willow-memory/willow-mcp", "feat/x")
    assert out["pushed"] is True, out
    assert git.pushes == [["push", "origin", "feat/x:feat/x"]]
    assert _citations(pg)[0]["project"] == "willow-memory/willow-mcp"
    assert _citations(pg)[0]["content"]["actor"] == "loki"


def test_tool_without_postgres_refuses(home, tmp_path, monkeypatch, checkout):
    server._buckets.clear()
    _manifest(home, "loki", ["envelope_apply"])
    monkeypatch.setattr(server, "get_pg", lambda: None)
    out = server.git_push_execute("loki", str(checkout), "willow-memory/willow-mcp", "feat/x")
    assert out["error"] == "postgres_unavailable"


# ── remote-base ancestry preflight (gap bc9945dd47da) ────────────────────────

def test_current_base_passes_preflight_and_pushes(home, tmp_path, monkeypatch, checkout):
    """The default case: `remote/HEAD` reads `master`, the fetch succeeds,
    ahead>=0 and behind=0. The push proceeds and the receipt carries the
    preflight verdict so the seat can prove the check happened."""
    _charter(tmp_path, monkeypatch)
    pg, git = _FakeGovernancePg(), _FakeGit(preflight_ahead=5, preflight_behind=0)
    out = _push(checkout, pg, git)
    assert out["ok"] and out["pushed"], out
    pf = out["preflight"]
    assert pf["state"] == "current"
    assert pf["base_branch"] == "master"
    assert pf["ahead"] == 5 and pf["behind"] == 0


def test_behind_base_is_refused_with_estale_before_citation(home, tmp_path, monkeypatch, checkout):
    """A head that is entirely behind the remote base is stale — the
    envelope must not be consumed and no push is attempted."""
    _charter(tmp_path, monkeypatch)
    pg, git = _FakeGovernancePg(), _FakeGit(preflight_ahead=0, preflight_behind=4)
    out = _push(checkout, pg, git)
    assert out["ok"] is False and out["pushed"] is False
    assert out["error"] == "ESTALE"
    assert out["preflight"]["state"] == "behind"
    assert out["preflight"]["behind"] == 4
    assert _citations(pg) == []  # no envelope consumed
    assert git.pushes == []       # no push attempted


def test_diverged_base_is_refused_with_estale(home, tmp_path, monkeypatch, checkout):
    _charter(tmp_path, monkeypatch)
    pg, git = _FakeGovernancePg(), _FakeGit(preflight_ahead=2, preflight_behind=3)
    out = _push(checkout, pg, git)
    assert out["error"] == "ESTALE"
    assert out["preflight"]["state"] == "diverged"
    assert out["preflight"]["ahead"] == 2 and out["preflight"]["behind"] == 3
    assert _citations(pg) == []


def test_explicit_base_wins_over_origin_head(home, tmp_path, monkeypatch, checkout):
    """A caller who names `base=release` is checked against `origin/release`,
    not against whatever `refs/remotes/origin/HEAD` points at. The FakeGit's
    `default_base` is what the symref would answer, but the executor asks
    for the caller's value instead."""
    _charter(tmp_path, monkeypatch)
    # A runner that expects `origin/release` as the resolved base.
    git = _FakeGit(default_base="release", preflight_ahead=1, preflight_behind=0)
    pg = _FakeGovernancePg()
    out = _push(checkout, pg, git, base="release")
    assert out["ok"] and out["pushed"], out
    assert out["preflight"]["base_branch"] == "release"
    # No symbolic-ref call is made when the caller supplied a base.
    assert not any(c[3:5] == ["symbolic-ref", "--short"] for c in git.calls)


def test_no_symref_and_no_base_is_a_skipped_preflight_not_a_refusal(
    home, tmp_path, monkeypatch, checkout,
):
    """A repo whose remote HEAD is not advertised, called with no base,
    reports `state="skipped"` and the push still proceeds. Honest absence
    rather than a fabricated verdict — the seat reader sees the missing
    field named, not a `state="current"` bluff."""
    _charter(tmp_path, monkeypatch)
    git = _FakeGit(default_base="")  # symref returns rc=1
    pg = _FakeGovernancePg()
    out = _push(checkout, pg, git)
    assert out["ok"] and out["pushed"], out
    assert out["preflight"]["state"] == "skipped"
    assert "no origin/HEAD symref" in out["preflight"]["reason"]


def test_fetch_failure_is_efetch_not_estale(home, tmp_path, monkeypatch, checkout):
    """A network failure during the preflight fetch is EFETCH, distinct from
    a stale-base ESTALE. Refuse before envelope citation either way — the
    fetch failed, we cannot claim the base is current."""
    _charter(tmp_path, monkeypatch)
    git = _FakeGit(fetch_rc=128, fetch_err="fatal: could not read from remote")
    pg = _FakeGovernancePg()
    out = _push(checkout, pg, git)
    assert out["error"] == "EFETCH"
    assert "could not read from remote" in out["reason"]
    assert _citations(pg) == []
    assert git.pushes == []


def test_preflight_runs_before_the_envelope_citation(home, tmp_path, monkeypatch, checkout):
    """The order matters: a stale head must not consume the one-use push
    envelope. The receipt names the preflight verdict, not a citation id."""
    _charter(tmp_path, monkeypatch)
    git = _FakeGit(preflight_ahead=0, preflight_behind=1)
    pg = _FakeGovernancePg()
    out = _push(checkout, pg, git)
    assert "citation_id" not in out or out.get("citation_id") is None
    assert pg.commits == 0
