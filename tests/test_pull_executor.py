"""The brokered pull (gap 57f2c1762b4d) — a merge comes home without a keyboard.

No envelope: a fast-forward creates no history and publishes none. What is
held here is the safety rule — a pull never loses work — the receipt, and the
trigger consumer. Every git call goes through a fake runner; nothing here
touches a remote.
"""
from __future__ import annotations

import subprocess

import pytest

from willow_mcp import pull_executor as plx
from willow_mcp import server


# ── a fake ledger that just records appends ──────────────────────────────────

class _Ledger:
    def __init__(self):
        self.rows = []

    def append(self, project, event_type, content):
        self.rows.append({"project": project, "event_type": event_type, "content": content})
        return f"rec-{len(self.rows)}"


# ── a fake git ──────────────────────────────────────────────────────────────

class _FakeGit:
    """Answers what the executor asks and records every mutating call."""

    def __init__(self, *, remote_url="https://github.com/forge-play/Forge.git",
                 current="feat/x", dirty="", ahead=0, behind=2,
                 local_sha="aaa111", remote_sha="bbb222", branches=("master", "feat/x"),
                 remote_head="master", fetch_rc=0, ff_rc=0, unmerged=()):
        self.remote_url, self.current, self.dirty = remote_url, current, dirty
        self.ahead, self.behind = ahead, behind
        self.local_sha, self.remote_sha = local_sha, remote_sha
        self.branches, self.remote_head = set(branches), remote_head
        self.fetch_rc, self.ff_rc, self.unmerged = fetch_rc, ff_rc, set(unmerged)
        self.calls: list[list[str]] = []
        self.head = local_sha

    @staticmethod
    def _after_config(sub):
        i = 0
        while i + 1 < len(sub) and sub[i] == "-c":
            i += 2
        return sub[i:]

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        rest = self._after_config(argv[3:])
        cp = lambda rc, out="", err="": subprocess.CompletedProcess(argv, rc, out, err)  # noqa: E731
        if rest[:2] == ["remote", "get-url"]:
            return cp(0, self.remote_url + "\n")
        if rest[:3] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return cp(0, self.current + "\n")
        if rest == ["rev-parse", "HEAD"]:
            return cp(0, self.head + "\n")
        if rest[:2] == ["status", "--porcelain"]:
            return cp(0, self.dirty)
        if rest[0] == "fetch":
            return cp(self.fetch_rc, "", "" if self.fetch_rc == 0 else "fatal: could not read from remote")
        if rest[:2] == ["symbolic-ref", "--short"]:
            return cp(0, f"origin/{self.remote_head}\n") if self.remote_head else cp(1)
        if rest[:3] == ["rev-parse", "--verify", "--quiet"]:
            ref = rest[3]
            if ref.startswith("refs/remotes/origin/"):
                return cp(0, self.remote_sha + "\n") if ref.endswith(self.remote_head) else cp(1)
            b = ref.removeprefix("refs/heads/")
            return cp(0, self.local_sha + "\n") if b in self.branches else cp(1)
        if rest[:3] == ["rev-list", "--left-right", "--count"]:
            return cp(0, f"{self.ahead}\t{self.behind}\n")
        if rest[:2] == ["checkout", "-q"]:
            self.current = rest[2]
            return cp(0)
        if rest[:2] == ["merge", "--ff-only"]:
            if self.ff_rc == 0:
                self.head = self.remote_sha
            return cp(self.ff_rc, "", "" if self.ff_rc == 0 else "fatal: Not possible to fast-forward")
        if rest[:2] == ["branch", "-d"]:
            b = rest[2]
            if b in self.unmerged:
                return cp(1, "", f"error: The branch '{b}' is not fully merged.")
            self.branches.discard(b)
            return cp(0, f"Deleted branch {b}\n")
        raise AssertionError(f"unexpected git call {rest}")

    def mutations(self):
        out = []
        for c in self.calls:
            rest = self._after_config(c[3:])
            if rest[0] in ("fetch", "checkout", "merge", "branch"):
                out.append(rest)
        return out


@pytest.fixture(autouse=True)
def _no_app(monkeypatch):
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": False, "mode": "host", "reason": "test: no app"},
    )


@pytest.fixture(autouse=True)
def _clear_retired_home_cache():
    plx.paths._retired_home_cache.clear()
    yield
    plx.paths._retired_home_cache.clear()


@pytest.fixture
def checkout(tmp_path):
    d = tmp_path / "Forge"
    (d / ".git").mkdir(parents=True)
    return d


def _pull(checkout, git, ledger=None, **kw):
    args = dict(checkout=checkout, repo="forge-play/Forge", project="forge-play",
                ledger=ledger, runner=git)
    args.update(kw)
    return plx.execute_pull("willow", **args)


# ── the happy path ───────────────────────────────────────────────────────────

def test_a_behind_only_branch_fast_forwards_and_leaves_a_receipt(checkout):
    git, ledger = _FakeGit(), _Ledger()
    out = _pull(checkout, git, ledger, prune_branches=["feat/x"])
    assert out["ok"] and out["pulled"], out
    assert out["branch"] == "master" and out["before"] == "aaa111" and out["after"] == "bbb222"
    assert out["auth_mode"] == "none"
    assert git.mutations() == [
        ["fetch", "--prune", "origin"],
        ["checkout", "-q", "master"],
        ["merge", "--ff-only", "origin/master"],
        ["branch", "-d", "feat/x"],
    ]
    assert out["pruned"] == ["feat/x"] and out["kept"] == {}
    assert out["receipt_id"] == "rec-1"
    row = ledger.rows[0]
    assert row["event_type"] == "git_pull" and row["project"] == "forge-play"
    assert row["content"]["before"] == "aaa111" and row["content"]["after"] == "bbb222"


def test_already_up_to_date_is_ok_but_not_pulled(checkout):
    git = _FakeGit(local_sha="bbb222", remote_sha="bbb222", ahead=0, behind=0, current="master")
    out = _pull(checkout, git)
    assert out["ok"] and out["pulled"] is False and out["before"] == out["after"]
    assert ["checkout", "-q", "master"] not in git.mutations()


def test_branch_defaults_to_the_remote_head(checkout):
    git = _FakeGit(remote_head="main", branches=("main",), current="main")
    out = _pull(checkout, git)
    assert out["ok"] and out["branch"] == "main"


def test_an_unmerged_prune_is_kept_and_named_not_forced(checkout):
    git = _FakeGit(unmerged={"feat/x"})
    out = _pull(checkout, git, prune_branches=["feat/x"])
    assert out["ok"]
    assert out["pruned"] == [] and "not fully merged" in out["kept"]["feat/x"]
    assert not any(m[:2] == ["branch", "-D"] for m in git.mutations())


def test_app_token_rides_as_an_extraheader_never_in_the_url(checkout, monkeypatch):
    monkeypatch.setattr(
        "willow_mcp.github_app_credentials.mint_installation_token",
        lambda repo: {"ok": True, "mode": "app", "token": "ghs_t",
                      "permissions": {"contents": "read"}},
    )
    git = _FakeGit()
    out = _pull(checkout, git)
    assert out["ok"] and out["auth_mode"] == "app"
    fetch = next(c for c in git.calls if "fetch" in c)
    assert fetch[3] == "-c" and "AUTHORIZATION: basic" in fetch[4]
    assert "ghs_t" not in " ".join(fetch)


# ── a pull never loses work ──────────────────────────────────────────────────

def test_a_dirty_tree_is_ebusy_before_any_fetch(checkout):
    git = _FakeGit(dirty=" M forge/entry.py\n")
    out = _pull(checkout, git)
    assert not out["ok"] and out["error"] == "EBUSY"
    assert out["dirty_files"] == ["forge/entry.py"]
    assert git.mutations() == []


def test_untracked_files_do_not_block(checkout):
    """`status --porcelain --untracked-files=no` — a stray data/ folder is
    not work a pull can lose."""
    git = _FakeGit(dirty="")
    _pull(checkout, git)
    status = next(c for c in git.calls if "status" in c)
    assert "--untracked-files=no" in status


def test_an_ahead_branch_is_ediverged_after_fetch_before_merge(checkout):
    git = _FakeGit(ahead=1, behind=3)
    out = _pull(checkout, git)
    assert not out["ok"] and out["error"] == "EDIVERGED"
    assert out["ahead"] == 1 and out["behind"] == 3
    assert "1 commit(s) ahead" in out["reason"] and "3 behind" in out["reason"]
    assert [m[0] for m in git.mutations()] == ["fetch"]


def test_a_wrong_repo_is_refused_before_fetch(checkout):
    git = _FakeGit(remote_url="https://github.com/someone/else.git")
    out = _pull(checkout, git)
    assert out["error"] == "EINVAL" and "is not 'forge-play/Forge'" in out["reason"]
    assert git.mutations() == []


def test_a_symlinked_checkout_is_refused(tmp_path, checkout):
    link = tmp_path / "link"
    link.symlink_to(checkout, target_is_directory=True)
    out = _pull(link, _FakeGit())
    assert out["error"] == "EINVAL" and "symlink" in out["reason"]


def test_fetch_failure_is_efetch_with_gits_words(checkout):
    git = _FakeGit(fetch_rc=128)
    out = _pull(checkout, git)
    assert out["error"] == "EFETCH" and "could not read from remote" in out["reason"]


def test_ff_refusal_is_eff(checkout):
    git = _FakeGit(ff_rc=128)
    out = _pull(checkout, git)
    assert out["error"] == "EFF" and "fast-forward" in out["reason"].lower()


@pytest.mark.parametrize("bad", [dict(repo="Forge"), dict(branch="-x"), dict(remote="--upload-pack=x"),
                                 dict(prune_branches=["-D"])])
def test_malformed_asks_are_einval(checkout, bad):
    git = _FakeGit()
    out = _pull(checkout, git, **bad)
    assert out["error"] == "EINVAL" and git.calls == []


# ── the trigger consumer ─────────────────────────────────────────────────────

def _make_clone(root, owner, name, url):
    d = root / owner / name
    (d / ".git").mkdir(parents=True)
    return d


class _MultiGit(_FakeGit):
    """One fake per checkout path, so a sweep across repos answers each with
    its own remote URL."""

    def __init__(self, by_path: dict):
        super().__init__()
        self.by_path = by_path
        self.seen = []

    def __call__(self, argv, **kw):
        path = argv[2]
        fake = self.by_path.get(path)
        if fake is None:
            # an unknown candidate path: no remote configured
            return subprocess.CompletedProcess(argv, 128, "", "fatal: not a git repository")
        self.seen.append(path)
        return fake(argv, **kw)


def test_sweep_resolves_org_layout_pulls_and_removes_the_flag(tmp_path):
    root = tmp_path / "github"
    forge = _make_clone(root, "forge-play", "Forge", "")
    triggers = tmp_path / "gitsync"
    triggers.mkdir()
    (triggers / "trigger-forge-play-Forge.flag").write_text("2026-09-14T22:53:07Z\n")
    git = _MultiGit({str(forge): _FakeGit(current="master")})
    ledger = _Ledger()
    out = plx.sweep_triggers("willow", project="fleet", ledger=ledger, root=root,
                             triggers=triggers, runner=git)
    assert out["ok"] and out["present"]
    assert len(out["swept"]) == 1
    r = out["swept"][0]
    assert r["ok"] and r["pulled"] and r["repo"] == "forge-play/Forge" and r["flag_removed"]
    assert not (triggers / "trigger-forge-play-Forge.flag").exists()
    assert ledger.rows[0]["content"]["repo"] == "forge-play/Forge"


def test_sweep_leaves_the_flag_when_the_pull_is_refused(tmp_path):
    root = tmp_path / "github"
    forge = _make_clone(root, "forge-play", "Forge", "")
    triggers = tmp_path / "gitsync"
    triggers.mkdir()
    flag = triggers / "trigger-forge-play-Forge.flag"
    flag.write_text("x\n")
    git = _MultiGit({str(forge): _FakeGit(dirty=" M a.py\n")})
    out = plx.sweep_triggers("willow", project="fleet", root=root, triggers=triggers, runner=git)
    r = out["swept"][0]
    assert not r["ok"] and r["error"] == "EBUSY"
    assert flag.exists(), "a refused pull keeps its trigger for the next sweep"


def test_sweep_reports_a_flag_with_no_clone(tmp_path):
    root = tmp_path / "github"
    root.mkdir()
    triggers = tmp_path / "gitsync"
    triggers.mkdir()
    (triggers / "trigger-someone-nowhere.flag").write_text("x\n")
    out = plx.sweep_triggers("willow", project="fleet", root=root, triggers=triggers,
                             runner=_MultiGit({}))
    r = out["swept"][0]
    assert r["error"] == "ENOCLONE" and r["flag"] == "trigger-someone-nowhere.flag"


def test_sweep_says_absent_when_there_is_no_trigger_dir(tmp_path):
    out = plx.sweep_triggers("willow", project="fleet", triggers=tmp_path / "nope")
    assert out["ok"] and out["present"] is False and out["swept"] == []


def test_resolve_clone_prefers_org_layout_and_verifies_origin(tmp_path):
    root = tmp_path / "github"
    org = _make_clone(root, "forge-play", "Forge", "")
    flat = _make_clone(root, ".", "Forge", "")  # root/Forge
    git = _MultiGit({
        str(org): _FakeGit(remote_url="https://github.com/forge-play/Forge.git"),
        str(flat): _FakeGit(remote_url="https://github.com/rudi193-cmd/Forge.git"),
    })
    assert plx.resolve_clone("forge-play/Forge", root=root, runner=git) == org
    assert plx.resolve_clone("rudi193-cmd/Forge", root=root, runner=git) == flat
    assert plx.resolve_clone("nobody/Forge", root=root, runner=git) is None


# ── the resolver is case-insensitive (gap 6fbf1453f029) ─────────────────────

def test_resolve_clone_matches_owner_and_repo_case_insensitively(tmp_path):
    """The clone on disk is `Die-Namic-Systems/nestor`; GitHub, and the
    trigger flag willow-bot writes, name it `Die-Namic-Systems/Nestor`."""
    root = tmp_path / "github"
    nestor = _make_clone(root, "Die-Namic-Systems", "nestor", "")
    git = _MultiGit({str(nestor): _FakeGit(
        remote_url="https://github.com/Die-Namic-Systems/Nestor.git")})
    assert plx.resolve_clone("Die-Namic-Systems/Nestor", root=root, runner=git) == nestor


def test_resolve_clone_refuses_two_case_variants_as_ambiguous(tmp_path):
    root = tmp_path / "github"
    lower = _make_clone(root, "Die-Namic-Systems", "nestor", "")
    upper = _make_clone(root, "Die-Namic-Systems", "Nestor", "")
    git = _MultiGit({
        str(lower): _FakeGit(remote_url="https://github.com/Die-Namic-Systems/Nestor.git"),
        str(upper): _FakeGit(remote_url="https://github.com/Die-Namic-Systems/Nestor.git"),
    })
    status = plx.resolve_clone_status("Die-Namic-Systems/Nestor", root=root, runner=git)
    assert status["clone"] is None and status["error"] == "EAMBIG"
    assert set(status["candidates"]) == {str(lower), str(upper)}
    # the backward-compatible wrapper never guesses between them
    assert plx.resolve_clone("Die-Namic-Systems/Nestor", root=root, runner=git) is None


def test_resolve_clone_missing_stays_enoclone(tmp_path):
    root = tmp_path / "github"
    root.mkdir()
    status = plx.resolve_clone_status("someone/nowhere", root=root, runner=_MultiGit({}))
    assert status["clone"] is None and status["error"] is None


def test_sweep_resolves_a_case_variant_clone_via_the_flag_name(tmp_path):
    root = tmp_path / "github"
    nestor = _make_clone(root, "Die-Namic-Systems", "nestor", "")
    triggers = tmp_path / "gitsync"
    triggers.mkdir()
    (triggers / "trigger-Die-Namic-Systems-Nestor.flag").write_text("x\n")
    git = _MultiGit({str(nestor): _FakeGit(
        remote_url="https://github.com/Die-Namic-Systems/Nestor.git", current="master")})
    out = plx.sweep_triggers("willow", project="fleet", root=root, triggers=triggers, runner=git)
    r = out["swept"][0]
    assert r["ok"] and r["checkout"] == str(nestor), "the receipt names the resolved path"


def test_sweep_reports_eambig_for_two_case_variant_clones(tmp_path):
    root = tmp_path / "github"
    lower = _make_clone(root, "Die-Namic-Systems", "nestor", "")
    upper = _make_clone(root, "Die-Namic-Systems", "Nestor", "")
    triggers = tmp_path / "gitsync"
    triggers.mkdir()
    flag = triggers / "trigger-Die-Namic-Systems-Nestor.flag"
    flag.write_text("x\n")
    git = _MultiGit({
        str(lower): _FakeGit(remote_url="https://github.com/Die-Namic-Systems/Nestor.git"),
        str(upper): _FakeGit(remote_url="https://github.com/Die-Namic-Systems/Nestor.git"),
    })
    out = plx.sweep_triggers("willow", project="fleet", root=root, triggers=triggers, runner=git)
    r = out["swept"][0]
    assert r["error"] == "EAMBIG" and set(r["candidates"]) == {str(lower), str(upper)}
    assert flag.exists(), "an ambiguous match is not a guess; the flag stays for a human"


# ── trigger_dir routes through paths.willow_home() (no ~/.willow fallback) ──

def test_trigger_dir_resolves_when_home_is_set(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "live"))
    assert plx.trigger_dir() == tmp_path / "live" / "gitsync"


def test_trigger_dir_raises_on_a_retired_implicit_default(tmp_path, monkeypatch):
    monkeypatch.delenv("WILLOW_HOME", raising=False)
    monkeypatch.setattr(plx.paths.Path, "home", staticmethod(lambda: tmp_path))
    home = tmp_path / ".willow"
    home.mkdir()
    (home / plx.paths.TOMBSTONE_MARKER).write_text("retired\n")
    with pytest.raises(plx.paths.RetiredHomeError):
        plx.trigger_dir()


def test_sweep_triggers_reports_unreachable_for_a_retired_home(tmp_path, monkeypatch):
    """Unset WILLOW_HOME plus a tombstoned `~/.willow` must surface as a
    structured unreachable — never a raise, never an empty `{"swept": []}`
    that looks like a clean sweep of nothing."""
    monkeypatch.delenv("WILLOW_HOME", raising=False)
    monkeypatch.setattr(plx.paths.Path, "home", staticmethod(lambda: tmp_path))
    home = tmp_path / ".willow"
    home.mkdir()
    (home / plx.paths.TOMBSTONE_MARKER).write_text("retired\n")
    out = plx.sweep_triggers("willow", project="fleet")
    assert out["ok"] is False
    assert out["state"] == "unreachable" and out["reason"] == "retired_home"
    assert out["swept"] == []


# ── the tools are wired like the push and the PR ────────────────────────────

def test_the_pull_tools_are_gated_as_envelope_apply_by_name():
    catalogue = server._gate_tool_catalogue()
    assert catalogue["git_pull_execute"] == "envelope_apply"
    assert catalogue["gitsync_sweep"] == "envelope_apply"
