"""Ratification registry mismatch (gap 4c7512c57a7e).

An operator said "ratified"; the broker's ``envelope_pending_read`` still
said ``proposed``; the seat ratified again on the operator's word. Whatever
wrote, wrote somewhere the desk does not read. Three surfaces close that:

* every ratify / reject / revoke refuses ``EREGISTRY`` when the registry it
  resolves is not ``$WILLOW_HOME/constitutional/pre-approved.json``, naming
  both paths and the env that steered the resolve;
* ``envelope_pending_read`` names the registry it read (``path`` +
  ``fingerprint``) so the desk can say "your ratification is not here";
* ``split_brain.scan()`` names the implicit ``~/.willow`` registry as a
  problem when it holds a proposal newer than the resolved one.
"""
from __future__ import annotations

import json
import os

import pytest

from willow_mcp import envelope_authoring as ea
from willow_mcp import human_session
from willow_mcp import keyring as keyring_mod
from willow_mcp import server, split_brain

_REGISTRY = {"schema": "envelope-registry/v1.1", "active": [], "proposals": []}
_SYSCALLS = {"verbs": [{"id": 999, "verb": "demo_verb",
                        "bounds": {"path_pattern": "", "max_bytes": 0}}]}


def _write_json(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.chmod(str(path), 0o600)
    return path


@pytest.fixture
def ring_with_rita(tmp_path):
    human_session.clear_attribution_cache()
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")
        k.save()
        keyring_mod.set_keyring(k)
        human_session._remember_attributed("s-orch")
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)
            human_session.clear_attribution_cache()


@pytest.fixture
def home_registry(tmp_path, monkeypatch):
    """WILLOW_HOME at tmp_path/home, registry where the home names it, no
    steering env. This is the clean shape: no mismatch."""
    home = tmp_path / "home"
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.delenv("WILLOW_ENVELOPE_REGISTRY", raising=False)
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(_write_json(tmp_path / "syscall-table.json", _SYSCALLS)))
    reg = _write_json(home / "constitutional" / "pre-approved.json", _REGISTRY)
    return home, reg


def _propose(verb="demo_verb"):
    return ea.propose(verb=verb, grantee="hanuman",
                      bounds={"path_pattern": "docs/**", "max_bytes": 1},
                      reason="t", verifier="rita", session_id="s-orch")


# ── registry_mismatch(): the resolve vs. the home ────────────────────────────

def test_no_mismatch_when_registry_is_the_homes_own(home_registry):
    assert ea.registry_mismatch() is None


def test_no_mismatch_when_override_names_the_same_file(home_registry, monkeypatch):
    _, reg = home_registry
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    assert ea.registry_mismatch() is None


def test_mismatch_names_both_paths_and_the_steering_env(home_registry, tmp_path, monkeypatch):
    _, reg = home_registry
    elsewhere = _write_json(tmp_path / "elsewhere" / "pre-approved.json", _REGISTRY)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(elsewhere))
    out = ea.registry_mismatch()
    assert out["error"] == "EREGISTRY"
    assert out["resolved"] == str(elsewhere)
    assert out["expected"] == str(reg)
    assert out["steered_by"] == "WILLOW_ENVELOPE_REGISTRY"
    assert str(elsewhere) in out["message"] and str(reg) in out["message"]


def test_mismatch_names_charter_repo_when_that_steers(home_registry, tmp_path, monkeypatch):
    charter = tmp_path / "charter"
    _write_json(charter / "envelopes" / "pre-approved.json", _REGISTRY)
    monkeypatch.setenv("WILLOW_CHARTER_REPO", str(charter))
    out = ea.registry_mismatch()
    assert out["error"] == "EREGISTRY"
    assert out["steered_by"] == "WILLOW_CHARTER_REPO"
    assert out["resolved"] == str(charter / "envelopes" / "pre-approved.json")


def test_mismatch_when_home_is_unset_names_the_implicit_default(tmp_path, monkeypatch):
    fake_home = tmp_path / "fake_home"
    (fake_home / ".willow" / "constitutional").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("WILLOW_HOME", raising=False)
    monkeypatch.delenv("WILLOW_CHARTER_REPO", raising=False)
    elsewhere = _write_json(tmp_path / "elsewhere" / "pre-approved.json", _REGISTRY)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(elsewhere))
    out = ea.registry_mismatch()
    assert out["error"] == "EREGISTRY"
    assert out["expected"] == str(fake_home / ".willow" / "constitutional" / "pre-approved.json")
    # the override is what steered; the message still says where the home is
    assert out["steered_by"] == "WILLOW_ENVELOPE_REGISTRY"


# ── every ratify path refuses before any write ───────────────────────────────

@pytest.fixture
def steered_away(home_registry, tmp_path, monkeypatch):
    """A proposal exists in the registry the process resolves — which is not
    the home's. Ratify/reject/revoke must refuse and leave both files alone."""
    home, home_reg = home_registry
    elsewhere = _write_json(tmp_path / "elsewhere" / "pre-approved.json", _REGISTRY)
    # propose while steered so the proposal lives in the resolved file
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(elsewhere))
    return home_reg, elsewhere


def test_ratify_refuses_eregistry_and_writes_nothing(ring_with_rita, steered_away):
    home_reg, elsewhere = steered_away
    pid = _propose()["id"]
    before = elsewhere.read_bytes(), home_reg.read_bytes()
    with pytest.raises(ea.RegistryMismatchError) as exc:
        ea.ratify(pid, verifier="rita")
    assert exc.value.detail["error"] == "EREGISTRY"
    assert "ratify refused" in str(exc.value)
    assert (elsewhere.read_bytes(), home_reg.read_bytes()) == before
    assert json.loads(elsewhere.read_text())["proposals"][0]["id"] == pid  # still proposed


def test_reject_and_revoke_refuse_eregistry(ring_with_rita, steered_away):
    _, elsewhere = steered_away
    pid = _propose()["id"]
    with pytest.raises(ea.RegistryMismatchError):
        ea.reject(pid, reason="no", verifier="rita")
    with pytest.raises(ea.RegistryMismatchError):
        ea.revoke("anything", reason="no", verifier="rita")
    assert json.loads(elsewhere.read_text())["proposals"][0]["id"] == pid


def test_ratify_refuses_eregistry_before_looking_up_the_proposal(ring_with_rita, steered_away):
    """The registry check comes before the proposal lookup: a wrong registry
    is the finding, not 'no such proposal' in the wrong file."""
    with pytest.raises(ea.RegistryMismatchError):
        ea.ratify("no-such-id", verifier="rita")


def test_keyring_check_still_comes_first(steered_away):
    """An unknown verifier is refused as such, whatever the registry: the
    operator gate is not weakened by the registry gate."""
    with pytest.raises(ea.OperatorVerifierRequired):
        ea.ratify("x", verifier="nobody")


def test_ratify_succeeds_on_the_homes_own_registry(ring_with_rita, home_registry):
    pid = _propose()["id"]
    row = ea.ratify(pid, verifier="rita")
    assert row["status"] == "active"


def test_cli_ratify_refuses_eregistry(ring_with_rita, steered_away, monkeypatch, capsys):
    """The CLI path surfaces the same refusal through EnvelopeAuthoringError."""
    import argparse
    from willow_mcp import cli_envelope
    monkeypatch.setattr(cli_envelope, "_require_operator", lambda: "")
    pid = _propose()["id"]
    args = argparse.Namespace(envelope_command="ratify", proposal_id=pid,
                              verifier="rita", json=False)
    rc = cli_envelope.cmd_envelope(args)
    err = capsys.readouterr().err
    assert rc == cli_envelope.EXIT_FAIL
    assert "EREGISTRY" in err


# ── MCP surface: EREGISTRY dict, registry identity on pending_read ───────────

@pytest.fixture(autouse=True)
def _fresh_rate_buckets():
    server._buckets.clear()
    yield
    server._buckets.clear()


@pytest.fixture
def desk(home_registry, monkeypatch):
    """willow desk with an attributed orchestrator session.

    ``server._DEFAULT_APP_ID`` is read from ``WILLOW_APP_ID`` once, at
    ``server`` module import time (see ``server.py``: ``_DEFAULT_APP_ID =
    os.environ.get("WILLOW_APP_ID", "")``) -- long before this fixture's
    ``monkeypatch.setenv`` calls run. ``envelope_pending_read`` /
    ``envelope_ratify`` / ``envelope_reject`` take no ``app_id`` parameter
    at all, so ``_guarded`` falls back to that frozen module global to
    resolve the gate's caller. A desk-broker shell that already has
    ``WILLOW_APP_ID=willow`` set before the test process starts hides this
    completely; CI has no such ambient env, so ``_DEFAULT_APP_ID`` stays
    ``""``, ``gate.valid_app_id("")`` is False, and every one of these
    calls was refused ``invalid app_id`` before ever reaching the registry
    logic under test -- surfacing three calls later as a bare ``KeyError``
    on ``count``/``registry``/``ok``. Patch the module global directly so
    the fixture is correct with or without ``WILLOW_APP_ID`` in the
    environment.
    """
    home, _ = home_registry
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(home / "mcp_apps"))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(home / "store"))
    apps = home / "mcp_apps" / "willow"
    apps.mkdir(parents=True, exist_ok=True)
    (apps / "manifest.json").write_text(json.dumps(
        {"app_id": "willow",
         "permissions": ["orchestrator", "envelope_read", "envelope_write"]}))
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    monkeypatch.setattr(server, "_DEFAULT_APP_ID", "willow")
    monkeypatch.setattr(server, "get_pg", lambda: None)
    (home / "sessions").mkdir(exist_ok=True)
    (home / "sessions" / "willow-s-orch.json").write_text(json.dumps(
        {"app_id": "willow", "session_id": "s-orch", "status": "idle",
         "dispatch_id": "", "verifier": "rita"}))
    monkeypatch.setattr(server, "_current_orchestrator_session", lambda: "s-orch")

    # Name a future gate refusal at the source instead of a bare KeyError
    # three lines later when a test indexes into the success shape.
    # EREGISTRY is a real, expected outcome several tests below assert on
    # explicitly (steered_away) -- only an unanticipated refusal fails here.
    def _refusing(fn, fn_name):
        def wrapper(*a, **kw):
            result = fn(*a, **kw)
            err = isinstance(result, dict) and result.get("error")
            if err and err != "EREGISTRY":
                pytest.fail(f"{fn_name} refused unexpectedly: {result}")
            return result
        return wrapper

    for _name in ("envelope_pending_read", "envelope_ratify", "envelope_reject"):
        monkeypatch.setattr(server, _name, _refusing(getattr(server, _name), _name))

    return home


def test_pending_read_names_the_registry_it_read(ring_with_rita, desk, home_registry):
    _, reg = home_registry
    pid = _propose()["id"]
    out = server.envelope_pending_read()
    assert out["count"] == 1 and out["pending"][0]["id"] == pid
    assert out["registry"]["path"] == str(reg)
    assert out["registry"]["exists"] is True
    assert len(out["registry"]["fingerprint"]) == 16
    assert out["registry"]["proposals"] == 1
    assert "registry_mismatch" not in out
    # the fingerprint follows the content, so two readers can compare
    ea.ratify(pid, verifier="rita")
    after = server.envelope_pending_read()
    assert after["registry"]["fingerprint"] != out["registry"]["fingerprint"]
    assert after["registry"]["active"] == 1


def test_pending_read_reports_mismatch_and_ratify_returns_eregistry(ring_with_rita, desk, steered_away):
    home_reg, elsewhere = steered_away
    pid = _propose()["id"]
    out = server.envelope_pending_read()
    assert out["registry"]["path"] == str(elsewhere)
    assert out["registry_mismatch"]["error"] == "EREGISTRY"
    assert out["registry_mismatch"]["expected"] == str(home_reg)

    res = server.envelope_ratify(pid)
    assert res["error"] == "EREGISTRY"
    assert res["resolved"] == str(elsewhere)
    assert res["expected"] == str(home_reg)
    assert res["steered_by"] == "WILLOW_ENVELOPE_REGISTRY"
    assert server.envelope_reject(pid, reason="no")["error"] == "EREGISTRY"
    # still proposed, nowhere else touched
    assert server.envelope_pending_read()["count"] == 1
    assert json.loads(home_reg.read_text())["active"] == []


def test_ratify_result_carries_registry_identity(ring_with_rita, desk, home_registry):
    _, reg = home_registry
    pid = _propose()["id"]
    res = server.envelope_ratify(pid)
    assert res["ok"] is True
    assert res["registry"]["path"] == str(reg)
    assert res["registry"]["active"] == 1


# ── split_brain: the implicit ~/.willow shadow ───────────────────────────────

def _shadow_env(tmp_path, monkeypatch, *, shadow_doc, resolved_doc):
    fake_home = tmp_path / "fake_home"
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(home / "store"))
    for var in ("WILLOW_ENVELOPE_REGISTRY", "WILLOW_CHARTER_REPO", "WILLOW_VAULT_BOX", "WILLOW_KEYRING"):
        monkeypatch.delenv(var, raising=False)
    shadow = _write_json(fake_home / ".willow" / "constitutional" / "pre-approved.json", shadow_doc)
    resolved = _write_json(home / "constitutional" / "pre-approved.json", resolved_doc)
    return shadow, resolved


def _row(pid, ts):
    return {"id": pid, "verb": "demo_verb", "grantee": "hanuman", "bounds": {},
            "proposed_at": ts, "status": "proposed"}


def test_shadow_with_newer_proposal_is_a_named_problem(tmp_path, monkeypatch):
    shadow, resolved = _shadow_env(
        tmp_path, monkeypatch,
        shadow_doc={"active": [], "proposals": [_row("env-new", "2026-09-20T21:57:00Z")]},
        resolved_doc={"active": [], "proposals": [_row("env-old", "2026-09-19T00:00:00Z")]},
    )
    report = split_brain.scan()["artifacts"]["envelope_registry"]
    assert report["status"] == "warn"
    # not a "divergent" in the old sense: the shadow is unreachable from here
    assert report["divergent"] is False
    cand = next(c for c in report["candidates"] if c["source"] == "implicit_home_shadow")
    assert cand["path"] == str(shadow) and cand["reachable"] is False and cand["exists"]
    problem = report["shadow_problem"]
    assert problem["shadow"] == str(shadow)
    assert problem["resolved"] == str(resolved)
    assert problem["shadow_newest"] == "2026-09-20T21:57:00Z"
    assert problem["unseen_proposals"] == ["env-new"]
    assert "newer than anything in the resolved registry" in report["detail"]
    assert "without WILLOW_HOME" in report["detail"]


def test_shadow_that_is_older_stays_a_quiet_leftover(tmp_path, monkeypatch):
    shadow, _ = _shadow_env(
        tmp_path, monkeypatch,
        shadow_doc={"active": [], "proposals": [_row("old", "2026-09-01T00:00:00Z")]},
        resolved_doc={"active": [], "proposals": [_row("old", "2026-09-01T00:00:00Z"),
                                                   _row("new", "2026-09-20T00:00:00Z")]},
    )
    report = split_brain.scan()["artifacts"]["envelope_registry"]
    assert report["status"] == "ok"
    assert "shadow_problem" not in report
    cand = next(c for c in report["candidates"] if c["source"] == "implicit_home_shadow")
    assert cand["reachable"] is False


def test_no_shadow_candidate_when_home_is_unset(tmp_path, monkeypatch):
    """With WILLOW_HOME unset the implicit default IS the resolved registry —
    it is the home_default candidate, not a shadow of itself."""
    fake_home = tmp_path / "fake_home"
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("WILLOW_HOME", raising=False)
    for var in ("WILLOW_ENVELOPE_REGISTRY", "WILLOW_CHARTER_REPO"):
        monkeypatch.delenv(var, raising=False)
    _write_json(fake_home / ".willow" / "constitutional" / "pre-approved.json", _REGISTRY)
    sources = [c.source for c in split_brain.envelope_registry_candidates()]
    assert "implicit_home_shadow" not in sources
    assert "home_default" in sources


def test_diagnostic_summary_surfaces_the_shadow_problem(tmp_path, monkeypatch):
    _shadow_env(
        tmp_path, monkeypatch,
        shadow_doc={"active": [], "proposals": [_row("env-new", "2026-09-20T21:57:00Z")]},
        resolved_doc={"active": [], "proposals": []},
    )
    report = server._diag_split_brain()
    assert report["status"] == "warn"
    assert report["artifacts"]["envelope_registry"]["shadow_problem"]["unseen_proposals"] == ["env-new"]
