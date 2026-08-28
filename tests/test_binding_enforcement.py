"""Binding enforcement through _gate (willow-gate seam Phase 3 / H2).

Phase 2 only *observed* the binding; Phase 3 makes it a CONTROL — but only when
WILLOW_MCP_ENFORCE_BINDING is on AND the app is registered in the keystore. These
tests drive the real _gate funnel: manifest ACL first, then the tier ceiling.

The threat model these pin (from the H1 spike table): a call carrying only app_id
cannot ride a registered identity; a captured signature cannot replay; a signature
for one (app, tool) cannot be reused for another; and a bound tier below the tool's
class is denied even when the manifest would allow it.
"""
import json
import uuid

import pytest

from willow_mcp import server, agent_registry as reg, session_binder as sb
from willow_mcp.db import Store
from willow_mcp.receipts import ReceiptLog


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "apps"))
    monkeypatch.delenv("WILLOW_MCP_ENFORCE_BINDING", raising=False)
    monkeypatch.setattr(server, "_store", Store(str(tmp_path / "store")))
    monkeypatch.setattr(server, "_receipt_log", ReceiptLog(str(tmp_path / "r.db")))
    monkeypatch.setattr(server, "_binder", sb.SessionBinder())
    server._CALL_CREDENTIAL.set(None)

    def _manifest(app_id, perms=("full_access",)):
        d = tmp_path / "apps" / app_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text(json.dumps({"permissions": list(perms)}))
        return app_id

    return _manifest


def _enforce(monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_ENFORCE_BINDING", "1")


def _header(agent_id, secret, trust):
    h = {"agent_id": agent_id, "agent_name": agent_id, "last_gate": "t",
         "pass_count": 100, "fail_count": 0, "drift": 0,
         "nonce": uuid.uuid4().hex, "trust_level": trust,
         "timestamp": 1000, "tools": ["read"], "state_hash": "s0",
         "reserved": 0, "signature": "0" * 64}
    h["signature"] = sb.expected_header_sig(secret, h)
    return h


def _check_in(app_id, trust, max_trust=None):
    secret = bytes.fromhex(reg.register_agent(app_id, max_trust or trust)["secret_hex"])
    session = server._binder.check_in(_header(app_id, secret, trust))
    return secret, session["session_id"]


def _sign_call(secret, session_id, app_id, tool):
    nonce = uuid.uuid4().hex
    return {"session_id": session_id, "call_nonce": nonce,
            "sig": sb.call_sig(secret, session_id, app_id, tool, nonce)}


# ── enforcement is off / app unregistered: nothing changes ────────────────────

def _fn(tool):
    return getattr(tool, "fn", tool)


def test_observe_only_records_bind_observed_receipt(env, monkeypatch):
    # Phase 2 path: a bound session, enforcement OFF → the tier is LOGGED, not gated.
    env("worker")
    _check_in("worker", 3)
    server._CALL_CREDENTIAL.set(None)
    _fn(server.receipts_tail)(app_id="worker", limit=5)   # any guarded call
    rows = server._receipt_log.tail("worker")
    assert any(r["outcome"] == "bind_observed" and "tier=Veteran" in (r["detail"] or "")
               for r in rows)


def test_off_registered_agent_without_credential_still_passes(env, monkeypatch):
    env("veep")
    _check_in("veep", 3)                       # registered, but enforcement OFF
    server._CALL_CREDENTIAL.set(None)
    eff, err = server._gate("veep", "store_put")
    assert err is None and eff == "veep"       # Phase 2 observe-only behavior


def test_on_unregistered_app_is_manifest_only(env, monkeypatch):
    env("plain")
    _enforce(monkeypatch)                       # enforcement ON, but 'plain' unregistered
    eff, err = server._gate("plain", "store_put")
    assert err is None and eff == "plain"


# ── strict: unregistered is refused, not waved through ────────────────────────

def _strict(monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_ENFORCE_BINDING", "strict")


def test_strict_denies_an_unregistered_app(env, monkeypatch):
    """The whole point of the mode. Under `on` this same call passes
    manifest-only (test_on_unregistered_app_is_manifest_only above), which is
    what let a partial rollout harden one agent while the most privileged
    identity stayed on the unbound path."""
    env("plain")
    _strict(monkeypatch)
    eff, err = server._gate("plain", "store_put")
    assert eff is None and "binding required" in err["error"]
    assert "not registered" in err["error"]


def test_strict_still_admits_a_registered_agent_that_signs(env, monkeypatch):
    """Strict tightens only the unregistered case; a properly bound call is
    unaffected."""
    env("veep")
    secret, sid = _check_in("veep", 3)
    _strict(monkeypatch)
    server._CALL_CREDENTIAL.set(_sign_call(secret, sid, "veep", "store_get"))
    eff, err = server._gate("veep", "store_get")
    assert err is None and eff == "veep"


def test_strict_fails_closed_on_an_unreadable_secret_too(env, monkeypatch, tmp_path):
    """The registered-but-broken tie-break must not be reachable only under
    `on` — strict is a superset of its denials, never a different set."""
    env("veep")
    _check_in("veep", 3)
    (tmp_path / "gate" / "secrets" / "veep.key").unlink()
    _strict(monkeypatch)
    server._CALL_CREDENTIAL.set(None)
    eff, err = server._gate("veep", "store_get")
    assert eff is None and "binding unavailable" in err["error"]


def test_a_typo_in_the_switch_is_refused_not_read_as_off(env, monkeypatch):
    """`WILLOW_MCP_ENFORCE_BINDING=stict` silently meaning "no enforcement" is
    the failure this mode exists to prevent, one layer up."""
    monkeypatch.setenv("WILLOW_MCP_ENFORCE_BINDING", "stict")
    with pytest.raises(ValueError, match="not one of"):
        server._binding_mode()


def test_the_switch_has_exactly_three_positions(env, monkeypatch):
    seen = set()
    for raw in ("", "0", "false", "no", "off", "1", "true", "yes", "on", "strict"):
        monkeypatch.setenv("WILLOW_MCP_ENFORCE_BINDING", raw)
        seen.add(server._binding_mode())
    assert seen == set(server._BINDING_MODES)


# ── enforcement on + registered: the credential is required and checked ────────

def test_registered_but_unreadable_secret_fails_closed(env, monkeypatch, tmp_path):
    env("veep")
    _check_in("veep", 3)
    (tmp_path / "gate" / "secrets" / "veep.key").unlink()   # registered, secret gone
    _enforce(monkeypatch)
    server._CALL_CREDENTIAL.set(None)
    eff, err = server._gate("veep", "store_get")
    # Must NOT silently downgrade to manifest-only — that's the fail-open hole.
    assert eff is None and "binding unavailable" in err["error"]


def test_registered_agent_without_credential_is_denied(env, monkeypatch):
    env("veep")
    _check_in("veep", 3)
    _enforce(monkeypatch)
    server._CALL_CREDENTIAL.set(None)           # app_id alone must not bind
    eff, err = server._gate("veep", "store_get")
    assert eff is None and "binding required" in err["error"]


def test_valid_signed_call_within_tier_passes_and_receipts(env, monkeypatch):
    env("veep")
    secret, sid = _check_in("veep", 3)          # Veteran
    _enforce(monkeypatch)
    server._CALL_CREDENTIAL.set(_sign_call(secret, sid, "veep", "task_submit"))
    eff, err = server._gate("veep", "task_submit")
    assert err is None and eff == "veep"
    rows = server._receipt_log.tail("veep")
    assert any(r["tool"] == "task_submit" and r["outcome"] == "bind_enforced" for r in rows)


def test_tier_below_tool_is_denied_even_with_valid_signature(env, monkeypatch):
    env("rook")
    secret, sid = _check_in("rook", 1)          # Rookie — read only
    _enforce(monkeypatch)
    server._CALL_CREDENTIAL.set(_sign_call(secret, sid, "rook", "store_put"))
    eff, err = server._gate("rook", "store_put")
    assert eff is None and "tier too low" in err["error"]


def test_admin_tool_needs_elder(env, monkeypatch):
    env("vet")
    secret, sid = _check_in("vet", 3)           # Veteran, not Elder
    _enforce(monkeypatch)
    server._CALL_CREDENTIAL.set(_sign_call(secret, sid, "vet", "schema_confirm_mapping"))
    eff, err = server._gate("vet", "schema_confirm_mapping")
    assert eff is None and "tier too low" in err["error"]


# ── the H1 attacks: ride / tamper / replay ────────────────────────────────────

def test_ride_a_signature_for_a_different_app_is_denied(env, monkeypatch):
    env("veep"); env("victim")
    reg.register_agent("veep", 3)               # 'veep' is a registered app → must bind
    secret, sid = _check_in("victim", 4)        # attacker holds victim's real credential
    _enforce(monkeypatch)
    # Attacker calls as the registered 'veep' but supplies a credential legitimately
    # signed for 'victim'. The sig binds app_id, so it won't verify for 'veep'.
    server._CALL_CREDENTIAL.set(_sign_call(secret, sid, "victim", "store_get"))
    eff, err = server._gate("veep", "store_get")
    assert eff is None and "binding rejected" in err["error"]


def test_tampered_signature_is_denied(env, monkeypatch):
    env("veep")
    secret, sid = _check_in("veep", 3)
    _enforce(monkeypatch)
    cred = _sign_call(secret, sid, "veep", "store_get")
    cred["sig"] = "0" * 64                       # forged
    server._CALL_CREDENTIAL.set(cred)
    eff, err = server._gate("veep", "store_get")
    assert eff is None and "binding rejected" in err["error"]


def test_replayed_call_nonce_is_denied(env, monkeypatch):
    env("veep")
    secret, sid = _check_in("veep", 3)
    _enforce(monkeypatch)
    cred = _sign_call(secret, sid, "veep", "store_get")
    server._CALL_CREDENTIAL.set(cred)
    eff, err = server._gate("veep", "store_get")
    assert err is None                           # first use binds
    server._CALL_CREDENTIAL.set(dict(cred))      # same nonce again
    eff2, err2 = server._gate("veep", "store_get")
    assert eff2 is None and "binding rejected" in err2["error"]
