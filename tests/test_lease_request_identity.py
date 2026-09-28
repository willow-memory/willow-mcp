"""`lease_request` must not let a stdio caller ask for another seat's lease.

`lease_request` is `@_guarded`, so it already runs through `_gate` on every
call. Under binding enforcement, `_gate` calls `_enforce_binding_gate`, which
refuses a call whose per-call credential does not prove ownership of
`app_id` — the same guarantee `whoami` documents for itself (Loki 8EB4478D
B2: "an app may ask for its own lease; it may not ask for anyone else's" was
untested through the real wrapper, and the docstring's absolute claim did not
hold on a plain unenforced box).

These tests go through the REAL wrapper (`server.lease_request`, unwrapped
only of the outer `mcp.tool()` layer via `.fn`) rather than
`lease_request.__wrapped__` — a test that calls `__wrapped__` skips `_gate`
entirely and can never exercise this identity path.
"""
from __future__ import annotations

import json
import uuid

import pytest

from willow_mcp import agent_registry as reg
from willow_mcp import gate  # noqa: F401 — imported for readability at call sites
from willow_mcp import net_authority as na
from willow_mcp import server
from willow_mcp import session_binder as sb
from willow_mcp import signing
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
    server._LAST_BIND_RESULT.set(None)

    def _manifest(app_id, perms=("net_lease_request", "task_net"), **extra):
        d = tmp_path / "apps" / app_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text(json.dumps({"permissions": list(perms), **extra}))
        return app_id

    return _manifest


def _fn(tool):
    return getattr(tool, "fn", tool)


def _register_and_bind(app_id, trust):
    secret = bytes.fromhex(reg.register_agent(app_id, trust)["secret_hex"])
    header = signing.build_checkin_header(secret, app_id, trust, tools=["read"])
    sid = server._binder.check_in(header)["session_id"]
    return secret, sid


def _enforce(monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_ENFORCE_BINDING", "1")


# ── unenforced: trusted-host behavior is unchanged ────────────────────────────

def test_lease_request_unenforced_uses_the_passed_app_id(env, monkeypatch):
    """A plain unenforced box: the ordinary single-operator stdio trust model
    every write tool uses, unchanged by this fix."""
    env("kart")
    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = _fn(server.lease_request)(app_id="kart", ttl_seconds=1800, reason="unit test")
    assert out == {"status": "proposed"}
    assert seen["app_id"] == "kart"


# ── enforced: a seat may only ask for the lease it can prove it owns ──────────

def test_lease_request_denies_asking_for_another_seats_lease_under_enforcement(env, monkeypatch):
    env("victim")
    env("attacker")
    _register_and_bind("victim", 4)
    a_secret, a_sid = _register_and_bind("attacker", 4)
    _enforce(monkeypatch)
    # attacker signs a CORRECTLY-SHAPED credential over its own live session
    # and secret, but the signed message itself NAMES the victim's app_id —
    # exactly what `verify_call` receives as `app_id` when `lease_request`
    # is called with app_id="victim" below. This reaches `verify_call`'s sig
    # check (it verifies), so the only thing that can still refuse it is the
    # identity line `sess["agent_id"] != app_id` (Loki 02057439 N2 / P3) —
    # a nonce that doesn't match the credential's call_nonce, or an app_id
    # in the signed message that doesn't match the one passed to
    # lease_request, would refuse earlier at "call signature mismatch" and
    # never reach the identity check at all.
    nonce = uuid.uuid4().hex
    server._CALL_CREDENTIAL.set(
        {"session_id": a_sid, "call_nonce": nonce,
         "sig": sb.call_sig(a_secret, a_sid, "victim", "lease_request", nonce)})

    called = []
    monkeypatch.setattr(na, "propose_lease", lambda **kw: called.append(kw) or {"status": "proposed"})
    out = _fn(server.lease_request)(app_id="victim", ttl_seconds=1800, reason="not mine to ask")

    assert "error" in out
    assert "signed session is not this app_id" in out["error"]
    assert called == []  # never reached propose_lease — refused at the gate, not proposed


def test_lease_request_denies_when_no_credential_under_enforcement(env, monkeypatch):
    env("victim")
    _register_and_bind("victim", 4)
    _enforce(monkeypatch)
    server._CALL_CREDENTIAL.set(None)

    called = []
    monkeypatch.setattr(na, "propose_lease", lambda **kw: called.append(kw) or {"status": "proposed"})
    out = _fn(server.lease_request)(app_id="victim", ttl_seconds=1800, reason="x")

    assert "error" in out
    assert called == []


def test_lease_request_allows_your_own_identity_under_enforcement(env, monkeypatch):
    env("me")
    secret, sid = _register_and_bind("me", 3)
    _enforce(monkeypatch)
    nonce = uuid.uuid4().hex
    server._CALL_CREDENTIAL.set(
        {"session_id": sid, "call_nonce": nonce,
         "sig": sb.call_sig(secret, sid, "me", "lease_request", nonce)})

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = _fn(server.lease_request)(app_id="me", ttl_seconds=1800, reason="mine to ask")
    assert out == {"status": "proposed"}
    assert seen["app_id"] == "me"


# ── R1 (Loki E48668A0): requested_by must be verified or say it isn't ─────────
#
# These three run through the REAL `_guarded` wrapper (`server.lease_request`,
# not `.__wrapped__`) with binding OFF — the default, live shape on this box —
# where `_enforce_binding_gate` is a no-op. `_observe_binding` still runs
# `verify_call` for every call and caches the result on `_LAST_BIND_RESULT`
# (scoped to exactly this call); `lease_request` reads that cached outcome
# rather than calling `verify_call` a second time, so what actually stands
# between a caller's claim and what gets recorded is `_observe_binding`'s
# `verify_call`, read back through the per-call cache.

def test_lease_request_unverified_credential_naming_another_seat_yields_null_requested_by(env, monkeypatch):
    """An unsigned credential carrying another seat's live session_id must
    never be trusted as that seat's ask (Loki E48668A0 R1: this used to
    write 'heimdallr asks: Grant willow…' into the sealed question and the
    Nestor origin with binding OFF). `requested_by` must come back null and
    unverified, and the target `app_id` alone must go to `propose_lease`."""
    env("willow")
    env("heimdallr")
    _, h_sid = _register_and_bind("heimdallr", 4)
    # binding stays OFF — WILLOW_MCP_ENFORCE_BINDING is not set (env fixture)
    server._CALL_CREDENTIAL.set(
        {"session_id": h_sid, "call_nonce": uuid.uuid4().hex, "sig": "0" * 64})

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = _fn(server.lease_request)(app_id="willow", ttl_seconds=1800, reason="grant willow")
    assert out == {"status": "proposed"}
    assert seen["app_id"] == "willow"
    assert seen["requested_by"] is None
    assert seen["requested_by_verified"] is False


def test_lease_request_replayed_credential_yields_null_requested_by(env, monkeypatch):
    """A call_nonce already consumed by a prior verify_call must refuse to
    re-verify (replay), so the second use must fall back to null/unverified
    rather than trusting the now-stale credential."""
    env("me")
    secret, sid = _register_and_bind("me", 3)
    nonce = uuid.uuid4().hex
    sig = sb.call_sig(secret, sid, "me", "lease_request", nonce)
    server._CALL_CREDENTIAL.set({"session_id": sid, "call_nonce": nonce, "sig": sig})

    seen = []
    monkeypatch.setattr(na, "propose_lease", lambda **kw: seen.append(kw) or {"status": "proposed"})
    first = _fn(server.lease_request)(app_id="me", ttl_seconds=1800, reason="first ask")
    assert first == {"status": "proposed"}
    assert seen[0]["requested_by"] == "me"
    assert seen[0]["requested_by_verified"] is True

    # Same credential (same call_nonce) presented again — the nonce was
    # consumed by the first verify_call, so this must NOT re-verify.
    out = _fn(server.lease_request)(app_id="me", ttl_seconds=1800, reason="replayed ask")
    assert out == {"status": "proposed"}
    assert seen[1]["requested_by"] is None
    assert seen[1]["requested_by_verified"] is False


def test_lease_request_valid_own_credential_yields_verified_requested_by(env, monkeypatch):
    """The one honest path: a credential that verify_call actually binds to
    `app_id` yields a VERIFIED requested_by equal to the caller — the only
    shape `net_authority.question_for_lease`'s "X asks:" prefix may ever
    reach (it always equals the target here, since verify_call requires
    `sess['agent_id'] == app_id`; there is no separate `for_app_id`)."""
    env("loki")
    secret, sid = _register_and_bind("loki", 4)
    nonce = uuid.uuid4().hex
    server._CALL_CREDENTIAL.set(
        {"session_id": sid, "call_nonce": nonce,
         "sig": sb.call_sig(secret, sid, "loki", "lease_request", nonce)})

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = _fn(server.lease_request)(app_id="loki", ttl_seconds=1800, reason="mine, proven")
    assert out == {"status": "proposed"}
    assert seen["requested_by"] == "loki"
    assert seen["requested_by_verified"] is True


# ── B1 (Loki C1FEAD98): the verify cache must never outlive its call ──────────

def test_lease_request_same_context_replay_under_enforced_unregistered_target_stays_null(
        env, monkeypatch):
    """Loki C1FEAD98's own reported shape. Under binding ON, a credential
    valid for a REGISTERED app is verified and its nonce consumed by one
    call. A second call reusing the IDENTICAL credential but naming an
    UNREGISTERED app_id must not read back the first call's cached verified
    result. Either defence alone closes this particular shape: with `app_id`
    removed from the key (Loki 3B4C2E05 L1) it still passes, because in call
    2 `_gate` steps aside for the unregistered `unreg1` and `_observe_binding`
    steps aside under enforcement, so the per-call reset already leaves the
    cache at `None` before `lease_request` ever reads it — see
    `test_lease_request_same_context_reuse_after_deregistration_under_enforced_stays_null`
    below for the shape that isolates the RESET fix from the key fix, and
    `test_lease_request_cache_entry_forged_with_a_different_app_id_is_a_miss`
    / `..._different_tool_is_a_miss` below for tests that pin the app_id and
    tool_name components of the key directly."""
    env("loki")
    env("unreg1")
    secret, sid = _register_and_bind("loki", 4)
    _enforce(monkeypatch)
    nonce = uuid.uuid4().hex
    sig = sb.call_sig(secret, sid, "loki", "lease_request", nonce)
    server._CALL_CREDENTIAL.set({"session_id": sid, "call_nonce": nonce, "sig": sig})

    seen = []
    monkeypatch.setattr(na, "propose_lease", lambda **kw: seen.append(kw) or {"status": "proposed"})
    first = _fn(server.lease_request)(app_id="loki", ttl_seconds=1800, reason="mine")
    assert first == {"status": "proposed"}
    assert seen[0]["requested_by"] == "loki"
    assert seen[0]["requested_by_verified"] is True

    # SAME credential (loki's nonce is already spent), now naming an
    # UNREGISTERED app_id — must not inherit loki's verified identity.
    out = _fn(server.lease_request)(app_id="unreg1", ttl_seconds=1800, reason="grant unreg1")
    assert out == {"status": "proposed"}
    assert seen[1]["requested_by"] is None
    assert seen[1]["requested_by_verified"] is False


def test_lease_request_same_context_reuse_after_deregistration_under_enforced_stays_null(
        env, monkeypatch):
    """Isolates the RESET fix from the key fix. Even with `app_id` in the
    cache key, if the SAME app_id, session_id, call_nonce and sig are
    presented again for a second call in the same context, that call's own
    pipeline must decide the outcome fresh rather than read back the first
    call's leftover on `_LAST_BIND_RESULT` — the contextvar's per-call
    scope, not the key's specificity, is what closes this shape. Modeled on
    an agent being deregistered between the two calls (secret rotated or
    removed from the keystore): the first call is registered and verified;
    by the second call it is not, so `_enforce_binding_gate` steps aside
    (unregistered ⇒ manifest-only, `=on`) WITHOUT calling `verify_call`
    again — a hit here can only be call one's leftover, key match or not."""
    env("flaky")
    secret, sid = _register_and_bind("flaky", 4)
    _enforce(monkeypatch)
    nonce = uuid.uuid4().hex
    sig = sb.call_sig(secret, sid, "flaky", "lease_request", nonce)
    server._CALL_CREDENTIAL.set({"session_id": sid, "call_nonce": nonce, "sig": sig})

    seen = []
    monkeypatch.setattr(na, "propose_lease", lambda **kw: seen.append(kw) or {"status": "proposed"})
    first = _fn(server.lease_request)(app_id="flaky", ttl_seconds=1800, reason="mine")
    assert first == {"status": "proposed"}
    assert seen[0]["requested_by"] == "flaky"
    assert seen[0]["requested_by_verified"] is True

    # Deregister "flaky" (operator removed/rotated it) — agent_registry no
    # longer has an entry, so it now reads as UNREGISTERED.
    data = reg._read_registry()
    del data["flaky"]
    reg._write_registry(data)

    # SAME app_id, session_id, call_nonce and sig as the first call — the
    # key MATCHES call one's cache entry component-for-component. Only the
    # per-call reset (not the key) stops this from reading as verified.
    out = _fn(server.lease_request)(app_id="flaky", ttl_seconds=1800,
                                    reason="replayed after deregistration")
    assert out == {"status": "proposed"}
    assert seen[1]["requested_by"] is None
    assert seen[1]["requested_by_verified"] is False


def test_lease_request_cache_entry_differing_only_in_sig_is_a_miss(env, monkeypatch):
    """Loki C1FEAD98 M2 (survivor): the cache key must include `sig` in
    full. A forged cache entry matching (app_id, tool_name, session_id,
    call_nonce) but carrying a DIFFERENT `sig` — and a false verified
    'attacker' identity — must be a miss, so `lease_request` falls through
    to a fresh `verify_call` against the caller's REAL, unconsumed
    credential rather than trusting the forgery."""
    env("victim")
    secret, sid = _register_and_bind("victim", 4)
    nonce = uuid.uuid4().hex
    real_sig = sb.call_sig(secret, sid, "victim", "lease_request", nonce)
    server._CALL_CREDENTIAL.set({"session_id": sid, "call_nonce": nonce, "sig": real_sig})
    # Forged entry: same app_id/tool/session_id/call_nonce, WRONG sig,
    # falsely claiming a verified "attacker" identity.
    server._LAST_BIND_RESULT.set(
        ("victim", "lease_request", sid, nonce, "0" * 64,
         {"bound": True, "agent_id": "attacker", "tier": "trusted", "trust_level": 9}))

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = server.lease_request.__wrapped__(app_id="victim", ttl_seconds=1800,
                                           reason="genuine ask")
    assert out == {"status": "proposed"}
    # The mismatched-sig entry was a miss: a FRESH verify_call ran against
    # the real credential and correctly named "victim" — never the forged
    # "attacker" the stale entry claimed.
    assert seen["requested_by"] == "victim"
    assert seen["requested_by_verified"] is True


def test_lease_request_cache_entry_differing_only_in_nonce_is_a_miss(env, monkeypatch):
    """Loki C1FEAD98 M1 (survivor): the cache key must include `call_nonce`
    in full. A forged cache entry matching (app_id, tool_name, session_id,
    sig) but carrying a DIFFERENT `call_nonce` — and a false verified
    'attacker' identity — must be a miss."""
    env("victim")
    secret, sid = _register_and_bind("victim", 4)
    nonce = uuid.uuid4().hex
    real_sig = sb.call_sig(secret, sid, "victim", "lease_request", nonce)
    server._CALL_CREDENTIAL.set({"session_id": sid, "call_nonce": nonce, "sig": real_sig})
    other_nonce = uuid.uuid4().hex
    # Forged entry: same app_id/tool/session_id/sig STRING, WRONG nonce,
    # falsely claiming a verified "attacker" identity.
    server._LAST_BIND_RESULT.set(
        ("victim", "lease_request", sid, other_nonce, real_sig,
         {"bound": True, "agent_id": "attacker", "tier": "trusted", "trust_level": 9}))

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = server.lease_request.__wrapped__(app_id="victim", ttl_seconds=1800,
                                           reason="genuine ask")
    assert out == {"status": "proposed"}
    assert seen["requested_by"] == "victim"
    assert seen["requested_by_verified"] is True


def test_lease_request_cache_entry_forged_with_a_different_app_id_is_a_miss(env, monkeypatch):
    """Loki 3B4C2E05 L1 (survivor): the cache key must include `app_id`
    itself, not just the credential triplet. A forged cache entry matching
    (tool_name, session_id, call_nonce, sig) but carrying a DIFFERENT
    `app_id` — 'attacker' instead of the caller's real 'victim' — and a
    false verified 'attacker' identity, must be a miss, so `lease_request`
    falls through to a fresh `verify_call` against the real credential and
    correctly names 'victim'."""
    env("victim")
    secret, sid = _register_and_bind("victim", 4)
    nonce = uuid.uuid4().hex
    real_sig = sb.call_sig(secret, sid, "victim", "lease_request", nonce)
    server._CALL_CREDENTIAL.set({"session_id": sid, "call_nonce": nonce, "sig": real_sig})
    # Forged entry: same tool/session_id/call_nonce/sig, WRONG app_id,
    # falsely claiming a verified "attacker" identity.
    server._LAST_BIND_RESULT.set(
        ("attacker", "lease_request", sid, nonce, real_sig,
         {"bound": True, "agent_id": "attacker", "tier": "trusted", "trust_level": 9}))

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = server.lease_request.__wrapped__(app_id="victim", ttl_seconds=1800,
                                           reason="genuine ask")
    assert out == {"status": "proposed"}
    assert seen["requested_by"] == "victim"
    assert seen["requested_by_verified"] is True


def test_lease_request_cache_entry_forged_with_a_different_tool_is_a_miss(env, monkeypatch):
    """Loki 3B4C2E05 L2 (survivor): the cache key must include `tool_name`
    itself. A forged cache entry matching (app_id, session_id, call_nonce,
    sig) but carrying a DIFFERENT `tool_name` — 'whoami' instead of
    'lease_request' — and a false verified 'attacker' identity, must be a
    miss. 'whoami' is a real writer of this cache outside the per-call
    reset (`_own_identity_denial` -> `_enforce_binding_gate`, server.py),
    so this is not a hypothetical shape."""
    env("victim")
    secret, sid = _register_and_bind("victim", 4)
    nonce = uuid.uuid4().hex
    real_sig = sb.call_sig(secret, sid, "victim", "lease_request", nonce)
    server._CALL_CREDENTIAL.set({"session_id": sid, "call_nonce": nonce, "sig": real_sig})
    # Forged entry: same app_id/session_id/call_nonce/sig, WRONG tool_name,
    # falsely claiming a verified "attacker" identity for 'whoami'.
    server._LAST_BIND_RESULT.set(
        ("victim", "whoami", sid, nonce, real_sig,
         {"bound": True, "agent_id": "attacker", "tier": "trusted", "trust_level": 9}))

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = server.lease_request.__wrapped__(app_id="victim", ttl_seconds=1800,
                                           reason="genuine ask")
    assert out == {"status": "proposed"}
    assert seen["requested_by"] == "victim"
    assert seen["requested_by_verified"] is True


def test_lease_request_valid_own_credential_verified_under_enforcement(env, monkeypatch):
    """Loki C1FEAD98 M6 (survivor): `_enforce_binding_gate` consumes the
    per-call nonce via its own `verify_call` before `lease_request` ever
    runs. If `_enforce_binding_gate` did not cache that result (M6),
    `lease_request` would resolve `requested_by` by calling `verify_call`
    again with the SAME nonce — which fails as a replay, since the gate
    already spent it — producing a false-negative `requested_by=None` for
    the caller's own honest ask under binding ON. The cache is what lets the
    honest path succeed."""
    env("me")
    secret, sid = _register_and_bind("me", 3)
    _enforce(monkeypatch)
    nonce = uuid.uuid4().hex
    server._CALL_CREDENTIAL.set(
        {"session_id": sid, "call_nonce": nonce,
         "sig": sb.call_sig(secret, sid, "me", "lease_request", nonce)})

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = _fn(server.lease_request)(app_id="me", ttl_seconds=1800, reason="mine to ask")
    assert out == {"status": "proposed"}
    assert seen["requested_by"] == "me"
    assert seen["requested_by_verified"] is True


def test_lease_request_wrapped_fresh_verify_when_cache_is_empty(env, monkeypatch):
    """Loki C1FEAD98 M4 (survivor): calling the raw function directly
    (`.__wrapped__`, skipping `_gate` / `_observe_binding` entirely) means
    `_LAST_BIND_RESULT` was never populated for this call.
    `lease_request` must still resolve `requested_by` by calling
    `verify_call` fresh on a cache miss — the only path that exercises that
    fallback branch, since every call through `_guarded` always populates
    the cache first."""
    env("loki")
    secret, sid = _register_and_bind("loki", 4)
    nonce = uuid.uuid4().hex
    server._CALL_CREDENTIAL.set(
        {"session_id": sid, "call_nonce": nonce,
         "sig": sb.call_sig(secret, sid, "loki", "lease_request", nonce)})
    server._LAST_BIND_RESULT.set(None)  # explicit: no pipeline call populated this

    seen = {}
    monkeypatch.setattr(na, "propose_lease",
                        lambda **kw: seen.update(kw) or {"status": "proposed"})
    out = server.lease_request.__wrapped__(app_id="loki", ttl_seconds=1800,
                                           reason="direct call, no pipeline")
    assert out == {"status": "proposed"}
    assert seen["requested_by"] == "loki"
    assert seen["requested_by_verified"] is True
