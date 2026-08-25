"""PR8: SessionStart hook auto-signs the session when
WILLOW_OPERATOR_VERIFIER is set.

Removes the "open a second terminal per session_id" ritual — the biggest
UX papercut the identity+accrual work left standing. Opt-in, single-box
deployments only (the MCP server process runs as the operator's own uid,
so signing there IS the operator signing — same trust story as running
willow-mcp sign-session by hand).

Invariants:
* Auto-sign fires only when WILLOW_OPERATOR_VERIFIER is set.
* Fails gracefully (no crash) on: keyring disabled / unknown verifier /
  compromised verifier / missing private half. Hook still returns a
  usable additional_context.
* On success, session record carries verifier and session is IMMEDIATELY
  in the attribution cache (so first envelope_propose works without an
  intermediate orchestrator write).
* Legacy path (WILLOW_OPERATOR_VERIFIER unset) is behavior-preserved.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import (
    dispatch,
    human_session,
    keyring as keyring_mod,
    paths,
    session_start_hook,
)


@pytest.fixture
def ring_with_rita(tmp_path):
    human_session.clear_attribution_cache()
    sd = paths.sessions_dir()
    if sd.is_dir():
        for p in sd.glob("willow-*"):
            p.unlink()
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rudi")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)
            human_session.clear_attribution_cache()
            if sd.is_dir():
                for p in sd.glob("willow-*"):
                    p.unlink()


def _run(session_id, monkeypatch, *, app_id="willow", operator_verifier=None):
    monkeypatch.setenv("WILLOW_APP_ID", app_id)
    if operator_verifier is None:
        monkeypatch.delenv("WILLOW_OPERATOR_VERIFIER", raising=False)
    else:
        monkeypatch.setenv("WILLOW_OPERATOR_VERIFIER", operator_verifier)
    payload = {"session_id": session_id}
    result = session_start_hook.handle(payload)
    ctx = json.loads(result["additional_context"])
    return ctx


# --- opt-in gate ---------------------------------------------------------


def test_no_operator_verifier_env_means_no_auto_sign(ring_with_rita, monkeypatch):
    """Existing deployments without WILLOW_OPERATOR_VERIFIER set MUST NOT
    change behavior — the session enters unsigned, verifier field is
    empty. Legacy path preserved."""
    ctx = _run("s-legacy-1", monkeypatch)
    # No auto-sign fired
    assert "auto_sign_note" not in ctx
    # Session record has empty verifier (legacy behavior)
    record = dispatch.session_read("willow", "s-legacy-1")
    assert record.get("verifier", "") == ""
    # NOT in attribution cache
    assert not human_session.is_session_attributed("s-legacy-1")


# --- happy path ----------------------------------------------------------


def test_auto_sign_warms_attribution_cache_after_session_enter(
    ring_with_rita, monkeypatch
):
    """The hook writes the sidecar AND warms the attribution cache after
    session_enter succeeds. Both are needed: sidecar for disk-durable
    verification across process restarts, cache for the operator's very
    first envelope_propose without an intermediate orchestrator_write
    to warm from the sidecar-verify path.
    """
    from unittest import mock
    with mock.patch("willow_mcp.server.session_enter",
                    return_value={"entry_mode": "human_orchestrator"}):
        _run("s-cache-warm", monkeypatch, operator_verifier="rudi")
    assert human_session.is_session_attributed("s-cache-warm"), (
        "PR8 hook must warm the attribution cache after a successful "
        "auto-sign + session_enter — sidecar on disk and cache in memory "
        "must agree, so the operator's next call doesn't hit "
        "UnattributedSessionError"
    )


def test_auto_sign_passes_verifier_and_sig_to_session_enter(
    ring_with_rita, monkeypatch
):
    """The whole reason PR8 exists: with WILLOW_OPERATOR_VERIFIER set,
    the hook produces a valid signature and passes it into session_enter
    so the operator doesn't have to run `willow-mcp sign-session` in a
    second terminal.

    Verified by spying on session_enter's kwargs — this test doesn't
    depend on the manifest-ACL layer (that's a downstream gate covered
    elsewhere). The signature validity itself is asserted by round-
    tripping through session_signing.session_is_valid.
    """
    from unittest import mock
    from willow_mcp import session_signing

    captured = {}
    def spy(**kwargs):
        captured.update(kwargs)
        return {"entry_mode": "human_orchestrator", "app_id": "willow"}

    with mock.patch("willow_mcp.server.session_enter", spy):
        ctx = _run("s-happy", monkeypatch, operator_verifier="rudi")

    assert "auto_sign_note" in ctx
    assert "auto-signed by rudi" in ctx["auto_sign_note"]

    # The hook must have passed verifier + attested_at + a real sig
    assert captured.get("verifier") == "rudi"
    assert captured.get("attested_at")
    assert captured.get("seal_sig")

    # The signature must actually verify against the frozen wire message —
    # this is the load-bearing invariant that means downstream session_enter
    # will accept it, no matter what other gates surround it.
    assert session_signing.session_is_valid(
        "willow", "s-happy", "rudi",
        captured["attested_at"], captured["seal_sig"],
    ), (
        "PR8's auto-signed sig must verify against the frozen wire message; "
        "if it doesn't, session_enter's _resolve_session_sig will refuse it"
    )


def test_auto_sign_writes_sidecar_to_disk(ring_with_rita, monkeypatch):
    """PR8 must write the sidecar+sig files to disk (same shape sign_session_cli
    produces), so that orchestrator_write_denial's sidecar-verify path finds
    them on the next orchestrator write. Without this, the operator gets
    refused on the first envelope_propose because the sidecar is missing —
    even though session_enter was passed a valid sig.
    """
    from unittest import mock
    from willow_mcp import paths, session_signing

    with mock.patch("willow_mcp.server.session_enter",
                    return_value={"entry_mode": "human_orchestrator"}):
        _run("s-sidecar-check", monkeypatch, operator_verifier="rudi")

    attest_file = paths.session_attestation_path("willow", "s-sidecar-check")
    sig_file = attest_file.parent / f"{attest_file.name}.sig"
    assert attest_file.is_file(), "auto-sign must write the sidecar to disk"
    assert sig_file.is_file(), "auto-sign must write the .sig alongside"

    # Sidecar payload is the _v2 shape orchestrator_write_denial expects
    payload = json.loads(attest_file.read_text(encoding="utf-8"))
    assert payload["format"] == "orchestrator_session_attestation_v2"
    assert payload["app_id"] == "willow"
    assert payload["session_id"] == "s-sidecar-check"
    assert payload["verifier"] == "rudi"

    # Sig verifies against the frozen wire message — the same check
    # orchestrator_write_denial will run
    sig_hex = sig_file.read_text(encoding="utf-8").strip()
    assert session_signing.session_is_valid(
        "willow", "s-sidecar-check", "rudi",
        payload["attested_at"], sig_hex,
    )


# --- graceful failure modes ---------------------------------------------


def test_auto_sign_downgrades_when_keyring_disabled(monkeypatch):
    """WILLOW_OPERATOR_VERIFIER set but no keyring → hook succeeds, session
    enters unattributed, note explains why."""
    human_session.clear_attribution_cache()
    keyring_mod.set_keyring(None)
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(keyring_mod, "_from_env", None)
    monkeypatch.setattr(keyring_mod, "_loaded_from", None)

    ctx = _run("s-no-keyring", monkeypatch, operator_verifier="rudi")
    assert "auto_sign_note" in ctx
    assert "WILLOW_KEYRING is not" in ctx["auto_sign_note"]
    record = dispatch.session_read("willow", "s-no-keyring")
    assert record.get("verifier", "") == ""


def test_auto_sign_downgrades_when_verifier_unknown(ring_with_rita, monkeypatch):
    """Env var names an unknown verifier → hook succeeds, note explains,
    session unattributed. Points at `willow-mcp keys add` in the message."""
    ctx = _run("s-unknown", monkeypatch, operator_verifier="mallory")
    assert "unknown to the keyring" in ctx["auto_sign_note"]
    assert "willow-mcp keys add mallory" in ctx["auto_sign_note"]
    record = dispatch.session_read("willow", "s-unknown")
    assert record.get("verifier", "") == ""


def test_auto_sign_downgrades_when_verifier_compromised(
    ring_with_rita, monkeypatch
):
    """A compromised verifier is untrusted — same code path as unknown
    (both return None from verifying_entry)."""
    ring_with_rita.revoke("rudi", compromised=True)
    ring_with_rita.save()

    ctx = _run("s-comp", monkeypatch, operator_verifier="rudi")
    assert "unknown to the keyring or compromised" in ctx["auto_sign_note"]
    record = dispatch.session_read("willow", "s-comp")
    assert record.get("verifier", "") == ""


def test_auto_sign_off_for_specialist_workspaces(ring_with_rita, monkeypatch):
    """WILLOW_OPERATOR_VERIFIER is orchestrator-scoped. A specialist
    workspace (app_id != willow) does NOT auto-sign — attribution is a
    seat property, and the seat is Willow's."""
    ctx = _run("s-hanuman", monkeypatch, app_id="hanuman", operator_verifier="rudi")
    # No auto-sign attempted for non-willow app_id
    assert "auto_sign_note" not in ctx or ctx.get("auto_sign_note") == ""


# --- backward compat: WILLOW_APP_ID unset still refuses ------------------


def test_unset_willow_app_id_still_refuses(monkeypatch):
    """PR4's strict-app_id refusal takes precedence over PR8's auto-sign.
    Empty WILLOW_APP_ID → refuse at the boundary, never reach the sign
    path (there's no app_id to bind to)."""
    monkeypatch.delenv("WILLOW_APP_ID", raising=False)
    monkeypatch.setenv("WILLOW_OPERATOR_VERIFIER", "rudi")
    result = session_start_hook.handle({"session_id": "s-no-app"})
    ctx = result.get("additional_context", "")
    assert "WILLOW_APP_ID is not set" in ctx
