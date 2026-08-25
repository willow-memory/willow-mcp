"""PR4: _attributed_sessions lazy cache in orchestrator_write_denial.

Invariants:
* First orchestrator write for a session pays the on-disk verify; subsequent
  writes are O(1) set-membership.
* A failed verify clears the cache — a cached session that lost its trust
  (revocation, tampering) does not silently continue to be allowed.
* Deleting the live session file drops the cache entry.
* clear_attribution_cache() with no argument clears the whole cache
  (restart-equivalent for post-revocation environments).
"""
from __future__ import annotations

import argparse
import json
from unittest import mock

import pytest

from willow_mcp import (
    dispatch,
    human_session,
    keyring as keyring_mod,
    paths,
    session_signing,
    sign_session_cli,
)


@pytest.fixture
def ring_with_rita(tmp_path):
    human_session.clear_attribution_cache()  # tests interact via a shared process-global
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)
            human_session.clear_attribution_cache()


def _attest(session_id: str, verifier: str = "rita"):
    """session_enter + sign-session for a session under `verifier`."""
    sig = session_signing.sign_session(
        "willow", session_id, verifier, "2026-08-25T00:00:00Z"
    )
    dispatch.session_enter(
        app_id="willow",
        session_id=session_id,
        verifier=verifier,
        attested_at="2026-08-25T00:00:00Z",
        seal_sig=sig,
    )
    ns = argparse.Namespace(session_id=session_id, verifier=verifier)
    with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
        rc = sign_session_cli.cmd_sign_session(ns)
    assert rc == sign_session_cli.EXIT_OK


def _wd(session_id: str, monkeypatch) -> str | None:
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    return human_session.orchestrator_write_denial(
        app_id="willow",
        tool_name="dispatch_send",
        serve_mode=False,
        session_id=session_id,
    )


# --- cache lifecycle ------------------------------------------------------


def test_first_verify_populates_cache(ring_with_rita, monkeypatch):
    _attest("s-first")
    assert not human_session.is_session_attributed("s-first")

    assert _wd("s-first", monkeypatch) is None  # allowed
    assert human_session.is_session_attributed("s-first"), (
        "successful verify must populate the attribution cache"
    )


def test_subsequent_verify_skips_crypto(ring_with_rita, monkeypatch):
    """The whole optimization: after the first verify populates the cache,
    later writes never touch _verify_v2_sidecar_via_keyring."""
    _attest("s-hot")
    assert _wd("s-hot", monkeypatch) is None  # warms the cache

    with mock.patch.object(
        human_session, "_verify_v2_sidecar_via_keyring"
    ) as verify_mock:
        # Should NOT be called — cache hit short-circuits before the sidecar
        # check reaches this function.
        assert _wd("s-hot", monkeypatch) is None
        assert verify_mock.call_count == 0


def test_failed_verify_clears_cache(ring_with_rita, monkeypatch):
    _attest("s-tamper")
    assert _wd("s-tamper", monkeypatch) is None  # baseline
    assert human_session.is_session_attributed("s-tamper")

    # Tamper: swap the verifier field on the sidecar. The signature no longer
    # matches. A fresh verify must fail — and drop the cache entry.
    # We force a re-verify by clearing the cache first, then triggering a
    # failing verify that must not re-cache.
    human_session.clear_attribution_cache("s-tamper")

    ring_with_rita.add("sam")
    ring_with_rita.save()
    attest = paths.session_attestation_path("willow", "s-tamper")
    payload = json.loads(attest.read_text(encoding="utf-8"))
    payload["verifier"] = "sam"
    attest.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    denial = _wd("s-tamper", monkeypatch)
    assert denial is not None  # refused
    assert not human_session.is_session_attributed("s-tamper"), (
        "a failed verify must NOT leave the session in the attribution cache"
    )


def test_missing_live_session_file_drops_cache(ring_with_rita, monkeypatch):
    _attest("s-live")
    assert _wd("s-live", monkeypatch) is None
    assert human_session.is_session_attributed("s-live")

    # Delete the live session record — the session is no longer bound.
    paths.session_path("willow", "s-live").unlink()

    denial = _wd("s-live", monkeypatch)
    assert denial is not None
    assert "missing" in denial
    assert not human_session.is_session_attributed("s-live"), (
        "deleting the live session file must drop the cache entry — "
        "orchestrator writes arming against a session no longer live is the "
        "very failure this cache invalidation prevents"
    )


def test_clear_cache_empty_arg_clears_all(ring_with_rita, monkeypatch):
    _attest("s-a")
    _attest("s-b")
    assert _wd("s-a", monkeypatch) is None
    assert _wd("s-b", monkeypatch) is None
    assert human_session.is_session_attributed("s-a")
    assert human_session.is_session_attributed("s-b")

    human_session.clear_attribution_cache()  # no argument = clear all
    assert not human_session.is_session_attributed("s-a")
    assert not human_session.is_session_attributed("s-b")


def test_clear_cache_specific_id_leaves_others(ring_with_rita, monkeypatch):
    _attest("s-keep")
    _attest("s-drop")
    _wd("s-keep", monkeypatch)
    _wd("s-drop", monkeypatch)

    human_session.clear_attribution_cache("s-drop")
    assert human_session.is_session_attributed("s-keep")
    assert not human_session.is_session_attributed("s-drop")


# --- keyring compromise invalidates cached attribution --------------------


def test_compromise_plus_cache_clear_denies_previously_allowed(
    ring_with_rita, monkeypatch
):
    """The revocation-across-processes reality: `willow-mcp keys revoke` runs
    in a separate process and the server does not see the change until
    someone drops the in-process cache. This models what happens when the
    operator clears the cache after revoking (or restarts, equivalent):
    the cached session must not silently continue to be allowed."""
    _attest("s-comp")
    assert _wd("s-comp", monkeypatch) is None
    assert human_session.is_session_attributed("s-comp")

    ring_with_rita.revoke("rita", reason="stolen", compromised=True)
    ring_with_rita.save()
    human_session.clear_attribution_cache()  # simulates operator restart / manual clear

    denial = _wd("s-comp", monkeypatch)
    assert denial is not None, (
        "after keyring compromise + cache clear, the previously-cached "
        "session must fail fresh verification"
    )
