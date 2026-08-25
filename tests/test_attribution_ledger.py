"""PR4: attribution_ledger — append-only hash chain of session attestations.

The invariants:
* head() returns "genesis" for an absent or empty ledger.
* append() links each entry to the previous via prev = sha256(prev line).
* verify() walks the chain and refuses on any break.
* verify(expected_head=…) closes the last-line-is-editable gap.
* entries() returns lines without verifying, filterable by session_id.
* sign-session writes a ledger entry after a successful attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from unittest import mock

import pytest

from willow_mcp import (
    attribution_ledger,
    dispatch,
    human_session,
    keyring as keyring_mod,
    paths,
    session_signing,
    sign_session_cli,
)


@pytest.fixture
def ring_with_rita(tmp_path):
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("rita")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


def _fresh_ledger():
    """Delete any pre-existing ledger before a test; conftest points $WILLOW_HOME
    at a tmp dir so this is scoped to the test's own state."""
    p = paths.attribution_ledger_path()
    if p.exists():
        p.unlink()
    return p


# --- head() ---------------------------------------------------------------


def test_head_returns_genesis_when_absent():
    p = _fresh_ledger()
    assert not p.exists()
    assert attribution_ledger.head() == "genesis"


def test_head_returns_genesis_for_empty_file(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    assert attribution_ledger.head(p) == "genesis"


def test_head_returns_sha_of_last_line(tmp_path):
    p = tmp_path / "one.jsonl"
    line = '{"kind":"session_attestation","session_id":"s","prev":"genesis"}'
    p.write_text(line + "\n", encoding="utf-8")
    expected = hashlib.sha256(line.encode("utf-8")).hexdigest()
    assert attribution_ledger.head(p) == expected


# --- append() -------------------------------------------------------------


def test_append_links_to_genesis_for_first_entry():
    _fresh_ledger()
    new_head = attribution_ledger.append(
        session_id="s-1",
        verifier="rita",
        attested_at="2026-08-25T00:00:00Z",
        sig_digest="abcd" * 16,
    )
    # New head is not "genesis"; there is now a line to hash
    assert new_head != "genesis"
    p = paths.attribution_ledger_path()
    line = p.read_text(encoding="utf-8").strip()
    rec = json.loads(line)
    assert rec["prev"] == "genesis"
    assert rec["session_id"] == "s-1"
    assert rec["verifier"] == "rita"
    assert new_head == hashlib.sha256(line.encode("utf-8")).hexdigest()


def test_append_chains_multiple_entries():
    _fresh_ledger()
    h1 = attribution_ledger.append("s-1", "rita", "t1", "d1")
    h2 = attribution_ledger.append("s-2", "sam", "t2", "d2")
    h3 = attribution_ledger.append("s-1", "rita", "t3", "d3")  # re-attest

    lines = paths.attribution_ledger_path().read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["prev"] == "genesis"
    assert json.loads(lines[1])["prev"] == h1
    assert json.loads(lines[2])["prev"] == h2
    assert attribution_ledger.head() == h3


# --- verify() -------------------------------------------------------------


def test_verify_passes_on_intact_chain():
    _fresh_ledger()
    attribution_ledger.append("s-1", "rita", "t1", "d1")
    attribution_ledger.append("s-2", "sam", "t2", "d2")
    ok, detail = attribution_ledger.verify()
    assert ok
    assert "2 entries" in detail


def test_verify_passes_when_absent_and_head_is_genesis():
    _fresh_ledger()
    ok, detail = attribution_ledger.verify()
    assert ok
    assert "no ledger yet" in detail


def test_verify_refuses_when_absent_but_head_expected():
    _fresh_ledger()
    ok, detail = attribution_ledger.verify(expected_head="deadbeef" * 8)
    assert not ok
    assert "missing" in detail


def test_verify_catches_tampered_middle_line():
    _fresh_ledger()
    attribution_ledger.append("s-1", "rita", "t1", "d1")
    attribution_ledger.append("s-2", "sam", "t2", "d2")
    attribution_ledger.append("s-3", "rita", "t3", "d3")
    p = paths.attribution_ledger_path()
    lines = p.read_text(encoding="utf-8").splitlines()
    # Tamper with the middle line's verifier — its bytes change, so the next
    # line's prev no longer matches.
    tampered = json.loads(lines[1])
    tampered["verifier"] = "mallory"
    lines[1] = json.dumps(tampered, separators=(",", ":"), ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, detail = attribution_ledger.verify()
    assert not ok
    assert "broken chain at line 3" in detail


def test_verify_catches_edited_last_line_via_expected_head():
    """Nestor's ledger docstring names this: the walk alone can't catch a
    last-line edit; expected_head closes it."""
    _fresh_ledger()
    attribution_ledger.append("s-1", "rita", "t1", "d1")
    good_head = attribution_ledger.append("s-2", "sam", "t2", "d2")

    p = paths.attribution_ledger_path()
    lines = p.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[-1])
    tampered["verifier"] = "mallory"
    lines[-1] = json.dumps(tampered, separators=(",", ":"), ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Walk-alone passes (last-line-editable property)
    ok, _ = attribution_ledger.verify()
    assert ok
    # With expected_head, the tampered tip is caught
    ok, detail = attribution_ledger.verify(expected_head=good_head)
    assert not ok
    assert "last entry was edited" in detail


def test_verify_catches_non_json_line():
    _fresh_ledger()
    attribution_ledger.append("s-1", "rita", "t1", "d1")
    p = paths.attribution_ledger_path()
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("not json\n")

    ok, detail = attribution_ledger.verify()
    assert not ok
    assert "not valid JSON" in detail


# --- entries() ------------------------------------------------------------


def test_entries_returns_empty_for_absent_ledger():
    _fresh_ledger()
    assert attribution_ledger.entries() == []


def test_entries_returns_all_by_default():
    _fresh_ledger()
    attribution_ledger.append("s-1", "rita", "t1", "d1")
    attribution_ledger.append("s-2", "sam", "t2", "d2")
    got = attribution_ledger.entries()
    assert [e["session_id"] for e in got] == ["s-1", "s-2"]


def test_entries_filters_by_session_id():
    _fresh_ledger()
    attribution_ledger.append("s-1", "rita", "t1", "d1")
    attribution_ledger.append("s-2", "sam", "t2", "d2")
    attribution_ledger.append("s-1", "rita", "t3", "d3")  # re-attest
    got = attribution_ledger.entries(session_id="s-1")
    assert len(got) == 2
    assert all(e["session_id"] == "s-1" for e in got)


def test_entries_skips_unparseable_but_still_returns_parseable():
    _fresh_ledger()
    attribution_ledger.append("s-1", "rita", "t1", "d1")
    p = paths.attribution_ledger_path()
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("not json\n")
    attribution_ledger.append("s-2", "sam", "t2", "d2")

    got = attribution_ledger.entries()
    assert [e["session_id"] for e in got] == ["s-1", "s-2"]


# --- sig_digest_hex helper ------------------------------------------------


def test_sig_digest_hex_is_sha256_of_hex_bytes():
    sig = "deadbeef" * 16
    got = attribution_ledger.sig_digest_hex(sig)
    assert got == hashlib.sha256(sig.encode("utf-8")).hexdigest()


# --- sign-session integration --------------------------------------------


def test_sign_session_appends_ledger_entry(ring_with_rita):
    _fresh_ledger()
    sig = session_signing.sign_session(
        "willow", "s-attested", "rita", "2026-08-25T00:00:00Z"
    )
    dispatch.session_enter(
        app_id="willow",
        session_id="s-attested",
        verifier="rita",
        attested_at="2026-08-25T00:00:00Z",
        seal_sig=sig,
    )
    ns = argparse.Namespace(session_id="s-attested", verifier="rita")
    with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
        rc = sign_session_cli.cmd_sign_session(ns)
    assert rc == sign_session_cli.EXIT_OK

    got = attribution_ledger.entries(session_id="s-attested")
    assert len(got) == 1
    assert got[0]["verifier"] == "rita"
    assert got[0]["prev"] == "genesis"
    assert "sig_digest" in got[0]


def test_sign_session_re_attestation_creates_new_ledger_entry(ring_with_rita):
    """Re-attesting the same session appends a fresh entry — the whole trust
    history is preserved, not overwritten. The chain's `prev` differs even
    when the underlying payload is identical (same second, same verifier),
    so two ledger entries land regardless of attested_at resolution."""
    _fresh_ledger()
    for _ in range(2):
        sig = session_signing.sign_session(
            "willow", "s-multi", "rita", "2026-08-25T00:00:00Z"
        )
        dispatch.session_enter(
            app_id="willow",
            session_id="s-multi",
            verifier="rita",
            attested_at="2026-08-25T00:00:00Z",
            seal_sig=sig,
        )
        ns = argparse.Namespace(session_id="s-multi", verifier="rita")
        with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
            sign_session_cli.cmd_sign_session(ns)

    got = attribution_ledger.entries(session_id="s-multi")
    assert len(got) == 2, (
        f"re-attest must append, not overwrite; got {len(got)} entries"
    )
    # The two entries' prev fields must differ — the second links to the first
    assert got[0]["prev"] != got[1]["prev"]
    assert got[1]["prev"] != "genesis"


def test_ledger_chain_survives_a_full_pr3_cycle(ring_with_rita):
    """End-to-end: enter session → sign → verify chain → repeat. The chain
    must remain intact across multiple attestations of the same and
    different sessions."""
    _fresh_ledger()
    for session_id, verifier_name in [
        ("s-a", "rita"),
        ("s-b", "rita"),
        ("s-a", "rita"),  # re-attest s-a
    ]:
        sig = session_signing.sign_session(
            "willow", session_id, verifier_name, "2026-08-25T00:00:00Z"
        )
        dispatch.session_enter(
            app_id="willow",
            session_id=session_id,
            verifier=verifier_name,
            attested_at="2026-08-25T00:00:00Z",
            seal_sig=sig,
        )
        ns = argparse.Namespace(session_id=session_id, verifier=verifier_name)
        with mock.patch.object(human_session, "require_operator_terminal", lambda: None):
            sign_session_cli.cmd_sign_session(ns)

    ok, detail = attribution_ledger.verify()
    assert ok, detail
    assert "3 entries" in detail
