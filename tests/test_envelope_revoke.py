"""Envelope revocation: the writer for a state the gate already honoured.

Before this, `envelopes.py` refused a row carrying ``revoked``/``status ==
"revoked"`` and nothing in the codebase could set either — `envelope reject`
acts on pending PROPOSALS, not live grants. Withdrawing an envelope meant
hand-editing `constitutional/pre-approved.json`, the trust root, which is the
act the envelope programme exists to keep hands off.

These tests pin the three properties that make revocation safe: the row is
KEPT (a disappeared grant cannot be audited), the operator keyring is required,
and the gate stops honouring the grant immediately.
"""
import json

import pytest

from willow_mcp import envelope_authoring as ea
from willow_mcp import envelopes


def _registry(extra=None):
    return {
        "schema": "test",
        "active": [
            {
                "id": "env-dispatch-1", "verb_id": 11, "verb": "dispatch",
                "grantee": "willow", "bounds": {"to_agents": ["loki"],
                                                "task_class": ["auditor"]},
                "issued_by": "root", "issued_at": "2026-01-01T00:00:00Z",
                "ratified_via": "frank ledger entry abc", "expires_at": None,
                "max_count": None, "use_count_source": "frank", "status": "active",
            },
            *(extra or []),
        ],
        "proposals": [],
    }


@pytest.fixture
def register(tmp_path, monkeypatch):
    p = tmp_path / "pre-approved.json"
    p.write_text(json.dumps(_registry()))
    monkeypatch.setattr(envelopes, "registry_path", lambda: p)
    monkeypatch.setattr(ea, "_load_registry", lambda: json.loads(p.read_text()))
    monkeypatch.setattr(ea, "_keyring_verifier_active", lambda v: v == "sean")
    return p


class _Ledger:
    def __init__(self, fail=False):
        self.entries = []
        self.fail = fail

    def append(self, project, event_type, content):
        if self.fail:
            raise RuntimeError("postgres_unavailable")
        self.entries.append((project, event_type, content))
        return "rec-1"


def test_revoke_keeps_the_row_rather_than_deleting_it(register):
    ea.revoke("env-dispatch-1", verifier="sean", reason="redundant")
    reg = json.loads(register.read_text())
    assert len(reg["active"]) == 1, "the row must survive; a vanished grant cannot be audited"
    row = reg["active"][0]
    assert row["status"] == "revoked" and row["revoked"] is True
    assert row["revoked_by"] == "sean"
    assert row["revoked_reason"] == "redundant"
    assert row["revoked_at"]
    # what it WAS must still be readable
    assert row["bounds"] == {"to_agents": ["loki"], "task_class": ["auditor"]}
    assert row["ratified_via"] == "frank ledger entry abc"


def test_the_gate_stops_honouring_a_revoked_envelope(register):
    assert envelopes.governing_envelope_ids("dispatch", "willow") == ["env-dispatch-1"]
    ea.revoke("env-dispatch-1", verifier="sean", reason="redundant")
    assert envelopes.governing_envelope_ids("dispatch", "willow") == []


def test_revoke_requires_an_operator_verifier(register):
    with pytest.raises(ea.OperatorVerifierRequired):
        ea.revoke("env-dispatch-1", verifier="an-agent", reason="because I said so")
    assert json.loads(register.read_text())["active"][0]["status"] == "active"


def test_revoke_requires_a_reason(register):
    with pytest.raises(ea.EnvelopeAuthoringError):
        ea.revoke("env-dispatch-1", verifier="sean", reason="   ")
    assert json.loads(register.read_text())["active"][0]["status"] == "active"


def test_governing_envelopes_returns_full_rows_and_matches_the_id_projection(register):
    """`governing_envelopes` is the fuller sibling `_ambiguous_envelope_detail`
    (server.py) builds its EAMBIG message from -- it must return the whole
    row (bounds included), and its ids must always agree with
    `governing_envelope_ids`, since the two are one resolution, not two."""
    rows = envelopes.governing_envelopes("dispatch", "willow")
    assert [row["id"] for row in rows] == envelopes.governing_envelope_ids("dispatch", "willow")
    assert rows[0]["bounds"] == {"to_agents": ["loki"], "task_class": ["auditor"]}

    ea.revoke("env-dispatch-1", verifier="sean", reason="redundant")
    assert envelopes.governing_envelopes("dispatch", "willow") == []


def test_revoking_an_unknown_envelope_is_refused(register):
    with pytest.raises(ea.EnvelopeNotFoundError):
        ea.revoke("env-nope", verifier="sean", reason="x")


def test_revoking_twice_is_refused_rather_than_silently_reapplied(register):
    ea.revoke("env-dispatch-1", verifier="sean", reason="first")
    with pytest.raises(ea.EnvelopeAuthoringError):
        ea.revoke("env-dispatch-1", verifier="sean", reason="second")
    assert json.loads(register.read_text())["active"][0]["revoked_reason"] == "first"


def test_revocation_is_ledgered(register):
    led = _Ledger()
    out = ea.revoke("env-dispatch-1", verifier="sean", reason="redundant", ledger=led)
    assert out["ledger_record_id"] == "rec-1"
    project, event_type, content = led.entries[0]
    assert event_type == ea.FRANK_EVENT_REVOKED
    assert content["envelope_id"] == "env-dispatch-1"
    assert content["revoked_by"] == "sean"
    assert content["reason"] == "redundant"


def test_a_ledger_outage_does_not_undo_the_revocation(register):
    out = ea.revoke("env-dispatch-1", verifier="sean", reason="redundant",
                    ledger=_Ledger(fail=True))
    assert out["ledger_error"]
    assert json.loads(register.read_text())["active"][0]["status"] == "revoked"


# ── the listing must not disagree with the gate ──────────────────────────────

def test_list_active_excludes_revoked(register):
    assert [r["id"] for r in ea.list_active()] == ["env-dispatch-1"]
    ea.revoke("env-dispatch-1", verifier="sean", reason="redundant")
    assert ea.list_active() == []


def test_list_revoked_shows_what_was_withdrawn(register):
    ea.revoke("env-dispatch-1", verifier="sean", reason="redundant")
    rows = ea.list_revoked()
    assert [r["id"] for r in rows] == ["env-dispatch-1"]
    assert rows[0]["revoked_reason"] == "redundant"


def test_list_active_honours_a_row_marked_revoked_by_hand(tmp_path, monkeypatch):
    """A register edited outside this module (which is how it had to be done
    before `revoke` existed) must read the same way here as at the gate."""
    p = tmp_path / "pre-approved.json"
    reg = _registry()
    reg["active"][0]["status"] = "revoked"
    reg["active"][0]["revoked"] = True
    p.write_text(json.dumps(reg))
    monkeypatch.setattr(envelopes, "registry_path", lambda: p)
    monkeypatch.setattr(ea, "_load_registry", lambda: json.loads(p.read_text()))
    assert ea.list_active() == []
    assert envelopes.governing_envelope_ids("dispatch", "willow") == []
