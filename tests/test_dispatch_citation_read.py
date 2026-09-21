"""Cited-packet read (gaps fe3ae204a964 / e40691d86df6).

An audit packet cites the builder's dispatch_id in its context_refs; the
auditor must be able to read the cited packet (brief + handoff) through the
verbs, not off disk. B-54 (#242) still holds: no seat reads a packet it has
no relationship to, the relationship is the orchestrator-written citation
in the signed meta of a working/complete packet addressed to the reader,
depth one, read only, receipted with `via`.
"""
import json

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import handoff as ho
from willow_mcp import server


@pytest.fixture(autouse=True)
def _fresh_rate_buckets():
    server._buckets.clear()
    yield
    server._buckets.clear()


def _write_manifest(home, app_id, **overrides):
    d = home / "mcp_apps" / app_id
    d.mkdir(parents=True, exist_ok=True)
    data = {"app_id": app_id, "permissions": ["dispatch_read", "dispatch_write"]}
    data.update(overrides)
    (d / "manifest.json").write_text(json.dumps(data))


@pytest.fixture
def seats(home):
    for app in ("hanuman", "loki", "jeles"):
        _write_manifest(home, app)
    return home


def _builder_packet(done: bool = True) -> str:
    sent = ds.dispatch_send("willow", "hanuman", "# Build\n\nShip it.\n", summary="build")
    did = sent["dispatch_id"]
    ds.dispatch_accept(did, "hanuman", session_id="s-build")
    if done:
        ho.handoff_write_v4(
            "hanuman", did, narrative="Built.",
            findings=[{"id": "f1", "text": "x", "severity": "low", "evidence": ["a.py:1"]}],
        )
    return did


def _audit_packet(
    cites: str, ref_style: str = "bare", accept: bool = True,
    sender: str = "willow", to: str = "loki",
) -> str:
    ref = {
        "bare": cites,
        "prefixed": f"dispatch:{cites}",
    }[ref_style]
    sent = ds.dispatch_send(
        sender, to, "# Audit\n\nRead the builder's packet.\n",
        summary="audit", context_refs=[ref, "Nestor pair 11ccb0f7 (sealed)"],
    )
    assert "dispatch_id" in sent, sent
    did = sent["dispatch_id"]
    if accept:
        ds.dispatch_accept(did, to, session_id=f"s-audit-{to}")
    return did


# ── citation_set: the id parse ───────────────────────────────────────────────

def test_citation_set_takes_only_bare_and_prefixed_entries():
    """Loki 40A353F2 A2: an entry cites only when it IS the id. Prose is not a
    citation — "see dispatch DEADBEEF-ish notes" used to mint DEADBEEF."""
    meta = {"context_refs": [
        "67E344A9",
        " dispatch:73d3e5d8 ",
        "dispatch 74E87D5C (Hanuman handoff, verified; handoff.json in the packet dir)",
        "see dispatch DEADBEEF-ish notes",
        "dispatch:DEADBEEF-ish",
        "DEADBEEF0",
        "Nestor pair 11ccb0f7-6323-40ef-84a5-913336395b03 (sealed)",
        "FRANK 2ff5a399-2041-41a4-845d-129ace0f9f2c",
        "gap 6ac14a6c7a0b",
        42,
    ]}
    assert ds.citation_set(meta) == {"67E344A9", "73D3E5D8"}


def test_citation_set_empty_when_no_refs():
    assert ds.citation_set({}) == set()
    assert ds.citation_set({"context_refs": ["just words"]}) == set()


# ── party reads unchanged ────────────────────────────────────────────────────

def test_party_reads_still_pass_without_via(seats):
    did = _builder_packet()
    out = server.dispatch_read("hanuman", did)
    assert out["dispatch_id"] == did and "via" not in out
    out = server.handoff_read("hanuman", did)
    assert out["handoff"]["narrative"] == "Built." and "via" not in out


def test_unrelated_seat_refused_with_the_citation_hint(seats):
    did = _builder_packet()
    out = server.dispatch_read("jeles", did)
    assert out["error"] == "not_party_to_dispatch"
    assert "context_refs" in out["message"]
    assert server.handoff_read("jeles", did)["error"] == "not_party_to_dispatch"


# ── the citation grant ───────────────────────────────────────────────────────

@pytest.mark.parametrize("style", ["bare", "prefixed"])
def test_orchestrator_audit_packet_citing_build_packet_grants_read_with_via(seats, style):
    """The case the feature exists for: willow → loki audit citing the
    willow → hanuman build packet."""
    builder = _builder_packet()
    audit = _audit_packet(builder, ref_style=style)
    out = server.dispatch_read("loki", builder)
    assert out.get("error") is None, out
    assert out["via"] == audit and out["via_status"] == "working"
    assert out["via_from"] == "willow"
    assert "Ship it" in out["assignment"]
    ho_out = server.handoff_read("loki", builder)
    assert ho_out["via"] == audit
    assert ho_out["handoff"]["findings"][0]["evidence"] == ["a.py:1"]


def test_citation_read_is_receipted_with_via_and_who_vouched(seats):
    builder = _builder_packet()
    audit = _audit_packet(builder)
    server.dispatch_read("loki", builder)
    rows = server._receipt_log.tail("loki", limit=10)
    hits = [r for r in rows if r.get("detail") and "citation_read" in r["detail"]]
    assert hits, rows
    detail = json.loads(hits[0]["detail"])
    assert detail == {"citation_read": builder, "via": audit, "via_from": "willow"}


# ── who may vouch (Loki 40A353F2, A1) ────────────────────────────────────────

def test_a_seat_cannot_mint_its_own_citation(seats):
    """Loki's reproduction: loki → loki citing X (a willow → hanuman packet loki
    is no party to), accept, read X. Refused at the send; and even a
    self-addressed packet planted on disk vouches for nothing."""
    builder = _builder_packet()
    sent = ds.dispatch_send("loki", "loki", "# Mine\n", context_refs=[builder])
    assert sent["error"] == "EINVAL"
    assert "sent to its sender" in sent["message"]
    assert server.dispatch_send("loki", "loki", "# Mine\n", context_refs=[builder])["error"] == "EINVAL"
    assert ds.citation_read_access("loki", builder) is None
    assert server.dispatch_read("loki", builder)["error"] == "not_party_to_dispatch"


def test_planted_self_addressed_packet_vouches_for_nothing(seats, home):
    """Belt and braces: bypass dispatch_send's refusal by rewriting a real
    packet's from_app to loki and re-signing it with the runtime key — the
    signature verifies, but from_app loki is no party to the cited packet,
    so citation_may_vouch says no."""
    from willow_mcp import dispatch_signing
    builder = _builder_packet()
    audit = _audit_packet(builder)  # willow → loki, working, cites builder
    assert ds.citation_read_access("loki", builder)["via"] == audit
    meta_path = home / "dispatch" / audit / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["from_app"] = "loki"
    meta.pop("signature", None)
    meta["signature"] = dispatch_signing.sign_meta(meta)
    meta_path.write_text(json.dumps(meta))
    assert dispatch_signing.signature_status(meta) == dispatch_signing.SIG_VALID
    assert ds.citation_read_access("loki", builder) is None


def test_specialist_sender_vouches_only_when_party_to_the_cited_packet(seats):
    """hanuman → loki citing the willow → hanuman build packet: granted, and
    only because hanuman is to_app of the cited one."""
    builder = _builder_packet()
    handoff = _audit_packet(builder, sender="hanuman", to="loki")
    out = server.dispatch_read("loki", builder)
    assert out.get("error") is None, out
    assert out["via"] == handoff and out["via_from"] == "hanuman"


def test_specialist_stranger_to_the_cited_packet_cannot_vouch(seats):
    """jeles → loki citing the willow → hanuman build packet: jeles is no
    party to it, so its packet opens nothing to loki."""
    builder = _builder_packet()
    _audit_packet(builder, sender="jeles", to="loki")
    assert ds.citation_read_access("loki", builder) is None
    assert server.dispatch_read("loki", builder)["error"] == "not_party_to_dispatch"


def test_citation_may_vouch_rules():
    cited = {"from_app": "willow", "to_app": "hanuman", "reply_to": "willow"}
    assert ds.citation_may_vouch({"from_app": "willow"}, cited) is True
    assert ds.citation_may_vouch({"from_app": "hanuman"}, cited) is True
    assert ds.citation_may_vouch({"from_app": "HANUMAN"}, cited) is True
    assert ds.citation_may_vouch({"from_app": "loki"}, cited) is False
    assert ds.citation_may_vouch({"from_app": ""}, cited) is False
    assert ds.citation_may_vouch({}, cited) is False


def test_citation_of_a_missing_packet_grants_nothing(seats):
    sent = ds.dispatch_send("willow", "loki", "# x\n", context_refs=["0BADF00D"])
    ds.dispatch_accept(sent["dispatch_id"], "loki", session_id="s")
    assert ds.citation_read_access("loki", "0BADF00D") is None


def test_citing_packet_still_pending_grants_nothing(seats):
    builder = _builder_packet()
    _audit_packet(builder, accept=False)
    assert server.dispatch_read("loki", builder)["error"] == "not_party_to_dispatch"


def test_citing_packet_complete_still_grants(seats):
    builder = _builder_packet()
    audit = _audit_packet(builder)
    ho.handoff_write_v4("loki", audit, narrative="Audited.", findings=[])
    assert server.dispatch_read("loki", builder)["via"] == audit


def test_citation_of_a_citation_grants_nothing(seats):
    builder = _builder_packet()
    audit = _audit_packet(builder)  # loki cites builder
    # jeles is sent a packet citing the AUDIT, not the builder
    sent = ds.dispatch_send("willow", "jeles", "# Rework\n", context_refs=[audit])
    ds.dispatch_accept(sent["dispatch_id"], "jeles", session_id="s-rw")
    assert server.dispatch_read("jeles", audit)["via"] == sent["dispatch_id"]
    assert server.dispatch_read("jeles", builder)["error"] == "not_party_to_dispatch"


def test_citation_grants_only_to_the_citing_packets_to_app(seats):
    builder = _builder_packet()
    _audit_packet(builder)  # addressed to loki
    assert server.dispatch_read("jeles", builder)["error"] == "not_party_to_dispatch"


def test_write_verbs_never_pass_through_a_citation(seats):
    builder = _builder_packet(done=False)  # working, not yet complete
    _audit_packet(builder)
    acc = server.dispatch_accept("loki", builder)
    assert acc["error"] == "wrong_recipient"
    wr = server.handoff_write_v4("loki", builder, narrative="x")
    assert wr["error"] == "wrong_recipient"


def test_forged_citing_packet_grants_nothing(seats, home):
    builder = _builder_packet()
    audit = _audit_packet(builder)
    # tamper the citing packet's meta so its signature no longer verifies
    meta_path = home / "dispatch" / audit / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["context_refs"].append("deadbeef")
    meta_path.write_text(json.dumps(meta))
    assert server.dispatch_read("loki", builder)["error"] == "not_party_to_dispatch"


def test_self_citation_is_ignored(seats):
    builder = _builder_packet()
    sent = ds.dispatch_send("willow", "loki", "# x\n", context_refs=[])
    did = sent["dispatch_id"]
    ds.dispatch_accept(did, "loki", session_id="s")
    assert ds.citation_read_access("loki", did) is None
    assert ds.citation_read_access("loki", builder) is None
