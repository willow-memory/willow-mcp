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


def _audit_packet(cites: str, ref_style: str = "bare", accept: bool = True) -> str:
    ref = {
        "bare": cites,
        "prefixed": f"dispatch:{cites}",
        "prose": f"dispatch {cites} (Hanuman handoff, verified)",
    }[ref_style]
    sent = ds.dispatch_send(
        "willow", "loki", "# Audit\n\nRead the builder's packet.\n",
        summary="audit", context_refs=[ref, "Nestor pair 11ccb0f7 (sealed)"],
    )
    did = sent["dispatch_id"]
    if accept:
        ds.dispatch_accept(did, "loki", session_id="s-audit")
    return did


# ── citation_set: the id parse ───────────────────────────────────────────────

def test_citation_set_parses_bare_prefixed_and_prose_and_ignores_the_rest():
    meta = {"context_refs": [
        "67E344A9",
        "dispatch:73d3e5d8",
        "dispatch 74E87D5C (Hanuman handoff, verified; handoff.json in the packet dir)",
        "Nestor pair 11ccb0f7-6323-40ef-84a5-913336395b03 (sealed)",
        "FRANK 2ff5a399-2041-41a4-845d-129ace0f9f2c",
        "gap 6ac14a6c7a0b",
        42,
    ]}
    assert ds.citation_set(meta) == {"67E344A9", "73D3E5D8", "74E87D5C"}


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

@pytest.mark.parametrize("style", ["bare", "prefixed", "prose"])
def test_citing_packet_working_grants_read_with_via(seats, style):
    builder = _builder_packet()
    audit = _audit_packet(builder, ref_style=style)
    out = server.dispatch_read("loki", builder)
    assert out.get("error") is None, out
    assert out["via"] == audit and out["via_status"] == "working"
    assert "Ship it" in out["assignment"]
    ho_out = server.handoff_read("loki", builder)
    assert ho_out["via"] == audit
    assert ho_out["handoff"]["findings"][0]["evidence"] == ["a.py:1"]


def test_citation_read_is_receipted_with_via(seats):
    builder = _builder_packet()
    audit = _audit_packet(builder)
    server.dispatch_read("loki", builder)
    rows = server._receipt_log.tail("loki", limit=10)
    hits = [r for r in rows if r.get("detail") and "citation_read" in r["detail"]]
    assert hits, rows
    detail = json.loads(hits[0]["detail"])
    assert detail == {"citation_read": builder, "via": audit}


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
