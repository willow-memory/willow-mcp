"""WitnessCollector + coerce_witnesses + the _mem_ratify_gate seam.

Everything the vendored mem_ratify tests can't cover — because the
vendored copy has no supply — is covered here. The vendored files are
NOT touched by any of this: the collector is a sibling.
"""
from __future__ import annotations

import pytest

import importlib

from willow_mcp import mem_ratify, server
from willow_mcp.mem_ratify.collect import (
    ProposerAsWitnessError,
    WitnessCollector,
    coerce_witnesses,
)


# ── WitnessCollector: construction + dedup + proposer-guard ────────────────
def test_collector_requires_proposer_id():
    with pytest.raises(ValueError, match="proposer_id"):
        WitnessCollector(proposer_id="")


def test_collector_dedupes_on_agent_id():
    c = WitnessCollector(proposer_id="app")
    c.add("witness-a", "gpt-5", independence_evidence="review-1")
    c.add("witness-a", "gpt-5", independence_evidence="review-2-updated")
    assert len(c) == 1, "same agent_id must not double-count"
    (only,) = c.witnesses()
    assert only.independence_evidence == "review-2-updated", "last add wins"


def test_collector_refuses_proposer_as_witness():
    c = WitnessCollector(proposer_id="app-42")
    with pytest.raises(ProposerAsWitnessError, match="§0.2"):
        c.add("app-42", "gpt-5", independence_evidence="self-vouch")


def test_collector_requires_agent_and_base_model():
    c = WitnessCollector(proposer_id="app")
    with pytest.raises(ValueError, match="agent_id"):
        c.add("", "gpt-5")
    with pytest.raises(ValueError, match="base_model"):
        c.add("witness-a", "")


def test_extend_accepts_dicts_and_witness_instances():
    c = WitnessCollector(proposer_id="app")
    c.extend([
        {"agent_id": "a", "base_model": "gpt-5", "independence_evidence": "e1"},
        mem_ratify.Witness(agent_id="b", base_model="opus-5",
                           independence_evidence="e2"),
    ])
    assert len(c) == 2
    assert c.distinct_base_models() == frozenset({"gpt-5", "opus-5"})


def test_extend_refuses_wrong_type():
    c = WitnessCollector(proposer_id="app")
    with pytest.raises(TypeError, match="Witness or dict"):
        c.extend(["just-a-string"])


# ── build_request: witnesses snapshot ──────────────────────────────────────
def test_build_request_snapshots_witnesses():
    c = WitnessCollector(proposer_id="app")
    c.add("a", "gpt-5")
    c.add("b", "opus-5")
    req = c.build_request(
        claim_id="claim-1",
        current_tier="contested",
        target_tier="frontier",
        ledger_evidence_ref="ledger:head:x",
    )
    assert len(req.witnesses) == 2
    # Mutating the collector after build must not touch the request
    c.add("c", "claude-5")
    assert len(req.witnesses) == 2, "build_request must snapshot"
    assert len(c) == 3


# ── the real path: two witnesses clear the frontier quorum ─────────────────
def test_two_independent_witnesses_reach_frontier():
    c = WitnessCollector(proposer_id="app")
    c.add("a", "gpt-5",  independence_evidence="review-a")
    c.add("b", "opus-5", independence_evidence="review-b")
    req = c.build_request(
        claim_id="claim-x",
        current_tier="contested",
        target_tier="frontier",
        ledger_evidence_ref="ledger:head:x",
    )
    decision = mem_ratify.ratify(req)
    assert decision.allowed is True
    assert decision.independent_witness_count >= 2


def test_one_witness_denied_at_frontier():
    c = WitnessCollector(proposer_id="app")
    c.add("a", "gpt-5", independence_evidence="review-a")
    req = c.build_request(
        claim_id="claim-y",
        current_tier="contested",
        target_tier="frontier",
    )
    decision = mem_ratify.ratify(req)
    assert decision.allowed is False
    assert any("quorum" in r.lower() for r in decision.reasons)


# ── coerce_witnesses: the one-shot server-side helper ──────────────────────
def test_coerce_none_and_empty():
    assert coerce_witnesses(None, proposer_id="app") == ()
    assert coerce_witnesses([],   proposer_id="app") == ()


def test_coerce_mixed():
    tup = coerce_witnesses(
        [
            {"agent_id": "a", "base_model": "gpt-5"},
            mem_ratify.Witness(agent_id="b", base_model="opus-5"),
        ],
        proposer_id="app",
    )
    assert len(tup) == 2
    assert {w.agent_id for w in tup} == {"a", "b"}


def test_coerce_refuses_proposer():
    with pytest.raises(ProposerAsWitnessError):
        coerce_witnesses(
            [{"agent_id": "app", "base_model": "gpt-5"}],
            proposer_id="app",
        )


# ── _mem_ratify_gate: witnesses actually admit the write ───────────────────
def test_gate_still_blocks_with_no_witnesses(monkeypatch):
    """The existing invariant: no witnesses → refused, fail-closed."""
    monkeypatch.setenv("WILLOW_MEM_RATIFY_ENFORCE", "1")
    denied = server._mem_ratify_gate("app", "general", "")
    assert denied is not None
    assert denied["error"].startswith("mem_ratify_denied:")


def test_gate_witnesses_show_up_in_the_decision_reasons(monkeypatch):
    """Proves the plumbing engaged end-to-end through the server wire.

    The gate's target is hardcoded Contested→Canonical (Article IV Canon).
    A Canonical write also needs a ledger evidence ref and the Operator
    Key (IV.3), neither of which this bare tool call supplies, so the
    gate refuses in both cases. What changes is *why* — with witnesses
    supplied, the reasons show 2 witness(es) were counted; without them,
    they don't. Widening the gate to accept ledger/operator-key params
    is a separate decision beyond this seam.
    """
    monkeypatch.setenv("WILLOW_MEM_RATIFY_ENFORCE", "1")
    # Turn stepwise off so the reasons reach the Canonical-composition
    # check rather than short-circuiting on tier-skipping. mem_ratify's
    # __init__.py re-imports the `ratify` function under the same name,
    # shadowing the submodule attribute, so reach it via importlib.
    ratify_module = importlib.import_module("willow_mcp.mem_ratify.ratify")
    monkeypatch.setattr(ratify_module, "REQUIRE_STEPWISE_PROMOTION", False)

    denied_bare = server._mem_ratify_gate("app", "general", "")
    denied_with = server._mem_ratify_gate(
        "app", "general", "",
        witnesses=[
            {"agent_id": "a", "base_model": "gpt-5",  "independence_evidence": "e1"},
            {"agent_id": "b", "base_model": "opus-5", "independence_evidence": "e2"},
        ],
    )
    reasons_bare = " ".join(denied_bare["mem_ratify"]["reasons"]).lower()
    reasons_with = " ".join(denied_with["mem_ratify"]["reasons"]).lower()
    assert "2 witness" not in reasons_bare, \
        "bare call: no witness count should appear in reasons"
    assert "2 witness" in reasons_with, \
        f"with-witness call: '2 witness(es)' should appear; reasons were {reasons_with!r}"


def test_gate_refuses_proposer_witness(monkeypatch):
    """A caller that accidentally lists the proposer as its own witness
    gets a typed error at the collector rather than a silent drop or a
    Decision.flags_for_human buried in the detail dict."""
    monkeypatch.setenv("WILLOW_MEM_RATIFY_ENFORCE", "1")
    with pytest.raises(ProposerAsWitnessError):
        server._mem_ratify_gate(
            "app", "general", "",
            witnesses=[{"agent_id": "app", "base_model": "gpt-5"}],
        )
