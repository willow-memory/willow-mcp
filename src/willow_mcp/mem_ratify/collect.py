"""WitnessCollector — the missing supply for the vendored mem_ratify gate.

The vendored ``mem_ratify.ratify`` enforces quorum but no path in this repo
supplies witnesses to it — ``server.py`` calls ``RatifyRequest.build`` with
``witnesses=()`` and the resulting Decision refuses every write. The
vendored ``ratify.py`` itself calls this shape out as an intentional
follow-up: *"see mem_ratify/README.md 'follow-up' for the witness/tier
metadata plumbing that makes an enabled gate admit legitimate promotions
rather than refusing every direct write."*

This module is that plumbing, sibling to the vendored files so nothing
touches the drift-guarded contract. Callers accumulate cross-model
attestations as they arrive (multiple LLMs, multiple humans, a scripted
oracle) and hand the resulting tuple to :func:`_mem_ratify_gate`.

Deliberate non-goals:

* No persistence. A collector's job is to gather witnesses for ONE
  proposed promotion; the audit trail on the far side is the ledger's,
  not this module's. Rehydrating from a store would let a stale
  attestation vouch for a claim the witness never saw.
* No opinion on what counts as independent. That decision belongs to
  :func:`willow_mcp.mem_ratify.ratify` (§0.2 excludes the proposer;
  same-base-model witnesses are flagged for human confirmation). This
  module dedupes on ``agent_id`` and refuses the proposer's own id — the
  weakest possible filter — and lets ratify score the rest.
* No egress. Stdlib only, in-memory only, no networking.
"""
from __future__ import annotations

from typing import Iterable

from .ratify import RatifyRequest, Tier, Witness


class ProposerAsWitnessError(ValueError):
    """A proposer tried to vouch for their own proposal — §0.2 refuses this
    before the request is even built, so the caller sees a typed error at
    the collector rather than a downstream ``Decision.flags_for_human``."""


class WitnessCollector:
    """Accumulate :class:`Witness` rows for one proposed promotion, then
    emit a :class:`RatifyRequest` when asked.

    Not thread-safe. A collector is a per-request thing — one operation,
    one collector, one request. Reusing an instance across proposals
    would let witnesses drift onto claims they never saw.

    Duplicates by ``agent_id`` are silently ignored (a witness that
    already attested does not attest twice); the last attestation wins so
    a caller can amend evidence in place before building the request.

    Usage::

        c = WitnessCollector(proposer_id="app-42")
        c.add("gpt-5-a", "gpt-5", independence_evidence="review-a")
        c.add("opus-5-b", "opus-5", independence_evidence="review-b")
        req = c.build_request(
            claim_id="knowledge_ingest:app-42:policy",
            current_tier="contested",
            target_tier="frontier",
            ledger_evidence_ref="ledger:head:abc123",
        )
        decision = ratify(req)
    """

    def __init__(self, *, proposer_id: str) -> None:
        if not proposer_id:
            raise ValueError("proposer_id is required — §0.2 excludes it from quorum")
        self._proposer_id = proposer_id
        self._witnesses: dict[str, Witness] = {}

    @property
    def proposer_id(self) -> str:
        return self._proposer_id

    def add(
        self,
        agent_id: str,
        base_model: str,
        *,
        independence_evidence: str | None = None,
    ) -> Witness:
        """Register one attestation. Returns the resulting :class:`Witness`.

        Refuses ``agent_id == proposer_id`` up front: the proposer cannot
        vouch for its own proposal (§0.2), and letting the collector
        silently drop that row would hide a caller bug behind a passing
        Decision.
        """
        if not agent_id:
            raise ValueError("agent_id is required")
        if not base_model:
            raise ValueError("base_model is required")
        if agent_id == self._proposer_id:
            raise ProposerAsWitnessError(
                f"proposer {agent_id!r} cannot witness its own proposal (§0.2). "
                "Collect witnesses from other agents; ratify() would flag it "
                "and refuse the promotion, so refuse it here where the caller "
                "can see the mistake."
            )
        w = Witness(
            agent_id=agent_id,
            base_model=base_model,
            independence_evidence=independence_evidence,
        )
        self._witnesses[agent_id] = w
        return w

    def extend(self, witnesses: Iterable[Witness | dict]) -> None:
        """Bulk-add witnesses. Dicts are unpacked into :meth:`add`; already-
        typed :class:`Witness` instances pass straight through the same
        dedup + proposer-guard path."""
        for w in witnesses:
            if isinstance(w, Witness):
                self.add(w.agent_id, w.base_model,
                         independence_evidence=w.independence_evidence)
                continue
            if not isinstance(w, dict):
                raise TypeError(
                    f"witness must be Witness or dict, got {type(w).__name__}"
                )
            self.add(
                str(w["agent_id"]),
                str(w["base_model"]),
                independence_evidence=w.get("independence_evidence"),
            )

    def __len__(self) -> int:
        return len(self._witnesses)

    def witnesses(self) -> tuple[Witness, ...]:
        """The current tuple, insertion-ordered by first-add per agent_id."""
        return tuple(self._witnesses.values())

    def distinct_base_models(self) -> frozenset[str]:
        """Cheap inspection: how many distinct base_models are on file.
        Ratify's own ``_count_independent_witnesses`` is authoritative; this
        is a caller-side hint for whether it's worth even building a
        request yet."""
        return frozenset(w.base_model for w in self._witnesses.values())

    def build_request(
        self,
        *,
        claim_id: str,
        current_tier: "Tier | str | int",
        target_tier: "Tier | str | int",
        ledger_evidence_ref: str | None = None,
        operator_key_signature: str | None = None,
        prior_frontier_ratifiers: Iterable[str] = (),
    ) -> RatifyRequest:
        """Emit a :class:`RatifyRequest` pinning the accumulated witnesses.

        The witness tuple is a snapshot: mutating this collector after
        ``build_request`` returns has no effect on the request that
        already went out.
        """
        return RatifyRequest.build(
            claim_id=claim_id,
            current_tier=current_tier,
            target_tier=target_tier,
            proposer_id=self._proposer_id,
            witnesses=self.witnesses(),
            ledger_evidence_ref=ledger_evidence_ref,
            operator_key_signature=operator_key_signature,
            prior_frontier_ratifiers=prior_frontier_ratifiers,
        )


def coerce_witnesses(
    witnesses: Iterable[Witness | dict] | None,
    *,
    proposer_id: str,
) -> tuple[Witness, ...]:
    """One-shot helper for the server wire: turn a caller-supplied
    ``witnesses=`` kwarg (dicts, Witness instances, or None) into the
    tuple ``RatifyRequest`` wants, applying the same proposer-guard and
    dedup a :class:`WitnessCollector` would.

    Used by the ``_mem_ratify_gate`` call site so a caller can hand
    witnesses directly without instantiating a collector when the request
    is one-shot.
    """
    if not witnesses:
        return ()
    c = WitnessCollector(proposer_id=proposer_id)
    c.extend(witnesses)
    return c.witnesses()
