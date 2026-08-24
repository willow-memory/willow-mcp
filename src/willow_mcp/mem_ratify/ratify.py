"""mem_ratify — the Canon-promotion gate for Article IV (Knowledge & Canon).

ΔΣ=42

This module decides whether a knowledge item may be promoted between the three
epistemic tiers defined by ``CONSTITUTION.md`` Article IV (CONST-IV):

    Contested (proposed, unverified)  <  Frontier (corroborated, working belief)
                                       <  Canonical (settled, load-bearing)

It is the deterministic enforcement artifact named at ``CONSTITUTION.md`` line
442 ("Tiered atoms (contested/frontier/canonical); ``mem_ratify``; promotion
gated in code") — but see the OFF-BY-DEFAULT contract below.

Design posture
--------------
* **Pure & stdlib-only.** No I/O, no network, no crypto keys, no third-party
  imports. Every decision is a pure function of its inputs, so it is trivially
  testable and cannot itself mutate memory, a ledger, or a database.
* **Advisory / OFF-BY-DEFAULT.** Importing or calling this module changes *no*
  live behavior. Nothing in the fleet imports it yet (see FOLLOW-UP below). A
  caller that *does* wire it must consult :func:`enforcement_enabled` (env var
  ``WILLOW_MEM_RATIFY_ENFORCE``, default ``False``) and, while enforcement is
  off, treat a denial as a *loud advisory* only — mirroring the fleet
  "off-by-default enforce flag" convention (handoff-2026-07-25).
* **Fail-closed decision logic.** Independently of the enforcement flag, the
  *decision* itself refuses promotion whenever any Article IV requirement is
  unmet or unprovable (IV.4 "debasement is refused, not quietly admitted").
  "Fail-closed" describes the verdict; "off-by-default" describes whether a
  caller is obliged to honor it. They are separate knobs on purpose.

PLACEHOLDERS — owner must confirm
---------------------------------
The constitution deliberately leaves several numbers to the operator (see
``CONSTITUTION.md`` "Proposed parameters awaiting your number", line 478, and
Article IX.2). Where a real doctrine decision is required, this module uses a
**conservative** placeholder, marked ``# PLACEHOLDER — owner must confirm`` at
its definition. These MUST be signed off before enforcement is switched on:

  1. ``FRONTIER_MIN_WITNESSES`` / ``CANONICAL_MIN_WITNESSES`` — the quorum size
     (minimum count of *independent* witnesses). Defaulted to 2, the Article
     IX.2 founding default; Article IV names no number of its own.
  2. ``REQUIRE_STEPWISE_PROMOTION`` — whether Contested may jump straight to
     Canonical or must pass through Frontier. Defaulted to True (stricter).
  3. Independent-Witness evidence quality — this module can only check the
     *presence* of a rebuttal attestation, never judge whether the recorded
     evidence truly shows divergent failure modes. Any reliance on an
     attestation is surfaced in ``Decision.flags_for_human`` for audit.
  4. Operator-Key / ledger-evidence *verification* — this module checks only
     that the tokens are *present*. Cryptographic verification of the Operator
     Key signature and the ledger-evidence reference is delegated to the wiring
     layer and flagged for human/keyholder confirmation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable, Optional


# --------------------------------------------------------------------------- #
# Tiers (Article IV.1)
# --------------------------------------------------------------------------- #
class Tier(IntEnum):
    """The three epistemic tiers, ordered by weight/cost to enter (IV.1)."""

    CONTESTED = 0
    FRONTIER = 1
    CANONICAL = 2

    @classmethod
    def parse(cls, value: "Tier | str | int") -> "Tier":
        if isinstance(value, Tier):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper()
        try:
            return cls[key]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown tier: {value!r}") from exc


# --------------------------------------------------------------------------- #
# PLACEHOLDER doctrine parameters — owner must confirm before enforcement
# --------------------------------------------------------------------------- #

# Doctrine parameters — env-configurable, conservative defaults.
#
# Article IV names no quorum size; Article IX.2's founding default is "at least
# 2 independent agent witnesses" (also listed as operator-adjustable, line 478).
# Override via WILLOW_* env vars; the defaults preserve the original placeholders.
FRONTIER_MIN_WITNESSES = int(os.environ.get("WILLOW_FRONTIER_MIN_WITNESSES", "2"))

# Canonical is "the fleet's highest standard" (IV.3) yet the charter gives it no
# larger number. The owner may wish this higher.
CANONICAL_MIN_WITNESSES = int(os.environ.get("WILLOW_CANONICAL_MIN_WITNESSES", "2"))

# IV.3's "at least one ratifying agent must not have participated in the prior
# Frontier promotion" presumes stepwise promotion (Contested -> Frontier ->
# Canonical). Set to 0/false to allow direct Contested -> Canonical jumps.
REQUIRE_STEPWISE_PROMOTION = os.environ.get(
    "WILLOW_REQUIRE_STEPWISE_PROMOTION", "1",
).strip().lower() not in {"0", "false", "no", "off"}


ENFORCE_ENV_VAR = "WILLOW_MEM_RATIFY_ENFORCE"


def enforcement_enabled() -> bool:
    """Return True only if an operator has explicitly turned enforcement on.

    OFF BY DEFAULT (fleet convention). While this returns False a wired caller
    MUST treat any denial as advisory and take no blocking action.
    """
    return os.environ.get(ENFORCE_ENV_VAR, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# --------------------------------------------------------------------------- #
# Inputs
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Witness:
    """A single ratifying agent.

    ``base_model`` drives the Independent-Witness presumption: separate
    instances of the same base model are presumed non-independent and collapse
    to one effective witness (Definitions, CONSTITUTION.md line 95). That
    presumption is rebuttable *only* by an explicit designation backed by
    recorded evidence — ``independence_evidence`` here — with the burden on
    whoever asserts independence. This module checks that such evidence is
    *present*; it cannot judge its quality, and flags any reliance for audit.
    """

    agent_id: str
    base_model: str
    # Optional recorded evidence rebutting the same-base-model presumption.
    # A non-empty value lets this witness count separately from same-base peers.
    independence_evidence: Optional[str] = None


@dataclass(frozen=True)
class RatifyRequest:
    """A request to promote (or demote) a knowledge claim across tiers."""

    claim_id: str
    current_tier: Tier
    target_tier: Tier
    proposer_id: str
    witnesses: tuple[Witness, ...] = ()
    # Canonical-only (IV.3): a reference to the recorded ledger evidence and the
    # Operator Key signature. Presence-checked here; cryptographic/actual
    # verification is delegated to the wiring layer (flagged for human).
    ledger_evidence_ref: Optional[str] = None
    operator_key_signature: Optional[str] = None
    # Canonical composition (IV.3): agent_ids that ratified the *prior* Frontier
    # promotion of this same claim. At least one Canonical witness must not be
    # among them.
    prior_frontier_ratifiers: frozenset[str] = frozenset()

    @staticmethod
    def build(
        claim_id: str,
        current_tier: "Tier | str | int",
        target_tier: "Tier | str | int",
        proposer_id: str,
        witnesses: Iterable[Witness] = (),
        ledger_evidence_ref: Optional[str] = None,
        operator_key_signature: Optional[str] = None,
        prior_frontier_ratifiers: Iterable[str] = (),
    ) -> "RatifyRequest":
        return RatifyRequest(
            claim_id=claim_id,
            current_tier=Tier.parse(current_tier),
            target_tier=Tier.parse(target_tier),
            proposer_id=proposer_id,
            witnesses=tuple(witnesses),
            ledger_evidence_ref=ledger_evidence_ref,
            operator_key_signature=operator_key_signature,
            prior_frontier_ratifiers=frozenset(prior_frontier_ratifiers),
        )


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
@dataclass
class Decision:
    """The verdict. Pure data — deciding never mutates anything."""

    allowed: bool
    claim_id: str
    current_tier: Tier
    target_tier: Tier
    reasons: list[str] = field(default_factory=list)
    independent_witness_count: int = 0
    # Doctrine placeholders this verdict relied upon (need owner sign-off).
    placeholders_relied_on: list[str] = field(default_factory=list)
    # Things a human/keyholder must still confirm (evidence quality, signatures).
    flags_for_human: list[str] = field(default_factory=list)

    def is_blocking(self) -> bool:
        """Whether a wired caller should actually block on this verdict.

        Off-by-default: only blocks when the verdict denies AND an operator has
        turned enforcement on. Otherwise the denial is advisory.
        """
        return (not self.allowed) and enforcement_enabled()


# --------------------------------------------------------------------------- #
# Independent-Witness accounting (IV.2 + Definitions line 95)
# --------------------------------------------------------------------------- #
def _norm_identity(value: object) -> str:
    """Fold an identity string for comparison: collapse whitespace, lowercase.

    Every rule this module enforces is a string comparison — the proposer
    exclusion (§0.2, IV.2) and the same-base-model collapse (Definitions line
    95). Compared raw, ``Claude-Opus-5`` beside ``claude-opus-5`` reads as two
    independent witnesses and clears a Frontier quorum on its own, with
    ``allowed=True`` and no flag raised. Folded, it is one witness, which is
    what the charter says it is.

    ``Tier.parse`` already normalises its input the same way; this carries that
    habit to the identities, which is where it was missing.

    Returns ``""`` for anything carrying no identity. Callers must treat that as
    *cannot count* — never as *matches nothing*, which is how an unnamed
    witness would otherwise slip past both guards.
    """
    return " ".join(str(value or "").split()).strip().lower()


def _count_independent_witnesses(
    witnesses: Iterable[Witness],
    proposer_id: str,
    flags_for_human: list[str],
) -> tuple[int, list[str]]:
    """Return (independent_witness_count, reason_notes).

    Rules applied:
      * The proposer is never counted (§0.2, IV.2).
      * Duplicate agent_ids collapse to one (a witness cannot vote twice).
      * Witnesses sharing a base model collapse to ONE effective witness unless
        one carries recorded ``independence_evidence`` rebutting the
        presumption (Definitions line 95); any such reliance is flagged.
    """
    notes: list[str] = []
    seen_agents: set[str] = set()
    # group -> whether the group has been counted once already
    counted_base_models: set[str] = set()
    count = 0

    # Fold once. Notes keep the ORIGINAL strings, so an audit trail shows what
    # the caller actually supplied rather than what this function compared.
    proposer_norm = _norm_identity(proposer_id)

    for w in witnesses:
        agent_norm = _norm_identity(w.agent_id)
        base_norm = _norm_identity(w.base_model)

        if not agent_norm:
            notes.append("witness with an empty agent_id; not counted - an "
                         "unnamed hand cannot satisfy a quorum")
            continue
        if agent_norm == proposer_norm:
            notes.append(
                f"witness {w.agent_id!r} is the proposer; not counted (§0.2)"
            )
            continue
        if agent_norm in seen_agents:
            notes.append(f"witness {w.agent_id!r} listed more than once; counted once")
            continue
        seen_agents.add(agent_norm)

        if w.independence_evidence:
            # Presumption rebutted by recorded evidence — count separately, but
            # a human must confirm the evidence actually shows divergence.
            count += 1
            flags_for_human.append(
                f"witness {w.agent_id!r} counted as independent on a rebuttal "
                f"attestation (base_model={w.base_model!r}); a human must "
                f"confirm the recorded evidence shows divergent failure modes "
                f"(burden of proof is on the asserter, per Definitions)."
            )
            continue

        if not base_norm:
            notes.append(
                f"witness {w.agent_id!r} declares no base_model; not counted - "
                f"independence cannot be presumed for an unstated model "
                f"(Definitions line 95, fail-closed)"
            )
            continue
        if base_norm in counted_base_models:
            notes.append(
                f"witness {w.agent_id!r} shares base_model {w.base_model!r} "
                f"with an already-counted witness; presumed non-independent, "
                f"not counted (Definitions line 95)"
            )
            continue

        counted_base_models.add(base_norm)
        count += 1

    return count, notes


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #
def ratify(request: RatifyRequest) -> Decision:
    """Decide whether ``request`` may promote/demote a claim. Pure function.

    Encodes Article IV (CONST-IV). Fail-closed: any unmet or unprovable
    requirement yields ``allowed=False`` with a reason. Never mutates state.
    """
    d = Decision(
        allowed=False,
        claim_id=request.claim_id,
        current_tier=request.current_tier,
        target_tier=request.target_tier,
    )

    cur = request.current_tier
    tgt = request.target_tier

    # --- Proposal / drop to Contested (IV.2 "any agent may propose; recorded")
    # Creating or (re)asserting a claim at the lowest, most-doubted tier is
    # Auto-Applied: no quorum. Dropping a claim down to Contested is the
    # fail-safe direction and likewise needs no quorum.
    if tgt == Tier.CONTESTED:
        d.allowed = True
        d.reasons.append(
            "Contested is auto-applied (IV.2): proposal recorded / claim held "
            "at the most-doubted tier; no quorum required"
        )
        return d

    # --- No-op ---------------------------------------------------------------
    if tgt == cur:
        d.reasons.append("target tier equals current tier; nothing to ratify")
        return d

    # --- Demotion from Frontier/Canonical (IV.4) -----------------------------
    if tgt < cur:
        return _decide_demotion(request, d)

    # --- Promotion (IV.3) ----------------------------------------------------
    if REQUIRE_STEPWISE_PROMOTION and tgt > cur + 1:
        d.placeholders_relied_on.append("REQUIRE_STEPWISE_PROMOTION")
        d.reasons.append(
            f"tier-skipping refused: {cur.name} -> {tgt.name} must pass through "
            f"the intermediate tier (PLACEHOLDER REQUIRE_STEPWISE_PROMOTION)"
        )
        return d

    ind_count, notes = _count_independent_witnesses(
        request.witnesses, request.proposer_id, d.flags_for_human
    )
    d.independent_witness_count = ind_count
    d.reasons.extend(notes)

    if tgt == Tier.FRONTIER:
        _decide_frontier(request, d, ind_count)
    elif tgt == Tier.CANONICAL:
        _decide_canonical(request, d, ind_count)
    else:  # pragma: no cover - defensive; all tiers handled above
        d.reasons.append(f"unsupported target tier {tgt!r}")

    return d


def _decide_frontier(request: RatifyRequest, d: Decision, ind_count: int) -> None:
    """Promotion to Frontier: an independent quorum (IV.3)."""
    d.placeholders_relied_on.append("FRONTIER_MIN_WITNESSES")
    if ind_count < FRONTIER_MIN_WITNESSES:
        d.reasons.append(
            f"Frontier quorum not met: {ind_count} independent witness(es), "
            f"need >= {FRONTIER_MIN_WITNESSES} (PLACEHOLDER) with the proposer "
            f"excluded (§0.2) and Independent-Witness applied (IV.2)"
        )
        return
    d.allowed = True
    d.reasons.append(
        f"Frontier quorum met: {ind_count} independent witness(es) "
        f">= {FRONTIER_MIN_WITNESSES}; proposer excluded (§0.2)"
    )


def _decide_canonical(request: RatifyRequest, d: Decision, ind_count: int) -> None:
    """Promotion to Canonical: quorum + ledger evidence + Operator Key (IV.3)."""
    d.placeholders_relied_on.append("CANONICAL_MIN_WITNESSES")
    ok = True

    if ind_count < CANONICAL_MIN_WITNESSES:
        ok = False
        d.reasons.append(
            f"Canonical quorum not met: {ind_count} independent witness(es), "
            f"need >= {CANONICAL_MIN_WITNESSES} (PLACEHOLDER); proposer "
            f"excluded (§0.2), Independent-Witness applied (IV.2)"
        )

    # Ledger evidence (IV.3). Presence-checked; verification delegated.
    if not request.ledger_evidence_ref:
        ok = False
        d.reasons.append("Canonical requires recorded ledger evidence (IV.3); none supplied")
    else:
        d.flags_for_human.append(
            "ledger-evidence reference is present but NOT verified by this "
            "module; the wiring layer/keyholder must confirm it resolves to a "
            "real Canonical-Chain entry."
        )

    # Operator Key (IV.3). Presence-checked; signature verification delegated.
    if not request.operator_key_signature:
        ok = False
        d.reasons.append(
            "Canonical requires the Operator Key (IV.3); no signature supplied"
        )
    else:
        d.flags_for_human.append(
            "Operator-Key signature is present but NOT cryptographically "
            "verified by this module; the wiring layer/keyholder must verify it."
        )

    # Fresh-witness composition (IV.3): at least one ratifying witness must not
    # have participated in the prior Frontier promotion of the same claim.
    _proposer = _norm_identity(request.proposer_id)
    _prior = {_norm_identity(a) for a in request.prior_frontier_ratifiers}
    fresh = [
        w
        for w in request.witnesses
        if _norm_identity(w.agent_id)
        and _norm_identity(w.agent_id) != _proposer
        and _norm_identity(w.agent_id) not in _prior
    ]
    if not fresh:
        ok = False
        d.reasons.append(
            "Canonical composition unmet (IV.3): at least one ratifying witness "
            "must NOT have participated in the prior Frontier promotion of this "
            "claim; all supplied witnesses did (or none supplied)"
        )
    else:
        d.reasons.append(
            f"Canonical composition met: {len(fresh)} witness(es) fresh vs. the "
            f"prior Frontier promotion (IV.3)"
        )

    d.allowed = ok
    if ok:
        d.reasons.append(
            "Canonical promotion satisfied all in-code checks; human/keyholder "
            "confirmations remain (see flags_for_human)"
        )


def _decide_demotion(request: RatifyRequest, d: Decision) -> Decision:
    """Demotion from Canonical: quorum + Operator Key + recorded evidence (IV.4).

    Only Canonical demotion is doctrinally gated (IV.4). Demoting from Frontier
    downward is treated as gated the same way conservatively (fail-closed).
    """
    ind_count, notes = _count_independent_witnesses(
        request.witnesses, request.proposer_id, d.flags_for_human
    )
    d.independent_witness_count = ind_count
    d.reasons.extend(notes)
    d.placeholders_relied_on.append("CANONICAL_MIN_WITNESSES")

    ok = True
    if ind_count < CANONICAL_MIN_WITNESSES:
        ok = False
        d.reasons.append(
            f"demotion quorum not met: {ind_count} independent witness(es), "
            f"need >= {CANONICAL_MIN_WITNESSES} (PLACEHOLDER)"
        )
    if not request.operator_key_signature:
        ok = False
        d.reasons.append("demotion requires the Operator Key (IV.4); none supplied")
    else:
        d.flags_for_human.append(
            "Operator-Key signature present but NOT verified by this module."
        )
    if not request.ledger_evidence_ref:
        ok = False
        d.reasons.append(
            "demotion requires recorded evidence of error or new facts (IV.4); "
            "none supplied"
        )

    d.allowed = ok
    if ok:
        d.reasons.append(
            "demotion satisfied all in-code checks; human/keyholder "
            "confirmations remain (see flags_for_human)"
        )
    return d
