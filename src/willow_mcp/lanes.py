"""Lane membership and the crossings that permit reading across one.

The charter's rule, at source (`PROTECTED_AGENTS.md` Part III, via
`terpsi-music/records/crossing.py`):

> *"Lanes are mutually sealed. Between wards, default deny; a crossing requires
> a guardian-signed envelope naming both lanes, purpose, and expiry. A shared
> event is two lane entries with one referent."*

**Why this module exists.** `kb_ingest` has taken a `sensitivity` argument since
it was written, defaulting to `"sensitive"`, and stores it on the row and as a
`sensitivity:<value>` tag. Measured 2026-08-28 on the live store: 10,975 rows
marked `sensitive`, 10,939 marked `open` — and `knowledge_search` mentions the
field zero times. The prohibition was recorded on every row and enforced on
none. This is the read side that was missing, not a new policy.

**Naming.** `willow_mcp.envelopes` already means something else here — the
*constitutional* envelope, matching a syscall against the operator's
pre-approved registry. A lane crossing is a different act with the same English
word, so it is called a `Crossing` throughout. Two meanings under one name in
one package is how a reader ends up believing a syscall grant opened a lane.

**Ported, not copied** (rule 11). `terpsi-music/records/crossing.py` and
`records/rungs.py` implement this with forgery tests; the *patterns* are taken
and the code is written fresh against this package's own types.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, Optional, Sequence

#: The environment variable a store declares its lane in. One variable, no
#: table of store names — a mapping kept here would be a second copy of a fact
#: the deployment already holds, and decision 0227's rule is that "the
#: enumeration must be the authority, never a copy of one". `WILLOW_PG_DB`
#: already says *which* store; this says *what kind*.
LANE_ENV = "WILLOW_LANE"


class Lane(Enum):
    """The lanes a record can belong to. Values are names, never numbers.

    **Deliberately not an ordinal type** (terpsi's rule 14 — "scales never
    compare as bare integers"). `Lane.SYSTEM < Lane.PERSONAL` raises
    `TypeError`, because the two are not points on one scale: personal is not
    "more" than system, it is *other* than system, and an ordering operator
    would invite exactly the arithmetic that quietly promotes a row.

    An `Enum` rather than two module-level strings for that reason alone — the
    first draft of this module used bare strings, and `"system" < "personal"`
    is valid Python that silently answers alphabetically. The test asserting
    non-ordinality is what caught it.
    """

    SYSTEM = "system"
    PERSONAL = "personal"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def of_store(cls, declared: Optional[str] = None) -> "Lane":
        """The lane the connected store carries — **the authoritative answer.**

        A lane is a property of the store, not a column on the row, and that is
        the whole design rather than an implementation convenience:

        * a per-row label must be checked on every query, every join, and every
          semantic neighbour, and one missed filter is a silent leak. A store
          boundary is enforced by whether a connection exists at all.
        * a row can be mislabeled; there is no label to get wrong.
        * separability — the operator's stated requirement, that personal data
          can be exported or deleted whole and the system keep running — is
          `pg_dump` on one store, not a predicate over another's rows.

        Declared, never guessed. `WILLOW_PG_DB` already names *which* store the
        process is connected to; `WILLOW_LANE` says *what kind* it is. No table
        of store names lives here on purpose (0227).

        **Fail closed.** An undeclared store resolves to PERSONAL, which is
        loud: reads from the system lane start refusing until somebody declares
        the lane, and that complaint is visible and one env var from fixed.
        Defaulting to SYSTEM would be silent and would serve private rows.
        """
        raw = declared if declared is not None else os.environ.get(LANE_ENV, "")
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.PERSONAL

    @classmethod
    def of_row(cls, sensitivity: Optional[str]) -> "Lane":
        """The lane a row claims via its own `sensitivity` field — **legacy.**

        Kept for rows written before the split, where the store cannot answer
        because both lanes shared one. It is a weaker signal than
        :meth:`of_store` and measurably so: on the live store 2026-08-28,
        10,975 rows were marked `sensitive` and 8,752 of those were LoCoMo and
        benchmark fixtures that inherited `kb_ingest`'s `sensitivity="sensitive"`
        default without anyone deciding. A marking that is 80% default is not a
        classification, which is why enforcing it directly was never possible
        and why the lane moved to the store.

        **Fail closed**, like :meth:`of_store`. An unset, empty, or unrecognised
        value resolves to PERSONAL, never SYSTEM. An unmarked row is not a row
        proven open; it is a row nobody classified, and the two mistakes do not
        cost the same — serving a private record as open cannot be undone by
        marking it later, while refusing an open record produces a visible,
        fixable complaint. Same asymmetry `gate.store_scope` uses when it reads
        "no manifest" as deny-all.

        New writes should not set `sensitivity` at all; the store they land in
        says what they are.
        """
        if sensitivity is None:
            return cls.PERSONAL
        # The `sensitivity` vocabulary already on disk. Read off what the store
        # actually holds rather than imposed on it: `sensitive` was the
        # kb_ingest default long before this module existed.
        return {
            "open": cls.SYSTEM,
            "sensitive": cls.PERSONAL,
        }.get(str(sensitivity).strip().lower(), cls.PERSONAL)

    @classmethod
    def is_personal(cls, sensitivity: Optional[str]) -> bool:
        """Legacy row-field question. See :meth:`of_row`."""
        return cls.of_row(sensitivity) is cls.PERSONAL


#: A signature must name a person. A role cannot sign, and neither can the thing
#: being permitted — the whole point of a guardian's signature is that it is not
#: the system granting itself passage. Ported from terpsi's `_NOT_A_PERSON`,
#: widened with this fleet's own machine-flavoured names (`gate.py`'s app ids,
#: the seat vocabulary) for the same reason `nestor/bench/harness.py` seals under
#: a verifier "deliberately not a person and so deliberately not in anybody's
#: real keyring".
_NOT_A_PERSON = frozenset({
    "system", "machine", "agent", "automation", "bot", "service",
    "guardian", "the guardian", "role:guardian", "staff",
    "director", "the director", "operator", "orchestrator",
    "willow", "claude", "assistant", "model", "mcp", "willow-mcp",
})


class CrossingError(ValueError):
    """A crossing that cannot exist. Raised at construction, never at use."""


@dataclass(frozen=True)
class Crossing:
    """A guardian-signed permission for one lane to be read from another.

    Four required fields and no defaults, because each is the one a hurried
    implementation omits:

    * **both lanes named** — a crossing naming one lane is a wildcard over the other
    * **a purpose** — a crossing "because it was convenient" is not a crossing
    * **an expiry** — a crossing without one is a standing grant
    * **a guardian's signature** — a person, not a role and not the system

    Frozen, because a crossing is a fact about what was signed, not a handle a
    caller adjusts afterwards.
    """

    from_lane: "Lane"
    to_lane: "Lane"
    purpose: str
    signed_by: str
    signed_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not self.from_lane or not self.to_lane:
            raise CrossingError("a crossing must name both lanes")
        if self.from_lane == self.to_lane:
            raise CrossingError(
                "a crossing naming one lane twice is not a crossing — "
                "reading a lane from itself needs no permission"
            )
        for lane in (self.from_lane, self.to_lane):
            if not isinstance(lane, Lane):
                raise CrossingError(
                    f"unknown lane {lane!r} — a crossing names Lane members, not "
                    f"free strings, so a typo cannot invent a third lane"
                )
        if not (self.purpose or "").strip():
            raise CrossingError(
                "a crossing without a purpose is a standing crossing; name why"
            )
        name = (self.signed_by or "").strip()
        if not name or name.lower() in _NOT_A_PERSON:
            raise CrossingError(
                f"{self.signed_by!r} is not a guardian's signature; a role cannot sign"
            )
        if self.expires_at <= self.signed_at:
            raise CrossingError(
                "a crossing without a future expiry is a standing grant"
            )

    def live_at(self, when: datetime) -> bool:
        return self.signed_at <= when < self.expires_at


def permits(
    crossings: Sequence[Crossing],
    *,
    from_lane: "Lane",
    to_lane: "Lane",
    at: Optional[datetime] = None,
) -> Optional[Crossing]:
    """The live crossing permitting this read, or `None`.

    **Direction is not symmetric.** A crossing permitting the system lane to
    read the personal lane does not permit the reverse. Treating it as symmetric
    would mean one signature opened two seals, which is the cheap violation this
    type exists to make unwritable.

    **Liveness is evaluated at the instant of use**, not of signing — a crossing
    signed while valid does not stay open past its expiry because it was once
    good. Same doctrine `federation_egress` states for its own locks: "a lease
    on disk owned elsewhere is a fact; a cached decision is a claim."
    """
    when = at or datetime.now(timezone.utc)
    for crossing in crossings:
        if crossing.from_lane != from_lane or crossing.to_lane != to_lane:
            continue
        if crossing.live_at(when):
            return crossing
    return None


def response_lane(sensitivities: Iterable[Optional[str]]) -> "Lane":
    """The lane a whole response belongs to: PERSONAL if *any* part is.

    Ported from homestead's **I-12** — "the rung of a whole context window … is
    the `max` of everything that ends up in it, **and the neighbours a semantic
    search pulled in**". A prompt is not scored per fragment, and neither is a
    result set.

    This is the rule that closes the hole a per-row check leaves open: an agent
    working in the system lane runs a semantic search, one personal-lane row
    ranks into the neighbours, and the crossing has happened with nobody
    signing anything. Scoring the response as a whole is what makes the
    per-row marking enforceable rather than advisory.
    """
    return (Lane.PERSONAL if any(Lane.of_row(s) is Lane.PERSONAL for s in sensitivities)
            else Lane.SYSTEM)


def refusal(
    *,
    rows_sensitivity: Iterable[Optional[str]],
    reader_lane: Optional["Lane"] = None,
    crossings: Sequence[Crossing] = (),
    at: Optional[datetime] = None,
) -> Optional[dict]:
    """Why this read must be refused, or `None` if it may proceed.

    Returns a *recorded negative* rather than a bare bool — "a recorded negative
    is not an absence" — so a caller can say what was withheld and what would
    permit it, which is the difference between a refusal that teaches and one
    that merely blocks.
    """
    reader_lane = reader_lane if reader_lane is not None else Lane.of_store()
    holding = response_lane(rows_sensitivity)
    if holding is reader_lane:
        return None
    if permits(crossings, from_lane=reader_lane, to_lane=holding, at=at):
        return None
    return {
        "refused": True,
        "reader_lane": reader_lane.value,
        "holding_lane": holding.value,
        "reason": (
            f"the result set contains {holding} rows and the reader is in the "
            f"{reader_lane} lane; lanes are mutually sealed and no live crossing "
            f"permits {reader_lane} to read {holding}"
        ),
        "what_would_permit": (
            "a guardian-signed crossing naming both lanes, a purpose, and a "
            "future expiry — signed by a person, not a role"
        ),
    }
