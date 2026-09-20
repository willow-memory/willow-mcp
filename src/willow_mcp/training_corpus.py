"""willow_mcp.training_corpus — a shared training-example schema.

Several willow-mcp subsystems already produce data shaped like a training
example, but each in its own bespoke format: nest's classifier cascade logs
tier-3 escalations to a per-model JSONL file (`nest/selflearn.py`,
`append_escalations`), the friction watcher persists flags to SOIL
(`friction.py`), nest_intake records classifier-vs-human corrections
(`nest/intake.py`), and a future kb-verification or dispatch-routing signal
would invent its own shape again if nothing here existed.

This module defines ONE format — `TrainingExample` — that any of those
sources can be normalized into, so a later trainer/curator can iterate one
SOIL collection instead of five bespoke formats. It does not change any
existing producer; it gives them a common target to map onto (that wiring is
future work).

Schema shape, at a glance:

    TrainingExample(
        id=...,                 # stable content hash — see make_id()
        ts=...,                 # ISO-8601 UTC
        source=...,             # producer tag, see SOURCES
        provenance={...},       # model / file / session / record_id / etc.
        input={...},            # what the small model (or heuristic) saw
        small_model_output={...} | None,   # the SRM/heuristic's own guess
        large_label={...} | None,          # teacher verdict / human label /
                                            # verification outcome
        label_kind="teacher"|"human"|"verification"|"none",
        weight=1.0,             # curation weight; negative demotes (correction)
        schema_version="training/v1",
    )

Storage: `append_training_example` writes to the SOIL collection
`training_corpus`, keyed by `id` — the same `store.put(collection, record,
record_id=...)` idiom `friction.py` and `nest/intake.py` already use.
Idempotent: re-appending an example with the same `id` overwrites the stored
record with (by construction, since the id is a content hash of the logical
example) an identical payload — a no-op in effect, never a duplicate.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# SOIL collection this module reads/writes.
COLLECTION = "training_corpus"

SCHEMA_VERSION = "training/v1"

# Known producer tags. Not enforced as a closed set — new sources are
# accepted (forward-compatible) as long as `source` is a non-empty str — but
# these are the ones willow-mcp itself currently knows how to produce or will
# soon:
#   nest_classify   — nest-seed's small-model classification of a document
#   kb_verify       — a knowledge-base verification outcome (verify/retract)
#   tool_oracle     — a tool-call routing decision checked against an oracle
#   friction        — a friction_floor flag (mirroring-during-escalation)
#   dispatch_route  — a dispatch/routing decision and its outcome
#   nest_intake     — nest_intake's classifier-vs-human-correction signal
SOURCE_NEST_CLASSIFY = "nest_classify"
SOURCE_KB_VERIFY = "kb_verify"
SOURCE_TOOL_ORACLE = "tool_oracle"
SOURCE_FRICTION = "friction"
SOURCE_DISPATCH_ROUTE = "dispatch_route"
SOURCE_NEST_INTAKE = "nest_intake"

SOURCES = (
    SOURCE_NEST_CLASSIFY,
    SOURCE_KB_VERIFY,
    SOURCE_TOOL_ORACLE,
    SOURCE_FRICTION,
    SOURCE_DISPATCH_ROUTE,
    SOURCE_NEST_INTAKE,
)

LABEL_KINDS = ("teacher", "human", "verification", "none")


class TrainingCorpusError(ValueError):
    """A malformed TrainingExample — bad source, label_kind, or weight."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj: Any) -> str:
    """A stable string form of arbitrary JSON-ish input, for hashing.

    `sort_keys=True` and no whitespace variance make two logically identical
    dicts (same keys/values, built in a different order) hash the same way.
    """
    return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))


def make_id(source: str, input: dict, large_label: Optional[dict]) -> str:
    """Derive a stable content hash: same (source, input, label) -> same id.

    This is the dedup key. Only the fields that define the *logical* example
    feed the hash — not `ts`, `provenance`, `weight`, or `small_model_output`
    (a small-model guess can be recomputed differently without the example
    itself becoming a different example). Two calls that produce the same
    example — e.g. a scan re-run over an overlapping window — collapse to the
    same id, so re-appending is idempotent.
    """
    payload = _canonical({"source": source, "input": input, "large_label": large_label})
    return "tex_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


@dataclass
class TrainingExample:
    """One example in the unified training corpus.

    See the module docstring for the schema's purpose and shape.
    """

    source: str
    input: dict
    small_model_output: Optional[dict] = None
    large_label: Optional[dict] = None
    label_kind: str = "none"
    weight: float = 1.0
    provenance: dict = field(default_factory=dict)
    ts: str = field(default_factory=_now_iso)
    schema_version: str = SCHEMA_VERSION
    id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise TrainingCorpusError("source must be a non-empty str")
        if not isinstance(self.input, dict):
            raise TrainingCorpusError("input must be a dict")
        if self.small_model_output is not None and not isinstance(self.small_model_output, dict):
            raise TrainingCorpusError("small_model_output must be a dict or None")
        if self.large_label is not None and not isinstance(self.large_label, dict):
            raise TrainingCorpusError("large_label must be a dict or None")
        if self.label_kind not in LABEL_KINDS:
            raise TrainingCorpusError(f"label_kind must be one of {LABEL_KINDS}, got {self.label_kind!r}")
        if not isinstance(self.provenance, dict):
            raise TrainingCorpusError("provenance must be a dict")
        try:
            self.weight = float(self.weight)
        except (TypeError, ValueError):
            raise TrainingCorpusError("weight must be a number") from None
        if not self.id:
            self.id = make_id(self.source, self.input, self.large_label)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "TrainingExample":
        known = {
            "id", "ts", "source", "provenance", "input", "small_model_output",
            "large_label", "label_kind", "weight", "schema_version",
        }
        kwargs = {k: v for k, v in data.items() if k in known}
        return cls(**kwargs)


def append_training_example(store, example: TrainingExample) -> str:
    """Write `example` to the SOIL collection `training_corpus`, keyed by id.

    Idempotent: writing the same logical example twice re-puts the same id
    with the same content — an overwrite that is identical in effect to a
    no-op (see make_id / module docstring). Returns the example's id.
    """
    store.put(COLLECTION, example.to_dict(), record_id=example.id)
    return example.id


def iter_training_examples(store, source: Optional[str] = None) -> list[dict]:
    """Read back training examples, optionally filtered by `source`.

    Mirrors the surrounding readers' populated/empty behavior: an empty or
    unreachable collection reads back as `store.all()` already resolves it —
    an empty list — never an exception; this function adds no state of its
    own beyond the store's.
    """
    rows = store.all(COLLECTION)
    if source is not None:
        rows = [r for r in rows if r.get("source") == source]
    return rows
