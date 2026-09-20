"""willow_mcp/nest/correct.py — human negative-correction path (GAP #2a).

`selflearn.apply_correction` is the pure, numerically-stable mechanism:
retract the offending vector from the wrong category's learned store, and
optionally promote it into the correct one. This module is the thin
persistence wrapper around it (same shape as `kb_verify.verify_and_record`
for GAP #3): it resolves a vector from `text` when the caller didn't already
have one, applies the correction, and appends a matching training_corpus
example — a human correction is ground truth, so it always carries
`label_kind="human"` and a NEGATIVE weight, distinct from the ordinary
teacher/verification signals other sources emit.

Everything above the persistence layer stays inside `selflearn.py`;
everything here is additive and never mutates that module's pure functions.
"""
from __future__ import annotations

import logging
from typing import Optional

from ..training_corpus import (
    SOURCE_NEST_CLASSIFY,
    TrainingExample,
    append_training_example,
)
from . import embed as _embed
from . import selflearn as _selflearn

logger = logging.getLogger(__name__)

# The negative weight a human correction's training_corpus row carries — the
# mirror of the implicit +1.0 an uncorrected observation carries by not
# having a weight at all. Fixed rather than caller-supplied so a correction
# can never accidentally emit a *positive* weight and be mistaken for
# ordinary teacher/verification signal.
CORRECTION_WEIGHT = -1.0


def record_correction(store, model: str, *, wrong_category: str,
                      text: Optional[str] = None,
                      vec: Optional[list] = None,
                      correct_category: Optional[str] = None,
                      record_hash: Optional[str] = None,
                      embed_model: Optional[str] = None,
                      app_id: Optional[str] = None) -> dict:
    """Record a human correction: demote `wrong_category`, optionally promote
    `correct_category`, and log a training_corpus example — best effort on
    the training_corpus write only (see below).

    Exactly one of `text` / `vec` must be resolvable to a vector: `vec` is
    used as given; otherwise `text` is embedded with the same model the
    classifier used. Neither given, or embedding unavailable/failing, is a
    clear error — never a silent no-op.

    Invalid corrections (unknown category, malformed vector) raise nothing:
    they are caught and returned as `{"status": "error", "error": ...}`, so
    a bad correction from a caller can never partially apply.
    """
    resolved_vec = vec
    if resolved_vec is None:
        if not text or not text.strip():
            return {"status": "error",
                   "error": "one of vec or text is required to identify the correction"}
        resolved_vec = _embed.embed_document(text, model=embed_model or _embed.DEFAULT_EMBED_MODEL)
        if not resolved_vec:
            return {"status": "error",
                   "error": "embedding unavailable — cannot resolve text to a vector; "
                            "pass vec directly instead"}

    try:
        result = _selflearn.apply_correction(
            model,
            wrong_category=wrong_category,
            vec=resolved_vec,
            correct_category=correct_category or None,
            record_hash=record_hash or None,
        )
    except _selflearn.CorrectionError as e:
        return {"status": "error", "error": str(e)}

    try:
        example = TrainingExample(
            source=SOURCE_NEST_CLASSIFY,
            input={"text": (text or "")[:500], "hash": record_hash, "app_id": app_id},
            small_model_output={"category": wrong_category},
            large_label={"category": correct_category or f"not {wrong_category}"},
            label_kind="human",
            weight=CORRECTION_WEIGHT,
            provenance={"model": model, "embed_model": embed_model, "kind": "nest_correction"},
        )
        example_id = append_training_example(store, example)
        result["training_example_id"] = example_id
    except Exception:
        logger.exception(
            "record_correction: failed to append training_corpus example for "
            "wrong_category=%r correct_category=%r", wrong_category, correct_category)
        result["training_example_id"] = None

    return result
