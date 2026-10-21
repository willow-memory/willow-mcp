"""willow_mcp/secret_scan.py — egress secret redaction.

Defense-in-depth for the guarantee stated in the README ("No tool ever returns
a credential — only its source"). The credential *accessor* already enforces
this: credential_source() returns `env:VAR`/`vault`, never the value. But the
DATA path did not — a SOIL record, a KB atom, a task's output, or an external
integration's response body that happens to carry an `sk-...`, an `AKIA...`, or
a private-key block was returned verbatim. This module closes that gap at the
one funnel every tool response passes through (server._guarded).

Design:
  * REDACT, don't block. Redaction preserves the response structure and removes
    only the secret substring — the caller still gets its data, minus the
    credential the server was never supposed to hand back. This enforces the
    stated guarantee rather than breaking legitimate retrieval.
  * High-confidence patterns only. Each pattern matches a credential FORMAT
    distinctive enough to name (a provider key prefix, a PEM private-key block,
    a structured token) — not a generic high-entropy heuristic, which would
    redact legitimate ids and hashes. Precision over recall: a backstop that
    cried wolf would be turned off.
  * One rule, one home (flatten-2 F12). The patterns are the one script's
    ``onescript/scrub.py`` (the operator: "Using the onescript at every
    path."): the set ``credentials`` for this funnel, ``credentials`` plus
    ``journal_kv`` for a journal tail. This module keeps the funnel's shape (the
    walk, the opaque scan, the audit kinds) and names which sets it uses. With
    the one script out of reach it refuses: ``redact_egress`` raises
    ``ScrubUnreachable`` (``server._guarded`` turns that into
    ``egress_scan_failed``), ``scan_opaque`` reports ``unreachable`` (a refusal),
    ``redact_journal_tail`` withholds the whole tail. Never a copy of the old
    patterns.
  * Payload-free reporting. The caller-facing value is the redacted structure;
    the audit trail records only WHICH KINDS were redacted, never the value —
    so the backstop cannot itself become the leak (a stack trace / receipt with
    the secret in it).
"""
from __future__ import annotations

import json
from typing import Any

from .scrub_reach import ScrubUnreachable, get, need

_PLACEHOLDER = "[REDACTED:{kind}]"

#: The shared funnel's set, and the journal's wider one. The funnel NEVER takes
#: ``journal_kv``: its label heuristics (``*_KEY=``, ``password=``) redact
#: ``primary_key=True``, ``sort_key=lambda`` and a credential SOURCE
#: (``OPENAI_API_KEY=env:OPENAI_API_KEY``) in a structured tool answer, and a
#: test holds that line (Loki 0DFFEFA6 B3).
EGRESS_SETS = ("credentials",)
JOURNAL_SETS = ("credentials", "journal_kv")

# Bound recursion so a hostile deeply-nested payload can't blow the stack; past
# this depth we stop descending and leave the substructure as-is (fail-closed
# would over-block, so we cap and rely on the funnel's size sanitizer upstream).
_MAX_DEPTH = 40


def _redact_str(s: str, found: set, sets=EGRESS_SETS) -> str:
    return need().apply(s, sets, marker=_PLACEHOLDER, found=found)


def _walk(obj: Any, found: set, depth: int, sets=EGRESS_SETS) -> Any:
    # Values only: keys are structural field names, not payload.
    return need().walk_strings(
        obj, lambda s: _redact_str(s, found, sets), _MAX_DEPTH, depth
    )


def is_opaque(obj: Any) -> bool:
    """Whether `_walk` would pass `obj` through without looking inside it.

    `_walk` handles str/dict/list/tuple and returns everything else untouched.
    For scalars that is right — an int carries no secret. For a structured
    object it is a hole: a pydantic result model (SEP-2322's
    `InputRequiredResult`, say) would sail through the redaction funnel
    unscanned, and "no tool ever returns a credential" would quietly stop
    applying to whichever return type was added most recently.
    """
    return not isinstance(obj, (str, dict, list, tuple, bool, int, float, type(None)))


def scan_opaque(obj: Any) -> list[str]:
    """Kinds detected in `obj`'s serialized form, without rewriting it.

    For a result this module cannot safely rebuild, detection is still
    possible: serialize and scan the text. The caller decides what a hit
    means — for the tool funnel it means refuse, because a credential that
    cannot be redacted in place must not be returned at all.

    Raises nothing of its own; an object that cannot be serialized at all is
    reported as a scan failure by returning the sentinel kind
    ``"unserializable"``, which the caller must treat as fail-closed rather
    than as "clean".
    """
    try:
        text = json.dumps(obj, default=str, sort_keys=True)
    except Exception:
        try:
            text = str(obj)
        except Exception:
            return ["unserializable"]
    found: set = set()
    try:
        _redact_str(text, found)
    except ScrubUnreachable:
        return ["unreachable"]
    return sorted(found)


def redact_egress(result: Any) -> tuple[Any, list[str]]:
    """Scan a JSON-serializable tool result and redact any credential-shaped
    substrings. Returns (possibly-new result, sorted list of redacted kinds).

    Non-string scalars pass through untouched; strings have each detected
    secret replaced by `[REDACTED:<kind>]`. The returned kinds list is for the
    audit receipt — it never contains the redacted value itself.
    """
    found: set = set()
    redacted = _walk(result, found, 0)
    return redacted, sorted(found)


# ── journal-tail-only redaction (Loki 0DFFEFA6 B3) ──────────────────────────
#
# Used ONLY by `unit_status.journal_tail` — and, through it, the ELOOP/EDEAD
# journal `unit_reload_executor`/`unit_install_executor` attach to a refusal.
# NEVER the shared `redact_egress` funnel above. A raw journal tail is free
# text read for troubleshooting; a label heuristic ("anything ending in
# `_KEY=`") or a bare `password=` is the right level of paranoia there, and the
# wrong one for a structured tool response. The rules themselves (the `_KEY=`
# suffixes, the skip-a-credential-source values, the truncated PEM block, the
# Authorization scheme kept and the value to end of line, the DSN password
# behind the last `@`) moved whole to `onescript/scrub.py` (`journal_kv`).


def redact_journal_tail(text: str) -> tuple[str, list[str]]:
    """Redact a raw ``journalctl`` tail through the WIDER, journal-scoped
    sets (:data:`JOURNAL_SETS`). Used only by
    :func:`willow_mcp.unit_status.journal_tail` — never the general
    tool-response funnel (:func:`redact_egress`), which the label/kv rules
    would over-redact (Loki 0DFFEFA6 B3). With the one script out of reach the
    whole tail is withheld, with the reason."""
    mod, why = get()
    if mod is None:
        return _PLACEHOLDER.format(kind=f"unreachable: {why}"), ["unreachable"]
    found: set = set()
    redacted = mod.apply(text, JOURNAL_SETS, marker=_PLACEHOLDER, found=found)
    return redacted, sorted(found)
