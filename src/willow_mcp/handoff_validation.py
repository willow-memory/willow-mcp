"""Shared validator for handoff_write_v4 and verify_handoff (gap 21f80b2b348a,
sealed cdcd948c stage 2, gap 34c8e60f4260).

ONE validator, used by both the writer and the verifier, so the writer
refuses at write time exactly what the verifier would refuse later. Before
this, an unknown top-level key (e.g. `summary`/`details` instead of
`narrative`/`findings` -- the exact BFF5284B shape) was silently dropped
before it ever reached the writer, and the packet was written with
`findings=[]`, an empty narrative, and `checklist_resolved=True` -- the
auditor had nothing to judge (measured: two builders hit this in one
night). Also narrows the standing producer/consumer gap for the finding
shape itself: both handoff_write_v4 and verify_handoff now call the exact
same `invalid_findings`/`empty_findings_reason_missing` here, rather than
each carrying its own drifted copy of "what makes a finding valid."

Closed since (Loki 23CAD2B4 F3, gap 34c8e60f4260 fully): `handoff.handoff_write_v4`
now pre-flights `_has_completion_evidence`/`_judge_lint_claims` -- the exact
functions `verify_handoff` runs, not a second copy -- whenever
`checklist_resolved=True`, and refuses with the identical reason string
before ever writing. That pre-flight lives in handoff.py (it needs
`_judge_lint_claims`, which needs `ci_lint_pin`, which this module does not
import, to keep this module's own dependency surface small), not here; this
module still owns the shape checks (`invalid_findings`,
`empty_findings_reason_missing`) both the writer and verifier call. Landing
this did break the existing `test_handoff_write_v4_success` fixture (its
narrative "Fixed the issue." carried no counted test result, and its one
finding carried no `evidence`) and ~10 other call sites across the test
suite that asserted `checklist_resolved=True` with nothing checkable behind
it -- fixed at each site by adding real evidence, per Loki's instruction
("fix the call sites, do not weaken the rule").

KNOWN LIMIT (named, not faked): `write_refusal`'s unknown-key check only
sees kwargs that actually reach `handoff.handoff_write_v4` -- a direct
Python/test call, or the `**_unknown_fields` catch-all that function's own
signature now carries. The MCP tool boundary itself (server.py's
`@mcp.tool()`-decorated `handoff_write_v4`) still declares a fixed
keyword-only signature; the tool framework's own arg model
(`mcp.server.mcpserver.utilities.func_metadata.func_metadata`) builds a
pydantic model from that signature with the library's default
`extra='ignore'` on `ArgModelBase`, so a key that is not one of the
declared parameters is dropped by pydantic before the tool wrapper --
before this module -- ever sees it. Fully closing that half needs a
`ServerMiddleware` (see request_context.py's `RequestContextMiddleware` for
the established pattern -- it already proves the SDK exposes the raw,
pre-validation params on `ServerRequestContext`, since `ServerMiddleware`
runs "before any validation") that captures the raw `arguments` dict for a
`tools/call` targeting `handoff_write_v4` and diffs it against
`WRITE_ACCEPTED_FIELDS` before pydantic gets a chance to filter it. That is
real, separately-scoped work and is named here as the follow-on rather than
covered by a check that cannot see what pydantic already stripped.
"""

from __future__ import annotations

from typing import Optional

#: The exact keyword fields `handoff_write_v4` accepts beyond the two
#: positional identifiers (app_id, dispatch_id). A key outside this set is a
#: misspelling or an unmigrated caller -- refused by name, never dropped.
WRITE_ACCEPTED_FIELDS: frozenset = frozenset({
    "findings", "narrative", "checklist_resolved", "envelope_clean",
    "no_findings_reason",
})

#: The keys a finding may carry its one-line statement under, in the order
#: they are tried (loki: {n, branch, file, finding}; hanuman: title/summary).
FINDING_TEXT_KEYS: tuple = ("text", "title", "finding", "summary")

EXAMPLE_FINDING: dict = {
    "id": "F1",
    "text": "one-line statement of what was found",
    "severity": "medium",
    "evidence": ["42 passed", "commit abc1234"],
}


def finding_text(f: dict) -> str:
    """The finding's statement under whichever accepted key it used, or ''."""
    for key in FINDING_TEXT_KEYS:
        val = f.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def finding_evidence(f: dict) -> list:
    """Evidence as a list of non-empty strings, or [] if absent/empty."""
    raw = f.get("evidence")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw if str(x).strip()]
    return [str(raw)] if str(raw).strip() else []


def unknown_write_keys(extra_kwargs: dict) -> list:
    """Sorted names of any kwarg outside WRITE_ACCEPTED_FIELDS."""
    return sorted(k for k in (extra_kwargs or {}) if k not in WRITE_ACCEPTED_FIELDS)


def invalid_findings(findings: list) -> list:
    """Every finding that carries no statement under any accepted key, with
    its index and the keys it did carry, so a refusal names its cause. This
    is the shape check (a finding must SAY something) -- whether that
    statement is backed by `evidence` is judged separately, at the level of
    the whole handoff's completion claim, by `_has_completion_evidence`/
    `_judge_lint_claims` in handoff.py (shared as-is: handoff_write_v4 and
    verify_handoff both call the very same functions, not a second copy of
    the logic) -- requiring `evidence` on every individual finding would
    have broken every existing caller that passes a bare {id, text,
    severity} finding, which was never the shape in question here."""
    bad: list = []
    for i, f in enumerate(findings or []):
        if not isinstance(f, dict):
            bad.append({"index": i, "keys": [], "type": type(f).__name__})
        elif not finding_text(f):
            bad.append({"index": i, "keys": sorted(f.keys())})
    return bad


def empty_findings_reason_missing(findings: list, no_findings_reason: Optional[str]) -> bool:
    """True when findings is empty and no documented reason was given."""
    return not findings and not (isinstance(no_findings_reason, str) and no_findings_reason.strip())


def write_refusal(*, extra_kwargs: dict, findings: list, checklist_resolved: bool,
                   no_findings_reason: Optional[str]) -> Optional[dict]:
    """The single refusal check both handoff_write_v4 and verify_handoff run.
    Returns an EINVAL-shaped error dict naming exactly what is wrong, or
    None if the shape is acceptable. `checklist_resolved` is accepted for a
    symmetrical call signature even though the current rule does not key off
    it directly (an empty findings list needs a reason whether or not the
    checklist claims completion -- an honest blocker report still names why
    there is nothing to show)."""
    unknown = unknown_write_keys(extra_kwargs)
    if unknown:
        return {
            "error": "EINVAL",
            "message": f"unknown field(s): {', '.join(unknown)}",
            "unknown_fields": unknown,
            "accepted_fields": sorted(WRITE_ACCEPTED_FIELDS | {"app_id", "dispatch_id"}),
        }
    if empty_findings_reason_missing(findings, no_findings_reason):
        # This is the ONE refusal a real MCP client ever sees for the
        # BFF5284B shape (Loki EB30E84F F3): the SDK's own arg-validation
        # already dropped an unrecognized key like `summary`/`details`
        # before this function runs, so a caller who mistyped a field name
        # lands here with no other signal. Name the accepted fields and the
        # possible cause explicitly, not just "empty findings" -- the
        # message at the moment of failure has to carry what the docstring
        # otherwise only says up front.
        return {
            "error": "EINVAL",
            "message": (
                "empty `findings` requires `no_findings_reason` (a documented string "
                "explaining why there is nothing to report) -- or at least one finding, "
                f"e.g. {EXAMPLE_FINDING}. If you intended to pass findings/narrative and "
                "see this anyway, check your field names: an unrecognized keyword (e.g. "
                "`summary`/`details` instead of `narrative`/`findings`) is silently "
                "dropped before this check runs, not refused on its own."
            ),
            "accepted_fields": sorted(WRITE_ACCEPTED_FIELDS | {"app_id", "dispatch_id"}),
        }
    bad = invalid_findings(findings)
    if bad:
        return {
            "error": "EINVAL",
            "message": (
                f"{len(bad)} finding(s) carry no statement under any of "
                f"{'/'.join(FINDING_TEXT_KEYS)}, e.g. {EXAMPLE_FINDING}"
            ),
            "invalid_findings": bad,
        }
    return None
