#!/usr/bin/env python3
"""deploy/manifest-grant/seed_envelope_ratify.py — the installer's bootstrap
seed for the `envelope.ratify` envelope itself (gap `18affe49e198`; sealed
`1bd6fd29`; dispatch A9BF01A9 amending BD5843FD).

With row 24 (`envelope.ratify`) present in `syscall-table.json` (gap
`c1395b307421`, this same PR's step 1c), `envelope_propose(verb=
"envelope.ratify")` succeeds — but nothing can ever ratify that proposal:
`envelope_ratify_request` refuses `ENOENT` until an ACTIVE envelope already
governs `envelope.ratify`, and the only way to create one is
`envelope.ratify`. No principal can break this from either side — the
broker can read its own proposals sidecar but cannot write the trust-owner
register; the trust owner can write the register but cannot read the
broker-owned 0600 proposals sidecar (Loki 42B3B46F, U1). Only root, running
once at install time, spans both — sealed `1bd6fd29`: "Setup is the
installer's (root, once, detects rather than asks)."

This step runs AS THE TRUST OWNER (install.sh's `as_to`, after the signing
key exists) and calls `envelope_authoring.ratify_proposal_row` — the SAME
function the real `envelope.ratify` apply half calls (see
`trust_owner_verbs._apply_envelope_ratify`) — rather than hand-building the
active-register row's shape a second time. Idempotent: if an active
`envelope.ratify` grant for grantee `willow` already exists, this prints
that and changes nothing; it never disturbs any other active envelope, the
proposals sidecar, or the register's `proposals[]`/`archived[]`.

**Bounds, and why unbounded (argued in the PR body, not silently chosen):**
`{"proposal_ids": ["*"]}` — the wildcard-list convention this codebase
already uses elsewhere for an unbounded list-shaped bound
(`envelopes._bound_matches`: a list bound is a set of `fnmatch` patterns,
and `"*"` matches any string). At install time no proposal has ever
existed to name, so a bounds shape naming specific proposal ids would
recreate the exact deadlock this step exists to break, one ratification
later. This is not the same kind of escalation an unbounded `manifest.grant`
would be: every actual USE of this envelope still requires its own sealed
Nestor pair naming that proposal's own content digest (Loki BDC2B0F2, A2) —
the human seal is the real gate; this envelope only says "the desk may act
on ratifications the operator already sealed."

No FRANK citation is inked for this seed (unlike the real apply half, which
cites a `pair_id`): there is no sealed pair to cite — this is root's own
one-time bootstrap act, not a ratification of anything a human sealed. That
is itself a defensible, machine-checkable claim: the seeded row's own
`ratified_via` names install.sh and this gap, so a FRANK reader can always
tell this row apart from a real ratification even without a citation to
follow.
"""
from __future__ import annotations

import datetime
import sys

VERB = "envelope.ratify"
GRANTEE = "willow"
BOUNDS = {"proposal_ids": ["*"]}
ENVELOPE_ID = "env-envelope.ratify-bootstrap"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def find_active_grant(active: list) -> "dict | None":
    """The active `envelope.ratify` grant for `willow`, if any. Matched by
    (verb, grantee, status) rather than a fixed id — a future re-seed under
    a different id (or one hand-ratified through the normal path once it
    exists) is recognized just as well as this script's own prior run."""
    for row in active:
        if (
            row.get("verb") == VERB
            and row.get("grantee") == GRANTEE
            and row.get("status") == "active"
            and not row.get("revoked")
        ):
            return row
    return None


def seed(envelope_authoring, envelopes, *, sign_as: "str | None" = None) -> dict:
    """Idempotent seed. `envelope_authoring`/`envelopes` are passed in
    (rather than imported at module scope) so tests can point them at a
    throwaway registry via the modules' own `WILLOW_ENVELOPE_REGISTRY`/
    `WILLOW_SYSCALL_TABLE` env-var overrides without importing willow_mcp
    at collection time.

    Returns `{"seeded": True, "envelope_id": ...}` on a fresh write, or
    `{"seeded": False, "envelope_id": ..., "reason": ...}` when an active
    grant already covers this verb+grantee — box left completely untouched
    either way past this read.

    `sign_as` (dispatch FA4F79AC, M1 — install deadlock): install.sh calls
    this AFTER 1c (`constitutional/` already trust-owner-owned, the
    directory `pgp.pgp_enabled()` treats as "this box is provisioned for
    trust") but BEFORE trust.env is ever written — the generated
    fingerprint is not yet published anywhere `pgp.expected_fingerprint()`
    would find it. Going through the normal `pgp.pgp_enabled()` gate here
    raised `PgpSourceUnreadable` on EVERY fresh install, forever: not a
    retryable failure, since trust.env is only ever written by a LATER
    step that this one blocks. `sign_as`, when given, is passed straight
    through to `ratify_proposal_row`, which signs the register write
    unconditionally under that fingerprint — root's own already-resolved
    value, the same one install.sh is about to publish — instead of
    consulting the not-yet-published trust config. See
    `envelope_authoring._save_active`'s own docstring for the full
    argument."""
    registry = envelopes._load(envelopes.registry_path())
    active = list(registry.get("active") or [])
    existing = find_active_grant(active)
    if existing is not None:
        return {"seeded": False, "envelope_id": existing.get("id"), "reason": "already active"}

    verbs_by_id = envelope_authoring._load_syscall_table()
    verb_id = envelope_authoring._validate_bounds_signature(VERB, BOUNDS, verbs_by_id)

    row = {
        "id": ENVELOPE_ID,
        "verb_id": verb_id,
        "verb": VERB,
        "grantee": GRANTEE,
        "bounds": BOUNDS,
        "issued_by": "",
        "issued_at": "",
        "ratified_via": "",
        "expires_at": None,
        "max_count": None,
        "use_count_source": "frank",
        "status": "proposed",
        "notes": (
            "installer bootstrap seed (sealed 1bd6fd29, gap 18affe49e198) — "
            "envelope.ratify governs its own ratification; no proposal ever "
            "existed for this row, root seeds it once so the request/apply "
            "split for envelope.ratify itself can ever run."
        ),
        "proposed_at": _now_iso(),
        "proposed_by": {
            "verifier": "", "session_id": "", "orchestrator_session_id": "",
            "proposer_app_id": "deploy/manifest-grant/install.sh",
        },
        "precedent_ids": [],
    }
    ratified = envelope_authoring.ratify_proposal_row(
        row,
        ratified_by="install.sh (sealed 1bd6fd29)",
        ratified_via="installer bootstrap seed — gap 18affe49e198, no proposal to ratify from",
        citation_id=None,
        ledger=None,
        sign_as=sign_as,
    )
    return {"seeded": True, "envelope_id": ratified.get("id")}


def main(argv: "list[str] | None" = None) -> int:
    import os
    import re

    if argv:
        print(f"STOP: no arguments expected, got {argv!r}", file=sys.stderr)
        return 2

    # Imported lazily so this module stays importable (and its own argv
    # handling testable) even outside a willow_mcp checkout.
    from willow_mcp import envelope_authoring, envelopes

    # install.sh passes WILLOW_PGP_FINGERPRINT=$FPR in this one process's
    # own env (its own fresh-generated/resolved key, already validated as
    # a real gpg key by the `gpg --list-keys` call that produced it) —
    # used here as the explicit sign_as, never through pgp.expected_
    # fingerprint()/trust.env (see seed()'s own docstring, M1). Validated
    # to look like a real fingerprint before use; an unset or malformed
    # value falls back to the pre-existing pgp.pgp_enabled()-gated path
    # rather than silently signing under garbage.
    env_fpr = (os.environ.get("WILLOW_PGP_FINGERPRINT") or "").strip().upper()
    sign_as = env_fpr if re.match(r"^[A-F0-9]{40}$", env_fpr) else None

    report = seed(envelope_authoring, envelopes, sign_as=sign_as)
    if report["seeded"]:
        print(f"  seeded {report['envelope_id']} — envelope.ratify now governed for grantee willow")
    else:
        print(f"  {report['envelope_id']}: {report['reason']} — no-op")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
