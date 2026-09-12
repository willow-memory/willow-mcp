"""subject_consent — consent for a subject who isn't the owner.

The stdlib-only, egress-free core of the guardian-consent seam. One shared
primitive for the gap that corpus-lens named its "biggest unshipped gap", the
willow-mcp seam doc mapped, and UTETY built privately: *did this person — or a
guardian on their behalf — agree to their data being used this way?*

This is the extracted, standalone package (the Kart/`kartikeya` pattern applied
to the consent primitive): three consumers depend on it rather than each carrying
a copy — **willow-mcp** (a thin binding wires it into its gate + ReceiptLog),
**UTETY** (the reference implementation, on a child's device), and **corpus-lens**
(its `person_inference` capability). It imports nothing but the standard library,
and `tests/` enforces that boundary — that is what lets a child-device consumer
and a stdlib-only-charter consumer both depend on it without dragging a runtime
in behind it. Bindings may import this core; this core imports none of them.

Provenance: home is THIS repo. This package was vendored from
rudi193-cmd/safe-app-store ``libs/subject-consent`` (MIT; box audit A1) under a
hash pin and a CI compare. safe-app-store is archived and is never an origin
again (owner decision, 2026-09-12), so since that date this is the canonical
copy: edit it here. The HARD CONSTRAINT above is unchanged — stdlib only, no
network, no willow-mcp runtime imports — and tests/test_subject_consent.py holds
it.
"""
from __future__ import annotations

from .core import (
    RELATIONS,
    SCOPES,
    Backend,
    ChainTamperError,
    Consent,
    DeidentificationError,
    FileBackend,
    Subject,
    SubjectConsentError,
    deidentify,
    grant,
    permitted,
    read_disclosures,
    record_disclosure,
    revoke,
    verify_consent_chain,
)

__all__ = [
    "SCOPES",
    "RELATIONS",
    "Subject",
    "Consent",
    "Backend",
    "FileBackend",
    "SubjectConsentError",
    "DeidentificationError",
    "ChainTamperError",
    "grant",
    "revoke",
    "permitted",
    "verify_consent_chain",
    "deidentify",
    "record_disclosure",
    "read_disclosures",
]
