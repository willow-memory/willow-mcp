"""
nest-seed/secrets.py — credential detection + redaction.

A personal dump is exactly where stray credentials hide (a Discord token in a
`discord.txt`, a JWT pasted into a chat export). The classifier must never store
those as plaintext "notes". This module finds high-signal secrets so classify.py
can (a) emit a `secret` fragment that *flags* the exposure and (b) redact the raw
value out of the text before anything else embeds or stores it.

Detection is conservative and pattern-based — high-precision shapes only, plus
placeholder filtering — so it flags real credentials, not every long string.

Anchoring: earlier versions bounded each shape with `\\b` (a transition
between `\\w` and non-`\\w`). That is a WORD boundary, not a credential
boundary — a live key glued directly to adjacent letters on either side
(`wrapAKIAABCDEFGHIJKLMNOPwrap`) has no `\\w`/non-`\\w` transition immediately
before "AKIA", so `\\bAKIA...` never even attempts a match there and the key
sails through both the body and filename scans untouched. Every shape below
now matches on the credential's own structure instead — literal prefix +
fixed charset + length — with no boundary requirement, so gluing arbitrary
text on either side can no longer hide it.

A trailing negative-lookahead was tried on the AWS shape to reject a
truncated slice of a longer same-charset run, but that reopened the exact
evasion it was meant to close: a real 20-char AWS key immediately followed
by same-charset glue (one more uppercase letter or digit — the kind of
glue that shows up in filenames, base64-ish blobs, or a pasted block with
no separator) made the lookahead fail and the whole key evade detection.
The AWS shape now has no trailing anchor at all — `AKIA[0-9A-Z]{16,}`
greedily consumes the key plus any trailing same-charset run, exactly like
GitHub PAT / Google API key already did. A bare 20-char key still matches
in full; a key glued to more uppercase/digits matches the whole run (still
HELD/redacted as one value — over-matching a same-charset run costs
nothing since it is never a real ordinary-prose shape); a key followed by
a lowercase letter stops at 20 chars as before. Leading glue is still
caught by substring/finditer search regardless of anchor.

Flatten-2 F12: the shapes, their unanchored form and the ``api_key = value``
rule now live in the one script's ``onescript/scrub.py`` (sets ``credentials``
and ``assigned_credential``; the operator: "Using the onescript at every
path."), which keeps every fix above. willow-mcp carries them as ``scrub_local`` (a
parity-tested byte copy, so an installed server works with no checkout beside
it; operator: "2 carry copies"). This module keeps the Nest's names for the
kinds and its fingerprint.
"""

from __future__ import annotations

from .. import scrub_local

_SETS = ("credentials_bounded", "assigned_credential")

#: The Nest's names for the kinds the one script names otherwise.
_KIND = {
    "aws_access_key_id": "aws_access_key",
    "github_token": "github_pat",
    "provider_api_key": "openai_key",
}


def redact_value(v: str) -> str:
    """A safe fingerprint: enough to recognize, not enough to use."""
    v = v.strip()
    return f"{v[:6]}…{v[-4:]}" if len(v) > 12 else "[redacted]"


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return [(kind, raw_value), …] — deduped, in first-seen order. With the
    one script out of reach: [("unreachable", why)], so a caller that checks
    `if found:` holds the item rather than reading "could not look" as clean."""
    if not text:
        return []
    return [(_KIND.get(k, k), v) for k, v in scrub_local.find(text, _SETS)]


def redact_text(text: str) -> str:
    """Replace every detected secret with a typed placeholder."""
    if not text:
        return text
    return scrub_local.replace_found(text, scrub_local.find(text, _SETS), kind_of=lambda k: _KIND.get(k, k))
