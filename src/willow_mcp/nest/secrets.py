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
"""
from __future__ import annotations

import re

# Ordered: specific shapes first, broad JWT last (so redaction labels are precise).
_PATTERNS: list[tuple[str, "re.Pattern"]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16,}")),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("discord_token", re.compile(r"[MN][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}")),
]

# key = value style, with placeholder rejection
_ASSIGNED = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|token|bearer)\b['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"
)
_PLACEHOLDER = re.compile(r"(?i)(your|example|xxxx+|placeholder|none|null|true|false|changeme|redacted)")


def redact_value(v: str) -> str:
    """A safe fingerprint: enough to recognize, not enough to use."""
    v = v.strip()
    return f"{v[:6]}…{v[-4:]}" if len(v) > 12 else "[redacted]"


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return [(kind, raw_value), …] — deduped, in first-seen order."""
    if not text:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind, rx in _PATTERNS:
        for m in rx.finditer(text):
            val = m.group(0)
            if val not in seen:
                seen.add(val)
                out.append((kind, val))
    for m in _ASSIGNED.finditer(text):
        val = m.group(2)
        if val in seen or _PLACEHOLDER.search(val):
            continue
        # skip if already caught by a specific pattern above
        if any(val in v for _, v in out):
            continue
        seen.add(val)
        out.append(("credential", val))
    return out


def redact_text(text: str) -> str:
    """Replace every detected secret with a typed placeholder."""
    for kind, val in find_secrets(text):
        text = text.replace(val, f"[REDACTED:{kind}]")
    return text
