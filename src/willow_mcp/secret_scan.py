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
  * Payload-free reporting. The caller-facing value is the redacted structure;
    the audit trail records only WHICH KINDS were redacted, never the value —
    so the backstop cannot itself become the leak (a stack trace / receipt with
    the secret in it).
"""
from __future__ import annotations

import json
import re
from typing import Any

_PLACEHOLDER = "[REDACTED:{kind}]"

# (kind, compiled pattern). Ordered most-specific first; a private-key block is
# matched before any token pattern could nibble at its base64 body.
_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    # PEM private key blocks (RSA/EC/OPENSSH/DSA/PGP or bare) — whole block.
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        r".*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        re.DOTALL)),
    # AWS access key id (long-term AKIA / temporary ASIA).
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # GitHub tokens: ghp_ (PAT), gho_/ghu_/ghs_/ghr_ (app/oauth/server/refresh).
    ("github_token", re.compile(r"\bgh[posur]_[A-Za-z0-9]{36,}\b")),
    # Slack tokens.
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # Google API key.
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # Stripe live secret / restricted keys.
    ("stripe_key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b")),
    # Provider secret keys with an `sk-` prefix (OpenAI / Anthropic `sk-ant-` /
    # others). Kept after stripe so `sk_live_` is claimed by the stripe rule.
    ("provider_api_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}\b")),
    # JSON Web Token: three base64url segments, header starts `eyJ`.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")),
]

# Bound recursion so a hostile deeply-nested payload can't blow the stack; past
# this depth we stop descending and leave the substructure as-is (fail-closed
# would over-block, so we cap and rely on the funnel's size sanitizer upstream).
_MAX_DEPTH = 40


def _redact_str(s: str, found: set) -> str:
    for kind, pat in _PATTERNS:
        if pat.search(s):
            found.add(kind)
            s = pat.sub(_PLACEHOLDER.format(kind=kind), s)
    return s


def _walk(obj: Any, found: set, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        return obj
    if isinstance(obj, str):
        return _redact_str(obj, found)
    if isinstance(obj, dict):
        # Values only — keys are structural field names, not payload.
        return {k: _walk(v, found, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        walked = [_walk(v, found, depth + 1) for v in obj]
        return type(obj)(walked) if isinstance(obj, tuple) else walked
    return obj


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
    _redact_str(text, found)
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
