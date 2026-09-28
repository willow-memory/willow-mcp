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
#: This is the SHARED funnel's pattern set — pre-branch behaviour, restored
#: (Loki 0DFFEFA6 B3 / the desk's correction: the branch's new provider
#: prefixes and, worse, its label-heuristic KV patterns were added HERE,
#: where every tool response passes through `server._guarded`, and
#: over-redacted legitimate callers — `primary_key=True`, `sort_key=lambda`,
#: `password=None`, even `OPENAI_API_KEY=env:OPENAI_API_KEY` (the credential
#: SOURCE the README's own guarantee promises, not a value). None of that
#: belongs in a funnel every tool answer rides through; it belongs scoped to
#: the one place it was actually needed. See `_JOURNAL_PATTERNS` below and
#: `redact_journal_tail`, used ONLY by `unit_status.journal_tail` (and, via
#: it, the ELOOP/EDEAD journal paths in `unit_reload_executor` /
#: `unit_install_executor`).

def _whole_match_replacer(kind: str):
    """Every pattern in the shared `_PATTERNS` list replaces its ENTIRE match
    with the placeholder — no prefix/suffix to preserve."""
    placeholder = _PLACEHOLDER.format(kind=kind)
    return lambda m: placeholder


#: (kind, compiled pattern, replacer) triples the shared funnel scans with.
_COMPILED_PATTERNS: list[tuple[str, "re.Pattern[str]", Any]] = [
    (kind, pat, _whole_match_replacer(kind)) for kind, pat in _PATTERNS
]

# Bound recursion so a hostile deeply-nested payload can't blow the stack; past
# this depth we stop descending and leave the substructure as-is (fail-closed
# would over-block, so we cap and rely on the funnel's size sanitizer upstream).
_MAX_DEPTH = 40


def _redact_str(s: str, found: set, patterns=None) -> str:
    for kind, pat, replacer in (patterns if patterns is not None else _COMPILED_PATTERNS):
        if pat.search(s):
            found.add(kind)
            s = pat.sub(replacer, s)
    return s


def _walk(obj: Any, found: set, depth: int, patterns=None) -> Any:
    if depth > _MAX_DEPTH:
        return obj
    if isinstance(obj, str):
        return _redact_str(obj, found, patterns)
    if isinstance(obj, dict):
        # Values only — keys are structural field names, not payload.
        return {k: _walk(v, found, depth + 1, patterns) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        walked = [_walk(v, found, depth + 1, patterns) for v in obj]
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


# ── journal-tail-only redaction (Loki 0DFFEFA6 B3) ──────────────────────────
#
# Everything below is used ONLY by `unit_status.journal_tail` — and, through
# it, the ELOOP/EDEAD journal `unit_reload_executor`/`unit_install_executor`
# attach to a refusal. NEVER the shared `redact_egress` funnel above. A raw
# journal tail is free text read for troubleshooting; a label heuristic
# ("anything ending in `_KEY=`") or a bare `password=` is the right level of
# paranoia there, and the wrong one for a structured tool response, where the
# same heuristics redacted `primary_key=True`, `sort_key=lambda`, and even
# `OPENAI_API_KEY=env:OPENAI_API_KEY` — a credential SOURCE, exactly what the
# README's guarantee says a tool MAY return.

#: Any of these NAME suffixes, matched case-SENSITIVELY (unlike the retired
#: shared pattern) so ordinary lowercase field names never match at all.
#: `_?PASSWORD` (optional underscore) catches both `DB_PASSWORD` and the
#: unseparated `PGPASSWORD` (Loki 0DFFEFA6 F3 residual (b)).
_JOURNAL_LABEL_SUFFIX = r"(?:_KEY|_TOKEN|_SECRET|_?PASSWORD)"

#: Where a skipped VALUE's own token must end — whitespace, closing quote,
#: common trailing JSON/text punctuation, or end of string. Required after
#: `None`/`null`/`NULL` and `vault` below so the skip only fires on the EXACT
#: token, never a PREFIX of it: `null-9f8e7d6c5b4a` and `vaultpass123secret`
#: are real secret values that happen to start with a skip word, not the
#: word itself (58BC828C F: the old bare `\b` treated the boundary between
#: `null`/`vault` and the next character as enough, and a hyphen or letter
#: right after is already a non-word/word transition either way).
_JOURNAL_SKIP_TOKEN_END = r'(?=[\s,;)}\]]|$)'

#: A value naming a credential's SOURCE (`env:VAR`, `vault`) or an
#: obviously-absent one (`None`/`null`/empty) is never a secret, however
#: labelled — skipped regardless of an already-redacted placeholder too.
_JOURNAL_SKIP_VALUE = (
    r'(?:"?\[REDACTED:'
    r'|""'
    r'|"?(?:None|null|NULL)"?' + _JOURNAL_SKIP_TOKEN_END +
    r'|"?env:'
    r'|"?vault"?' + _JOURNAL_SKIP_TOKEN_END +
    r')'
)

#: The value a labelled/password KV pattern captures: a quoted string
#: (spaces and all, redacted whole through its closing quote — 58BC828C: the
#: old bare `\S+` stopped at the first space and left the tail of a quoted
#: multi-word value, e.g. `SECRET_KEY="two words"`, leaking past the
#: placeholder) or, failing that, a bare non-whitespace run.
_JOURNAL_VALUE_TOKEN = r'(?:"(?:[^"\\\n]|\\.)*"|\S+)'


def _journal_kv_replacer(kind: str):
    placeholder = _PLACEHOLDER.format(kind=kind)
    return lambda m: f"{m.group(1)}={placeholder}"


def _journal_json_kv_replacer(kind: str):
    placeholder = _PLACEHOLDER.format(kind=kind)
    return lambda m: f'"{m.group(1)}": "{placeholder}"'


def _journal_auth_header_replacer(kind: str):
    placeholder = _PLACEHOLDER.format(kind=kind)
    return lambda m: f"Authorization: {m.group(1)} {placeholder}"


def _journal_dsn_replacer(kind: str):
    placeholder = _PLACEHOLDER.format(kind=kind)
    return lambda m: f"{m.group(1)}{placeholder}{m.group(3)}"


_JOURNAL_PATTERNS: list[tuple[str, "re.Pattern[str]", Any]] = [
    # The shared, whole-match, high-confidence patterns apply here too — a
    # journal tail can carry any of them just as easily as a tool response.
    # `private_key` is excluded here — the truncation-tolerant replacement
    # below supersedes it for journal use.
    *(t for t in _COMPILED_PATTERNS if t[0] != "private_key"),
    # PEM private key block, ALSO matching a block the `-n` window cut off
    # before a closing `-----END ... KEY-----` ever appeared (Loki 0DFFEFA6
    # F3 residual (a)): the non-greedy body tries the real END first, and
    # only falls through to end-of-text when no END exists in the tail at
    # all — so a truncated key still redacts everything it left visible,
    # rather than leaking every line of a body with no END in view.
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        r".*?(?:-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----|\Z)",
        re.DOTALL), _whole_match_replacer("private_key")),
    ("groq_api_key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),
     _whole_match_replacer("groq_api_key")),
    ("hf_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
     _whole_match_replacer("hf_token")),
    ("cerebras_api_key", re.compile(r"\bcsk-[A-Za-z0-9]{20,}\b"),
     _whole_match_replacer("cerebras_api_key")),
    ("xai_api_key", re.compile(r"\bxai-[A-Za-z0-9]{20,}\b"),
     _whole_match_replacer("xai_api_key")),
    # `Authorization: <scheme> <value>` — keep the scheme (whatever it is;
    # 58BC828C: the old fixed `Bearer|Basic|Token` list left `ApiKey` and
    # every other scheme unredacted), redact the WHOLE value up to end of
    # line (a SigV4-shaped value has internal spaces of its own, e.g.
    # `AWS4-HMAC-SHA256 Credential=..., Signature=...`). `[ \t]` (never
    # `\s`) between the scheme and the value, and `[^\r\n]` for the value
    # itself, so a journal line with no value never crosses the `\n` and
    # eats the FOLLOWING line's timestamp (residual (d)).
    ("authorization_header", re.compile(
        r"(?i)\bAuthorization:[ \t]*(\S+)[ \t]+(?!\[REDACTED:)[^\r\n]+"),
     _journal_auth_header_replacer("authorization_header")),
    # `postgres(ql)://user:PASSWORD@host` — keep the scheme/user, redact only
    # the password. Greedy `[^\s]+` backtracks from the end of the run to the
    # LAST `@` on the line, so a password itself containing `@` no longer
    # leaks its tail (residual (c)).
    ("pg_dsn_password", re.compile(
        r"(?i)\b(postgres(?:ql)?://[^\s:/@]+:)(?!\[REDACTED:)([^\s]+)(@)"),
     _journal_dsn_replacer("pg_dsn_password")),
    # `password=`/`passwd=` (env dumps, querystrings) via `=` or `:` — never a
    # value that names a source or is absent. The value token accepts a
    # quoted string (58BC828C: a bare `\S+` stopped at the first space and
    # left the tail of `password="two words"` leaking past the placeholder).
    ("password_kv", re.compile(
        r"(?i)\b(password|passwd)[ \t]*[:=][ \t]*(?!" + _JOURNAL_SKIP_VALUE + r")"
        + _JOURNAL_VALUE_TOKEN),
     _journal_kv_replacer("password_kv")),
    # Labelled secret assignment, `=` or `:` (residual (b): the colon form) —
    # e.g. `NESTOR_SEAL_KEY: <64-hex>` as well as `NESTOR_SEAL_KEY=<64-hex>`.
    ("labelled_secret_kv", re.compile(
        r"\b([A-Z][A-Z0-9_]*" + _JOURNAL_LABEL_SUFFIX + r")[ \t]*[:=][ \t]*"
        r"(?!" + _JOURNAL_SKIP_VALUE + r")" + _JOURNAL_VALUE_TOKEN),
     _journal_kv_replacer("labelled_secret_kv")),
    # Same label set, JSON form (residual (b)): `"KEY": "value"` — the
    # colon-form pattern above cannot match through the key's closing quote.
    ("labelled_secret_kv", re.compile(
        r'"([A-Z][A-Z0-9_]*' + _JOURNAL_LABEL_SUFFIX + r')"[ \t]*:[ \t]*'
        r'(?!' + _JOURNAL_SKIP_VALUE + r')(?:"(?:[^"\\\n]|\\.)*"|\S+)'),
     _journal_json_kv_replacer("labelled_secret_kv")),
]


def redact_journal_tail(text: str) -> tuple[str, list[str]]:
    """Redact a raw ``journalctl`` tail through the WIDER, journal-scoped
    pattern set above. Used only by :func:`willow_mcp.unit_status.journal_tail`
    — never the general tool-response funnel (:func:`redact_egress`), which
    the label/kv patterns here would over-redact (Loki 0DFFEFA6 B3)."""
    found: set = set()
    redacted = _redact_str(text, found, _JOURNAL_PATTERNS)
    return redacted, sorted(found)
