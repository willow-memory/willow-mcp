"""scrub.py -- what must not leave, once (flatten-2 F12).

Eleven places each took out the text that must not leave, each with a piece of
the answer: willow-mcp ``secret_scan`` (nine credential shapes, the egress walk)
and its journal set (Groq, HF, Cerebras, xAI, the Authorization header, a
Postgres DSN, ``password=``); willow-mcp ``nest/secrets`` (the same shapes with
the ``\\b`` anchors taken off, to close a key glued to letters); the
safe-app-store copy of it, still ``\\b``-anchored; ratatosk ``redact`` (nine
shapes); Grove ``seat_record.scrub`` (the best generic hex, base64 and
``key=...`` rules); this script's ``serve._scrub`` (64-hex only); willow-mcp
``observability`` (sensitive key names and secret paths) and ``push_executor``
(a git trace); willow-bot ``ingress.redact_url``. No one covered the rest.
The operator: "Using the onescript at every path."

This is the union, as **named sets** and one ordered apply. A caller picks the
sets it wants, in the order it wants, and the marker it prints:

  hash64               a 64-hex run (a full-width hash)
  credentials          the credential shapes, **unanchored**: each is matched on
                       its own prefix, charset and length, so a key glued to
                       letters on either side is still found
  credentials_bounded  the same, with a GitHub token and a Google key at their
                       fixed length (for a finder that reports the value)
  journal_kv           free-text rules for a raw log: ``Authorization:``, a
                       Postgres DSN password, ``password=``, ``*_KEY=``
  assigned_credential  ``api_key = <16+ chars>`` with a placeholder filter
  generic              Grove's: known secrets (and a secret cut by up to three
                       non-word characters), ``key/seed/secret/token/password``
                       set to a value, long hex, split hex, mixed base64
  secret_path          a string that names where secrets live (whole value)
  git_trace            a git/curl trace: the Authorization header, ``gh?_`` tokens
  pii                  a person's data, each kind with its rung (``RUNGS``):
                       SSN, ITIN, card, birth date, bank and case numbers,
                       IBAN, passport, driver's licence, medical record,
                       phone, email, EIN, IP, MAC, a wallet, a location, a
                       home path, a Discord mention; ``withhold`` keeps what a
                       ceiling allows and names what it holds back
  typed_password       a password a person wrote, by its label (``pw:``,
                       ``$password =``): the label stays, the value goes

and ``redact_url`` for a URL. Observability's sensitive *key* test is
``sensitive_key``.

Three rules held here:

* **The union may never catch less than any copy did.** ``tests/test_scrub.py``
  holds each retired copy's own positive fixtures and asserts this catches
  every one (rule: "a scrubber may never catch less than any copy did").
* **Output is the caller's.** The marker is a string or a function of the
  kind; a caller keeps the token it printed before (``[hash withheld]``,
  ``[REDACTED:<kind>]``, ``[withheld]``, ``[redacted-by-willow-membrane]``).
  Persisted records and tests read those tokens, so only *added* coverage may
  change a caller's output. Where a caller names a kind differently
  (``aws_access_key`` for ``aws_access_key_id``) it maps the kind itself.
* **Order is the caller's.** A caller lists its old rules first and the
  added sets after, so what it already handled comes out as it did.

Unanchored costs something: ``sk-`` also matches inside ``task-<20 letters or
digits>``. A scrubber that cries wolf is turned off, but one a key can hide from
is worse; the nest copy took that trade first (2026-09, the glued-key evasion)
and this keeps it.

Pure standard library. Every function takes text and gives text; none reads
a file or the environment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

#: The marker most callers print: ``[REDACTED:<kind>]``.
DEFAULT_MARKER = "[REDACTED:{kind}]"

Marker = Any  # a str (``{kind}`` is filled in) or a function of the kind


def mark(marker: Marker, kind: str) -> str:
    """The text a caller prints for ``kind``."""
    if callable(marker):
        return marker(kind)
    return marker.format(kind=kind) if "{kind}" in marker else marker


@dataclass(frozen=True)
class Rule:
    """One rule of a set. ``rx`` is replaced by the marker (or by ``repl(m,
    marker)``); ``whole`` returns the marker for the whole value when ``rx``
    is found anywhere in it; ``fn(text, ctx)`` is a rule that needs more than
    a pattern. ``group``, ``reject`` and ``inside`` are for ``find``."""

    kind: str
    rx: Any = None
    repl: Callable | None = None
    whole: bool = False
    fn: Callable | None = None
    group: int = 0
    reject: Any = None
    inside: bool = False


@dataclass
class Ctx:
    marker: Marker
    secrets: tuple = ()
    known: tuple = ()
    found: set | None = None

    def mark(self, kind: str) -> str:
        return mark(self.marker, kind)


# -- hash64 (serve) -----------------------------------------------------------

_HASH64 = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)

# -- credentials: the union, unanchored ---------------------------------------

_PEM = r"(?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?"

_CREDENTIALS = (
    # A PEM block whole, and one a window cut off before its END line: the
    # non-greedy body tries a real END first and only then the end of the text
    # (journal rule, Loki 0DFFEFA6 F3), so a truncated key still goes.
    Rule(
        "private_key",
        re.compile(rf"-----BEGIN {_PEM}-----.*?(?:-----END {_PEM}-----|\Z)", re.DOTALL),
    ),
    Rule("aws_access_key_id", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16,}")),
    Rule("github_token", re.compile(r"gh[posur]_[A-Za-z0-9]{36,}")),
    # A fine-grained personal access token: `github_pat_`, 22, `_`, 59. Not a
    # `gh?_` shape, so the rule above never saw one (2026-10-31).
    Rule("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    Rule("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    Rule("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35,}")),
    Rule("stripe_key", re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{16,}")),
    # before `sk-`: unanchored, `csk-` would be nibbled from its second letter
    Rule("groq_api_key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    Rule("hf_token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    Rule("cerebras_api_key", re.compile(r"csk-[A-Za-z0-9]{20,}")),
    Rule("xai_api_key", re.compile(r"xai-[A-Za-z0-9]{20,}")),
    # after stripe, so `sk_live_` is claimed there
    Rule("provider_api_key", re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{20,}")),
    Rule(
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}"),
    ),
    Rule(
        "discord_token",
        re.compile(r"[MN][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"),
    ),
)

#: For a finder that reports the value (the Nest fingerprints and holds it): a
#: GitHub token and a Google key at their fixed length, so the letters glued
#: after one do not join the value (``AIza<35>trailing`` reports the key, not
#: the key and "trailing"). The redactors use the greedy form above, which
#: takes a longer same-charset run whole; this one only ever finds a prefix of
#: what that does.
_BOUNDED = {
    "github_token": re.compile(r"gh[posur]_[A-Za-z0-9]{36}"),
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
}
_CREDENTIALS_BOUNDED = tuple(
    replace(r, rx=_BOUNDED[r.kind]) if r.kind in _BOUNDED else r for r in _CREDENTIALS
)

# -- journal_kv: free text from a raw log (moved from willow-mcp secret_scan) --

#: Matched case-SENSITIVELY so ordinary lowercase field names never match.
#: ``_?PASSWORD`` catches ``DB_PASSWORD`` and ``PGPASSWORD``.
_LABEL_SUFFIX = r"(?:_KEY|_TOKEN|_SECRET|_?PASSWORD)"
#: Where a skipped value's own token must end, so ``null-9f8e7d`` (a real
#: value that starts with a skip word) is not skipped.
_SKIP_TOKEN_END = r"(?=[\s,;)}\]]|$)"
#: A value naming a credential's SOURCE (``env:VAR``, ``vault``) or an absent
#: one (``None``/``null``/empty) is never a secret, however labelled.
_SKIP_VALUE = (
    r'(?:"?\[REDACTED:'
    r'|""'
    r'|"?(?:None|null|NULL)"?' + _SKIP_TOKEN_END + r'|"?env:'
    r'|"?vault"?' + _SKIP_TOKEN_END + r")"
)
#: A quoted string (spaces and all, through its closing quote) or a bare run.
_VALUE_TOKEN = r'(?:"(?:[^"\\\n]|\\.)*"|\S+)'


def _kv(kind):
    return lambda m, mk: f"{m.group(1)}={mk}"


_JOURNAL_KV = (
    # `Authorization: <scheme> <value>`: keep the scheme, redact the value to
    # the end of the line; `[ \t]` and `[^\r\n]` so a bare header never eats
    # the next line.
    Rule(
        "authorization_header",
        re.compile(r"(?i)\bAuthorization:[ \t]*(\S+)[ \t]+(?!\[REDACTED:)[^\r\n]+"),
        lambda m, mk: f"Authorization: {m.group(1)} {mk}",
    ),
    # `postgres(ql)://user:PASSWORD@host`: keep scheme and user; the greedy run
    # backtracks to the LAST `@`, so a password holding `@` does not leak.
    Rule(
        "pg_dsn_password",
        re.compile(r"(?i)\b(postgres(?:ql)?://[^\s:/@]+:)(?!\[REDACTED:)([^\s]+)(@)"),
        lambda m, mk: f"{m.group(1)}{mk}{m.group(3)}",
    ),
    Rule(
        "password_kv",
        re.compile(
            r"(?i)\b(password|passwd)[ \t]*[:=][ \t]*(?!"
            + _SKIP_VALUE
            + r")"
            + _VALUE_TOKEN
        ),
        _kv("password_kv"),
    ),
    # `NESTOR_SEAL_KEY: <hex>` as well as `=`
    Rule(
        "labelled_secret_kv",
        re.compile(
            r"\b([A-Z][A-Z0-9_]*"
            + _LABEL_SUFFIX
            + r")[ \t]*[:=][ \t]*(?!"
            + _SKIP_VALUE
            + r")"
            + _VALUE_TOKEN
        ),
        _kv("labelled_secret_kv"),
    ),
    # the same label set in JSON: `"KEY": "value"`
    Rule(
        "labelled_secret_kv",
        re.compile(
            r'"([A-Z][A-Z0-9_]*'
            + _LABEL_SUFFIX
            + r')"[ \t]*:[ \t]*(?!'
            + _SKIP_VALUE
            + r')(?:"(?:[^"\\\n]|\\.)*"|\S+)'
        ),
        lambda m, mk: f'"{m.group(1)}": "{mk}"',
    ),
)

# -- assigned_credential (nest/secrets): key = value, 16+ chars ---------------

_ASSIGNED_CRED = re.compile(
    r"(?i)(api[_-]?key|secret|password|passwd|token|bearer)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"
)
_PLACEHOLDER = re.compile(
    r"(?i)(your|example|xxxx+|placeholder|none|null|true|false|changeme|redacted)"
)

# -- typed_password: a password a person wrote, labelled -----------------------
#
# The credential shapes are machine-made keys; a password a person typed has
# no shape, only a label. quick-stupids' the-box (IDEAS 119) carried two past
# serve: `$password = "password";` and `user: cwcftp pw: widgets1998`. The
# label stays and the value goes. A comparison (`$p == $password`), a label
# with no value, and a value that names a source or nothing (`env:`, `None`,
# a placeholder) are left alone; `pass` alone is too common a word to be a label.

_TYPED_PASSWORD = re.compile(
    r"(?i)(?<![\w$])(\$?(?:password|passwd|passphrase|pwd|pw)\b['\"]?\s*"
    r"(?<![=!<>])[:=](?!=)\s*)"
    r"(?!" + _SKIP_VALUE + r"|\$)"
    r"(\"[^\"\n]+\"|'[^'\n]+'|[^\s\"',;)}\]]+)"
)


def _p_typed_password(text: str, ctx: Ctx) -> str:
    def one(m: re.Match) -> str:
        if _PLACEHOLDER.search(m.group(2)):
            return m.group(0)
        return m.group(1) + ctx.mark("password")

    return _TYPED_PASSWORD.sub(one, text)


# -- secret_path / git_trace --------------------------------------------------

_SECRET_PATH = re.compile(
    r"(sean-data-vault|/\.willow/|/mcp_apps/|/vault/|WILLOW_HOME)",
    re.I,
)
#: Substrings that mark a key as sensitive: its value is redacted wholesale.
SENSITIVE_KEY = re.compile(
    r"(dsn|token|lease|consent|vault|secret|api[_-]?key|password|passwd|"
    r"authorization|cookie|session|seed|private|credential)",
    re.I,
)

_AUTH_TRACE = re.compile(r"(?i)(authorization:\s*)(basic|bearer|token)?\s*\S+")
_GH_SHORT = re.compile(r"\bgh[sopu]_[A-Za-z0-9]+")

_GIT_TRACE = (
    Rule("authorization_trace", _AUTH_TRACE, lambda m, mk: m.group(1) + "<redacted>"),
    Rule("gh_token", _GH_SHORT, lambda m, mk: "gh?_<redacted>"),
)

# -- generic (Grove seat_record.scrub, moved) ----------------------------------

_NAMED = r"\w*(?:key|seed|secret|token|passphrase|password)\w*"
#: ``HUMAN_KEY=...``, ``seed: ...``: the whole field (up to the next `` · ``
#: or the end of the line) is the value.
_ASSIGNED = re.compile(rf"\b{_NAMED}\s*[:=]\s*[^\n]*?(?= · |\n|$)", re.I)
#: ``seed <hex or base64>``: a secret's name, then a long token, no colon.
_NAMED_VALUE = re.compile(
    rf"\b(?!\w*_id\b){_NAMED}\s+[A-Za-z0-9+/_=-]{{16,}}", re.I
)  # (`seed_id 9f..` names a public id, not a seed)
_HEX_RUN = re.compile(r"[0-9a-fA-F]{24,}")
_HEX_PART = re.compile(
    r"(?<![0-9A-Za-z])(?=[0-9a-f]*[a-f])[0-9a-f]{8,}(?![0-9A-Za-z])", re.I
)
_B64_RUN = re.compile(
    r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_=-])"
)
#: Where a 64-hex is a record's own hash (a subject, the run's version).
_HASH_AFTER = re.compile(
    r"(?:\b(?:proposal|serve|outcome|forecast|seal|run|subject|head|merged)[: ]"
    r"|\btip:\d+:|\(\d+, )$",
    re.I,
)
_SHA_AFTER = re.compile(r"(?:\b(?:commit|sha1?|green on|head|merged)\W{0,3})$", re.I)


def _hex_ok(line: str, m: re.Match, known: tuple) -> bool:
    run = m.group(0)
    before = line[: m.start()]
    after = line[m.end() : m.end() + 1]
    if before[-1:].isalnum() or after.isalnum():
        return False  # glued into a word: no boundary, no hash
    if run in known:
        return True
    if len(run) == 64:
        return bool(_HASH_AFTER.search(before))
    if len(run) == 40:
        return bool(_SHA_AFTER.search(before))
    return False


def _g_known(line: str, ctx: Ctx) -> str:
    out = ctx.mark("known_secret")
    for sec in ctx.secrets:
        if sec and len(sec) >= 4:
            line = line.replace(sec, out)
        if sec and len(sec) >= 16:
            # the same secret cut into pieces by up to three non-word characters
            # (`,` `-` `/` `:` space ` · `) between any two of its characters
            gap = r"[^0-9A-Za-z]{0,3}"
            line = re.sub(
                gap.join(re.escape(ch) for ch in sec), lambda m: out, line, flags=re.I
            )
    return line


def _g_assigned(line: str, ctx: Ctx) -> str:
    out = ctx.mark("assigned_secret")
    return _ASSIGNED.sub(lambda m: out, line)


def _g_named_value(line: str, ctx: Ctx) -> str:
    out = ctx.mark("named_value")
    return _NAMED_VALUE.sub(lambda m: out, line)


def _g_0x(line: str, ctx: Ctx) -> str:
    out = ctx.mark("hex_0x")
    return re.sub(r"0[xX][0-9a-fA-F]{8,}", lambda m: out, line)


def _g_hex_run(line: str, ctx: Ctx) -> str:
    out = ctx.mark("hex_run")
    known = ctx.known
    return _HEX_RUN.sub(lambda m: m.group(0) if _hex_ok(line, m, known) else out, line)


def _g_hex_pieces(line: str, ctx: Ctx) -> str:
    """A key cut in pieces: adjacent hex pieces (space or ' · ') adding up to a key."""
    out = ctx.mark("hex_pieces")

    def pieces(m: re.Match) -> str:
        n = sum(len(x) for x in re.findall(r"[0-9a-fA-F]+", m.group(0)))
        return out if n >= 24 else m.group(0)

    return re.sub(
        rf"{_HEX_PART.pattern}(?:(?: · | ){_HEX_PART.pattern})+",
        pieces,
        line,
        flags=re.I,
    )


def _g_b64(line: str, ctx: Ctx) -> str:
    out = ctx.mark("base64")

    def b64(m: re.Match) -> str:
        t = m.group(0)
        mixed = (
            any(c.isdigit() for c in t)
            and any(c.isupper() for c in t)
            and any(c.islower() for c in t)
        )
        return out if mixed else t

    return _B64_RUN.sub(b64, line)


_GENERIC = (
    Rule("known_secret", fn=_g_known),
    Rule("assigned_secret", fn=_g_assigned),
    Rule("named_value", fn=_g_named_value),
    Rule("hex_0x", fn=_g_0x),
    Rule("hex_run", fn=_g_hex_run),
    Rule("hex_pieces", fn=_g_hex_pieces),
    Rule("base64", fn=_g_b64),
)

# -- pii: a person's data, each kind with its rung (IDEAS 119) -----------------
#
# The union of the fleet's personal-data checks, under this module's rule (it
# may never catch less than any copy did; `test_scrub.py` keeps each copy's
# positives): homestead `keep/advise.py` (the rungs and the labelled-only
# kinds), willow-2.0 `core/pii_detect.py` (the bare card with a Luhn check, a
# `+1` phone), its nest `pipeline/scrub.py` (account and case numbers),
# corpus-lens `egress_shapes.py` (a home path, which carries a username) and
# hermes-agent `agent/redact.py` (an E.164 phone, a Discord mention).
# willow-2.0's `scripts/pii_check.py` is left out: its rules are one person's
# literals, not shapes. A calendar date is left out too: a bare date is a
# hearing date far more often than a birth date (homestead's reason).
#
# Rungs are homestead's (L1 lowest, L5 never crosses). A labelled kind is
# matched only beside its label, and runs first, so `account 123456789` is a
# bank number and not also a bare SSN.

_DOB_LABEL = r"\b(?:dob|d\.o\.b\.?|date of birth|birth\s?date|born(?:\s+on)?)\b"
_DOB = re.compile(
    _DOB_LABEL + r"[\s:]*(?:\d{1,4}[-/]\d{1,2}[-/]\d{1,4}"
    r"|[A-Za-z]+\.?\s+\d{1,2},?\s+\d{4})",
    re.IGNORECASE,
)
_BANK = re.compile(
    r"\b(?:routing|aba|acct|account(?:\s*(?:no|number|#))?)\b[\s#:.]*\d{4,17}\b",
    re.IGNORECASE,
)
_SSN_LABELLED = re.compile(
    r"\b(?:ssn|social security(?: number| no\.?)?)\b[\s#:.]*\d{3}-?\d{2}-?\d{4}\b",
    re.IGNORECASE,
)
# The number must hold a digit, and `no` must end there: "the claim no longer
# open" is prose, and read as claim number "longer" it was marked (2026-10-31).
_CASE_NO = re.compile(
    r"\b(?:case|claim)\s*(?:no\b\.?|number\b|#)[:\s#]*(?=[\w\-]*\d)[\w\-]+\b", re.I
)
_SSN = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")
_CARD_GROUPS = re.compile(r"\b(?:\d{4}[-\s]){3}\d{4}\b")
_CARD_BARE = re.compile(r"\b\d{13,19}\b")
_EIN = re.compile(r"\b\d{2}-\d{7}\b")
_PHONE = re.compile(
    r"(?<![\d+])(?:\+?1[-.\s]?)?(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}(?!\d)"
)
_E164 = re.compile(r"\+[1-9]\d{6,14}(?![A-Za-z0-9])")
_EMAIL = re.compile(r"[^\s@\"'<>()\[\],;:]+@[^\s@\"'<>()\[\],;:]+\.[A-Za-z]{2,}\b")
_HOME_PATH = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\Users\\)[^/\\\s\"']+")
_DISCORD_USER = re.compile(r"<@!?\d{17,20}>")

# The baseline kinds no copy had (the detector catalogues' common set: IP,
# IBAN, ITIN, passport, driver's licence, medical record, MAC, a crypto
# wallet, a location). A labelled kind needs its label; a shape that random
# text can wear (an IBAN) needs its checksum. Loopback and unspecified
# addresses name no one and are left.
_ITIN = re.compile(r"\b9\d{2}[-\s](?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])[-\s]\d{4}\b")
_PASSPORT = re.compile(
    r"\bpassport(?:\s*(?:no\.?|number|#))?[\s#:.]*[A-Z0-9]{6,9}\b", re.I
)
_DRIVER_LICENSE = re.compile(
    r"\b(?:driver'?s?\s+licen[cs]e|DL\s*(?:no\.?|number|#))"
    r"(?:\s*(?:no\.?|number|#))?[\s#:.]*[A-Z0-9-]{5,15}\b",
    re.I,
)
_MRN = re.compile(
    r"\b(?:MRN|medical record(?:\s*(?:no\.?|number|#))?)[\s#:.]*[A-Z0-9-]{5,12}\b",
    re.I,
)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\d.])")
_IPV6 = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![\w:])"
    r"|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:){0,5}"
    r"[0-9A-Fa-f]{1,4}(?![\w:])"
)
_NOT_A_HOST = re.compile(r"^(?:127\.|0\.0\.0\.0$|255\.255\.255\.255$)")
_MAC = re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
_WALLET = re.compile(r"\b(?:bc1[a-z0-9]{25,59}|0x[0-9a-fA-F]{40})\b")
_LATLON = re.compile(r"(?<![\d.])-?\d{1,2}\.\d{4,},\s*-?\d{1,3}\.\d{4,}(?![\d.])")


def _host(value: str) -> bool:
    """An address that names a machine: not loopback or unspecified, and an
    IPv6 one with at least three groups (``a::b`` is C++, not a host)."""
    if _NOT_A_HOST.match(value):
        return False
    return ":" not in value or len([g for g in value.split(":") if g]) >= 3


def _p_ip(text: str, ctx: Ctx) -> str:
    """An IPv4 or IPv6 address that names a machine (`_host`)."""
    for rx in (_IPV4, _IPV6):
        text = rx.sub(
            lambda m: ctx.mark("ip") if _host(m.group(0)) else m.group(0), text
        )
    return text


def _iban_ok(value: str) -> bool:
    s = value.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def _p_iban(text: str, ctx: Ctx) -> str:
    """An IBAN only when its mod-97 check holds."""
    return _IBAN.sub(
        lambda m: ctx.mark("iban") if _iban_ok(m.group(0)) else m.group(0), text
    )


def _luhn(digits: str) -> bool:
    total = 0
    for i, d in enumerate(int(c) for c in reversed(digits)):
        total += (d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 else d
    return total % 10 == 0


def _p_card_bare(text: str, ctx: Ctx) -> str:
    """A run of 13-19 digits is a card only when its Luhn check holds."""
    return _CARD_BARE.sub(
        lambda m: ctx.mark("credit_card") if _luhn(m.group(0)) else m.group(0), text
    )


_PII = (
    Rule("ssn", _SSN_LABELLED),
    Rule("dob", _DOB),
    Rule("bank", _BANK),
    Rule("passport", _PASSPORT),
    Rule("driver_license", _DRIVER_LICENSE),
    Rule("medical_record", _MRN),
    Rule("case_no", _CASE_NO),
    Rule("iban", fn=_p_iban),
    Rule("itin", _ITIN),
    Rule("ssn", _SSN),
    Rule("credit_card", _CARD_GROUPS),
    Rule("credit_card", fn=_p_card_bare),
    Rule("ein", _EIN),
    Rule("phone", _PHONE),
    Rule("phone", _E164),
    Rule("email", _EMAIL),
    Rule("home_path", _HOME_PATH),
    Rule("discord_user", _DISCORD_USER),
    Rule("wallet", _WALLET),
    Rule("mac", _MAC),
    Rule("ip", fn=_p_ip),
    Rule("location", _LATLON),
)

#: Each pii kind's rung: 5 never crosses; 4 is money and birth; 3 resolves to a
#: person; 2 names a matter.
RUNGS: dict[str, int] = {
    "ssn": 5,
    "itin": 5,
    "credit_card": 4,
    "dob": 4,
    "bank": 4,
    "iban": 4,
    "passport": 4,
    "driver_license": 4,
    "medical_record": 4,
    "wallet": 4,
    "phone": 3,
    "email": 3,
    "ein": 3,
    "home_path": 3,
    "discord_user": 3,
    "ip": 3,
    "mac": 3,
    "location": 3,
    "name": 3,
    "case_no": 2,
}

#: The marker for a withheld kind: what it was and its rung, never the value.
WITHHELD_PII = "[withheld: {kind}, L{rung}]"


def names_rule(names) -> Rule | None:
    """A ``name`` rule for the names a person gives (their household, their
    clients): each whole, any case, longest first so "Jose Aguirre" goes
    before "Jose". No pattern finds a name; a list of the ones that matter
    does (willow-2.0's ``pii_check`` configured names). The list is the
    caller's and is never kept here."""
    names = sorted({n.strip() for n in names if n and n.strip()}, key=len, reverse=True)
    if not names:
        return None
    alt = "|".join(r"\s+".join(map(re.escape, n.split())) for n in names)
    return Rule("name", re.compile(rf"(?<!\w)(?:{alt})(?!\w)", re.IGNORECASE))


def withhold(text: Any, ceiling: int, *, names=(), found: set | None = None):
    """``text`` with every pii kind whose rung is over ``ceiling`` withheld and
    named (``[withheld: ssn, L5]``); kinds at or under it stay, since what is
    allowed depends on where the text is going. ``names``, when given, are
    withheld as ``name`` (`names_rule`). ``found`` gets the withheld kinds.
    ``ceiling`` 5 withholds nothing; 0 withholds every kind."""
    if not isinstance(text, str) or not text:
        return text
    ctx = Ctx(
        lambda kind: WITHHELD_PII.format(kind=kind, rung=RUNGS[kind]),
        found=found,
    )
    rules = _PII + ((r,) if (r := names_rule(names)) else ())
    for rule in rules:
        if RUNGS[rule.kind] > ceiling:
            text = _run(rule, text, ctx)
    return text


#: Every named set. A caller lists the sets it wants, in order, to ``apply``.
SETS: dict[str, tuple] = {
    "hash64": (Rule("hash64", _HASH64),),
    "credentials": _CREDENTIALS,
    "credentials_bounded": _CREDENTIALS_BOUNDED,
    "journal_kv": _JOURNAL_KV,
    "assigned_credential": (
        Rule("credential", _ASSIGNED_CRED, group=2, reject=_PLACEHOLDER, inside=True),
    ),
    "generic": _GENERIC,
    "secret_path": (Rule("secret_path", _SECRET_PATH, whole=True),),
    "git_trace": _GIT_TRACE,
    "pii": _PII,
    "typed_password": (Rule("password", fn=_p_typed_password),),
}


def kinds_of(sets) -> list[str]:
    """The kinds the named sets can report, in order, without repeats."""
    out: list[str] = []
    for name in sets:
        for r in SETS[name]:
            if r.kind not in out:
                out.append(r.kind)
    return out


def sensitive_key(name: Any) -> bool:
    """Does this key name mark its value as one to redact wholesale?"""
    return bool(SENSITIVE_KEY.search(str(name)))


def apply(
    text: Any,
    sets,
    *,
    marker: Marker = DEFAULT_MARKER,
    secrets: tuple = (),
    known: tuple = (),
    found: set | None = None,
):
    """``text`` with what the named ``sets`` find replaced, set by set and rule
    by rule in the order given. ``found`` (a set), when given, gets the kind of
    every rule that fired: kinds, never values. A non-string passes through."""
    if not isinstance(text, str) or not text:
        return text
    ctx = Ctx(marker, tuple(secrets), tuple(known), found)
    for name in sets:
        for rule in SETS[name]:
            text = _run(rule, text, ctx)
    return text


def _run(rule: Rule, text: str, ctx: Ctx) -> str:
    if rule.fn is not None:
        new = rule.fn(text, ctx)
        if new != text and ctx.found is not None:
            ctx.found.add(rule.kind)
        return new
    out = ctx.mark(rule.kind)
    if rule.whole:
        if rule.rx.search(text):
            if ctx.found is not None:
                ctx.found.add(rule.kind)
            return out
        return text
    if not rule.rx.search(text):
        return text
    if ctx.found is not None:
        ctx.found.add(rule.kind)
    if rule.repl is not None:
        return rule.rx.sub(lambda m: rule.repl(m, out), text)
    return rule.rx.sub(lambda m: out, text)


def found_kinds(text: Any, sets) -> list[str]:
    """Which kinds ``apply`` would mask in ``text``, in the sets' order: what
    ``apply`` itself reports (a ``csk-`` key is a Cerebras key, not also a
    ``sk-`` one). For diagnostics; never the value."""
    if not isinstance(text, str) or not text:
        return []
    got: set = set()
    apply(text, sets, found=got)
    return [k for k in kinds_of(sets) if k in got]


def find(text: str, sets=("credentials",)) -> list[tuple[str, str]]:
    """``[(kind, value), ...]`` for the pattern rules of ``sets``: deduped, in
    first-seen order. A rule with a ``reject`` drops values it matches (a
    placeholder); one with ``inside`` drops a value already inside an earlier
    one. Rules that are not patterns (``generic``) and ``whole`` rules are
    skipped."""
    if not text:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name in sets:
        for rule in SETS[name]:
            if rule.rx is None or rule.whole:
                continue
            for m in rule.rx.finditer(text):
                val = m.group(rule.group)
                if val in seen:
                    continue
                if rule.reject is not None and rule.reject.search(val):
                    continue
                if rule.inside and any(val in v for _, v in out):
                    continue
                seen.add(val)
                out.append((rule.kind, val))
    return out


def replace_found(
    text: str, pairs, *, marker: Marker = DEFAULT_MARKER, kind_of=None
) -> str:
    """``text`` with each found value (from ``find``) replaced by its marker.
    ``kind_of`` maps a kind to the name the caller prints."""
    for kind, val in pairs:
        text = text.replace(val, mark(marker, kind_of(kind) if kind_of else kind))
    return text


def walk_strings(
    obj: Any, fn: Callable[[str], str], max_depth: int = 40, _depth: int = 0
):
    """``obj`` with ``fn`` applied to every string value, through dicts, lists
    and tuples. Keys are structural field names, not payload. Past
    ``max_depth`` a substructure is left as it is (a hostile, deeply nested
    payload must not blow the stack; the funnel's size cap is upstream)."""
    if _depth > max_depth:
        return obj
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {k: walk_strings(v, fn, max_depth, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        walked = [walk_strings(v, fn, max_depth, _depth + 1) for v in obj]
        return type(obj)(walked) if isinstance(obj, tuple) else walked
    return obj


# -- redact_url (willow-bot steward/ingress.py, moved) -------------------------

_SAFE_SEGMENT = re.compile(r"^[a-z][a-z_.-]{0,31}$")
#: GitHub's own token prefixes: a segment starting with one is a token,
#: whatever its letters (``ghp_``, ``github_pat_``, ...).
_TOKEN_PREFIX = re.compile(r"^(gh[pousr]_|github_pat_)", re.IGNORECASE)


def _redact_segment(seg: str) -> str:
    """A path segment is kept only when it reads as a word (lowercase letters
    and ``_ . -`` only, at most 32 characters: ``webhook``, ``hooks``,
    ``github-app``) and does not start with a GitHub token prefix. Anything
    else is shown as ``…``: a relay channel (``smee.io/<channel>``) is
    mixed-case, often letters only, and a token placed in the path is exactly
    that shape (Loki 757108E8, 87DF2A04)."""
    if not seg:
        return seg
    if _TOKEN_PREFIX.match(seg) or not _SAFE_SEGMENT.match(seg):
        return "…"
    return seg


def redact_url(url: str) -> str:
    """``scheme://host[:port]/path`` with every path segment that could be a
    secret replaced by ``…``: drops any login, query and fragment, the other
    places a credential rides in a webhook URL. An IPv6 host keeps its
    brackets (``http://[::1]:9000/webhook``). Anything that is not a URL with
    a scheme and a host gives ``""``."""
    try:
        parts = urlsplit(str(url or "").strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return ""
    if not parts.scheme or not host:
        return ""
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port else host
    path = "/".join(_redact_segment(seg) for seg in parts.path.split("/"))
    return urlunsplit((parts.scheme, netloc, path, "", ""))
