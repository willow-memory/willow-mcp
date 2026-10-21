"""canon.py -- the canonical-bytes encodings, once, each by name (flatten-2 F7).

Eleven places in four repos turned a JSON value into the bytes a hash or a
signature covers, by seven different ``json.dumps`` calls. Most of them hash
data already on disk, so none may change by one byte. The operator: "Using the
onescript at every path." (D-e: bytes already persisted never change; the old
encodings survive as NAMED variants, each pinned by a byte-for-byte test, as
F-15 kept xorshift beside the stream.)

This is a registry of named encodings, one function per family, and each says
where its bytes are persisted. A copy imports its family by name; it does not
retype the ``json.dumps`` call. Where a call site does more than encode (adds
``b"\\x00" + prev``, strips chain keys, wraps in an HMAC), that stays at the
call site and only the encode step comes here.

THIS IS NOT JCS (RFC 8785). ``json.dumps`` emits ``NaN``/``Infinity`` by
default, coerces non-string keys (``{1: x, "1": y}`` collides), passes a lone
surrogate until it is encoded, and writes floats with ``repr``. None of these
families is a standard; they are what the fleet's chains already hold. Never
call one JCS, and never reproduce one in another language from this docstring:
read the pinned bytes in ``tests/test_canon.py``.

The families (letters are the F7 research's; the name says what the bytes are)::

    name                              version id          family
    sorted_compact_utf8               wgrv-canon-a/v1     A
    sorted_compact_ascii              wgrv-canon-b/v1     B, C
    sorted_compact_ascii_default_str  wgrv-canon-b-str/v1 B'
    compact_utf8                      wgrv-canon-e/v1     E, H
    compact_ascii                     wgrv-canon-e-ascii/v1  E'
    spaced_utf8                       wgrv-canon-f/v1     F
    sorted_spaced_ascii               wgrv-canon-g/v1     G, I
    strict_sorted_compact_utf8        wgrv-canon-strict/v1   NEW CODE ONLY

Families that came out byte-identical are one encoding here, with every
persisted place listed: C is B (constitutional writes ``ensure_ascii=True``
explicitly, which is the default), H is E (one is the shape of the input, a
dict or an array, not of the encoding), I is G (the line is hashed raw).
Merged because their bytes must be identical, not because they look alike.

Each ``Encoding`` is called with a value and returns ``str``; ``.bytes(value)``
is the UTF-8 of that. A family that keeps non-ASCII literal (A, E, F) raises
``UnicodeEncodeError`` from ``.bytes`` on a lone surrogate, as the copies did;
the ASCII families escape it. ``strict_sorted_compact_utf8`` refuses it.

Who imports and who keeps (operator rulings, 2026-10-21): the one script's own
modules, willow-mcp's non-trust-owner modules (``bound_receipt``,
``session_signing``, ``attribution_ledger``) and Grove import their family by
name. willow-mcp's trust-owner code (the manifest-grant, envelope and
constitutional closure, which runs from a root-owned venv and never reaches a
sibling checkout), ``willow_bot.deposits`` (a wheel without ``one-script/``),
``subject_consent.core`` (a stdlib charter), Forge, the frozen
ai-game-master ``verify_ledger`` and safe-app-store (a parts bin) keep their
own code. Their ``persisted`` entries below are known uses, each held to its
family by a byte-for-byte test where the code lives.

Stdlib only: the one script's consumers load this through
``onescript_reach.module("canon")``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable


class CanonError(ValueError):
    """A value the strict encoding refuses (said plainly, never coerced)."""


@dataclass(frozen=True)
class Encoding:
    """One named encoding: ``name``, a stable ``version`` id, the persisted
    places that depend on it, and the ``json.dumps`` it is."""

    name: str
    version: str
    families: tuple[str, ...]
    persisted: tuple[str, ...]
    _dumps: Callable[[Any], str]

    def __call__(self, obj: Any) -> str:
        return self._dumps(obj)

    def bytes(self, obj: Any) -> bytes:
        return self._dumps(obj).encode("utf-8")


def _enc(name, version, families, persisted, dumps) -> Encoding:
    return Encoding(name, version, tuple(families), tuple(persisted), dumps)


#: A. sorted keys, compact, non-ASCII literal.
sorted_compact_utf8 = _enc(
    "sorted_compact_utf8",
    "wgrv-canon-a/v1",
    "A",
    (
        "onescript record rows (hash = sha256 of the row without `hash`) and the tip anchor",
        "onescript xref index cache",
        "onescript session bundles (`session:<sha256>` subjects; mirrors Nestor's session_seal.canonical)",
        "willow-mcp manifest_policy_digest, envelope bounds digest, egress envelope payload "
        "(signed), trust_owner_verbs proposal digest",
    ),
    lambda obj: json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ),
)

#: B (and C). sorted keys, compact, non-ASCII escaped to \uXXXX.
sorted_compact_ascii = _enc(
    "sorted_compact_ascii",
    "wgrv-canon-b/v1",
    "BC",
    (
        "willow-mcp dispatch_signing signable bytes, session_binder header HMAC, "
        "manifest_grant_executor payload, subject_consent consent/disclosure chains, "
        "constitutional governance-row hashes (explicit ensure_ascii=True, load-bearing)",
        "safe-app-store sap_gate manifest signatures, libs/subject-consent chains, "
        "store_reconcile projection hash, aristarchus ledger body hash",
        "willow-bot deposits ci_outcomes row_hash (body without the chain keys)",
    ),
    lambda obj: json.dumps(obj, sort_keys=True, separators=(",", ":")),
)

#: B'. B with ``default=str``: a value json cannot encode is its ``str()``.
sorted_compact_ascii_default_str = _enc(
    "sorted_compact_ascii_default_str",
    "wgrv-canon-b-str/v1",
    "B'",
    ("willow-mcp training_corpus ids",),
    lambda obj: json.dumps(obj, sort_keys=True, default=str, separators=(",", ":")),
)

#: E (and H). insertion order, compact, non-ASCII literal. Positional arrays
#: (the input is a list, so there is no order to choose) and attribution rows.
compact_utf8 = _enc(
    "compact_utf8",
    "wgrv-canon-e/v1",
    "EH",
    (
        "Nestor seal signatures: onescript nestor_seal.message == willow-mcp "
        "net_signer.seal_message (FROZEN by Nestor)",
        "willow-mcp session_signing._message (client-signed sessions, FROZEN wire contract)",
        "willow-mcp bound_receipt refs and canonical_signed_bytes; receipts._entry_hash",
        "willow-mcp attribution_ledger lines (dict, insertion order; each line is hashed raw)",
    ),
    lambda obj: json.dumps(obj, separators=(",", ":"), ensure_ascii=False),
)

#: E'. insertion order, compact, non-ASCII escaped.
compact_ascii = _enc(
    "compact_ascii",
    "wgrv-canon-e-ascii/v1",
    "E'",
    ("willow-mcp session_binder.call_sig (HMAC over a positional array)",),
    lambda obj: json.dumps(obj, separators=(",", ":")),
)

#: F. insertion order, default separators (", " and ": "), non-ASCII literal.
#: The caller fixes the key order by building the dict in it.
spaced_utf8 = _enc(
    "spaced_utf8",
    "wgrv-canon-f/v1",
    "F",
    (
        "the-table ledger_sink rows written into an ai-game-master campaign.db "
        "(byte-for-byte what its frozen bootstrap/verify_ledger.py canonical_row walks)",
    ),
    lambda obj: json.dumps(obj, ensure_ascii=False),
)

#: G (and I). sorted keys, default separators, non-ASCII escaped.
sorted_spaced_ascii = _enc(
    "sorted_spaced_ascii",
    "wgrv-canon-g/v1",
    "GI",
    (
        "willow-mcp governance_ledger frank rows; willows-grove grove_db._frank_ledger_append "
        "(the same chain, written from Grove); Grove u2u packet signing input",
        "safe-app-store sap_gate SigningLedger lines, aristarchus ledger lines, "
        "playgate disposition lines (each line is hashed raw by the next)",
    ),
    lambda obj: json.dumps(obj, sort_keys=True),
)


# -- the strict one, for NEW code only ---------------------------------------

_LONE = re.compile("[\ud800-\udfff]")


def _check(obj: Any, allow_floats: bool, path: str = "$") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonError(f"{path}: key {k!r} is not a string")
            if _LONE.search(k):
                raise CanonError(f"{path}: key holds a lone surrogate")
            _check(v, allow_floats, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check(v, allow_floats, f"{path}[{i}]")
    elif isinstance(obj, str):
        if _LONE.search(obj):
            raise CanonError(f"{path}: string holds a lone surrogate")
    elif isinstance(obj, float):
        if not allow_floats:
            raise CanonError(f"{path}: floats stay out of hashed rows ({obj!r})")


class _Strict:
    """A, minus what A lets through, for code that has no persisted rows to
    keep. It refuses: NaN and Infinity (``allow_nan=False``), a key that is not
    a string (``json.dumps`` would coerce it), a lone surrogate, and (unless
    ``allow_floats``) any float. ``loads`` also refuses a duplicate key."""

    name = "strict_sorted_compact_utf8"
    version = "wgrv-canon-strict/v1"
    families: tuple[str, ...] = ()
    persisted: tuple[str, ...] = ("new code only; nothing persisted yet",)

    def __call__(self, obj: Any, allow_floats: bool = False) -> str:
        _check(obj, allow_floats)
        try:
            return json.dumps(
                obj,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as e:
            raise CanonError(str(e)) from e

    def bytes(self, obj: Any, allow_floats: bool = False) -> bytes:
        return self(obj, allow_floats).encode("utf-8")

    def loads(self, text: str | bytes, allow_floats: bool = False) -> Any:
        def pairs(items):
            out = {}
            for k, v in items:
                if k in out:
                    raise CanonError(f"duplicate key {k!r}")
                out[k] = v
            return out

        def constant(name):
            raise CanonError(f"{name} is not allowed")

        try:
            obj = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
        except json.JSONDecodeError as e:
            raise CanonError(str(e)) from e
        _check(obj, allow_floats)
        return obj


strict_sorted_compact_utf8 = _Strict()

#: Every encoding, by name. The strict one is in it too.
ENCODINGS: dict[str, Any] = {
    e.name: e
    for e in (
        sorted_compact_utf8,
        sorted_compact_ascii,
        sorted_compact_ascii_default_str,
        compact_utf8,
        compact_ascii,
        spaced_utf8,
        sorted_spaced_ascii,
        strict_sorted_compact_utf8,
    )
}
BY_VERSION: dict[str, Any] = {e.version: e for e in ENCODINGS.values()}


def get(name_or_version: str):
    """An encoding by its name or its version id. ``KeyError`` names what was
    asked; there is no default encoding to fall back to."""
    try:
        return ENCODINGS.get(name_or_version) or BY_VERSION[name_or_version]
    except KeyError:
        raise KeyError(f"no canon encoding {name_or_version!r}") from None
