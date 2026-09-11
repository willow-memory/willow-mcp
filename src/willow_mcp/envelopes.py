"""Fail-closed constitutional envelope matching and citation-before-act."""
from __future__ import annotations

import fnmatch
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .governance_ledger import GovernanceLedger
from .paths import envelope_registry_path, syscall_table_path, trusted_read


def registry_path() -> Path:
    """Resolve the active envelope registry.

    ``WILLOW_ENVELOPE_REGISTRY`` always wins when set. Otherwise the default is
    ``<WILLOW_CHARTER_REPO>/envelopes/pre-approved.json`` when
    ``WILLOW_CHARTER_REPO`` is set, else
    ``$WILLOW_HOME/constitutional/pre-approved.json`` (see
    ``paths.envelope_registry_path``).
    """
    configured = os.environ.get("WILLOW_ENVELOPE_REGISTRY", "").strip()
    if configured:
        return Path(configured).expanduser()
    return envelope_registry_path()


def syscall_path() -> Path:
    configured = os.environ.get("WILLOW_SYSCALL_TABLE", "").strip()
    if configured:
        return Path(configured).expanduser()
    return registry_path().with_name(syscall_table_path().name)


def _load(path: Path) -> dict:
    # Authenticate the input's trust root before believing its bytes (§4.6): a
    # writable/symlinked registry or syscall table is a forged-envelope vector.
    trusted_read(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain an object")
    return data


def _deadline(value) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expires_at must be a timestamp/date or null")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _granted(grantee, actor: str) -> bool:
    return actor == grantee or (
        isinstance(grantee, list) and actor in grantee
    )


def usable_active_grants(registry: dict) -> list:
    """The active rows that could ever match an envelope check: dicts carrying a
    non-empty id. A registry with none is systemically empty — the #332
    condition — whether `active` is absent, null, an empty list, or present but
    all-malformed (a truncated write or bad merge). Shared by check()'s guard
    and diagnostic_summary's registry probe so the two never disagree on what
    'holds no grants' means."""
    return [
        row
        for row in registry.get("active") or []
        if isinstance(row, dict) and row.get("id")
    ]


def _no_grants_reason() -> str:
    """The loud, actionable message for a registry that loads but holds no
    active grants — the empty starter seeded when $WILLOW_HOME is relocated and
    the ratified registry is left behind (#332). Naming the resolved file turns
    a systemic misconfiguration into a one-line diagnosis instead of a generic
    per-envelope miss."""
    return (
        f"envelope registry holds no active grants: {registry_path()} — an "
        "unpopulated starter or a registry shadowed by a $WILLOW_HOME relocation. "
        "Issue grants (verb 11) or point WILLOW_ENVELOPE_REGISTRY at the ratified "
        "registry."
    )


def _bound_matches(grant, actual) -> bool:
    if isinstance(grant, list):
        if isinstance(actual, list):
            return all(
                any(fnmatch.fnmatch(str(item), str(pattern)) for pattern in grant)
                for item in actual
            )
        return any(
            fnmatch.fnmatch(str(actual), str(pattern)) for pattern in grant
        )
    return actual == grant


def governing_envelope_ids(verb: str, actor: str) -> list[str]:
    """The active grant id(s), if any, that cover `verb` for `actor` — the
    resolution step verb-level citation-before-act enforcement (#333) needs
    BEFORE it can cite anything: which envelope, if any, governs this call.

    Reads only the registry + trust root (no ledger, no Postgres), so an
    actor with no envelope programme configured for `verb` costs nothing
    beyond a file read — a verb-level gate built on this never turns an
    unenveloped install into a hard Postgres dependency (see
    server._enveloped_verb_gate's docstring).

    Zero matches means `verb` is unenveloped for `actor`: the caller's
    contract is to proceed exactly as before #333 — an envelope registry
    that grants nothing for this actor+verb pair is not a reason to refuse
    an act nothing ever governed. More than one match is a registry that
    cannot say which grant would be charged; the caller refuses that as
    ambiguous rather than guessing (the same reasoning EnvelopeAuthority
    .check() already applies to a duplicate envelope *id* — see its
    "envelope not active" / len(matches) != 1 guard — applied here to
    verb+actor instead of id).

    Raises whatever `_load` raises (OSError/PermissionError, ValueError,
    json.JSONDecodeError) on an unreadable/untrusted/malformed registry — it
    never conflates "the registry cannot be read" with "nothing governs this
    verb" by returning `[]` for both. What a caller does with that exception
    is its own call, not this function's: an explicit, caller-named
    envelope_id (`EnvelopeAuthority.check()`) fails closed on it, because
    refusing an unverifiable claim is correct there; an AMBIENT resolution
    that runs on every call to a verb-level-enforced tool for every actor
    (`server._enveloped_verb_gate`) instead treats it as "not governed" —
    see that function's docstring for why turning a missing/misconfigured
    registry into a hard failure for every install, enveloped or not, would
    be the wrong tradeoff there.

    A thin id-only projection of `governing_envelopes` — kept so existing
    callers that only ever needed the id list are unaffected by the fuller
    row shape a caller building an actionable ambiguity message needs."""
    return [row["id"] for row in governing_envelopes(verb, actor)]


def governing_envelopes(verb: str, actor: str) -> list[dict]:
    """Full active-grant rows (id, bounds, ...) governing `verb` for `actor` —
    the same resolution `governing_envelope_ids` performs, but returning the
    whole row instead of just its id.

    Exists so a caller building an EAMBIG message when more than one grant
    matches (dispatch-EAMBIG-blocker: the raw ambiguous-match refusal named
    no ids and no distinguishing detail, so a seat burned turns guessing —
    or, worse, revoked a valid grant trying to fix it) can name not just
    WHICH envelope ids matched but WHAT distinguishes them (their bounds),
    without re-deriving the match itself and risking it drifting from this
    one true resolution. `governing_envelope_ids` stays the id-only
    projection of this so both never disagree about what matched."""
    registry = _load(registry_path())
    return [
        dict(row)
        for row in usable_active_grants(registry)
        if row.get("verb") == verb
        and row.get("status") == "active"
        and not row.get("revoked")
        and _granted(row.get("grantee"), actor)
    ]


class EnvelopeAuthority:
    def __init__(self, ledger: GovernanceLedger):
        self.ledger = ledger

    def _registry(self) -> tuple[dict, dict[int, dict]]:
        registry = _load(registry_path())
        table = _load(syscall_path())
        verbs = {
            int(row["id"]): row
            for row in table.get("verbs") or []
            if isinstance(row, dict) and isinstance(row.get("id"), int)
        }
        return registry, verbs

    def check(
        self,
        envelope_id: str,
        *,
        actor: str,
        verb: str,
        call_args: dict,
        now: datetime | None = None,
    ) -> dict:
        try:
            registry, verbs = self._registry()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {"ok": False, "errno": "EAMBIG", "reason": str(exc)}
        # #332 (runtime guard): a registry that loads but carries no usable
        # active grant is refused LOUDLY and distinctly, before the per-envelope
        # miss below. A functioning system always holds at least the orchestrator
        # seat's own planting, so "no grants" is never steady state — it is a
        # fresh-but-unpopulated starter, the empty starter seeded at a relocated
        # $WILLOW_HOME shadowing the ratified registry (#332), or an `active`
        # list corrupted to all-malformed rows. Reported as the generic ENOENT
        # ("envelope not active") it read as one grant expiring and hid the
        # outage for ~60 hours; ENOGRANTS names the systemic cause and the file,
        # so it surfaces at the first check.
        active_grants = usable_active_grants(registry)
        if not active_grants:
            return {"ok": False, "errno": "ENOGRANTS", "reason": _no_grants_reason()}
        matches = [row for row in active_grants if row.get("id") == envelope_id]
        if len(matches) != 1:
            return {"ok": False, "errno": "ENOENT", "reason": "envelope not active"}
        envelope = matches[0]
        if envelope.get("issued_by") != "root":
            return {"ok": False, "errno": "EACCES", "reason": "issuer mismatch"}
        if envelope.get("revoked") or envelope.get("status") == "revoked":
            return {"ok": False, "errno": "EACCES", "reason": "envelope revoked"}
        if envelope.get("status") != "active":
            return {"ok": False, "errno": "ENOENT", "reason": "envelope inactive"}
        if not _granted(envelope.get("grantee"), actor):
            return {"ok": False, "errno": "EACCES", "reason": "grantee mismatch"}
        spec = verbs.get(envelope.get("verb_id"))
        if not spec or spec.get("verb") != envelope.get("verb") or verb != envelope.get("verb"):
            return {"ok": False, "errno": "EAMBIG", "reason": "verb mismatch"}
        bounds = envelope.get("bounds")
        if not isinstance(bounds, dict) or not isinstance(call_args, dict):
            return {"ok": False, "errno": "EAMBIG", "reason": "malformed bounds"}
        signature = set((spec.get("bounds") or {}).keys())
        # Registry v1.1 deliberately hoists metering fields from older verb rows.
        signature -= {"max_count", "expires_at"}
        if set(bounds) != signature:
            return {"ok": False, "errno": "EAMBIG", "reason": "bounds signature mismatch"}
        failed = sorted(set(call_args) - set(bounds)) + [
            key
            for key, granted in bounds.items()
            if key not in call_args or not _bound_matches(granted, call_args[key])
        ]
        if failed:
            return {"ok": False, "errno": "EAMBIG", "reason": "bounds mismatch", "fields": failed}
        try:
            expiry = _deadline(envelope.get("expires_at"))
        except ValueError as exc:
            return {"ok": False, "errno": "EAMBIG", "reason": str(exc)}
        if expiry and expiry <= (now or datetime.now(timezone.utc)):
            return {"ok": False, "errno": "EEXPIRED", "reason": "envelope expired"}
        maximum = envelope.get("max_count")
        if maximum is not None:
            if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
                return {"ok": False, "errno": "EAMBIG", "reason": "invalid max_count"}
            if envelope.get("use_count_source") != "frank":
                return {"ok": False, "errno": "EAMBIG", "reason": "untrusted meter"}
            used = self.ledger.citation_count(envelope_id)
            if used >= maximum:
                return {"ok": False, "errno": "EDQUOT", "used": used, "max_count": maximum}
        return {"ok": True, "envelope": envelope}

    def authorize_and_cite(
        self,
        envelope_id: str,
        *,
        actor: str,
        verb: str,
        call_args: dict,
        project: str,
        session: str,
    ) -> dict:
        result = self.check(
            envelope_id, actor=actor, verb=verb, call_args=call_args
        )
        outcome = "granted" if result.get("ok") else result.get("errno", "EAMBIG")
        content = {
            "envelope_id": envelope_id,
            "verb": verb,
            "call_args": call_args,
            "outcome": outcome,
            "session": session,
            "actor": actor,
        }
        maximum = (
            result.get("envelope", {}).get("max_count")
            if result.get("ok")
            else None
        )
        citation_id, final_outcome = self.ledger.append_citation(
            project,
            content,
            max_count=maximum,
        )
        if final_outcome == "EDQUOT" and result.get("ok"):
            result = {
                "ok": False,
                "errno": "EDQUOT",
                "reason": "envelope quota exhausted during atomic citation",
            }
        return {**result, "citation_id": citation_id, "cited_before_act": True}
