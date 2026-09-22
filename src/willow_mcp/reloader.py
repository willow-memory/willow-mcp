"""willow_mcp/reloader.py — the hand that restarts the broker onto a pull it
already brought home; the broker itself never touches the switch.

Decision ``e961aff8`` (operator, 2026-09-18; Nestor pair
``e961aff8-f722-4781-b924-55c0a489a085``, gap ``2451a10a19a3``):
:func:`unit_reload_executor.execute_unit_reload` refuses the broker's own
unit by design (``EPERM`` — a broker that can restart itself is a
self-grant). So the restart lives in a *separate* systemd ``--user`` unit,
``willow-mcp-reloader``, that owns exactly one act — ``systemctl --user
restart <broker unit>`` — and fires only when BOTH:

1. a FRANK ``git_pull`` receipt exists for the broker's own checkout (the
   request — written by :mod:`pull_executor` when the desk or the steward's
   sweep pulled a merge home), AND
2. a sealed Nestor decision names that receipt by its FRANK row id (the
   confirm — the operator's seal, made from a phone if need be).

Request and confirm sit on different principals and the reloader is a
third; that is the shape of brokered push (ruling 2026-09-10) pointed at
the broker's own process. The alternative — ``Restart=`` plus a graceful
self-exit after the pull — was considered and refused in the same seal:
the broker would then decide when it reloads itself.

The preflight is the executor's own, run here by a different principal:
the unit's ``ActiveEnterTimestamp`` must predate the receipt (``EALREADY``
otherwise — the unit is already on code no older than what was pulled,
which is also what makes a polling reloader idempotent: one restart, then
quiet), and the checkout's HEAD must still equal the receipt's ``after``
sha (``EDRIFT`` otherwise — the tree moved again since the pull, and the
seal named *that* receipt, not whatever is there now).

What the reloader does NOT do: propose the decision. The seal is the
operator's; the draft the operator seals is the desk's (``decision_propose``
naming the receipt id). A reloader that wrote its own confirm would be the
self-grant again, one process removed. When the receipt is there and the
seal is not, the reloader says so (``ENOSEAL``) and waits.

Three states, never collapsed (INVARIANTS §1): the Nestor database
unreadable is ``unreachable``, no sealed pair naming the receipt is
``empty``, a match is ``populated``. Only the act leaves FRANK ink — a
``unit_reload`` receipt with ``actor=willow-mcp-reloader`` citing the pull
receipt, the sealing pair and its verifier; refusals go to the journal.

Follow-on (decision ``1bd6fd29``, 2026-09-22, "operations are Willow's… the
operator's only keyboard act is the seal"): the SAME shape now also covers
a change to the broker's env — read the way the unit actually carries it
(:func:`env_fingerprint.resolve_env_source`: ``EnvironmentFile=`` when the
unit has one, its ``Environment=`` lines otherwise, a labeled fallback
file path only as a last resort) — a rotated provider key, a new
``WILLOW_PGP_FINGERPRINT``, an added ``WILLOW_MCP_APPS_ROOT``. Today those
have no FRANK receipt at all, so the broker runs on stale env until someone
types the restart by hand; that keyboard act is what this follow-on
removes. Request/confirm/act is identical to the pull path — a FRANK
``env_changed`` receipt (:mod:`env_fingerprint` computes it: key NAMES and
ONE SHA-256 digest, never a value, never anything keyed per value), a
sealed decision naming that receipt's row id, then the one act — with its
own preflight (:func:`check_env`) and its own errno for "nothing has
changed since the broker's own startup record" or "no state file to
compare against" (an older broker). A pull receipt and an env receipt may
both be waiting in the same tick; :func:`run_once` restarts once and cites
whichever of the two were sealed — but ONLY when every trigger that is
actually pending (open) is sealed (Loki F4): a sealed pull with an
unsealed, still-open env diff refuses the whole restart rather than
loading the unsealed env as a side effect of the pull-triggered restart.
See :mod:`env_fingerprint` for why a value, or anything derived per-key
from one, never rides in the receipt, the journal, or this process's own
persisted state.

Rework (Loki audit E79FCAE7, 2026-09-22): F1 (a STALE env_changed receipt —
the file moved again before any seal — was reused forever instead of
superseded, wedging both EDRIFT and EALREADY into permanent refusals with
nothing new in the journal; see :func:`_env_receipt_state`); F2 (a per-key
value digest in the state file was exactly the rainbow-table oracle the
brief forbade; gone, see :mod:`env_fingerprint`); F3 (the fallback env FILE
was fingerprinted and called "the unit's env" even when the live unit
carries no ``EnvironmentFile=`` at all — this fleet's actually doesn't; see
:func:`env_fingerprint.resolve_env_source`); F4 (a restart could apply a
sealed trigger while a second, unsealed trigger was also open, silently
carrying the unsealed one along for the ride; see :func:`_is_open_trigger`);
F5 (:func:`find_sealing_decision` accepted any non-empty ``seal_sig``
string without ever calling :func:`net_signer.verify_seal` — a forged
verifier/signature confirmed a restart exactly like a real seal; fixed for
both triggers, since the pull path shared the same function).

Rework 2 (Loki audit 747B0C04, 2026-09-22): R1 (F5's ring fix switched the
DEPLOYED reloader off — ``bundle/deploy/willow-mcp-reloader.service.template``
set no ``WILLOW_KEYRING``, so every seal read ``ESEALS``, silently, forever;
the template now carries a ``WILLOW_KEYRING`` line naming the PUBLIC ring
(:func:`net_signer.default_ring_path`, normally
``$WILLOW_HOME/config/verifiers.public.json``) — never the private
``config/verifiers.json``, because this oneshot only ever verifies, never
signs, and has no legitimate use for a private half; the live installed unit
must still be re-rendered — ``unit_install_execute``, row 17 — a desk act,
this rework only fixes the template); R2 (a source FLAP — the baseline
recorded via one ``env_source``, a tick reading a different one because
``systemctl`` hiccuped — was diffed as if comparable, filing a receipt whose
``keys_removed`` was every key the real source had; a source mismatch is now
``EUNREACH``, not a diff); R3 (``keys_changed`` naming every common key
"changed" was itself a false, if safe, claim; replaced with exact
``keys_added``/``keys_removed`` plus one ``values_changed`` boolean that
names no key — see :func:`env_fingerprint.diff_keys`); R4
(:func:`_is_open_trigger` now treats the env side's ``EUNREACH`` as open too,
so a corrupt env state file blocks a sealed pull's restart instead of
silently letting it through onto unaudited env); F6 (a missing env file —
populated to absent — is now its own refusal, ``EMISSING``, never filed as a
diff naming ``'<empty>'`` as the target); F7 (partial: :func:`server._diag_env_stale`
now names ``unit``/``describes`` so the desk can tell whose baseline it is
reading; ``record_startup`` failure is still indistinguishable from an older
broker — left open, gap ``ce9c914985d9``, see :func:`server._diag_env_stale`);
R5 (``EPARTIAL`` now reports ``act=False`` — a waiting state, not a failure —
so ``tick`` exits 0 while waiting on the second seal instead of reddening the
journal every poll).

Rework 3 (Loki audit BE590C53, 2026-09-22, narrow): T1 (blocking — rework 2's
own fix was unreachable in practice: :func:`net_signer.default_ring_path`
reads ``WILLOW_NET_SIGNER_RING`` from the RENDERER's own environment, which on
a real box is set only inside the net-signer's installed system unit, never
the desk/broker's — a row-17 render from the desk baked in a
``WILLOW_KEYRING`` naming a file that was never staged. :func:`_resolve_keyring_path`
now reads the net-signer unit's OWN ``Environment=`` line — the same fact its
installer already baked in, not a second guess — falling back to
``default_ring_path()`` only when that unit cannot be read at all; either way,
:func:`render_units` now refuses to render when the resolved path is not an
existing file, naming the path and how it was resolved); T2 (``get_keyring()``
raising ``KeyringError`` for a configured-but-unusable ring was uncaught —
:func:`find_sealing_decision` now catches it and maps it to ``unreachable``,
the same three-state discipline an unset ring already got).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import env_fingerprint as envfp
from . import paths
from . import unit_reload_executor as urx

logger = logging.getLogger(__name__)

#: The principal on the FRANK receipt. Not an MCP app_id — no manifest, no
#: tool surface — but a name the ledger can tell apart from the broker
#: (``willow``) that wrote the pull receipt and the operator who sealed it.
ACTOR = "willow-mcp-reloader"

#: The env-trigger's own FRANK event type, sibling of :data:`unit_reload_executor.PULL_EVENT`.
ENV_EVENT = "env_changed"

#: The broker unit this fleet actually runs (`scripts/willow-serve install`
#: writes it); the bare ``willow-mcp.service`` is the other spelling
#: :data:`unit_reload_executor._BROKER_UNIT_SUFFIXES` refuses.
DEFAULT_UNIT = "willow-mcp-serve.service"
DEFAULT_REPO = "willow-memory/willow-mcp"
#: Polling cadence for the timer; a pull receipt is minutes old before
#: anyone can have sealed a decision naming it.
DEFAULT_INTERVAL = "60s"

UNIT_PREFIX = "willow-mcp-reloader"
SERVICE_UNIT = f"{UNIT_PREFIX}.service"
TIMER_UNIT = f"{UNIT_PREFIX}.timer"

_ENV_UNIT = "WILLOW_RELOADER_UNIT"
_ENV_CHECKOUT = "WILLOW_RELOADER_CHECKOUT"
_ENV_REPO = "WILLOW_RELOADER_REPO"

_SYSTEMCTL_TIMEOUT_S = 15



# ── configuration ─────────────────────────────────────────────────────────────

def default_checkout() -> Optional[Path]:
    """The broker's own checkout: ``WILLOW_RELOADER_CHECKOUT`` if set, else
    the source tree this module was imported from when that tree is a git
    checkout (the editable install the served broker runs on). ``None`` when
    neither holds — a wheel install has no tree to pull."""
    override = os.environ.get(_ENV_CHECKOUT, "").strip()
    if override:
        return Path(override).expanduser()
    tree = Path(__file__).resolve().parents[2]
    if (tree / ".git").exists():
        return tree
    return None


@dataclass(frozen=True)
class ReloaderConfig:
    unit: str
    checkout: Optional[Path]
    repo: str
    nestor_db: Path


def default_config() -> ReloaderConfig:
    from .seal_handler import _nestor_db_path

    return ReloaderConfig(
        unit=os.environ.get(_ENV_UNIT, DEFAULT_UNIT).strip() or DEFAULT_UNIT,
        checkout=default_checkout(),
        repo=os.environ.get(_ENV_REPO, DEFAULT_REPO).strip() or DEFAULT_REPO,
        nestor_db=_nestor_db_path(),
    )


# ── the confirm: a sealed decision naming the receipt ─────────────────────────

def _ring_from_keyring(kr) -> dict[str, dict]:
    """The ``verify_seal`` ring shape (``{name: {key, kind, revoked_at,
    compromised}}``), built from the process's OWN keyring — the same shape
    :func:`manifest_grant_executor._ring_from_keyring` builds, duplicated
    here (a few lines) rather than imported, so this module carries no
    dependency on a file another packet owns."""
    return {
        e.name: {"key": e.key, "kind": e.kind, "revoked_at": e.revoked_at, "compromised": e.compromised}
        for e in kr.entries()
    }


def find_sealing_decision(receipt_id: str, db_path: Path) -> dict:
    """Look in Nestor's own database for a sealed ``decision`` pair whose
    text names ``receipt_id`` AND whose ``seal_sig`` actually verifies.

    Returns ``{"state": "populated", "pair_id", "verifier", "sealed_at"}``,
    ``{"state": "empty"}`` when no sealed pair names it (or none of the
    candidates that do carries a signature that verifies), or
    ``{"state": "unreachable", "cause": ...}`` when the database or the
    verifier ring cannot be read — three states, because "no seal" and
    "cannot see the seals" call for different next moves (wait vs. fix the
    path) and a reloader that reported both as "no" would restart nothing
    forever, silently.

    Rework (Loki audit E79FCAE7, F5, gap 3df4bbb26cf0): this used to accept
    ANY row with ``status='sealed'`` and a non-empty ``seal_sig`` string —
    it never called :func:`net_signer.verify_seal`, so a row naming
    verifier ``"nobody"`` and ``seal_sig="garbage"`` confirmed a restart
    exactly as well as a real seal. This now loads the same per-verifier
    keyring :func:`manifest_grant_executor._bind_to_seal` checks against
    and calls :func:`net_signer.verify_seal` on every text-matching
    candidate (newest first), returning the first that verifies. A
    revoked/compromised/unknown verifier or a bad signature is treated
    exactly like "no seal names it" — ``empty``, not an act. No keyring
    configured at all is ``unreachable`` (``ESEALS``): a seal cannot be
    trusted sight-unseen just because nothing was there to check it
    against. This is the SAME function the pull path already used, so this
    fix applies to both triggers, not only the env one.
    """
    rid = (receipt_id or "").strip()
    if not rid:
        return {"state": "empty"}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}", "path": str(db_path)}
    try:
        rows = conn.execute(
            "SELECT id, source_norm, target_text, verifier, seal_sig, created_at FROM tm_pairs "
            "WHERE source_lang = 'decision' AND status = 'sealed' "
            "AND seal_sig != '' AND superseded_by = '' "
            "AND (instr(source_text, ?) > 0 OR instr(target_text, ?) > 0) "
            "ORDER BY created_at DESC",
            (rid, rid),
        ).fetchall()
    except sqlite3.Error as exc:
        return {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}", "path": str(db_path)}
    finally:
        conn.close()
    if not rows:
        return {"state": "empty"}

    from . import keyring as _keyring
    from . import net_signer

    # T2 (Loki BE590C53): get_keyring() RAISES KeyringError for a
    # WILLOW_KEYRING that names a path with nothing readable at it (a
    # missing file, malformed JSON, ...) — it does not return None the way
    # "unset" does. Left uncaught, that traceback propagated out of
    # main() on the first tick with a pending receipt: exactly the
    # three-state collapse this function exists to prevent. Both "no ring
    # configured" and "a ring is configured but unusable" are the SAME
    # verdict from a caller's point of view — unreachable, fix the path —
    # so both land here.
    try:
        ring_kr = _keyring.get_keyring()
    except _keyring.KeyringError as exc:
        return {"state": "unreachable",
                "cause": f"WILLOW_KEYRING={_keyring.keyring_path()!r} is configured but could not "
                         f"be loaded: {exc}",
                "path": str(db_path)}
    if ring_kr is None:
        return {"state": "unreachable",
                "cause": "no keyring configured (WILLOW_KEYRING) — a seal cannot be verified "
                         "without a ring to verify it against",
                "path": str(db_path)}
    ring = _ring_from_keyring(ring_kr)

    for pair_id, source_norm, target_text, verifier, seal_sig, created_at in rows:
        sealed = {"source_norm": source_norm, "target_text": target_text,
                  "verifier": verifier, "seal_sig": seal_sig, "created_at": created_at}
        # max_age_s=None: a restart confirm is a standing governance decision
        # (like manifest.grant's), not a one-shot task lease — it does not go
        # stale on a calendar just because nobody happened to act on it
        # within net_authority.SEAL_MAX_AGE_S. Revocation is supersession,
        # already enforced by the superseded_by='' filter above.
        ok, _reason, _field = net_signer.verify_seal(sealed, ring, max_age_s=None)
        if ok:
            return {"state": "populated", "pair_id": pair_id, "verifier": verifier,
                    "sealed_at": created_at, "count": len(rows)}
    return {"state": "empty"}


# ── the check ─────────────────────────────────────────────────────────────────

def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "act": False, "error": errno, "reason": reason, **extra}


# ── the env trigger: detect / request / confirm / act ─────────────────────────

def _mint_env_receipt(ledger, *, unit: str, env_path: str, recorded: dict, live: dict,
                      supersedes: Optional[str] = None) -> dict:
    """Write ONE fresh ``env_changed`` receipt against the CURRENT live
    fingerprint and return it in the same ``{"id", "content", "created_at"}``
    shape :meth:`GovernanceLedger.latest_event` returns — so the caller
    never has to special-case "just minted" vs. "read back from the
    ledger." ``supersedes`` names the row this one replaces (F1: a STALE
    receipt is superseded, not silently reused)."""
    detected_at = datetime.now(timezone.utc).isoformat()
    content = {
        "actor": ACTOR, "unit": unit, "env_path": env_path,
        "fingerprint_before": envfp.summary(recorded), "fingerprint_after": envfp.summary(live),
        "env_source": live.get("env_source"), "detected_at": detected_at,
        **envfp.diff_keys(recorded, live),
    }
    if supersedes:
        content["supersedes"] = supersedes
    receipt_id = ledger.append("willow-mcp", ENV_EVENT, content)
    return {"id": receipt_id, "content": content, "created_at": detected_at}


def _env_receipt_state(ledger, receipt: Optional[dict], *, live_summary: str) -> str:
    """Classify the LATEST ``env_changed`` receipt found for this unit/path
    against the file's CURRENT fingerprint. Four states (Loki F1):

    ``none`` — no receipt at all.
    ``consumed`` — a ``unit_reload`` receipt already cites this one's id;
    its job is done regardless of what the file holds now.
    ``stale`` — unconsumed, but its ``fingerprint_after`` no longer matches
    the current live fingerprint: the file moved again since it was
    written. NOT open — reusing it (the original bug) means the confirm
    and act preflight run forever against a target the file has already
    left behind.
    ``current`` — unconsumed and still accurate: the one to reuse.
    """
    if receipt is None:
        return "none"
    rid = receipt.get("id")
    if rid and ledger.latest_event(urx.EVENT, match={"env_receipt_id": rid}) is not None:
        return "consumed"
    if receipt["content"].get("fingerprint_after") != live_summary:
        return "stale"
    return "current"


def check_env(config: ReloaderConfig, *, ledger, runner: Optional[Callable] = None) -> dict:
    """Decide whether the restart is due because the broker's env has moved
    out from under it. Never restarts, never writes a value.

    Detect: :func:`env_fingerprint.read_state` (what the running broker
    loaded) against a fresh :func:`env_fingerprint.resolve_env_source` +
    :func:`env_fingerprint.fingerprint_source` read of what its unit
    carries RIGHT NOW (F3 — a file the unit does not load is never
    fingerprinted and called its env; ``Environment=`` lines are read
    directly when there is no ``EnvironmentFile=``). ``ESTATEEMPTY`` — no
    startup record at all: an older broker that predates this state file,
    or one that has not restarted since it landed; nothing to compare
    against, so this does nothing rather than guess. ``EUNREACH`` — the
    state file or the live read exists but could not be completed. No
    diff — ``ok=True, act=False`` quietly, the same "nothing due" shape a
    pull check returns when there is no receipt to act on.

    Request: a diff mints (or, when the latest receipt is still current,
    reuses — idempotently) a FRANK ``env_changed`` receipt naming only key
    NAMES, the two digests, and ``env_source``. A STALE latest receipt
    (Loki F1: the file moved again before anyone sealed it) is
    SUPERSEDED — a fresh receipt is minted citing it — rather than reused,
    so the confirm/act preflight below is always run against a target that
    still matches the file. A CONSUMED latest receipt (already restarted
    past) is left alone and a fresh one is minted for whatever new diff
    exists now, same as ``none``.

    Confirm: :func:`find_sealing_decision` against the CURRENT receipt's
    row id — ``ENOSEAL`` when nothing sealed names it yet.

    Act preflight: the unit must not already be active since after the
    receipt was written (``EALREADY`` — a previous tick already restarted
    onto it), and the live fingerprint must still equal that receipt's
    ``fingerprint_after`` at the moment of the check. Unlike the request
    step above, THIS drift is checked against a receipt that IS sealed —
    silently superseding a sealed receipt would let the reloader decide,
    on its own, what the operator's seal actually confirmed. So a
    sealed-but-now-stale receipt is NOT silently replaced here: it mints a
    fresh successor receipt for the NEXT tick to pick up (so the desk has
    something current to propose a new seal for) but returns ``EDRIFT``
    for THIS one, naming both the stale (sealed) receipt and its
    successor — never a silent forever-refusal with nothing new in the
    journal (Loki F1's second complaint).

    Every return carries ``request_state`` — ``none``/``fresh``/
    ``superseded_stale``/``superseded_consumed``/``current`` — naming which
    of the above happened, so a tick that found nothing actionable still
    says which state it found.
    """
    unit = (config.unit or "").strip()
    if not urx.is_broker_unit(unit):
        return _refuse("EINVAL", f"{unit!r} is not the broker's unit — reload it "
                                 f"through unit_reload_execute under a unit.reload envelope")
    if ledger is None:
        return _refuse("EAMBIG", "no governance ledger: a restart that cannot be matched to an "
                                 "env_changed receipt is not performed")

    state = envfp.read_state()
    if state["state"] == "unreachable":
        return _refuse("EUNREACH", f"env-fingerprint state file unreadable: {state.get('cause')}",
                       request_state="none")
    if state["state"] == "empty":
        return _refuse("ESTATEEMPTY",
                       "no env-fingerprint state file from the running broker — an older "
                       "broker that predates this, or one that has not started since; "
                       "nothing to compare the env against", request_state="none")
    recorded = state["env_fingerprint"]

    src = envfp.resolve_env_source(unit, runner=runner)
    live = envfp.fingerprint_source(src)
    if live["state"] == "unreachable":
        return _refuse("EUNREACH", f"unit env ({live.get('env_source')}) unreadable: {live.get('cause')}",
                       request_state="none")

    # R2 (Loki 747B0C04): a source FLAP — the baseline was recorded via one
    # env_source (e.g. unit_environment) and this read resolved a DIFFERENT
    # one (e.g. fallback, because systemctl hiccuped) — is not a diff. Two
    # readings from two different sources are not comparable; diffing them
    # anyway files a receipt whose keys_removed is every key the baseline
    # source had and keys_added is every key the fallback source has. Refuse
    # as unreachable instead — no receipt, nothing in the journal but a
    # refusal, exactly like a read that failed outright.
    if recorded.get("env_source") != live.get("env_source"):
        return _refuse("EUNREACH",
                       f"running-broker baseline was recorded via env_source="
                       f"{recorded.get('env_source')!r} but this read resolved env_source="
                       f"{live.get('env_source')!r} — not comparable (a source flap, e.g. "
                       f"systemctl briefly unreachable), not a diff",
                       request_state="none")

    if envfp.fingerprints_equal(recorded, live):
        return {"ok": True, "act": False, "error": None, "reason": "env unchanged",
                "unit": unit, "env_source": live.get("env_source"), "env_ref": live.get("env_ref"),
                "request_state": "none"}

    # F6 (E79FCAE7, still open at de3462a): the env file going from populated
    # to MISSING is a state change, not a diff to request a restart onto —
    # INVARIANTS §1, "empty" is its own state. (Only reachable for the
    # environment_file/fallback sources; unit_environment has no file to
    # remove.) Refuse rather than file a receipt naming '<empty>' as the
    # target — restarting onto a genuinely absent env is not something this
    # trigger should ever request on its own.
    if live["state"] != "populated":
        return _refuse("EMISSING",
                       f"the unit's env ({live.get('env_source')}) is now {live['state']} — a state "
                       f"change (the file was deleted or moved), not a diff to request a restart "
                       f"onto; fix the env source, or if this is intentional, restart the broker by "
                       f"hand so its own startup record reflects the new baseline",
                       request_state="none")

    env_path = live.get("env_ref") or ""
    live_summary = envfp.summary(live)
    existing = ledger.latest_event(ENV_EVENT, match={"unit": unit, "env_path": env_path})
    rstate = _env_receipt_state(ledger, existing, live_summary=live_summary)

    if rstate == "current":
        receipt = existing
        request_state = "current"
    elif rstate == "stale":
        existing_id = existing.get("id")
        seal = find_sealing_decision(existing_id, config.nestor_db) if existing_id else {"state": "empty"}
        if seal["state"] == "unreachable":
            return _refuse("ESEALS", f"seal store unreachable: {seal.get('cause')}",
                           receipt_id=existing_id, path=seal.get("path"), request_state="stale")
        successor = _mint_env_receipt(ledger, unit=unit, env_path=env_path, recorded=recorded,
                                      live=live, supersedes=existing_id)
        if seal["state"] == "populated":
            # Sealed but the file has moved on: refuse THIS tick (the seal
            # names the stale receipt, not the current file) while leaving
            # a fresh, unsealed successor in the journal for the next one.
            return _refuse("EDRIFT",
                           f"env_changed receipt {existing_id} was sealed but the unit's env has "
                           f"moved again since — the seal names that receipt, not whatever it "
                           f"holds now; a successor receipt {successor['id']} is waiting for a new seal",
                           receipt_id=existing_id, receipt=existing["content"],
                           successor_receipt_id=successor["id"], request_state="superseded_stale")
        receipt = successor
        request_state = "superseded_stale"
    else:  # "none" or "consumed"
        receipt = _mint_env_receipt(ledger, unit=unit, env_path=env_path, recorded=recorded, live=live)
        request_state = "fresh" if rstate == "none" else "superseded_consumed"

    receipt_id = receipt.get("id")
    if not receipt_id:
        return _refuse("EAMBIG", "the env_changed receipt carries no row id; a seal cannot name it",
                       request_state=request_state)
    content = receipt["content"]

    state_unit = urx.show_unit(unit, runner=runner)
    if not state_unit.get("ok"):
        return _refuse("EUNREACH", f"unit state unreachable: {state_unit.get('cause')}",
                       cause=state_unit.get("cause"), detail=state_unit.get("detail"),
                       receipt_id=receipt_id, request_state=request_state)

    active_enter = urx._parse_systemd_timestamp(state_unit.get("ActiveEnterTimestamp"))
    receipt_at = urx._as_utc(receipt.get("created_at"))
    if active_enter is not None and receipt_at is not None and active_enter >= receipt_at:
        return _refuse("EALREADY",
                       f"{unit} has been active since {state_unit.get('ActiveEnterTimestamp')!r}, "
                       f"which is no older than env_changed receipt {receipt_id} — already restarted onto it",
                       receipt_id=receipt_id, receipt=content, request_state=request_state)

    live_again = envfp.fingerprint_source(envfp.resolve_env_source(unit, runner=runner))
    if live_again["state"] == "unreachable":
        return _refuse("EUNREACH", f"unit env unreadable: {live_again.get('cause')}",
                       receipt_id=receipt_id, request_state=request_state)
    if envfp.summary(live_again) != content.get("fingerprint_after"):
        return _refuse("EDRIFT",
                       f"the unit's env has moved again since env_changed receipt {receipt_id} was "
                       f"written — the seal names that receipt, not whatever it holds now",
                       receipt_id=receipt_id, receipt=content, request_state=request_state)

    seal = find_sealing_decision(receipt_id, config.nestor_db)
    if seal["state"] == "unreachable":
        return _refuse("ESEALS", f"seal store unreachable: {seal.get('cause')}",
                       receipt_id=receipt_id, path=seal.get("path"), request_state=request_state)
    if seal["state"] == "empty":
        added, removed = content.get("keys_added") or [], content.get("keys_removed") or []
        summary_bits = [b for b in (
            f"+{','.join(added)}" if added else "",
            f"-{','.join(removed)}" if removed else "",
            "values changed" if content.get("values_changed") and not (added or removed) else "",
        ) if b]
        return _refuse("ENOSEAL",
                       f"env_changed receipt {receipt_id} ({'; '.join(summary_bits) or 'no key names changed'}) "
                       f"is waiting for a sealed decision that names it — the desk proposes, the operator seals",
                       receipt_id=receipt_id, receipt=content, request_state=request_state)

    return {"ok": True, "act": True, "unit": unit, "env_path": env_path,
            "receipt_id": receipt_id, "receipt": content, "seal": seal, "state_before": state_unit,
            "request_state": request_state}


#: How many unconsumed git_pull receipts at the checkout's current HEAD
#: `check()` will examine looking for a sealed one. A sha collision this
#: deep would mean dozens of pulls landing back at the exact same commit
#: (reverts and reapplies) without a single one ever being consumed —
#: bounded defensively, not because the ordinary case gets anywhere near it.
_PULL_SCAN_LIMIT = 20


def _pull_receipts_at(ledger, *, repo: str, checkout: str, after: str,
                       limit: int = _PULL_SCAN_LIMIT) -> list[dict]:
    """Every ``git_pull`` receipt for ``repo``+``checkout`` whose ``after``
    equals ``after`` (the checkout's CURRENT HEAD), newest first, capped at
    ``limit`` rows examined.

    Gap ``3df997ffe92b``: the seal names a receipt id — the operator's
    confirmation of THAT sha. Matching against "whichever git_pull row
    happens to be newest right now" instead of "a receipt describing the
    sha the seal actually confirmed" meant a later, unrelated row (even one
    at the SAME sha, from a second pull that also landed there) could
    silently take over the match. This collects every receipt at the
    confirmed sha instead of picking one by row order.
    """
    return ledger.all_events(urx.PULL_EVENT, match={"repo": repo, "checkout": checkout, "after": after})[:limit]


def _is_consumed(ledger, receipt_id: str) -> bool:
    """A ``unit_reload`` receipt already cites ``receipt_id`` via
    ``pull_receipt_id`` — a prior restart already acted on it. Consumed
    receipts are not re-offered to a fresh seal search (a stray later seal
    naming an already-spent receipt should not fire a second restart)."""
    return bool(receipt_id) and ledger.latest_event(urx.EVENT, match={"pull_receipt_id": receipt_id}) is not None


def _no_match_refusal(ledger, *, repo: str, checkout: str, head: str) -> dict:
    """No unconsumed ``git_pull`` receipt names the checkout's current HEAD.
    ``ENORECEIPT`` when nothing has ever been pulled here at all;
    ``EDRIFT`` naming the newest receipt otherwise — the tree moved past
    every receipt on file, so the seal (if any) names a sha that is no
    longer HEAD."""
    latest = ledger.latest_event(urx.PULL_EVENT, match={"repo": repo, "checkout": checkout})
    if latest is None:
        return _refuse("ENORECEIPT", f"no git_pull receipt for repo={repo!r} checkout={checkout!r}")
    latest_id = latest.get("id")
    latest_content = latest.get("content") or {}
    latest_after = latest_content.get("after")
    return _refuse("EDRIFT",
                   f"{checkout} HEAD is {head!r} but the newest git_pull receipt {latest_id}'s "
                   f"after-sha is {latest_after!r} — the tree moved again since the pull; the seal "
                   f"names the receipt, not the tree",
                   receipt_id=latest_id, receipt=latest_content, head=head)


def check(config: ReloaderConfig, *, ledger, runner: Optional[Callable] = None) -> dict:
    """Decide whether the restart is due. Never restarts anything.

    Returns ``{"ok": True, "act": True, ...}`` with the receipt, HEAD, seal
    and unit state when every condition holds; otherwise ``ok=False`` with
    the executor's errnos (``EINVAL``, ``EUNREACH``, ``ENORECEIPT``,
    ``EALREADY``, ``EDRIFT``) plus the reloader's own ``ENOSEAL`` (receipt
    present, no sealed decision names it — the waiting state) and
    ``ESEALS`` (the seal store cannot be read).

    Fix (gap ``3df997ffe92b``, 2026-09-22): matches by WHAT was confirmed,
    not by row. Every ``git_pull`` receipt whose ``after`` equals the
    checkout's current HEAD is collected; EALREADY is decided against the
    newest of them (consumed or not — a restart already on that sha stays
    quiet regardless of a stray later row at the same sha). If not yet
    applied, every receipt at that sha NOT already cited by a prior
    ``unit_reload`` (``pull_receipt_id``) is a live candidate, tried against
    :func:`find_sealing_decision` newest first until one verifies. A no-op
    pull no longer mints a receipt at all (see :mod:`pull_executor`), but
    even so a later real pull that lands back at the SAME sha (a revert and
    reapply) still must not displace an already-sealed receipt at that sha
    — scanning every unconsumed candidate rather than trusting "newest" is
    what survives that.
    """
    unit = (config.unit or "").strip()
    if not urx.is_broker_unit(unit):
        # Inverse of the executor's EPERM: this unit exists ONLY for the
        # broker. Anything else is verb 15's job, under an envelope.
        return _refuse("EINVAL", f"{unit!r} is not the broker's unit — reload it "
                                 f"through unit_reload_execute under a unit.reload envelope")
    if config.checkout is None:
        return _refuse("EINVAL", f"no broker checkout: set {_ENV_CHECKOUT} or run from an editable install")
    path = Path(config.checkout).expanduser()
    if not (path / ".git").exists():
        return _refuse("EINVAL", f"{path} is not a git checkout (no .git)")
    if ledger is None:
        return _refuse("EAMBIG", "no governance ledger: a restart that cannot be matched to a pull receipt is not performed")

    # Cheap, ledger-only existence/id checks first — no runner call yet, so
    # ENORECEIPT and "the receipt can't be named" still return before
    # touching git or systemctl, same as every caller of this function has
    # relied on since the original build.
    any_receipt = ledger.latest_event(urx.PULL_EVENT, match={"repo": config.repo, "checkout": str(path)})
    if any_receipt is None:
        return _refuse("ENORECEIPT", f"no git_pull receipt for repo={config.repo!r} checkout={str(path)!r}")
    if not any_receipt.get("id"):
        return _refuse("EAMBIG", "the pull receipt carries no row id; a seal cannot name it")

    head = urx._git(path, "rev-parse", "HEAD", runner=runner)
    if head.returncode != 0:
        return _refuse("EINVAL", f"could not read HEAD of {path}")
    current_head = (head.stdout or "").strip()

    at_head = _pull_receipts_at(ledger, repo=config.repo, checkout=str(path), after=current_head)
    if not at_head:
        return _no_match_refusal(ledger, repo=config.repo, checkout=str(path), head=current_head)

    state = urx.show_unit(unit, runner=runner)
    if not state.get("ok"):
        return _refuse("EUNREACH", f"unit state unreachable: {state.get('cause')}",
                       cause=state.get("cause"), detail=state.get("detail"),
                       receipt_id=at_head[0].get("id"), head=current_head)

    active_enter = urx._parse_systemd_timestamp(state.get("ActiveEnterTimestamp"))

    # EALREADY is decided against the NEWEST receipt at this sha, consumed
    # or not: if the unit has been active since no older than that pull, the
    # tree's current sha is already served — a stray unsealed OR
    # already-consumed row at the same sha changes nothing about that fact.
    newest = at_head[0]
    newest_at = urx._as_utc(newest.get("created_at"))
    if active_enter is not None and newest_at is not None and active_enter >= newest_at:
        return _refuse("EALREADY",
                       f"{unit} has been active since {state.get('ActiveEnterTimestamp')!r}, "
                       f"which is no older than pull receipt {newest.get('id')} — already on that code",
                       receipt_id=newest.get("id"), receipt=newest.get("content"), head=current_head)

    # Not yet applied. Only receipts no restart has already consumed are
    # live candidates for a NEW seal to act on — try each, newest first,
    # until one verifies. Journal honesty (Loki-shaped ask): name every
    # candidate examined so the desk can see the shape without reading raw
    # ledger rows.
    candidates = [r for r in at_head if not _is_consumed(ledger, r.get("id"))]
    if not candidates:
        # Every receipt at this sha has already been consumed by an earlier
        # restart, yet the unit's own timestamp does not (yet) reflect it —
        # a fake/observation lag, not a new fact to wait on.
        return _refuse("EALREADY",
                       f"every pull receipt at HEAD {current_head!r} for repo={config.repo!r} has "
                       f"already been consumed by a prior restart ({[r.get('id') for r in at_head]})",
                       receipt_id=newest.get("id"), head=current_head)

    enoseal_ids = []
    for receipt in candidates:
        receipt_id = receipt.get("id")
        if not receipt_id:
            continue
        content = receipt["content"]
        seal = find_sealing_decision(receipt_id, config.nestor_db)
        if seal["state"] == "unreachable":
            return _refuse("ESEALS", f"seal store unreachable: {seal.get('cause')}",
                           receipt_id=receipt_id, path=seal.get("path"), head=current_head)
        if seal["state"] == "empty":
            enoseal_ids.append(receipt_id)
            continue
        return {"ok": True, "act": True, "unit": unit, "repo": config.repo, "checkout": str(path),
                "receipt_id": receipt_id, "receipt": content, "head": current_head,
                "seal": seal, "state_before": state}

    # Every unconsumed candidate at this sha was examined (none had an id
    # missing without being skipped above, or the loop would have returned
    # already) — none carries a sealed decision.
    return _refuse("ENOSEAL",
                   f"{len(candidates)} unconsumed git_pull receipt(s) at HEAD {current_head!r} for "
                   f"repo={config.repo!r} — waiting for a sealed decision that names one of "
                   f"{enoseal_ids} — the desk proposes, the operator seals",
                   receipt_id=enoseal_ids[0] if enoseal_ids else candidates[0].get("id"),
                   candidates=[c.get("id") for c in candidates], head=current_head)


# ── the act ───────────────────────────────────────────────────────────────────

def _is_open_trigger(verdict: dict) -> bool:
    """True when ``verdict`` represents a pending change for its trigger
    that a restart must not silently ride past — ready to act on
    (``act=True``), waiting on a seal / blocked by drift
    (``ENOSEAL``/``EDRIFT``), or a subsystem failure that means THIS
    trigger's real state cannot be established at all (``EUNREACH``).
    False for "nothing pending, confirmed" (``ENORECEIPT``,
    ``ESTATEEMPTY``, no-diff, ``EMISSING``) and for genuine input errors
    (``EINVAL``/``EAMBIG``/``ESEALS``) that are surfaced
    (``diagnostic_summary``'s ``env_stale``, or the refusal itself) but do
    not block the OTHER trigger.

    Rework (Loki 747B0C04, R4): ``EUNREACH`` used to fall on the "not open"
    side, so a corrupt/unreadable env state let a sealed pull restart onto
    whatever env happened to be on disk — unaudited, exactly the side
    effect F4 was meant to stop. "Cannot tell whether it's pending" is not
    "confirmed not pending" (INVARIANTS §1); it now blocks the same way an
    unsealed pending change does. The cost is symmetric and accepted: a
    persistently broken env-fingerprint read also now blocks pull-only
    restarts until fixed, rather than silently ignoring the env side."""
    return bool(verdict.get("act")) or verdict.get("error") in ("ENOSEAL", "EDRIFT", "EUNREACH")


def run_once(config: ReloaderConfig, *, ledger, runner: Optional[Callable] = None,
             project: str = "willow-mcp") -> dict:
    """One tick, both triggers: a sealed ``git_pull`` receipt (:func:`check`)
    and a sealed ``env_changed`` receipt (:func:`check_env`) are both
    checked; when either (or both) is due, ``systemctl --user restart`` the
    broker unit ONCE and write ONE FRANK ``unit_reload`` receipt citing
    whichever fired. Two due triggers never earn two restarts — one act
    satisfies both, the same idempotence guarantee each trigger already
    gives on its own.

    Rework (Loki F4): a restart happens ONLY when every OPEN trigger is
    sealed. Before this, a sealed pull with an unsealed-but-pending env
    diff would restart onto the pull alone — loading the unsealed env
    change too, as an accidental side effect of ANY restart re-reading the
    unit's env from disk, and leaving the env receipt EALREADY forever
    once the seal for it finally landed (the unit would already look
    "active since after" that later receipt). Symmetrically for the
    reverse. Now: if either trigger is open (a real pending change) but
    not yet due (not sealed), the WHOLE restart is refused with
    ``EPARTIAL``, naming both verdicts, rather than acting on only the
    sealed one.

    A refusal is returned as-is (``reloaded=False``); it is not ink. When
    neither is due the *pull* verdict rides at the top level — unchanged
    from this function's shape before the env trigger existed, so an
    existing caller reading ``error``/``reason`` off the result keeps
    seeing exactly what it saw before — with the env verdict alongside it
    under ``env`` for a caller that wants both.
    """
    pull_verdict = check(config, ledger=ledger, runner=runner)
    env_verdict = check_env(config, ledger=ledger, runner=runner)
    due_pull = bool(pull_verdict.get("act"))
    due_env = bool(env_verdict.get("act"))
    open_pull = _is_open_trigger(pull_verdict)
    open_env = _is_open_trigger(env_verdict)

    if not (due_pull or due_env):
        out = dict(pull_verdict)
        out["reloaded"] = False
        out["env"] = env_verdict
        return out

    if (open_pull and not due_pull) or (open_env and not due_env):
        # R5 (Loki 747B0C04): act=False — this is a WAITING state (the same
        # resting state ENOSEAL already is for a single trigger), not a
        # failure. `act=True` here made main()'s `tick` exit 1 on every 60s
        # poll until the operator sealed the second receipt, turning the
        # intended "waiting for a seal" state red in the journal.
        return {"ok": False, "act": False, "reloaded": False, "error": "EPARTIAL",
                "reason": "not every open trigger is sealed — refusing to restart onto a "
                          "partially-confirmed state; both triggers are named below",
                "pull": pull_verdict, "env": env_verdict}

    unit = pull_verdict["unit"] if due_pull else env_verdict["unit"]
    try:
        restarted = urx._run(["systemctl", "--user", "restart", unit], runner=runner,
                             timeout=_SYSTEMCTL_TIMEOUT_S)
    except FileNotFoundError:
        return {"ok": False, "act": True, "reloaded": False, "error": "EUNREACH",
                "reason": "systemctl_missing", "unit": unit, "pull": pull_verdict, "env": env_verdict}
    except subprocess.TimeoutExpired:
        return {"ok": False, "act": True, "reloaded": False, "error": "ETIMEDOUT",
                "reason": f"systemctl restart exceeded {_SYSTEMCTL_TIMEOUT_S}s",
                "unit": unit, "pull": pull_verdict, "env": env_verdict}
    if restarted.returncode != 0:
        tail = (restarted.stderr or restarted.stdout or "").strip()[-300:]
        return {"ok": False, "act": True, "reloaded": False, "error": "ERESTART",
                "reason": tail or f"systemctl restart exited {restarted.returncode}",
                "unit": unit, "pull": pull_verdict, "env": env_verdict}

    triggers = []
    content = {"actor": ACTOR, "unit": unit, "decision": "e961aff8"}
    if due_pull:
        triggers.append("git_pull")
        content.update({
            "repo": config.repo, "checkout": str(pull_verdict["checkout"]),
            "head": pull_verdict["head"], "pull_receipt_id": pull_verdict["receipt_id"],
        })
    if due_env:
        triggers.append("env_changed")
        content.update({
            "env_path": env_verdict["env_path"], "env_receipt_id": env_verdict["receipt_id"],
        })
    content["trigger"] = triggers[0] if len(triggers) == 1 else "both"
    if due_pull and due_env:
        content["nestor_pair_ids"] = {"pull": pull_verdict["seal"]["pair_id"],
                                      "env": env_verdict["seal"]["pair_id"]}
        content["nestor_verifiers"] = {"pull": pull_verdict["seal"]["verifier"],
                                       "env": env_verdict["seal"]["verifier"]}
    elif due_pull:
        content["nestor_pair_id"] = pull_verdict["seal"]["pair_id"]
        content["nestor_verifier"] = pull_verdict["seal"]["verifier"]
    else:
        content["nestor_pair_id"] = env_verdict["seal"]["pair_id"]
        content["nestor_verifier"] = env_verdict["seal"]["verifier"]

    out = {"ok": True, "act": True, "reloaded": True, "unit": unit, "triggers": triggers,
           "pull": pull_verdict, "env": env_verdict, "state_after": urx.show_unit(unit, runner=runner)}
    try:
        out["reload_receipt_id"] = ledger.append(project, urx.EVENT, content)
    except Exception as exc:  # noqa: BLE001 — the restart happened; the receipt failing is reported, not hidden
        out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return out


# ── the units ─────────────────────────────────────────────────────────────────
# Same doctrine as repo_sweep_service: install/uninstall manage unit files and
# daemon-reload only. They never start, stop, enable or disable a live unit —
# whether the reloader runs is the operator's decision, not the installer's.

def _template(name: str) -> Path:
    return Path(__file__).resolve().parent / "bundle" / "deploy" / name


def unit_dir() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base.expanduser() / "systemd" / "user"


def _safe(value: object, field: str) -> str:
    text = str(value)
    if not text or any(char in text for char in ("\n", "\r", '"')):
        raise ValueError(f"{field} contains characters unsafe for a systemd unit")
    return text


#: The net-signer's own SYSTEM unit — the one process on this box whose
#: ``WILLOW_NET_SIGNER_RING`` is ever actually set, because it is the one
#: that carries the public ring's real, installed location baked into its
#: own ``Environment=`` line at render time (net_signer.render_unit).
_NET_SIGNER_UNIT = "willow-mcp-net-signer.service"


def _resolve_keyring_path(*, runner: Optional[Callable] = None) -> tuple[Path, str]:
    """Where the reloader's rendered unit should point ``WILLOW_KEYRING`` —
    resolved from the SAME place the net-signer's own installed unit
    already resolved it, rather than a second, independent guess (Loki
    BE590C53, T1). ``net_signer.default_ring_path()`` reads
    ``WILLOW_NET_SIGNER_RING`` from THIS process's environment — which on
    a real box is set inside the net-signer's system unit and nowhere
    else, so calling it here (in the desk/broker's own environment) named
    a file that was never staged there. Read the net-signer unit's own
    ``Environment=`` line instead — ``systemctl show
    willow-mcp-net-signer.service --property=Environment`` — a read of
    the SAME fact the signer's own installer baked in, not an invented
    third source.

    Returns ``(path, source)`` — ``source`` is ``"net-signer-unit"`` when
    read from there, ``"default"`` when that unit could not be read at
    all (not installed, no system bus reachable) and
    :func:`net_signer.default_ring_path` was used as a last resort.
    """
    from . import net_signer

    run = runner or subprocess.run
    try:
        proc = run(["systemctl", "show", _NET_SIGNER_UNIT, "--property=Environment"],
                   capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired):
        proc = None
    if proc is not None and proc.returncode == 0:
        for line in (proc.stdout or "").splitlines():
            if line.startswith("Environment="):
                for name, value in envfp._parse_environment_pairs(line[len("Environment="):]):
                    if name == net_signer.RING_ENV and value:
                        return Path(value), "net-signer-unit"
    return net_signer.default_ring_path(), "default"


def render_units(config: ReloaderConfig, *, python: Optional[Path] = None,
                 interval: str = DEFAULT_INTERVAL, runner: Optional[Callable] = None) -> dict[str, str]:
    """The .service and .timer bodies, rendered together so the timer's
    ``Unit=`` can never drift from the service it schedules.

    Refuses (``ValueError``, the same ``ETEMPLATE``-shaped refusal an
    unresolved ``@KEY@`` already gets) when the resolved keyring path is
    not an existing file — Loki BE590C53 T1/T8: a unit rendered against a
    ring that is not actually staged can never verify a real seal, and
    that must fail at render time, loudly, naming the path and how it was
    resolved, not at the first tick with a pending receipt.
    """
    if config.checkout is None:
        raise ValueError(f"no broker checkout to render: set {_ENV_CHECKOUT}")

    keyring_path, keyring_source = _resolve_keyring_path(runner=runner)
    if not keyring_path.is_file():
        raise ValueError(
            f"WILLOW_KEYRING would render to {keyring_path} (resolved via {keyring_source}), "
            f"which is not a file — refusing to render a reloader unit whose seal confirm can "
            f"never succeed; stage the public ring first (`willow-mcp-net-signer export-ring` "
            f"or `install`) or re-render from where {_NET_SIGNER_UNIT} is actually installed")

    values = {
        "PYTHON": python or Path(sys.executable),
        "WILLOW_HOME": paths.willow_home(),
        "WILLOW_STORE_ROOT": paths.store_root(),
        "PG_DB": paths.pg_db(),
        "NESTOR_DB": config.nestor_db,
        "UNIT": config.unit,
        "CHECKOUT": config.checkout,
        "REPO": config.repo,
        "INTERVAL": interval,
        "SERVICE_UNIT": SERVICE_UNIT,
        # The PUBLIC-only ring (never config/verifiers.json — see the
        # template's own header comment, Loki 747B0C04 R1): this oneshot
        # only ever verifies a seal, never signs one. Resolved above from
        # the net-signer unit's own environment, not guessed (T1).
        "KEYRING": keyring_path,
    }
    out: dict[str, str] = {}
    for unit, tmpl in ((SERVICE_UNIT, f"{UNIT_PREFIX}.service.template"),
                       (TIMER_UNIT, f"{UNIT_PREFIX}.timer.template")):
        rendered = _template(tmpl).read_text(encoding="utf-8")
        for key, value in values.items():
            safe = str(value) if key == "PYTHON" else _safe(value, key)
            rendered = rendered.replace(f"@{key}@", safe)
        if "@" in rendered:
            raise ValueError(f"{unit} template contains unresolved placeholders")
        out[unit] = rendered
    return out


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", "--user", *args], check=False,
                          capture_output=True, text=True, timeout=15)


def install_services(config: ReloaderConfig, *, destination: Optional[Path] = None,
                     reload: bool = True, interval: str = DEFAULT_INTERVAL) -> dict:
    root = Path(destination) if destination is not None else unit_dir()
    root.mkdir(parents=True, exist_ok=True)
    written = []
    for unit, body in render_units(config, interval=interval).items():
        path = root / unit
        path.write_text(body, encoding="utf-8")
        written.append(str(path))
    if reload:
        result = _systemctl("daemon-reload")
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "systemctl daemon-reload failed").strip())
    # started/enabled are always empty and that is the contract, not an omission.
    return {"installed": written, "started": [], "enabled": []}


def service_status(*, destination: Optional[Path] = None,
                   runner: Callable[..., subprocess.CompletedProcess] = _systemctl) -> dict:
    root = Path(destination) if destination is not None else unit_dir()
    units = []
    for name in (SERVICE_UNIT, TIMER_UNIT):
        path = root / name
        active = False
        if path.is_file():
            result = runner("is-active", name)
            active = result.returncode == 0 and result.stdout.strip() == "active"
        units.append({"unit": name, "path": str(path), "installed": path.is_file(), "active": active})
    return {"services": units}


def uninstall_services(*, destination: Optional[Path] = None, reload: bool = True,
                       runner: Callable[..., subprocess.CompletedProcess] = _systemctl) -> dict:
    root = Path(destination) if destination is not None else unit_dir()
    status = service_status(destination=root, runner=runner)
    active = [u["unit"] for u in status["services"] if u["active"]]
    if active:
        raise RuntimeError("refusing to uninstall an active reloader unit; stop it explicitly first: "
                           + ", ".join(active))
    removed = []
    for u in status["services"]:
        path = Path(u["path"])
        if path.is_file():
            path.unlink()
            removed.append(str(path))
    if reload:
        result = runner("daemon-reload")
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "systemctl daemon-reload failed").strip())
    return {"removed": removed}


# ── entrypoint ────────────────────────────────────────────────────────────────

def _live_ledger():
    from .db import get_pg
    from .governance_ledger import GovernanceLedger

    pg = get_pg()
    return GovernanceLedger(pg) if pg else None


def main(argv: Optional[list] = None) -> int:
    """``python -m willow_mcp.reloader {tick,check,install,status,uninstall}``.

    ``tick`` is what the timer runs: one check, one restart at most, exit 0
    whether or not the restart was due (a waiting reloader is not a failed
    one). ``check`` is the same without the act. Exit 1 only when the act
    was due and failed — that is the row the journal should go red on.
    """
    parser = argparse.ArgumentParser(
        prog="willow-mcp-reloader",
        description="Restart the broker onto a sealed pull receipt (decision e961aff8).")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("tick", "check"):
        p = sub.add_parser(name)
        p.add_argument("--unit", default=None)
        p.add_argument("--checkout", default=None)
        p.add_argument("--repo", default=None)
    inst = sub.add_parser("install", help="write the .service and .timer (never enables or starts them) — "
                                          "the keyboard path; the broker path is unit_install_execute")
    inst.add_argument("--interval", default=DEFAULT_INTERVAL, help="OnUnitActiveSec= for the timer")
    inst.add_argument("--no-reload", action="store_true")
    inst.add_argument("--keyboard", action="store_true",
                      help="I am at a keyboard on a box with no broker; write the units by hand")
    sub.add_parser("status")
    un = sub.add_parser("uninstall")
    un.add_argument("--no-reload", action="store_true")
    args = parser.parse_args(argv)

    config = default_config()
    if args.command in ("tick", "check"):
        if args.unit or args.checkout or args.repo:
            config = ReloaderConfig(
                unit=args.unit or config.unit,
                checkout=Path(args.checkout).expanduser() if args.checkout else config.checkout,
                repo=args.repo or config.repo,
                nestor_db=config.nestor_db,
            )
        ledger = _live_ledger()
        if args.command == "check":
            out = dict(check(config, ledger=ledger))
            out["env"] = check_env(config, ledger=ledger)
        else:
            out = run_once(config, ledger=ledger)
        print(json.dumps(out, default=str, indent=2))
        # Due-and-failed is the only exit that should wake anyone.
        return 1 if (out.get("act") and not out.get("reloaded")) else 0
    if args.command == "install":
        # Verb 17 (unit.install, sealed 197aafa5): one shared keyboard guard.
        from .unit_install_executor import keyboard_install_refused
        if keyboard_install_refused(args):
            return 2
        print(json.dumps(install_services(config, reload=not args.no_reload, interval=args.interval), indent=2))
        return 0
    if args.command == "status":
        print(json.dumps(service_status(), indent=2))
        return 0
    print(json.dumps(uninstall_services(reload=not args.no_reload), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
