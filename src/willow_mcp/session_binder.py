"""session_binder — cryptographic agent identity binding (willow-gate seam, H1).

The agent-side counterpart to `identity_binding` (which binds serve-mode OAuth
*humans*): agents don't OAuth, so their app_id is otherwise just a string. This
binds it. Two verbs, exactly the H1 spike promoted to real code:

  * check_in(header): HMAC-verify a 13-field header against the agent's registered
    secret, cap the claimed trust at the registered ceiling, refuse a replayed
    nonce → a live bound session.
  * verify_call(session_id, app_id, tool, call_nonce, sig): the SIGNED per-call
    check — a call carries a fresh nonce and an HMAC over
    (session_id|app_id|tool|call_nonce). Recompute, reject a reused nonce, and
    require the session's agent_id == the call's app_id. This is what stops the
    "pass app_id=operator and ride the live session" hole: a bearer session token
    would not, a per-call signature does (see the H1 spike).

Phase 2 is OBSERVE-ONLY: `_gate` calls this to LOG the binding, never to change a
decision. Pure stdlib (hmac/hashlib) — no willow-gate dependency, no PGP.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from datetime import datetime, timezone
from typing import Optional

from . import agent_registry, paths, tier_policy

# (name, read_only) — the ladder for logging; D1 maps tiers→groups at enforcement.
#
# Home: willow-gate, `willow_gate.TRUST_LEVELS`. Until 2026-09-03 this was a
# hand-kept twin of the gate's ladder, pinned to it only by a golden vector in
# both repos' tests/test_trust_ladder_canonical.py because the two could not
# share code (seam doc D5: no willow-gate dependency, no PGP). With willow-gate
# taken as a dependency the same way forge-play was, the twin is derived from
# the gate's own object — one ladder, read here in the shape this module's
# callers already use. The golden-vector test stays as the independent check.
from willow_gate import TRUST_LEVELS as _GATE_LEVELS

TRUST_LEVELS = {
    level: (tl.name, tl.read_only) for level, tl in sorted(_GATE_LEVELS.items())
}
REQUIRED_FIELDS = {
    "agent_id", "agent_name", "last_gate", "pass_count", "fail_count", "drift",
    "nonce", "trust_level", "timestamp", "tools", "state_hash", "signature",
    "reserved",
}
_SIGNED_FIELDS = sorted(REQUIRED_FIELDS - {"signature"})

# D4 — the reconciled subset of the 13-field declaration. The entry header
# already carries all 13 (identity + crypto + these); at check-out the agent
# re-declares just this subset — "what I did" — to diff against the receipt log.
# The other entry fields (agent_name, nonce, signature, timestamp, trust_level,
# reserved, last_gate) are identity/crypto, not part of the declare-vs-did diff.
RECONCILED_FIELDS = ("tools", "pass_count", "fail_count", "drift", "state_hash")
_PRIVILEGED_CLASSES = frozenset({tier_policy.WRITE, tier_policy.EXECUTE, tier_policy.ADMIN})


def reconcile(entry_declared: dict, exit_declared: dict, actual_tools: list) -> dict:
    """Pure declare-vs-did diff (willow-gate seam H3). No session, no I/O — just
    the three inputs and the verdict, so it is trivially testable.

    * `entry_declared` — the tool CLASSES the agent named at check-in (its plan).
    * `exit_declared`  — what the agent claims it did at check-out (RECONCILED_FIELDS).
    * `actual_tools`   — the tool NAMES the receipt log shows actually ran; the
                         ground truth. Classified to willow-gate classes here.

    Verdict `clean` is driven by the two integrity signals, at privileged classes
    only (read is universal enough that a coarse over/under-report of it is noise):
      * claimed_not_done — a class the agent SAYS it exercised that NO receipt
        backs (the H3 catch: a false claim, or use through a path that bypassed
        the gate and left no receipt);
      * beyond_entry / done_not_claimed — a privileged class the receipts show it
        used that it did NOT pre-declare at entry / did NOT report at exit (scope
        creep, or hidden activity).
    Read-class over/under-reporting is surfaced but never makes a session unclean.
    """
    exit_classes = {c for c in (exit_declared.get("tools") or []) if isinstance(c, str)}
    entry_classes = {c for c in (entry_declared.get("tools") or []) if isinstance(c, str)}
    actual_classes = {c for t in actual_tools if (c := tier_policy.classify(t)) is not None}

    claimed_not_done = exit_classes - actual_classes
    done_not_claimed = actual_classes - exit_classes
    beyond_entry = actual_classes - entry_classes

    # Only a PRIVILEGED discrepancy (in any direction) makes a session unclean:
    # a false execute claim / an unreported write is an integrity signal; over- or
    # under-reporting read is noise (session_enter, whoami-style reads are ambient).
    clean = not ((claimed_not_done | done_not_claimed | beyond_entry) & _PRIVILEGED_CLASSES)
    return {
        "clean": clean,
        "entry_declared_classes": sorted(entry_classes),
        "exit_declared_classes": sorted(exit_classes),
        "actual_classes": sorted(actual_classes),
        "actual_tools": sorted(set(actual_tools)),
        "claimed_not_done": sorted(claimed_not_done),
        "done_not_claimed": sorted(done_not_claimed),
        "beyond_entry": sorted(beyond_entry),
        # Echoed, never reconciled: willow-mcp has no independent ground truth for
        # the agent's self-scored task metrics, so they are recorded, not judged.
        "self_report": {k: exit_declared.get(k) for k in
                        ("pass_count", "fail_count", "drift", "state_hash")},
    }


class BindError(Exception):
    """A check-in / verification refusal. Carries a short machine reason."""


def _canonical(header: dict) -> bytes:
    return json.dumps({k: header[k] for k in _SIGNED_FIELDS},
                      sort_keys=True, separators=(",", ":")).encode()


def expected_header_sig(secret: bytes, header: dict) -> str:
    return hmac.new(secret, _canonical(header), hashlib.sha256).hexdigest()


def call_sig(secret: bytes, session_id: str, app_id: str, tool: str, call_nonce: str) -> str:
    # Structured, unambiguous encoding — a JSON array length-delimits every field
    # so no combination of `session_id|app_id|tool|call_nonce` values can collide
    # by shifting a delimiter (the "call" tag also domain-separates it from the
    # header signature). Attackers cannot sign, but the binding should not rely on
    # the field alphabets happening to exclude a separator.
    msg = json.dumps(["call", session_id, app_id, tool, call_nonce],
                     separators=(",", ":")).encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


class SessionBinder:
    def __init__(self):
        self._sessions: dict = {}          # nonce -> session dict (process-lived)
        self._used_nonces_file = paths.willow_home() / "gate" / "used_checkin_nonces"
        # FastMCP dispatches sync tools on a threadpool, so session state is
        # touched concurrently. A reentrant lock guards the session dict, the
        # per-session nonce sets, and the check-in nonce file's check-then-mark.
        self._lock = threading.RLock()

    # ── check-in ──────────────────────────────────────────────────────────────
    def _load_used(self) -> set:
        try:
            return set((self._used_nonces_file.read_text()).split())
        except FileNotFoundError:
            return set()                       # not yet created ⇒ nothing used
        except OSError as e:
            # The file EXISTS but cannot be read (EACCES/EIO/replaced-by-dir):
            # treating that as "nothing used" would silently disable check-in
            # replay protection, so fail CLOSED instead.
            raise BindError(f"check-in nonce store unreadable — refusing: {e}")

    def _mark_used(self, nonce: str) -> None:
        self._used_nonces_file.parent.mkdir(parents=True, exist_ok=True)
        with self._used_nonces_file.open("a") as f:
            f.write(nonce + "\n")

    def check_in(self, header: dict) -> dict:
        """Verify a header and open a bound session. Raises BindError on any
        refusal (fail-closed). Returns the session (nonce is its id)."""
        if not isinstance(header, dict):
            raise BindError("header must be an object")
        missing = REQUIRED_FIELDS - set(header)
        if missing:
            raise BindError(f"missing fields: {sorted(missing)}")
        if set(header) - REQUIRED_FIELDS:
            raise BindError("unknown fields present")          # 13 in, 13 out
        if header["reserved"] != 0:
            raise BindError("trap field 'reserved' must be 0")
        trust = header["trust_level"]
        if trust not in TRUST_LEVELS:
            raise BindError(f"bad trust_level: {trust}")
        # Exiled (0) is entry_allowed=False by design (tier_policy) — deny the
        # check-in outright rather than open a read-only session it should not get.
        if int(trust) == 0:
            raise BindError("Exiled (trust 0): entry denied")
        if len(str(header["nonce"])) != 32:
            raise BindError("nonce must be 32 chars")
        if len(str(header["signature"])) != 64:
            raise BindError("signature must be 64 hex chars")

        agent_id = header["agent_id"]
        loaded = agent_registry.load(agent_id)
        if loaded is None:
            raise BindError(f"unregistered agent_id: {agent_id!r}")
        secret, ceiling = loaded
        if not hmac.compare_digest(expected_header_sig(secret, header), str(header["signature"])):
            raise BindError("signature mismatch — identity not verified")
        if int(trust) > int(ceiling):
            raise BindError(f"trust claim {trust} exceeds registered ceiling {ceiling}")

        nonce = str(header["nonce"])
        name, read_only = TRUST_LEVELS[int(trust)]
        # check-then-mark-then-insert under one lock so two threads replaying the
        # same signed header cannot both pass the membership test.
        with self._lock:
            if nonce in self._load_used() or nonce in self._sessions:
                raise BindError("nonce already used — replay refused")
            self._mark_used(nonce)
            session = {"session_id": nonce, "agent_id": agent_id, "trust_level": int(trust),
                       "tier": name, "read_only": read_only, "used_call_nonces": set(),
                       # Retained for check-out reconciliation (Phase 4): the entry
                       # declaration (the plan) and a trustworthy SERVER start time to
                       # window the receipt-log feed — never the agent's timestamp.
                       "started_ts": datetime.now(timezone.utc).isoformat(),
                       "entry_declared": {k: header.get(k) for k in RECONCILED_FIELDS}}
            self._sessions[nonce] = session
        return {k: session[k] for k in ("session_id", "agent_id", "trust_level", "tier", "read_only")}

    # ── per-call verification (SIGNED; H1) ─────────────────────────────────────
    def verify_call(self, session_id: str, app_id: str, tool: str,
                    call_nonce: str, sig: str) -> dict:
        """Verify a per-call credential binds this call to a live check-in.
        Returns {bound, agent_id, trust_level, tier, reason}. bound=False with a
        reason on any failure — never raises (the caller only observes)."""
        with self._lock:
            sess = self._sessions.get(session_id or "")
            if sess is None:
                return {"bound": False, "reason": "no live session for session_id"}
            if not call_nonce or call_nonce in sess["used_call_nonces"]:
                return {"bound": False, "reason": "missing or replayed call_nonce"}
            loaded = agent_registry.load(sess["agent_id"])
            if loaded is None:
                return {"bound": False, "reason": "agent no longer registered"}
            secret, _ = loaded
            if not hmac.compare_digest(call_sig(secret, session_id, app_id, tool, call_nonce), sig or ""):
                return {"bound": False, "reason": "call signature mismatch"}
            if sess["agent_id"] != app_id:
                return {"bound": False, "reason": "signed session is not this app_id"}
            sess["used_call_nonces"].add(call_nonce)
            return {"bound": True, "agent_id": sess["agent_id"], "trust_level": sess["trust_level"],
                    "tier": sess["tier"], "read_only": sess["read_only"], "reason": "verified"}

    def session_for(self, app_id: str) -> Optional[dict]:
        """The most recent live session bound to this app_id, if any (used by the
        observe hook when no per-call credential was presented)."""
        with self._lock:
            for s in reversed(list(self._sessions.values())):
                if s["agent_id"] == app_id:
                    return s
        return None

    # ── check-out reconciliation (declare-vs-did; H3) ──────────────────────────
    def session_started_ts(self, session_id: str, app_id: Optional[str] = None) -> Optional[str]:
        """The server-stamped start time of a live session, to window the receipt
        feed. None if there is no live session for this id — or, when `app_id` is
        given, if the session is not bound to that app (so a caller cannot probe
        another agent's session window)."""
        with self._lock:
            sess = self._sessions.get(session_id or "")
            if sess is None or (app_id is not None and sess["agent_id"] != app_id):
                return None
            return sess["started_ts"]

    def check_out(self, session_id: str, exit_declaration: dict,
                  actual_tools: list, app_id: Optional[str] = None) -> dict:
        """Close a bound session and reconcile the agent's exit declaration against
        the tools the receipt log shows actually ran (`actual_tools`, supplied by
        the server from ReceiptLog — H3). Raises BindError on a bad
        session/declaration (fail-closed); otherwise returns the reconcile() report
        and DROPS the session (freeing its used-nonce set — the H1 residual note).

        `app_id`, when given, must equal the session's bound agent_id — the same
        ownership rule verify_call enforces. Without it a caller who learned
        another agent's session_id could destroy that session (cross-agent DoS)
        and forge a discrepancy stamped with the victim's identity.
        """
        if not isinstance(exit_declaration, dict):
            raise BindError("exit_declaration must be an object")
        tools = exit_declaration.get("tools")
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise BindError("exit_declaration.tools must be a list of class strings")
        with self._lock:
            sess = self._sessions.get(session_id or "")
            if sess is None:
                raise BindError("no live session for session_id")
            if app_id is not None and sess["agent_id"] != app_id:
                raise BindError("session is not bound to this app_id")
            report = reconcile(sess["entry_declared"], exit_declaration, list(actual_tools or []))
            report["session_id"] = session_id
            report["agent_id"] = sess["agent_id"]
            report["tier"] = sess["tier"]
            del self._sessions[session_id]
        return report
