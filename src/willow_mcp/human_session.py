"""Human-only orchestrator seat — trust boundary for app_id=willow.

The orchestrator (Willow) is always run by a human operator, never by a
dispatched agent. Prompt injection in assignment.md or handoff narratives must
not be able to *become* the orchestrator or invoke orchestrator write tools.

Enforcement layers (defense in depth):
  1. session_enter(willow) → human_orchestrator only; never dispatch path
  2. Orchestrator write tools require human host attestation (stdio) or OAuth
     binding to willow (serve mode)
  3. Specialists use their own app_id; willow manifest not wired in worker MCP configs
  4. verify_handoff reads structured handoff.json — narrative is evidence, not instructions

See docs/design/human-orchestrator.md
"""

from __future__ import annotations

import os

ORCHESTRATOR_APP_ID = "willow"

# Tools that advance fleet work on behalf of the operator — never agent-autonomous.
# frank_append and envelope_apply mutate the shared governance chain; a process
# claiming app_id=willow must be a human-attested orchestrator host to run them,
# so a prompt-injected agent forging the willow seat cannot append or cite as the
# orchestrator (Loki B5FB7E2B §4.2). A non-willow app still reaches them only
# through its own capability grant; this boundary blocks the willow-seat bypass.
#
# dispatch_accept and handoff_write_v4 (#186 B-53, issue #239): session_enter
# refuses a dispatch_id for app_id=willow up front (human-only, never dispatch
# entry), but that guard lived only in session_enter -- calling either tool
# directly, bypassing session_enter, let a stdio caller with no
# WILLOW_HUMAN_ORCHESTRATOR accept and complete a real packet as willow.
# Red-team 2026-07-31 demonstrated this live against packet 96F54DA7.
ORCHESTRATOR_WRITE_TOOLS = frozenset({
    "dispatch_send",
    "dispatch_accept",
    "handoff_write_v4",
    "verify_handoff",
    "agent_clear",
    "frank_append",
    "envelope_apply",
})

# PR3: sidecar format tokens. v1 = original attest-session payload (PGP
# detached-signed by WILLOW_PGP_FINGERPRINT, no verifier field). v2 = keyring
# path (client-signed via willow-mcp sign-session, ed25519 hex sig, adds a
# verifier field naming the operator). Both continue to verify during
# migration — legacy_key pattern from Nestor §5.8.
_ATTEST_FORMAT_V1 = "orchestrator_session_attestation_v1"
_ATTEST_FORMAT_V2 = "orchestrator_session_attestation_v2"


def _sidecar_is_v2(attest_path) -> bool:
    """True if the sidecar at `attest_path` declares itself v2. Any parse
    failure or missing format falls through to False (treat as v1 legacy)."""
    import json

    try:
        payload = json.loads(attest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return payload.get("format") == _ATTEST_FORMAT_V2


def _verify_v2_sidecar_via_keyring(attest_path, sig_path, session_id: str):
    """Verify a v2 sidecar under the keyring. Returns:

    * ``None`` if the sidecar is v1 (fall through to legacy PGP path) OR if
      the sidecar is v2 and its signature verifies (allow the write).
    * A denial string if the sidecar IS v2 but the payload is malformed, the
      signature is missing, the signature does not verify against the named
      verifier's key in the keyring, or the payload names a different
      identity than claimed.

    The signal design mirrors ``session_signing.session_is_valid``: the
    validator returns bool, the enforcer here returns the operator-facing
    denial message.
    """
    import json

    from . import session_signing

    try:
        payload = json.loads(attest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            f"attestation sidecar is unreadable ({exc}) — re-run "
            f"`willow-mcp sign-session {session_id} --verifier NAME` from the "
            "operator terminal."
        )
    if payload.get("format") != _ATTEST_FORMAT_V2:
        return None  # v1 sidecar; caller falls through to PGP legacy path

    try:
        sig_hex = sig_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            f"attestation signature sidecar is unreadable ({exc})."
        )

    verifier = payload.get("verifier", "")
    attested_at = payload.get("attested_at", "")
    if payload.get("app_id") != ORCHESTRATOR_APP_ID or payload.get("session_id") != session_id:
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            "attestation sidecar signs a different identity than claimed — "
            "the signed payload names another app_id or session_id, so its "
            "signature is not evidence about this session."
        )
    if not verifier or not attested_at or not sig_hex:
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            "v2 attestation is missing one of verifier/attested_at/signature; "
            f"re-run `willow-mcp sign-session {session_id} --verifier NAME`."
        )
    if not session_signing.session_is_valid(
        ORCHESTRATOR_APP_ID, session_id, verifier, attested_at, sig_hex
    ):
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            f"was v2-attested by {verifier!r} but the signature does not "
            "verify against that verifier's key in the keyring (rotated key, "
            "compromised key, tampered sidecar, or the operator signed under a "
            "different keyring). Re-run "
            f"`willow-mcp sign-session {session_id} --verifier {verifier}` from "
            "the operator terminal."
        )
    return None  # verified — allow the write


def is_orchestrator_app(app_id: str) -> bool:
    return (app_id or "").strip().lower() == ORCHESTRATOR_APP_ID


def human_orchestrator_attested() -> bool:
    """Host-level signal: MCP process was started for the human orchestrator seat.

    Set WILLOW_HUMAN_ORCHESTRATOR=1 only in the orchestrator workspace MCP config
    (e.g. ~/github/willow/.cursor/mcp.json). Do NOT set on specialist seats.
    """
    return os.environ.get("WILLOW_HUMAN_ORCHESTRATOR", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def by_human_attested(app_id: str, *, serve_mode: bool) -> bool:
    """True only when this call really comes from the human-orchestrator seat.

    `is_orchestrator_app()` alone must never decide this. In stdio mode `app_id`
    is a caller-supplied tool-call argument, so a string compare against it
    records what the caller *called itself*, not who it is — any agent passing
    app_id="willow" would mint a record the operator appears to have signed.

    The two signals a caller cannot set for itself:
      * stdio: WILLOW_HUMAN_ORCHESTRATOR on the *server process* environment,
        set by the operator in the orchestrator workspace's MCP config. Nothing
        reachable from a tool call can change the server's own env.
      * serve: `app_id` is not caller-supplied at all — `server._gate` replaces
        it with the identity resolved from the authenticated session's confirmed
        OAuth binding (L-AUTH-02), which the operator created by hand with
        `willow-mcp confirm-binding`. Reaching this function as "willow" in
        serve mode already required that human confirmation.

    Deliberately a *downgrade*, not a denial: an unattested willow seat still
    writes its attestation, attributed to willow, with by_human False. The
    operator's signature is the thing being withheld, not the record.
    """
    if not is_orchestrator_app(app_id):
        return False
    if serve_mode:
        return True
    return human_orchestrator_attested()


def require_operator_terminal() -> None:
    """Fail-closed operator-presence gate for local mutation CLIs (Loki §4.3).

    ``sys.stdin.isatty()`` alone is forgeable — an agent process can allocate a
    pty and pass it. This adds two checks a sandboxed or re-parented agent cannot
    satisfy: it must not be running inside the Kart sandbox, and its controlling
    terminal must be owned by the real invoking user. An agent draining tasks has
    no operator-owned controlling tty, so it fails closed here even if it fakes
    isatty().
    """
    import sys

    if os.environ.get("WILLOW_IN_KART", "").strip():
        raise PermissionError("mutation refused inside the Kart sandbox")
    if not sys.stdin.isatty():
        raise PermissionError("mutation requires an interactive operator terminal")
    try:
        terminal = os.ttyname(sys.stdin.fileno())
        owner_uid = os.stat(terminal).st_uid
    except OSError as exc:
        raise PermissionError(f"operator terminal not verifiable: {exc}")
    if owner_uid != os.getuid():
        raise PermissionError(
            "controlling terminal is not owned by the invoking operator"
        )


def orchestrator_write_denial(
    app_id: str, tool_name: str, *, serve_mode: bool, session_id: str = ""
) -> str | None:
    """Return denial reason if this orchestrator write must be blocked, else None.

    `session_id` is the process's *currently entered* orchestrator session (set
    by session_enter, threaded in from server._current_orchestrator_session() —
    see #186 P2) — not a caller-supplied argument, since most orchestrator write
    tools don't carry a session_id of their own. Stdio only: serve mode's OAuth
    binding is trusted on its own, same as before this slice.
    """
    if not is_orchestrator_app(app_id):
        return None
    if tool_name not in ORCHESTRATOR_WRITE_TOOLS:
        return None
    if serve_mode:
        # OAuth identity binding to willow implies a human signed in and confirmed.
        return None
    if not human_orchestrator_attested():
        return (
            f"orchestrator_human_required: {tool_name} for app_id=willow requires a "
            "human orchestrator host (WILLOW_HUMAN_ORCHESTRATOR=1 on the MCP server "
            "env). Agents cannot run Willow."
        )

    # P2 (#186): once PGP is enabled, env attestation alone is no longer
    # enough — the current session must also carry a valid signature over
    # its stable identity. No-op (interim env-only) until either
    # WILLOW_PGP_FINGERPRINT (legacy) or WILLOW_KEYRING (PR3 keyring path)
    # is set.
    from . import keyring as keyring_mod
    from . import pgp

    keyring_on = keyring_mod.enabled()
    if not pgp.pgp_enabled() and not keyring_on:
        return None

    from .paths import session_attestation_path, session_path

    if not session_id:
        return (
            "orchestrator_session_attestation_missing: no active orchestrator "
            "session on record for this process — call "
            "session_enter(app_id='willow', session_id=...) first, then "
            "`willow-mcp attest-session <session_id>` (legacy PGP) or "
            "`willow-mcp sign-session <session_id> --verifier NAME` (keyring, PR3) "
            "from the operator terminal."
        )

    # Live session file must still exist (proof session_enter's binding is on
    # disk for this id). The sidecar alone is not enough — otherwise deleting
    # sessions/willow-<id>.json after attest would leave orchestrator writes
    # armed against a session that is no longer live.
    live_session = session_path(ORCHESTRATOR_APP_ID, session_id)
    if not live_session.is_file():
        return (
            f"orchestrator_session_attestation_missing: session {session_id!r} "
            "has no live session file on disk — call "
            "session_enter(app_id='willow', session_id=...) first, then "
            f"`willow-mcp attest-session {session_id}` (legacy PGP) or "
            f"`willow-mcp sign-session {session_id} --verifier NAME` (keyring) "
            "from the operator terminal."
        )

    # #313: verify against the dedicated attest-session sidecar
    # (paths.session_attestation_path), not the live session record --
    # session_bind (session_enter, dispatch_accept, session_handoff_write,
    # agent_clear, ...) rewrites the latter's status/dispatch_id/updated_at on
    # every ordinary state change, which self-invalidated a signature over the
    # session file itself. The sidecar holds only the {app_id, session_id}
    # tuple attest-session signed and is never touched by those writes.
    attest_path = session_attestation_path(ORCHESTRATOR_APP_ID, session_id)
    sig_path = attest_path.parent / f"{attest_path.name}.sig"

    # PR3: if a v2 sidecar exists and the keyring is enabled, verify through
    # the keyring path (client-signed ed25519 or hmac). v2 sidecars carry a
    # `verifier` field naming the operator; the sig lives in a separate
    # .sig file as raw hex (not a PGP detached sig). Fall back to the PGP
    # legacy path (v1 sidecar) when either the sidecar is v1 or the keyring
    # is disabled.
    if keyring_on and attest_path.is_file() and sig_path.is_file():
        v2_denial = _verify_v2_sidecar_via_keyring(
            attest_path, sig_path, session_id
        )
        if v2_denial is not None:
            return v2_denial
        # v2_denial is None either because verification succeeded (allow the
        # write) or because the sidecar is v1 (fall through to PGP legacy).
        if _sidecar_is_v2(attest_path):
            return None

    if not attest_path.is_file() or not sig_path.is_file():
        # Distinguish "never attested" from "attested, but the signature no
        # longer verifies" in the top-level reason (#313) -- the operator
        # response differs: attest for the first time vs re-attest because
        # something invalidated a prior attestation (tamper, key rotation, a
        # write path that shouldn't have touched the sidecar but did).
        # Token rename from orchestrator_session_attestation_required (#186):
        # parsers that still match the old needle should look for
        # orchestrator_session_attestation_missing / _invalid instead.
        remedy = (
            f"`willow-mcp sign-session {session_id} --verifier NAME`"
            if keyring_on
            else f"`willow-mcp attest-session {session_id}`"
        )
        return (
            f"orchestrator_session_attestation_missing: session {session_id!r} "
            f"has never been attested (no attestation record on file) — run "
            f"{remedy} from the operator terminal."
        )
    # PR3: reaching here means either the keyring is off (legacy PGP path)
    # or the sidecar is v1 (predates keyring adoption). Both need the PGP
    # verifier; if PGP is not enabled and we still reach here, that means
    # the operator has a keyring but a v1 sidecar and no PGP fingerprint —
    # ask them to re-attest under the keyring path so the sidecar rolls to
    # v2.
    if not pgp.pgp_enabled():
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            "has a v1 (PGP) attestation sidecar but WILLOW_PGP_FINGERPRINT is "
            "not set, so it cannot be verified. The keyring is on — re-attest "
            f"under it with `willow-mcp sign-session {session_id} --verifier "
            "NAME` from the operator terminal to roll the sidecar to v2."
        )
    ok, detail = pgp.verify_detached(attest_path)
    if not ok:
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            f"was attested but the signature is BAD ({detail}) — the "
            "attestation was invalidated (tampered sidecar, unexpected signer, "
            f"or a rotated key). Re-run `willow-mcp attest-session {session_id}` "
            "from the operator terminal to restore it."
        )

    # Belt-and-braces: the signature verifies, but also confirm the signed
    # payload actually names *this* app_id/session_id, not just that some
    # valid signature exists at this path (session_path's filename sanitizer
    # truncates/collapses session_id, so two distinct ids could in principle
    # collide on one file). A mismatch here is the same "invalid" class as a
    # bad signature -- the content signed off on isn't this session's.
    import json

    try:
        payload = json.loads(attest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            f"attestation sidecar is unreadable ({exc}) — re-run "
            f"`willow-mcp attest-session {session_id}` from the operator terminal."
        )
    if payload.get("app_id") != ORCHESTRATOR_APP_ID or payload.get("session_id") != session_id:
        return (
            f"orchestrator_session_attestation_invalid: session {session_id!r} "
            "attestation sidecar signs a different identity than claimed — "
            f"re-run `willow-mcp attest-session {session_id}` from the operator "
            "terminal."
        )
    return None
