"""Supported-client SessionStart bridge to native ``session_enter``."""
from __future__ import annotations

import json
import logging
import os
import sys
import uuid

from .boot_context import build_boot_lines
from .seed_loader import seed_corpus_corrections


def handle(payload: dict) -> dict:
    from .server import session_enter

    source = str(payload.get("source") or "startup")
    try:
        seed_corpus_corrections()
    except Exception:
        logging.getLogger("willow_mcp.session_start_hook").debug(
            "seed_corpus_corrections failed", exc_info=True)

    workspace = (
        payload.get("workspace")
        or payload.get("workspace_root")
        or payload.get("cwd")
        or os.environ.get("WILLOW_PROJECT_ROOT", "")
    )
    session_id = str(
        payload.get("session_id") or payload.get("conversation_id") or uuid.uuid4()
    )
    # PR4 of the identity-in-session plan: refuse to enter with an inferred
    # identity. The prior default silently assigned app_id="willow"
    # (orchestrator seat) to any workspace without WILLOW_APP_ID set — the
    # exact anti-pattern nestor.memory._same_verifier codified ("empty is
    # unknown, not a person"). Every existing willow orchestrator workspace
    # must set WILLOW_APP_ID=willow explicitly next to the
    # WILLOW_HUMAN_ORCHESTRATOR flag it already carries; specialist
    # workspaces must set their own app_id or refuse at boot.
    app_id = os.environ.get("WILLOW_APP_ID", "").strip()
    if not app_id:
        message = (
            "WILLOW_APP_ID is not set on this MCP server env. Willow no longer "
            "defaults to 'willow' — an unset value used to silently claim the "
            "orchestrator seat. Set WILLOW_APP_ID=willow (orchestrator "
            "workspace) or WILLOW_APP_ID=<specialist_id> (specialist workspace) "
            "in your MCP config next to WILLOW_HUMAN_ORCHESTRATOR. See "
            "docs/design/human-orchestrator.md wiring checklist item 2."
        )
        logging.getLogger("willow_mcp.session_start_hook").error(message)
        return {"additional_context": f"WILLOW session_enter FAILED — {message}"}
    # PR8 (envelope-accrual UX): auto-sign the session at seat-open when the
    # operator has set WILLOW_OPERATOR_VERIFIER. Removes the "open a second
    # terminal and run willow-mcp sign-session per session_id" ritual — the
    # single biggest UX papercut the identity+accrual work left standing
    # (see docs/design/envelope-accrual.md, "where the friction still is").
    #
    # Design: the MCP server process is running as the operator's own uid
    # (SessionStart hooks fire in the client's local environment; for the
    # typical single-box deployment that IS the operator's box). Signing
    # here IS the operator signing — same trust story as the operator
    # running `willow-mcp sign-session` from a terminal. The PR3 "server
    # never signs on the client-supplied path" invariant is preserved
    # because this is not a client-supplied path — no untrusted caller is
    # asking the server to sign for them; the server is signing on its
    # own uid's behalf, and only if the operator explicitly opted in.
    #
    # Opt-in: WILLOW_OPERATOR_VERIFIER unset → no auto-sign, existing
    # behavior. When set, the hook still succeeds even if auto-sign
    # fails (unknown/compromised verifier, keyring not enabled, missing
    # private half) — it just doesn't produce a sig, and session_enter
    # falls through to the unattested downgrade path (existing).
    verifier_arg = os.environ.get("WILLOW_OPERATOR_VERIFIER", "").strip()
    seal_sig = ""
    attested_at = ""
    auto_sign_note = ""
    if verifier_arg and app_id == "willow":
        try:
            from datetime import datetime, timezone
            from . import keyring as _keyring
            from . import session_signing as _ss
            if not _keyring.enabled():
                auto_sign_note = (
                    "WILLOW_OPERATOR_VERIFIER set but WILLOW_KEYRING is not; "
                    "session will not be auto-signed."
                )
            elif _keyring.get_keyring().verifying_entry(verifier_arg) is None:
                auto_sign_note = (
                    f"WILLOW_OPERATOR_VERIFIER={verifier_arg!r} is unknown to "
                    "the keyring or compromised; session will not be "
                    "auto-signed. Run `willow-mcp keys add "
                    f"{verifier_arg}` or check keyring status."
                )
            else:
                attested_at = (
                    datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                seal_sig = _ss.sign_session(
                    app_id, session_id, verifier_arg, attested_at,
                )
                # Write the sidecar + sig files atomically — the same shape
                # sign_session_cli produces so orchestrator_write_denial's
                # sidecar-verify path (PR3) finds them on the next
                # orchestrator write. Without this, session_enter's cache
                # would agree with the sig but the sidecar wouldn't be on
                # disk; a process restart would find nothing to verify
                # against and refuse the operator.
                from . import paths as _paths
                attest_file = _paths.session_attestation_path(app_id, session_id)
                sig_file = attest_file.parent / f"{attest_file.name}.sig"
                attest_file.parent.mkdir(parents=True, exist_ok=True)
                payload = {
                    "format": "orchestrator_session_attestation_v2",
                    "app_id": app_id,
                    "session_id": session_id,
                    "verifier": verifier_arg,
                    "attested_at": attested_at,
                }
                attest_file.write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                sig_file.write_text(seal_sig + "\n", encoding="utf-8")
                auto_sign_note = (
                    f"session auto-signed by {verifier_arg} at "
                    f"{attested_at} (PR8; sidecar at {attest_file.name})"
                )
        except Exception as exc:
            # Any auto-sign failure downgrades to unattested — the hook
            # must never crash the client's session-start flow. Operator
            # can still run `willow-mcp sign-session` manually as before.
            auto_sign_note = (
                f"auto-sign failed ({exc.__class__.__name__}: {exc}); "
                "session will not be attributed. Fall back to `willow-mcp "
                "sign-session` from the operator terminal."
            )
            seal_sig = ""
            attested_at = ""
            logging.getLogger("willow_mcp.session_start_hook").warning(
                "auto-sign failed", exc_info=True,
            )
    result = session_enter(
        app_id=app_id,
        session_id=session_id,
        project=os.environ.get("WILLOW_HANDOFF_PROJECT", ""),
        workspace=str(workspace or ""),
        verifier=verifier_arg if seal_sig else "",
        attested_at=attested_at,
        seal_sig=seal_sig,
    )
    if auto_sign_note:
        result["auto_sign_note"] = auto_sign_note
    # Warm the attribution cache now — the hook wrote the sidecar+sig,
    # session_enter accepted the sig, session record carries the verifier.
    # Disk state matches; the in-process cache should agree so the
    # operator's very first envelope_propose after seat-open works
    # without an intermediate orchestrator_write_denial to warm from
    # the sidecar. Skipped when session_enter returned an error (gate
    # denial, unattested downgrade, etc.).
    if seal_sig and not result.get("error"):
        from . import human_session as _human_session
        _human_session._remember_attributed(session_id)
    boot_lines = build_boot_lines(app_id, session_id, source, result)
    result["boot_context"] = "\n".join(boot_lines)
    return {"additional_context": json.dumps(result, sort_keys=True)}


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        print(json.dumps(handle(payload if isinstance(payload, dict) else {})))
    except Exception as exc:
        message = f"WILLOW session_enter FAILED — orientation did not run: {exc}"
        print(f"[willow.session_start] {message}", file=sys.stderr)
        print(json.dumps({"additional_context": message}))


if __name__ == "__main__":
    main()
