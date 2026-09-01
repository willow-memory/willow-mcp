"""
willow-mcp MCP server — agent-neutral core tools.

Modes:
  stdio (default):  python3 -m willow_mcp
  serve (HTTP):     python3 -m willow_mcp --serve [--port 8765] [--host 127.0.0.1]

Tools:
  Store (SQLite):  store_put, store_get, store_list, store_update, store_search,
                   store_delete, store_search_all
  Knowledge (PG):  knowledge_ingest, knowledge_search, kb_ingest,
                   kb_at, kb_promote, kb_journal, kb_startup_continuity
  Tasks (PG):      task_submit, task_status, task_list
  Agent (PG):      agent_route, agent_dispatch_result
  Dispatch (FS):   dispatch_send, dispatch_read, dispatch_list, dispatch_accept,
                   handoff_write_v4, handoff_read, verify_handoff, agent_clear,
                   session_read, session_enter, session_handoff_write
  Registry:        specialist_list, specialist_get, agent_seed_mirror,
                   exposure_config_get, exposure_slice
  Fleet (PG):      fleet_status, fleet_health
  Grove (PG):      grove_list_channels, grove_get_history, grove_search, grove_watch,
                   grove_watch_all, grove_get_thread, grove_bus_receive, grove_inbox,
                   grove_flagged, grove_get_identity, grove_agents, grove_fleet_status,
                   grove_human_required, grove_send_message, grove_reply, grove_flag,
                   grove_unflag, grove_bus_send, grove_ack, grove_heartbeat
                   (grove.* tables live in willow_20 — see grove.py DB-name trap note)
  Context (SQLite):context_save, context_get, context_list, context_expire
  Integrations:    integration_list, integration_status, integration_call
  Federated MCP:   federation_discover, federation_list_servers, federation_call
  Audit (SQLite):  receipts_tail
  Diagnostic:      diagnostic_summary (ungated self-check)

Auth (stdio): manifest-based per-tool ACL — app_id required on every call.
  Exception: diagnostic_summary is ungated (must answer when a manifest is broken).
Auth (serve): OAuth 2.0 PKCE (Google / Apple) + per-tool ACL gate.
Fail-closed: no manifest = all calls denied.

Security (Phase 4): every tool call runs gate -> sanitize -> rate-check ->
dispatch -> receipt, via the _guarded() decorator. See _gate, _sanitize,
_check_rate, and receipts.ReceiptLog.
"""
# b17: WLWMCP  ΔΣ=42

import inspect
import json
import math
import os
import re
import shutil
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Iterable, Optional

from mcp.server.mcpserver import MCPServer
from psycopg2.extras import Json

from .db import Store, get_pg, encode_cursor, decode_cursor
from .gate import log_manifest_verify_sweep, permitted, resolve_collection_alias
from .identity_binding import resolve_app_id
from .receipts import ReceiptLog
from . import paths
from . import schema_profile as sp
from . import dispatch as dispatch_stack
from . import handoff as handoff_stack
from . import gaps as gap_backlog
from . import kb_curate as kbc
from . import kb_verify
from . import postgres_lifecycle
from . import secret_scan

_store = Store()
_receipt_log = ReceiptLog()

from .lineage import Lineage
_lineage = Lineage(_store)

from .friction import FrictionWatcher
_friction = FrictionWatcher(_store)

import contextvars
from . import agent_registry, tier_policy
from .session_binder import SessionBinder, BindError
from .signing import CREDENTIAL_META_KEY
_binder = SessionBinder()
# Per-call SIGNED credential (H1). It rides the MCP request's out-of-band `_meta`
# (never a tool argument); _read_call_credential pulls it from the request context.
# This contextvar is an explicit OVERRIDE seam — tests set it directly, and it wins
# when set — but in production nothing sets it, so _current_call_credential falls
# through to reading `_meta`. Phase 2 OBSERVES the credential; Phase 3 (when
# WILLOW_MCP_ENFORCE_BINDING is on) ENFORCES it for registered apps.
_CALL_CREDENTIAL: "contextvars.ContextVar[Optional[dict]]" = contextvars.ContextVar(
    "willow_call_credential", default=None)

# Tools exempt from the per-call credential requirement. `session_bind` is the
# check-in itself — there is no session to sign against yet, and it authenticates
# via its own header HMAC — so requiring a per-call signature would be a
# bootstrap deadlock. It is the ONLY exemption; everything after check-in signs.
_BINDING_BOOTSTRAP_TOOLS = frozenset({"session_bind"})


def _read_call_credential() -> Optional[dict]:
    """Pull the per-call credential the signing client attached to the MCP
    request's out-of-band `_meta` (key CREDENTIAL_META_KEY). Returns a normalized
    {session_id, call_nonce, sig} dict, or None if absent/malformed. Never raises —
    a missing request context or meta is simply "no credential".

    Reads `request_context.current_meta()`, which our own middleware publishes
    from the `ServerRequestContext` the SDK hands it. SDK 1.x had an ambient
    `mcp.server.lowlevel.server.request_ctx`; 2.0 removed it deliberately and
    injects `Context` into tool functions instead — an injection that does not
    reach a decorator wrapping 120 tools. See willow_mcp/request_context.py for
    why the replacement is a ContextVar we own rather than one the SDK might
    move again.
    """
    from . import request_context

    meta = request_context.current_meta()
    if meta is None:
        return None
    # SDK 1.x `_meta` was a pydantic model carrying unknown keys in
    # `.model_extra`; SDK 2.0's `RequestParamsMeta` is a TypedDict, i.e. an
    # ordinary mapping. Read whichever this SDK hands us — the credential is an
    # out-of-band key either way, and guessing wrong is a silent "no credential".
    if isinstance(meta, dict):
        extra = meta
    else:
        extra = getattr(meta, "model_extra", None) or {}
    cred = extra.get(CREDENTIAL_META_KEY)
    if isinstance(cred, dict) and all(k in cred for k in ("session_id", "call_nonce", "sig")):
        return {"session_id": str(cred["session_id"]),
                "call_nonce": str(cred["call_nonce"]),
                "sig": str(cred["sig"])}
    return None


def _current_call_credential() -> Optional[dict]:
    """The per-call credential for this call: an explicitly-set contextvar (the
    test override) if present, else whatever the request `_meta` carried."""
    cred = _CALL_CREDENTIAL.get()
    if cred is not None:
        return cred
    return _read_call_credential()


#: The three positions of the Phase 3 switch. `on` and `strict` differ only in
#: what an UNREGISTERED app_id means — see `_binding_mode`.
_BINDING_MODES = ("off", "on", "strict")


def _binding_mode() -> str:
    """Phase 3 switch, read live (not cached) so it can be toggled per process /
    per test. Returns one of `_BINDING_MODES`.

    - **off** (default) — registering an agent while this is off is exactly
      Phase 2 (observe-only), so an operator can watch the binding in receipts
      before the day it can lock anyone out.
    - **on** — a *registered* app must present a valid per-call signature and
      clear the tier ceiling. An *unregistered* app stays manifest-only
      (seam-doc D3), so a plain clone keeps working.
    - **strict** — as `on`, and an *unregistered* app is DENIED.

    Why `strict` exists. Under `on`, "not in the keystore" means two unrelated
    things at once: "binding is not enabled for this deployment" and "this agent
    is unknown". willow-gate reads the same fact the opposite way — an
    unregistered check-in has no expected signature to compare against and is a
    hard stop (`test_checkin_unregistered_agent_rejected`). While the two halves
    disagree, partial adoption inverts the control's value: registering the
    gatekeeper and leaving the orchestrator unregistered hardens the lesser
    identity and leaves the most privileged one on the unbound path, since
    nothing stops a caller passing a different `app_id`. `on` closes H1 for
    agents that opted in, which is a weaker claim than closing H1.

    `strict` is where the halves finally agree: unknown means refuse, end to
    end. It is a separate position rather than a change to `on` because the
    rollout needs both — register everyone, run `on` and read the receipts, then
    move to `strict` once `list-agents` covers the roster.

    An unrecognized value is refused rather than silently treated as off: a
    typo'd `WILLOW_MCP_ENFORCE_BINDING=stict` must not read as "no enforcement".
    """
    raw = os.environ.get("WILLOW_MCP_ENFORCE_BINDING", "").strip().lower()
    if raw in ("", "0", "false", "no", "off"):
        return "off"
    if raw in ("1", "true", "yes", "on"):
        return "on"
    if raw == "strict":
        return "strict"
    raise ValueError(
        f"WILLOW_MCP_ENFORCE_BINDING={raw!r} is not one of "
        f"off/0/false/no, on/1/true/yes, strict")


def _enforce_binding() -> bool:
    """True when the Phase 3 gate runs at all — `on` or `strict`. Call sites that
    only need "is the gate live" keep using this; the on/strict distinction is
    read inside `_enforce_binding_gate`, which is the one place it changes an
    outcome."""
    return _binding_mode() != "off"


def _authority_check_enabled() -> bool:
    """S1 PDP seam (dispatch E5F2D78B). OFF by default: landing the module must
    not change live gate behavior until an operator flips this on."""
    return os.environ.get("WILLOW_MCP_AUTHORITY_CHECK", "").strip().lower() in (
        "1", "true", "yes", "on")


def _enforce_db_perimeter() -> bool:
    """B2 master switch, read live. OFF by default so this lands without breaking
    any current `allow_db` caller: today's behavior (the `task_db` capability
    check alone) is unchanged until an operator flips this on. ON: local Postgres
    access also needs an operator-signed per-task envelope (`sign-db-task`) — the
    same authority model `allow_net` already has, so a `task_db`-holding app can
    no longer queue arbitrary `psql`. Enabling it presumes the operator has run
    `setup-egress`; with no verifier configured, gated db work fails closed."""
    return os.environ.get("WILLOW_MCP_ENFORCE_DB_PERIMETER", "").strip().lower() in (
        "1", "true", "yes", "on")


def _enforce_mem_ratify() -> bool:
    """B8 master switch, read live. OFF by default so this lands without changing
    any current knowledge-base write: today's behavior (a `knowledge_ingest`/
    `gap_promote`/`nest_promote` caller writes straight into the shared-Postgres
    knowledge base with no tier/quorum/witness check) is byte-for-byte unchanged
    until an operator flips this on. ON: the shared KB is treated as Article IV
    Canon and every core write must clear `mem_ratify.ratify(...)` — the pure,
    stdlib Canon-promotion gate vendored at `willow_mcp.mem_ratify` (canonical
    home: the willow repo). Fail-closed: a write with no independent quorum /
    Operator Key is refused, closing the box-scan B8 hole ("any ACL-holder writes
    straight into shared-Postgres Canon"). This flag mirrors the fleet
    off-by-default enforce-flag convention (`WILLOW_MCP_ENFORCE_DB_PERIMETER`,
    B2). Note the second, independent knob inside mem_ratify itself: even with
    this ON, `WILLOW_MEM_RATIFY_ENFORCE` (the gate's own env var, also default
    OFF) decides whether a denial actually blocks — so flipping this alone still
    only logs an advisory. Both must be ON to block. See mem_ratify/README.md
    "follow-up" for the witness/tier metadata plumbing that makes an enabled gate
    admit legitimate promotions rather than refusing every direct write."""
    return os.environ.get("WILLOW_MCP_ENFORCE_MEM_RATIFY", "").strip().lower() in (
        "1", "true", "yes", "on")


def _mem_ratify_gate(
    app_id: str,
    domain: str,
    source: str,
    *,
    witnesses: "Iterable[object] | None" = None,
) -> Optional[dict]:
    """B8: consult the Article IV Canon-promotion gate for a shared-KB write.

    Returns None to allow (gate not enforced, or the decision does not block),
    or an error dict to refuse. A no-op unless `WILLOW_MCP_ENFORCE_MEM_RATIFY`
    is set — the default path never calls this.

    ``witnesses`` (mem_ratify/README.md follow-up 1-3, now landed as
    ``mem_ratify.collect``): an optional iterable of ``Witness`` instances or
    ``{agent_id, base_model, independence_evidence?}`` dicts, deduped by
    ``agent_id`` and with the proposer refused (§0.2). Default ``None`` /
    ``()`` preserves today's behavior exactly — a bare write with no quorum
    that ratify fail-closes on — so existing callers see no change.

    A bare knowledge write with no witnesses is modeled as what it actually
    is: an attempt to seat an unratified proposal (Contested) straight into
    shared Canon (Canonical) with an empty quorum. `ratify()` fail-closes on
    that, and `Decision.is_blocking()` folds in mem_ratify's own
    `WILLOW_MEM_RATIFY_ENFORCE` knob so a denial blocks only when the
    operator has turned BOTH knobs on; otherwise it is a logged advisory that
    changes nothing. The Decision (reasons/flags/placeholders) is surfaced to
    the caller for the audit trail."""
    # Lazy, local import (kb_ingest-style): mem_ratify is pure stdlib so this is
    # always importable, but importing only inside the enforced branch keeps
    # import-time behavior and the default path provably untouched.
    import logging

    from . import mem_ratify
    from .mem_ratify.collect import coerce_witnesses

    log = logging.getLogger("willow_mcp.server")

    witness_tuple = coerce_witnesses(witnesses, proposer_id=app_id)
    request = mem_ratify.RatifyRequest.build(
        claim_id=f"knowledge_ingest:{app_id}:{domain or 'general'}",
        current_tier=mem_ratify.Tier.CONTESTED,
        target_tier=mem_ratify.Tier.CANONICAL,
        proposer_id=app_id,
        witnesses=witness_tuple,
    )
    decision = mem_ratify.ratify(request)
    detail = {
        "allowed": decision.allowed,
        "reasons": decision.reasons,
        "flags_for_human": decision.flags_for_human,
        "placeholders_relied_on": decision.placeholders_relied_on,
        "enforcing": mem_ratify.enforcement_enabled(),
    }
    if decision.is_blocking():
        log.warning("mem_ratify BLOCKED knowledge write by %s: %s", app_id, decision.reasons)
        return {"error": (
            "mem_ratify_denied: WILLOW_MCP_ENFORCE_MEM_RATIFY and WILLOW_MEM_RATIFY_ENFORCE "
            "are both set, so a write into the shared knowledge base (Article IV Canon) must "
            "clear the mem_ratify promotion gate. This write carries no independent quorum / "
            "Operator Key and was refused, fail-closed."), "mem_ratify": detail}
    if not decision.allowed:
        # Advisory only: enforcement is off on at least one knob, so behavior is
        # unchanged — but the denial is logged loudly per the off-by-default contract.
        log.warning("mem_ratify ADVISORY (not blocking) for knowledge write by %s: %s",
                    app_id, decision.reasons)
    return None


def _enforce_binding_gate(app_id: str, tool_name: str) -> Optional[dict]:
    """Apply the willow-gate binding as a CONTROL (Phase 3, H2), inside _gate and
    only after permitted() has already allowed the tool per the manifest.

    Returns None to allow, or an error dict to deny. Fail-closed on every ambiguous
    path. Records the successful bind receipt itself so the audit line survives;
    denials are receipted by the _guarded wrapper.

    Rule (seam-doc §1 opt-in, D3): under `on`, if the app is *not registered* in
    the keystore this is a no-op — a plain local clone keeps working with
    manifest-only auth and no HMAC ceremony. If it *is* registered, the call must
    carry a valid signed credential whose bound tier is high enough for this
    tool, or it is denied.

    Under `strict`, an unregistered app is DENIED instead, which is the only
    position in which this gate and willow-gate's own check-in agree that an
    unknown identity is refused. See `_binding_mode`."""
    # The check-in call itself carries no per-call credential (there is no session
    # yet) and authenticates via its own header HMAC — exempt it, or enforcement is
    # a bootstrap deadlock. The only exemption.
    if tool_name in _BINDING_BOOTSTRAP_TOOLS:
        return None
    # Distinguish "not registered" (→ manifest-only, unchanged) from "registered
    # but its secret is unreadable/short" (→ load() is None but is_registered() is
    # True). The latter must FAIL CLOSED: waving it through would silently downgrade
    # a registered agent to app_id-only auth — the exact hole binding exists to
    # close. load() alone conflates the two; is_registered() breaks the tie.
    if agent_registry.load(app_id) is None:
        if agent_registry.is_registered(app_id):
            return {"error": (
                f"binding unavailable: '{app_id}' is registered but its secret is "
                f"unreadable or invalid — refusing (fail-closed). An operator must "
                f"repair the keystore ($WILLOW_HOME/gate/secrets/).")}
        if _binding_mode() == "strict":
            return {"error": (
                f"binding required: '{app_id}' is not registered in the keystore "
                f"and WILLOW_MCP_ENFORCE_BINDING=strict refuses unregistered "
                f"identities. Register it (`willow-mcp register-agent {app_id} "
                f"--max-trust N`) or run with =on to allow manifest-only apps.")}
        return None  # genuinely unregistered ⇒ manifest-only (mode 'on')
    cred = _current_call_credential()
    if not cred:
        return {"error": (
            f"binding required: '{app_id}' is a registered agent, so this call must "
            f"carry a signed per-call credential (session_id, call_nonce, sig) supplied "
            f"out-of-band by the client's signing middleware. app_id alone cannot bind.")}
    v = _binder.verify_call(cred.get("session_id", ""), app_id, tool_name,
                            cred.get("call_nonce", ""), cred.get("sig", ""))
    if not v.get("bound"):
        return {"error": f"binding rejected for '{app_id}': {v.get('reason')}"}
    if not tier_policy.tier_permits(v["trust_level"], tool_name,
                                    read_only=v.get("read_only")):
        return {"error": (
            f"tier too low: '{app_id}' is bound at {v['tier']} "
            f"(level {v['trust_level']}), which may not call '{tool_name}'.")}
    _receipt_log.record(app_id, tool_name, "bind_enforced",
                        f"tier={v['tier']} sig=ok")
    return None


def _own_identity_denial(app_id: str, tool_name: str) -> Optional[dict]:
    """Identity proof for the UNGATED self-report tools (whoami / diagnostic_summary).

    Those tools are deliberately not @_guarded — they must answer even when the
    manifest is empty or missing — but that also means they never went through the
    binding gate, so in stdio a caller could pass ANY app_id and read that
    identity's config (permissions/role/store_scope). When binding is ENFORCED,
    route them through the same per-call credential check the gate uses, so a caller
    may only read the identity it can prove it owns; whoami is unclassified, so this
    is identity proof, not a tier gate. No-op when enforcement is off (trusted-host
    single-operator model) or the app_id is unregistered (no bound identity to
    protect) — consistent with how _gate treats every other tool."""
    if not _enforce_binding():
        return None
    return _enforce_binding_gate(app_id, tool_name)


from . import announce as _announce


def _announce_hook(app_id: str, tool: str, outcome: str, detail: Optional[str]) -> None:
    """Phase 5: surface each recorded decision on the operator log at a volume
    graduated by the caller's BOUND trust tier (louder for the less trusted).
    Reads the tier from the live session if there is one, else None (unbound →
    loud). Cheap no-op when WILLOW_MCP_ANNOUNCE is off; never raises (ReceiptLog
    swallows sink errors, and this is guarded besides)."""
    if not _announce.enabled():
        return
    try:
        sess = _binder.session_for(app_id)
        trust = sess["trust_level"] if sess else None
        # Receipt `detail` can carry raw error/exception text (e.g. an
        # integration_call auth failure echoing a bearer token). Inside the box it
        # only ever lived in the receipt DB; the announce sink may be an EXTERNAL
        # ledger (set_sink), so redact credential-shaped substrings before it
        # leaves — the same backstop the tool-result path uses.
        safe_detail = detail
        if detail:
            safe_detail, _kinds = secret_scan.redact_egress(detail)
        _announce.announce(app_id, tool, outcome, trust, safe_detail)
    except Exception:
        import logging
        logging.getLogger("willow_mcp.server").debug(
            "announce hook failed for %s/%s", app_id, tool, exc_info=True)


_receipt_log.on_record = _announce_hook


def _observe_binding(app_id: str, tool_name: str) -> None:
    """Phase 2, OBSERVE-ONLY: log the identity binding for this call — a per-call
    signature if the client supplied one, else the app_id's live check-in tier —
    WITHOUT changing the authorization decision (manifest ACL still governs).
    Must never affect the call: all failures swallowed.

    When enforcement is on, _enforce_binding_gate has already verified the
    per-call credential inside _gate (consuming its single-use nonce and writing
    a bind_enforced receipt), so re-verifying here would only spuriously fail on
    the now-spent nonce. Step aside in that case."""
    if _enforce_binding():
        return
    try:
        cred = _current_call_credential()
        if cred:
            r = _binder.verify_call(cred.get("session_id", ""), app_id, tool_name,
                                    cred.get("call_nonce", ""), cred.get("sig", ""))
            _receipt_log.record(app_id, tool_name, "bind_observed",
                                f"tier={r['tier']} sig=ok" if r.get("bound")
                                else f"unbound: {r.get('reason')}")
            return
        sess = _binder.session_for(app_id)
        if sess is not None:
            _receipt_log.record(app_id, tool_name, "bind_observed",
                                f"session tier={sess['tier']} (no per-call sig)")
    except Exception:
        import logging
        logging.getLogger("willow_mcp.server").debug(
            "binding observer failed for %s/%s", app_id, tool_name, exc_info=True)

def _argv_opt(flag: str) -> Optional[str]:
    """Read `--flag value` or `--flag=value` from sys.argv at import time.

    The FastMCP object, base URL, and OAuth issuer are all built at import —
    before main()'s argparse runs — so the CLI host/port must be resolved here
    or the flags are silently ignored (only the env vars would take effect).
    """
    for i, arg in enumerate(sys.argv):
        if arg == flag and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return None


# Precedence: CLI flag > env var > default.
_PORT = int(_argv_opt("--port") or os.getenv("WILLOW_MCP_PORT", "8765"))
_HOST = _argv_opt("--host") or os.getenv("WILLOW_MCP_HOST", "127.0.0.1")
_DEFAULT_APP_ID = os.environ.get("WILLOW_APP_ID", "")

_SERVE_MODE = "--serve" in sys.argv


def _serve_mode() -> bool:
    """Is this process serving over HTTP+OAuth rather than speaking stdio?

    The value is still `--serve` in argv, still decided once at import — this
    changes nothing about how production picks a mode, and nothing about what
    serve mode then does. What it adds is a *named seam*: every read of serve
    mode that happens at call time goes through this one function, so a test
    can enter the serve branch with
    `monkeypatch.setattr(server, "_serve_mode", lambda: True)`.

    Patching the `_SERVE_MODE` global happens to work today, because each read
    site resolves it as a module global at call time. That is an accident of
    how the reads are currently written, not a property anyone declared: the
    first `from .server import _SERVE_MODE`, default-argument capture, or local
    alias would snapshot it at import and strand the serve branch as untestable
    again — with the tests still green, since they would be patching a name the
    code no longer reads. Routing the reads through an accessor makes the seam
    the thing being maintained.

    The import-time branch below (which FastMCP to build, whether to mount the
    OAuth provider) deliberately keeps reading `_SERVE_MODE` directly. That
    decision is baked into the object graph before any test could patch
    anything; routing it through here would imply an injectability that does
    not exist.
    """
    return _SERVE_MODE


_BASE_URL_ENV = (os.getenv("WILLOW_MCP_URL") or "").strip().rstrip("/")
_BASE_URL = _BASE_URL_ENV if _BASE_URL_ENV else f"http://{_HOST}:{_PORT}"

from .request_context import RequestContextMiddleware

_common_kwargs: dict[str, Any] = dict(
    # Outermost: publishes the per-request context on a ContextVar we own,
    # which is how _read_call_credential reaches `_meta` now that SDK 2.0
    # removed the ambient request contextvar.
    middleware=[RequestContextMiddleware()],
    instructions=(
        "Willow sovereign agent platform (willow-mcp). "
        "FIRST CALL of every session: session_enter(app_id, session_id) — it returns your "
        "entry_mode and, for a dispatched specialist, your assignment. Read the bundled "
        "'session-start' skill for the full lifecycle. "
        "app_id=willow is the human-orchestrator seat (WILLOW_HUMAN_ORCHESTRATOR=1); agents "
        "must use their OWN app_id, never willow, and never pass dispatch_id as willow. "
        "Close a session with session_handoff_write (human path) or handoff_write_v4 (dispatch path). "
        "Core verbs: store/get/search records; kb_ingest / kb_search the knowledge base; "
        "task_submit + task_status for sandboxed Kart execution. "
        "Kart tasks are network-isolated by default: egress needs THREE keys held at once — "
        "the task_net capability in your manifest, the operator's consent.internet, and an "
        "unexpired operator-issued lease (willow-mcp grant-net). No MCP tool can mint a lease; "
        "ask the operator. "
        "Pass app_id on every call — it matches your manifest in $WILLOW_HOME/mcp_apps/<app_id>/manifest.json."
    ),
)

if _SERVE_MODE:
    from .oauth import WillowOAuthProvider
    from .vault import default_vault
    from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
    import pathlib

    _vault = default_vault()
    _willow_home = pathlib.Path(os.environ.get("WILLOW_HOME", pathlib.Path.home() / ".willow"))
    _auth_provider = WillowOAuthProvider(
        token_path=_willow_home / "mcp_token.json",
        base_url=_BASE_URL,
        vault=_vault,
    )
    mcp = MCPServer(
        "willow-mcp",
        **_common_kwargs,
        auth_server_provider=_auth_provider,
        auth=AuthSettings(
            issuer_url=_BASE_URL + "/",
            resource_server_url=_BASE_URL + "/",
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=["willow"],
                default_scopes=["willow"],
            ),
            required_scopes=["willow"],
        ),
    )
    _auth_provider.register_routes(mcp)
else:
    mcp = MCPServer("willow-mcp", **_common_kwargs)


# ── MarkdownAI (mai) tools — vendored from legacy fleet monolith (sap/mai) ──────────────────
# Ten mai_* tools that render/execute @markdownai documents (phases, macros,
# constraints, @env/@db/@http directives). Opt-in: these are ungated filesystem
# tools, so they stay off unless WILLOW_MCP_MARKDOWNAI is set — the same posture
# willow-mcp takes for other non-default surfaces. @db resolves against the same
# WILLOW_PG_* Postgres the knowledge base uses.
if os.environ.get("WILLOW_MCP_MARKDOWNAI", "").strip().lower() in ("1", "true", "yes", "on"):
    from willow_mcp.mai import tools as _mai_tools

    _mai_tools.register(mcp)


# ── Grove tools — agent-side successor to legacy fleet monolith's sap/grove_tools.py ────────
# 20 grove_* tools (13 read + 7 write) giving agents a voice in the fleet's Grove
# messaging room. Registered unconditionally, like store/knowledge/task — Grove
# is a baseline fleet capability, not an opt-in surface like mai. Per-app access
# is still manifest-gated (grove_read/grove_write in gate.PERMISSION_GROUPS);
# registering the tools only decides they exist. See willow_mcp/grove_tools.py
# and willow_mcp/grove.py (data layer) for the DB-name trap: grove.* tables live
# in the fleet's willow_20 database, not this server's default `willow` database.
from willow_mcp import grove_tools as _grove_tools

_grove_tools.register(mcp)


# ── MCP Resources — URI-addressable read-only data (2026-07-28 spec) ──────────
# KB atoms and Store records exposed as MCP Resources: clients fetch them into
# context on demand via resources/list and resources/read. See resources.py
# header and docs/PRIOR_ART.md "Resources (adopt — high priority)".
from willow_mcp import resources as _resources

_resources.register(mcp, _store)


# ── Gate helper ────────────────────────────────────────────────────────────────

def _resolve_serve_identity() -> tuple[Optional[str], Optional[dict]]:
    """Resolve the caller's bound app_id from the authenticated OAuth session.

    Serve-mode identity binding (L-AUTH-02): a Google/Apple sign-in alone
    grants no standing. This reads the session's verified (issuer, subject)
    via the MCP SDK's contextvar-based get_access_token() — never from a
    tool-call argument — and only returns an app_id if a human has separately
    confirmed a binding for that identity (identity_binding.confirm_binding,
    CLI-only). Returns (app_id, None) on success, (None, error_dict) on any
    failure — fail closed at every step, matching an unmanifested app_id's
    behavior in stdio mode.
    """
    from mcp.server.auth.middleware.auth_context import get_access_token

    token = get_access_token()
    if token is None:
        return None, {"error": "gate denied: no authenticated session (serve mode requires OAuth sign-in)"}

    # `idp` — the upstream provider name ("google"/"apple"). Deliberately not
    # `iss`: RFC 9207 reserves that for this server's own issuer URL, and
    # SEP-2468 makes clients MUST-validate it. See docs/design/idp-vs-issuer.md.
    idp = (token.claims or {}).get("idp")
    subject = token.subject
    if not idp or not subject:
        return None, {"error": "gate denied: authenticated session carries no bound identity"}

    bound_app_id = resolve_app_id(idp, subject)
    if not bound_app_id:
        return None, {
            "error": (
                f"gate denied: identity ({idp}, {subject}) is signed in but not yet bound to an "
                "app_id — ask the operator to run `willow-mcp confirm-binding` for this identity"
            )
        }
    return bound_app_id, None


def _gate(app_id: str, tool_name: str) -> tuple[Optional[str], Optional[dict]]:
    """Resolve the effective app_id and check permission.

    Returns (effective_app_id, None) on success, (None, error_dict) on denial.

    Serve mode (HTTP + OAuth): the effective app_id comes ONLY from the
    authenticated session's confirmed identity binding — the tool call's own
    app_id argument is never trusted for authorization purposes here (that
    was L-AUTH-02: previously any signed-in caller could self-declare any
    app_id and get whatever that manifest permitted).

    Stdio mode (default): unchanged — app_id comes from the tool call, same
    single-operator trust model as before.
    """
    if _serve_mode():
        effective, err = _resolve_serve_identity()
        if err:
            return None, err
    else:
        effective = app_id or _DEFAULT_APP_ID

    # A malformed app_id names no manifest — say so, rather than building a
    # (possibly traversal-looking) path string out of it and reporting a generic
    # "not permitted". An invalid id is rejected on its shape, not on ACL.
    from . import gate
    if not gate.valid_app_id(effective):
        return None, {
            "error": (
                f"invalid app_id: {effective!r} — an app_id must match "
                r"[a-zA-Z0-9_-]{1,64} (no path separators or dots)."
            )
        }

    if _authority_check_enabled():
        from . import authority as _authority

        decision = _authority.authority_check(
            principal=effective,
            action=_authority.ACTION_MCP_TOOL,
            resource=tool_name,
            context={},
        )
        if not decision.allowed:
            detail = decision.reason
            if decision.missing_authority:
                detail = f"{detail} (missing authority: {decision.missing_authority})"
            return None, {"error": f"authority denied: {detail}"}
    elif not permitted(effective, tool_name):
        return None, {
            "error": (
                f"gate denied: '{effective}' not permitted for '{tool_name}'. "
                f"Ensure a manifest exists at $WILLOW_HOME/mcp_apps/{effective}/manifest.json "
                f"and lists this tool or a group that includes it."
            )
        }

    # willow-gate binding ceiling (Phase 3, H2): the manifest allowed the tool;
    # now apply the *bound trust tier* on top of it. No-op unless enforcement is on
    # AND the app is registered (seam-doc D3) — see _enforce_binding_gate.
    if _enforce_binding():
        bind_err = _enforce_binding_gate(effective, tool_name)
        if bind_err:
            return None, bind_err

    from .human_session import orchestrator_write_denial

    human_denial = orchestrator_write_denial(
        effective,
        tool_name,
        serve_mode=_serve_mode(),
        session_id=_current_orchestrator_session(),
    )
    if human_denial:
        return None, {"error": human_denial}

    return effective, None


# ── Schema-adapted knowledge reads (docs/design/schema-adaptation.md §9 step 2) ─

# Canonical fields the `knowledge` read tools speak in — matches the §3.2
# example exactly. Not every host `knowledge` table will have all of these;
# unmapped ones are simply omitted from results (§3.3), never crash a read.
from ._kb_sql import KNOWLEDGE_FIELDS as _KNOWLEDGE_FIELDS
from ._kb_sql import build_select as _build_select
from ._kb_sql import row_to_dict as _row_to_dict

# Canonical fields the `tasks` tools speak in (§9 step 5). The real production
# table is named `tasks`, not `kart_task_queue`. The worker-production migration
# (docs/schema/tasks-worker-production.sql) added `steps` and `completed_at` as
# real columns, so both now map directly — `completed_at` is stamped only on the
# terminal transition, not on every update the way `updated_at` would be.
_TASK_FIELDS = [
    "task_id",
    "task",
    "submitted_by",
    "network_authorization",
    "db_authorization",
    "agent",
    "lane",
    "status",
    "result",
    "steps",
    "created_at",
    "completed_at",
    "claim_owner",
    "claimed_at",
    "attempts",
    "max_attempts",
    "retry_at",
]
_TASK_READ_FIELDS = [
    field for field in _TASK_FIELDS
    if field not in ("network_authorization", "db_authorization")
]

# Registry of tables schema_confirm_mapping knows how to confirm, and the
# canonical fields each one speaks in. Extend this when a new table gets a
# schema-adapted write path.
_CONFIRMABLE_TABLES: dict[str, list[str]] = {
    "knowledge": _KNOWLEDGE_FIELDS,
    "tasks": _TASK_FIELDS,
}


def _require_confirmed(mapping: dict) -> Optional[dict]:
    """§3.4: writes may not guess. A mapping's heuristic fields are fine for
    reads but must be explicitly confirmed (schema_confirm_mapping) before
    any write tool may use them."""
    if not mapping.get("confirmed"):
        return {
            "error": (
                f"unconfirmed_schema: table '{mapping.get('table')}' has not been confirmed "
                "for this database — call schema_confirm_mapping, or edit the mapping file "
                "directly, then retry"
            )
        }
    return None


def _postgres_unavailable() -> dict:
    """Shared 'no Postgres connection' response for every knowledge_*/task_*/
    fleet_* tool that needs one. `error` stays the bare code some callers
    string-match on (the nest-promotion batch-abort check does
    `res["error"] in ("postgres_unavailable",)`); `detail` carries the
    actionable half, reusing the phrasing diagnostic_summary's own Postgres
    check already has, rather than the 15+ call sites each inventing (or
    not inventing) their own."""
    return {
        "error": "postgres_unavailable",
        "detail": (
            "Postgres is not reachable (unix socket connection failed) — "
            "knowledge_*/task_*/fleet_* degrade until it's back. Run "
            "diagnostic_summary for current status, or start your Postgres "
            "cluster and retry."
        ),
    }


def _write_param(field_mapping: dict, value):
    """jsonb/json target columns need their Python value wrapped so psycopg2
    adapts it as JSON rather than a plain string."""
    if field_mapping.get("data_type") in ("jsonb", "json"):
        return Json(value)
    return value


# ── Sanitizer (Phase 4a) ─────────────────────────────────────────────────────

_MAX_BLOB_BYTES = 512 * 1024   # record / context dicts
_MAX_STR_BYTES = 64 * 1024     # content / task / query strings
_MAX_TAGS = 32
_MAX_TAG_LEN = 128
_PATH_TRAVERSAL_RE = re.compile(r"\.\.|[/\\]")


def _strip_nulls(obj):
    """Recursively remove NUL bytes from every string in a JSON-ish structure.

    NUL has no legitimate place in stored text and truncates C-string consumers
    downstream (and glitches some renderers), so strip it wherever it hides — not
    only in the reserved top-level string keys below. Values only; a NUL in a key
    is pathological and left alone rather than risk a key collision on removal."""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {k: _strip_nulls(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_nulls(v) for v in obj]
    return obj


def _sanitize(kwargs: dict) -> tuple[dict, Optional[str]]:
    """Clean known-risky fields by name, regardless of which tool they belong to.

    Returns (cleaned_kwargs, None) on success, or (kwargs, error_message) if a
    field fails validation outright (caller denies the call — no partial writes).
    """
    for key in ("record", "context", "value", "body"):
        val = kwargs.get(key)
        if isinstance(val, dict):
            size = len(json.dumps(val))
            if size > _MAX_BLOB_BYTES:
                return kwargs, f"'{key}' exceeds 512KB limit ({size} bytes)"
            # Strip NULs from every nested string, not just the reserved keys.
            kwargs[key] = _strip_nulls(val)

    for key in ("content", "task", "query", "question", "answer", "topic"):
        val = kwargs.get(key)
        if isinstance(val, str):
            cleaned = val.replace("\x00", "")
            encoded = cleaned.encode("utf-8")
            if len(encoded) > _MAX_STR_BYTES:
                cleaned = encoded[:_MAX_STR_BYTES].decode("utf-8", errors="ignore")
            kwargs[key] = cleaned

    collection = kwargs.get("collection")
    if isinstance(collection, str) and _PATH_TRAVERSAL_RE.search(collection):
        return kwargs, "'collection' contains illegal path characters"

    for key in ("tags", "sources"):
        items = kwargs.get(key)
        if isinstance(items, list):
            if len(items) > _MAX_TAGS:
                return kwargs, f"'{key}' exceeds max {_MAX_TAGS} items"
            for item in items:
                if isinstance(item, str) and len(item) > _MAX_TAG_LEN:
                    return kwargs, f"'{key}' item exceeds max {_MAX_TAG_LEN} chars"

    return kwargs, None


# ── Current orchestrator session (P2, #186) ──────────────────────────────────
# The human-orchestrator write gate (human_session.orchestrator_write_denial)
# checks PGP attestation on `sessions/willow-{session_id}.json` when PGP is
# enabled. Orchestrator write tools (dispatch_send, verify_handoff, ...) don't
# all carry a session_id argument, so per-call attestation can't be checked
# from call_kwargs alone -- instead session_enter (the documented FIRST CALL
# of every session) records the session_id it bound as app_id=willow here, and
# _gate reads it back for every subsequent orchestrator-write check in this
# process. In-process/single-operator, matching _buckets below.

_orchestrator_session_lock = threading.Lock()
_orchestrator_session_id: str = ""


def _set_orchestrator_session(session_id: str) -> None:
    global _orchestrator_session_id
    with _orchestrator_session_lock:
        _orchestrator_session_id = session_id or ""


def _current_orchestrator_session() -> str:
    with _orchestrator_session_lock:
        return _orchestrator_session_id


# ── Rate limiter (Phase 4b) ──────────────────────────────────────────────────

class _Bucket:
    __slots__ = ("tokens", "last_refill")

    def __init__(self, tokens: float, last_refill: float):
        self.tokens = tokens
        self.last_refill = last_refill


_buckets: dict[str, _Bucket] = {}
_buckets_lock = threading.Lock()
_RATE = 60.0    # tokens per minute
_BURST = 10.0   # bucket capacity


def _check_rate(app_id: str) -> tuple[bool, int]:
    """Token bucket, in-process, no external dependency.

    Single-operator assumption matches the rest of the package — a
    multi-process deploy can swap this for a pluggable backend later.
    Returns (allowed, retry_after_seconds).
    """
    now = time.monotonic()
    with _buckets_lock:
        bucket = _buckets.get(app_id)
        if bucket is None:
            bucket = _Bucket(tokens=_BURST, last_refill=now)
            _buckets[app_id] = bucket
        elapsed = now - bucket.last_refill
        bucket.tokens = min(_BURST, bucket.tokens + elapsed * (_RATE / 60.0))
        bucket.last_refill = now
        if bucket.tokens < 1.0:
            deficit = 1.0 - bucket.tokens
            retry_after = max(1, math.ceil(deficit / (_RATE / 60.0)))
            return False, retry_after
        bucket.tokens -= 1.0
        return True, 0


# ── Guarded dispatch (Phase 4a+4b+4c combined) ───────────────────────────────

def _guarded(tool_name: str, *, list_error: bool = False, paginated: bool = False):
    """Central pipeline: gate -> sanitize -> rate check -> dispatch -> receipt.

    Gate runs first (B-16) so an unpermitted caller gets a clean permission
    denial as the very first signal, rather than a sanitizer error for a call
    it was never allowed to make. Gate also validates the app_id shape (via
    gate.permitted -> _validate_app_id), so an invalid/unmanifested app_id is
    rejected before it can reach _sanitize or ever be used as a _buckets dict
    key — an unvalidated app_id string must never reach _check_rate, or a
    caller can grow _buckets unbounded with arbitrary strings (L-DOS-01).

    list_error=True for tools whose declared return type is list so a denial
    comes back list-wrapped, matching the tool's own success-path shape.
    paginated=True for tools that return {items, next_cursor} dicts — errors
    are wrapped in that same shape so callers see a consistent structure.
    """
    def decorator(fn):
        sig = inspect.signature(fn)

        @wraps(fn)
        def wrapper(*args, **kwargs):
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            call_kwargs = dict(bound.arguments)
            app_id = call_kwargs.get("app_id", "") or _DEFAULT_APP_ID

            def _shape(err: dict):
                if paginated:
                    return {"items": [err], "next_cursor": None}
                return [err] if list_error else err

            # effective_app_id is the identity gate actually authorized this
            # call under — in serve mode this is the bound identity, NOT
            # necessarily call_kwargs["app_id"] (see _gate / L-AUTH-02). Every
            # downstream step (sanitize, rate limit, dispatch, receipt) uses it
            # instead of the raw caller-supplied app_id.
            #
            # Gate runs BEFORE sanitize (B-16): an unpermitted caller is denied
            # up front, so it never reaches the sanitizer. A denial is the first
            # signal, not a sanitize error for a call that was never allowed.
            effective_app_id, gate_err = _gate(app_id, tool_name)
            if gate_err:
                _receipt_log.record(app_id, tool_name, "denied", gate_err.get("error"))
                return _shape(gate_err)
            if "app_id" in call_kwargs:
                call_kwargs["app_id"] = effective_app_id

            # Phase 2 (observe-only): log the identity binding; does not gate.
            _observe_binding(effective_app_id, tool_name)

            # Third gate check (guardian-consent seam): after capability consent
            # (gate.permitted) comes SUBJECT consent — did this non-owner person
            # agree to this scope? Composed by AND, never around. Inert for every
            # tool that carries no `subject_id` (all of them today); it activates
            # the instant a subject-touching tool grows that parameter. A denial
            # is fail-closed, and even an *error* inside the check denies rather
            # than passes — a gate that crashes open is not a gate.
            subject_id = call_kwargs.get("subject_id")
            if subject_id:
                try:
                    from . import subject_consent_binding
                    subj_err = subject_consent_binding.subject_gate(
                        effective_app_id, tool_name, subject_id
                    )
                except Exception as e:  # deny on failure, never fall through open
                    subj_err = {"error": f"subject_consent_check_failed: {e}"}
                if subj_err:
                    _receipt_log.record(
                        effective_app_id, tool_name, "denied", subj_err.get("error")
                    )
                    return _shape(subj_err)

            collection = call_kwargs.get("collection")
            if (
                isinstance(collection, str)
                and ".." not in collection
                and "\\" not in collection
            ):
                resolved, alias_error = resolve_collection_alias(
                    effective_app_id, collection
                )
                if alias_error:
                    _receipt_log.record(
                        effective_app_id,
                        tool_name,
                        "error",
                        alias_error,
                    )
                    return _shape({"error": alias_error})
                call_kwargs["collection"] = resolved

            cleaned, problem = _sanitize(call_kwargs)
            if problem:
                _receipt_log.record(effective_app_id, tool_name, "error", f"sanitize: {problem}")
                return _shape({"error": f"sanitize: {problem}"})
            call_kwargs = cleaned

            allowed, retry_after = _check_rate(effective_app_id)
            if not allowed:
                _receipt_log.record(effective_app_id, tool_name, "rate_limited", f"retry_after={retry_after}")
                return _shape({"error": "rate_limited", "retry_after": retry_after})

            try:
                result = fn(**call_kwargs)
            except Exception as e:
                _receipt_log.record(effective_app_id, tool_name, "error", f"{type(e).__name__}: {e}")
                raise

            probe = (result[0] if (isinstance(result, list) and result
                                    and isinstance(result[0], dict)) else result)
            if isinstance(probe, dict) and "error" in probe:
                _receipt_log.record(effective_app_id, tool_name, "error", str(probe["error"]))
            else:
                _receipt_log.record(effective_app_id, tool_name, "ok", None)

            # Egress secret redaction (defense-in-depth for the README
            # guarantee "No tool ever returns a credential"). Enforced at this
            # single funnel so a credential smuggled through the DATA path — a
            # stored record, a KB atom, task output, an integration response
            # body — is redacted before it leaves, not just the accessor.
            # Fail-closed: if the scanner itself breaks, deny the payload rather
            # than risk returning it unscanned (ARCHITECT.md: never fail open).
            #
            # The scan runs regardless so the audit trail is complete; an
            # operator-declared per-manifest exemption (gate.egress_secret_exempt
            # — e.g. an integration_call doing an OAuth token exchange that must
            # return the token) suppresses the redaction but is itself receipted
            # as `credential_returned`, so the exception is loud, never silent.
            try:
                scanned, redacted_kinds = secret_scan.redact_egress(result)
            except Exception as e:
                _receipt_log.record(effective_app_id, tool_name, "error",
                                    f"egress_scan_failed: {type(e).__name__}")
                return _shape({"error": "egress_scan_failed"})
            if redacted_kinds:
                from . import gate
                if gate.egress_secret_exempt(effective_app_id, tool_name):
                    # Operator-sanctioned raw return — keep `result` unredacted,
                    # but record that a credential left under the exemption.
                    _receipt_log.record(effective_app_id, tool_name, "credential_returned",
                                        "exempt kinds=" + ",".join(redacted_kinds))
                else:
                    result = scanned
                    # Payload-free: record WHICH kinds were redacted, never the value.
                    _receipt_log.record(effective_app_id, tool_name, "redacted",
                                        "kinds=" + ",".join(redacted_kinds))

            return result

        return wrapper
    return decorator


# ── Store tools ────────────────────────────────────────────────────────────────
#
# Collection-level scoping (B-24 / SECURITY_AUDIT.md L-ISO-01): the SOIL store
# shares the wider Willow fleet's store by default (WILLOW_STORE_ROOT) — a
# default, not a design commitment; point it elsewhere and diagnostic_summary's
# `severance` check confirms the cut — store_* tools have no isolation unless
# an app's manifest opts in via a `store_scope` list (gate.store_scope /
# gate.collection_permitted). Unscoped apps keep today's unrestricted access;
# this only closes the gap for apps an operator explicitly chooses to confine.

# MCP tool annotations — single import from annotations.py so all three
# tool-hosting modules share one definition.
from willow_mcp.annotations import (          # noqa: E402
    ANNO_READ as _ANNO_READ,
    ANNO_READ_OPEN as _ANNO_READ_OPEN,
    ANNO_WRITE as _ANNO_WRITE,
    ANNO_WRITE_IDEM as _ANNO_WRITE_IDEM,
    ANNO_DESTRUCTIVE as _ANNO_DESTRUCTIVE,
    ANNO_WRITE_OPEN as _ANNO_WRITE_OPEN,
)


def _collection_denied(app_id: str, collection: str) -> dict:
    return {"error": (
        f"collection_denied: '{collection}' is outside this app's store_scope "
        f"in $WILLOW_HOME/mcp_apps/{app_id or '<app_id>'}/manifest.json")}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("store_put")
def store_put(
    app_id: str,
    collection: str,
    record: dict,
    record_id: Optional[str] = None,
    deviation: float = 0.0,
) -> dict:
    """Write a JSON record to a named SOIL collection (created on first write).
    Pass `record_id` to pin a stable ID — re-putting the same ID overwrites the
    record; omit it to auto-generate one. `deviation` (radians) declares how far
    this write departs from established pattern: >= 0.785 is recorded as 'flag',
    >= 1.571 as 'stop', otherwise 'work_quiet'. Returns {id, action}. Confined
    to the collections in your manifest's store_scope."""
    from . import gate
    if not gate.collection_permitted(app_id, collection):
        return _collection_denied(app_id, collection)
    rid, action = _store.put(collection, record, record_id=record_id, deviation=deviation)
    return {"id": rid, "action": action}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("store_get")
def store_get(app_id: str, collection: str, record_id: str) -> dict:
    """Read one record from a SOIL collection by its exact ID. Returns the
    stored record plus _id/_created/_updated/_deviation/_action metadata, or
    {error: not_found} if the ID is absent or soft-deleted. Read-only; confined
    to your store_scope."""
    from . import gate
    if not gate.collection_permitted(app_id, collection):
        return _collection_denied(app_id, collection)
    item = _store.get(collection, record_id)
    return item or {"error": "not_found"}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("store_list", paginated=True)
def store_list(app_id: str, collection: str,
               limit: int = 50, cursor: Optional[str] = None) -> dict:
    """Return live records in one SOIL collection, oldest first, each with
    _id/_created/_updated metadata.  Paginated: returns ``{items, next_cursor}``
    — pass the returned ``next_cursor`` as ``cursor`` to fetch the next page
    (``next_cursor`` is ``null`` on the last page).  ``limit`` caps page size
    (default 50).  Use store_search for filtered results, store_collections
    to discover collection names. Read-only; confined to your store_scope."""
    from . import gate
    if not gate.collection_permitted(app_id, collection):
        return {"items": [_collection_denied(app_id, collection)], "next_cursor": None}
    items, next_cursor = _store.all_paginated(collection, limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("store_update")
def store_update(
    app_id: str,
    collection: str,
    record_id: str,
    record: dict,
    deviation: float = 0.0,
) -> dict:
    """Replace an existing record's data in-place — same ID, updated_at bumped,
    audit metadata retained. Never creates: an unknown ID returns
    {error: not_found} (use store_put to create). `deviation` declares
    pattern-departure exactly as in store_put. Returns {id} on success.
    Confined to your store_scope."""
    from . import gate
    if not gate.collection_permitted(app_id, collection):
        return _collection_denied(app_id, collection)
    rid = _store.update(collection, record_id, record, deviation=deviation)
    return {"id": rid} if rid else {"error": "not_found"}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("store_search", paginated=True)
def store_search(app_id: str, collection: str, query: str,
                 limit: int = 50, cursor: Optional[str] = None) -> dict:
    """Full-text search one SOIL collection: the query is split on whitespace
    and EVERY token must appear somewhere in a record's JSON (AND logic,
    substring match).  Paginated: returns ``{items, next_cursor}`` — pass the
    returned ``next_cursor`` as ``cursor`` to fetch the next page.  An empty
    query returns ``{items: [], next_cursor: null}``.  Read-only; confined to
    your store_scope."""
    from . import gate
    if not gate.collection_permitted(app_id, collection):
        return {"items": [_collection_denied(app_id, collection)], "next_cursor": None}
    items, next_cursor = _store.search_paginated(collection, query, limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor}


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("store_delete")
def store_delete(app_id: str, collection: str, record_id: str) -> dict:
    """Soft-delete one record by ID: it disappears from get/list/search but is
    retained on disk for audit and recovery (hard removal is an operator act,
    deliberately outside the tool surface). Returns {deleted: true|false} —
    false means the ID wasn't found. Confined to your store_scope."""
    from . import gate
    if not gate.collection_permitted(app_id, collection):
        return _collection_denied(app_id, collection)
    deleted = _store.delete(collection, record_id)
    return {"deleted": deleted}


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("store_purge_collection")
def store_purge_collection(app_id: str, collection: str, confirm: str = "") -> dict:
    """Soft-delete EVERY record in a collection at once — a bulk store_delete,
    for clearing out a whole collection (e.g. leftover test/scratch data).
    Archive, not drop: records are retained (deleted=1) and stay recoverable,
    they just fall out of get/list/search, matching the store's soft-delete
    model. The collection's store.db is never removed — hard removal is an
    operator/filesystem act, deliberately outside the tool surface. Guarded
    against fat-finger accidents: pass confirm=<collection name> to proceed.
    Confined to your store_scope like every other store_* tool."""
    from . import gate
    if not collection:
        return {"error": "collection is required"}
    if not gate.collection_permitted(app_id, collection):
        return _collection_denied(app_id, collection)
    if confirm != collection:
        return {"error": "confirm_required",
                "detail": f"pass confirm='{collection}' to purge all records in "
                          f"'{collection}' — a bulk soft-delete (reversible)"}
    purged = _store.purge_collection(collection)
    return {"purged": purged, "collection": collection}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("store_search_all", paginated=True)
def store_search_all(app_id: str, query: str,
                     limit: int = 50, cursor: Optional[str] = None) -> dict:
    """Token-AND search across every SOIL collection you can see — all of them,
    or only your manifest's store_scope if one is set. Each hit carries a
    _collection field naming where it was found.  Paginated: returns
    ``{items, next_cursor}`` — pass the returned ``next_cursor`` as ``cursor``
    to fetch the next page.  Use when you don't know which collection holds
    the data; prefer store_search when you do. Read-only."""
    from . import gate
    items, next_cursor = _store.search_all_paginated(
        query, scope=gate.store_scope(app_id), limit=limit, cursor=cursor,
    )
    return {"items": items, "next_cursor": next_cursor}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("store_collections")
def store_collections(app_id: str) -> dict:
    """List the SOIL collections you can see — every collection under the store,
    narrowed to your `store_scope` if your manifest sets one. Answers "what's in
    the store" without running a search (store_list needs a collection name;
    this is how you learn the names). Returns the collection names, a count, and
    the scope that was applied (null = unrestricted within this store)."""
    from . import gate
    scope = gate.store_scope(app_id)
    names = _store.list_collections(scope=scope)
    return {"collections": names, "count": len(names), "store_scope": scope}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("store_stats")
def store_stats(app_id: str) -> dict:
    """Per-collection live-record counts for the collections you can see
    (narrowed to your store_scope) — the numeric companion to store_collections.
    Counts only live records (soft-deleted ones don't show). Returns each
    collection with its count (largest first), plus store-wide totals — handy
    for spotting a polluted or runaway collection before deciding what to purge."""
    from . import gate
    scope = gate.store_scope(app_id)
    stats = _store.stats(scope=scope)
    return {
        "collections": stats,
        "total_collections": len(stats),
        "total_records": sum(s["count"] for s in stats),
        "store_scope": scope,
    }


# ── Lineage / provenance tools ─────────────────────────────────────────────────

def _lineage_denied(app_id: str):
    """Recording touches both the node and edge collections; querying reads
    both. Require permission on each rather than only the node collection."""
    from . import gate
    for col in (_lineage.collection, _lineage.edges):
        if not gate.collection_permitted(app_id, col):
            return _collection_denied(app_id, col)
    return None


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("lineage_record")
def lineage_record(
    app_id: str,
    id: str,
    title: str,
    rationale: str,
    origin: str = "",
    authority: str = "",
    evidence: Optional[list] = None,
    tags: Optional[list] = None,
    supersedes: Optional[list] = None,
    derived_from: Optional[list] = None,
    motivated_by: Optional[list] = None,
    subject_id: str = "",
) -> dict:
    """Record a provenance atom — the "story of this willow" as memory an agent
    can query later. Answers the questions agents keep asking: where did this
    come from, why is it this way, what was here before. `rationale` (the WHY)
    and at least one `evidence` citation (a PR / commit / file / session) are
    REQUIRED — an atom that can't cite is lore, not memory, and is refused.

    Relationships to other atoms are typed EDGES (stored in `lineage_edges`, the
    same {from,to,relation,context} shape willow's own knowledge graph uses), and
    direction is QUERIED, not stored twice:
      - `supersedes`   — atoms this REPLACES (the old ones become non-current)
      - `derived_from` — atoms this CAME FROM but did NOT retire (both stay valid)
      - `motivated_by` — the friction/decision behind it (may be a gap id or an
                         external node, not only another atom)
    Corrections re-record the same `id` in place; edges persist independently.
    Confined to your store_scope like every store write.

    `subject_id` (guardian-consent seam): a provenance atom that makes a
    person-shaped claim about a *non-owner* names that subject here. This is the
    highest bar in the seam — `person_inference` — corpus-lens's quarantined
    PERSON_CLAIM_TYPES: making the claim at all requires a verified grant. Opaque,
    never stored on the atom. Leave empty for the owner or for non-person lineage."""
    denied = _lineage_denied(app_id)
    if denied:
        return denied
    result = _lineage.record(id=id, title=title, rationale=rationale, origin=origin,
                             authority=authority, evidence=evidence, tags=tags,
                             supersedes=supersedes, derived_from=derived_from,
                             motivated_by=motivated_by)
    if isinstance(result, dict) and not result.get("error"):
        _subject_disclose(subject_id, "lineage_record", f"atom={id}")
    return result


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("lineage_link")
def lineage_link(app_id: str, from_id: str, to_id: str, relation: str,
                 context: str = "") -> dict:
    """Add one provenance edge without (re)writing a node — e.g. mark an atom
    `motivated_by` a gap discovered after the fact, or `derived_from` a source
    you only now connected. `relation` is free-form; the `why` verb reads
    supersedes / derived_from / motivated_by. Idempotent per (from, relation, to)."""
    denied = _lineage_denied(app_id)
    if denied:
        return denied
    return _lineage.link(from_id, to_id, relation, context)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("lineage_why")
def lineage_why(app_id: str, query: str) -> dict:
    """Answer "why does X exist / where did X come from" from recorded lineage.
    Give a slug id or free text; returns the matching atom's rationale, origin,
    authority, and evidence, PLUS its typed edges — what it supersedes (and
    whether it is itself still current), what it was derived_from, and what
    motivated it — the lineage, not a blob. A plain-language `answer` synthesizes
    it. This is the verb a curious agent runs before acting on something it
    didn't build."""
    denied = _lineage_denied(app_id)
    if denied:
        return denied
    return _lineage.why(query)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("lineage_list")
def lineage_list(app_id: str, current_only: bool = False,
                 limit: int = 50, cursor: Optional[str] = None) -> dict:
    """List recorded lineage atoms (id, title, whether current, tags) — the index
    of "what parts of this willow have a recorded story". Paginated: returns
    ``{items, next_cursor}``.  Pass current_only=True to hide atoms that a
    later ``supersedes`` edge has retired."""
    denied = _lineage_denied(app_id)
    if denied:
        return {"items": [denied], "next_cursor": None}
    return _lineage.list_atoms(current_only=current_only, limit=limit, cursor=cursor)


# ── Friction floor (relationship smoke detector) ────────────────────────────────

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("friction_scan")
def friction_scan(app_id: str, turns: list, window: int = 4, floor: float = 0.35) -> dict:
    """Scan a transcript window for the mirror failure mode: the agent has stopped
    being *other* and is reflecting the user back, smoothed, WHILE the user is
    escalating. Model-free and deterministic — no LLM, no egress; it NEVER blocks,
    it only flags. When a window of agent turns sits below the friction `floor`
    during escalation it raises (and persists, deduped) a loud human-facing flag
    naming where the agent stopped disagreeing.

    `turns`: [{"role": "user"|"agent", "text": str, "ts"?: number}, …] — the recent
    window, in order. It is a SIGNAL, not a verdict (false-positives happen; a
    clever mirror can duck it); its value is observability. It MUST be driven from
    OUTSIDE the watched model (a harness/monitor) — a mirror cannot audit itself;
    an agent scanning its own turns is theater."""
    from . import gate
    if not gate.collection_permitted(app_id, _friction.collection):
        return _collection_denied(app_id, _friction.collection)
    return _friction.scan(turns, window=window, floor=floor)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("friction_flags_list", list_error=True)
def friction_flags_list(app_id: str, limit: int = 20) -> list:
    """List recent friction flags recorded by `friction_scan` — the durable trace
    of when the relationship watcher tripped (most recent first)."""
    from . import gate
    if not gate.collection_permitted(app_id, _friction.collection):
        return [_collection_denied(app_id, _friction.collection)]
    return _friction.list_flags(limit=limit)


# ── Nestor tool oracle (natural-language → willow verb) ──────────────────────────

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("nestor_tool_route")
def nestor_tool_route(app_id: str, query: str) -> dict:
    """Route a natural-language intent to the willow-mcp verb that serves it.
    Returns status='served' with the resolved `tool` ONLY when a human-sealed
    phrasing clears the match threshold; otherwise status='queued' (the intent is
    logged for a human to seal) — it never guesses a verb. status='unavailable'
    when the optional Nestor engine isn't installed. Read-oriented, but every
    route leaves a hash-chained ledger trail like any other served answer.
    Backed by a signed catalog that is integrity-checked before it is trusted."""
    from . import tool_oracle
    return tool_oracle.route(query)


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("nestor_tool_seal")
def nestor_tool_seal(app_id: str, surface: str, tool: str) -> dict:
    """Teach the oracle: sanction that natural-language `surface` maps to willow
    verb `tool`. This is a GOVERNANCE WRITE — it seals a verified pair (signed,
    ledgered) that nestor_tool_route will then serve, so the `tool_oracle_seal`
    group is meant for human/attested seats only: sealing a phrasing mints
    invocation power for it. The counter-verb to a queued route; your app_id is
    recorded as the verifier."""
    from . import tool_oracle
    return tool_oracle.seal(surface, tool, verifier=app_id)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("nestor_tool_pending", list_error=True)
def nestor_tool_pending(app_id: str, limit: int = 20) -> list:
    """The teach-queue: natural-language intents nestor_tool_route couldn't serve,
    newest first, deduped by phrasing — what a human should seal (or reject) so
    the oracle learns them. Empty when every routed intent has a sealed home."""
    from . import tool_oracle
    return tool_oracle.pending(limit=limit)


# ── Identity binding (willow-gate seam — check-in / check-out) ───────────────────

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("session_bind")
def session_bind(app_id: str, header: dict) -> dict:
    """Open a cryptographically-bound session (check-in). Provide a 13-field
    HMAC-signed `header` whose `agent_id` equals your app_id; the server verifies
    it against your operator-registered secret and caps the claimed `trust_level`
    at your registered ceiling ("Elder is not a text field anyone can type").
    Returns {session_id, agent_id, trust_level, tier}, or {error} on refusal.

    Once bound, the tier is LOGGED on your subsequent calls (receipt
    `bind_observed`). With `WILLOW_MCP_ENFORCE_BINDING` on it is also ENFORCED —
    each call must carry a valid per-call signature and clear the tier ceiling
    (Phase 3). Registration/rotation of the secret is operator/CLI-only
    (`willow-mcp register-agent`); no MCP tool can mint one — the sudo invariant."""
    if isinstance(header, dict) and header.get("agent_id") not in (None, app_id):
        return {"error": "agent_id_mismatch", "detail": "header agent_id must equal app_id"}
    try:
        return _binder.check_in(header)
    except BindError as e:
        return {"error": "bind_refused", "detail": str(e)}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("session_reconcile")
def session_reconcile(app_id: str, session_id: str, exit_declaration: dict) -> dict:
    """Close a bound session and reconcile what you DECLARE you did against what the
    receipt log shows you actually did (check-out; willow-gate seam Phase 4 / H3).

    `exit_declaration` is the reconciled subset of the entry header — `tools` (the
    willow-gate CLASSES you exercised: read/write/execute/admin), plus your
    self-scored `pass_count`/`fail_count`/`drift`/`state_hash`. The server sources
    the ground truth from ReceiptLog (every gated call that actually ran since your
    check-in — you cannot feed it), classifies those tools, and diffs:
      * `claimed_not_done` — a class you claim you used that NO receipt backs;
      * `beyond_entry` / `done_not_claimed` — a privileged class the receipts show
        you used that you did not pre-declare / did not report.
    `clean` is false if any privileged discrepancy is found; read-level over/under-
    reporting is surfaced but never fails the session. The session is DROPPED after
    this call (its per-call nonce set is freed), so verify_call for it then fails.

    Requires a live session bound to your app_id (call session_bind first); returns
    {error} if there is none. This RECONCILES and records — it never blocks a
    handoff, so run session_handoff_write / handoff_write_v4 as usual alongside it."""
    # Ownership-scoped: session_started_ts returns None unless this session is
    # bound to THIS app_id, so a caller cannot even window another agent's session.
    started = _binder.session_started_ts(session_id, app_id=app_id)
    if started is None:
        return {"error": "no_live_session",
                "detail": "no live bound session for session_id — call session_bind first"}
    # Before trusting the log as ground truth, verify its hash chain (B12). A
    # same-uid process could delete the very rows that would show out-of-band use;
    # an unverified log then under-reports and the diff reads clean. A broken chain
    # means the audit trail was modified out of band, so the session cannot be
    # reconciled clean — surface it loudly instead of passing on tampered ground.
    integrity = _receipt_log.verify()
    if not integrity.get("ok"):
        _receipt_log.record(
            app_id, "session_reconcile", "reconcile_discrepancy",
            f"receipt_chain_broken at id={integrity.get('broken_at')} "
            f"({integrity.get('reason')})")
        return {"error": "receipt_integrity_failed", "clean": False,
                "detail": (
                    "the receipt log's hash chain is broken at id "
                    f"{integrity.get('broken_at')} ({integrity.get('reason')}); the "
                    "actual-tools ground truth cannot be trusted, so this session "
                    "cannot be reconciled clean. The audit trail was modified out of "
                    "band — an operator must investigate.")}
    # Ground truth: the DISTINCT set of tools that actually ran (outcome 'ok'),
    # scoped to this app_id and this session's window. distinct_tools is unbounded
    # by row count — a truncated fetch would let a late privileged call fall
    # outside the diff and read as clean. The agent cannot supply this list.
    actual_tools = _receipt_log.distinct_tools(app_id, started, outcome="ok")
    try:
        # app_id passed so check_out re-verifies ownership before it drops the
        # session — belt-and-suspenders with the started_ts scoping above.
        report = _binder.check_out(session_id, exit_declaration, actual_tools, app_id=app_id)
    except BindError as e:
        return {"error": "reconcile_refused", "detail": str(e)}
    _receipt_log.record(
        app_id, "session_reconcile",
        "reconciled" if report["clean"] else "reconcile_discrepancy",
        None if report["clean"] else
        f"claimed_not_done={report['claimed_not_done']} "
        f"beyond_entry={report['beyond_entry']} done_not_claimed={report['done_not_claimed']}")
    return report


# ── Knowledge tools ────────────────────────────────────────────────────────────

def _subject_disclose(subject_id: str, tool_name: str, detail: str = "") -> None:
    """Best-effort: after a subject-bearing tool completes, append what was done
    to that subject's disclosure chain (the guardian-readable record). Never
    raises into the tool — the write already landed; a failed audit line must not
    turn a success into an error. The gate that *authorized* the call is
    enforcement; this is the record of it, and only the gate is load-bearing."""
    if not subject_id:
        return
    try:
        from . import subject_consent_binding
        subject_consent_binding.record_disclosure(subject_id, tool_name, detail)
    except Exception as e:
        import logging
        logging.getLogger("willow_mcp.server").warning(
            "subject_consent: disclosure record failed for %s: %s", tool_name, e
        )


def _knowledge_ingest_core(
    app_id: str,
    content: str,
    domain: str = "general",
    source: str = "",
    tags: Optional[list] = None,
    *,
    witnesses: "Iterable[object] | None" = None,
) -> dict:
    """The actual knowledge-base write, shared by knowledge_ingest and
    gap_promote. Deliberately ungated (no @_guarded, no receipt of its
    own) — callers are tools already gated under their own name, and
    routing both through one _guarded("knowledge_ingest") wrapper would
    force gap_promote callers to also hold knowledge_ingest permission and
    would double the receipt/rate-limit accounting for one logical write.
    The schema-confirmation requirement below is the real gate either way:
    unconfirmed, this refuses to write regardless of caller."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    # B8: Article IV Canon-promotion gate. OFF by default — when the enforce flag
    # is unset this call is skipped entirely and the write below is unchanged.
    if _enforce_mem_ratify():
        denied = _mem_ratify_gate(app_id, domain, source, witnesses=witnesses)
        if denied:
            return denied

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    unconfirmed = _require_confirmed(mapping)
    if unconfirmed:
        return unconfirmed
    fields = mapping["fields"]
    if fields["id"]["column"] is None or fields["content"]["column"] is None:
        return {"error": "schema_unusable: 'knowledge' table has no mappable 'id' or 'content' column"}

    kid = str(uuid.uuid4())[:8].upper()
    values = {"id": kid, "content": content}
    if fields["domain"]["column"]:
        values["domain"] = domain
    if fields["source"]["column"]:
        values["source"] = source
    if fields["tags"]["column"]:
        values["tags"] = tags or []

    cols = ", ".join(f'"{fields[f]["column"]}"' for f in values)
    placeholders = ", ".join(["%s"] * len(values))
    params = [_write_param(fields[f], v) for f, v in values.items()]
    cur = pg.cursor()
    cur.execute(
        f"INSERT INTO knowledge ({cols}) VALUES ({placeholders}) ON CONFLICT DO NOTHING",  # nosec B608 - cols come from the confirmed schema_profile field mapping, not request input; placeholders is a fixed "%s" repeat; all values are bound params
        params,
    )
    cur.close()
    return {"id": kid}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("knowledge_ingest")
def knowledge_ingest(
    app_id: str,
    content: str,
    domain: str = "general",
    source: str = "",
    tags: Optional[list] = None,
    subject_id: str = "",
) -> dict:
    """Add a knowledge atom to the Postgres knowledge base. Check for duplicates first.

    `subject_id` (guardian-consent seam): name the person this atom is *about* when
    it is not the owner. Opaque and local — never written to the KB, only checked.
    Naming a non-owner subject requires a verified `kb_promotion` consent grant
    (see docs/design/guardian-consent-seam.md); leave it empty for the owner's own
    data. The successful write is logged to that subject's disclosure chain."""
    result = _knowledge_ingest_core(app_id, content, domain=domain, source=source, tags=tags)
    if isinstance(result, dict) and not result.get("error"):
        _subject_disclose(subject_id, "knowledge_ingest", f"domain={domain}")
    return result


# ── The Nest — personal-file content pipeline ───────────────────────────────────
#
# "Dump your life and let the pigeon figure it out." nest_scan walks a folder,
# extracts text (OCR/PDF/docx/plaintext), and classifies fragments by meaning
# into a canonical SQLite Nest DB — the local PII zone. nest_status / nest_digest
# read it back (digest is the WALLED view over MCP). nest_promote pushes the
# Nest's *structure* — counts, curated category names, redacted secret kinds,
# never fragment content — into the knowledge base via the same core write
# knowledge_ingest uses. The wall (willow_mcp.nest): structure is process
# (shareable); content is person (walled). See docs/NEST.md.


def _nest_db_path(db_path: str) -> Path:
    """Resolve a Nest DB path, defaulting under $WILLOW_HOME/nest/seed.db."""
    if db_path:
        return Path(db_path).expanduser()
    return paths.willow_home() / "nest" / "seed.db"


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("nest_scan")
def nest_scan(
    app_id: str,
    folder: str,
    owner: str = "",
    db_path: str = "",
    dry_run: bool = True,
    use_llm: bool = False,
    use_embed: bool = True,
) -> dict:
    """Walk a drop folder, extract + classify its files, and write a canonical
    SQLite Nest DB. Returns structure only (counts by source status and fragment
    type) — never file content.

    dry_run=True (default): classify and report counts WITHOUT writing the DB —
    inspect what a dump would become before committing it. dry_run=False writes.
    use_embed uses an Ollama embedding model when present (falls back to regex
    offline); use_llm escalates the uncertain tail to a text/vision model.

    Inference stays on this machine by default. It is NOT unconditional: the
    seams post to $OLLAMA_HOST, and if that points off-box this tool requires the
    operator's standing `consent.cloud_llm` and denies without it. Classification
    sends document bodies, so where that host points is a privacy decision, not a
    performance one. (This docstring used to promise "nothing leaves the machine"
    flatly, which was true of the default and false of the variable.)
    """
    import contextlib
    import io

    from . import model_egress

    # Before any work: classification sends fragment CONTENT to the model, so an
    # off-box host is egress out of the Nest PII zone. Checked at the tool
    # boundary rather than in nest/embed.py — those modules are vendored
    # byte-for-byte from safe-app-store's libs/nest-pipeline under a CI
    # drift-guard, and are deliberately policy-free. See model_egress.
    if use_embed or use_llm:
        denial = model_egress.denial("nest_scan")
        if denial:
            return denial

    from .nest import ingest as _ingest

    src = Path(folder).expanduser()
    if not src.exists() or not src.is_dir():
        return {"error": f"folder not found or not a directory: {folder}"}

    db = _nest_db_path(db_path)
    if not dry_run:
        db.parent.mkdir(parents=True, exist_ok=True)

    # The engine prints progress/dry-run detail to stdout; on an stdio MCP
    # transport that would corrupt the protocol, so capture and discard it.
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink):
            counts = _ingest.run(
                folder=src,
                db_path=db,
                owner=owner or app_id,
                dry_run=dry_run,
                verbose=False,
                use_llm=use_llm,
                use_embed=use_embed,
            )
    except Exception as e:  # engine failure must not take the server down
        return {"error": f"nest scan failed: {type(e).__name__}: {e}"}

    return {
        "status": "ok",
        "dry_run": dry_run,
        "db_path": str(db) if not dry_run else None,
        "counts": counts,
    }


@mcp.tool(annotations=_ANNO_READ)
@_guarded("nest_status")
def nest_status(app_id: str, db_path: str = "") -> dict:
    """Counts for a seeded Nest DB — sources by status, fragments by type,
    topical categories by size. Structure only; no content."""
    import sqlite3

    from .nest.digest import is_category_name

    db = _nest_db_path(db_path)
    if not db.exists():
        return {"error": f"no Nest DB at {db} — run nest_scan first"}
    try:
        conn = sqlite3.connect(str(db))
        q = lambda s: conn.execute(s).fetchall()
        sources = {r[0]: r[1] for r in q(
            "select status, count(*) from sources group by 1")}
        frags = {r[0]: r[1] for r in q(
            "select fragment_type, count(*) from fragments group by 1")}
        raw_cats = q(
            "select label, count(*) from fragments where label!='' and "
            "fragment_type in ('document','note','receipt') group by 1 order by 2 desc")
        owner_row = conn.execute("select owner from nest_meta where id=1").fetchone()
        conn.close()
    except sqlite3.Error as e:
        return {"error": f"could not read Nest DB: {e}"}
    # The wall (same as bridge/digest): a filename-as-label is not a category and
    # must not surface here — count it as uncategorised instead of naming it.
    cats = {lbl: n for lbl, n in raw_cats if is_category_name(lbl)}
    uncategorised = sum(n for lbl, n in raw_cats if not is_category_name(lbl))
    return {
        "status": "ok",
        "owner": owner_row[0] if owner_row else "unknown",
        "sources": sources,
        "fragments": frags,
        "categories": cats,
        "uncategorised": uncategorised,
    }


@mcp.tool(annotations=_ANNO_READ)
@_guarded("nest_digest")
def nest_digest(app_id: str, db_path: str = "") -> dict:
    """A one-page Markdown map of a seeded Nest DB — the WALLED view: category
    breakdown, discovered clusters, secret *kinds*, and how files were read.
    Person names, the date timeline, and source filenames are suppressed (they
    are content, not structure). The full unwalled digest is a local-CLI
    affordance only; it is never returned over MCP."""
    from .nest import digest as _digest

    db = _nest_db_path(db_path)
    if not db.exists():
        return {"error": f"no Nest DB at {db} — run nest_scan first"}
    try:
        md = _digest.build_digest(str(db), wall=True)
    except Exception as e:
        return {"error": f"could not build digest: {type(e).__name__}: {e}"}
    return {"status": "ok", "walled": True, "digest": md}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("nest_promote")
def nest_promote(app_id: str, db_path: str = "", dry_run: bool = False, subject_id: str = "") -> dict:
    """Promote a Nest's STRUCTURE into the knowledge base. Reads structure-only
    atoms from bridge.build_bridge — counts, curated category names, and redacted
    secret kinds, never fragment content, filenames, or person names — and
    ingests each through the same core write knowledge_ingest uses.

    dry_run=True: return the atoms that WOULD be promoted (safe to inspect —
    they are structure only) without writing. dry_run=False ingests them.

    `subject_id` (guardian-consent seam): when the Nest is a *non-owner's* life-dump
    (a co-parent, a child, an ex-partner — the case the seam exists for), name that
    subject. Even the structure-only bridge crossing into the shared KB then
    requires a verified `kb_promotion` grant for them; leave empty for the owner's
    own dump. Opaque, never written to the KB. A committed promotion is logged to
    the subject's disclosure chain."""
    from .nest import bridge as _bridge

    db = _nest_db_path(db_path)
    if not db.exists():
        return {"error": f"no Nest DB at {db} — run nest_scan first"}
    try:
        built = _bridge.build_bridge(str(db))
    except Exception as e:
        return {"error": f"could not build bridge: {type(e).__name__}: {e}"}
    atoms = built.get("atoms", [])

    if dry_run:
        return {"status": "ok", "dry_run": True, "would_promote": len(atoms),
                "owner": built.get("owner"), "atoms": atoms}

    promoted, errors = [], []
    for atom in atoms:
        res = _knowledge_ingest_core(
            app_id,
            content=atom.get("summary", ""),
            domain="nest",
            source=atom.get("source_id", ""),
            tags=atom.get("tags"),
        )
        if isinstance(res, dict) and res.get("error"):
            # postgres_unavailable / unconfirmed schema is fatal for the whole
            # batch — surface it once rather than repeating it per atom.
            if res["error"] in ("postgres_unavailable",) or "confirm" in res["error"]:
                return {"error": res["error"], "promoted": len(promoted)}
            errors.append({"source_id": atom.get("source_id"), "error": res["error"]})
        else:
            promoted.append(atom.get("source_id"))

    if promoted:
        _subject_disclose(subject_id, "nest_promote", f"promoted={len(promoted)}")
    return {"status": "ok", "dry_run": False, "promoted": len(promoted),
            "owner": built.get("owner"), "source_ids": promoted, "errors": errors}


# ── The Nest — live drop-folder router ──────────────────────────────────────────
#
# "The pigeon sorts your desktop." nest_intake_scan classifies new files in a
# drop folder by filename into a track and STAGES a review queue — nothing moves.
# nest_intake_file / nest_intake_skip are the human gate: file moves the file to
# its track's destination, skip passes. Every gate action feeds a correction
# counter; at threshold a rule-delta flag opens (nest_intake_flags) — the
# classifier proposes, the human ratifies. This is an owner==subject, single-
# operator surface: the queue names the operator's own files so they can decide,
# and that state stays in the local SOIL store (it is not promoted to any shared
# KB — that is nest_promote's job, and it is walled). See docs/NEST.md.


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("nest_intake_scan")
def nest_intake_scan(app_id: str, folder: str = "") -> dict:
    """Scan drop zone(s), classify new files by filename into tracks, and stage a
    review queue. Idempotent (a file already staged is not re-staged) and
    non-destructive — nothing is moved until nest_intake_file. `folder` overrides
    the default drop dirs (~/Desktop/Nest and $WILLOW_HOME/nest/inbox)."""
    from .nest import intake as _intake
    from pathlib import Path as _Path

    folders = [_Path(folder).expanduser()] if folder else None
    try:
        staged = _intake.scan(_store, folders=folders)
    except Exception as e:
        return {"error": f"nest intake scan failed: {type(e).__name__}: {e}"}
    return {"status": "ok", "newly_staged": len(staged), "items": staged}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("nest_intake_queue")
def nest_intake_queue(app_id: str) -> dict:
    """List the pending review queue — files staged by nest_intake_scan awaiting a
    confirm/override/skip decision, with the track the classifier predicted."""
    from .nest import intake as _intake
    return {"status": "ok", "pending": _intake.get_queue(_store)}


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("nest_intake_file")
def nest_intake_file(app_id: str, item_id: str, override_dest: str = "") -> dict:
    """File a staged item: MOVE the file to its predicted track's destination, or
    to `override_dest` if you're correcting the classifier. An override (the
    outcome track differs from the prediction) feeds the correction counter and,
    at threshold, opens a rule-delta flag."""
    from .nest import intake as _intake
    try:
        return _intake.confirm(_store, item_id,
                               override_dest=override_dest or None, app_id=app_id)
    except Exception as e:
        return {"error": f"nest intake file failed: {type(e).__name__}: {e}"}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("nest_intake_skip")
def nest_intake_skip(app_id: str, item_id: str) -> dict:
    """Skip a staged item — leave the file where it is and record the skip
    (removes it from the pending queue; the decision is logged as feedback)."""
    from .nest import intake as _intake
    return _intake.skip(_store, item_id, app_id=app_id)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("nest_intake_flags")
def nest_intake_flags(app_id: str) -> dict:
    """List open rule-delta flags — patterns the classifier got wrong often enough
    (CORRECTION_FLAG_THRESHOLD overrides) that it proposes a rules change. The
    classifier never rewrites its own rules; a human ratifies the delta."""
    from .nest import intake as _intake
    return {"status": "ok", "flags": _intake.open_flags(_store)}


# ── Gap backlog tools ──────────────────────────────────────────────────────────
#
# "What don't we know yet" — a fleet-wide backlog (core/gaps.py), not scoped
# to app_id, the same way knowledge_search/store_search_all are shared by
# default. gap_log/list/resolve work SOIL-only (no Postgres needed);
# gap_promote is the one write that reaches the knowledge base, and it does
# so through the exact same schema-confirmation gate as knowledge_ingest.

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("gap_log")
def gap_log(app_id: str, topic: str, question: str) -> dict:
    """Log or bump a "we don't know this yet" entry. Repeated asks of the
    same topic+question increment asked_count instead of duplicating —
    asked_count is the backlog's own priority signal for what to fill in
    next. Returns {id, status, asked_count}."""
    return gap_backlog.log(topic, question)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("gap_list", paginated=True)
def gap_list(
    app_id: str,
    topic: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> dict:
    """List backlog gaps, most-asked first — the fleet's shared "what we don't
    know yet" queue.  Paginated: returns ``{items, next_cursor}`` — pass the
    returned ``next_cursor`` as ``cursor`` to fetch the next page.  Filter by
    ``topic`` and/or ``status`` (open | resolved | promoted); asked_count shows
    demand for each answer. Read-only."""
    return gap_backlog.list_gaps(topic=topic, status=status, limit=limit, cursor=cursor)


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("gap_resolve")
def gap_resolve(app_id: str, gap_id: str, note: str = "") -> dict:
    """Mark a gap as being worked or answered — bookkeeping only, does not
    write to the knowledge base. Use gap_promote to actually land a
    verified answer and close the gap out."""
    return gap_backlog.resolve(gap_id, note=note)


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("gap_delete")
def gap_delete(app_id: str, gap_id: str) -> dict:
    """Soft-delete a single gap by id — for clearing junk or test entries from
    the backlog without disturbing its real gaps. Archive, not drop: the gap is
    retained (deleted=1) and just stops appearing in gap_list. Returns
    {deleted, id}, or {error: not_found}."""
    return gap_backlog.delete(gap_id)


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("gap_purge_topic")
def gap_purge_topic(app_id: str, topic: str, confirm: str = "") -> dict:
    """Soft-delete every gap under an exact topic in ONE call — bulk cleanup of a
    junk/test namespace without hitting gap_delete's per-call rate limit. Promoted
    gaps (which point at a landed knowledge atom) are left intact. Archive, not
    drop: purged gaps are retained (deleted=1), just removed from gap_list. Pass
    confirm=<topic> to proceed. Returns {purged, skipped_promoted, topic}.

    Note: gaps are a FLEET-SHARED backlog, not store_scoped — this purges every
    app's gaps under the topic, so it's gated on its own `gap_purge` permission
    (not the everyday `gap_write`) rather than handed out broadly."""
    if not topic:
        return {"error": "topic is required"}
    if confirm != topic:
        return {"error": "confirm_required",
                "detail": f"pass confirm='{topic}' to purge all gaps under topic "
                          f"'{topic}' — a bulk soft-delete (reversible)"}
    return gap_backlog.purge_topic(topic)


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("gap_promote")
def gap_promote(
    app_id: str,
    gap_id: str,
    answer: str,
    sources: list,
    confirmed_by: str,
    domain: str = "general",
    tags: Optional[list] = None,
) -> dict:
    """Turn a gap into trusted knowledge. Requires an answer, at least one
    source, and who's vouching for it (confirmed_by) — a human name, an
    agent id, whatever this fleet uses as an identity, but never empty.
    Writes through the SAME schema-confirmation gate as a direct
    knowledge_ingest call: if the 'knowledge' table mapping for this app_id
    hasn't been confirmed via schema_confirm_mapping, this refuses with
    unconfirmed_schema exactly like knowledge_ingest would. Requires
    Postgres — gap_log/list/resolve work SOIL-only, but promotion targets
    the durable, searchable knowledge base. Gated as its own permission
    (gap_promote), separate from gap_write, the same way schema_admin is
    kept separate from knowledge_write — landing something as trusted
    knowledge is a more consequential act than logging or resolving a gap."""
    gap = gap_backlog.get(gap_id)
    if not gap:
        return {"error": "not_found"}
    if gap.get("status") == "promoted":
        return {"error": "already_promoted", "promoted_to": gap.get("promoted_to")}

    answer = (answer or "").strip()
    confirmed_by = (confirmed_by or "").strip()
    source_list = [str(s) for s in (sources or []) if str(s).strip()]
    if not answer or not source_list or not confirmed_by:
        return {"error": "answer, at least one source, and confirmed_by are required"}

    merged_tags = list(tags or []) + [f"confirmed_by:{confirmed_by}", f"gap:{gap_id}"]
    result = _knowledge_ingest_core(
        app_id,
        answer,
        domain=domain,
        source=", ".join(source_list),
        tags=merged_tags,
    )
    if "error" in result:
        return result
    gap_backlog.mark_promoted(gap_id, result["id"])
    return {"id": result["id"], "gap_id": gap_id, "promoted": True}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("knowledge_search")
def knowledge_search(
    app_id: str,
    query: str,
    domain: Optional[str] = None,
    limit: int = 10,
) -> dict:
    """Search the fleet Postgres knowledge base by content: the query is
    whitespace-split and ALL tokens must appear in an atom (AND logic).
    `domain` narrows to one domain (e.g. 'journal', 'continuity'). Returns up
    to `limit` atoms. Read-only; use kb_at to fetch a known atom by ID."""
    tokens = query.split()
    if not tokens:
        return {"results": []}
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    fields = mapping["fields"]
    if fields["id"]["column"] is None or fields["content"]["column"] is None:
        return {"error": "schema_unusable: 'knowledge' table has no mappable 'id' or 'content' column"}

    select_clause, present, unmapped = _build_select(_KNOWLEDGE_FIELDS, fields)
    content_ref = sp.cast_for_ilike(fields["content"])
    conditions = " AND ".join([f"{content_ref} ILIKE %s"] * len(tokens))
    params: list = [f"%{t}%" for t in tokens]
    tags_col = fields["tags"]["column"]
    cols_by_name = {c.name: c for c in sp.introspect(pg, "knowledge")}
    retract_sql, retract_params = kbc.sql_exclude_retracted(tags_col, cols_by_name)
    sql = f"SELECT {select_clause} FROM knowledge WHERE {conditions}{retract_sql}"  # nosec B608 - select_clause/retract_sql are built from the confirmed schema_profile field mapping, not request input; conditions is a fixed "X ILIKE %s" repeat; all values are bound params
    params.extend(retract_params)
    if domain and fields["domain"]["column"]:
        sql += f' AND "{fields["domain"]["column"]}" = %s'
        params.append(domain)
    sql += " LIMIT %s"
    params.append(limit)

    cur = pg.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()

    result = {"results": [kbc.enrich_atom(_row_to_dict(r, present, unmapped)) for r in rows]}
    if unmapped:
        result["_unmapped"] = unmapped
    return result


@mcp.tool(annotations=_ANNO_READ)
@_guarded("knowledge_verify")
def knowledge_verify(
    app_id: str,
    domain: str = "",
    limit: int = 200,
) -> dict:
    """Verify source provenance of knowledge records. Checks each record
    for a non-empty source field. Returns {outcome, total, sourced, unsourced,
    unsourced_records, recommendation}. outcome is pass/warn/fail.
    Requires knowledge_read."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    return kb_verify.verify_sources(pg, app_id, domain=domain or None, limit=min(limit, 500))


@mcp.tool(annotations=_ANNO_READ)
@_guarded("knowledge_check")
def knowledge_check(
    app_id: str,
    domain: str = "",
    limit: int = 200,
) -> dict:
    """Health check on knowledge records (mem_check analog). Checks for
    unsourced records, missing domains, and duplicate content. Returns
    {flags, recommendation, evidence}. Requires knowledge_read."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    return kb_verify.check_health(pg, app_id, domain=domain or None, limit=min(limit, 500))


# ── Task queue tools ───────────────────────────────────────────────────────────

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("task_submit")
def task_submit(
    app_id: str,
    task: str,
    agent: str = "kart",
    lane: str = "fast",
    allow_net: bool = False,
    allow_localhost: bool = False,
    allow_db: bool = False,
    network_authorization: str = "",
    db_authorization: str = "",
) -> dict:
    """Submit a task to the Kart sandboxed execution queue. Returns task_id for polling.

    Tasks run network-isolated by default. Egress needs the `task_net` capability,
    standing `consent.internet`, a live operator lease, and an operator-signed
    per-task envelope passed as `network_authorization`. The envelope binds the
    submitter, task id, agent, normalized task hash, network scope, expiry, and
    nonce. The signed task id is the queue primary key, preventing the envelope
    from authorizing a second row. `# allow_net` and `# allow_localhost` remain
    requests, never authority.

    Local Postgres access (socket mount + PG/POSTGRES env) requires `allow_db=True`
    and the separate `task_db` manifest capability — not granted by task_queue or
    full_access. `# allow_db` in task text is a request, never authority. When the
    operator sets `WILLOW_MCP_ENFORCE_DB_PERIMETER` (off by default), `allow_db`
    additionally requires an operator-signed per-task `db_authorization` envelope
    (db scope) from `willow-mcp sign-db-task` — mirroring the network perimeter, so
    a `task_db` holder can no longer submit arbitrary `psql`.

    The Kartikeya executor verifies all host gates and the signed envelope again
    immediately before shell launch. Missing attribution or envelope, an invalid
    signature, expiry, replay, task mutation, unavailable verifier, or a strict
    trust-root failure denies network. Signing is available only through the local
    interactive `willow-mcp sign-net-task` CLI; no MCP tool can mint authority.

    Task text is security-scanned at SUBMIT time (defense-in-depth): a task the
    Kart scanner would refuse — destructive, exfiltration, secret access, obfusc-
    ation, or resource-exhaustion (fork bomb / spin / disk-fill) — is rejected
    here before it ever occupies a queue slot, not only when the worker later
    picks it up. The worker re-scans at execution regardless; this just denies
    earlier and keeps a bomb from sitting `pending`.
    """
    # Submit-time scan, before any DB work — a dangerous task is refused even if
    # Postgres is down. kartikeya is a hard dependency, but degrade open (worker
    # still scans) rather than crash the tool if it is somehow unimportable.
    try:
        from kartikeya import check_kart_task
        blocked = check_kart_task(task or "")
    except Exception as exc:
        import logging
        logging.getLogger("willow_mcp.server").warning("check_kart_task failed: %s", exc)
        blocked = None
    if blocked:
        return blocked
    lane = (lane or "").strip().lower()
    if lane not in ("fast", "batch"):
        return {"error": f"invalid_lane: expected fast|batch, got {lane!r}"}

    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    if allow_net and allow_localhost:
        return {"error": "network_mode_invalid: choose allow_net or allow_localhost"}
    network_requested = allow_net or allow_localhost
    if network_requested:
        from . import consent, gate, lease
        # Key 1: is this app allowed to ask at all? (capability, granted once)
        if not gate.permitted(app_id, gate.NET_PERMISSION):
            return {"error": (
                f"net_denied: shared network access requires the '{gate.NET_PERMISSION}' permission in "
                f"this app's manifest ($WILLOW_HOME/mcp_apps/{app_id or '<app_id>'}/manifest.json). "
                "It is not granted by task_queue or full_access — add it explicitly.")}
        # Key 2: does the operator permit egress right now? (standing consent)
        # Read fail-closed — an absent or unparseable policy is not consent.
        if not consent.internet_permitted():
            return {"error": (
                "consent_denied: shared network access also requires the operator's standing "
                f"'consent.internet' in {consent.settings_path()}. This app holds "
                f"'{gate.NET_PERMISSION}', but egress is switched off (or the consent "
                "policy could not be read, which denies). Only the operator may turn it "
                "on — an agent may request egress, never grant it to itself.")}
        # Key 3: has the operator issued a live lease for THIS app? (B-32)
        # A capability that never expires is indistinguishable from one that was
        # self-granted an hour ago; a lease has a clock and an issuer.
        lease_state = lease.read_lease(app_id)
        if lease_state["status"] != "active":
            return {"error": (
                f"lease_denied: shared network access requires an unexpired egress lease for '{app_id}' "
                f"(status: {lease_state['status']}"
                + (f" — {lease_state['error']}" if lease_state.get("error") else "")
                + "). Leases are issued only by the operator, on the host, via "
                f"`willow-mcp grant-net {app_id or '<app_id>'} --ttl 30m --reason ...`, and they "
                "expire. No MCP tool can mint one. Ask for a lease; do not write the file.")}
        # Whichever keys are within this process's own write reach are keys it
        # could have forged. Reported always; enforced only under strict mode,
        # because on a single-uid host that is every install (B-32 residual).
        if lease.strict_trust_root():
            forgeable = lease.self_writable_trust_paths(app_id)
            if forgeable:
                return {"error": (
                    "trust_root_denied: WILLOW_MCP_STRICT_TRUST_ROOT is set, but this "
                    "process can write the very keys that authorize it: "
                    + ", ".join(f"{f['key']} ({f['path']})" for f in forgeable)
                    + ". A confirm authority inside the actor's write reach is not an "
                    "authority. Chown these to a uid the agent does not run as.")}

    if allow_db:
        from . import gate

        if not gate.permitted(app_id, gate.DB_PERMISSION):
            return {"error": (
                f"db_denied: local Postgres access requires the '{gate.DB_PERMISSION}' permission in "
                f"this app's manifest ($WILLOW_HOME/mcp_apps/{app_id or '<app_id>'}/manifest.json). "
                "It is not granted by task_queue or full_access — add it explicitly.")}

    mapping = sp.resolve(pg, app_id, "tasks", _TASK_FIELDS)
    if "error" in mapping:
        return mapping
    unconfirmed = _require_confirmed(mapping)
    if unconfirmed:
        return unconfirmed
    fields = mapping["fields"]
    if fields["task_id"]["column"] is None or fields["task"]["column"] is None:
        return {"error": "schema_unusable: 'tasks' table has no mappable 'task_id' or 'task' column"}

    from . import egress_authorization

    task = "\n".join(
        line
        for line in egress_authorization.normalize_task(task).splitlines()
        if line.strip() not in {"# allow_net", "# allow_localhost", "# allow_db"}
    )
    task_id = ""
    if network_requested:
        task = egress_authorization.canonical_network_task(
            task, localhost=allow_localhost
        )
        if not network_authorization:
            return {
                "error": (
                    "net_authorization_denied: shared network access requires an "
                    "operator-signed per-task envelope from "
                    "`willow-mcp sign-net-task`"
                )
            }
        public_key = egress_authorization.public_key_path()
        if public_key is None:
            return {
                "error": (
                    "net_authorization_denied: "
                    "WILLOW_MCP_EGRESS_PUBLIC_KEY is not configured"
                )
            }
        task_id = egress_authorization.claimed_task_id(network_authorization)
        if not task_id:
            return {"error": "net_authorization_denied: malformed task_id claim"}
        verified, reason, _ = egress_authorization.verify_envelope(
            public_key_path=public_key,
            submitted_by=app_id,
            task_id=task_id,
            agent=agent,
            task=task,
            envelope=network_authorization,
        )
        if not verified:
            return {"error": f"net_authorization_denied: {reason}"}
        if not fields["network_authorization"]["column"]:
            return {
                "error": (
                    "schema_unusable: the confirmed tasks mapping has no "
                    "'network_authorization' column; apply the reviewed migration "
                    "and reconfirm the mapping before submitting network work"
                )
            }

    if allow_db:
        task = egress_authorization.canonical_db_task(task)
        if _enforce_db_perimeter():
            # B2: with the perimeter enforced, allow_db needs an operator-signed
            # per-task envelope (db scope) — the same authority allow_net has, so a
            # task_db-holding app can no longer queue arbitrary psql. Verified here
            # at submit; the ExecutorDbAuthorizer re-verifies at shell launch once
            # kartikeya exposes a db seam. `# allow_db` stays a request, not authority.
            if not db_authorization:
                return {"error": (
                    "db_authorization_denied: WILLOW_MCP_ENFORCE_DB_PERIMETER is set, so "
                    "local Postgres access requires an operator-signed per-task envelope "
                    "from `willow-mcp sign-db-task`. Ask for one; no MCP tool can mint it.")}
            public_key = egress_authorization.public_key_path()
            if public_key is None:
                return {"error": (
                    "db_authorization_denied: no verifier configured — "
                    "run `willow-mcp setup-egress` (WILLOW_MCP_EGRESS_PUBLIC_KEY)")}
            db_task_id = egress_authorization.claimed_task_id(db_authorization)
            if not db_task_id:
                return {"error": "db_authorization_denied: malformed task_id claim"}
            if task_id and db_task_id != task_id:
                return {"error": (
                    "db_authorization_denied: the db envelope's task_id does not match "
                    "the network envelope's task_id for this submission")}
            verified, reason, _ = egress_authorization.verify_envelope(
                public_key_path=public_key,
                submitted_by=app_id,
                task_id=db_task_id,
                agent=agent,
                task=task,
                envelope=db_authorization,
                expected_scope=egress_authorization.DB_SCOPE,
            )
            if not verified:
                return {"error": f"db_authorization_denied: {reason}"}
            # .get(): a mapping confirmed before this field existed has no
            # 'db_authorization' key at all (not just a null column), so a bare
            # fields["db_authorization"] would KeyError. Absent key and null
            # column both mean the same operator action — migrate + reconfirm.
            if not (fields.get("db_authorization") or {}).get("column"):
                return {"error": (
                    "schema_unusable: the confirmed tasks mapping has no "
                    "'db_authorization' column; apply the reviewed migration "
                    "(docs/schema/tasks-add-db-authorization.sql) and reconfirm the "
                    "mapping before submitting gated db work")}
            task_id = db_task_id

    if not task_id:
        import random
        task_id = "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", k=8))
    values = {"task_id": task_id, "task": task}
    if fields["submitted_by"]["column"]:
        values["submitted_by"] = app_id or "willow-mcp"
    if network_requested:
        values["network_authorization"] = network_authorization
    if allow_db and _enforce_db_perimeter():
        values["db_authorization"] = db_authorization
    if fields["agent"]["column"]:
        values["agent"] = agent
    if not fields["lane"]["column"]:
        return {
            "error": (
                "schema_unusable: the confirmed tasks mapping has no 'lane' "
                "column; apply the worker-production migration before queueing work"
            )
        }
    values["lane"] = lane

    cols = ", ".join(f'"{fields[f]["column"]}"' for f in values)
    placeholders = ", ".join(["%s"] * len(values))
    params = [_write_param(fields[f], v) for f, v in values.items()]
    cur = pg.cursor()
    cur.execute(f"INSERT INTO tasks ({cols}) VALUES ({placeholders})", params)  # nosec B608 - cols come from the confirmed schema_profile field mapping, not request input; placeholders is a fixed "%s" repeat; all values are bound params
    cur.close()
    return {"task_id": task_id, "status": "pending"}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("task_status")
def task_status(app_id: str, task_id: str) -> dict:
    """Poll one task submitted via task_submit. Reads the fleet Postgres queue
    and returns the task row — status, result, submitted_by, timestamps — or
    {error: not_found} for an unknown task_id. Read-only; poll until the
    worker marks the task complete."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "tasks", _TASK_FIELDS)
    if "error" in mapping:
        return mapping
    fields = mapping["fields"]
    id_col = fields["task_id"]["column"]
    if id_col is None:
        return {"error": "schema_unusable: 'tasks' table has no mappable 'task_id' column"}

    select_clause, present, unmapped = _build_select(_TASK_READ_FIELDS, fields)
    cur = pg.cursor()
    cur.execute(f'SELECT {select_clause} FROM tasks WHERE "{id_col}" = %s', (task_id,))  # nosec B608 - select_clause/id_col come from the confirmed schema_profile field mapping, not request input; task_id is a bound param
    row = cur.fetchone()
    cur.close()
    if not row:
        return {"error": "not_found"}

    result = _row_to_dict(row, present, unmapped)
    if unmapped:
        result["_unmapped"] = unmapped
    return result


@mcp.tool(annotations=_ANNO_READ)
@_guarded("task_list")
def task_list(app_id: str, agent: str = "kart", limit: int = 10,
              cursor: Optional[str] = None) -> dict:
    """List tasks still waiting in the Kart queue for one worker `agent`
    (default 'kart'), oldest first, task text truncated to 80 chars.  Paginated:
    returns ``{pending, next_cursor}`` — pass the returned ``next_cursor`` as
    ``cursor`` to fetch the next page.  Answers "what is queued to run" — use
    task_status for one task's full detail.  Requires the fleet Postgres.
    Read-only."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "tasks", _TASK_FIELDS)
    if "error" in mapping:
        return mapping
    fields = mapping["fields"]
    id_col, status_col, agent_col = (fields["task_id"]["column"], fields["status"]["column"],
                                      fields["agent"]["column"])
    if id_col is None or status_col is None or agent_col is None:
        return {"error": "schema_unusable: 'tasks' table has no mappable 'task_id', 'status', or 'agent' column"}

    sort_col = fields["created_at"]["column"] or id_col
    listed_fields = ["task_id", "task", "submitted_by", "created_at"]
    select_clause, present, unmapped = _build_select(listed_fields, fields)
    cur = pg.cursor()
    if cursor:
        after_val = decode_cursor(cursor)
        cur.execute(
            f'SELECT {select_clause} FROM tasks WHERE "{status_col}" = \'pending\' AND "{agent_col}" = %s '  # nosec B608 - column names come from confirmed schema_profile mapping
            f'AND "{sort_col}" > %s '
            f'ORDER BY "{sort_col}" LIMIT %s',
            (agent, after_val, limit + 1)
        )
    else:
        cur.execute(
            f'SELECT {select_clause} FROM tasks WHERE "{status_col}" = \'pending\' AND "{agent_col}" = %s '  # nosec B608 - select_clause/status_col/agent_col/created_at column come from the confirmed schema_profile field mapping, not request input; agent/limit are bound params
            f'ORDER BY "{sort_col}" LIMIT %s',
            (agent, limit + 1)
        )
    rows = cur.fetchall()
    cur.close()
    has_more = len(rows) > limit
    rows = rows[:limit]
    pending = [_row_to_dict(r, present, unmapped) for r in rows]
    for p in pending:
        if p.get("task"):
            p["task"] = p["task"][:80]
    next_cursor = None
    if has_more and pending:
        # Use the sort column value from the last row as the cursor key
        last = pending[-1]
        cursor_val = str(last.get("created_at") or last.get("task_id", ""))
        next_cursor = encode_cursor(cursor_val)
    result = {"pending": pending, "next_cursor": next_cursor}
    if unmapped:
        result["_unmapped"] = unmapped
    return result


# ── Knowledge extension tools ──────────────────────────────────────────────────

@mcp.tool(annotations=_ANNO_READ)
@_guarded("kb_at")
def kb_at(app_id: str, atom_id: str) -> dict:
    """Fetch one knowledge-base atom by its exact ID from the fleet Postgres —
    content, domain, source, and tags. Returns {error: not_found} for an
    unknown ID. Read-only; the direct-address companion to knowledge_search."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    fields = mapping["fields"]
    id_col = fields["id"]["column"]
    if id_col is None:
        return {"error": "schema_unusable: 'knowledge' table has no mappable 'id' column"}

    select_clause, present, unmapped = _build_select(_KNOWLEDGE_FIELDS, fields)
    cur = pg.cursor()
    cur.execute(f'SELECT {select_clause} FROM knowledge WHERE "{id_col}" = %s', (atom_id,))  # nosec B608 - select_clause/id_col come from the confirmed schema_profile field mapping, not request input; atom_id is a bound param
    row = cur.fetchone()
    cur.close()
    if not row:
        return {"error": "not_found"}

    result = kbc.enrich_atom(_row_to_dict(row, present, unmapped))
    if unmapped:
        result["_unmapped"] = unmapped
    return result


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("knowledge_flag")
def knowledge_flag(
    app_id: str,
    atom_id: str,
    reason: str,
    severity: str = "medium",
    refs: Optional[list] = None,
) -> dict:
    """Attach a visible integrity flag to an existing KB atom (tags only).

    Idempotent: re-flagging replaces the prior flag metadata. Original content
    is unchanged. Requires ``knowledge_curate`` and a confirmed schema with a
    mapped ``tags`` column."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    unconfirmed = _require_confirmed(mapping)
    if unconfirmed:
        return unconfirmed
    fields = mapping["fields"]
    id_col, tags_col = fields["id"]["column"], fields["tags"]["column"]
    if id_col is None or tags_col is None:
        return {"error": "schema_unusable: 'knowledge' needs mappable 'id' and 'tags' columns"}

    cur = pg.cursor()
    cur.execute(f'SELECT "{tags_col}" FROM knowledge WHERE "{id_col}" = %s', (atom_id,))  # nosec B608 - tags_col/id_col come from the confirmed schema_profile field mapping, not request input; atom_id is a bound param
    row = cur.fetchone()
    if not row:
        cur.close()
        return {"error": "not_found"}
    new_tags = kbc.merge_flag_tags(
        row[0], app_id=app_id, reason=reason, severity=severity, refs=refs
    )
    cur.execute(
        f'UPDATE knowledge SET "{tags_col}" = %s WHERE "{id_col}" = %s',  # nosec B608 - tags_col/id_col come from the confirmed schema_profile field mapping, not request input; values are bound params
        (_write_param(fields["tags"], new_tags), atom_id),
    )
    cur.close()
    return {"id": atom_id, "flagged": True, "severity": severity}


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("knowledge_retract")
def knowledge_retract(app_id: str, atom_id: str, reason: str) -> dict:
    """Tombstone a KB atom in place — hidden from default search, fetchable by id.

  Adds ``kb:retracted`` tags; ``kb_at`` still returns the atom with
  ``retracted: true``. Requires ``knowledge_curate`` and mapped ``tags``."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    unconfirmed = _require_confirmed(mapping)
    if unconfirmed:
        return unconfirmed
    fields = mapping["fields"]
    id_col, tags_col = fields["id"]["column"], fields["tags"]["column"]
    if id_col is None or tags_col is None:
        return {"error": "schema_unusable: 'knowledge' needs mappable 'id' and 'tags' columns"}

    cur = pg.cursor()
    cur.execute(f'SELECT "{tags_col}" FROM knowledge WHERE "{id_col}" = %s', (atom_id,))  # nosec B608 - tags_col/id_col come from the confirmed schema_profile field mapping, not request input; atom_id is a bound param
    row = cur.fetchone()
    if not row:
        cur.close()
        return {"error": "not_found"}
    new_tags = kbc.merge_retract_tags(row[0], app_id=app_id, reason=reason)
    cur.execute(
        f'UPDATE knowledge SET "{tags_col}" = %s WHERE "{id_col}" = %s',  # nosec B608 - tags_col/id_col come from the confirmed schema_profile field mapping, not request input; values are bound params
        (_write_param(fields["tags"], new_tags), atom_id),
    )
    cur.close()
    return {"id": atom_id, "retracted": True}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("kb_promote")
def kb_promote(app_id: str, atom_id: str, domain: str) -> dict:
    """Move an existing knowledge atom to a different domain — e.g. lift a
    'journal' entry into a topical domain once it proves durable. Updates the
    atom in place; content and ID are unchanged. Returns {id, domain} or
    {error: not_found}. Requires a confirmed 'knowledge' schema mapping."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    unconfirmed = _require_confirmed(mapping)
    if unconfirmed:
        return unconfirmed
    fields = mapping["fields"]
    id_col, domain_col = fields["id"]["column"], fields["domain"]["column"]
    if id_col is None or domain_col is None:
        return {"error": "schema_unusable: 'knowledge' table has no mappable 'id' or 'domain' column"}

    cur = pg.cursor()
    cur.execute(f'UPDATE knowledge SET "{domain_col}" = %s WHERE "{id_col}" = %s', (domain, atom_id))  # nosec B608 - domain_col/id_col come from the confirmed schema_profile field mapping, not request input; values are bound params
    updated = cur.rowcount
    cur.close()
    return {"id": atom_id, "domain": domain} if updated else {"error": "not_found"}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("kb_journal")
def kb_journal(
    app_id: str,
    content: str,
    source: str = "",
    tags: Optional[list] = None,
) -> dict:
    """Append a free-text journal entry to the knowledge base: a new atom in
    domain 'journal', tagged 'journal' plus any `tags` you pass, with optional
    `source` attribution. Lighter than knowledge_ingest — no domain choice or
    sensitivity tiering. Returns {id, domain}. Requires a confirmed
    'knowledge' schema mapping."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    unconfirmed = _require_confirmed(mapping)
    if unconfirmed:
        return unconfirmed
    fields = mapping["fields"]
    if fields["id"]["column"] is None or fields["content"]["column"] is None:
        return {"error": "schema_unusable: 'knowledge' table has no mappable 'id' or 'content' column"}

    kid = str(uuid.uuid4())[:8].upper()
    all_tags = list(set(["journal"] + (tags or [])))
    values = {"id": kid, "content": content}
    if fields["domain"]["column"]:
        values["domain"] = "journal"
    if fields["source"]["column"]:
        values["source"] = source
    if fields["tags"]["column"]:
        values["tags"] = all_tags

    cols = ", ".join(f'"{fields[f]["column"]}"' for f in values)
    placeholders = ", ".join(["%s"] * len(values))
    params = [_write_param(fields[f], v) for f, v in values.items()]
    cur = pg.cursor()
    cur.execute(
        f"INSERT INTO knowledge ({cols}) VALUES ({placeholders}) ON CONFLICT DO NOTHING",  # nosec B608 - cols come from the confirmed schema_profile field mapping, not request input; placeholders is a fixed "%s" repeat; all values are bound params
        params,
    )
    cur.close()
    return {"id": kid, "domain": "journal"}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("kb_journal_read")
def kb_journal_read(
    app_id: str,
    limit: int = 50,
    since_id: Optional[str] = None,
) -> list:
    """Return recent kb_journal atoms (domain 'journal'), newest first.

    Companion to kb_journal — the C11 read-back seam Grove's journal_reader
    calls in-process or over HTTP. `limit` is clamped to [1, 200].
    `since_id`, when set, returns only atoms strictly newer than that id in
    newest-first order (same semantics as Grove's journal_reader). Read-only."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    fields = mapping["fields"]
    id_col = fields["id"]["column"]
    domain_col = fields["domain"]["column"]
    if id_col is None or fields["content"]["column"] is None:
        return {"error": "schema_unusable: 'knowledge' table has no mappable 'id' or 'content' column"}
    if not domain_col:
        return {"error": "schema_unusable: 'knowledge' table has no mappable 'domain' column"}

    if not isinstance(limit, int) or limit <= 0:
        limit = 50
    if limit > 200:
        limit = 200

    select_clause, present, unmapped = _build_select(_KNOWLEDGE_FIELDS, fields)
    cols_by_name = {c.name: c for c in sp.introspect(pg, "knowledge")}
    tags_col = fields["tags"]["column"]
    retract_sql, retract_params = kbc.sql_exclude_retracted(tags_col, cols_by_name)
    order_col = "created_at" if "created_at" in cols_by_name else id_col
    extra_ts = f', "{order_col}"' if order_col not in {fields[f]["column"] for f in present if fields[f]["column"]} else ""

    sql = (
        f'SELECT {select_clause}{extra_ts} FROM knowledge '
        f'WHERE "{domain_col}" = %s{retract_sql} '
        f'ORDER BY "{order_col}" DESC LIMIT %s'
    )  # nosec B608 - built from confirmed schema_profile mapping, not request input
    params: list = ["journal", *retract_params, 200]

    cur = pg.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()

    atoms: list[dict] = []
    for row in rows:
        base = list(row)
        ts_val = None
        if extra_ts and len(base) > len(present):
            ts_val = base[-1]
            base = base[:-1]
        atom = kbc.enrich_atom(_row_to_dict(tuple(base), present, unmapped))
        if ts_val is not None:
            atom["created_at"] = ts_val.isoformat() if hasattr(ts_val, "isoformat") else str(ts_val)
        if unmapped:
            atom["_unmapped"] = unmapped
        atoms.append(atom)

    if since_id:
        for i, atom in enumerate(atoms):
            if atom.get("id") == since_id:
                atoms = atoms[:i]
                break

    return atoms[:limit]


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("kb_ingest")
def kb_ingest(
    app_id: str,
    agent_id: str,
    slice: str = "",
    sensitivity: str = "sensitive",
    tier: str = "canonical",
    supersede: bool = True,
    subject_id: str = "",
) -> dict:
    """Promote a ratified agent_seed slice to Postgres KB (source_type: agent_seed).

    Requires ratified + trusted seed at $WILLOW_HOME/seeds/{agent_id}.json.
    slice: voice_only | work_context | full (omit to use exposure.json default for kb_ingest).
    Never promotes persona.cast or context.personal_note.

    `subject_id` (guardian-consent seam): if a seed slice carries a *non-owner*
    subject's data across into the shared KB, name them — the crossing then needs a
    verified `kb_promotion` grant. Opaque, never written. Empty for the owner's own
    agent seed (the usual case). A committed promotion is logged to the subject's
    disclosure chain."""
    from . import seed_kb as skb

    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    unconfirmed = _require_confirmed(mapping)
    if unconfirmed:
        return unconfirmed

    kid = str(uuid.uuid4())[:8].upper()
    result = skb.promote_seed_to_kb(
        pg,
        mapping["fields"],
        agent_id=agent_id,
        slice_name=slice,
        sensitivity=sensitivity,
        tier=tier,
        supersede=supersede,
        new_id=kid,
    )
    if isinstance(result, dict) and not result.get("error"):
        _subject_disclose(subject_id, "kb_ingest", f"agent={agent_id} slice={slice}")
    return result


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("schema_confirm_mapping")
def schema_confirm_mapping(app_id: str, table: str, overrides: Optional[dict] = None,
                           preview: bool = False) -> dict:
    """Confirm a table's schema mapping, unlocking write tools for it (knowledge_ingest,
    kb_journal, kb_promote today). `overrides` lets you correct individual
    canonical-field -> real-column assignments before confirming, e.g.
    {"source": "origin_ref"} or {"tags": null} to explicitly mark a field
    unmapped. Gated separately from knowledge_write — confirming a mapping
    is a more consequential act than a single write.

    preview=True: dry-run — return the proposed mapping AND a rendered `sample`
    row (what each canonical field actually resolves to) WITHOUT confirming or
    writing. Review the sample first: a column that name-matches but holds the
    wrong data — e.g. a `content` column that is really a provenance blob, with
    the real text in `title`/`summary` — reveals itself in the sample where a
    name match cannot. preview=False (default): confirm, and include the sample
    in the response so the confirmation is never blind."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    canonical_fields = _CONFIRMABLE_TABLES.get(table)
    if canonical_fields is None:
        return {
            "error": f"unknown_table: '{table}' is not a table willow-mcp knows how to map "
                     f"(known: {sorted(_CONFIRMABLE_TABLES)})"
        }
    if preview:
        return sp.preview(pg, app_id, table, canonical_fields, overrides=overrides)
    result = sp.confirm(pg, app_id, table, canonical_fields, overrides=overrides)
    if isinstance(result, dict) and "error" not in result:
        result["sample"] = sp.render_sample(pg, table, result.get("fields", {}))
    return result


@mcp.tool(annotations=_ANNO_READ)
@_guarded("kb_startup_continuity")
def kb_startup_continuity(app_id: str, limit: int = 20) -> dict:
    """Fetch the knowledge atoms marked for session-startup continuity —
    domain 'continuity' or tagged "continuity" — newest first, up to `limit`.
    Call early in a session to recover standing decisions and in-flight state.
    The result always includes _continuity_filter showing exactly what was
    searched, so an empty list is legible. Read-only."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "knowledge", _KNOWLEDGE_FIELDS)
    if "error" in mapping:
        return mapping
    fields = mapping["fields"]
    id_col = fields["id"]["column"]
    domain_col = fields["domain"]["column"]
    tags_col = fields["tags"]["column"]
    if id_col is None:
        return {"error": "schema_unusable: 'knowledge' table has no mappable 'id' column"}

    # 'tags' often has no top-level column: on willow-style schemas the tags
    # live inside a jsonb metadata/provenance blob physically named 'content'
    # — which is NOT the canonical 'content' field (that maps to the
    # human-readable 'summary'; the jsonb blob is deliberately unmapped, B-10).
    # Discover a jsonb 'content' column by introspection rather than assuming
    # one, and read continuity tags from content->'tags' (a string array,
    # e.g. ["release-process","ci"]). Only consulted when there is no
    # top-level tags column to filter on.
    cols_by_name = {c.name: c for c in sp.introspect(pg, "knowledge")}
    tags_jsonb_col = None
    if tags_col is None:
        if cols_by_name.get("content") and cols_by_name["content"].data_type in ("jsonb", "json"):
            tags_jsonb_col = "content"

    select_clause, present, unmapped = _build_select(_KNOWLEDGE_FIELDS, fields)
    where_parts, params, filters = [], [], []
    if domain_col:
        where_parts.append(f'"{domain_col}" = %s')
        params.append("continuity")
        filters.append(f"{domain_col}='continuity'")
    if tags_col:
        tags_type = cols_by_name[tags_col].data_type if tags_col in cols_by_name else None
        if tags_type == "ARRAY":
            # Native array (e.g. text[]): match an exact element. NOT ::text LIKE
            # — Postgres renders an array as {continuity} (no quotes), so the
            # quoted-token pattern silently misses it. `= ANY` is also more
            # precise (no 'discontinuity' false positive).
            where_parts.append(f'%s = ANY("{tags_col}")')
            params.append("continuity")
            filters.append(f'"continuity" = ANY({tags_col})')
        else:
            # text holding a JSON array string ("[\"continuity\"]") OR native
            # jsonb. jsonb has no LIKE (~~) operator, so a bare LIKE crashes on
            # it; ::text renders both forms to the same quoted-token string this
            # pattern matches.
            where_parts.append(f'"{tags_col}"::text LIKE %s')
            params.append('%"continuity"%')
            filters.append(f"{tags_col}::text LIKE '\"continuity\"'")
    elif tags_jsonb_col:
        where_parts.append(f'"{tags_jsonb_col}"->\'tags\' @> %s::jsonb')
        params.append('["continuity"]')
        filters.append(f'{tags_jsonb_col}->tags @> ["continuity"]')

    # No way to identify continuity atoms on this schema (no domain, no tags
    # column, no jsonb content blob) -> fail loud with an explanatory empty
    # rather than a silent [] that reads as "nothing to continue".
    if not where_parts:
        return {"atoms": [], "_unmapped": unmapped,
                "_note": "cannot identify continuity atoms on this schema — none of "
                         "'domain', a top-level 'tags' column, or a jsonb 'content' "
                         "blob is available to filter on"}
    where_sql = " OR ".join(where_parts)
    retract_sql, retract_params = kbc.sql_exclude_retracted(tags_col, cols_by_name)
    params.extend(retract_params)
    params.append(limit)

    cur = pg.cursor()
    cur.execute(
        f'SELECT {select_clause} FROM knowledge WHERE ({where_sql}){retract_sql} '  # nosec B608 - select_clause/where_sql/retract_sql/id_col come from the confirmed schema_profile field mapping, not request input; all values are bound params
        f'ORDER BY "{id_col}" DESC LIMIT %s',
        params,
    )
    rows = cur.fetchall()
    cur.close()

    # _continuity_filter is always present so an empty result is legible: it
    # says exactly WHAT was searched, distinguishing "genuinely nothing to
    # continue" from "the query couldn't target this schema" (B-15 fail-loud).
    result = {
        "atoms": [kbc.enrich_atom(_row_to_dict(r, present, unmapped)) for r in rows],
        "_continuity_filter": filters,
    }
    if unmapped:
        result["_unmapped"] = unmapped
    return result


# ── Agent dispatch tools ───────────────────────────────────────────────────────

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("agent_route")
def agent_route(
    app_id: str,
    task: str,
    target_agent: str,
    context: Optional[dict] = None,
) -> dict:
    """Record a routing decision — "this task goes to that agent" — in the
    fleet's routing_decisions ledger and return a routing_id for correlating
    the eventual outcome. Does NOT start or notify the target agent: pair with
    dispatch_send to actually deliver the work, and report completion via
    agent_dispatch_result."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    import hashlib
    routing_id = str(uuid.uuid4())[:8].upper()
    prompt_hash = hashlib.sha256(task.encode()).hexdigest()[:16]
    decision = {"task": task, "target": target_agent, "context": context or {}}
    try:
        cur = pg.cursor()
        cur.execute(
            "INSERT INTO routing_decisions "
            "(id, prompt_hash, session_id, rule_id, confidence, decision, kind) "
            "VALUES (%s, %s, %s, %s, %s, %s, 'agent_route')",
            (routing_id, prompt_hash, app_id, target_agent, 1.0, json.dumps(decision))
        )
        cur.close()
    except Exception as e:
        return {"error": f"routing_unavailable: {e}"}
    return {"routing_id": routing_id, "target": target_agent, "status": "routed"}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("agent_dispatch_result")
def agent_dispatch_result(
    app_id: str,
    routing_id: str,
    result: str,
    status: str = "done",
) -> dict:
    """Close the loop on an agent_route call: attach the outcome — `result`
    text plus `status` (e.g. 'done', 'failed') — to the routing_decisions row
    named by `routing_id`. Returns {routing_id, status}, or {error: not_found}
    for an unknown routing_id."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    try:
        cur = pg.cursor()
        cur.execute(
            "UPDATE routing_decisions "
            "SET decision = decision || %s::jsonb "
            "WHERE id = %s",
            (json.dumps({"result": result, "dispatch_status": status}), routing_id)
        )
        updated = cur.rowcount
        cur.close()
    except Exception as e:
        return {"error": f"routing_unavailable: {e}"}
    return {"routing_id": routing_id, "status": status} if updated else {"error": "not_found"}


# ── Verb-level citation-before-act enforcement (#333) ──────────────────────────
#
# Background: envelope use counts are DERIVED by counting `envelope_citation`
# entries in FRANK, never a stored counter (envelopes.py's own docstring, and
# the schema note in pre-approved.json: "a stored counter is mutable state an
# agent could touch, a derived count is not"). That design has a hole: a verb
# an envelope governs only gets metered if *something* writes the citation
# first, and until now the only writer was the `envelope_apply` tool — a
# separate, optional call. An enveloped verb (observed: `dispatch_send`) that
# simply never calls `envelope_apply` writes no citation and is never charged
# or denied; the meter reads clean whether the caller complied or bypassed
# governance entirely. Cite-before-act was discipline, not mechanism.
#
# Fix: the verb's own handler resolves its governing envelope and cites it
# itself, before the act, so citation and act are one indivisible call --- an
# uncited act becomes impossible rather than merely discouraged.
#
# VERB_LEVEL_ENFORCED_VERBS names every syscall-table verb whose MCP tool
# handler now carries this gate at its own top (currently just "dispatch" —
# dispatch_send, the bypass the issue observed). Growing this set means
# wiring `_enveloped_verb_gate` into that verb's own handler the same way;
# it is not itself an enforcement mechanism, only the roster `envelope_apply`
# below consults to know which verbs already cite for themselves.
VERB_LEVEL_ENFORCED_VERBS = frozenset({"dispatch"})


def _enveloped_verb_gate(
    app_id: str, verb: str, call_args: dict, *, project: str, session: str = ""
) -> Optional[dict]:
    """Cite-before-act for one verb-governed MCP tool call (#333).

    Resolves the active envelope (if any) governing `verb` for `app_id` and,
    when one exists, writes its FRANK citation and enforces its quota BEFORE
    the caller is allowed to proceed — the same indivisible check-then-cite
    `envelope_apply` already performs, just triggered by the verb's own
    handler instead of a separate opt-in call.

    Returns ``None`` when the call may proceed: either no envelope governs
    `verb` for this actor (today's behavior, unmetered — an envelope
    programme that grants nothing here is not a reason to refuse an act
    nothing ever governed), or a governing envelope granted the citation.
    Returns an error dict the caller MUST return immediately, without
    performing the act, when a governing envelope was FOUND but refused
    (quota exhausted, bounds mismatch, expired, revoked, ...), when more than
    one active envelope governs this verb+actor pair (ambiguous — refused
    rather than guessed), or when a governing envelope was found but
    Postgres is unreachable to cite it.

    Resolving *whether* the verb is governed needs only the registry file
    (no Postgres) — see `envelopes.governing_envelope_ids`. Postgres is only
    required once a governing envelope is actually found, to write the
    citation and read the derived count; a Postgres-less install with no
    envelope configured for this verb+actor is unaffected, same as before
    #333. Once a governing envelope IS found, missing Postgres fails closed
    (mirrors `envelope_apply`'s own `_postgres_unavailable()` — a citation
    that cannot be written must not be treated as though it were).

    Backward-compat note: an UNREADABLE registry (missing file, wrong
    ownership/permissions, malformed JSON — `governing_envelope_ids` raises
    for all three, same as `EnvelopeAuthority.check()` does for an
    explicitly-named envelope_id) is treated here as "not governed", NOT as
    a fail-closed refusal. This is deliberately narrower than `check()`'s own
    fail-closed stance: `check()` is reached only when a caller already
    asserts a specific `envelope_id` ought to apply (`envelope_apply`, or
    this same gate once a match IS found), so refusing on an unreadable
    registry there is refusing a claim that cannot be verified. This
    resolution step runs on EVERY call to an enforced verb, for every actor,
    whether or not they hold — or believe they hold — any envelope at all;
    treating "the registry itself is missing" as a hard failure here would
    turn every install that has not configured envelope governance (which is
    most installs — the shipped default is an empty starter, see
    envelopes.py's `registry_path` docstring) into one where dispatch_send
    cannot run at all. An actor that genuinely holds an active "dispatch"
    grant in a registry that then becomes unreadable degrades to unmetered,
    exactly the pre-#333 behavior for that actor — not a new hole, since
    #333 closes the "held a grant, cited nothing" bypass, not "the
    environment is broken in a way that predates this fix" cases."""
    try:
        from .envelopes import governing_envelope_ids

        matches = governing_envelope_ids(verb, app_id)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not matches:
        # PR6 (envelope-accrual): ENOGRANTS. Currently the gate is
        # permissive here (returns None → call proceeds unmetered) —
        # behavior preserved. But an attributed orchestrator session
        # that hits this path is a good signal the operator would want
        # to ratify an envelope covering this shape, so it becomes a
        # queue entry. Silent best-effort; gate's real return is
        # unchanged.
        _auto_propose_on_gate_miss(app_id, verb, call_args, session)
        return None
    if len(matches) > 1:
        return {
            "error": "EAMBIG",
            "reason": "multiple active envelopes govern this verb for actor",
            "envelope_ids": matches,
        }
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    try:
        from .envelopes import EnvelopeAuthority
        from .governance_ledger import GovernanceLedger

        result = EnvelopeAuthority(GovernanceLedger(pg)).authorize_and_cite(
            matches[0],
            actor=app_id,
            verb=verb,
            call_args=call_args,
            project=project,
            session=session,
        )
    except Exception as exc:
        return {"error": f"envelope_gate_failed: {exc}"}
    if result.get("ok"):
        return None
    # PR6: envelope existed but the check failed (bounds mismatch, quota
    # exhausted, expiry). Auto-propose captures the ACTUAL call_args so
    # the operator can widen bounds or bump quota with one ratify click
    # rather than diffing errno.reason.fields[] against the current
    # envelope by hand.
    _auto_propose_on_gate_miss(app_id, verb, call_args, session)
    return {
        "error": result.get("errno", "EAMBIG"),
        "reason": result.get("reason"),
        "citation_id": result.get("citation_id"),
    }


# PR6: dedup for auto-propose. A single call site can hit the gate many
# times per session (dispatch loops, retry paths); we don't want the queue
# to fill with 20 identical proposals for one shape. Track (session, verb,
# bounds_digest) tuples in-process — cleared on process restart, same
# discipline the attribution cache follows.
_auto_propose_seen: set[tuple[str, str, str]] = set()
_auto_propose_seen_lock = None

# Follow-on to PR6, filed against Nestor's dogfood prior:
#   "A ledger line that will not parse is a state that cannot happen.
#    What does the code do when it happens? It ignored it. entries()
#    walked past and returned a shorter chain in silence. Fixed with
#    a second walk — ledger.unreadable() — rather than a condition
#    inside the first."
#
# Same shape here. The auto-propose write path is deliberately silent
# so an EnvelopeAuthoringError doesn't mask the specialist's real errno
# (that reasoning stays right). But silence on the WRITE path shouldn't
# mean the discards leave no residue anywhere: an operator whose queue
# says "3 pending" needs to know if it should have said "5 pending, 2
# lost." The two-walk pattern: propose() writes what succeeds,
# _auto_propose_discards accumulates what got swallowed. The orient
# block surfaces the count so the operator sees the residue at seat-open,
# not weeks later when a shape they thought was queued turns out not to
# be.
_auto_propose_discards: list[dict] = []


def _auto_propose_lock():
    global _auto_propose_seen_lock
    if _auto_propose_seen_lock is None:
        import threading
        _auto_propose_seen_lock = threading.Lock()
    return _auto_propose_seen_lock


def clear_auto_propose_cache(session: str = "") -> None:
    """Drop cached dedup tuples AND discard residue. Empty session clears
    the whole cache and all discards (test-fixture / operator-restart use);
    a specific session drops just that session's memoized shapes and
    swallowed proposals."""
    with _auto_propose_lock():
        if not session:
            _auto_propose_seen.clear()
            _auto_propose_discards.clear()
            return
        stale = [key for key in _auto_propose_seen if key[0] == session]
        for key in stale:
            _auto_propose_seen.discard(key)
        _auto_propose_discards[:] = [
            d for d in _auto_propose_discards if d.get("session_id") != session
        ]


def list_auto_propose_discards(session: str = "") -> list[dict]:
    """Read the swallowed-auto-propose residue accumulated in this process.

    Second walk of the two-walk pattern the Nestor dogfood prior names:
    the write path (propose) yields what succeeded; this yields what got
    discarded. Non-empty means at least one gate miss failed to land in
    the queue — the operator's pending count is a floor, not the true
    count. Empty ``session`` returns all discards; a specific session_id
    filters. Read-only; does not touch the cache."""
    with _auto_propose_lock():
        if not session:
            return list(_auto_propose_discards)
        return [d for d in _auto_propose_discards
                if d.get("session_id") == session]


def _auto_propose_on_gate_miss(
    app_id: str, verb: str, call_args: dict, session: str
) -> None:
    """PR6 back-channel: turn a gate refusal into a queue entry.

    Silent best-effort. Never blocks or alters the gate's return path — the
    caller still receives the original success/refusal signal. Fires only
    when the current session is an attributed orchestrator session (per
    PR1-4 identity) whose record carries a verifier; skips otherwise so
    unattributed / specialist-owned processes cannot spam the queue.

    Dedup by (session, verb, bounds_digest) tuple: repeat calls with the
    same shape produce one proposal, not N.

    Specialist-side auto-propose (a specialist's OWN process auto-proposing
    from ITS ENOGRANTS, attributed via the dispatch packet's from_app) is
    deferred to a follow-up: it needs the dispatch packet meta.json to
    carry the orchestrator's verifier, which is a schema extension in a
    separate PR.
    """
    from . import envelope_authoring as _ea
    from . import human_session as _hs
    from . import keyring as _keyring

    if not _keyring.enabled():
        return
    if not session or not _hs.is_session_attributed(session):
        return
    # Read the session record — must have a verifier bound (PR2 discipline).
    # dispatch_stack.session_read expects (app_id, session_id).
    record = dispatch_stack.session_read(app_id, session)
    verifier = (record or {}).get("verifier", "")
    if not verifier:
        return

    # Dedup: same (session, verb, bounds) → one proposal, not N.
    try:
        digest = _ea._bounds_digest(dict(call_args or {}))
    except Exception:
        return
    key = (session, verb, digest)
    with _auto_propose_lock():
        if key in _auto_propose_seen:
            return
        _auto_propose_seen.add(key)

    pg = get_pg()
    ledger = None
    if pg is not None:
        try:
            from .governance_ledger import GovernanceLedger
            ledger = GovernanceLedger(pg)
        except Exception:
            ledger = None
    try:
        _ea.propose(
            verb=verb, grantee=app_id, bounds=dict(call_args or {}),
            reason=f"auto-proposed from gate miss on session {session}",
            verifier=verifier, session_id=session,
            proposer_app_id=app_id, ledger=ledger,
        )
    except _ea.EnvelopeAuthoringError as exc:
        # Silent on the WRITE path — auto-propose failing must never mask
        # the gate's real return signal. UnknownVerbError, UnattributedSessionError,
        # InvalidBoundsSignatureError — all fall through here so the
        # specialist still sees its original errno.
        #
        # BUT the discard is not silent overall. Record it in the residue
        # walk so the orient block can surface "3 pending, 2 discarded"
        # at the operator's next seat-open. Nestor's dogfood prior on
        # ledger.unreadable() is the shape: a discard leaves no residue to
        # count is the failure; a companion walk fixes it.
        from datetime import datetime, timezone
        with _auto_propose_lock():
            _auto_propose_discards.append({
                "session_id": session,
                "verifier": verifier,
                "app_id": app_id,
                "verb": verb,
                "bounds": dict(call_args or {}),
                "error_class": type(exc).__name__,
                "error_message": str(exc)[:400],
                "at": datetime.now(timezone.utc)
                    .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            })


# Project used for the FRANK citation a verb-level gate writes on the caller's
# behalf. Verb-level citations (unlike `envelope_apply`'s, which takes an
# explicit `project`) have no natural project/workspace of their own — the
# citation exists to meter and audit the grant, not to file the act under a
# workspace — so they are recorded under the same fixed "governance" project
# `GovernanceLedger.rechain()`'s own self-documenting marker rows use for
# mechanism-level FRANK entries that aren't about any one project.
_VERB_CITATION_PROJECT = "governance"


# ── Dispatch packet stack (filesystem — no Postgres required) ─────────────────

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("dispatch_send")
def dispatch_send(
    app_id: str,
    to_app: str,
    assignment_md: str,
    role: str = "",
    reply_to: str = "willow",
    summary: str = "",
    phase: str = "operate",
    priority: str = "normal",
    context_refs: Optional[list] = None,
) -> dict:
    """Create a dispatch packet assigning work to another agent: writes
    meta.json + assignment.md with status 'pending' under
    $WILLOW_HOME/dispatch/. `assignment_md` is the full brief the specialist
    will read; `reply_to` names who verifies the handoff. The packet advances
    pending → working → complete via dispatch_accept and handoff_write_v4.
    Filesystem-backed unless an authority envelope governs verb "dispatch"
    for this caller (#333) — then citing that envelope (and its quota) gates
    the write, Postgres-backed for that one check. Returns the new packet's
    metadata including its dispatch_id."""
    # #333: cite-before-act. `role` is resolved here with dispatch.py's own
    # fallback (`role or to_app`, lowercased) so the bounds an envelope is
    # checked against name the same task_class dispatch.py will actually
    # record as `role` on the packet — not a value the gate invented.
    resolved_role = (role or to_app).lower()
    orch_session = _current_orchestrator_session()
    gate_err = _enveloped_verb_gate(
        app_id,
        "dispatch",
        {"to_agents": to_app, "task_class": resolved_role},
        project=_VERB_CITATION_PROJECT,
        session=orch_session,
    )
    if gate_err:
        return gate_err
    # Envelope-accrual PR9: propagate the operator's identity onto the
    # dispatch packet so the specialist can inherit attribution. The
    # session record for the currently-entered orchestrator carries the
    # verifier PR2/PR3 bound on session_enter; look it up here and pass
    # it through to _meta_new. Silent when the orchestrator's session is
    # unattested (verifier=""), which is the same "no orchestrator to
    # attribute to" case that already skips auto-propose today.
    from_verifier = ""
    from_session = ""
    if orch_session:
        rec = dispatch_stack.session_read(app_id, orch_session)
        if not rec.get("error"):
            from_verifier = str(rec.get("verifier") or "").strip()
            if from_verifier:
                from_session = orch_session
    return dispatch_stack.dispatch_send(
        from_app=app_id,
        to_app=to_app,
        assignment_md=assignment_md,
        role=role,
        reply_to=reply_to,
        summary=summary,
        phase=phase,
        priority=priority,
        context_refs=context_refs,
        from_verifier=from_verifier,
        from_session=from_session,
    )


@mcp.tool(annotations=_ANNO_READ)
@_guarded("dispatch_read")
def dispatch_read(app_id: str, dispatch_id: str) -> dict:
    """Read one dispatch packet by ID: its meta (from/to app, role, phase,
    priority), current status, and the full assignment.md body. Read-only —
    how a specialist sees its brief before calling dispatch_accept. Returns
    {error: not_found} for an unknown dispatch_id, or {error:
    not_party_to_dispatch} if app_id is neither from_app, to_app, reply_to,
    nor the orchestrator (B-54, issue #242 -- dispatch_read permission alone
    used to let any holder read any dispatch_id's full content)."""
    pkt = dispatch_stack.dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id) and not dispatch_stack.is_dispatch_party(app_id, pkt["meta"]):
        return {"error": "not_party_to_dispatch", "dispatch_id": dispatch_id}
    return pkt


@mcp.tool(annotations=_ANNO_READ)
@_guarded("dispatch_list")
def dispatch_list(
    app_id: str,
    to_app: str = "",
    from_app: str = "",
    status: str = "",
    limit: int = 20,
    cursor: Optional[str] = None,
) -> dict:
    """List dispatch packets newest-first, filtered by any combination of
    to_app / from_app / status ('' = no filter).  Paginated: returns
    ``{dispatches, total, unverified, unverified_total, next_cursor}`` — pass
    the returned ``next_cursor`` as ``cursor`` to fetch the next page.
    Returns packet metadata only, no assignment bodies — use dispatch_read
    for one packet's brief.  Read-only. ``dispatches`` only carries packets
    whose meta.json HMAC signature verified (B-52, issue #241); a packet with
    no signature (legacy, pre-dates signing) or a wrong one (tampered/forged)
    is never mixed into it, instead appearing in ``unverified`` with
    ``unverified: true`` and a ``signature_status`` of ``legacy_unsigned`` or
    ``invalid``."""
    return dispatch_stack.dispatch_list(
        to_app=to_app, from_app=from_app, status=status, limit=limit,
        cursor=cursor,
    )


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("dispatch_accept")
def dispatch_accept(
    app_id: str,
    dispatch_id: str,
    session_id: str = "",
) -> dict:
    """Accept a dispatch packet addressed to you: flips its status pending →
    working and records your session_id against it. Refuses if the packet is
    addressed to a different app (wrong_recipient) or is not currently pending
    (invalid_transition). Read the brief with dispatch_read first; close out
    with handoff_write_v4 when the work is done."""
    return dispatch_stack.dispatch_accept(dispatch_id, app_id, session_id)


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("handoff_write_v4")
def handoff_write_v4(
    app_id: str,
    dispatch_id: str,
    findings: Optional[list] = None,
    narrative: str = "",
    checklist_resolved: bool = True,
    envelope_clean: bool = True,
) -> dict:
    """Close out a dispatch you accepted: writes handoff.json (the structured
    `findings` list) plus closeout.md (the `narrative`) into the packet and
    flips its status to complete. `checklist_resolved` and `envelope_clean`
    are your declarations that the assignment checklist is finished and no
    authority envelope was left open — the orchestrator checks both in
    verify_handoff before releasing you via agent_clear."""
    return handoff_stack.handoff_write_v4(
        app_id,
        dispatch_id,
        findings=findings,
        narrative=narrative,
        checklist_resolved=checklist_resolved,
        envelope_clean=envelope_clean,
    )


@mcp.tool(annotations=_ANNO_READ)
@_guarded("handoff_read")
def handoff_read(app_id: str, dispatch_id: str) -> dict:
    """Read the closeout of a completed dispatch: the structured handoff.json
    findings plus the closeout.md narrative. What the orchestrator reads
    before verify_handoff, and what a successor agent reads to pick up the
    thread. Read-only. Returns {error: not_party_to_dispatch} if app_id is
    neither from_app, to_app, reply_to, nor the orchestrator (B-54, issue
    #242 -- same packet-party check as dispatch_read)."""
    pkt = dispatch_stack.dispatch_read(dispatch_id)
    if pkt.get("error"):
        return pkt
    from .human_session import is_orchestrator_app

    if not is_orchestrator_app(app_id) and not dispatch_stack.is_dispatch_party(app_id, pkt["meta"]):
        return {"error": "not_party_to_dispatch", "dispatch_id": dispatch_id}
    return handoff_stack.handoff_read(dispatch_id)


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("verify_handoff")
def verify_handoff(app_id: str, dispatch_id: str) -> dict:
    """Orchestrator-side check of a completed dispatch's handoff: confirms the
    closeout exists and its declarations hold — checklist resolved, envelope
    clean, findings present. Sets status to 'verified'. Run this before
    agent_clear releases the specialist for its next packet."""
    return handoff_stack.verify_handoff(dispatch_id)


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("agent_clear")
def agent_clear(
    app_id: str,
    target_app: str,
    dispatch_id: str,
    session_id: str = "",
) -> dict:
    """Release a specialist after its handoff has been verified: clears
    `target_app`'s live assignment state for `dispatch_id`, leaving the agent
    ready for the next packet. The final step of the dispatch lifecycle
    (send → accept → handoff → verify → clear); orchestrator-side."""
    return dispatch_stack.agent_clear(target_app, dispatch_id, session_id)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("session_read")
def session_read(app_id: str, session_id: str) -> dict:
    """Read the thin per-session state file for an app/session pair — entry
    mode, bound dispatch, project/workspace — as written by session_enter.
    Returns {error: not_found} for an unknown session. Read-only."""
    return dispatch_stack.session_read(app_id, session_id)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("sessions_read_unverifiable")
def sessions_read_unverifiable() -> dict:
    """PR4 of the identity-in-session plan: enumerate orchestrator sessions
    whose attestation sidecar exists but no longer verifies. The browsable
    trust-view an operator needs after a keyring compromise, a key rotation
    that invalidated prior sigs, or a tampered sidecar — without this, the
    operator learns about invalidated sessions one denial-per-write at a
    time.

    Returns {"unverifiable": [{session_id, verifier, format, reason}, ...]}.
    A session with a sidecar that verifies is NOT listed. A session with no
    sidecar at all is NOT listed either (that is unattested, not
    unverifiable). Read-only — does not touch the attribution cache or the
    ledger."""
    from . import human_session

    return {"unverifiable": human_session.list_unverifiable_sessions()}


@mcp.tool(annotations=_ANNO_WRITE_IDEM)
@_guarded("session_enter")
def session_enter(
    app_id: str,
    session_id: str,
    dispatch_id: str = "",
    project: str = "",
    workspace: str = "",
    verifier: str = "",
    attested_at: str = "",
    seal_sig: str = "",
) -> dict:
    """FIRST CALL of any session. Registers the app/session pair, resolves the
    entry mode (human seat vs dispatched specialist — pass `dispatch_id` when
    entering to work an assigned packet), and returns orientation: project
    info, ORIENT.md presence, standing records (stack, portfolio, milestones,
    commitments, governance flags), the latest project handoff, collection
    aliases, and FRANK ledger presence. Close the session later with
    session_handoff_write (human path) or handoff_write_v4 (dispatch path).

    Identity-in-session PR2: `verifier`, `attested_at`, and `seal_sig` are
    optional and route through the willow orchestrator branch. When the
    per-verifier keyring (`WILLOW_KEYRING`) is enabled and all three are
    supplied, the signature is verified over the frozen wire message BEFORE
    any session record is written; an invalid signature returns a structured
    error rather than a raw exception. When the keyring is not enabled the
    three parameters are ignored and pre-PR2 behavior stands verbatim."""
    from . import session_signing as _session_signing

    try:
        result = dispatch_stack.session_enter(
            app_id,
            session_id,
            dispatch_id,
            project=project,
            workspace=workspace,
            verifier=verifier,
            attested_at=attested_at,
            seal_sig=seal_sig,
        )
    except _session_signing.InvalidSessionSignatureError as exc:
        return {
            "app_id": app_id,
            "session_id": session_id,
            "error": "invalid_session_signature",
            "message": str(exc),
        }
    if result.get("error"):
        return result

    from .human_session import is_orchestrator_app
    if is_orchestrator_app(app_id):
        _set_orchestrator_session(session_id)

    from . import gate

    project_info = result.get("project") or {}
    root = Path(project_info["root"]) if project_info.get("root") else None
    aliases = gate.collection_aliases(app_id)
    reads: dict[str, Any] = {}
    for logical in (
        "stack",
        "pm/portfolio",
        "pm/milestones",
        "pa/commitments",
        "governance/flags",
    ):
        physical = aliases.get(logical)
        if not physical:
            reads[logical] = {"error": "alias_not_configured"}
        elif not gate.collection_permitted(app_id, physical):
            reads[logical] = _collection_denied(app_id, physical)
        else:
            reads[logical] = _store.all(physical)
    orient_path = root / "ORIENT.md" if root else None
    project_name = project_info.get("name")
    result["orientation"] = {
        "orient": {
            "path": str(orient_path) if orient_path else None,
            "exists": bool(orient_path and orient_path.is_file()),
        },
        "records": reads,
        "latest_handoff": (
            dispatch_stack.latest_project_handoff(app_id, project_name)
            if project_name
            else None
        ),
        "collection_aliases": aliases,
        "frank": {
            "status": (
                "present"
                if root and (root / "FRANK").exists()
                else "not_present"
            ),
            "path": str(root / "FRANK") if root else None,
        },
    }
    from .stack_snapshot import read_stack_snapshot

    snap = read_stack_snapshot(app_id)
    if snap:
        result["orientation"]["stack_snapshot"] = snap

    # PR6 (envelope-accrual): surface the operator's pending-proposal count
    # at seat entry so an attributed orchestrator sees "N proposals waiting
    # for ratification" as part of orient, not mid-dispatch when the queue
    # has silently grown. Only surfaced for orchestrator sessions — a
    # specialist's orient block doesn't include the operator queue.
    #
    # Follow-on: surface the auto-propose discard residue too. Nestor
    # prior (dogfood: ledger.unreadable): a discard leaves no residue to
    # count is the failure. Non-zero discards mean the pending count is a
    # floor, not the true count — the operator needs to know that at
    # seat-open, not weeks later.
    from .human_session import is_orchestrator_app
    if is_orchestrator_app(app_id):
        try:
            from . import envelope_authoring as _ea
            pending = _ea.list_pending(oldest_first=True, limit=1000)
            result["orientation"]["envelope_proposals_pending"] = {
                "count": len(pending),
                "oldest_id": pending[0]["id"] if pending else None,
                "oldest_at": pending[0].get("proposed_at") if pending else None,
            }
        except Exception:
            # A missing registry / trusted_read failure is not a reason to
            # refuse session_enter — the queue count is orient sugar, the
            # registry itself is checked by the auto-propose path with
            # its own error handling.
            pass
        discards = list_auto_propose_discards()
        result["orientation"]["envelope_auto_propose_discards"] = {
            "count": len(discards),
            "latest_error_class": (
                discards[-1]["error_class"] if discards else None
            ),
        }
    return result


@mcp.tool(annotations=_ANNO_READ)
@_guarded("envelope_read_discards")
def envelope_read_discards(session_id: str = "") -> dict:
    """Read the auto-propose discard residue for the current process.

    PR6 auto-propose (envelope-accrual) is silent on failure — it swallows
    EnvelopeAuthoringError so the specialist's real errno isn't masked.
    But silence on the write path shouldn't mean the discards leave no
    residue. This tool is the second walk (mirroring Nestor's
    ledger.unreadable() pattern): what got proposed AND what got
    swallowed, so the operator can see whether the pending queue is
    the full picture or a floor.

    Empty ``session_id`` returns all discards this process has seen; a
    specific session_id filters. Discards are cleared on process
    restart (same discipline as the attribution and dedup caches);
    ``clear_auto_propose_cache()`` also clears them per-session or
    globally."""
    return {"discards": list_auto_propose_discards(session=session_id or "")}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("session_handoff_write")
def session_handoff_write(
    app_id: str,
    session_id: str,
    narrative: str,
    summary: str = "",
    findings: Optional[list] = None,
    next_bite: str = "",
    project: str = "",
    workspace: str = "",
) -> dict:
    """Close a human-entry session with a project-scoped markdown closeout:
    `narrative` (what happened), `summary`, structured `findings`, and
    `next_bite` — the suggested next step for whoever resumes. The human-path
    sibling of handoff_write_v4, which closes dispatched work and requires a
    dispatch_id; this one needs only the session."""
    return dispatch_stack.session_handoff_write(
        app_id,
        session_id,
        narrative=narrative,
        summary=summary,
        findings=findings,
        next_bite=next_bite,
        project=project,
        workspace=workspace,
    )


# ── Specialist registry (desk) ───────────────────────────────────────────────

@mcp.tool(annotations=_ANNO_READ)
@_guarded("specialist_list")
def specialist_list(app_id: str, include_permissions: bool = False) -> dict:
    """List the specialist registry (config/specialists.json): every agent the
    orchestrator can route work to, with role metadata and — when
    include_permissions=true — each one's permission set. Returns {registry,
    specialists, total}. Read-only; use specialist_get for one agent's full
    row and persona."""
    from . import registry as reg

    return {
        "registry": str(reg.registry_path()),
        "specialists": reg.list_specialists(include_permissions=include_permissions),
        "total": len(reg.list_specialists(include_permissions=False)),
    }


@mcp.tool(annotations=_ANNO_READ)
@_guarded("specialist_get")
def specialist_get(app_id: str, agent_id: str, include_permissions: bool = True) -> dict:
    """Fetch one specialist's registry row by agent_id, including its compiled
    persona text and persona file path when available. Returns {error:
    not_found} for an unknown agent. Read-only — how an orchestrator inspects
    a specialist before dispatching work to it."""
    from . import registry as reg

    row = reg.get_specialist(agent_id, include_permissions=include_permissions)
    if not row:
        return {"error": "not_found", "agent_id": agent_id}
    persona = reg.read_persona_text(agent_id)
    if persona is not None:
        row["persona"] = persona
        path = reg.resolve_persona_path(agent_id)
        row["persona_file"] = str(path) if path else None
    return row


@mcp.tool(annotations=_ANNO_READ)
@_guarded("exposure_config_get")
def exposure_config_get(app_id: str) -> dict:
    """Read the standing exposure defaults from $WILLOW_HOME/config/
    exposure.json — which preset governs each seed destination when
    exposure_slice is called without an explicit one. Returns {format, path,
    exists, config}; exists=false means no config file, so built-in defaults
    apply. Read-only (AS-8)."""
    from . import exposure as exp
    from .paths import exposure_config_path, willow_home

    path = exposure_config_path()
    cfg = exp.load_exposure_config()
    return {
        "format": exp.EXPOSURE_FORMAT,
        "path": str(path.relative_to(willow_home())) if path.is_file() else None,
        "exists": path.is_file(),
        "config": cfg,
    }


@mcp.tool(annotations=_ANNO_READ)
@_guarded("exposure_slice")
def exposure_slice(
    app_id: str,
    agent_id: str,
    destination: str = "session_enter",
    preset: str = "",
    fields: list[str] | None = None,
) -> dict:
    """Resolve and apply an exposure preset for a seed destination (AS-8).

    destination: session_enter | kb_ingest | agent_seed_mirror | grove | cloud_llm | dispatch.
    preset: override standing default. fields: custom dotted paths (checkbox IDs).
    """
    from . import exposure as exp

    return exp.build_exposure_slice(
        agent_id,
        destination=destination,
        preset=preset,
        fields=fields,
    )


@mcp.tool(annotations=_ANNO_WRITE_IDEM)
@_guarded("agent_seed_mirror")
def agent_seed_mirror(app_id: str, agent_id: str, slice: str = "") -> dict:
    """Mirror a ratified home seed into SOIL collection willow_agents_seeds (AS-5).

    Requires ratified status; when WILLOW_PGP_FINGERPRINT is set the detached
    .sig must verify. slice: full | voice_only | work_context (omit for exposure.json default).
    """
    from . import gate
    from . import seed_mirror as sm

    if not gate.collection_permitted(app_id, sm.MIRROR_COLLECTION):
        return _collection_denied(app_id, sm.MIRROR_COLLECTION)
    return sm.mirror_seed_to_store(_store, agent_id, slice_name=slice)


# ── Fleet read tools ───────────────────────────────────────────────────────────

@mcp.tool(annotations=_ANNO_READ)
@_guarded("fleet_status")
def fleet_status(app_id: str) -> dict:
    """Read the canonical fleet roster (fleet.json) — every registered agent
    and its declared state — annotated with drift diagnostics wherever the
    fleet Postgres disagrees with the file. Read-only; requires Postgres. Use
    fleet_health for liveness signals rather than roster membership."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    try:
        from .fleet_roster import status

        return status(pg)
    except Exception as e:
        return {"error": f"fleet_unavailable: {e}"}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("frank_read")
def frank_read(app_id: str, project: str = "", limit: int = 50) -> dict:
    """Read recent entries from the FRANK governance ledger — the fleet's
    hash-chained, Postgres-backed audit chain — newest first, optionally
    filtered to one `project`. Each entry carries its prev_hash/hash links;
    use frank_verify to check chain integrity rather than eyeballing them.
    `limit` must be 1–500. Read-only."""
    if limit < 1 or limit > 500:
        return {"error": "limit must be between 1 and 500"}
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    cur = pg.cursor()
    try:
        if project:
            cur.execute(
                "SELECT id, project, event_type, content, created_at, prev_hash, hash "
                "FROM frank_ledger WHERE project=%s ORDER BY created_at DESC LIMIT %s",
                (project, limit),
            )
        else:
            cur.execute(
                "SELECT id, project, event_type, content, created_at, prev_hash, hash "
                "FROM frank_ledger ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
        keys = ("id", "project", "event_type", "content", "created_at", "prev_hash", "hash")
        return {"entries": [dict(zip(keys, row)) for row in cur.fetchall()]}
    except Exception as exc:
        return {"error": f"frank_unavailable: {exc}"}
    finally:
        cur.close()


@mcp.tool(annotations=_ANNO_READ)
@_guarded("frank_verify")
def frank_verify(app_id: str) -> dict:
    """Re-hash the entire FRANK governance chain and verify every prev_hash →
    hash link, detecting tampering, edits, or gaps. Returns the verification
    verdict, including where the chain breaks if it does.

    Also checks the chain's head against the externally-held anchor at
    `$WILLOW_HOME/constitutional/frank_head_anchor.json` when one exists
    (#280): a chain can be internally consistent (every link valid) and
    still not be the same chain it was yesterday — that's what an
    edit-then-`rechain()` relink looks like from outside the database.
    `anchor_status` reports which case applied: "anchored" (compared;
    `valid` reflects both internal consistency AND the head match),
    "unanchored" (no anchor file — most installs, opted out), "untrusted"
    (anchor file failed the ownership/permission trust check), or
    "unreadable" (missing/malformed). Only "anchored" means the head was
    actually compared; the other three are reported explicitly rather than
    silently treated as a pass. Use `willow-mcp frank-anchor` (CLI-only —
    never an MCP tool, so an agent cannot mint its own anchor) to create or
    refresh one. Read-only; may take a moment on a long ledger."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    try:
        from .frank_head_anchor import read_anchor
        from .governance_ledger import GovernanceLedger

        anchor = read_anchor()
        expected_head = anchor["head"] if anchor["status"] == "anchored" else None
        result = GovernanceLedger(pg).verify(expected_head=expected_head)
        result["anchor_status"] = anchor["status"]
        if anchor["status"] == "anchored":
            result["anchor_recorded_at"] = anchor.get("anchored_at")
        return result
    except Exception as exc:
        return {"error": f"frank_unavailable: {exc}"}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("frank_append")
def frank_append(
    app_id: str, project: str, event_type: str, content: dict
) -> dict:
    """Append one event to the shared FRANK governance ledger: `project` +
    `event_type` + an object `content`, hash-chained onto the previous entry.
    Append-only — entries can never be edited or deleted afterwards, so write
    settled facts, not drafts. Returns {id, project, event_type}."""
    if not project or not event_type or not isinstance(content, dict):
        return {"error": "project, event_type, and object content are required"}
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    try:
        from .governance_ledger import GovernanceLedger

        record_id = GovernanceLedger(pg).append(project, event_type, content)
        return {"id": record_id, "project": project, "event_type": event_type}
    except Exception as exc:
        return {"error": f"frank_append_failed: {exc}"}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("envelope_apply")
def envelope_apply(
    app_id: str,
    envelope_id: str,
    verb: str,
    call_args: dict,
    project: str,
    session: str,
) -> dict:
    """Check an authority envelope — an operator-granted, scoped permission —
    BEFORE acting under it: verifies `envelope_id` is active and covers `verb`
    with the given `call_args`, then appends a citation to the FRANK ledger
    recording the use against `project`/`session`. Refuses with the reason
    when the grant is missing, expired, or out of scope.

    #333 double-charging note: `verb` in VERB_LEVEL_ENFORCED_VERBS (currently
    just "dispatch") now cites itself from inside its own tool handler
    (dispatch_send) — that handler is authoritative for the act. Calling
    envelope_apply first for one of those verbs and then performing the act
    would charge the grant's quota twice for one real act, so for those verbs
    this tool is advisory-only: it still runs the full `check()` (so a caller
    can preflight "would this be granted?" without side effects) but does NOT
    write a citation — `cited_before_act` comes back False and `note` says so.
    The verb handler cites exactly once, at the act, regardless of whether
    envelope_apply was called first. Every other verb is unchanged: still
    checks AND cites here, since no other verb has a handler-side citation
    path yet."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()
    try:
        from .envelopes import EnvelopeAuthority
        from .governance_ledger import GovernanceLedger

        authority = EnvelopeAuthority(GovernanceLedger(pg))
        if verb in VERB_LEVEL_ENFORCED_VERBS:
            result = authority.check(
                envelope_id, actor=app_id, verb=verb, call_args=call_args
            )
            return {
                **result,
                "citation_id": None,
                "cited_before_act": False,
                "note": (
                    f"verb {verb!r} cites automatically when its own tool call "
                    "executes (#333) — envelope_apply is advisory-only here to "
                    "avoid charging this grant's quota twice for one act."
                ),
            }
        return authority.authorize_and_cite(
            envelope_id,
            actor=app_id,
            verb=verb,
            call_args=call_args,
            project=project,
            session=session,
        )
    except Exception as exc:
        return {"error": f"envelope_apply_failed: {exc}"}


# ---------------------------------------------------------------------------
# Envelope authoring (PR5 of the envelope-accrual plan).
#
# envelope_apply above is the READ side of the envelope contract — check a
# grant, cite it, run the act. These five tools are the WRITE side that was
# missing: an agent proposes into pre-approved.json#proposals[], an operator
# ratifies (moves to active[]) or rejects (records the "no" with reopen_when),
# and both surfaces are readable. Every authoring act appends a FRANK ledger
# event alongside the existing envelope_citation events.
#
# All five gate on the CURRENT ORCHESTRATOR SESSION (per PR1-4 attribution):
# propose/ratify/reject require an entered orchestrator session whose verifier
# passes the keyring check. Specialists cannot MCP-call these directly; the
# auto-propose path from _enveloped_verb_gate (PR6) is how a specialist's
# gate miss lands in the queue attributed to the orchestrator that
# dispatched it. See docs/design/envelope-accrual.md.
# ---------------------------------------------------------------------------


def _envelope_authoring_session() -> tuple[str, str] | dict:
    """(verifier, session_id) for the current orchestrator session, or a
    structured refusal dict when no attributed session is in force.

    Every envelope authoring MCP tool routes through this. The pattern
    matches human_session.orchestrator_write_denial's discipline: refuse at
    the boundary, name the missing piece, point at the fix."""
    from . import human_session as _hs
    session_id = _current_orchestrator_session()
    if not session_id:
        return {"error": "orchestrator_session_required",
                "message": "envelope authoring requires an entered orchestrator "
                "session (call session_enter(app_id='willow', session_id=...) "
                "first)."}
    record = dispatch_stack.session_read("willow", session_id)
    verifier = (record or {}).get("verifier", "")
    if not verifier:
        return {"error": "unattributed_session",
                "message": (
                    f"session {session_id!r} has no verifier on record — "
                    "envelope authoring is attribution-gated. Sign the "
                    f"session with `willow-mcp sign-session {session_id} "
                    "--verifier NAME` from an operator terminal (PR3), then "
                    "call session_enter again with the seal_sig."
                )}
    if not _hs.is_session_attributed(session_id):
        return {"error": "unattributed_session",
                "message": (
                    f"session {session_id!r} carries verifier {verifier!r} "
                    "on record but is not in the process's attribution "
                    "cache. This can mean the sig was invalidated "
                    "(compromised key, tampered sidecar) or the process was "
                    "restarted after a revocation. Call an orchestrator "
                    "write once (e.g. dispatch_list) to refresh the cache, "
                    "or check `sessions_read_unverifiable`."
                )}
    return verifier, session_id


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("envelope_propose")
def envelope_propose(
    verb: str,
    grantee: str,
    bounds: dict,
    reason: str,
    expires_at: str = "",
    max_count: int | None = None,
) -> dict:
    """Draft an envelope into pre-approved.json#proposals[]. No force until
    the operator ratifies. Attribution-gated: refuses when the current
    orchestrator session isn't keyring-attributed (PR1-4). Writes an
    envelope_proposed event to the FRANK ledger."""
    ctx = _envelope_authoring_session()
    if isinstance(ctx, dict):
        return ctx
    verifier, session_id = ctx
    from . import envelope_authoring as _ea
    pg = get_pg()
    ledger = None
    if pg is not None:
        from .governance_ledger import GovernanceLedger
        ledger = GovernanceLedger(pg)
    try:
        row = _ea.propose(
            verb=verb, grantee=grantee, bounds=bounds, reason=reason,
            verifier=verifier, session_id=session_id,
            expires_at=expires_at or None, max_count=max_count,
            ledger=ledger, proposer_app_id="willow",
        )
    except _ea.EnvelopeAuthoringError as exc:
        return {"error": type(exc).__name__, "message": str(exc)}
    return {"ok": True, "proposal": row}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("envelope_ratify")
def envelope_ratify(proposal_id: str) -> dict:
    """Move a proposal from proposals[] to active[]. Operator-only; requires
    the current orchestrator session's verifier to pass the keyring check.
    Writes envelope_ratified to the FRANK ledger. issued_by is stamped as
    'root' (invariant preserved from pre-PR5)."""
    ctx = _envelope_authoring_session()
    if isinstance(ctx, dict):
        return ctx
    verifier, _ = ctx
    from . import envelope_authoring as _ea
    pg = get_pg()
    ledger = None
    if pg is not None:
        from .governance_ledger import GovernanceLedger
        ledger = GovernanceLedger(pg)
    try:
        row = _ea.ratify(proposal_id, verifier=verifier, ledger=ledger)
    except _ea.EnvelopeAuthoringError as exc:
        return {"error": type(exc).__name__, "message": str(exc)}
    return {"ok": True, "envelope": row}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("envelope_reject")
def envelope_reject(
    proposal_id: str, reason: str, reopen_when: str = ""
) -> dict:
    """Record a "no" on a proposal. Same operator-attribution gate as
    envelope_ratify. reopen_when distinguishes NEVER (empty) from NOT YET
    (non-empty), mirroring nestor.memory.reject_match's shape."""
    ctx = _envelope_authoring_session()
    if isinstance(ctx, dict):
        return ctx
    verifier, _ = ctx
    from . import envelope_authoring as _ea
    pg = get_pg()
    ledger = None
    if pg is not None:
        from .governance_ledger import GovernanceLedger
        ledger = GovernanceLedger(pg)
    try:
        row = _ea.reject(
            proposal_id, reason=reason, verifier=verifier,
            reopen_when=reopen_when, ledger=ledger,
        )
    except _ea.EnvelopeAuthoringError as exc:
        return {"error": type(exc).__name__, "message": str(exc)}
    return {"ok": True, "rejection": row}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("envelope_list")
def envelope_list(grantee: str = "", verb: str = "") -> dict:
    """List currently ACTIVE envelopes, optionally filtered by grantee
    and/or verb. Read-only."""
    from . import envelope_authoring as _ea
    rows = _ea.list_active(grantee=grantee or None, verb=verb or None)
    return {"active": rows, "count": len(rows)}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("envelope_pending_read")
def envelope_pending_read(
    oldest_first: bool = True, limit: int = 50,
    include_precedents: bool = True,
) -> dict:
    """List envelope PROPOSALS awaiting operator ratification. Oldest first
    by default so the queue is drained in FIFO order. Read-only.

    This is the operator's queue view for the accrual loop — see
    docs/design/envelope-accrual.md.

    When ``include_precedents`` is True (default, PR10), each row's
    ``precedent_ids`` are expanded into a ``precedents_expanded`` list
    of the full currently-active envelope rows they name. That's what
    turns a ratify into one glance ("confirm precedents X, Y or
    override") rather than a two-hop dance through ``envelope_list``.
    Precedent IDs that no longer resolve to an active envelope are
    silently dropped from the expansion (revoked / hand-edited registry);
    ``precedent_ids`` itself stays intact as tamper evidence."""
    from . import envelope_authoring as _ea
    rows = _ea.list_pending(
        oldest_first=oldest_first, limit=limit,
        include_precedents=include_precedents,
    )
    return {"pending": rows, "count": len(rows)}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("fleet_health")
def fleet_health(app_id: str) -> dict:
    """Fleet health — task queue counts by status, plus live worker heartbeats.

    A queue depth is only half the picture: `pending` tasks with no live worker
    are not "queued", they are stranded. `workers` reports every process
    publishing a heartbeat, and `stranded` is true when there is pending work and
    nothing running to drain it."""
    pg = get_pg()
    if not pg:
        return _postgres_unavailable()

    mapping = sp.resolve(pg, app_id, "tasks", _TASK_FIELDS)
    if "error" in mapping:
        return mapping
    status_col = mapping["fields"]["status"]["column"]
    if status_col is None:
        return {"error": "schema_unusable: 'tasks' table has no mappable 'status' column"}

    try:
        cur = pg.cursor()
        cur.execute(f'SELECT "{status_col}", COUNT(*) FROM tasks GROUP BY "{status_col}"')  # nosec B608 - status_col comes from the confirmed schema_profile field mapping, not request input
        rows = cur.fetchall()
        cur.close()
    except Exception as e:
        return {"error": f"fleet_unavailable: {e}"}
    counts = {r[0]: r[1] for r in rows}
    from .heartbeat import read_workers
    workers = read_workers()
    pending = counts.get("pending", 0)

    # Per-lane strand detection (Loki DD0114E5 §2.2): pending work on a lane with
    # no *alive* worker for that lane is stranded, even when another lane is
    # healthy — a live batch worker must not hide a dead fast lane. Falls back to
    # the aggregate signal if the tasks table exposes no mappable lane column.
    lane_col = mapping["fields"].get("lane", {}).get("column")
    stranded_lanes: list[str] = []
    pending_by_lane: dict = {}
    if lane_col and pending > 0:
        try:
            cur = pg.cursor()
            cur.execute(
                f'SELECT COALESCE("{lane_col}", \'fast\'), COUNT(*) FROM tasks '  # nosec B608 - lane_col/status_col come from the confirmed schema_profile field mapping, not request input
                f'WHERE "{status_col}" = \'pending\' GROUP BY 1'
            )
            pending_by_lane = {r[0]: r[1] for r in cur.fetchall()}
            cur.close()
        except Exception:
            pending_by_lane = {}
        by_lane = workers.get("by_lane", {})
        stranded_lanes = [
            lane
            for lane, n in pending_by_lane.items()
            if n > 0 and by_lane.get(lane, {}).get("readiness") != "alive"
        ]

    return {
        "pending":   pending,
        "running":   counts.get("running", 0),
        "completed": counts.get("completed", 0),
        "failed":    counts.get("failed", 0),
        "total":     sum(counts.values()),
        "workers":   workers,
        "stranded":  pending > 0 and workers.get("alive", 0) == 0,
        "pending_by_lane": pending_by_lane,
        "stranded_lanes":  stranded_lanes,
    }


# ── Session context tools ────────────────────────────────────────────────────
#
# Ephemeral, per-identity working state that survives across sessions — a
# to-do note, a cursor, a scratch value — with an optional TTL. Distinct from
# store_* in exactly that: contexts can expire, and reads transparently skip
# (and lazily purge) expired entries. Backed by the SOIL store, so this works
# with no Postgres — matching the README's "SOIL store works standalone."
# Scoped to the caller's app_id (the bound identity in serve mode), so one
# identity never reads another's context.

def _ctx_collection(app_id: str) -> str:
    return f"ctx__{app_id}"


def _ctx_expired(rec: dict) -> bool:
    exp = rec.get("_ctx_expires_epoch")
    return bool(exp) and time.time() > exp


@mcp.tool(annotations=_ANNO_WRITE_IDEM)
@_guarded("context_save")
def context_save(app_id: str, key: str, value: dict, ttl_seconds: int = 0) -> dict:
    """Save ephemeral working state under `key`, optionally expiring after
    ttl_seconds (0 = never). Overwrites an existing key. Per-identity — scoped
    to your app_id. Backed by the SOIL store, so no Postgres is required."""
    expires_epoch = (time.time() + ttl_seconds) if ttl_seconds and ttl_seconds > 0 else None
    expires_at = (datetime.fromtimestamp(expires_epoch, timezone.utc).isoformat()
                  if expires_epoch else None)
    record = {
        "value": value,
        "_ctx_key": key,
        "_ctx_saved_at": datetime.now(timezone.utc).isoformat(),
        "_ctx_expires_epoch": expires_epoch,
        "_ctx_expires_at": expires_at,
    }
    _store.put(_ctx_collection(app_id), record, record_id=key)
    return {"key": key, "expires_at": expires_at}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("context_get")
def context_get(app_id: str, key: str) -> dict:
    """Read a saved context by key. Returns {error: not_found} if absent, or
    {error: expired} (and purges it) if its TTL has passed."""
    coll = _ctx_collection(app_id)
    rec = _store.get(coll, key)
    if not rec:
        return {"error": "not_found"}
    if _ctx_expired(rec):
        _store.delete(coll, key)
        return {"error": "expired"}
    return {"key": key, "value": rec.get("value"),
            "saved_at": rec.get("_ctx_saved_at"),
            "expires_at": rec.get("_ctx_expires_at")}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("context_list")
def context_list(app_id: str, limit: int = 50,
                 cursor: Optional[str] = None) -> dict:
    """List your saved context keys with save/expiry times (values omitted —
    use context_get).  Paginated: returns ``{contexts, next_cursor}`` — pass
    the returned ``next_cursor`` as ``cursor`` to fetch the next page.
    Expired entries are skipped and purged."""
    coll = _ctx_collection(app_id)
    after_key = decode_cursor(cursor) if cursor else ""
    out = []
    for rec in _store.all(coll):
        key = rec.get("_ctx_key") or rec.get("_id")
        if _ctx_expired(rec):
            _store.delete(coll, key)
            continue
        if after_key and key <= after_key:
            continue
        out.append({"key": key, "saved_at": rec.get("_ctx_saved_at"),
                    "expires_at": rec.get("_ctx_expires_at")})
    out.sort(key=lambda r: r["key"])
    limit = max(1, limit)
    has_more = len(out) > limit
    items = out[:limit]
    next_cursor = None
    if has_more and items:
        next_cursor = encode_cursor(items[-1]["key"])
    return {"contexts": items, "next_cursor": next_cursor}


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("context_expire")
def context_expire(app_id: str, key: str) -> dict:
    """Delete one of your saved contexts immediately, ahead of any TTL.
    Returns {expired: true} if a record was removed, false if the key didn't
    exist. Scoped to your app_id — you cannot expire another app's context."""
    return {"expired": _store.delete(_ctx_collection(app_id), key)}


# ── Integrations (outbound adapters) ─────────────────────────────────────────
#
# External HTTP APIs, called from the server process — see integrations.py for
# the adapter ledger (live vs declared stubs) and the earn rule. Live calls are
# the fourth consumer of the three-key egress gate: the integration_net
# capability (own line, never implied by task_net), the operator's standing
# consent.internet, and an unexpired lease. integration_call is additionally
# kept out of full_access (gate.py), so even the attempt surface is opt-in.

@mcp.tool(annotations=_ANNO_READ)
@_guarded("integration_list")
def integration_list(app_id: str) -> dict:
    """List every integration adapter — live and declared stubs — with status,
    credential *source* (env/vault, never the value), and, for stubs, what is
    missing and what earns the implementation."""
    from . import integrations
    return {"integrations": integrations.list_integrations()}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("integration_status")
def integration_status(app_id: str, name: str) -> dict:
    """Offline readiness readout for one integration: live or stub, credential
    presence, and whether the three-key egress gate would pass for this app
    right now. Makes no network call — ask this before asking for a lease."""
    from . import integrations
    return integrations.status(app_id, name)


@mcp.tool(annotations=_ANNO_WRITE_OPEN)
@_guarded("integration_call")
def integration_call(app_id: str, name: str, method: str, path: str,
                     params: Optional[dict] = None,
                     body: Optional[dict] = None) -> dict:
    """Call an external API through a registered integration adapter.

    Egress needs THREE keys, all held at once: the 'integration_net' capability
    in this app's manifest (own line — NOT granted by task_net, integration_call,
    or full_access), the operator's standing consent.internet, and an unexpired
    egress lease issued via `willow-mcp grant-net`. Declared stubs refuse with
    what is missing and what earns their implementation."""
    from . import integrations
    adapter = integrations.get(name)
    if adapter is None:
        return {"error": f"unknown_integration: {name!r}",
                "known": sorted(integrations.REGISTRY)}
    denial = integrations.egress_denial(app_id)
    if denial:
        return denial
    return adapter.request(method, path, params=params, body=body)


# ── Federated MCP (willow-mcp as a client) ──────────────────────────────────
#
# docs/design/federated-mcp-gating.md, built in the order its §9 sets out.
# federation_discover and federation_list_servers are inventory-only (no
# subprocess, no egress); federation_call is the escalated dispatcher and is
# where the fourth egress class (`mcp_federation`) plus the per-downstream-tool
# namespaced grant are enforced, both re-checked from disk at call time.

@mcp.tool(annotations=_ANNO_READ)
@_guarded("federation_discover")
def federation_discover(app_id: str, root: Optional[str] = None) -> dict:
    """Shadow-IT scan: `.mcp.json` files under `root` (default: this host's
    home directory, or $WILLOW_MCP_FEDERATION_SCAN_ROOT) that the ratified
    registry does not yet own. Read-only — never parses an entry into a
    connectable spec and never ratifies anything. "Which MCP servers exist
    that willow-mcp does not know about" is the first question an orchestrator
    must answer before it can federate at all."""
    from . import mcp_federation
    scan_root = Path(root) if root else Path(
        os.environ.get("WILLOW_MCP_FEDERATION_SCAN_ROOT", "") or Path.home()
    )
    unmanaged = mcp_federation.unregistered_mcp_files(scan_root)
    return {"root": str(scan_root), "unregistered": [str(p) for p in unmanaged]}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("federation_list_servers")
def federation_list_servers(app_id: str) -> dict:
    """List every operator-ratified downstream MCP server: id, name, launch
    command/args, the environment-variable NAMES it receives (never values),
    who ratified it and when. Never includes a discovered-but-unratified
    server — connecting requires ratification first (see federation_discover)."""
    from . import mcp_federation
    return {"servers": mcp_federation.list_ratified()}


@mcp.tool(annotations=_ANNO_WRITE_OPEN)
@_guarded("federation_call")
def federation_call(app_id: str, server_id: str, tool: str,
                    arguments: Optional[dict] = None) -> dict:
    """Call one tool on one ratified downstream MCP server.

    Authorized only at the intersection of two ceilings (docs/design/
    federated-mcp-gating.md Decision 2): this app's manifest must grant BOTH
    the 'mcp_federation' capability (own line — spawning a server at all) AND
    the namespaced `mcp:<server_id>:<tool>` permission (this specific tool on
    this specific server) — plus the operator's standing consent.federation
    and an unexpired egress lease, same as every other egress lane. The
    server itself must be in the operator-ratified registry regardless of
    what this app's manifest grants; a manifest grant alone can never make an
    unratified server reachable.

    The downstream tool's result is scanned by external-guard and
    sandwich-wrapped if flagged (untrusted output, same treatment
    willow_web_fetch gives fetched pages) before it comes back."""
    from . import federation_egress, mcp_federation_client

    denial = federation_egress.egress_denial(app_id, server_id, tool)
    if denial:
        return denial

    from . import mcp_federation
    result = mcp_federation_client.call_tool(server_id, tool, arguments)
    _receipt_log.record(
        app_id, "federation_call", "federated_call",
        f"server_id={server_id} tool={tool} "
        f"guard_verdict={result.get('guard_verdict')}")
    entry = mcp_federation.get_ratified(server_id) or {}
    result["server_id"] = server_id
    result["server_name"] = entry.get("name")
    result["tool"] = tool
    return result


# ── Self-audit ───────────────────────────────────────────────────────────────

@mcp.tool(annotations=_ANNO_READ)
@_guarded("receipts_tail")
def receipts_tail(app_id: str, limit: int = 20) -> dict:
    """Return your own most-recent tool-call receipts, newest first: ts, tool,
    outcome (ok/denied/rate_limited/error), detail. Scoped to your app_id — a
    self-audit trail, never another identity's calls."""
    return {"receipts": _receipt_log.tail(app_id, limit)}


# ── Self-diagnostic ──────────────────────────────────────────────────────────
#
# "Is this willow-mcp install wired correctly?" — the one tool a user reaches
# for when nothing else works, so it must run even when the manifest is missing
# or the database is empty. It is therefore NOT wrapped in _guarded (a broken
# manifest would make the diagnostic itself undiagnosable). It reveals only the
# caller's own environment/config — no fleet rows, no vault secrets. In serve
# mode it still requires a confirmed identity, so an unbound remote caller never
# reads local internals; local filesystem paths are collapsed to ~ for a remote
# (bound) caller.
#
# Its headline job is catching the empty-DB / wrong-env failure: Postgres
# connects fine, but WILLOW_PG_DB points at a database without willow-mcp's
# tables (e.g. serve mode under systemd --user not inheriting a shell export).

_EXPECTED_PG_TABLES = {
    "knowledge":         "knowledge_* / kb_*",
    "tasks":             "task_* / fleet_health",
    "agents":            "fleet_status",
    "routing_decisions": "agent_route / agent_dispatch_result",
}


def _diag_store() -> dict:
    check: dict = {"backend": "soil-sqlite", "root": None, "exists": False,
                   "writable": False, "collections": 0, "names": []}
    try:
        root = _store.root
        check["root"] = str(root)
        check["exists"] = root.exists()
        try:
            root.mkdir(parents=True, exist_ok=True)
            probe = root / ".diag_write_probe"
            probe.write_text("ok")
            probe.unlink()
            check["writable"] = True
        except Exception as e:
            check["write_error"] = str(e)[:120]
        names = sorted(p.parent.name for p in root.glob("*/store.db")) if root.exists() else []
        check["collections"] = len(names)
        check["names"] = names[:20]
        check["status"] = "ok" if check["writable"] else "fail"
    except Exception as e:
        check["status"] = "fail"
        check["error"] = str(e)[:160]
    return check


def _diag_rings() -> dict:
    """Learned-mapping tree (schema_rings): how much column->field vocabulary this
    deployment has confirmed, and how close it sits to the prune (canopy) cap."""
    check: dict = {"backend": "schema-rings"}
    try:
        g = sp.girth()  # {columns, pairs, cap, tick}
        pairs = g.get("pairs", 0)
        cap = g.get("cap", 0) or 1
        check.update({
            "columns": g.get("columns", 0),
            "pairs": pairs,
            "cap": g.get("cap", 0),
            "confirmations": g.get("tick", 0),
            "saturation_pct": round(100.0 * pairs / cap, 1),
            "status": "ok",
        })
    except Exception as e:
        check["status"] = "fail"
        check["error"] = str(e)[:160]
    return check


def _diag_postgres() -> dict:
    check: dict = {"backend": "postgres", "reachable": False,
                   "dbname": os.environ.get("WILLOW_PG_DB", "willow"),
                   "user": os.environ.get("WILLOW_PG_USER", os.environ.get("USER", "")),
                   "tables": {}}
    pg = get_pg()
    if not pg:
        check["status"] = "fail"
        hint = "postgres_unavailable — not reachable via unix socket (knowledge_*, task_*, fleet_* degrade)"
        if postgres_lifecycle.ensure_enabled():
            hint += "; WILLOW_MCP_ENSURE_POSTGRES is set but recovery did not succeed"
        else:
            hint += "; set WILLOW_MCP_ENSURE_POSTGRES=1 to attempt local service restart on connect"
        check["detail"] = hint
        return check
    check["reachable"] = True
    try:
        dsn = pg.get_dsn_parameters()
        check["dbname"] = dsn.get("dbname", check["dbname"])
        check["host"] = dsn.get("host") or "local-socket"
        wanted = list(_EXPECTED_PG_TABLES)
        cur = pg.cursor()
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name = ANY(%s)", (wanted,))
        present = {r[0] for r in cur.fetchall()}
        est: dict = {}
        if present:
            cur.execute("SELECT relname, reltuples::bigint FROM pg_class WHERE relname = ANY(%s)",
                        (list(present),))
            est = {r[0]: int(r[1]) for r in cur.fetchall()}
        cur.close()
        for t in wanted:
            check["tables"][t] = {"present": t in present, "rows_est": est.get(t),
                                   "backs": _EXPECTED_PG_TABLES[t]}
        check["missing"] = [t for t in wanted if t not in present]
        check["status"] = "ok" if not check["missing"] else "warn"
    except Exception as e:
        check["status"] = "fail"
        check["error"] = str(e)[:160]
    return check


def _diag_schema(app_id: str) -> dict:
    check: dict = {"tables": {}}
    pg = get_pg()
    if not pg:
        check["status"] = "skip"
        check["detail"] = "postgres unavailable"
        return check
    try:
        eff = app_id or "willow-mcp"
        for table, fields in _CONFIRMABLE_TABLES.items():
            m = sp.resolve(pg, eff, table, fields)
            if "error" in m:
                check["tables"][table] = {"present": False, "confirmed": False, "note": m["error"]}
                continue
            check["tables"][table] = {
                "present": True,
                "confirmed": bool(m.get("confirmed")),
                # field -> real column (names only, no row data) so a
                # confirmed-but-wrong mapping like content->content is visible
                # here; run schema_confirm_mapping(preview=True) to see the
                # rendered values that prove or disprove it.
                "columns": {f: v["column"] for f, v in m["fields"].items()},
                "unmapped": [f for f, v in m["fields"].items() if v["column"] is None],
                "drift": bool(m.get("schema_drift")),
            }
        check["status"] = "ok"
    except Exception as e:
        check["status"] = "fail"
        check["error"] = str(e)[:160]
    return check


def _diag_manifest(app_id: str) -> dict:
    from . import gate
    check: dict = {"app_id": app_id, "apps_root": str(gate._apps_root())}
    if not app_id:
        check["status"] = "warn"
        check["reason"] = "no_app_id"
        check["detail"] = "no app_id supplied — pass the app_id you call willow-mcp with"
        return check
    manifest = gate._load_manifest(app_id)
    if manifest is None:
        reason, detail = gate.manifest_diagnosis(app_id)
        check["status"] = "fail"
        check["reason"] = reason
        check["detail"] = f"{detail} — every call is denied"
        return check
    perms = manifest.get("permissions", [])
    allowed: set = set()
    for p in perms:
        g = gate.PERMISSION_GROUPS.get(p)
        allowed.update(g if g is not None else {p})
    check["permissions"] = perms
    check["tools_allowed"] = sorted(allowed)
    if not perms:
        check["status"] = "warn"
        check["detail"] = "manifest present but permissions empty — every call is denied"
    else:
        check["status"] = "ok"
    return check


def _diag_bindings() -> dict:
    from . import gate
    root = gate._apps_root() / "_identity_bindings"
    check: dict = {"dir": str(root), "total": 0, "confirmed": 0}
    try:
        if root.exists():
            files = list(root.glob("*.json"))
            check["total"] = len(files)
            for f in files:
                try:
                    if json.loads(f.read_text()).get("confirmed"):
                        check["confirmed"] += 1
                except Exception:
                    import logging
                    logging.getLogger("willow_mcp.server").debug(
                        "unreadable attestation file %s", f, exc_info=True)
        check["status"] = "ok"
    except Exception as e:
        check["status"] = "fail"
        check["error"] = str(e)[:160]
    return check


def _diag_worker(app_id: str) -> dict:
    """Worker liveness + the queue depth that makes its absence matter.

    `pending` is best-effort: no Postgres, an unconfirmed mapping, or any query
    failure leaves it None, which means "unknown" and never raises a problem. An
    install that only uses store_*/knowledge_* has no worker and no queue — that
    is healthy, not degraded (B-18's lesson: don't diagnose a non-defect)."""
    from .heartbeat import read_workers
    check = read_workers()
    check["pending"] = None
    check["pending_by_lane"] = {}
    check["stranded_lanes"] = []
    try:
        pg = get_pg()
        if pg is not None:
            mapping = sp.resolve(pg, app_id, "tasks", _TASK_FIELDS)
            status_col = mapping.get("fields", {}).get("status", {}).get("column")
            if "error" not in mapping and status_col:
                cur = pg.cursor()
                cur.execute(f'SELECT COUNT(*) FROM tasks WHERE "{status_col}" = %s', ("pending",))  # nosec B608 - status_col comes from the confirmed schema_profile field mapping, not request input
                check["pending"] = cur.fetchone()[0]
                cur.close()
                lane_col = mapping.get("fields", {}).get("lane", {}).get("column")
                if lane_col and check["pending"]:
                    cur = pg.cursor()
                    cur.execute(
                        f'SELECT COALESCE("{lane_col}", \'fast\'), COUNT(*) FROM tasks '  # nosec B608 - lane_col/status_col come from the confirmed schema_profile field mapping, not request input
                        f'WHERE "{status_col}" = %s GROUP BY 1', ("pending",)
                    )
                    check["pending_by_lane"] = {r[0]: r[1] for r in cur.fetchall()}
                    cur.close()
                    by_lane = check.get("by_lane", {})
                    check["stranded_lanes"] = [
                        lane for lane, n in check["pending_by_lane"].items()
                        if n > 0 and by_lane.get(lane, {}).get("readiness") != "alive"
                    ]
    except Exception:
        pass  # unknown, not broken
    return check


def _diag_consent() -> dict:
    """Standing operator consent — the fleet-wide key of the three-key egress gate.

    Read-only and fail-closed: willow-mcp never authors this policy, and anything
    it cannot read as an explicit `true` reads as denial."""
    from . import consent
    return consent.read_consent()


def _diag_net_lease(app_id: str) -> dict:
    """Egress leases — the third key, and an honest report on who could forge it.

    `self_writable` is the part that matters. It lists the trust-root paths this
    very process can write: every one of them is a key it could mint for itself.
    On a single-uid host that is all of them, which is exactly B-32.

    `private_key_readable` is a distinct question (#182): the egress signing key
    needs no forgery at all if this process can simply read it — it can sign
    with the real authority. `self_writable` alone reported `[]` on a hardened
    install even while the key sat world-owned by the agent's own uid; this
    closes that gap."""
    from . import gate, lease
    holds_capability = bool(app_id) and gate.permitted(app_id, gate.NET_PERMISSION)
    forgeable = lease.self_writable_trust_paths(app_id)
    key_exposed = lease.egress_key_readable_by_self()
    return {
        "lease_root": str(lease._leases_root()),
        "max_ttl_seconds": lease.MAX_TTL_SECONDS,
        "strict_trust_root": lease.strict_trust_root(),
        "holds_task_net": holds_capability,
        "lease": lease.read_lease(app_id) if app_id else {"status": "none"},
        "self_writable": forgeable,
        "private_key_readable": key_exposed,
        # A sub-check that lists the keys this process could forge and then calls
        # itself "ok" is asserting a membrane it just measured a hole in. The
        # verdict still turns on _derive_problems (a lone `warn` here would make
        # `degraded` every install's resting state, B-18) — but this field now
        # says what it found.
        "status": "ok" if not forgeable and not key_exposed else "warn",
    }


def _diag_build_leases() -> dict:
    """Earn-first build leases — what building is currently authorized, by
    whom, and until when.

    Deliberately informational (never folded into `_derive_problems` / the
    verdict): an install with no active build lease is not degraded, an
    expired lease is not wrong, and a malformed one is the reader's own
    report — same B-18 rule the net-lease residual reporting follows. The
    self-writable residual is not re-reported per family here — `net_lease`
    already measured `mcp_apps/` writability at the root, and both lease
    subtrees inherit it. A single note points at that check instead.
    """
    from . import build_lease

    leases = build_lease.list_leases()
    roster_names = {fam for fam, _ in build_lease.EARN_FIRST_ROSTER}
    on_disk = {row["tool"] for row in leases}
    tallies = {"active": 0, "expired": 0, "malformed": 0, "mismatch": 0, "none": 0}
    for row in leases:
        tallies[row["status"]] = tallies.get(row["status"], 0) + 1

    return {
        "lease_root": str(build_lease._leases_root()),
        "max_ttl_seconds": build_lease.MAX_TTL_SECONDS,
        "roster_size": len(roster_names),
        "roster_dry": sorted(roster_names - on_disk),
        "extras": sorted(on_disk - roster_names),
        "leases": leases,
        "tally": tallies,
        # `net_lease.self_writable` already reports the shared mcp_apps root;
        # duplicating it here would suggest a distinct membrane.
        "self_writable_note": "shared root with net_lease — see net_lease.self_writable",
        # A sub-check that reports N active leases and calls itself "ok" is
        # honest here: there is nothing about a build lease's mere existence
        # that is a problem (its point is authorization). "status" stays "ok"
        # unconditionally so the verdict is unmoved.
        "status": "ok",
    }


def _diag_uid_separation(app_id: str) -> dict:
    """B-32/#231, made legible: whose *account* actually owns the trust root,
    named next to whose account is asking.

    `net_lease.self_writable` already answers the question the verdict is
    built on — could this process WRITE the keys. This answers the one an
    operator asks first while following the harden-trust-root deployment
    runbook (`docs/deploy/dedicated-uid-deployment.md`) — "did that actually
    move the files to a different account, or did `repair-runtime-perms` just
    chown them back to me". Purely informational: never folded into
    `_derive_problems`/the verdict, so it cannot turn every existing
    single-uid install's resting state into a new `warn` (B-18's rule) —
    `strict_trust_root`/`net_lease`/`severance` already carry the
    enforcement-relevant verdict for this surface."""
    from . import trust_root_setup
    return trust_root_setup.uid_separation_report(app_id)


def _diag_store_db_perms(app_id: str) -> dict:
    """#232: OS-level permission posture on the store `.db` files themselves
    -- the concrete, one-target-set-over sibling of #231's `_diag_uid_separation`,
    and the check that answers what the client-side hook
    (`bundle/hooks/pre_tool_use.py`'s `_OWNED_DB_FILE_RE`) never could: does
    the OS actually refuse a same-uid-as-agent read, or only this process's
    own harness.

    `exposure` is the mode-bit hygiene fact (see
    `trust_root_setup.store_db_exposure()`) -- independent of who is asking.
    `enforced` folds that into one bool for convenience, but stays honestly
    `False` on a fresh/unhardened install with no `.db` files yet (empty
    list is not evidence of protection) as well as on any install that
    hasn't run `repair-runtime-perms` since #232 shipped.

    Purely informational, same B-18 discipline as `_diag_uid_separation`:
    never folded into `_derive_problems`/the verdict, so a `False` here
    cannot turn today's honest single-uid resting state into a new `warn`.
    `app_id` is accepted (mirroring the other `_diag_*` checks' signatures)
    but unused today -- the exposure check is per-file, not per-caller."""
    from . import trust_root_setup
    files = trust_root_setup.store_db_files()
    exposure = trust_root_setup.store_db_exposure()
    return {
        "files": [str(p) for p in files],
        "exposure": exposure,
        "enforced": bool(files) and not exposure,
    }


def _under(child: Path, parent: Path) -> bool:
    """Is `child` the same inode as `parent`, or inside it — after symlinks?

    Compares resolved paths. `~/.willow` is commonly a symlink into a fleet tree,
    so a string prefix test reports "severed" for two names of one directory."""
    try:
        c, p = child.resolve(), parent.resolve()
    except OSError:
        return False
    return c == p or p in c.parents


def _egress_severance(net_lease: dict | None) -> dict:
    """The fourth surface (B-38): can this process reach the network without a key
    it does not hold?

    store/postgres/trust_root can all be severed and the process still reach the
    internet, because egress is a THREE-key gate — `task_net` (manifest), the
    `consent.internet` switch (settings file), and a signed egress lease — and
    severance from a fleet's STATE is not severance from its NETWORK. This asserts
    the process cannot FORGE those keys. It was undefinable until B-37 moved the
    egress signing key beyond write reach; the executor authorizer
    (`egress_authorization.ExecutorNetworkAuthorizer`) now demands a non-writable
    Ed25519 verification key, so the property is finally checkable.

    Reuses the manifest + lease-root paths `net_lease` already measured, and adds
    the three the `trust_root` check names in its message but never actually
    measures: the consent switch, the egress verification key, and — #182 — the
    egress *signing* key itself. Reading the private key needs no forgery at all;
    a process that holds it signs with the real authority. B-37/B-38 only ever
    asked whether the *public* key was writable (a substitution attack); this
    asks the more basic question first.

    Verdict, respecting strict mode (and B-18's no-false-positive rule):
      - strict ON, nothing forgeable, key present & protected → severed True
      - strict ON, but a key is forgeable or the verifier is unprotected → False (error)
      - strict OFF → None (unknown): the executor denies egress by default, so
        key-separation is not being enforced and severance cannot be *proven* — a
        warn, never a break. This is the state the 2026-07-09 install was in while
        reporting `ok`.
    """
    from . import consent as _consent
    from . import egress_authorization as _ea
    from . import egress_setup as _es
    from . import lease as _lease

    # manifest + lease_root, already measured for the third key
    forgeable = [f["path"] for f in ((net_lease or {}).get("self_writable") or [])]

    # the private signing key (#182) — a read, not a write, but it belongs in
    # the same "keys this process could act with" list: the effect is identical.
    if (net_lease or {}).get("private_key_readable"):
        key_path = _es.resolve_private_key_path()
        forgeable.append(str(key_path) if key_path else "<egress private key>")

    # the consent switch — the second key, named by trust_root but never measured
    consent_writable: list[str] = []
    for p in {_consent.settings_path(), _consent.legacy_path()}:
        try:
            if _lease.path_is_directly_writable_for_trust(p):
                consent_writable.append(str(p))
        except OSError:
            consent_writable.append(str(p))  # unverifiable ⇒ cannot claim protection

    # the Ed25519 verification key — B-37's key, the reason this is now definable
    pubkey = _ea.public_key_path()
    if pubkey is None:
        key_status: dict = {"configured": False}
        key_protected = False
    else:
        try:
            present = pubkey.is_file()
            writable = _lease.path_is_self_writable_or_replaceable(pubkey)
        except OSError:
            present, writable = False, True
        key_status = {"configured": True, "path": str(pubkey),
                      "present": present, "self_writable": writable}
        key_protected = present and not writable

    strict = _lease.strict_trust_root()
    forgeable_keys = sorted(set(forgeable) | set(consent_writable))
    can_forge = bool(forgeable_keys) or not key_protected

    if not strict:
        severed: bool | None = None
        reason: str | None = ("strict trust root is off — the executor denies egress by "
                              "default, so egress key-separation is not enforced and "
                              "severance cannot be proven (set WILLOW_MCP_STRICT_TRUST_ROOT=1)")
    elif can_forge:
        severed = False
        reason = "this process can forge the three-key egress gate"
    else:
        severed = True
        reason = None

    return {"severed": severed, "reason": reason,
            "strict_trust_root": strict,
            "forgeable_keys": forgeable_keys,
            "consent_writable": consent_writable,
            "verification_key": key_status}


def _diag_severance(store: dict, postgres: dict, net_lease: dict | None) -> dict:
    """Can this install still see — or reach out through — the fleet it claims to
    be cut off from?

    Four properties, each independently checkable from inside the process:

      store      — the SOIL store is not the fleet's store
      postgres   — the database is not the fleet's database
      trust_root — this process cannot rewrite the ACLs that gate it
      egress     — this process cannot forge the three-key network gate (B-38)

    The first two are DATA: someone who writes them corrupts records. The last two
    are AUTHORITY: someone who writes them grants themselves egress. Only authority
    can turn a severed install into a compromised one, so only it is an `error`.

    Reports `not_asserted` when the operator has named no fleet. That is not a
    failure — a single-trust-domain install is complete without severance, and
    an install that has never claimed to be cut off cannot be caught lying."""
    fleet_home = paths.fleet_home()
    fleet_db = paths.fleet_pg_db()

    if fleet_home is None and not fleet_db:
        return {"status": "not_asserted",
                "detail": ("no fleet named — set WILLOW_MCP_FLEET_HOME and "
                           "WILLOW_MCP_FLEET_PG_DB to assert this install is severed from one"),
                "surfaces": {}}

    surfaces: dict = {}

    # ── data: store ───────────────────────────────────────────────────────────
    store_root = store.get("root")
    if fleet_home is None:
        surfaces["store"] = {"severed": None, "reason": "WILLOW_MCP_FLEET_HOME unset"}
    elif not store_root:
        surfaces["store"] = {"severed": None, "reason": "store root unresolved"}
    else:
        shared = _under(Path(store_root), fleet_home)
        surfaces["store"] = {
            "path": store_root, "severed": not shared,
            "reason": f"resolves inside {fleet_home}" if shared else None}

    # ── data: postgres ────────────────────────────────────────────────────────
    dbname = postgres.get("dbname")
    if not fleet_db:
        surfaces["postgres"] = {"severed": None, "reason": "WILLOW_MCP_FLEET_PG_DB unset"}
    else:
        shared = bool(dbname) and dbname == fleet_db
        surfaces["postgres"] = {
            "dbname": dbname, "severed": not shared,
            "reason": f"is the fleet database '{fleet_db}'" if shared else None}

    # ── authority: trust root ─────────────────────────────────────────────────
    # Reuses the paths _diag_net_lease already computes. A trust root this
    # process can write is a gate it can open, whether or not it holds task_net
    # today — B-32 (host self-grant) and B-33 (sandbox writes consent) are both
    # this property, observed at two different callers.
    forgeable = (net_lease or {}).get("self_writable") or []
    apps_root = paths.mcp_apps_root()
    inside_fleet = fleet_home is not None and _under(apps_root, fleet_home)
    surfaces["trust_root"] = {
        "apps_root": str(apps_root),
        "self_writable": [f["path"] for f in forgeable],
        "inside_fleet_home": inside_fleet,
        "severed": not forgeable and not inside_fleet,
    }

    # ── authority: egress (B-38, the fourth surface) ──────────────────────────
    surfaces["egress"] = _egress_severance(net_lease)

    violated = [k for k, v in surfaces.items() if v.get("severed") is False]
    unknown = [k for k, v in surfaces.items() if v.get("severed") is None]
    status = "violated" if violated else ("partial" if unknown else "ok")
    return {"status": status, "fleet_home": str(fleet_home) if fleet_home else None,
            "fleet_pg_db": fleet_db or None, "violated": violated,
            "unknown": unknown, "surfaces": surfaces}


def _diag_env() -> dict:
    # Config-bearing env, set-or-None. A var showing None here (its default in
    # effect) while data lives elsewhere is the serve-mode env footgun: the
    # systemd --user unit does not inherit a shell `export`.
    keys = ["WILLOW_HOME", "WILLOW_PG_DB", "WILLOW_PG_USER", "WILLOW_STORE_ROOT",
            "WILLOW_APP_ID", "WILLOW_MCP_APPS_ROOT", "WILLOW_MCP_HOST", "WILLOW_MCP_PORT",
            "WILLOW_SETTINGS_GLOBAL", "WILLOW_MCP_FLEET_HOME", "WILLOW_MCP_FLEET_PG_DB",
            "WILLOW_WORKER_LANE", "WILLOW_WORKER_HEARTBEAT_ROOT"]
    return {k: os.environ.get(k) for k in keys}


def _derive_problems(store: dict, postgres: dict, manifest: dict, mode: str,
                     worker: dict | None = None, consent: dict | None = None,
                     net_lease: dict | None = None, severance: dict | None = None,
                     envelope_registry: dict | None = None) -> list[dict]:
    """Pure: turn raw check dicts into actionable problems. Unit-tested without
    a live DB — this is where the empty-DB footgun becomes a named diagnosis."""
    from . import gate
    problems: list[dict] = []
    if store.get("status") == "fail":
        problems.append({"severity": "error", "check": "store",
                         "detail": store.get("write_error") or store.get("error") or "SOIL store not writable",
                         "fix": (f"run `willow-mcp repair-runtime-perms` to restore write access to "
                                 f"{store.get('root')} for the MCP runtime user (WILLOW_STORE_ROOT)")})
    if postgres.get("status") == "fail":
        problems.append({"severity": "warn", "check": "postgres",
                         "detail": "Postgres unreachable — knowledge_*, task_*, fleet_* will return postgres_unavailable",
                         "fix": "start Postgres and confirm unix-socket peer auth for WILLOW_PG_USER, or ignore if you only use the SOIL store"})
    elif postgres.get("missing"):
        env_note = (" Serve mode (systemd --user) does not inherit a shell `export WILLOW_PG_DB` — "
                    "see README 'Turning serve mode on and off'.") if mode == "serve" else ""
        problems.append({"severity": "error", "check": "postgres",
                         "detail": (f"Postgres connected to database '{postgres.get('dbname')}' but "
                                    f"expected tables are missing: {postgres['missing']}. "
                                    f"If your data lives in another database, WILLOW_PG_DB is wrong." + env_note),
                         "fix": f"set WILLOW_PG_DB to the database that actually holds these tables (currently '{postgres.get('dbname')}')"})
    if manifest.get("status") == "fail":
        _mpath = f"{manifest.get('apps_root')}/{manifest.get('app_id')}/manifest.json"
        # The fix has to match the reason. "create this file" pointed at a file
        # that already existed, unsigned, and cost an operator weeks of looking
        # for a missing manifest that was never missing.
        _mfix = {
            gate.MANIFEST_UNSIGNED: (
                f"sign it: `willow-mcp sign-manifest {manifest.get('app_id')}` "
                f"(the manifest is present and valid — PGP enforcement is on and it "
                f"has no verifying signature). If {_mpath}'s directory is not writable "
                f"by you, sign to a scratch path and install the .sig as its owner. "
                f"To turn enforcement off instead, unset WILLOW_PGP_FINGERPRINT."
            ),
            gate.MANIFEST_UNPARSEABLE: f"repair the JSON in {_mpath}",
        }.get(manifest.get("reason"),
              f"create/populate {_mpath} with a \"permissions\" list")
        problems.append({"severity": "error", "check": "manifest",
                         "reason": manifest.get("reason"),
                         "detail": manifest.get("detail"),
                         "fix": _mfix})
    elif manifest.get("status") == "warn":
        p = {"severity": "warn", "check": "manifest", "detail": manifest.get("detail")}
        if manifest.get("reason") == "no_app_id":
            # Caller omission, not an install defect: the caller didn't pass an
            # app_id to this self-check. Surfaced here (and in checks.manifest)
            # but flagged caller_input so it does NOT drag the verdict off "ok"
            # when every probed subsystem is healthy (B-18).
            p["caller_input"] = True
            p["fix"] = "pass app_id=<the id you call willow-mcp with> to diagnostic_summary"
        else:
            p["fix"] = (f"populate {manifest.get('apps_root')}/{manifest.get('app_id')}"
                        "/manifest.json with a non-empty \"permissions\" list")
        problems.append(p)
    if worker:
        pending = worker.get("pending")
        alive = worker.get("alive", 0)
        stranded_lanes = worker.get("stranded_lanes") or []
        # No worker is only a defect when something is waiting on one. An install
        # that never submits tasks is complete without a worker; saying otherwise
        # would make `degraded` the resting state for most installs. A per-lane
        # strand still warns even when a *different* lane is alive (Loki §2.2): a
        # live batch worker must not mask a dead fast lane.
        aggregate_stranded = alive == 0 and isinstance(pending, int) and pending > 0
        if aggregate_stranded or stranded_lanes:
            died = [w for w in worker.get("workers", []) if w.get("state") in ("stale", "dead")]
            readiness = worker.get("readiness") or (
                "stale" if any(w.get("state") == "stale" for w in died)
                else "dead" if died
                else "absent"
            )
            reason = {
                "absent": "no worker heartbeat has ever been published",
                "dead": "the worker process exited",
                "stale": "the worker process exists but its heartbeat stalled",
            }.get(readiness, "no live worker is ready")
            if stranded_lanes:
                pbl = worker.get("pending_by_lane", {})
                lanes_desc = ", ".join(
                    f"{lane} ({pbl.get(lane, '?')} pending)" for lane in sorted(stranded_lanes)
                )
                detail = (
                    f"lane(s) stranded: {lanes_desc}; no alive worker on that lane to "
                    f"drain it (other lanes may be healthy)"
                )
            else:
                detail = (
                    f"{pending} task(s) stranded: {reason}; nothing will drain the queue"
                )
            if died:
                detail += (f" (found {len(died)} heartbeat(s) from stopped worker(s): "
                           f"{', '.join(str(w.get('pid')) for w in died)})")
            problems.append({"severity": "warn", "check": "worker", "detail": detail,
                             "worker_readiness": readiness,
                             "stranded_lanes": stranded_lanes,
                             "fix": "inspect `willow-mcp worker-service status`, then start "
                                    "the installed worker unit for the stranded lane (or use "
                                    "`willow-mcp worker --lane <lane> --once` for a one-shot drain)"})
    if consent:
        if consent.get("status") == "fail":
            problems.append({
                "severity": "error", "check": "consent",
                "detail": (f"consent policy at {consent.get('canonical_path')} is "
                           f"{consent.get('error')} — every consent key is denied, so "
                           "allow_net tasks will be refused"),
                "fix": f"repair or remove {consent.get('canonical_path')}"})
        disagreement = consent.get("disagreement")
        if disagreement:
            # Never resolved silently: the two files are both plausible statements
            # of operator intent, and picking one is the operator's call. The
            # canonical file is what willow-mcp obeys; say so, and say what the
            # other one claims, so a stale `internet: false` cannot look like a
            # setting that is doing something.
            #
            # Do NOT advise deleting consent.json (B-30). It is a mirror, not a
            # leftover: legacy fleet monolith's save_global_settings(sync_legacy=True) — the
            # default — recreates it from the canonical block on every save, as does
            # Grove's consent toggle. A delete looks like a fix and comes back.
            keys = ", ".join(disagreement["keys"])
            problems.append({
                "severity": "error", "check": "consent",
                "detail": (f"consent disagrees between files on: {keys}. "
                           f"canonical={disagreement['canonical']} "
                           f"legacy={disagreement['legacy']}. willow-mcp obeys the "
                           f"canonical file. {consent.get('legacy_path')} is a mirror "
                           f"legacy fleet monolith rewrites on every save and reads only when the "
                           f"canonical file is absent — so it is a stale mirror, not an "
                           f"inert file, and deleting it will not keep it gone."),
                "fix": (
                    "decide which value states your intent. To keep the canonical "
                    "one and atomically re-sync its mirror, run from an operator "
                    "terminal: `willow-mcp consent reconcile`. To change one key, "
                    "run `willow-mcp consent set <key> <true|false>`."
                )})
    from . import egress_setup as _egress_setup
    if _egress_setup.resolve_public_key_path() is None:
        problems.append({
            "severity": "warn",
            "check": "egress_keys",
            "detail": (
                "signed network tasks need an Ed25519 verification key; none is configured"
            ),
            "fix": (
                "run `willow-mcp setup-egress` once from an operator terminal, reload the IDE, "
                "then `willow-mcp run-net <app_id> --task-file <script>`"
            ),
        })
    if net_lease:
        lease_state = net_lease.get("lease", {})
        status = lease_state.get("status")
        if status in ("malformed", "mismatch"):
            problems.append({
                "severity": "warn", "check": "net_lease",
                "detail": (f"egress lease at {lease_state.get('path')} is {status}"
                           + (f": {lease_state['error']}" if lease_state.get("error") else "")
                           + " — allow_net is denied. A lease is only ever written by "
                             "`willow-mcp grant-net`; this one was not, or was edited after."),
                "fix": f"remove it, then re-issue with `willow-mcp grant-net {net_lease.get('app_id') or lease_state.get('app_id') or '<app_id>'} --ttl 30m`"})
        forgeable = net_lease.get("self_writable") or []
        if forgeable and net_lease.get("strict_trust_root"):
            problems.append({
                "severity": "error", "check": "net_lease",
                "detail": ("WILLOW_MCP_STRICT_TRUST_ROOT is set, but this process can write "
                           "the keys that authorize it: "
                           + ", ".join(f["path"] for f in forgeable)
                           + " — every allow_net task will be refused"),
                "fix": "chown the lease root and manifest to a uid the agent does not run as, "
                       "or unset WILLOW_MCP_STRICT_TRUST_ROOT and accept the residual (B-32)"})
        elif forgeable and net_lease.get("holds_task_net"):
            # Only for an app that actually holds the egress capability. Warning on
            # every install would make `degraded` the resting verdict for the many
            # that never request egress — the false-positive class B-18 removed.
            problems.append({
                "severity": "warn", "check": "net_lease",
                "detail": ("this app holds 'task_net' and this process can write the keys "
                           "that authorize its egress: "
                           + ", ".join(f"{f['key']} ({f['path']})" for f in forgeable)
                           + ". Leases expire and are attributed, so a self-grant now decays "
                             "and leaves a record — but the OS is not preventing one. "
                             "Request and confirm are not yet separate authorities here (B-32)."),
                "fix": "chown the lease root (and manifest) to a uid the agent does not run as, "
                       "then set WILLOW_MCP_STRICT_TRUST_ROOT=1 to enforce it"})
    if severance and severance.get("status") not in (None, "not_asserted"):
        surfaces = severance.get("surfaces", {})
        # A severed install that reports `ok` while wired to the fleet is worse
        # than no check at all. Once the operator has named a fleet, every surface
        # that still resolves into it is a named problem.
        for name in severance.get("violated", []):
            surf = surfaces.get(name, {})
            if name == "trust_root":
                # AUTHORITY, not data. This process can rewrite the ACLs that gate
                # it: the manifest that grants task_net, the lease root, the consent
                # file. Severance from a fleet whose gate you still hold the pen for
                # is not severance. B-32 (host lane) and B-33 (sandbox lane).
                writable = ", ".join(surf.get("self_writable", [])) or surf.get("apps_root", "")
                problems.append({
                    "severity": "error", "check": "severance",
                    "detail": ("this install claims severance but its trust root is within "
                               "reach: " + writable + ". A process that can write its own "
                               "manifest, lease root, or consent file can grant itself the "
                               "egress the cut was supposed to deny."),
                    "fix": ("move the trust root outside every path this process and the Kart "
                            "sandbox can write (WILLOW_MCP_APPS_ROOT), and chown it to a uid "
                            "the agent does not run as")})
            elif name == "egress":
                # AUTHORITY, like trust_root, but the NETWORK key specifically. Under
                # enforcement the process can still forge the three-key egress gate:
                # a writable consent switch, manifest, or lease root, or an
                # absent/self-writable verification key. B-38.
                keys = ", ".join(surf.get("forgeable_keys", [])) or "the egress trust root"
                vk = surf.get("verification_key", {})
                vk_note = ("" if vk.get("configured") and vk.get("present") and not vk.get("self_writable")
                           else " the Ed25519 egress verification key is absent, self-writable, "
                                "or unconfigured, so a forged envelope would verify;")
                problems.append({
                    "severity": "error", "check": "severance",
                    "detail": ("this install claims severance but can forge egress:" + vk_note +
                               " within write reach: " + keys + ". The three-key network gate "
                               "(task_net + consent.internet + a signed lease) can be "
                               "self-granted, so severance from the fleet's STATE is not "
                               "severance from its NETWORK."),
                    "fix": ("move the consent file, manifest, lease root, and egress "
                            "verification key outside every path this process can write "
                            "(chown to a uid the agent does not run as), and keep "
                            "WILLOW_MCP_STRICT_TRUST_ROOT=1")})
            else:
                # DATA. Corruptible, not authority-bearing. Degrades; does not break.
                problems.append({
                    "severity": "warn", "check": "severance",
                    "detail": (f"{name} is not severed from the fleet named by "
                               f"WILLOW_MCP_FLEET_HOME/WILLOW_MCP_FLEET_PG_DB: "
                               f"{surf.get('reason')}"),
                    "fix": (f"point WILLOW_STORE_ROOT at a store outside "
                            f"{severance.get('fleet_home')}" if name == "store"
                            else f"set WILLOW_PG_DB to a database other than "
                                 f"'{severance.get('fleet_pg_db')}'")})
        for name in severance.get("unknown", []):
            if name == "egress":
                # Not half a claim — a claim the OS is not being asked to enforce.
                # strict trust root is off, so the executor denies egress by default
                # but nothing separates the keys; severance cannot be *proven*.
                # Warns (degrades), never breaks — the 2026-07-09 install's true state.
                problems.append({
                    "severity": "warn", "check": "severance",
                    "detail": (surfaces.get("egress", {}).get("reason")
                               or "egress severance cannot be proven"),
                    "fix": ("chown the consent file, manifest, lease root, and egress "
                            "verification key to a uid the agent does not run as, then set "
                            "WILLOW_MCP_STRICT_TRUST_ROOT=1 so the executor enforces the split")})
                continue
            # Half a claim. The operator asserted severance from *something* but
            # left the other coordinate unnamed, so this surface cannot be checked
            # either way. Fail closed: an unverifiable claim is not a passing one.
            problems.append({
                "severity": "warn", "check": "severance",
                "detail": (f"severance is asserted but {name} cannot be checked: "
                           f"{surfaces.get(name, {}).get('reason')}"),
                "fix": "set both WILLOW_MCP_FLEET_HOME and WILLOW_MCP_FLEET_PG_DB, or neither"})
    # #332: an envelope registry that resolves to no usable active grant means
    # nothing can be authorized. Warns (degrades) rather than breaks — the same
    # "present but unpopulated needs the operator to fill it" shape the manifest
    # empty-permissions case takes, and on a fresh install this is the expected
    # "now plant your grants" nudge. Either way it surfaces here on day one
    # instead of being read off a denied act on day three.
    if envelope_registry and envelope_registry.get("status") == "warn":
        reg = envelope_registry
        path = reg.get("path") or "the resolved registry path"
        if reg.get("error"):
            detail = f"envelope registry at {path} could not be read: {reg.get('error')}"
            fix = "repair the registry file, or set WILLOW_ENVELOPE_REGISTRY to your ratified registry"
        elif not reg.get("present"):
            detail = (f"envelope registry not found at {path} — no enveloped act can be "
                      "authorized until it exists and holds grants")
            fix = ("run willow-mcp-init to seed it then plant grants (verb 11), or set "
                   "WILLOW_ENVELOPE_REGISTRY to your ratified registry")
        else:
            detail = (f"envelope registry at {path} holds no active grants (#332: an unpopulated "
                      "starter, or a $WILLOW_HOME relocation shadowing the ratified registry with a "
                      "fresh empty one) — every enveloped act will fail closed")
            fix = ("plant grants (verb 11) into that file, or point WILLOW_ENVELOPE_REGISTRY at the "
                   "ratified registry")
        problems.append({"severity": "warn", "check": "envelope_registry",
                         "detail": detail, "fix": fix})
    return problems


def _derive_verdict(problems: list[dict]) -> str:
    if any(p["severity"] == "error" for p in problems):
        return "broken"
    # caller_input problems (e.g. no app_id passed to this self-check) are warns
    # that describe the CALL, not the install — they surface in `problems` and
    # the relevant sub-check, but must not drag the verdict off "ok" when every
    # probed subsystem is healthy (B-18).
    if any(not p.get("caller_input") for p in problems):
        return "degraded"
    return "ok"


def _collapse_home(obj):
    """Replace the home-dir prefix with ~ in any string values (serve-mode
    redaction for a remote bound caller — no absolute host paths leak)."""
    home = str(os.path.expanduser("~"))
    if isinstance(obj, str):
        return obj.replace(home, "~")
    if isinstance(obj, dict):
        return {k: _collapse_home(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_collapse_home(v) for v in obj]
    return obj


@mcp.tool(annotations=_ANNO_READ)
def whoami(app_id: str = "") -> dict:
    """Report who you are and what you may do: your app_id, role, the permission
    groups your manifest grants, the resolved set of tools you can actually call
    (group expansion minus any deny_tools), your store_scope, and whether you're
    a human-only seat. Read-only and self-scoped — your own manifest, never
    another identity's: in serve mode the app_id comes from your OAuth binding, and
    in stdio under enforcement you must prove you own the app_id you pass (a valid
    per-call credential), so whoami can't enumerate another bound agent's config.
    Ungated otherwise, like diagnostic_summary, so it still answers when your
    manifest is empty or missing (it says exactly that)."""
    from . import gate
    if _serve_mode():
        bound, err = _resolve_serve_identity()
        if err:
            return err
        app_id = bound or ""
    else:
        # stdio: under enforcement, prove you own this app_id before reading its
        # config — whoami must not enumerate another bound agent's manifest.
        denial = _own_identity_denial(app_id, "whoami")
        if denial:
            return denial
    if not app_id:
        return {"error": "no_app_id",
                "detail": "no app_id supplied — pass the app_id you call willow-mcp with"}
    manifest = gate._load_manifest(app_id)
    if manifest is None:
        reason, detail = gate.manifest_diagnosis(app_id)
        return {"app_id": app_id, "error": "no_manifest", "reason": reason,
                "detail": f"{detail} — every call is denied"}
    perms = manifest.get("permissions", []) or []
    allowed: set = set()
    for p in perms:
        g = gate.PERMISSION_GROUPS.get(p)
        allowed.update(g if g is not None else {p})
    deny = manifest.get("deny_tools") or []
    if isinstance(deny, list):
        allowed -= set(deny)
    return {
        "app_id": app_id,
        "role": manifest.get("role", ""),
        "human_only": bool(manifest.get("human_only", False)),
        "permissions": perms,
        "tools_allowed": sorted(allowed),
        "deny_tools": deny if isinstance(deny, list) else [],
        "store_scope": manifest.get("store_scope"),
    }


def _diag_envelope_registry() -> dict:
    """The Article III.2 envelope registry: does it resolve to a file holding at
    least one usable active grant? An empty, missing, or all-malformed registry
    is the #332 footgun — a $WILLOW_HOME relocation seeds a fresh empty starter
    that shadows the ratified registry, and every enveloped act then fails
    closed. Probed here so that loss is visible in the routine self-check, not
    only at the first denied act (which read as one grant expiring and hid the
    outage for ~60 hours). Read-only; reports rather than enforces."""
    from . import envelopes

    try:
        path = envelopes.registry_path()
    except Exception as exc:  # resolution itself failed — report, never raise
        return {"status": "warn", "error": str(exc)}
    if not path.exists():
        return {"status": "warn", "path": str(path), "present": False, "active_grants": 0}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        count = len(envelopes.usable_active_grants(data)) if isinstance(data, dict) else 0
    except Exception as exc:
        return {"status": "warn", "path": str(path), "present": True, "error": str(exc)}
    return {
        "status": "ok" if count > 0 else "warn",
        "path": str(path),
        "present": True,
        "active_grants": count,
    }


@mcp.tool(annotations=_ANNO_READ)
def diagnostic_summary(app_id: str = "") -> dict:
    """Self-check: is this willow-mcp install wired correctly? Reports the SOIL
    store (path/writable/collections), Postgres (reachable + which database +
    whether willow-mcp's tables are present), schema-mapping confirmation state,
    your app_id's manifest + resolved permissions, identity bindings, whether a
    task worker is alive to drain the queue, your egress lease and which of the
    keys authorizing it this process could forge, whether this install is still
    wired to a fleet it claims to be severed from, and the config-bearing
    environment — then a verdict (ok/degraded/broken) with named problems and
    fixes. Ungated on purpose: it must answer even when your manifest or database
    is misconfigured. Reveals only your own config, never fleet rows or vault secrets.

    Severance is asserted, never assumed: name a fleet with WILLOW_MCP_FLEET_HOME
    and WILLOW_MCP_FLEET_PG_DB and every shared surface becomes a named problem.
    Name none and the check reports `not_asserted` and changes nothing."""
    mode = "serve" if _serve_mode() else "stdio"
    redact = False
    if _serve_mode():
        bound, err = _resolve_serve_identity()
        if err:
            return {"verdict": "unauthenticated", "mode": mode, "detail": err["error"],
                    "hint": "sign in and have the operator confirm your binding, then call diagnostic_summary again"}
        app_id = bound
        redact = True
        allowed, retry_after = _check_rate(app_id)
        if not allowed:
            return {"error": "rate_limited", "retry_after": retry_after}
    else:
        # stdio: same identity proof as whoami — under enforcement you may only
        # diagnose the identity you can prove you own, not enumerate another's.
        denial = _own_identity_denial(app_id, "diagnostic_summary")
        if denial:
            return {"verdict": "unauthorized", "mode": mode, "detail": denial["error"]}

    eff = app_id or _DEFAULT_APP_ID
    store = _diag_store()
    postgres = _diag_postgres()
    rings = _diag_rings()
    schema = _diag_schema(eff)
    manifest = _diag_manifest(eff)
    bindings = _diag_bindings()
    worker = _diag_worker(eff)
    consent = _diag_consent()
    net_lease = _diag_net_lease(eff)
    build_leases = _diag_build_leases()
    severance = _diag_severance(store, postgres, net_lease)
    uid_separation = _diag_uid_separation(eff)
    store_db_perms = _diag_store_db_perms(eff)
    envelope_registry = _diag_envelope_registry()
    env = _diag_env()

    problems = _derive_problems(store, postgres, manifest, mode, worker, consent,
                                net_lease, severance, envelope_registry)
    verdict = _derive_verdict(problems)

    report = {
        "verdict": verdict,
        "mode": mode,
        "serve": {"host": _HOST, "port": _PORT, "base_url": _BASE_URL} if _serve_mode() else None,
        "app_id": eff or None,
        "checks": {"store": store, "postgres": postgres, "rings": rings,
                   "schema": schema, "manifest": manifest, "identity_bindings": bindings,
                   "worker": worker, "consent": consent, "net_lease": net_lease,
                   "build_leases": build_leases,
                   "severance": severance, "uid_separation": uid_separation,
                   "store_db_perms": store_db_perms,
                   "envelope_registry": envelope_registry, "env": env},
        "problems": problems,
    }
    if redact:
        report = _collapse_home(report)
    try:
        _receipt_log.record(eff or "-", "diagnostic_summary", "ok" if verdict == "ok" else "warn", verdict)
    except Exception:
        import logging
        logging.getLogger("willow_mcp.server").debug(
            "diagnostic_summary receipt failed", exc_info=True)
    return report


# ── The Commitment Membrane — the operator's kept record of their commitments ────
#
# Jarvis layer 2 (willow_mcp.commitments), the OUTWARD mirror of the voice ingress
# membrane. The engine (ledger + persistence + calendar source) landed in the tree
# with tests but no front door; these four tools ARE that door, under the membrane's
# own three disciplines:
#   - receipt-not-recording — the store holds the FACT (title/when/who/state), never
#     the event body/notes/location; the ledger drops body at ingest and a
#     persistence-boundary guard (_assert_no_forbidden) refuses to store it.
#   - states-not-deletions — a cancel is a WITHDRAWN state, a move keeps the old time
#     in history; nothing is deleted.
#   - NO NEW AUTHORITY — these tools read the calendar into fleet memory and surface
#     it; they NEVER write the calendar back. propose_action and the SAFE gate are
#     deliberately not exposed over MCP.
# The live gcal transport is unwired (OAuth is a home-box step), so `commitment_ingest`
# reads from operator-supplied events today and goes live when the transport lands —
# the same "live but dormant" shape the rest of the fleet ships.

# Physical SOIL collection. The membrane package's DEFAULT_COLLECTION is the logical
# name `willow/commitments`; the store validator only accepts physical names (no
# slash — the `/` form is resolved by the manifest alias layer, which this internal
# persistence deliberately bypasses), so the binding pins a physical name here.
_COMMITMENT_COLLECTION = "willow_commitments"


def _commitment_persistence():
    # References the module-level _store at call time so tests that monkeypatch
    # server._store are honored (same pattern as the store_* tools).
    from .commitments.commitment_store import CommitmentPersistence
    return CommitmentPersistence(_store, collection=_COMMITMENT_COLLECTION)


def _commitment_ledger_restored():
    """A fresh ledger with persisted commitments rehydrated — no calendar fetch."""
    from .commitments.commitment_ledger import CommitmentLedger, StubCalendarSource
    ledger = CommitmentLedger(source=StubCalendarSource())
    _commitment_persistence().restore_into(ledger)
    return ledger


def _commitment_parse_dt(raw: str):
    """ISO-8601 -> naive UTC datetime (the membrane's internal convention, matching
    GCalSyncSource which clocks on datetime.utcnow()). A tz-aware input is converted
    to UTC then stripped; a naive input is taken as already-UTC."""
    from datetime import datetime, timezone
    raw = raw.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _commitment_events_from_payload(events: list):
    """[{uid,title,start,end?,attendees?,body?,cancelled?}] -> [CalendarEvent].

    `body` may be passed but the ledger DROPS it at ingest and it is never persisted
    (receipt-not-recording) — accepted only so a caller can hand a raw event through
    without pre-stripping. Raises ValueError on a malformed row."""
    from .commitments.commitment_ledger import CalendarEvent
    out = []
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise ValueError(f"event[{i}] is not an object")
        uid = str(ev.get("uid") or "").strip()
        start = ev.get("start")
        if not uid or not start:
            raise ValueError(f"event[{i}] requires 'uid' and 'start'")
        out.append(CalendarEvent(
            uid=uid,
            title=str(ev.get("title") or "").strip(),
            start=_commitment_parse_dt(str(start)),
            end=_commitment_parse_dt(str(ev["end"])) if ev.get("end") else None,
            attendees=tuple(str(a) for a in (ev.get("attendees") or [])),
            body=str(ev.get("body") or ""),
            cancelled=bool(ev.get("cancelled", False)),
        ))
    return out


def _commitment_fact(c) -> dict:
    """A commitment as FACTS only — never a field that could hold the event body."""
    return {
        "uid": c.uid,
        "title": c.title,
        "when": c.when.isoformat(),
        "end": c.end.isoformat() if c.end else None,
        "who": list(c.who),
        "state": c.state.name,
        "acknowledged": c.acknowledged,
        "history_len": len(c.history),
    }


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("commitment_ingest")
def commitment_ingest(app_id: str, events: Optional[list] = None) -> dict:
    """Ingest calendar events into the operator's commitment ledger and persist the
    result (SOIL collection `willow/commitments`). Read-only reconcile: a new event
    becomes an ACTIVE commitment, a cancellation a WITHDRAWN state, a moved event
    keeps its old time in history — nothing is deleted (states-not-deletions). Only
    the FACT is stored (title/when/who/state); the event body/notes/location are read
    to derive the fact then DROPPED, never persisted (receipt-not-recording).

    `events`: a list of {uid, title, start, end?, attendees?, body?, cancelled?} — the
    operator/integration push path (start/end are ISO-8601). Omit it to pull from the
    live calendar source; that transport (gcal OAuth) is a home-box step, so until then
    an omitted `events` returns `transport_unwired` rather than inventing data.

    This tool NEVER writes the calendar back — a cancel/reschedule is a proposal routed
    through the SAFE gate, which is deliberately not exposed over MCP (no new authority)."""
    from .commitments.commitment_ledger import CommitmentLedger, StubCalendarSource

    if events is None:
        return {"status": "transport_unwired",
                "detail": ("no events supplied and the live calendar transport is not "
                           "wired (gcal OAuth is a home-box step). Pass events=[...] to "
                           "ingest now."),
                "ingested": 0}
    try:
        parsed = _commitment_events_from_payload(events)
    except ValueError as e:
        return {"error": f"malformed events: {e}"}

    ledger = CommitmentLedger(source=StubCalendarSource(parsed))
    _commitment_persistence().restore_into(ledger)   # reconcile against what's stored
    ledger.ingest()
    _commitment_persistence().save_ledger(ledger)

    # Summarize what changed on THIS ingest tick, by receipt kind (facts only).
    tick = ledger._tick
    changes: dict = {}
    for r in ledger.receipts:
        if r.get("tick") == tick and r.get("event") in ("ingest", "withdraw", "move"):
            changes[r["event"]] = changes.get(r["event"], 0) + 1
    return {"status": "ok", "ingested": len(parsed), "changes": changes,
            "total_commitments": len(ledger.commitments)}


@mcp.tool(annotations=_ANNO_WRITE_IDEM)
@_guarded("commitment_acknowledge")
def commitment_acknowledge(app_id: str, uid: str) -> dict:
    """Mark a commitment change as seen by the operator — the split-stick halves match
    again. Recorded as an 'acknowledged' history entry (never erased) and it stops
    surfacing as a 'mismatch'. Returns unknown_uid if there is no such commitment."""
    ledger = _commitment_ledger_restored()
    if uid not in ledger.commitments:
        return {"error": "unknown_uid", "uid": uid}
    ledger.acknowledge(uid)
    _commitment_persistence().save(ledger.commitments[uid])
    return {"status": "ok", "uid": uid, "acknowledged": True}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("commitment_surface")
def commitment_surface(app_id: str, now: str = "", lead_minutes: int = 15) -> dict:
    """The dew-rule view: what — if anything — deserves the operator's attention right
    now. Silent by default; it speaks only when the split-stick halves disagree — a
    commitment imminent (starting within `lead_minutes`), two active commitments in
    conflict, or a change not yet acknowledged (a 'mismatch'). Each surfacing carries
    title + time only, never the event body. Read-only.

    `now`: ISO-8601 instant to evaluate against (default: current UTC)."""
    from datetime import datetime, timedelta
    from .commitments.commitment_ledger import DewConfig
    try:
        at = _commitment_parse_dt(now) if now.strip() else datetime.utcnow()
    except ValueError as e:
        return {"error": f"malformed now: {e}"}
    ledger = _commitment_ledger_restored()
    ledger.cfg = DewConfig(lead=timedelta(minutes=max(0, int(lead_minutes))))
    surfacings = ledger.dew_surface(at)
    return {"status": "ok", "at": at.isoformat(), "count": len(surfacings),
            "surfacings": [{"kind": s.kind, "uids": list(s.uids),
                            "when": s.when.isoformat(), "fact": s.fact}
                           for s in surfacings]}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("commitment_list")
def commitment_list(app_id: str, state: str = "",
                    limit: int = 50, cursor: Optional[str] = None) -> dict:
    """List the operator's persisted commitments as FACTS only (uid/title/when/who/
    state/acknowledged/history length) — never the event body.  Paginated: returns
    ``{status, count, commitments, next_cursor}`` — pass the returned
    ``next_cursor`` as ``cursor`` to fetch the next page.  Read-only. ``state``
    filters to ACTIVE or WITHDRAWN (case-insensitive); omit for all."""
    want = state.strip().upper()
    if want and want not in ("ACTIVE", "WITHDRAWN"):
        return {"error": "state must be ACTIVE, WITHDRAWN, or omitted"}
    ledger = _commitment_ledger_restored()
    rows = [_commitment_fact(c) for c in ledger.commitments.values()
            if not want or c.state.name == want]
    rows.sort(key=lambda r: r["when"])
    if cursor:
        after_when = decode_cursor(cursor)
        # Cursor encodes "when\x00uid" for tie-breaking
        parts = after_when.split("\x00", 1)
        if len(parts) == 2:
            aw, au = parts
        else:
            aw, au = parts[0], ""
        rows = [r for r in rows
                if r["when"] > aw or (r["when"] == aw and r.get("uid", "") > au)]
    limit = max(1, limit)
    has_more = len(rows) > limit
    items = rows[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(f"{last['when']}\x00{last.get('uid', '')}")
    return {"status": "ok", "count": len(items), "commitments": items,
            "next_cursor": next_cursor}


# ── code_graph — a local, budget-aware symbol graph (legacy fleet monolith port) ───────────
#
# The top 🟢 item on the migration shortlist (docs/migrations/willow-2.0-gap-
# inventory.md §6): the only call-graph capability willow-mcp lacked, and a
# self-contained one — stdlib ast + sqlite3, no Postgres, no network, no external
# CLI. The engine (willow_mcp.code_graph) is a verbatim port; these six tools are
# the willow-mcp surface. `code_graph_index` writes a local SQLite DB (WRITE);
# search/explain/walk/suggest/impact are read-only queries over it.

def _code_graph_db(db_path: str = "") -> Path:
    """Resolve the symbol-graph DB. Explicit db_path wins; else WILLOW_CODE_GRAPH_DB;
    else $WILLOW_HOME/code_graph/graph.db (kept out of the SOIL store — it is a
    rebuildable index of source, not fleet state)."""
    if db_path:
        return Path(db_path).expanduser()
    env = os.environ.get("WILLOW_CODE_GRAPH_DB", "").strip()
    if env:
        return Path(env).expanduser()
    return paths.willow_home() / "code_graph" / "graph.db"


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("code_graph_index")
def code_graph_index(app_id: str, repo_root: str, db_path: str = "", force: bool = False) -> dict:
    """Index a repository's Python + JS/TS files into a local SQLite symbol graph
    (symbols, import/inherit edges, per-file stats). Run once before the read
    tools. Pure stdlib `ast` — no network, no Postgres, no external CLI.

    `repo_root` (required): the directory to index. `db_path`: override the graph
    DB location (default $WILLOW_HOME/code_graph/graph.db, or WILLOW_CODE_GRAPH_DB).
    `force`: reserved (the indexer upserts, so re-running is already idempotent)."""
    root = Path(repo_root).expanduser()
    if not root.is_dir():
        return {"error": f"repo_root not found or not a directory: {repo_root}"}
    from .code_graph import index_repo
    try:
        return index_repo(root, _code_graph_db(db_path), force=force)
    except Exception as e:
        return {"error": f"index failed: {type(e).__name__}: {e}"}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("code_graph_search")
def code_graph_search(app_id: str, query: str, kinds: Optional[list] = None,
                      max_results: int = 20, db_path: str = "") -> dict:
    """Fuzzy symbol search over the graph: exact → prefix → contains →
    camelCase/snake_case token split. `kinds` filters by symbol type
    (module|class|function|method); omit for all. Read-only."""
    db = _code_graph_db(db_path)
    if not db.is_file():
        return {"error": f"no symbol graph at {db} — run code_graph_index first"}
    from .code_graph import search_symbols
    results = search_symbols(db, query, max_results=max_results, kinds=kinds)
    return {"query": query, "count": len(results), "results": results}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("code_graph_explain")
def code_graph_explain(app_id: str, symbol: str, db_path: str = "") -> dict:
    """Explain a symbol: signature, file location, callers (inbound edges), and
    callees (outbound). `symbol` is a name or fully-qualified name
    (e.g. 'permitted' or 'willow_mcp.gate.permitted'). Read-only."""
    db = _code_graph_db(db_path)
    if not db.is_file():
        return {"error": f"no symbol graph at {db} — run code_graph_index first"}
    from .code_graph import explain_symbol
    return explain_symbol(db, symbol)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("code_graph_walk")
def code_graph_walk(app_id: str, anchor: str, hop_depth: int = 2,
                    max_tokens: int = 8000, db_path: str = "") -> dict:
    """BFS from an anchor symbol along import + inherit edges, collecting context
    until a token budget is hit. Deterministic (alphabetical within each hop).
    `anchor`: symbol name or fqn. Read-only."""
    db = _code_graph_db(db_path)
    if not db.is_file():
        return {"error": f"no symbol graph at {db} — run code_graph_index first"}
    from .code_graph import walk
    result = walk(db, anchor, hop_depth=hop_depth, max_tokens=max_tokens)
    return {
        "anchor_fqn": result.anchor_fqn,
        "hops_traversed": result.hops_traversed,
        "tokens_returned": result.tokens_returned,
        "files": result.files,
        "symbols": result.symbols,
    }


@mcp.tool(annotations=_ANNO_READ)
@_guarded("code_graph_suggest")
def code_graph_suggest(app_id: str, task: str, max_results: int = 10,
                       db_path: str = "") -> dict:
    """Suggest the files most relevant to a task description, ranked by keyword
    overlap with symbol names + file paths. No embeddings, no LLM. Read-only."""
    db = _code_graph_db(db_path)
    if not db.is_file():
        return {"error": f"no symbol graph at {db} — run code_graph_index first"}
    from .code_graph import suggest_files
    files = suggest_files(db, task, max_results=max_results)
    return {"task": task[:100], "suggestions": files}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("code_graph_impact")
def code_graph_impact(app_id: str, file_paths: list, db_path: str = "") -> dict:
    """Blast radius: which files/symbols import from the given files? `file_paths`
    are repo-relative (e.g. ['src/willow_mcp/gate.py']). Read-only."""
    db = _code_graph_db(db_path)
    if not db.is_file():
        return {"error": f"no symbol graph at {db} — run code_graph_index first"}
    from .code_graph import analyze_impact
    return analyze_impact(db, file_paths)


# ── open web (ported from legacy fleet monolith core/web_search + core/web_fetch) ────────
#
# Server-process HTTP egress — gated by web_net + consent.internet + lease
# (web_egress.py). Replaces native IDE WebSearch/WebFetch when the PreToolUse
# hook is active. Fetch runs external-guard scan + sandwich wrap.

@mcp.tool(annotations=_ANNO_READ_OPEN)
@_guarded("willow_web_search")
def willow_web_search(
    app_id: str,
    query: str,
    max_results: int = 8,
    trusted_only: bool = False,
    include_handoffs: bool = False,
) -> dict:
    """Open web search via DuckDuckGo HTML (no API key). Returns title, url,
    snippet, source, and hostname per result. Use for current events, tech news,
    and queries that need the live open web.

    `trusted_only`: heuristic filter — keep results whose hostname matches a
    hand-curated suffix list of institutional domains. Cannot distinguish a real
    institution from a lookalike and does not verify the source. Prefer
    `willow_institutional_search` for citations that need backing.
    `include_handoffs`: prepend OpenStreetMap/Google Maps links for navigational
    queries. Requires web_net + consent.internet + a live egress lease."""
    from . import web_egress, web_search

    denial = web_egress.egress_denial(app_id)
    if denial:
        return denial
    hits = web_search.search_web(
        query,
        max_results=max_results,
        trusted_only=trusted_only,
        include_handoffs=include_handoffs,
    )
    return {"query": query, "results": hits, "count": len(hits)}


@mcp.tool(annotations=_ANNO_READ_OPEN)
@_guarded("willow_institutional_search")
def willow_institutional_search(
    app_id: str,
    query: str,
    max_results: int = 10,
    sources: list[str] | None = None,
    limit_per_source: int = 3,
) -> dict:
    """Search ~60 named institutional and academic collections — arXiv, PubMed,
    Crossref, OpenAlex, Library of Congress, Europeana, CourtListener, the
    Smithsonian — and return citable results.

    Every hit carries `confidence: "institutional"` because a named collection
    was actually queried, not because its hostname looked reputable. Use this
    when a claim needs backing; use `willow_web_search` for the open web.

    Read `ok` before `hits`: `ok` true with no hits means the collections had
    nothing, `ok` false means no source completed a look. `sources_queried`,
    `failed`, `skipped` and `timed_out` say which is which. `sources` narrows
    the fan-out to specific registered ids.

    `max_results` caps the *returned* hits; `total` is the count before that cap,
    so a caller can tell whether there was more. `limit_per_source` is jeles'
    own knob and is per collection, not overall — with ~60 sources the default
    of 3 can produce far more hits than `max_results` keeps.

    Requires web_net + consent.internet + a live egress lease."""
    from . import web_egress

    denial = web_egress.egress_denial(app_id)
    if denial:
        return denial

    try:
        from jeles import institutional
    except ImportError:  # pragma: no cover - jeles is a declared dependency
        return {"error": (
            "jeles_missing: institutional search needs the `jeles` package. "
            "It is a declared dependency, so this means the install is broken "
            "rather than incomplete — reinstall with `pip install --force-"
            "reinstall willow-mcp`. This deliberately names no version: the "
            "floor lives in pyproject.toml, and the copy that used to be here "
            "said `jeles>=0.5.0` after the real floor moved to 0.5.1, so it was "
            "telling operators to install a version this package rejects.")}

    # Never raises by contract — a failed hop comes back as ok=False with an
    # explanation, which is why there is no try/except around it. Wrapping it
    # would turn a legible refusal into an opaque one.
    result = institutional.search_institutional(
        query, sources_filter=sources, limit_per_source=limit_per_source)

    # jeles' limit is per source. Truncate here so `max_results` means what it
    # says on every other search tool, and keep `total` as jeles reported it so
    # the truncation is visible rather than silent.
    hits = list(result.get("hits") or [])
    return {"query": query, **result,
            "hits": hits[:max_results],
            "count": min(len(hits), max_results)}


@mcp.tool(annotations=_ANNO_READ_OPEN)
@_guarded("willow_web_fetch")
def willow_web_fetch(
    app_id: str,
    url: str,
    wrap: bool = True,
    max_bytes: int = 512_000,
) -> dict:
    """Fetch a URL through external-guard (not native WebFetch).

    Returns text with sandwich defense when wrap=True. Blocks private, loopback
    and other non-public destinations — resolving names, not just matching them
    — and re-checks every redirect hop rather than the first URL alone; the
    chain taken comes back in `redirects`. Use willow_web_search to discover
    URLs first. Requires web_net + consent.internet + a live egress lease."""
    from . import web_egress, web_fetch

    denial = web_egress.egress_denial(app_id)
    if denial:
        return denial
    return web_fetch.fetch_url(url, wrap=wrap, max_bytes=max_bytes)


# ── forks — bounded work-unit tracking (SOIL-backed) ─────────────────────────

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("fork_create")
def fork_create(
    app_id: str,
    title: str,
    created_by: str,
    topic: str = "",
    fork_id: str = "",
) -> dict:
    """Open a fork — a named, bounded unit of work (feature branch + PR
    tracking) recorded in the SOIL store. Snapshots selected environment
    variables so env_check can later spot drift between where the fork was
    opened and where it's being worked. `fork_id` pins an explicit ID; omit it
    to auto-generate. Log changes with fork_log; close with fork_merge or
    fork_delete."""
    from . import forks
    try:
        return forks.create(
            _store, app_id=app_id, title=title, created_by=created_by,
            topic=topic, fork_id=fork_id,
        )
    except forks.ForkError as e:
        return {"error": str(e)}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("fork_join")
def fork_join(app_id: str, fork_id: str, component: str) -> dict:
    """Register `component` — an agent, repo, or subsystem name — as a
    participant in an open fork, so its changes can then be logged against
    the fork via fork_log. Errors if the fork is unknown or already closed."""
    from . import forks
    try:
        return forks.join(_store, fork_id=fork_id, component=component)
    except forks.ForkError as e:
        return {"error": str(e)}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("fork_log")
def fork_log(
    app_id: str,
    fork_id: str,
    component: str,
    type: str,
    ref: str,
    description: str = "",
) -> dict:
    """Append one change entry to an open fork's log: `type` names what kind
    of artifact changed (branch, atom, task, thread, …), `ref` points at it
    (branch name, atom ID, URL), and `description` says what happened. These
    entries are what fork_merge / fork_delete later tally as promoted or
    archived."""
    from . import forks
    try:
        return forks.log_change(
            _store, fork_id=fork_id, component=component, type_=type,
            ref=ref, description=description,
        )
    except forks.ForkError as e:
        return {"error": str(e)}


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("fork_merge")
def fork_merge(app_id: str, fork_id: str, outcome_note: str = "") -> dict:
    """Close an open fork as MERGED — the work landed. Tallies the fork's
    atom/kb change-log entries as promoted and records `outcome_note` as the
    close-out summary. Irreversible: a closed fork cannot be reopened, only
    inspected via fork_status."""
    from . import forks
    return forks.merge(_store, fork_id=fork_id, outcome_note=outcome_note)


@mcp.tool(annotations=_ANNO_DESTRUCTIVE)
@_guarded("fork_delete")
def fork_delete(app_id: str, fork_id: str, reason: str = "") -> dict:
    """Close an open fork as DELETED — the work was abandoned. The fork record
    is kept (this closes, it does not erase); its atom/kb change-log entries
    are tallied as archived and `reason` records why. Irreversible, like
    fork_merge."""
    from . import forks
    return forks.delete(_store, fork_id=fork_id, reason=reason)


@mcp.tool(annotations=_ANNO_READ)
@_guarded("fork_status", list_error=False)
def fork_status(app_id: str, fork_id: str) -> dict:
    """Full record for one fork: title, state (open/merged/deleted),
    participant components, the complete change log, and its environment
    snapshot. Returns {error} for an unknown fork_id. Read-only."""
    from . import forks
    rec = forks.status(_store, fork_id=fork_id)
    if not rec:
        return {"error": f"fork {fork_id} not found"}
    return rec


@mcp.tool(annotations=_ANNO_READ)
@_guarded("fork_list", paginated=True)
def fork_list(app_id: str, status: str = "open",
              limit: int = 50, cursor: Optional[str] = None) -> dict:
    """List forks in one state — 'open' (default), 'merged', or 'deleted' —
    as summary records, so you can find in-flight work units.  Paginated:
    returns ``{items, next_cursor}`` — pass the returned ``next_cursor`` as
    ``cursor`` to fetch the next page.  Use fork_status for one fork's full
    change log. Read-only."""
    from . import forks
    try:
        return forks.list_forks(_store, status=status, limit=limit, cursor=cursor)
    except forks.ForkError as e:
        return {"items": [{"error": str(e)}], "next_cursor": None}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("env_check", list_error=False)
def env_check(app_id: str, fork_id: str) -> dict:
    """Diff the current process environment against the snapshot taken at
    fork_create — catches "works on the machine that opened the fork" drift
    before merging. Returns the variables that changed or went missing.
    Read-only."""
    from . import forks
    return forks.env_check(_store, fork_id=fork_id)


# ── human-in-the-loop: an attention queue + durable attestations ────────────────
#
# Ported from legacy fleet monolith core/human_required.py + core/human_attestation.py
# (migration shortlist §6). Homed on the SOIL store, not the fleet Postgres (no
# unilateral schema migration — B-28), via willow_mcp.human_loop. The attester of
# a human_attestation is ALWAYS the calling identity, never a free parameter, and
# a non-forgeable by_human flag records whether that identity is the ATTESTED
# human-orchestrator seat — so an agent can never write a record claiming the
# operator signed something (the sudo invariant, applied to attestation).
#
# "Non-forgeable" is load-bearing and was once false: by_human was computed by
# string-comparing the caller-supplied app_id against "willow", so passing
# app_id="willow" was the whole exploit. It now comes from human_session.
# by_human_attested(), which reads a signal the caller cannot set — see that
# function. Never reintroduce is_orchestrator_app() as a source of privilege;
# it answers "what did this call name itself", not "who is calling".

@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("human_required_enqueue")
def human_required_enqueue(app_id: str, kind: str, title: str, summary: str = "",
                           priority: str = "normal", source_ref: str = "",
                           assignee: str = "") -> dict:
    """Enqueue work that must pause automation until a human acts. `kind`:
    consent | attestation | review | overload | onboarding. `priority`:
    low|normal|high|urgent. Records the calling app as source_agent."""
    from . import human_loop
    try:
        return human_loop.enqueue(_store, kind=kind, title=title, summary=summary,
                                  priority=priority, source_agent=app_id,
                                  source_ref=source_ref, assignee=assignee)
    except human_loop.HumanLoopError as e:
        return {"error": str(e)}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("human_required_resolve")
def human_required_resolve(app_id: str, item_id: str, status: str = "resolved",
                           note: str = "") -> dict:
    """Resolve / dismiss / acknowledge a human-required queue item. `status`:
    resolved | dismissed | acknowledged. The row is updated in place (who/when/
    note), never deleted. Returns unknown_item if there is no such id."""
    from . import human_loop
    try:
        return human_loop.resolve(_store, item_id, resolved_by=app_id,
                                  status=status, note=note)
    except human_loop.HumanLoopError as e:
        return {"error": str(e)}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("human_required_list")
def human_required_list(app_id: str, status: str = "open", kind: str = "",
                        limit: int = 20) -> dict:
    """List human-required queue items (newest first) with a by-status tally.
    `status` defaults to 'open'; pass '' for all. Read-only."""
    from . import human_loop
    items = human_loop.list_queue(_store, status=status, kind=kind, limit=limit)
    return {"items": items, "count": len(items), "stats": human_loop.queue_stats(_store)}


@mcp.tool(annotations=_ANNO_WRITE)
@_guarded("human_attestation_create")
def human_attestation_create(app_id: str, subject_id: str,
                             subject_type: str = "knowledge_atom", statement: str = "",
                             status: str = "attested", evidence_ref: str = "") -> dict:
    """Create a durable attestation/rejection/change-request record for a subject
    (knowledge_atom | edge | queue_item | external_review | other; status
    attested | rejected | needs_changes).

    The attester is the CALLING identity — there is deliberately no `attested_by`
    parameter, so no caller can forge a record in another's name. `by_human` is
    set from whether the caller is the *attested* human-orchestrator seat — the
    server's WILLOW_HUMAN_ORCHESTRATOR env in stdio, the confirmed OAuth binding
    in serve — never from the app_id string alone; only a by_human record
    satisfies `has_attestation(require_human=True)`."""
    from . import human_loop
    from .human_session import by_human_attested
    try:
        return human_loop.create_attestation(
            _store, subject_id=subject_id, subject_type=subject_type,
            statement=statement, status=status, evidence_ref=evidence_ref,
            attested_by=app_id,
            by_human=by_human_attested(app_id, serve_mode=_serve_mode()))
    except human_loop.HumanLoopError as e:
        return {"error": str(e)}


@mcp.tool(annotations=_ANNO_READ)
@_guarded("human_attestation_list")
def human_attestation_list(app_id: str, subject_id: str = "", subject_type: str = "",
                           status: str = "", limit: int = 20) -> dict:
    """List durable attestation records (newest first), optionally filtered by
    subject_id / subject_type / status. Read-only."""
    from . import human_loop
    items = human_loop.list_attestations(_store, subject_id=subject_id,
                                         subject_type=subject_type, status=status, limit=limit)
    return {"items": items, "count": len(items)}


# ── Entry points ───────────────────────────────────────────────────────────────

def _cmd_setup(args) -> None:
    """`willow-mcp setup` — write OAuth provider credentials to the vault.

    Secrets are only ever accepted via getpass/stdin prompt when the
    corresponding CLI flag is omitted, so a client-secret or private key
    never has to appear in shell history or a process listing.
    """
    import getpass
    import sys

    from .vault import default_vault

    vault = default_vault()
    did_anything = False

    if args.google_client_id:
        did_anything = True
        vault.write("google.client_id", args.google_client_id)
        secret = args.google_client_secret or getpass.getpass("Google client secret: ")
        vault.write("google.client_secret", secret)
        print("Google credentials written to vault.")

    if args.apple_team_id:
        did_anything = True
        vault.write("apple.team_id", args.apple_team_id)
        vault.write("apple.client_id", args.apple_client_id or "")
        vault.write("apple.key_id", args.apple_key_id or "")
        if args.apple_p8_key_path:
            with open(args.apple_p8_key_path) as f:
                p8_key = f.read()
        else:
            print("Paste the Apple .p8 private key contents, then press Ctrl-D:")
            p8_key = sys.stdin.read()
        vault.write("apple.p8_key", p8_key)
        print("Apple credentials written to vault.")

    if not did_anything:
        print("Nothing to do — pass --google-client-id and/or --apple-team-id.")


def _cmd_confirm_binding(args) -> None:
    """`willow-mcp confirm-binding` — bind a signed-in OAuth identity to an app_id.

    Local/stdio-only by design (L-AUTH-02): this is never reachable as an MCP
    tool, so a remote serve-mode caller can never confirm their own binding.
    Run this on the host after the person has signed in once via the OAuth
    approval page (which creates the unconfirmed binding record).
    """
    from .identity_binding import confirm_binding

    try:
        record = confirm_binding(args.idp, args.subject, args.app_id)
    except ValueError as e:
        print(f"Error: {e}")
        raise SystemExit(1)
    print(f"Bound ({record['issuer']}, {record['subject_id']}) -> app_id={record['app_id']!r} "
          f"(email: {record.get('email')}, basis: {record.get('email_basis', 'unknown')})")
    if record.get("email_drift"):
        print(f"  WARNING: email changed since this binding was first proposed "
              f"({record.get('drift_from_email')} -> {record.get('drift_to_email')}) "
              f"at {record.get('email_drift_detected_at')} — verify this is still the same person "
              f"before confirming.")


def _cmd_voice(args) -> None:
    """Run the voice ingress daemon (CLI: `willow-mcp voice`)."""
    from .voice.daemon import VoiceDaemon, VoiceDaemonConfig, load_handler
    from .voice.daemon import _echo_handler

    handler = None
    if getattr(args, "echo", False):
        handler = _echo_handler
    elif getattr(args, "handler", ""):
        handler = load_handler(args.handler)
    else:
        env_handler = os.environ.get("WILLOW_VOICE_HANDLER", "").strip()
        if env_handler:
            handler = load_handler(env_handler)

    if handler is None:
        print(
            "Error: voice dispatch handler required — pass --handler module:callable, "
            "--echo for smoke test, or set WILLOW_VOICE_HANDLER",
            file=sys.stderr,
        )
        raise SystemExit(1)

    config = VoiceDaemonConfig(
        app_id=(args.app_id or os.environ.get("WILLOW_APP_ID") or "willow").strip(),
        wake_models=tuple(args.wake_model or []),
        wake_threshold=args.wake_threshold,
        whisper_model=args.whisper_model,
        enable_frank=not args.no_frank,
        enable_kokoro=not args.no_speak,
        command_handler=handler,
        kokoro_url=args.kokoro_url or None,
        kokoro_voice=args.kokoro_voice or None,
        mic_device=args.mic_device,
    )
    VoiceDaemon(config).run()


def _cmd_voice_service(args) -> None:
    from . import voice_service

    cfg = voice_service.VoiceServiceConfig(
        python=Path(args.python),
        workdir=Path(args.workdir),
        willow_home=Path(args.willow_home),
        app_id=args.app_id,
        wake_models=args.wake_models,
        kokoro_url=args.kokoro_url,
        kokoro_voice=args.kokoro_voice,
        handler=args.handler,
    )
    if args.action == "install":
        result = voice_service.install(cfg)
    elif args.action == "status":
        result = voice_service.status()
    else:
        result = voice_service.uninstall()
    if result.get("error"):
        print(f"willow-mcp voice-service: {result['error']}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


def _cmd_worker(args) -> None:
    """Drain the Kart queue via the kartikeya worker (CLI: `willow-mcp worker`)."""
    from . import worker as worker_mod

    raise SystemExit(
        worker_mod.main(
            [
                *(["--lane", args.lane] if args.lane else []),
                *(["--slots", str(args.slots)] if args.slots is not None else []),
                "--interval",
                str(args.interval),
                *(["--once"] if args.once else []),
                *(["--require-postgres"] if args.require_postgres or args.lane == "batch" else []),
                "--app-id",
                args.app_id or _DEFAULT_APP_ID,
            ]
        )
    )


def _cmd_consent(args) -> None:
    from . import consent
    from . import consent_admin

    if args.action == "status":
        print(json.dumps(consent.read_consent(), indent=2))
        return
    if os.environ.get("WILLOW_IN_KART", "").strip() or not sys.stdin.isatty():
        print(
            "Error: consent mutation requires an interactive operator terminal",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        if args.action == "reconcile":
            result = consent_admin.reconcile()
        else:
            if args.value not in ("true", "false"):
                raise ValueError("value must be exactly true or false")
            result = consent_admin.set_key(args.key, args.value == "true")
    except (OSError, PermissionError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


def _cmd_grant_consent(args) -> None:
    """`willow-mcp grant-consent <subject_id> <scope> --by <guardian>` —
    operator-only. Records a GRANTED transition on the subject's consent chain,
    receipts it, and logs it on the subject's disclosure chain. Like grant-net
    and register-agent, no MCP tool can reach this (the sudo invariant): an app
    may *request* a subject grant, never mint one."""
    from . import subject_consent_binding as scb
    from .subject_consent.core import SubjectConsentError

    try:
        consent = scb.grant(args.subject_id, args.scope, args.by)
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except SubjectConsentError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps({
        "subject_id": consent.subject_id,
        "scope": consent.scope,
        "status": consent.status,
        "granted_by": consent.granted_by,
        "at": consent.at,
    }, indent=2))


def _cmd_revoke_consent(args) -> None:
    """`willow-mcp revoke-consent <subject_id> <scope> --by <guardian>` —
    operator-only. Records a REVOKED transition (the gate then fails closed for
    that subject + scope until re-granted). Operator terminal only."""
    from . import subject_consent_binding as scb
    from .subject_consent.core import SubjectConsentError

    try:
        consent = scb.revoke(args.subject_id, args.scope, args.by)
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except SubjectConsentError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps({
        "subject_id": consent.subject_id,
        "scope": consent.scope,
        "status": consent.status,
        "revoked_by": consent.granted_by,
        "at": consent.at,
    }, indent=2))


def _cmd_consent_status(args) -> None:
    """`willow-mcp consent-status <subject_id>` — read-only. Reports which scopes
    are currently GRANTED on the subject's chain (raw recorded state, before the
    binding's owner-exemption) plus the subject's disclosure chain. A read, so it
    needs no operator terminal — the counterpart to net-status for grant-net."""
    from . import subject_consent_binding as scb
    from .subject_consent import core

    store = scb.store()
    scopes = {scope: core.permitted(store, args.subject_id, scope) for scope in core.SCOPES}
    try:
        disclosures = core.read_disclosures(store, args.subject_id)
    except core.SubjectConsentError:
        disclosures = []
    owner = scb.owner_subject_id()
    print(json.dumps({
        "subject_id": args.subject_id,
        "is_owner": bool(owner) and args.subject_id == owner,
        "granted_scopes": [scope for scope, ok in scopes.items() if ok],
        "scopes": scopes,
        "disclosures": disclosures,
    }, indent=2))


def _cmd_repo_sweep(args) -> None:
    """Survey every repo under a root and report. Read-only unless --emit-flags."""
    from . import repo_sweep

    root = Path(args.root).expanduser()
    surveys = repo_sweep.sweep(root, args.branch_limit, args.max_depth)
    print(repo_sweep.format_report(root, surveys, as_json=args.as_json))
    if args.emit_flags:
        collection = args.collection or repo_sweep.DEFAULT_FLAG_COLLECTION
        n = repo_sweep.emit_flags(surveys, collection)
        print(f"\n[repo-sweep] raised {n} SOIL flags in {collection}")


def _cmd_repo_sweep_service(args) -> None:
    """Install, inspect, or uninstall the sweep units without changing live state."""
    from dataclasses import replace

    from . import repo_sweep_service

    config = repo_sweep_service.default_config()
    overrides = {}
    if args.root:
        overrides["root"] = Path(args.root).expanduser().resolve()
    if args.oncalendar:
        overrides["oncalendar"] = args.oncalendar
    if args.collection:
        overrides["collection"] = args.collection
    config = replace(config, **overrides)
    try:
        if args.action == "install":
            result = repo_sweep_service.install_services(config)
        elif args.action == "status":
            result = repo_sweep_service.service_status()
        else:
            result = repo_sweep_service.uninstall_services()
    except (RuntimeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


def _cmd_worker_service(args) -> None:
    """Install, inspect, or uninstall worker units without changing live state."""
    from dataclasses import replace

    from . import worker_service

    config = worker_service.default_config()
    config = replace(
        config,
        python=Path(args.python).expanduser(),
        workdir=Path(args.workdir).expanduser().resolve(),
        willow_home=Path(args.willow_home).expanduser().resolve(),
        store_root=Path(args.store_root).expanduser().resolve(),
        pg_db=args.pg_db,
        pg_user=args.pg_user,
        app_id=args.app_id,
        heartbeat_root=Path(args.heartbeat_root).expanduser().resolve(),
    )
    try:
        if args.action == "install":
            result = worker_service.install_services(config)
        elif args.action == "status":
            result = worker_service.service_status()
        else:
            result = worker_service.uninstall_services()
    except (OSError, RuntimeError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2))


def _cmd_frank_anchor(args) -> None:
    """Show or write the FRANK governance chain's externally-held head anchor (#280).

    CLI/operator-only, mirrors agent_registry.py's sudo invariant: no MCP tool
    writes this file, because the whole point is a value the same actor who
    can write frank_ledger rows cannot also quietly update. `write` refuses a
    chain that is not even internally consistent (that is a different, worse
    problem than "unanchored" and re-anchoring over it would hide it) and
    requires an interactive operator terminal, same boundary as `roster sync`
    and `sign-net-task` — a Kart task must not be able to mint its own anchor.
    """
    from . import frank_head_anchor

    if args.action == "show":
        print(json.dumps(frank_head_anchor.read_anchor(), indent=2, default=str))
        return
    if os.environ.get("WILLOW_IN_KART", "").strip() or not sys.stdin.isatty():
        print(
            "Error: frank-anchor write requires an interactive operator terminal; "
            "it cannot run from an MCP tool or queued task.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    pg = get_pg()
    if not pg:
        print("Error: Postgres unavailable", file=sys.stderr)
        raise SystemExit(1)
    try:
        from .governance_ledger import GovernanceLedger

        report = GovernanceLedger(pg).verify()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if not report.get("valid"):
        print(
            "Error: chain is not internally consistent (broken_at="
            f"{report.get('broken_at')!r}) -- refusing to anchor a broken chain. "
            "Investigate before re-anchoring.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    path = frank_head_anchor.write_anchor(
        report["head"], report["count"],
        anchored_by=args.by or os.environ.get("USER", "operator"),
    )
    print(json.dumps(
        {"anchored": True, "head": report["head"], "count": report["count"],
         "path": str(path)},
        indent=2,
    ))


def _cmd_roster(args) -> None:
    from . import fleet_roster

    pg = get_pg()
    if not pg:
        print("Error: Postgres unavailable", file=sys.stderr)
        raise SystemExit(1)
    if args.action == "sync" and (
        os.environ.get("WILLOW_IN_KART", "").strip() or not sys.stdin.isatty()
    ):
        print("Error: roster sync requires an interactive operator terminal", file=sys.stderr)
        raise SystemExit(1)
    try:
        result = (
            fleet_roster.sync(pg)
            if args.action == "sync"
            else fleet_roster.status(pg)
        )
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2, default=str))
def _cmd_sign_net_task(args) -> None:
    """Create a one-use task envelope from an operator's interactive terminal."""
    import secrets

    from . import egress_authorization, egress_setup, lease

    if os.environ.get("WILLOW_IN_KART", "").strip() or not sys.stdin.isatty():
        print(
            "Error: sign-net-task requires an interactive operator terminal "
            "outside Kart; it cannot run from an MCP tool or queued task.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    key_path = Path(args.key).expanduser() if args.key else egress_setup.resolve_private_key_path()
    if key_path is None:
        print(
            "Error: no egress signing key found. Run `willow-mcp setup-egress` once, "
            "or pass --key / set WILLOW_MCP_EGRESS_SIGNING_KEY.\n"
            "The private key is never read by the MCP server or worker.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        egress_setup.validate_key_path(key_path)
        raw_task = (
            Path(args.task_file).read_text(encoding="utf-8")
            if args.task_file
            else args.task
        )
        canonical_task = egress_authorization.canonical_network_task(
            raw_task, localhost=args.localhost
        )
        task_id = "".join(
            secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(8)
        )
        envelope = egress_authorization.sign_envelope(
            private_key_path=key_path,
            submitted_by=args.app_id,
            task_id=task_id,
            agent=args.agent,
            task=canonical_task,
            ttl_seconds=lease.parse_ttl(args.ttl),
            nonce=secrets.token_urlsafe(24),
        )
    except (OSError, ValueError, PermissionError) as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(envelope)


def _cmd_sign_db_task(args) -> None:
    """Sign one exact `# allow_db` task (B2), from an operator's interactive
    terminal. Same machinery and key as sign-net-task, bound to the db scope."""
    import secrets

    from . import egress_authorization, egress_setup, lease

    if os.environ.get("WILLOW_IN_KART", "").strip() or not sys.stdin.isatty():
        print(
            "Error: sign-db-task requires an interactive operator terminal "
            "outside Kart; it cannot run from an MCP tool or queued task.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    key_path = Path(args.key).expanduser() if args.key else egress_setup.resolve_private_key_path()
    if key_path is None:
        print(
            "Error: no egress signing key found. Run `willow-mcp setup-egress` once, "
            "or pass --key / set WILLOW_MCP_EGRESS_SIGNING_KEY.\n"
            "The private key is never read by the MCP server or worker.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        egress_setup.validate_key_path(key_path)
        raw_task = (
            Path(args.task_file).read_text(encoding="utf-8")
            if args.task_file
            else args.task
        )
        canonical_task = egress_authorization.canonical_db_task(raw_task)
        task_id = "".join(
            secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(8)
        )
        envelope = egress_authorization.sign_envelope(
            private_key_path=key_path,
            submitted_by=args.app_id,
            task_id=task_id,
            agent=args.agent,
            task=canonical_task,
            ttl_seconds=lease.parse_ttl(args.ttl),
            nonce=secrets.token_urlsafe(24),
            scope=egress_authorization.DB_SCOPE,
        )
    except (OSError, ValueError, PermissionError) as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(envelope)


def _cmd_sign_manifest(args) -> None:
    """`willow-mcp sign-manifest <app_id>` — detach-sign a manifest with the
    operator's PGP key (#183, docs/design/pgp-and-persona.md). Operator-terminal
    only: gpg-agent is unreachable inside the Kart bwrap sandbox (same lesson
    as sign-net-task/sign-db-task). No effect unless WILLOW_PGP_FINGERPRINT is
    set — signing an unenforced manifest is harmless but pointless, and a
    clear error here is better than a signature nobody will ever check."""
    from . import gate, pgp

    if os.environ.get("WILLOW_IN_KART", "").strip() or not sys.stdin.isatty():
        print(
            "Error: sign-manifest requires an interactive operator terminal "
            "outside Kart; it cannot run from an MCP tool or queued task.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not pgp.pgp_enabled():
        print(
            "Error: WILLOW_PGP_FINGERPRINT is not set. Manifest signing is an "
            "opt-in hardening layer (#183) -- set it to your operator key's "
            "fingerprint before signing; see docs/design/pgp-and-persona.md.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        app_id = gate._validate_app_id(args.app_id)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    manifest_path = gate._apps_root() / app_id / "manifest.json"
    if not manifest_path.is_file():
        print(f"Error: no manifest at {manifest_path}", file=sys.stderr)
        raise SystemExit(1)
    ok, detail = pgp.sign_detached(manifest_path)
    if not ok:
        print(f"Error: {detail}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Signed: {detail}")
    print(
        "Re-run this after any manifest edit -- gate._load_manifest denies a "
        "manifest whose signature no longer matches its content."
    )


def _cmd_attest_session(args) -> None:
    """`willow-mcp attest-session <session_id>` — detach-sign the human
    orchestrator's stable session identity (#186 P2 / #313,
    docs/design/pgp-and-persona.md). Operator-terminal only, same Kart/tty
    guard as sign-manifest/sign-seed. Requires session_enter(app_id='willow',
    session_id=...) to already have run for this session_id, as proof the
    session is live -- but what gets signed is a canonical
    {app_id, session_id} identity tuple written to a dedicated
    `<session>.attest.json` sidecar (paths.session_attestation_path), NOT the
    live `sessions/willow-<id>.json` record itself.

    #313: the session record carries mutable operational state (status,
    dispatch_id, updated_at) that the server rewrites on every session_bind
    call -- session_enter, dispatch_accept, session_handoff_write, agent_clear
    all pass through it. Signing that file directly meant the very next
    ordinary write self-invalidated the signature, disarming the orchestrator
    seat until a human could re-attest -- including from inside the closeout
    (session_handoff_write) that write triggers. The identity tuple this signs
    instead does not change across the session's lifetime, so normal session
    writes no longer invalidate the attestation.

    human_session.orchestrator_write_denial verifies this sidecar's signature
    before dispatch_send/verify_handoff/agent_clear/frank_append/envelope_apply
    run as app_id=willow, whenever WILLOW_PGP_FINGERPRINT is set."""
    from . import keyring as _keyring
    from . import pgp

    # PR3 deprecation notice: when the keyring is on, attest-session's
    # server-side pinentry burden is no longer the recommended path. Point
    # the operator at sign-session (client-side signing off the server
    # process) but continue with the PGP flow for backward compat — a
    # deployment migrating away from PGP might have both configured during
    # cutover, and refusing here would break their existing scripts.
    if _keyring.enabled():
        print(
            "Note: WILLOW_KEYRING is set. `willow-mcp attest-session` is the "
            "legacy PGP-fingerprint path; the recommended flow under the "
            "keyring is `willow-mcp sign-session <session_id> --verifier "
            "NAME`, which signs client-side so no signing key reaches this "
            "process. This command still writes a v1 sidecar for backward "
            "compatibility.",
            file=sys.stderr,
        )

    if os.environ.get("WILLOW_IN_KART", "").strip() or not sys.stdin.isatty():
        print(
            "Error: attest-session requires an interactive operator terminal "
            "outside Kart; it cannot run from an MCP tool or queued task.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not pgp.pgp_enabled():
        print(
            "Error: WILLOW_PGP_FINGERPRINT is not set. Session attestation is "
            "an opt-in hardening layer (#186) -- set it to your operator key's "
            "fingerprint before attesting; see docs/design/pgp-and-persona.md.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    session_id = (args.session_id or "").strip()
    if not session_id:
        print("Error: session_id is required", file=sys.stderr)
        raise SystemExit(1)
    session_file = paths.session_path("willow", session_id)
    if not session_file.is_file():
        print(
            f"Error: no session file at {session_file} -- run "
            "session_enter(app_id='willow', session_id=...) first.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    attest_file = paths.session_attestation_path("willow", session_id)
    attest_file.parent.mkdir(parents=True, exist_ok=True)
    # Preserve prior sidecar+sig so a failed re-attest cannot leave an
    # unsigned (or half-replaced) identity record on disk.
    previous_attest = (
        attest_file.read_text(encoding="utf-8") if attest_file.is_file() else None
    )
    previous_sig = pgp.read_detached_sig_bytes(attest_file)
    attest_data = {
        "format": "orchestrator_session_attestation_v1",
        "app_id": "willow",
        "session_id": session_id,
        "attested_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    attest_file.write_text(
        json.dumps(attest_data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    ok, detail = pgp.sign_detached(attest_file)
    if not ok:
        pgp.restore_signed_content(attest_file, previous_attest, previous_sig)
        print(f"Error: {detail}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Attested: {detail}")
    print(
        "This signs the stable {app_id, session_id} identity, not the session's "
        "mutable state -- ordinary session writes (session_handoff_write, "
        "dispatch_accept, agent_clear, ...) will not invalidate it. Re-run this "
        "only if you want to re-attest (e.g. after rotating your operator key). "
        "Upgrade note (#313): old sessions/willow-<id>.json.sig files are ignored; "
        "run attest-session once per live orchestrator session after deploying."
    )


def _cmd_setup_egress(args) -> None:
    """`willow-mcp setup-egress` — one-time Ed25519 keypair bootstrap (local CLI only)."""
    from . import egress_setup

    try:
        if args.private_key and args.public_key:
            result = egress_setup.ensure_keypair(
                force=args.force,
                private_key=Path(args.private_key),
                public_key=Path(args.public_key),
            )
        elif args.private_key or args.public_key:
            print("Error: pass both --private-key and --public-key to register existing keys.",
                  file=sys.stderr)
            raise SystemExit(1)
        else:
            result = egress_setup.ensure_keypair(force=args.force)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)

    print(json.dumps(result, indent=2))
    env = egress_setup.mcp_env_snippet()
    if env:
        print("\nAdd to willow-mcp MCP env, then reload the IDE:")
        print(json.dumps(env, indent=2))
    if args.write_mcp_json:
        path = Path(args.write_mcp_json).expanduser()
        if egress_setup.merge_mcp_env(path, env):
            print(f"\nMerged public key env into {path}")
        else:
            print(f"\nCould not merge into {path} — paste the env block above manually.",
                  file=sys.stderr)
    elif args.project_root:
        for path in egress_setup.project_mcp_json_paths(Path(args.project_root)):
            if egress_setup.merge_mcp_env(path, env):
                print(f"\nMerged public key env into {path}")


def _cmd_onboard(args) -> None:
    """`willow-mcp onboard` — first-run operator setup (local CLI only)."""
    from . import consent, consent_admin, egress_setup
    from .home_init import ensure_home_layout

    if os.environ.get("WILLOW_IN_KART", "").strip():
        print("Error: onboard cannot run inside Kart.", file=sys.stderr)
        raise SystemExit(1)

    home_result = ensure_home_layout()
    try:
        egress = egress_setup.ensure_keypair()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)

    env = egress_setup.mcp_env_snippet()
    merged: list[str] = []
    if args.project_root:
        for path in egress_setup.project_mcp_json_paths(Path(args.project_root)):
            if egress_setup.merge_mcp_env(path, env):
                merged.append(str(path))

    consent_result = None
    if args.enable_internet:
        if not sys.stdin.isatty():
            print("Error: --enable-internet requires an interactive terminal.", file=sys.stderr)
            raise SystemExit(1)
        try:
            consent_result = consent_admin.set_key("internet", True)
        except (OSError, PermissionError, ValueError) as e:
            print(f"Error: consent: {e}", file=sys.stderr)
            raise SystemExit(1)

    cli = shutil.which("wmc") or shutil.which("willow-mcp")
    if not cli:
        cli = str(Path(sys.executable).parent / "willow-mcp")

    print("Willow MCP operator onboard — complete.\n")
    print(json.dumps({"home": home_result.get("home"), "egress": egress, "consent": consent_result}, indent=2))
    print("\n── Next (copy/paste) ─────────────────────────────────────")
    print("1. Reload your IDE window (Cursor: Developer → Reload Window).")
    if merged:
        print(f"2. MCP public key wired into: {', '.join(merged)}")
    else:
        print("2. Re-run with --project-root <repo> to auto-wire .cursor/mcp.json")
    print("3. Sync IDE wiring: willow-mcp project sync willow")
    print(f"4. Network task: {cli} run-net {args.app_id} --task-file /path/to/script.sh --ttl 30m")
    print(f"5. Drain queue:  {cli} worker --lane fast --once")
    if consent.read_consent().get("internet") is not True:
        print(f"6. Enable egress: {cli} consent set internet true")


def _cmd_doctor(args) -> None:
    """`willow-mcp doctor` — human-readable install health + copy/paste fixes."""
    app_id = args.app_id or os.environ.get("WILLOW_APP_ID", "willow")
    from . import egress_setup
    from . import trust_root_setup

    summary = diagnostic_summary(app_id)
    print(f"verdict: {summary.get('verdict', 'unknown')}\n")
    for problem in summary.get("problems") or []:
        print(f"[{problem.get('severity', '?')}] {problem.get('check')}: {problem.get('detail')}")
        if problem.get("fix"):
            print(f"  fix: {problem['fix']}")
        print()

    pub = egress_setup.resolve_public_key_path()
    if pub is None:
        cli = shutil.which("wmc") or shutil.which("willow-mcp") or "willow-mcp"
        print("[warn] egress_keys: no verification key configured")
        print(f"  fix: {cli} setup-egress")
        if args.project_root:
            print(f"       {cli} onboard --project-root {args.project_root} --enable-internet")
        print()
    else:
        print(f"egress public key: {pub}\n")

    lease = (summary.get("checks") or {}).get("net_lease", {}).get("lease", {})
    if lease.get("status") != "active":
        cli = shutil.which("wmc") or shutil.which("willow-mcp") or "willow-mcp"
        print(f"net lease: {lease.get('status', 'absent')} — run: {cli} grant-net {app_id} --ttl 30m\n")

    audit = trust_root_setup.audit_trust_root(app_id)
    store_audit = audit.get("store") or {}
    if store_audit.get("writable") is False:
        cli = shutil.which("wmc") or shutil.which("willow-mcp") or "willow-mcp"
        print("[error] store: SOIL store is not writable by this process")
        if store_audit.get("error"):
            print(f"  detail: {store_audit['error']}")
        print(f"  fix: {cli} repair-runtime-perms")
        print()
    if audit.get("forgeable") and not audit.get("hardened"):
        cli = shutil.which("wmc") or shutil.which("willow-mcp") or "willow-mcp"
        print("[warn] trust_root: this process can forge egress authority keys")
        for item in audit["forgeable"]:
            print(f"  {item.get('key')}: {item.get('path')}")
        hint = f"{cli} harden-trust-root"
        if args.project_root:
            hint += f" --project-root {args.project_root}"
        print(f"  fix: {hint}")
        print()
    if audit.get("secret_file_exposure"):
        cli = shutil.which("wmc") or shutil.which("willow-mcp") or "willow-mcp"
        print("[warn] secret_files: group/world-readable secret file(s) (#181 audit)")
        for item in audit["secret_file_exposure"]:
            print(f"  {item.get('key')}: {item.get('path')} (mode {item.get('mode')})")
        print(f"  fix: {cli} repair-runtime-perms")
        print()
    if audit.get("store_db_exposure"):
        cli = shutil.which("wmc") or shutil.which("willow-mcp") or "willow-mcp"
        print("[warn] store_db: group/world-readable store .db file(s) (#232)")
        for item in audit["store_db_exposure"]:
            print(f"  {item.get('key')}: {item.get('path')} (mode {item.get('mode')})")
        print("  the client-side hook (pre_tool_use.py) is not an OS control --")
        print(f"  fix: {cli} repair-runtime-perms")
        print()

    # #231: plain-ownership identity, next to the access-bit checks above.
    # Informational only — never changes the verdict (see _diag_uid_separation).
    uid_sep = audit.get("uid_separation") or {}
    me = uid_sep.get("process") or {}
    if uid_sep.get("separated"):
        print(f"uid separation: OK — trust root is owned by a different account "
              f"than this process ({me.get('user')}, uid {me.get('uid')})\n")
    else:
        print(f"uid separation: NOT separated — this process runs as "
              f"{me.get('user')} (uid {me.get('uid')}), the same account that owns "
              f"the trust root (or nothing has been hardened yet)")
        print("  see docs/deploy/dedicated-uid-deployment.md for the full runbook\n")


def _cmd_run_net(args) -> None:
    """`willow-mcp run-net` — operator one-shot: lease (if needed) + sign + queue."""
    import secrets

    from . import egress_authorization, egress_setup, lease

    if os.environ.get("WILLOW_IN_KART", "").strip() or not sys.stdin.isatty():
        print(
            "Error: run-net requires an interactive operator terminal outside Kart.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    key_path = egress_setup.resolve_private_key_path()
    if key_path is None:
        print(
            "Error: no egress signing key — run `willow-mcp setup-egress` first.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if egress_setup.resolve_public_key_path() is None:
        print(
            "Error: no egress public key — run `willow-mcp setup-egress` and reload MCP.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        egress_setup.validate_key_path(key_path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)

    if not args.skip_grant:
        lease_state = lease.read_lease(args.app_id)
        if lease_state["status"] != "active":
            try:
                lease.grant(
                    args.app_id,
                    lease.parse_ttl(args.ttl),
                    issuer=args.issuer or os.environ.get("USER", "operator"),
                    reason=args.reason or "run-net",
                )
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                raise SystemExit(1)

    try:
        raw_task = (
            Path(args.task_file).read_text(encoding="utf-8")
            if args.task_file
            else args.task
        )
        canonical_task = egress_authorization.canonical_network_task(
            raw_task, localhost=args.localhost
        )
        task_id = "".join(
            secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(8)
        )
        envelope = egress_authorization.sign_envelope(
            private_key_path=key_path,
            submitted_by=args.app_id,
            task_id=task_id,
            agent=args.agent,
            task=canonical_task,
            ttl_seconds=lease.parse_ttl(args.ttl),
            nonce=secrets.token_urlsafe(24),
        )
    except (OSError, ValueError, PermissionError) as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)

    submit_task = "\n".join(
        line
        for line in egress_authorization.normalize_task(raw_task).splitlines()
        if line.strip() not in {"# allow_net", "# allow_localhost", "# allow_db"}
    )
    result = task_submit(
        args.app_id,
        submit_task,
        agent=args.agent,
        lane=args.lane,
        allow_net=not args.localhost,
        allow_localhost=args.localhost,
        network_authorization=envelope,
    )
    print(json.dumps(result, indent=2))
    if result.get("status") == "pending":
        print(
            f"\nQueued {result.get('task_id')}. Drain with:\n"
            f"  willow-mcp worker --lane {args.lane} --once",
            file=sys.stderr,
        )


def _cmd_register_agent(args) -> None:
    """`willow-mcp register-agent` — operator-only. Interactive/local by design,
    exactly like grant-net/confirm-binding: no MCP tool can reach this, so an
    agent can request standing and never mint it (the sudo invariant)."""
    from . import agent_registry
    secret = None
    if args.secret_file:
        try:
            secret = Path(args.secret_file).expanduser().read_bytes()
        except OSError as e:
            print(f"Error: cannot read --secret-file: {e}", file=sys.stderr)
            raise SystemExit(1)
    try:
        out = agent_registry.register_agent(args.agent_id, args.max_trust, secret=secret)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Registered agent_id={out['agent_id']!r} at trust ceiling {out['max_trust']}.")
    print("Install this secret into the agent's client-side signer (shown once):")
    print(f"  {out['secret_hex']}")


def _cmd_list_agents(args) -> None:
    from . import agent_registry
    print(json.dumps(agent_registry.list_agents(), indent=2, sort_keys=True))


def _cmd_revoke_agent(args) -> None:
    from . import agent_registry
    had = agent_registry.revoke(args.agent_id)
    print(f"Agent {args.agent_id!r} {'revoked' if had else 'was not registered'}.")


def _cmd_rotate_agent(args) -> None:
    """`willow-mcp rotate-agent` — mint a NEW secret for an already-registered
    agent, keeping its trust ceiling (D2). Rotation is hard by default: sessions
    signed with the old secret fail their next verify and must re-check-in — the
    correct compromise-response. Operator/CLI-only, like register-agent."""
    from . import agent_registry
    ceiling = agent_registry.list_agents().get(args.agent_id)
    if ceiling is None:
        print(f"Error: {args.agent_id!r} is not registered — use register-agent first.",
              file=sys.stderr)
        raise SystemExit(1)
    out = agent_registry.register_agent(args.agent_id, ceiling)   # fresh secret, same ceiling
    print(f"Rotated secret for agent_id={out['agent_id']!r} (trust ceiling {out['max_trust']}).")
    print("Install the NEW secret into the agent's client-side signer (shown once); "
          "the old secret is now dead:")
    print(f"  {out['secret_hex']}")


def _cmd_repair_runtime_perms(args) -> None:
    """`willow-mcp repair-runtime-perms` — restore MCP write paths (store, dispatch, …)."""
    from . import trust_root_setup
    from .human_session import require_operator_terminal

    if not args.dry_run:
        require_operator_terminal()
    try:
        result = trust_root_setup.repair_runtime_permissions(
            args.runtime_user,
            dry_run=args.dry_run,
        )
    except (ValueError, PermissionError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2))
    if not args.dry_run and result.get("runtime_user"):
        print(f"\nRuntime paths restored for {result['runtime_user']!r}. Reload the IDE if MCP was broken.")


def _cmd_harden_trust_root(args) -> None:
    """`willow-mcp harden-trust-root` — chown trust roots; wire strict mode (B-32)."""
    from . import trust_root_setup
    from .human_session import require_operator_terminal

    if not args.dry_run:
        require_operator_terminal()
    project = Path(args.project_root).expanduser() if args.project_root else None
    try:
        result = trust_root_setup.harden_trust_root(
            owner=args.owner,
            runtime_user=args.runtime_user,
            project_root=project,
            dry_run=args.dry_run,
            repair_runtime=not args.skip_runtime_repair,
        )
    except (ValueError, PermissionError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2))
    if not args.dry_run:
        print("\n── Operator commands (confirm authority) ─────────────────")
        for line in result.get("operator_commands") or []:
            print(f"  {line}")
        # #231: confirm the ownership actually moved, not just that the chown
        # commands ran without error — a `sudo -u <owner>` that silently fell
        # back to the caller's own uid would still print a clean action log.
        after = (result.get("after") or {}).get("uid_separation") or {}
        me = after.get("process") or {}
        if after.get("separated"):
            print(f"\nuid separation: confirmed — trust root now owned by a different "
                  f"account than this process ({me.get('user')}, uid {me.get('uid')}).")
        else:
            print(f"\nuid separation: NOT yet achieved — this process (still {me.get('user')}, "
                  f"uid {me.get('uid')}) owns the trust root it just hardened. Hardening only moves "
                  f"the files; a genuinely separate runtime uid must actually run the MCP server "
                  f"(or invoke this CLI) for separation to be real — see "
                  f"docs/deploy/dedicated-uid-deployment.md.")


def _cmd_grant_net(args) -> None:
    """`willow-mcp grant-net` — issue a time-boxed egress lease (B-32).

    Local/stdio-only by design, exactly like `confirm-binding`: no MCP tool can
    reach this, so an agent can request egress and never grant it to itself. The
    lease expires on its own; the ceiling is 3h (FRANK `cc553729`).
    """
    from . import lease

    try:
        ttl = lease.parse_ttl(args.ttl)
        record = lease.grant(args.app_id, ttl, issuer=args.issuer, reason=args.reason or "")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Egress lease issued to app_id={record['app_id']!r} by {record['issuer']!r}\n"
          f"  expires: {record['expires_at']} (ttl {record['ttl_seconds']}s)\n"
          f"  reason:  {record['reason'] or '(none given)'}")
    forgeable = lease.self_writable_trust_paths(args.app_id)
    if forgeable and not lease.strict_trust_root():
        print("\n  NOTE: this host has no uid separation — the agent's own process can write\n"
              "  " + ", ".join(f["path"] for f in forgeable) + "\n"
              "  so this lease constrains time and leaves a record, but does not prevent a\n"
              "  self-grant. Run: willow-mcp harden-trust-root (B-32).", file=sys.stderr)
    elif forgeable and lease.strict_trust_root():
        from . import trust_root_setup

        owner = trust_root_setup.default_trust_owner()
        print(f"\n  NOTE: strict trust root is on but this process can still write trust paths.\n"
              f"  Re-run harden-trust-root or use: sudo -u {owner} willow-mcp grant-net …",
              file=sys.stderr)


def _cmd_revoke_net(args) -> None:
    """`willow-mcp revoke-net` — end an egress lease before it expires."""
    from . import lease

    try:
        had = lease.revoke(args.app_id)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Egress lease for {args.app_id!r} {'revoked' if had else 'was not present'}.")


def _cmd_net_status(args) -> None:
    """`willow-mcp net-status` — what egress is currently authorized, and by whom."""
    from . import lease

    leases = [lease.read_lease(args.app_id)] if args.app_id else lease.list_leases()
    if not leases:
        print("No egress leases on disk. allow_net is denied for every app.")
    for st in leases:
        line = f"{st['app_id']:<24} {st['status']}"
        if st["status"] == "active":
            line += f"  expires in {st['remaining_seconds']}s (issuer: {st.get('issuer')})"
        elif st.get("error"):
            line += f"  — {st['error']}"
        print(line)
    forgeable = lease.self_writable_trust_paths(args.app_id or "")
    print(f"\nstrict_trust_root: {lease.strict_trust_root()}")
    if forgeable:
        print("self-writable trust paths (keys this process could forge):")
        for f in forgeable:
            print(f"  {f['key']}: {f['path']}")


def _cmd_dev_net(args) -> None:
    """`willow-mcp dev-net` — local/dev convenience: one command for the three
    legitimate open-web egress grants (#287).

    **Not a new bypass path.** It calls exactly the same operator-only admin
    functions `allow-permission`, `consent set`, and `grant-net` already call —
    `manifest_admin.set_permission`, `consent_admin.set_key`, `lease.grant` —
    so there is no extra code path to audit and nothing it grants that those
    three commands, run in sequence, would not also grant. Like them it is
    local-CLI-only and unreachable from any MCP tool; the PreToolUse self-grant
    guard blocks an agent from invoking it via Bash exactly as it blocks
    `grant-net` (the sudo invariant, FRANK 90e52ab7). The point is removing
    friction from the *sequence*, not from any individual gate.

    Consent mutation still requires an interactive operator terminal —
    `consent_admin.set_key` enforces that itself — but only when consent is
    not already granted, so a repeat run with consent already on needs no TTY.
    Refuses outright when `WILLOW_MCP_STRICT_TRUST_ROOT` is on (a hardened
    posture this local/dev shortcut is not meant for) unless `--force`.
    """
    from . import consent, consent_admin, gate, lease, manifest_admin, web_egress

    if os.environ.get("WILLOW_IN_KART", "").strip():
        print("Error: dev-net cannot run inside Kart.", file=sys.stderr)
        raise SystemExit(1)

    if lease.strict_trust_root() and not args.force:
        print(
            "Error: WILLOW_MCP_STRICT_TRUST_ROOT is set — this host is in a hardened "
            "posture, and dev-net's one-command convenience is for local/dev use, not "
            "a hardened deployment. Grant the three keys individually with full review "
            "(allow-permission / consent set / grant-net), or pass --force to proceed "
            "anyway.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    try:
        app_id = gate._validate_app_id(args.app_id)
        ttl = lease.parse_ttl(args.ttl)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)

    # 1. manifest permission — same call `allow-permission` makes.
    try:
        manifest_admin.set_permission(app_id, gate.WEB_NET_PERMISSION, True)
    except (ValueError, RuntimeError) as e:
        print(f"Error: manifest permission: {e}", file=sys.stderr)
        raise SystemExit(1)

    # 2. operator consent — same call `consent set internet true` makes.
    # Skipped (and so TTY-free) when consent is already granted.
    if not consent.internet_permitted():
        try:
            consent_admin.set_key("internet", True)
        except (OSError, PermissionError, ValueError) as e:
            print(f"Error: consent: {e}", file=sys.stderr)
            raise SystemExit(1)

    # 3. egress lease — same call `grant-net` makes.
    try:
        record = lease.grant(app_id, ttl, issuer=args.issuer, reason=args.reason or "dev-net")
    except ValueError as e:
        print(f"Error: lease: {e}", file=sys.stderr)
        raise SystemExit(1)

    status = web_egress.egress_status(app_id)
    print(f"dev-net: web egress granted for app_id={app_id!r}")
    print(f"  expires: {record['expires_at']} (ttl {record['ttl_seconds']}s)")
    print(f"  renew:   willow-mcp grant-net {app_id} --ttl {args.ttl} --reason \"...\"")
    if not status["egress_permitted"]:
        print(
            "\nNOTE: not every key reads as granted yet — see below "
            "(egress_status, all four keys):",
            file=sys.stderr,
        )
    print(json.dumps(status, indent=2))


def _cmd_grant_build(args) -> None:
    """`willow-mcp grant-build` — issue a time-boxed build lease for an
    earn-first tool.

    Local/stdio-only by design, exactly like `grant-net`: no MCP tool can
    reach this, so an agent can request a build and never authorize it to
    itself. The lease expires on its own; the ceiling is 3h (FRANK
    `cc553729`, the same ceiling `grant-net` uses).

    The reason field is what makes this a real gate. The rule the seal opens
    is 'the user asks AND agrees to what the ask opens' — `--reason` is
    where that agreement is written on the record.
    """
    from . import build_lease

    try:
        ttl = build_lease.parse_ttl(args.ttl)
        record = build_lease.grant(
            args.tool, ttl, issuer=args.issuer, reason=args.reason or "",
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(
        f"Build lease issued for tool={record['tool']!r} by {record['issuer']!r}\n"
        f"  expires: {record['expires_at']} (ttl {record['ttl_seconds']}s)\n"
        f"  reason:  {record['reason'] or '(none given)'}"
    )
    if not record["reason"]:
        print(
            "\n  NOTE: no --reason was given. The rule this lease opens is that "
            "the operator asks AND agrees to what the ask opens; the reason is "
            "where that agreement lives on the record. Re-grant with --reason "
            "when convenient.",
            file=sys.stderr,
        )


def _cmd_revoke_build(args) -> None:
    """`willow-mcp revoke-build` — end a build lease before it expires."""
    from . import build_lease

    try:
        had = build_lease.revoke(args.tool)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    print(
        f"Build lease for tool={args.tool!r} "
        f"{'revoked' if had else 'was not present'}."
    )


def _cmd_build_status(args) -> None:
    """`willow-mcp build-status` — what earn-first builds are currently
    authorized, and by whom. `--json` matches the read-only status
    convention `net-status` / `earn-check` / `gates --json` already use."""
    from . import build_lease

    leases = (
        [build_lease.read_lease(args.tool)] if args.tool
        else build_lease.list_leases()
    )
    if args.json:
        print(json.dumps({"leases": leases}, indent=2))
        return
    if not leases:
        print(
            "No build leases on disk. Every earn-first tool is dry — "
            "an operator ask (`willow-mcp grant-build <tool> --ttl 30m "
            "--reason ...`) is what earns any of them."
        )
        return
    for st in leases:
        line = f"{st['tool']:<28} {st['status']}"
        if st["status"] == "active":
            line += (
                f"  expires in {st['remaining_seconds']}s "
                f"(issuer: {st.get('issuer')})"
            )
        elif st.get("error"):
            line += f"  — {st['error']}"
        print(line)


def _cmd_earn_check(args) -> None:
    """`willow-mcp earn-check` — cross-reference the earn-first roster with
    build leases on disk.

    Emits `{ready, waiting, dry}` per row. `ready` = an active lease exists.
    `waiting` = a lease existed and expired (needs a fresh ask). `dry` = no
    lease has ever been issued for this family.

    Reads only; issues nothing. The whole point is to make the case-by-case
    re-litigation of 'should we build X now?' a lookup instead of an
    argument — either the operator asked (there is a lease) or they haven't
    (there is not).
    """
    from . import build_lease

    on_disk = {row["tool"]: row for row in build_lease.list_leases()}
    rows: list[dict] = []
    for family, blurb in build_lease.EARN_FIRST_ROSTER:
        lease_row = on_disk.get(family)
        if lease_row is None:
            state = "dry"
            expires_at = None
            remaining_seconds = None
            issuer = None
        elif lease_row["status"] == "active":
            state = "ready"
            expires_at = lease_row["expires_at"]
            remaining_seconds = lease_row["remaining_seconds"]
            issuer = lease_row.get("issuer")
        else:
            state = "waiting"
            expires_at = lease_row["expires_at"]
            remaining_seconds = lease_row["remaining_seconds"]
            issuer = lease_row.get("issuer")
        rows.append({
            "family": family,
            "state": state,
            "expires_at": expires_at,
            "remaining_seconds": remaining_seconds,
            "issuer": issuer,
            "blurb": blurb,
        })

    # A build lease outside the roster is not itself a bug — the roster is
    # the canonical list of gated tools, but an operator may grant on a
    # freshly-named family before it lands in the doc. Surface it so nothing
    # is invisible.
    extras = sorted(set(on_disk) - {fam for fam, _ in build_lease.EARN_FIRST_ROSTER})

    if args.json:
        print(json.dumps({"roster": rows, "extras": [
            {"family": t, **on_disk[t]} for t in extras
        ]}, indent=2))
        return

    tally = {"ready": 0, "waiting": 0, "dry": 0}
    for r in rows:
        tally[r["state"]] += 1
    print(
        f"earn-first roster: {len(rows)} families "
        f"— ready:{tally['ready']}  waiting:{tally['waiting']}  dry:{tally['dry']}"
    )
    print()
    for r in rows:
        marker = {"ready": "●", "waiting": "◐", "dry": "○"}[r["state"]]
        head = f"  {marker} {r['family']:<22} {r['state']}"
        if r["state"] == "ready":
            head += f"  (expires in {r['remaining_seconds']}s, by {r['issuer']})"
        elif r["state"] == "waiting":
            head += f"  (last lease expired at {r['expires_at']})"
        print(head)
        print(f"      {r['blurb']}")
    if extras:
        print("\n  leases outside the roster (grant on a family not yet in docs):")
        for t in extras:
            row = on_disk[t]
            print(f"    - {t}  {row['status']}  (issuer: {row.get('issuer')})")


def _cmd_gates(args) -> None:
    """`willow-mcp gates` — every authorization gate as one on/off panel.

    Bare `willow-mcp gates` in a real terminal launches the interactive
    curses TUI (navigate, press enter/space to actually flip a gate) — the
    static text/JSON/HTML outputs below are for piping, scripting, and CI,
    where there is no terminal to be interactive in anyway.
    """
    if args.serve:
        from . import gates_serve
        gates_serve.run(host=args.host, port=args.port, app_id=args.app_id or "")
        return

    if not args.static and not args.json and not args.html and sys.stdout.isatty():
        from . import gates_tui
        gates_tui.run(args.app_id or "")
        return

    from . import gates_panel

    rows = gates_panel.collect(args.app_id or "")

    if args.json:
        print(json.dumps([r.__dict__ for r in rows], indent=2))
        return

    if not args.no_tui or not args.html:
        print(gates_panel.render_tui(rows))

    if args.html:
        html = gates_panel.render_html(rows, datetime.now(timezone.utc).isoformat())
        out = Path(args.html).expanduser()
        out.write_text(html, encoding="utf-8")
        print(f"\nwrote {out}")


def _cmd_tree(args) -> None:
    """`willow-mcp tree` — every tree part in one call, for a real dashboard."""
    from . import tree_view

    eff_app_id = args.app_id or _DEFAULT_APP_ID
    tree = tree_view.build_tree(eff_app_id)
    if args.json:
        print(json.dumps(tree, indent=2, default=str))
    else:
        print(tree_view.render_summary(tree))


def _cmd_set_permission(args, *, granted: bool) -> None:
    """`willow-mcp allow-permission` / `deny-permission` — flip one manifest
    permission for one app. Local/stdio-only, exactly like `grant-net`: no
    MCP tool can reach this, so an agent can never grant itself a permission
    it was just denied.
    """
    from . import manifest_admin

    try:
        manifest = manifest_admin.set_permission(args.app_id, args.permission, granted)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise SystemExit(1)
    verb = "granted to" if granted else "revoked from"
    print(f"Permission {args.permission!r} {verb} app_id={args.app_id!r}.")
    print(f"  permissions now: {manifest['permissions']}")


def main():
    """Entry point. Wraps `_main` so a downstream reader closing early
    (`willow-mcp gates | head`, `... | grep -q`) exits clean instead of an
    unhandled `BrokenPipeError` traceback — several of these subcommands
    (`gates`, `net-status`, `tree`) print multiple lines and are exactly the
    shape someone pipes into `head`/`grep`."""
    try:
        _main()
    except BrokenPipeError:
        # Standard recipe (see Python docs, "brokenpipeerror-example"): the
        # reader is gone, so redirect our still-open stdout to devnull before
        # exiting — otherwise Python's own shutdown flush re-raises trying to
        # write to the closed pipe and prints a second, spurious traceback.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)


def _cmd_federation(args) -> None:
    """`willow-mcp federation` — the operator half of federated MCP.

    `mcp_federation.ratify()` says of itself "**Operator-only — never call this
    from an MCP tool**", and it was right to: ratifying a downstream server is
    the act `federation_egress`'s ceiling check depends on, so it must be a host
    act. But no operator command reached it either, so the only supported way to
    ratify anything was to import the module by hand. An operator-only function
    with no operator path is not a locked door, it is a wall — and the empty
    registry it produced read as nobody having federated a server yet rather
    than as nobody being able to.

    Local/stdio-only, exactly like `grant-net` and `allow-permission`.
    """
    from . import gate, mcp_federation

    action = args.federation_action

    if action == "list":
        rows = mcp_federation.list_ratified()
        if args.json:
            print(json.dumps(rows, indent=2))
            return
        if not rows:
            print("No ratified downstream MCP servers.")
            print("  `willow-mcp federation discover` to see what exists on this host.")
            return
        for e in rows:
            print(f"{e.get('server_id') or e.get('id')}  {e.get('name')}")
            print(f"    command: {e.get('command')} {' '.join(e.get('args') or [])}")
            print(f"    env_keys: {list(e.get('env_keys') or []) or '() — receives no environment'}")
            print(f"    ratified: {e.get('ratified_by')} at {e.get('ratified_at')}")
            if e.get("reason"):
                print(f"    reason: {e['reason']}")
        return

    scan_root = Path(args.root) if getattr(args, "root", None) else Path(
        os.environ.get("WILLOW_MCP_FEDERATION_SCAN_ROOT", "") or Path.home()
    )

    if action == "discover":
        specs = mcp_federation.discover_all_specs(scan_root)
        ratified = {e.get("id") or e.get("server_id") for e in mcp_federation.list_ratified()}
        if args.json:
            print(json.dumps(
                [{**sp.to_dict(), "ratified": sp.id in ratified} for sp in specs], indent=2))
            return
        if not specs:
            print(f"No .mcp.json server entries found under {scan_root}.")
            return
        print(f"Discovered under {scan_root} ({len(specs)} entries):")
        for sp in specs:
            mark = "ratified" if sp.id in ratified else "NOT ratified"
            print(f"  {sp.id}  {sp.name}  [{mark}]")
            print(f"      {sp.command} {' '.join(sp.args)}")
            print(f"      from {sp.source_path}")
        return

    if action == "ratify":
        specs = {sp.id: sp for sp in mcp_federation.discover_all_specs(scan_root)}
        spec = specs.get(args.server_id)
        if spec is None:
            print(f"Error: no discovered server with id {args.server_id!r} under "
                  f"{scan_root}.", file=sys.stderr)
            print("Run `willow-mcp federation discover` to list ids. A server is "
                  "ratified from a spec that was actually read off disk, never "
                  "from arguments typed at this prompt — the id is a digest of "
                  "the launch identity, so a hand-typed one would ratify "
                  "something nobody verified exists.", file=sys.stderr)
            raise SystemExit(1)
        try:
            entry = mcp_federation.ratify(
                spec, ratified_by=args.by, reason=args.reason or "")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1)
        print(f"Ratified {entry['name']!r} (server_id={entry['id']}) by {entry['ratified_by']!r}.")
        print(f"  env_keys: {list(entry.get('env_keys') or []) or '() — receives no environment'}")
        print()
        print("Ratification makes the server connectable. It grants nothing:")
        print(f"  willow-mcp allow-permission <app_id> {gate.MCP_FEDERATION_PERMISSION}")
        print(f"  willow-mcp allow-permission <app_id> mcp:{entry['id']}:<tool>   (one per tool)")
        return

    if action == "revoke":
        if mcp_federation.revoke_ratification(args.server_id):
            print(f"Revoked ratification for {args.server_id!r}.")
            print("  Any `mcp:<server_id>:<tool>` grants naming it now deny at "
                  "every call; revoke them too if they are meant to stay gone.")
        else:
            print(f"No ratified server {args.server_id!r}.", file=sys.stderr)
            raise SystemExit(1)
        return


def _cmd_project(args) -> None:
    """`willow-mcp project` — sync/audit agent-agnostic IDE wiring from the registry."""
    from . import mcp_projects

    if args.project_action == "list":
        rows = mcp_projects.list_projects()
        print(json.dumps(rows, indent=2))
        return

    project_ids = [args.project_id] if args.project_id else None
    if args.project_action == "sync":
        written = mcp_projects.sync_all(project_ids=project_ids, dry_run=args.dry_run)
        print(json.dumps({"synced": written}, indent=2))
        return
    if args.project_action == "audit":
        issues = mcp_projects.audit_all(project_ids=project_ids)
        if issues:
            for issue in issues:
                print(issue, file=sys.stderr)
            raise SystemExit(1)
        print(json.dumps({"status": "ok", "projects": project_ids or "all"}, indent=2))
        return


def _main():
    import argparse
    parser = argparse.ArgumentParser(prog="willow-mcp")
    parser.add_argument("--serve", action="store_true", help="Run as HTTP server with OAuth")
    parser.add_argument("--port", type=int, default=_PORT)
    parser.add_argument("--host", default=_HOST)
    subparsers = parser.add_subparsers(dest="command")

    setup_p = subparsers.add_parser("setup", help="Write OAuth provider credentials to the vault")
    setup_p.add_argument("--google-client-id")
    setup_p.add_argument("--google-client-secret", help="Omit to be prompted (recommended)")
    setup_p.add_argument("--apple-team-id")
    setup_p.add_argument("--apple-client-id")
    setup_p.add_argument("--apple-key-id")
    setup_p.add_argument("--apple-p8-key-path", help="Path to the .p8 private key file; omit to paste via stdin")

    confirm_p = subparsers.add_parser(
        "confirm-binding",
        help="Bind a signed-in OAuth identity to an app_id (local, stdio-only — never an MCP tool)",
    )
    # The upstream provider, not an RFC 9207 issuer URL. `--issuer` stays as a
    # deprecated alias so operator muscle memory and scripts keep working.
    confirm_p.add_argument("--idp", "--issuer", dest="idp", required=True,
                           choices=["google", "apple"])
    confirm_p.add_argument("--subject", required=True, help="The IdP 'sub' claim for this identity")
    confirm_p.add_argument("--app-id", required=True, dest="app_id")

    worker_p = subparsers.add_parser(
        "worker",
        help="Run the Kart task worker (drains the queue; publishes a liveness heartbeat)",
    )
    worker_p.add_argument("--lane", default="fast", choices=["fast", "batch"])
    worker_p.add_argument("--slots", type=int, default=None)
    worker_p.add_argument("--interval", type=float, default=5.0)
    worker_p.add_argument("--once", action="store_true", help="drain the queue and exit")
    worker_p.add_argument(
        "--require-postgres",
        action="store_true",
        help="refuse the lane-agnostic SQLite fallback (set by managed units)",
    )
    worker_p.add_argument("--app-id", dest="app_id", default=os.environ.get("WILLOW_APP_ID", ""),
                          help="app_id whose confirmed 'tasks' mapping to use (default $WILLOW_APP_ID)")

    voice_p = subparsers.add_parser(
        "voice",
        help="Run the voice ingress daemon (mic → wake → VAD → whisper → SAFE gate → Kokoro)",
    )
    voice_p.add_argument(
        "--app-id", dest="app_id", default=os.environ.get("WILLOW_APP_ID", "willow"),
    )
    voice_p.add_argument(
        "--wake-model", dest="wake_model", action="append", default=[],
        help="openWakeWord model path (repeatable; or WILLOW_VOICE_WAKE_MODELS)",
    )
    voice_p.add_argument("--wake-threshold", type=float, default=0.6)
    voice_p.add_argument("--whisper-model", default="base")
    voice_p.add_argument("--handler", default="", help="dispatch handler as module:callable")
    voice_p.add_argument("--echo", action="store_true", help="smoke-test handler (no utterance echo)")
    voice_p.add_argument("--no-frank", action="store_true", help="disable FRANK transition mirror")
    voice_p.add_argument("--no-speak", action="store_true", help="disable Kokoro TTS output")
    voice_p.add_argument("--kokoro-url", default="")
    voice_p.add_argument("--kokoro-voice", default="")
    voice_p.add_argument("--mic-device", type=int, default=None)

    consent_p = subparsers.add_parser(
        "consent",
        help="Read or atomically reconcile operator consent (mutation is interactive CLI-only)",
    )
    consent_p.add_argument("action", choices=["status", "set", "reconcile"])
    consent_p.add_argument("key", nargs="?", default="")
    consent_p.add_argument("value", nargs="?", default="")

    roster_p = subparsers.add_parser(
        "roster", help="Inspect or operator-sync fleet.json into existing agents rows"
    )
    roster_p.add_argument("action", choices=["status", "sync"])

    from .subject_consent.core import SCOPES as _SUBJECT_SCOPES
    grant_consent_p = subparsers.add_parser(
        "grant-consent",
        help="Record a subject-consent GRANT for one subject + scope (operator "
             "terminal only — never an MCP tool)",
    )
    grant_consent_p.add_argument("subject_id")
    grant_consent_p.add_argument("scope", choices=list(_SUBJECT_SCOPES))
    grant_consent_p.add_argument("--by", required=True,
                                 help="the guardian/owner recording the grant (audited)")
    revoke_consent_p = subparsers.add_parser(
        "revoke-consent",
        help="Record a subject-consent REVOKE for one subject + scope (operator "
             "terminal only — never an MCP tool)",
    )
    revoke_consent_p.add_argument("subject_id")
    revoke_consent_p.add_argument("scope", choices=list(_SUBJECT_SCOPES))
    revoke_consent_p.add_argument("--by", required=True,
                                  help="the guardian/owner recording the revoke (audited)")
    consent_status_p = subparsers.add_parser(
        "consent-status",
        help="Read a subject's recorded consent scopes and disclosure chain (read-only)",
    )
    consent_status_p.add_argument("subject_id")

    regagent_p = subparsers.add_parser(
        "register-agent",
        help="Bind an agent identity to an HMAC secret + trust ceiling (operator-only; "
             "no MCP tool can mint a secret)",
    )
    regagent_p.add_argument("agent_id")
    regagent_p.add_argument("--max-trust", type=int, required=True, choices=[0, 1, 2, 3, 4])
    regagent_p.add_argument("--secret-file", default="",
                            help="read the 32+ byte secret from this file; omit to generate one")
    subparsers.add_parser(
        "list-agents", help="List registered agent ids and their trust ceilings (no secrets)")
    regagent_revoke_p = subparsers.add_parser(
        "revoke-agent", help="Remove an agent's secret + registry entry (operator-only)")
    regagent_revoke_p.add_argument("agent_id")
    regagent_rotate_p = subparsers.add_parser(
        "rotate-agent",
        help="Mint a new secret for a registered agent, keeping its ceiling (operator-only)")
    regagent_rotate_p.add_argument("agent_id")
    sweep_p = subparsers.add_parser(
        "repo-sweep",
        help="Read-only git hygiene report across every repo under a root")
    sweep_p.add_argument("--root", default=str(Path.home() / "github"))
    sweep_p.add_argument("--branch-limit", type=int, default=15,
                         help="local branch count above this is litter (default 15)")
    sweep_p.add_argument("--max-depth", type=int, default=2,
                         help="how deep to look for repos; 2 covers the org layout")
    sweep_p.add_argument("--emit-flags", action="store_true",
                         help="also raise one SOIL flag per repo with findings")
    sweep_p.add_argument("--collection", default=None,
                         help="SOIL collection for flags (default willow_flags)")
    sweep_p.add_argument("--json", action="store_true", dest="as_json")

    sweep_service_p = subparsers.add_parser(
        "repo-sweep-service",
        help="Install/status/uninstall the weekly repo-sweep timer without starting it")
    sweep_service_p.add_argument("action", choices=["install", "status", "uninstall"])
    sweep_service_p.add_argument("--root", default=None)
    sweep_service_p.add_argument("--oncalendar", default=None,
                                 help="systemd OnCalendar (default 'Mon *-*-* 04:00:00')")
    sweep_service_p.add_argument("--collection", default=None)

    worker_service_p = subparsers.add_parser(
        "worker-service",
        help="Install/status/uninstall standalone fast+batch user units without starting or stopping them",
    )
    worker_service_p.add_argument("action", choices=["install", "status", "uninstall"])
    _service_home = os.environ.get("WILLOW_HOME", str(Path.home() / ".willow"))
    worker_service_p.add_argument("--python", default=sys.executable)
    worker_service_p.add_argument("--workdir", default=str(Path.cwd()))
    worker_service_p.add_argument("--willow-home", default=_service_home)
    worker_service_p.add_argument(
        "--store-root", default=os.environ.get("WILLOW_STORE_ROOT", _service_home)
    )
    worker_service_p.add_argument(
        "--pg-db", default=os.environ.get("WILLOW_PG_DB", "willow")
    )
    worker_service_p.add_argument(
        "--pg-user",
        default=(
            os.environ.get("WILLOW_PG_USER")
            or os.environ.get("USER")
            or "willow"
        ),
        help="Postgres role the worker connects as (mirrors the server's WILLOW_PG_USER)",
    )
    worker_service_p.add_argument(
        "--app-id", default=os.environ.get("WILLOW_APP_ID", "willow-mcp")
    )
    worker_service_p.add_argument(
        "--heartbeat-root",
        default=os.environ.get(
            "WILLOW_WORKER_HEARTBEAT_ROOT",
            str(Path(_service_home) / "worker_heartbeat"),
        ),
    )

    voice_service_p = subparsers.add_parser(
        "voice-service",
        help="Install/status/uninstall the voice ingress systemd user unit",
    )
    voice_service_p.add_argument("action", choices=["install", "status", "uninstall"])
    voice_service_p.add_argument("--python", default=sys.executable)
    voice_service_p.add_argument("--workdir", default=str(Path.cwd()))
    voice_service_p.add_argument("--willow-home", default=_service_home)
    voice_service_p.add_argument(
        "--app-id", default=os.environ.get("WILLOW_APP_ID", "willow"),
    )
    voice_service_p.add_argument(
        "--wake-models", default=os.environ.get("WILLOW_VOICE_WAKE_MODELS", ""),
    )
    voice_service_p.add_argument(
        "--kokoro-url",
        default=os.environ.get("WILLOW_KOKORO_URL", "http://localhost:5000/v1/audio/speech"),
    )
    voice_service_p.add_argument(
        "--kokoro-voice", default=os.environ.get("WILLOW_KOKORO_VOICE", "am_michael"),
    )
    voice_service_p.add_argument(
        "--handler", default=os.environ.get("WILLOW_VOICE_HANDLER", ""),
    )

    sign_net_p = subparsers.add_parser(
        "sign-net-task",
        help="Sign one exact network task (interactive operator terminal only; never an MCP tool)",
    )
    sign_net_p.add_argument("app_id", help="submitted_by identity bound into the envelope")
    sign_net_p.add_argument(
        "--agent", default="kart", help="queue agent identity bound into the envelope"
    )
    sign_net_p.add_argument(
        "--localhost",
        action="store_true",
        help="authorize # allow_localhost instead of full # allow_net",
    )
    sign_net_input = sign_net_p.add_mutually_exclusive_group(required=True)
    sign_net_input.add_argument("--task", default="", help="exact task text to authorize")
    sign_net_input.add_argument(
        "--task-file", default="", help="UTF-8 file containing the exact task text"
    )
    sign_net_p.add_argument("--ttl", default="30m", help="envelope lifetime (ceiling 3h)")
    sign_net_p.add_argument(
        "--key",
        default="",
        help="operator Ed25519 private PEM (default: setup-egress manifest or $WILLOW_MCP_EGRESS_SIGNING_KEY)",
    )

    sign_db_p = subparsers.add_parser(
        "sign-db-task",
        help="Sign one exact allow_db task (interactive operator terminal only; never an MCP tool)",
    )
    sign_db_p.add_argument("app_id", help="submitted_by identity bound into the envelope")
    sign_db_p.add_argument(
        "--agent", default="kart", help="queue agent identity bound into the envelope"
    )
    sign_db_input = sign_db_p.add_mutually_exclusive_group(required=True)
    sign_db_input.add_argument("--task", default="", help="exact task text to authorize")
    sign_db_input.add_argument(
        "--task-file", default="", help="UTF-8 file containing the exact task text"
    )
    sign_db_p.add_argument("--ttl", default="30m", help="envelope lifetime (ceiling 3h)")
    sign_db_p.add_argument(
        "--key",
        default="",
        help="operator Ed25519 private PEM (default: setup-egress manifest or $WILLOW_MCP_EGRESS_SIGNING_KEY)",
    )

    sign_manifest_p = subparsers.add_parser(
        "sign-manifest",
        help="Detach-sign an app manifest with the operator's PGP key (#183; "
             "interactive operator terminal only; never an MCP tool)",
    )
    sign_manifest_p.add_argument("app_id", help="whose manifest to sign")

    attest_session_p = subparsers.add_parser(
        "attest-session",
        help="Detach-sign the human orchestrator's session file with the operator's "
             "PGP key (#186; interactive operator terminal only; never an MCP tool)",
    )
    attest_session_p.add_argument(
        "session_id", help="session_id passed to session_enter(app_id='willow', ...)"
    )

    # Per-verifier keyring (identity-in-session plan, PR1). Opt-in via
    # WILLOW_KEYRING. When unset, this subcommand still parses but reports
    # that the keyring is not configured. See src/willow_mcp/keyring.py and
    # src/willow_mcp/cli_keys.py for the primitive and the subcommand.
    from . import cli_keys as _cli_keys
    _cli_keys.register(subparsers)

    # PR3: client-side session signer. Replaces the server-side pinentry
    # burden of attest-session for keyring-enabled deployments. See
    # src/willow_mcp/sign_session_cli.py.
    from . import sign_session_cli as _sign_session_cli
    _sign_session_cli.register(subparsers)

    # PR5: envelope authoring — operator surface for
    # ratify/reject/list/pending. See src/willow_mcp/cli_envelope.py.
    from . import cli_envelope as _cli_envelope
    _cli_envelope.register(subparsers)

    frank_anchor_p = subparsers.add_parser(
        "frank-anchor",
        help="Show or write the FRANK governance chain's externally-held head "
             "anchor (#280; write requires an interactive operator terminal, "
             "never an MCP tool)",
    )
    frank_anchor_p.add_argument(
        "action", choices=["show", "write"], nargs="?", default="show",
        help="show: print the current anchor file (default). "
             "write: re-anchor to the chain's CURRENT head over Postgres.",
    )
    frank_anchor_p.add_argument(
        "--by", default="",
        help="operator identity recorded as anchored_by (default: $USER)",
    )

    setup_egress_p = subparsers.add_parser(
        "setup-egress",
        help="Create or register egress signing keys outside WILLOW_HOME (local CLI only)",
    )
    setup_egress_p.add_argument("--force", action="store_true", help="regenerate default keypair")
    setup_egress_p.add_argument("--private-key", default="", help="register an existing private PEM")
    setup_egress_p.add_argument("--public-key", default="", help="register an existing public PEM")
    setup_egress_p.add_argument(
        "--write-mcp-json",
        default="",
        help="merge WILLOW_MCP_EGRESS_PUBLIC_KEY into this project's .cursor/mcp.json",
    )
    setup_egress_p.add_argument(
        "--project-root",
        default="",
        help="merge public key env into .cursor/mcp.json and .mcp.json under this repo",
    )

    onboard_p = subparsers.add_parser(
        "onboard",
        help="First-run operator setup: home layout, egress keys, MCP env, optional consent",
    )
    onboard_p.add_argument(
        "--app-id",
        default=os.environ.get("WILLOW_APP_ID", "willow"),
        dest="app_id",
    )
    onboard_p.add_argument(
        "--project-root",
        default="",
        help="auto-wire WILLOW_MCP_EGRESS_PUBLIC_KEY into this repo's MCP configs",
    )
    onboard_p.add_argument(
        "--enable-internet",
        action="store_true",
        help="set consent.internet=true (interactive terminal only)",
    )

    doctor_p = subparsers.add_parser(
        "doctor",
        help="Human-readable health check with copy/paste fixes",
    )
    doctor_p.add_argument(
        "--app-id",
        default=os.environ.get("WILLOW_APP_ID", "willow"),
        dest="app_id",
    )
    doctor_p.add_argument(
        "--project-root",
        default="",
        help="include onboard hint with this project path when keys are missing",
    )

    run_net_p = subparsers.add_parser(
        "run-net",
        help="Operator one-shot: grant lease (if needed), sign, and queue a network task",
    )
    run_net_p.add_argument("app_id", help="submitted_by identity bound into the envelope")
    run_net_input = run_net_p.add_mutually_exclusive_group(required=True)
    run_net_input.add_argument("--task", default="", help="exact task text to authorize")
    run_net_input.add_argument("--task-file", default="", help="UTF-8 file containing the task")
    run_net_p.add_argument("--agent", default="kart")
    run_net_p.add_argument("--lane", default="fast", choices=["fast", "batch"])
    run_net_p.add_argument("--ttl", default="30m")
    run_net_p.add_argument("--issuer", default=os.environ.get("USER", "operator"))
    run_net_p.add_argument("--reason", default="")
    run_net_p.add_argument("--skip-grant", action="store_true", help="do not auto-issue a lease")
    run_net_p.add_argument(
        "--localhost",
        action="store_true",
        help="authorize # allow_localhost instead of full # allow_net",
    )

    grant_p = subparsers.add_parser(
        "grant-net",
        help="Issue a time-boxed egress lease for an app_id (local-only — never an MCP tool)",
    )
    grant_p.add_argument("app_id")
    grant_p.add_argument("--ttl", default="30m",
                         help="lease lifetime: 900s / 30m / 2h (ceiling 3h)")
    grant_p.add_argument("--reason", default="", help="why this grant exists — it is recorded")
    grant_p.add_argument("--issuer", default=os.environ.get("USER", "operator"),
                         help="who is issuing the lease (default $USER)")

    revoke_p = subparsers.add_parser("revoke-net", help="End an egress lease before it expires")
    revoke_p.add_argument("app_id")

    status_p = subparsers.add_parser(
        "net-status", help="Show egress leases and which trust-root keys this process can forge")
    status_p.add_argument("app_id", nargs="?", default="")

    dev_net_p = subparsers.add_parser(
        "dev-net",
        help="Local/dev convenience: grant web_net + operator consent + an egress lease "
             "in one command (never an MCP tool — calls the same admin functions "
             "allow-permission/consent set/grant-net already call; #287)",
    )
    dev_net_p.add_argument("app_id")
    dev_net_p.add_argument("--ttl", default="30m",
                            help="lease lifetime: 900s / 30m / 2h (ceiling 3h)")
    dev_net_p.add_argument("--reason", default="", help="why this grant exists — it is recorded")
    dev_net_p.add_argument("--issuer", default=os.environ.get("USER", "operator"),
                            help="who is issuing the lease (default $USER)")
    dev_net_p.add_argument("--force", action="store_true",
                            help="proceed even though WILLOW_MCP_STRICT_TRUST_ROOT is set")

    grant_build_p = subparsers.add_parser(
        "grant-build",
        help="Issue a time-boxed build lease for an earn-first tool "
             "(local-only — never an MCP tool)",
    )
    grant_build_p.add_argument("tool",
                               help="tool name (family stem is fine, e.g. workflow, intake)")
    grant_build_p.add_argument("--ttl", default="30m",
                               help="lease lifetime: 900s / 30m / 2h (ceiling 3h)")
    grant_build_p.add_argument("--reason", default="",
                               help="what building this opens — recorded on the lease")
    grant_build_p.add_argument("--issuer", default=os.environ.get("USER", "operator"),
                               help="who is authorizing the build (default $USER)")

    revoke_build_p = subparsers.add_parser(
        "revoke-build", help="End a build lease before it expires")
    revoke_build_p.add_argument("tool")

    build_status_p = subparsers.add_parser(
        "build-status",
        help="Show build leases for earn-first tools")
    build_status_p.add_argument("tool", nargs="?", default="")
    build_status_p.add_argument("--json", action="store_true",
                                help="machine-readable output")

    earn_check_p = subparsers.add_parser(
        "earn-check",
        help="Cross-reference the earn-first roster with build leases on disk "
             "— replaces case-by-case re-litigation with a status readout",
    )
    earn_check_p.add_argument("--json", action="store_true",
                              help="machine-readable output")

    harden_p = subparsers.add_parser(
        "harden-trust-root",
        help="Separate egress confirm authority from the agent (B-32): chown trust roots + strict mode",
    )
    harden_p.add_argument(
        "--owner",
        default="",
        help="unix user that owns trust roots (default: willow-operator)",
    )
    harden_p.add_argument(
        "--project-root",
        default="",
        help="merge WILLOW_MCP_STRICT_TRUST_ROOT=1 into this repo's MCP configs",
    )
    harden_p.add_argument(
        "--dry-run",
        action="store_true",
        help="show planned chown/chmod actions without applying",
    )
    harden_p.add_argument(
        "--runtime-user",
        default="",
        help="unix user that owns store/dispatch runtime paths (default: $USER / $SUDO_USER)",
    )
    harden_p.add_argument(
        "--skip-runtime-repair",
        action="store_true",
        help="only harden trust roots; do not chown store/dispatch back to the runtime user",
    )

    repair_runtime_p = subparsers.add_parser(
        "repair-runtime-perms",
        help="Restore MCP runtime write paths (store, dispatch, …) after trust-root hardening",
    )
    repair_runtime_p.add_argument(
        "--runtime-user",
        default="",
        help="unix user that should own runtime paths (default: $USER / $SUDO_USER)",
    )
    repair_runtime_p.add_argument(
        "--dry-run",
        action="store_true",
        help="show planned chown/chmod actions without applying",
    )

    gates_p = subparsers.add_parser(
        "gates",
        help="Show every authorization gate (consent, manifest permissions, egress "
             "lease, identity bindings, worker...) as one on/off panel, egress-lease shaped",
    )
    gates_p.add_argument("app_id", nargs="?", default="",
                          help="scope to one app_id (default: every app under mcp_apps/)")
    gates_p.add_argument("--html", nargs="?", const="willow-gates.html", default=None,
                          metavar="PATH",
                          help="write a static HTML snapshot instead of (or as well as) "
                               "the terminal table; defaults to ./willow-gates.html")
    gates_p.add_argument("--json", action="store_true", help="print raw JSON, no table")
    gates_p.add_argument("--no-tui", action="store_true",
                          help="with --html, skip printing the terminal table")
    gates_p.add_argument("--static", action="store_true",
                          help="force the one-shot text printout instead of the interactive "
                               "TUI, even when run in a real terminal")
    gates_p.add_argument("--serve", action="store_true",
                          help="serve a live local HTML dashboard with working buttons "
                               "(127.0.0.1 by default) instead of a one-shot snapshot")
    gates_p.add_argument("--host", default="127.0.0.1",
                          help="bind host for --serve (default: 127.0.0.1 — localhost only)")
    gates_p.add_argument("--port", type=int, default=8788, help="bind port for --serve")

    allow_p = subparsers.add_parser(
        "allow-permission",
        help="Add a permission group (or the task_net capability) to an app's manifest")
    allow_p.add_argument("app_id")
    allow_p.add_argument("permission")

    deny_p = subparsers.add_parser(
        "deny-permission",
        help="Remove a permission group (or the task_net capability) from an app's manifest")
    deny_p.add_argument("app_id")
    deny_p.add_argument("permission")

    federation_p = subparsers.add_parser(
        "federation",
        help="Operator half of federated MCP: discover, ratify, revoke downstream servers")
    federation_sub = federation_p.add_subparsers(dest="federation_action", required=True)
    fed_list_p = federation_sub.add_parser("list", help="Ratified downstream MCP servers")
    fed_list_p.add_argument("--json", action="store_true")
    fed_disc_p = federation_sub.add_parser(
        "discover", help="`.mcp.json` server entries on this host, ratified or not")
    fed_disc_p.add_argument("--root", default="", help="scan root (default: $HOME)")
    fed_disc_p.add_argument("--json", action="store_true")
    fed_rat_p = federation_sub.add_parser(
        "ratify", help="Promote a discovered server into the ratified registry")
    fed_rat_p.add_argument("server_id", help="id from `federation discover`")
    fed_rat_p.add_argument("--by", required=True,
                           help="who is ratifying — an unattributed ratification is not one")
    fed_rat_p.add_argument("--reason", default="")
    fed_rat_p.add_argument("--root", default="", help="scan root (default: $HOME)")
    fed_rev_p = federation_sub.add_parser("revoke", help="Remove a server's ratification")
    fed_rev_p.add_argument("server_id")

    tree_p = subparsers.add_parser(
        "tree",
        help="Dump every tree part (trunk/sap/canopy/roots/rings/leaves/litter/stomata) "
             "as one call — the integration seam for a real dashboard",
    )
    tree_p.add_argument("app_id", nargs="?", default=os.environ.get("WILLOW_APP_ID", ""))
    tree_p.add_argument("--json", action="store_true", help="print raw JSON, no summary")

    compile_p = subparsers.add_parser(
        "compile-agents",
        help="Compile mcp_apps/*/manifest.json from specialists registry",
    )
    compile_p.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing manifests (default: only missing)",
    )
    compile_p.add_argument("--dry-run", action="store_true", help="report paths only")
    compile_p.add_argument(
        "--registry",
        default="",
        help="path to specialists.json (default: $WILLOW_HOME/config or bundle)",
    )

    persona_p = subparsers.add_parser(
        "compile-persona",
        help="Compile personas/{agent_id}.md from $WILLOW_HOME/seeds/{agent_id}.json",
    )
    persona_p.add_argument("agent_id", help="agent id (e.g. hanuman, willow)")
    persona_p.add_argument("--force", action="store_true", help="overwrite existing persona .md")
    persona_p.add_argument("--dry-run", action="store_true", help="preview markdown without writing")
    persona_p.add_argument("--out", default="", help="optional output path")

    project_p = subparsers.add_parser(
        "project",
        help="Sync or audit agent-agnostic IDE wiring (MCP JSON, hooks, Claude settings)",
    )
    project_p.add_argument(
        "project_action",
        choices=["sync", "audit", "list"],
        help="sync materializes configs; audit exits 1 on drift; list shows registry",
    )
    project_p.add_argument(
        "project_id",
        nargs="?",
        default="",
        help="registry project id (default: all projects)",
    )
    project_p.add_argument("--dry-run", action="store_true", help="preview writes only")

    args, _ = parser.parse_known_args()

    if args.command == "setup":
        _cmd_setup(args)
        return
    if args.command == "confirm-binding":
        _cmd_confirm_binding(args)
        return
    if args.command == "worker":
        _cmd_worker(args)
        return
    if args.command == "voice":
        _cmd_voice(args)
        return
    if args.command == "voice-service":
        _cmd_voice_service(args)
        return
    if args.command == "consent":
        _cmd_consent(args)
        return
    if args.command == "grant-consent":
        _cmd_grant_consent(args)
        return
    if args.command == "revoke-consent":
        _cmd_revoke_consent(args)
        return
    if args.command == "consent-status":
        _cmd_consent_status(args)
        return
    if args.command == "roster":
        _cmd_roster(args)
        return
    if args.command == "repo-sweep":
        _cmd_repo_sweep(args)
        return
    if args.command == "repo-sweep-service":
        _cmd_repo_sweep_service(args)
        return
    if args.command == "worker-service":
        _cmd_worker_service(args)
        return
    if args.command == "sign-net-task":
        _cmd_sign_net_task(args)
    if args.command == "sign-db-task":
        _cmd_sign_db_task(args)
        return
    if args.command == "sign-manifest":
        _cmd_sign_manifest(args)
        return
    if args.command == "attest-session":
        _cmd_attest_session(args)
        return
    if args.command == "keys":
        # cli_keys.cmd_keys returns an exit code; propagate it.
        from . import cli_keys as _cli_keys
        sys.exit(_cli_keys.cmd_keys(args))
    if args.command == "sign-session":
        from . import sign_session_cli as _sign_session_cli
        sys.exit(_sign_session_cli.cmd_sign_session(args))
    if args.command == "envelope":
        from . import cli_envelope as _cli_envelope
        sys.exit(_cli_envelope.cmd_envelope(args))
    if args.command == "frank-anchor":
        _cmd_frank_anchor(args)
        return
    if args.command == "setup-egress":
        _cmd_setup_egress(args)
        return
    if args.command == "onboard":
        _cmd_onboard(args)
        return
    if args.command == "doctor":
        _cmd_doctor(args)
        return
    if args.command == "run-net":
        _cmd_run_net(args)
        return
    if args.command == "register-agent":
        _cmd_register_agent(args)
        return
    if args.command == "list-agents":
        _cmd_list_agents(args)
        return
    if args.command == "revoke-agent":
        _cmd_revoke_agent(args)
        return
    if args.command == "rotate-agent":
        _cmd_rotate_agent(args)
        return
    if args.command == "grant-net":
        _cmd_grant_net(args)
        return
    if args.command == "revoke-net":
        _cmd_revoke_net(args)
        return
    if args.command == "net-status":
        _cmd_net_status(args)
        return
    if args.command == "dev-net":
        _cmd_dev_net(args)
        return
    if args.command == "grant-build":
        _cmd_grant_build(args)
        return
    if args.command == "revoke-build":
        _cmd_revoke_build(args)
        return
    if args.command == "build-status":
        _cmd_build_status(args)
        return
    if args.command == "earn-check":
        _cmd_earn_check(args)
        return
    if args.command == "harden-trust-root":
        _cmd_harden_trust_root(args)
        return
    if args.command == "repair-runtime-perms":
        _cmd_repair_runtime_perms(args)
        return
    if args.command == "gates":
        _cmd_gates(args)
        return
    if args.command == "allow-permission":
        _cmd_set_permission(args, granted=True)
        return
    if args.command == "deny-permission":
        _cmd_set_permission(args, granted=False)
        return
    if args.command == "federation":
        return _cmd_federation(args)
    if args.command == "tree":
        _cmd_tree(args)
        return
    if args.command == "compile-agents":
        from .registry import ManifestSignError, compile_agents_main

        reg = Path(args.registry).expanduser() if args.registry else None
        try:
            result = compile_agents_main(
                force=args.force,
                dry_run=args.dry_run,
                registry_file=reg,
            )
        except ManifestSignError as e:
            print(json.dumps(e.result, indent=2))
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1)
        print(json.dumps(result, indent=2))
        return
    if args.command == "compile-persona":
        from .persona_compile import compile_persona

        out = Path(args.out).expanduser() if args.out else None
        print(json.dumps(compile_persona(args.agent_id, dry_run=args.dry_run, force=args.force, out_path=out), indent=2))
        return
    if args.command == "project":
        _cmd_project(args)
        return

    # #312 startup verify sweep: an unsigned/tampered manifest denies every
    # gated call for that app_id with no reason surfaced to the caller
    # (_load_manifest is deliberately reason-free). Log every BAD-SIG / NO-SIG
    # row, then refuse to start — a process that would deny those app_ids on
    # every gated call is not a healthy serve/stdio boot. No-op (and no exit)
    # unless WILLOW_PGP_FINGERPRINT is set.
    _manifest_verify_problems = log_manifest_verify_sweep()
    if _manifest_verify_problems:
        print(
            "willow-mcp: refusing to start — "
            f"{len(_manifest_verify_problems)} manifest(s) failed PGP verification. "
            "Re-sign with `willow-mcp sign-manifest <app_id>` from a host terminal, "
            "or unset WILLOW_PGP_FINGERPRINT to run without enforcement.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Serve mode is SINGLE-INSTANCE per WILLOW_HOME — agent sessions, rate-limit
    # buckets and in-flight OAuth state are process memory, so a second replica
    # silently breaks binding and login rather than sharing load. Declared and
    # enforced in instance_lock; see docs/design/stateless-session-state.md.
    # The handle must outlive main(), so it is parked on the module (closing it
    # would release the flock while the server is still running).
    global _INSTANCE_LOCK
    if args.serve or _serve_mode():
        from . import instance_lock
        try:
            _INSTANCE_LOCK = instance_lock.acquire()
        except instance_lock.InstanceLockError as e:
            print(f"willow-mcp: refusing to start.\n{e}", file=sys.stderr)
            raise SystemExit(1)
        # SDK 2.x: host/port moved off the constructor onto the transport,
        # which is the stateless core making "where this instance listens" a
        # property of the run rather than of the server object.
        mcp.run(transport="streamable-http", host=_HOST, port=_PORT)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
