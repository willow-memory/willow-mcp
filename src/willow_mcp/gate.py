# willow_mcp/gate.py — manifest-based per-tool ACL gate.
#
# Identity model (stdio mode):
#   app_id is passed on every tool call. An app is authorized when a manifest
#   JSON file exists at $WILLOW_HOME/mcp_apps/<app_id>/manifest.json.
#   The manifest's "permissions" list controls which tools the app may call.
#
# Identity model (HTTP serve mode, Phase 2):
#   OAuth-verified identity (Google/Apple sub claim) is written into the
#   session before any tool dispatch; gate reads it from the session context.
#
# Fail-closed: missing app_id, missing manifest, or empty permissions → deny.
# GPG is opt-in (#183, docs/design/pgp-and-persona.md P1 slice): unset
# WILLOW_PGP_FINGERPRINT and a manifest is trusted as-is (file-system trust,
# single-operator assumption, unchanged default). Set it and an unsigned or
# tampered manifest has no standing — it is treated exactly like a missing
# one (deny), because a writable, unsigned JSON file is a forgeable identity
# and a self-grantable capability (issue #183, part of the #181 kill chain).
import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

from . import pgp

logger = logging.getLogger(__name__)

_APP_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def _apps_root() -> Path:
    home = Path(os.environ.get("WILLOW_HOME", Path.home() / ".willow"))
    return Path(os.environ.get("WILLOW_MCP_APPS_ROOT", home / "mcp_apps"))


def _validate_app_id(app_id: str) -> str:
    if not app_id or not _APP_ID_RE.match(app_id):
        raise ValueError(f"Invalid app_id: {app_id!r}")
    return app_id


def valid_app_id(app_id: str) -> bool:
    """True if `app_id` is well-formed (matches the id charset). Lets a caller
    distinguish a malformed id from a merely-unmanifested one before building a
    manifest path from it — an invalid id names no file."""
    return bool(app_id) and bool(_APP_ID_RE.match(app_id))


# Permission groups — named bundles that expand to sets of tool names.
# An app manifest lists group names and/or literal tool names in "permissions".
PERMISSION_GROUPS: dict[str, frozenset] = {
    "store_read": frozenset({
        "store_get", "store_search", "store_list", "store_search_all",
        "store_collections", "store_stats",
    }),
    "store_write": frozenset({
        "store_put", "store_update", "store_delete", "store_purge_collection",
        "agent_seed_mirror",
    }),
    "store_all": frozenset({
        "store_put", "store_get", "store_list", "store_update",
        "store_search", "store_delete", "store_purge_collection",
        "store_search_all", "store_collections", "store_stats",
    }),
    "knowledge_read": frozenset({
        "knowledge_search",
        "kb_at", "kb_startup_continuity",
        "knowledge_verify", "knowledge_check",
    }),
    "knowledge_write": frozenset({
        "knowledge_ingest",
        "kb_ingest", "kb_journal", "kb_promote",
    }),
    "knowledge_curate": frozenset({
        "knowledge_flag", "knowledge_retract",
    }),
    "task_queue": frozenset({
        "task_submit", "task_status", "task_list",
    }),
    "agent_dispatch": frozenset({
        "agent_route", "agent_dispatch_result",
    }),
    "dispatch_read": frozenset({
        "dispatch_read", "dispatch_list", "handoff_read", "session_read", "session_enter",
        "specialist_list", "specialist_get", "agent_seed_mirror",
        "exposure_config_get", "exposure_slice",
    }),
    # verify_handoff and agent_clear are deliberately NOT here (B-51, issue
    # #240): they are the orchestrator's own quality-gate step over a
    # specialist's work ("the orchestrator checks both in verify_handoff
    # before releasing you via agent_clear" -- handoff_write_v4's own
    # docstring), not something a builder should be able to run over its own
    # or a peer's dispatch. Red-team 2026-07-31 demonstrated a builder seat
    # (hanuman) verifying and clearing its own forged lifecycle end to end
    # with zero orchestrator/human involvement, because this group granted
    # both tools to every dispatch_write holder. They remain reachable only
    # via the `orchestrator` group, which is human-attestation-gated
    # (ORCHESTRATOR_WRITE_TOOLS, human_session.py).
    "dispatch_write": frozenset({
        "dispatch_send", "dispatch_accept", "handoff_write_v4",
        "session_handoff_write",
    }),
    "orchestrator": frozenset({
        "dispatch_send", "dispatch_read", "dispatch_list", "dispatch_accept",
        "handoff_write_v4", "handoff_read", "verify_handoff", "agent_clear",
        "session_read", "session_enter", "session_handoff_write", "agent_route", "agent_dispatch_result",
        "fleet_status", "fleet_health", "frank_read", "frank_verify",
        "frank_append", "envelope_apply",
        "context_save", "context_get",
        "context_list", "knowledge_search", "kb_ingest", "store_get", "store_search",
        "specialist_list", "specialist_get", "agent_seed_mirror",
        "exposure_config_get", "exposure_slice",
    }),
    "fleet_read": frozenset({
        "fleet_status", "fleet_health", "frank_read", "frank_verify",
    }),
    # Grove — the fleet's shared messaging room (willow-2.0's sap/grove_tools.py
    # successor; see willow_mcp/grove_tools.py). Read/write mirror the
    # store_read/store_write split above: 13 read tools (channel/message/thread/
    # flag/bus listing, plus grove_agents/grove_fleet_status/grove_human_required
    # fleet-awareness reads) and 7 write tools (post/reply/flag/bus-send/ack/
    # heartbeat). grove_all is the explicit union, same convention as
    # store_all — not derived, so it stays auditable as a literal set.
    "grove_read": frozenset({
        "grove_list_channels", "grove_get_history", "grove_search", "grove_watch",
        "grove_watch_all", "grove_get_thread", "grove_bus_receive", "grove_inbox",
        "grove_flagged", "grove_get_identity", "grove_agents", "grove_fleet_status",
        "grove_human_required",
    }),
    "grove_write": frozenset({
        "grove_send_message", "grove_reply", "grove_flag", "grove_unflag",
        "grove_bus_send", "grove_ack", "grove_heartbeat",
    }),
    "grove_all": frozenset({
        "grove_list_channels", "grove_get_history", "grove_search", "grove_watch",
        "grove_watch_all", "grove_get_thread", "grove_bus_receive", "grove_inbox",
        "grove_flagged", "grove_get_identity", "grove_agents", "grove_fleet_status",
        "grove_human_required",
        "grove_send_message", "grove_reply", "grove_flag", "grove_unflag",
        "grove_bus_send", "grove_ack", "grove_heartbeat",
    }),
    "frank_write": frozenset({
        "frank_append",
    }),
    "envelope_apply": frozenset({
        "envelope_apply",
    }),
    # Envelope-accrual loop (docs/design/envelope-accrual.md; PR5-7 + PR8).
    # envelope_apply above stays its own group — it is a specialist's
    # capability-exercise path. The four groups below govern the AUTHORING
    # loop: read the queue, propose, ratify (operator only), inspect the
    # auto-propose discard residue (Nestor's ledger.unreadable() prior).
    # Split into read/write mirrors dispatch_read/dispatch_write; splitting
    # envelope_read_discards into its own group keeps the residue walk
    # narrowly grantable without also granting the queue view.
    "envelope_read": frozenset({
        "envelope_list", "envelope_pending_read",
    }),
    "envelope_write": frozenset({
        "envelope_propose", "envelope_ratify", "envelope_reject",
    }),
    "envelope_read_discards": frozenset({
        "envelope_read_discards",
    }),
    "context": frozenset({
        "context_save", "context_get", "context_list", "context_expire",
    }),
    "audit": frozenset({
        "receipts_tail",
    }),
    "gap_read": frozenset({
        "gap_list",
    }),
    "gap_write": frozenset({
        "gap_log", "gap_resolve", "gap_delete",
    }),
    # Bulk-purging a whole topic hits the FLEET-SHARED gaps backlog across every
    # app, not just the caller's own — a more consequential act than logging,
    # resolving, or deleting one gap, so it's its own opt-in line rather than
    # folded into gap_write (same reasoning as gap_promote / schema_admin).
    "gap_purge": frozenset({
        "gap_purge_topic",
    }),
    # Provenance/"story of this willow" atoms. Read (why/list) is broadly safe —
    # it is exactly what a curious agent should be able to ask. Write is its own
    # group so recording lineage is a deliberate grant, not a side effect of a
    # store-write role.
    "lineage_read": frozenset({
        "lineage_why", "lineage_list",
    }),
    "lineage_write": frozenset({
        "lineage_record", "lineage_link",
    }),
    # Relationship smoke detector (model-free; never blocks, never egresses).
    # scan persists a flag when it trips, so it is a write; listing is a read.
    "friction_read": frozenset({
        "friction_flags_list",
    }),
    "friction_write": frozenset({
        "friction_scan",
    }),
    # Nestor tool oracle (docs/design/nestor-tool-route.md) — natural-language
    # routing to willow verbs. route persists a ledger passage + a teach-queue
    # entry, so it is write-capable (same reasoning as friction_scan); pending is
    # a pure read; sealing a phrasing -> verb mapping mints invocation power for
    # that phrasing, so it is its own group, meant for human/attested seats —
    # never a plain agent role.
    "tool_oracle_read": frozenset({
        "nestor_tool_pending",
    }),
    "tool_oracle_route": frozenset({
        "nestor_tool_route",
    }),
    "tool_oracle_seal": frozenset({
        "nestor_tool_seal",
    }),
    # Cryptographic identity binding (willow-gate seam, Phase 2). The security is
    # the HMAC signature, not this ACL; the group just lets a manifest opt an app
    # into calling check-in. Registration stays operator/CLI-only.
    "binding": frozenset({
        "session_bind", "session_reconcile",
    }),
    "integration_read": frozenset({
        "integration_list", "integration_status",
    }),
    # Federated MCP (willow_mcp.mcp_federation) — willow-mcp as a *client* of
    # other MCP servers (docs/design/federated-mcp-gating.md). Read is
    # inventory-only: discovery of .mcp.json files not yet owned by the
    # ratified registry (shadow-IT), plus the ratified server list itself —
    # neither spawns anything or reaches a downstream tool. federation_call is
    # its own group, deliberately NOT in full_access, for the same reason
    # integration_call and web_net stay off it: fork/exec at the server's own
    # uid is the single most privileged egress lane in this file (Decision 3),
    # so even the *attempt* surface is opt-in. Reaching an actual downstream
    # tool additionally needs the mcp_federation capability (own line, below),
    # a namespaced `mcp:<server_id>:<tool>` grant, and the three-key egress
    # gate in federation_egress.py — this group only unlocks the dispatcher.
    "federation_read": frozenset({
        "federation_discover", "federation_list_servers",
    }),
    "federation_call": frozenset({
        "federation_call",
    }),
    # integration_call is its own group and deliberately NOT in full_access:
    # it is the only tool whose entire purpose is server-process egress, so it
    # is granted on its own line — same spirit as NET_PERMISSION below. (The
    # actual egress still needs the integration_net capability + consent +
    # lease; this keeps even the *attempt* surface opt-in.)
    "integration_call": frozenset({
        "integration_call",
    }),
    # Open web — DuckDuckGo search + guarded URL fetch (server-process egress).
    # Requires web_net capability + consent.internet + lease (see web_egress.py).
    #
    # `willow_institutional_search` sits here too, and deliberately not on a
    # softer line: it fans out across ~60 named collections in one call, so it is
    # the largest egress surface of the three even though every destination is a
    # library or an academic index. One lease, sixty connections — the operator
    # is granting more here than with a single DuckDuckGo query, and the grant
    # should not look cheaper than it is.
    "web_read": frozenset({
        "willow_web_search", "willow_web_fetch", "willow_institutional_search",
    }),
    # Bounded work-units (branch + PR tracking) — SOIL-backed port of willow-2.0 forks.
    "fork_read": frozenset({
        "fork_list", "fork_status", "env_check",
    }),
    "fork_write": frozenset({
        "fork_create", "fork_join", "fork_log", "fork_merge", "fork_delete",
    }),
    # Landing a gap as trusted knowledge is a more consequential act than
    # logging or resolving one, so it's gated as its own group rather than
    # folded into gap_write — same reasoning as schema_admin below.
    "gap_promote": frozenset({
        "gap_promote",
    }),
    # Confirming a schema mapping unlocks write tools for a whole table — a
    # more consequential act than any single write, so it's gated as its
    # own group rather than folded into knowledge_write (docs/design/
    # schema-adaptation.md §8 open question, resolved this way).
    "schema_admin": frozenset({
        "schema_confirm_mapping",
    }),
    # The Nest — content-pipeline surface (willow_mcp.nest). Read is the
    # walled-digest / structure view (no content leaves); write walks a drop
    # folder into a local SQLite Nest DB and promotes its *structure* (counts,
    # curated category names, redacted secret kinds — never fragment content)
    # into the knowledge base. nest_promote is a write that reaches the KB, so
    # it is gated here rather than folded into knowledge_write: promoting a
    # whole dump's structure is a more consequential act than one atom ingest,
    # same reasoning as gap_promote / schema_admin above.
    "nest_read": frozenset({
        "nest_status", "nest_digest",
        "nest_intake_queue", "nest_intake_flags",   # router review surface
    }),
    "nest_write": frozenset({
        "nest_scan", "nest_promote",
        # live drop-folder router: scan stages a queue, file MOVES the file on the
        # host, skip records the decision. Filing is a filesystem mutation, so it
        # rides the write group (never nest_read).
        "nest_intake_scan", "nest_intake_file", "nest_intake_skip",
    }),
    # The Commitment Membrane (willow_mcp.commitments) — the operator's kept record
    # of their own calendar commitments (Jarvis layer 2). Read is the dew-rule surface
    # + a facts-only list (title + time, never the event body). Write ingests calendar
    # facts into the ledger and acknowledges changes — but NEVER writes the calendar
    # back: propose_action and the SAFE gate are deliberately not exposed over MCP, so
    # this group introduces no new authority (same reasoning that keeps integration_call
    # and task_net on their own lines). Body/notes/location are dropped at ingest and a
    # persistence-boundary guard refuses to store them, so even a write cannot record.
    "commitment_read": frozenset({
        "commitment_surface", "commitment_list",
    }),
    "commitment_write": frozenset({
        "commitment_ingest", "commitment_acknowledge",
    }),
    # code_graph (willow_mcp.code_graph) — a local, rebuildable symbol graph over a
    # repo (stdlib ast + sqlite, no network/Postgres). Read is the query surface
    # (search/explain/walk/suggest/impact); write is indexing, which builds the
    # local SQLite DB — same read/write split as the Nest (scan writes, digest
    # reads). Nothing here reaches the SOIL store or the KB, so it is its own pair
    # of groups rather than folded into store_*/knowledge_*.
    "code_graph_read": frozenset({
        "code_graph_search", "code_graph_explain", "code_graph_walk",
        "code_graph_suggest", "code_graph_impact",
    }),
    "code_graph_write": frozenset({
        "code_graph_index",
    }),
    # Human-in-the-loop (willow_mcp.human_loop) — an attention queue + durable
    # attestations, over the SOIL store. Read is listing; write is enqueue/resolve/
    # attest. Kept its own group pair (not folded into store_*) because these are
    # human-loop trust records, not general store rows — an app grants access to
    # the queue/attestations deliberately. The attester of an attestation is always
    # the caller's own identity, so `human_attestation_create` cannot be used to
    # forge a record in another's name regardless of who holds this group.
    "human_loop_read": frozenset({
        "human_required_list", "human_attestation_list",
    }),
    "human_loop_write": frozenset({
        "human_required_enqueue", "human_required_resolve", "human_attestation_create",
    }),
    # MarkdownAI (mai) tools — #153/#161. Registration is already opt-in via
    # WILLOW_MCP_MARKDOWNAI; these groups add per-app authorization on top,
    # because a registered tool surface with no gate is exactly the #161 hole.
    # Read/write cover the file+render tools; the directives group is the
    # dangerous half — it unlocks side-effectful @db/@http/@env resolution
    # inside render() via the pseudo-tool "__mai_directives__", which is
    # checked by the parser and never registered as an MCP tool. None of the
    # three ride full_access: mai reaches the filesystem, the database, and
    # the network, so each is a deliberate grant (same reasoning as task_net).
    "markdownai_read": frozenset({
        "mai_read_file", "mai_list_phases", "mai_resolve_phase",
        "mai_next_phase", "mai_call_macro", "mai_get_constraints",
    }),
    "markdownai_write": frozenset({
        "mai_write_file", "mai_invalidate_cache",
    }),
    "markdownai_directives": frozenset({
        "mai_execute_directive", "mai_get_env", "__mai_directives__",
    }),
    "full_access": frozenset({
        # Core store
        "store_put", "store_get", "store_list", "store_update",
        "store_search", "store_delete", "store_purge_collection",
        "store_search_all", "store_collections", "store_stats",
        # Knowledge
        "knowledge_search", "knowledge_ingest",
        "kb_at", "kb_startup_continuity",
        "kb_ingest", "kb_journal", "kb_promote",
        # Tasks
        "task_submit", "task_status", "task_list",
        # Dispatch
        "agent_route", "agent_dispatch_result",
        "dispatch_send", "dispatch_read", "dispatch_list", "dispatch_accept",
        "handoff_write_v4", "handoff_read", "verify_handoff", "agent_clear",
        "session_read", "session_enter", "session_handoff_write",
        "agent_seed_mirror",
        "exposure_config_get", "exposure_slice",
        # Specialist registry (read-only routing/orchestrator desk)
        "specialist_list", "specialist_get",
        # Fleet (read-only)
        "fleet_status", "fleet_health",
        "frank_read", "frank_verify",
        # Grove — the fleet's shared messaging room (read + write; no egress
        # concern like web_net/integration_net/mcp_federation, so unlike those
        # this rides full_access, same reasoning as knowledge_read/write above)
        "grove_list_channels", "grove_get_history", "grove_search", "grove_watch",
        "grove_watch_all", "grove_get_thread", "grove_bus_receive", "grove_inbox",
        "grove_flagged", "grove_get_identity", "grove_agents", "grove_fleet_status",
        "grove_human_required",
        "grove_send_message", "grove_reply", "grove_flag", "grove_unflag",
        "grove_bus_send", "grove_ack", "grove_heartbeat",
        # Schema admin
        "schema_confirm_mapping",
        # Session context
        "context_save", "context_get", "context_list", "context_expire",
        # Self-audit
        "receipts_tail",
        # Gap backlog
        "gap_log", "gap_list", "gap_resolve", "gap_delete", "gap_purge_topic",
        "gap_promote",
        # Lineage / provenance ("story of this willow")
        "lineage_why", "lineage_list", "lineage_record", "lineage_link",
        # Friction floor (relationship smoke detector)
        "friction_scan", "friction_flags_list",
        # Identity binding (check-in / check-out; registration is CLI-only)
        "session_bind", "session_reconcile",
        # Integrations (read-only ledger; integration_call stays own-line)
        "integration_list", "integration_status",
        # The Nest (content pipeline + live router; scan/promote/file/skip write)
        "nest_status", "nest_digest", "nest_scan", "nest_promote",
        "nest_intake_scan", "nest_intake_queue", "nest_intake_file",
        "nest_intake_skip", "nest_intake_flags",
        # The Commitment Membrane (read surface + ledger ingest/acknowledge; never
        # writes the calendar back — no new authority)
        "commitment_surface", "commitment_list",
        "commitment_ingest", "commitment_acknowledge",
        # code_graph (index writes a local SQLite graph; the rest query it)
        "code_graph_index", "code_graph_search", "code_graph_explain",
        "code_graph_walk", "code_graph_suggest", "code_graph_impact",
        # Human-in-the-loop queue + attestations
        "human_required_list", "human_required_enqueue", "human_required_resolve",
        "human_attestation_list", "human_attestation_create",
        # Envelope-accrual loop: reads + operator-facing writes. Same rule
        # ORCHESTRATOR_WRITE_TOOLS enforces in human_session.py — a broad
        # full_access grant reaches every envelope tool, but ratify/reject
        # additionally refuse unless the calling session is keyring-attributed
        # (a fresh gate check in each of them, not a manifest concern).
        "envelope_list", "envelope_pending_read", "envelope_read_discards",
        "envelope_propose", "envelope_ratify", "envelope_reject",
    }),
}


# Capability permissions — privilege flags a manifest may list to unlock an
# extra capability on a tool it already holds, rather than a tool name of their
# own. Checked explicitly by the tool (task_submit checks NET_PERMISSION before
# honoring allow_net). Deliberately NOT folded into full_access or task_queue:
# network egress from the Kart sandbox is an escalated privilege that must be
# granted on its own line, so a broad task_queue/full_access grant never
# silently carries net access with it (B-19; same spirit as B-14's trust-root
# separation).
NET_PERMISSION = "task_net"
# Local Postgres socket + PG/POSTGRES env inside Kart — separate from task_queue
# and full_access so default sandboxed tasks cannot reach the production DB lane.
DB_PERMISSION = "task_db"

# Same shape, different lane: NET_PERMISSION authorizes egress from inside the
# network-namespaced Kart sandbox; INTEGRATION_NET_PERMISSION authorizes the
# server process itself calling out via integration adapters — a strictly more
# privileged lane (server uid, full filesystem view), so holding one must never
# imply the other. Checked by integrations.egress_denial alongside
# consent.internet and a live lease (the same three-key gate task_submit uses).
INTEGRATION_NET_PERMISSION = "integration_net"
# Server-process open-web HTTP (willow_web_search / willow_web_fetch). Same
# three-key gate as integration_call but a separate manifest line so operators
# can grant web without arbitrary integration adapters.
WEB_NET_PERMISSION = "web_net"

# A stdio MCP server willow-mcp spawns itself is fork/exec at the server's own
# uid — strictly more privileged than the three lanes above (full filesystem
# view, no network namespace, a child that may hold its own credentials). See
# docs/design/federated-mcp-gating.md Decision 3. Own line, same reasoning as
# the three above: a task_net/integration_net/web_net grant must never be read
# as "and may also fork a downstream MCP server as me".
MCP_FEDERATION_PERMISSION = "mcp_federation"

# Grove sender lock. `grove_write` lets an app post to the fleet's shared
# room as *itself* (its resolved `grove_sender`) — that is the tool grant.
# Posting as a DIFFERENT identity is a distinct, more consequential privilege
# (forging another agent's orchestrator COMMAND, a fake heartbeat, clearing
# someone else's needs-reply flag) and must be granted on its own line, same
# reasoning as NET_PERMISSION/DB_PERMISSION above: deliberately NOT folded
# into `grove_write` or `full_access`, so a broad grant of either never
# silently carries impersonation with it. Operator-granted only — no seed
# seat holds it; an orchestrator posts as itself, relay is reserved for a
# future bridge seat (docs/design/permissions-matrix.md).
GROVE_RELAY_PERMISSION = "grove_relay"


def federated_tool_permission(server_id: str, tool: str) -> str:
    """The namespaced permission name for one tool on one downstream MCP
    server: ``mcp:<server_id>:<tool>``.

    `permitted()` above does not change to support this — it stays a literal
    name lookup, which is what makes the ACL auditable. Only the names grow a
    namespace, so a manifest grants federated tools one at a time, the way a
    grant for `store_get` never implied `store_delete` (docs/design/
    federated-mcp-gating.md Decision 1: gate per downstream tool, never per
    call). `server_id` is `mcp_federation._stable_id()` — a digest of the
    server's launch identity, not its human label, so renaming a server in a
    config file never silently carries its grants over.
    """
    return f"mcp:{server_id}:{tool}"


#: Why a manifest read produced no usable manifest. The gate's *behaviour* is
#: identical for every one of these — deny, everywhere, exactly as if the file
#: were absent (see test_load_manifest_pgp_denial_is_indistinguishable_from_no_manifest).
#: These codes exist only for the operator-facing diagnostic surface, which runs
#: locally as the operator and already prints the apps_root path. Collapsing them
#: into "no manifest at <path>" sent an operator hunting for a file that was
#: sitting right there, unsigned, for weeks. Never surface a reason on a denial
#: returned to a *caller* — only in diagnostics.
MANIFEST_OK = "ok"
MANIFEST_ABSENT = "absent"
MANIFEST_UNPARSEABLE = "unparseable"
MANIFEST_UNSIGNED = "unsigned"


def _read_manifest(app_id: str) -> tuple[Optional[dict], str, str]:
    """`(manifest_or_None, reason, detail)` — the single manifest resolution path.

    `_load_manifest` is the enforcement wrapper (dict or None, nothing else);
    `manifest_diagnosis` is the operator-facing one. Both go through here so the
    reported reason can never drift from the reason the gate actually acted on.
    """
    root = _apps_root()
    manifest_path = root / app_id / "manifest.json"
    if not manifest_path.exists():
        return None, MANIFEST_ABSENT, f"no manifest at {manifest_path}"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("gate: manifest unreadable for %s: %s", app_id, e)
        return None, MANIFEST_UNPARSEABLE, f"{manifest_path} is not readable JSON: {str(e)[:160]}"
    # #183: opt-in PGP enforcement. Every caller of _load_manifest already
    # treats None as "deny" (fail-closed) -- checking here, once, means an
    # unsigned or tampered manifest is denied everywhere a manifest is read,
    # with no per-call-site change needed. Only fires when the operator has
    # set WILLOW_PGP_FINGERPRINT; unset, behavior is byte-for-byte unchanged
    # from before this landed (docs/design/pgp-and-persona.md: "no dev_bypass,
    # no pgp_enforced toggle" -- the fingerprint's presence IS the switch).
    if pgp.pgp_enabled():
        ok, detail = pgp.verify_detached(manifest_path)
        if not ok:
            logger.error(
                "gate: manifest signature invalid for %s: %s — denied (PGP enforced)",
                app_id, detail,
            )
            return None, MANIFEST_UNSIGNED, (
                f"{manifest_path} exists and parses, but PGP enforcement is ON "
                f"(WILLOW_PGP_FINGERPRINT is set) and its signature did not verify: "
                f"{detail}. Sign it with `willow-mcp sign-manifest {app_id}`."
            )
    return data, MANIFEST_OK, "manifest loaded"


def _load_manifest(app_id: str) -> Optional[dict]:
    """The manifest, or None. Fail-closed and reason-free: every caller treats
    None as deny, and no denial ever tells a caller *why* (that would leak
    whether an app_id exists). Diagnostics use `manifest_diagnosis`."""
    data, _reason, _detail = _read_manifest(app_id)
    return data


def manifest_diagnosis(app_id: str) -> tuple[str, str]:
    """`(reason, detail)` for the operator-facing surfaces only — `doctor`,
    `diagnostic_summary`, `whoami`. Distinguishes absent / unparseable /
    unsigned, which the gate itself deliberately does not."""
    try:
        app_id = _validate_app_id(app_id)
    except ValueError:
        return MANIFEST_ABSENT, f"invalid app_id {app_id!r} — names no manifest file"
    _data, reason, detail = _read_manifest(app_id)
    return reason, detail


def authorized(app_id: str) -> bool:
    """Return True if a manifest exists for this app_id."""
    try:
        app_id = _validate_app_id(app_id)
    except ValueError:
        return False
    return _load_manifest(app_id) is not None


def verify_all_manifests() -> list[dict[str, str]]:
    """Startup verify sweep (issue #312): scan every mcp_apps/<app_id>/manifest.json
    on disk and report every one that fails PGP verification -- unsigned, tampered,
    unparseable, whatever `_read_manifest` would return non-`MANIFEST_OK` for.

    A no-op (`[]`) unless `pgp.pgp_enabled()`: with enforcement off, gate never
    checks signatures at all, so a sweep would only report noise nobody acts on.
    With enforcement on, a manifest a writer forgot to (re-)sign is otherwise
    invisible until an agent using that app_id happens to boot and gets denied
    with no reason surfaced (`_load_manifest` is reason-free by design) -- this
    exists to turn that into a line in the log at server start instead of a
    days-later "why can't I call anything" support thread. Catches breakage from
    ANY writer of mcp_apps/*/manifest.json, not just `compile_manifests` -- the
    next one that forgets to sign gets caught here too, without needing a fix at
    every write site (issue #312 item 4).
    """
    problems: list[dict[str, str]] = []
    if not pgp.pgp_enabled():
        return problems
    root = _apps_root()
    if not root.is_dir():
        return problems
    for app_dir in sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name):
        app_id = app_dir.name
        if not valid_app_id(app_id):
            continue
        if not (app_dir / "manifest.json").is_file():
            continue
        reason, detail = manifest_diagnosis(app_id)
        if reason != MANIFEST_OK:
            problems.append({"app_id": app_id, "reason": reason, "detail": detail})
    return problems


def log_manifest_verify_sweep() -> list[dict[str, str]]:
    """Run `verify_all_manifests` and log the result -- call once at server boot
    (see `server._main`). Returns the same problem list it logs, so a caller that
    wants it programmatically (tests, a future health endpoint) doesn't have to
    re-run the sweep. `server._main` treats a non-empty return as fatal and
    exits 1 rather than serving while those app_ids are silently gated off."""
    problems = verify_all_manifests()
    if not problems:
        if pgp.pgp_enabled():
            logger.info("gate: boot manifest verify sweep — all manifests under %s verified ok", _apps_root())
        return problems
    for p in problems:
        logger.error(
            "gate: boot manifest verify — %s: %s (%s)", p["app_id"], p["reason"], p["detail"],
        )
    logger.error(
        "gate: boot manifest verify sweep — %d of the manifests under %s failed PGP "
        "verification; every gated call for those app_ids is being denied. Re-sign "
        "with `willow-mcp sign-manifest <app_id>` from a host terminal. "
        "Server boot will refuse to start while any row remains bad.",
        len(problems), _apps_root(),
    )
    return problems


#: Returned when a scope cannot be established. `[]` denies every collection
#: (see db.collection_in_scope), so an unreadable policy confines rather than
#: releases. Distinct from None, which means "no policy declared".
_DENY_ALL: list = []


def store_scope(app_id: str) -> Optional[list]:
    """Return this app's manifest `store_scope` list.

    Three outcomes, and the difference between them is the whole point:

    * **Field absent, or explicitly `null` → `None` → unrestricted.** An app that
      never opted into isolation keeps seeing what it always saw — every
      collection in whatever store WILLOW_STORE_ROOT resolved to, which may or
      may not be the wider fleet's (see `diagnostic_summary`'s `severance` check).
      An explicit `null` is a declaration of no policy, not a broken one.
    * **Field present and well-formed → that list.** Exact names and/or
      `prefix*` wildcards; `[]` denies everything.
    * **Scope undeterminable → `[]` → deny-all.** A bad app_id, a missing or
      unreadable manifest, or a malformed `store_scope` cannot be read as
      consent. Returning None here would hand full store access to an operator
      who typed `"store_scope": "myapp_*"` (a string, the obvious typo for this
      field) and believes the app is confined. The app breaks loudly instead,
      which is the only outcome that reaches a human.

    This module fails closed on missing app_id, missing manifest, and empty
    permissions (see header). Scope now does too. See B-24 / L-ISO-01.
    """
    try:
        app_id = _validate_app_id(app_id)
    except ValueError:
        logger.warning("gate: invalid app_id %r for store_scope — denying all collections", app_id)
        return list(_DENY_ALL)
    manifest = _load_manifest(app_id)
    if manifest is None:
        logger.warning("gate: no readable manifest for %r — denying all collections", app_id)
        return list(_DENY_ALL)
    scope = manifest.get("store_scope")
    if scope is None:
        return None
    if not isinstance(scope, list) or not all(isinstance(p, str) for p in scope):
        logger.error(
            "gate: malformed store_scope for %r (expected a list of strings, got %r) "
            "— denying all collections",
            app_id,
            type(scope).__name__,
        )
        return list(_DENY_ALL)
    return scope


def collection_permitted(app_id: str, collection: str) -> bool:
    """True if this app's (optional) store_scope allows touching `collection`."""
    from . import db
    return db.collection_in_scope(collection, store_scope(app_id))


def egress_secret_exempt(app_id: str, tool_name: str) -> bool:
    """True if this app's manifest explicitly exempts `tool_name` from egress
    secret redaction (server._guarded).

    The redaction backstop enforces "no tool ever returns a credential" on the
    data path. A few tools legitimately need to hand a raw token back — the
    canonical case is an `integration_call` that performs an OAuth token
    exchange and must return the token it just obtained. This is the
    operator-controlled, per-tool carve-out for exactly that.

    Fail-closed, and the closed direction here is REDACT: any ambiguity — bad
    app_id, missing/unreadable manifest, a malformed `egress_secret_exempt`
    field (not a list of strings) — yields False, so the value is redacted. An
    exemption only ever comes from a well-formed manifest naming the tool, and a
    manifest is operator-side (the PreToolUse hook blocks an app from writing its
    own) — so an app can never exempt itself. Even an exempted return is still
    audited: server records a `credential_returned` receipt naming the kinds, so
    the exception is loud, never silent.
    """
    try:
        app_id = _validate_app_id(app_id)
    except ValueError:
        return False
    manifest = _load_manifest(app_id)
    if manifest is None:
        return False
    exempt = manifest.get("egress_secret_exempt")
    if not isinstance(exempt, list) or not all(isinstance(t, str) for t in exempt):
        if exempt is not None:
            logger.error(
                "gate: malformed egress_secret_exempt for %r (expected a list of "
                "tool-name strings, got %r) — redacting all egress",
                app_id, type(exempt).__name__)
        return False
    return tool_name in exempt


_PHYSICAL_COLLECTION_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_LOGICAL_COLLECTION_RE = re.compile(
    r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)+$"
)


def collection_aliases(app_id: str) -> dict[str, str]:
    """Return validated explicit logical→physical aliases from the manifest."""
    try:
        manifest = _load_manifest(_validate_app_id(app_id))
    except ValueError:
        return {}
    raw = (manifest or {}).get("collection_aliases") or {}
    if not isinstance(raw, dict):
        return {}
    raw_targets = {
        value for value in raw.values() if isinstance(value, str)
    }
    aliases: dict[str, str] = {}
    for logical, physical in raw.items():
        if (
            not isinstance(logical, str)
            or not isinstance(physical, str)
            or (
                "/" in logical
                and not _LOGICAL_COLLECTION_RE.fullmatch(logical)
            )
            or (
                "/" not in logical
                and not _PHYSICAL_COLLECTION_RE.fullmatch(logical)
            )
            or not _PHYSICAL_COLLECTION_RE.fullmatch(physical)
        ):
            continue
        if logical in raw_targets and logical != physical:
            logger.error(
                "gate: collection alias %r collides with a canonical target",
                logical,
            )
            return {}
        aliases[logical] = physical
    return aliases


def resolve_collection_alias(
    app_id: str, collection: str
) -> tuple[str | None, str | None]:
    """Resolve only declared aliases; never turn arbitrary slashes into names."""
    aliases = collection_aliases(app_id)
    if collection in aliases:
        return aliases[collection], None
    if collection in aliases.values():
        return collection, None
    if "/" in collection:
        return None, f"unknown collection alias: {collection!r}"
    return collection, None


def permitted(app_id: str, tool_name: str) -> bool:
    """
    Return True if app_id is authorized and its manifest permits tool_name.

    Reads "permissions" from the manifest — a list of group names and/or
    literal tool names. Expands groups via PERMISSION_GROUPS.
    Fail-closed: empty or missing permissions → deny.
    """
    try:
        app_id = _validate_app_id(app_id)
    except ValueError:
        logger.warning("gate: invalid app_id %r rejected (tool=%r)", app_id, tool_name)
        return False

    manifest = _load_manifest(app_id)
    if manifest is None:
        logger.warning("gate: no manifest for %r (tool=%r) — denied", app_id, tool_name)
        return False

    perms: list = manifest.get("permissions", [])
    if not perms:
        logger.warning("gate: empty permissions for %r (tool=%r) — denied", app_id, tool_name)
        return False

    allowed: set = set()
    for perm in perms:
        group = PERMISSION_GROUPS.get(perm)
        if group is not None:
            allowed.update(group)
        else:
            allowed.add(perm)

    if tool_name not in allowed:
        logger.info("gate: %r denied tool %r (permissions=%r)", app_id, tool_name, perms)
        return False

    deny: list = manifest.get("deny_tools") or []
    if not isinstance(deny, list):
        logger.error("gate: malformed deny_tools for %r — denying %r", app_id, tool_name)
        return False
    if tool_name in deny:
        logger.info("gate: %r denied tool %r (deny_tools)", app_id, tool_name)
        return False

    return True


def grove_relay_permitted(app_id: str) -> bool:
    """True only if `app_id`'s manifest explicitly lists the `grove_relay`
    capability (`GROVE_RELAY_PERMISSION`) in its "permissions" — the flag
    that unlocks posting to Grove as a different identity than the caller's
    own resolved `grove_sender`.

    Reuses `permitted()` — the same manifest load/expand/deny-overlay path
    every other gate check goes through — rather than a second read path, so
    this can never drift from what the gate enforces elsewhere. Same pattern
    as the capability checks already in this file (e.g.
    `gate.permitted(app_id, gate.NET_PERMISSION)` in `task_submit`): a
    capability flag is checked with the identical `permitted()` call as a
    tool name, since neither `full_access` nor any other group ever lists it
    (see `GROVE_RELAY_PERMISSION` above — deliberately not a member of
    `grove_write` or `full_access`)."""
    return permitted(app_id, GROVE_RELAY_PERMISSION)
