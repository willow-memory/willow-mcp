# willow_mcp/tier_policy.py — the trust-tier ceiling over the manifest ACL.
#
# Phase 3 of the willow-gate seam (docs/design/willow-gate-seam.md §2, D1). The
# manifest ACL (gate.permitted) says what an app *may* hold; the tier ceiling
# says what its *bound trust level* may exercise. Effective authorization is the
# intersection:
#
#     effective = expand(manifest.permissions) ∩ unlocked_tools(trust_level)
#
# This module is the second half — a pure, deterministic map from a willow-gate
# trust level (0..4) to the willow-mcp tools that level unlocks. It holds no
# secrets and makes no I/O; the security is the HMAC binding in session_binder,
# not this table. This just answers "given a *verified* tier, is this tool within
# reach?" so gate._gate can apply the ceiling after permitted() passes.
#
# Invariants carried from the seam doc:
#   * tiers unlock CLASSES cumulatively — read ⊆ +write ⊆ +execute ⊆ +admin;
#   * `admin` ≠ sudo: it reaches schema/gap-promote/purge, never authority
#     (minting manifests/secrets/tiers stays CLI-only, not a tool at any tier);
#   * egress stays DOUBLE-gated: integration_call (and the task_net capability)
#     need `execute` AND a non-read-only tier AND the manifest's own-line grant —
#     the tier never softens the existing own-line egress rule;
#   * classification is COMPLETE and tested (test_tier_policy) so a tool added to
#     a permission group can't silently escape or over-restrict the ceiling.
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Coarse willow-gate classes, ordered by privilege. `query` is deliberately a
# synonym for `read` here: willow-mcp has no capability that is "query but not
# read" (store_scope already confines breadth), so Veteran's real gain over
# Steady is `execute`, not `query`. Kept as a named rung for when a genuinely
# broad/expensive discovery tool warrants its own class (seam-doc D1).
READ, QUERY, WRITE, EXECUTE, ADMIN = "read", "query", "write", "execute", "admin"

# Per-TOOL class — the source of truth. Classifying at the tool level (rather
# than by permission-group membership) avoids the multi-group ambiguity a tool
# like agent_seed_mirror creates (it sits in both a read and a write group) and
# is directly auditable. Every @_guarded tool in server.py must appear here; the
# completeness test fails if one is added to a group without a class.
TOOL_CLASS: dict[str, str] = {
    # ── read ────────────────────────────────────────────────────────────────
    "store_get": READ, "store_search": READ, "store_list": READ,
    "store_search_all": READ, "store_collections": READ, "store_stats": READ,
    "knowledge_search": READ, "kb_at": READ, "kb_startup_continuity": READ,
    "knowledge_verify": READ, "knowledge_check": READ,
    "gap_list": READ,
    "dispatch_read": READ, "dispatch_list": READ, "handoff_read": READ,
    "session_read": READ, "session_enter": READ,
    "sessions_read_unverifiable": READ,
    "envelope_list": READ, "envelope_pending_read": READ,
    "envelope_read_discards": READ,
    "envelope_propose": WRITE, "envelope_ratify": WRITE, "envelope_reject": WRITE,
    "specialist_list": READ, "specialist_get": READ,
    "exposure_config_get": READ, "exposure_slice": READ,
    "fleet_status": READ, "fleet_health": READ, "frank_read": READ,
    "frank_verify": READ,
    "integration_list": READ, "integration_status": READ,
    # Federated MCP inventory — discovery (shadow-IT scan) and the ratified
    # server list are both read-only, no subprocess spawned.
    "federation_discover": READ, "federation_list_servers": READ,
    "receipts_tail": READ,
    "lineage_why": READ, "lineage_list": READ,
    "friction_flags_list": READ,
    "session_bind": READ, "session_reconcile": READ,
    "context_get": READ, "context_list": READ,
    "nest_status": READ, "nest_digest": READ,   # digest is the walled view
    "nest_intake_queue": READ, "nest_intake_flags": READ,
    # Commitment membrane: surface (dew rule) + facts-only list are read-only views.
    "commitment_surface": READ, "commitment_list": READ,
    # code_graph: querying the symbol graph is read-only (no store/KB, no network).
    "code_graph_search": READ, "code_graph_explain": READ, "code_graph_walk": READ,
    "code_graph_suggest": READ, "code_graph_impact": READ,
    # Human-loop: listing the queue and attestations are read-only views.
    "human_required_list": READ, "human_attestation_list": READ,
    "fork_list": READ, "fork_status": READ, "env_check": READ,
    # ── write ───────────────────────────────────────────────────────────────
    "store_put": WRITE, "store_update": WRITE, "store_delete": WRITE,
    "store_purge_collection": WRITE,          # reversible + confirm-guarded — stays write (D1)
    "agent_seed_mirror": WRITE,
    "knowledge_ingest": WRITE, "kb_ingest": WRITE, "kb_journal": WRITE,
    "kb_promote": WRITE, "knowledge_flag": WRITE, "knowledge_retract": WRITE,
    "gap_log": WRITE, "gap_resolve": WRITE, "gap_delete": WRITE,
    "dispatch_send": WRITE, "dispatch_accept": WRITE, "handoff_write_v4": WRITE,
    "verify_handoff": WRITE, "agent_clear": WRITE, "session_handoff_write": WRITE,
    "lineage_record": WRITE, "lineage_link": WRITE,
    "friction_scan": WRITE,
    # nestor_tool_route persists a ledger passage + teach-queue entry; seal writes
    # a verified pair; pending is a pure read. (docs/design/nestor-tool-route.md)
    "nestor_tool_route": WRITE, "nestor_tool_seal": WRITE, "nestor_tool_pending": READ,
    "context_save": WRITE, "context_expire": WRITE,
    "frank_append": WRITE,
    # nest_scan writes a local SQLite Nest DB; nest_promote writes structure-only
    # atoms to the KB — same class as knowledge_ingest/kb_promote (its own
    # permission group handles grant hygiene, not the tier ceiling).
    "nest_scan": WRITE, "nest_promote": WRITE,
    # router: scan stages the queue, file moves the host file, skip records it
    "nest_intake_scan": WRITE, "nest_intake_file": WRITE, "nest_intake_skip": WRITE,
    # Commitment membrane: ingest writes the ledger (facts only), acknowledge appends
    # a history entry. Neither writes the calendar back — no new authority — so they
    # are ordinary WRITEs, not EXECUTE (their own permission group handles egress-free
    # hygiene, not the tier ceiling).
    "commitment_ingest": WRITE, "commitment_acknowledge": WRITE,
    # code_graph_index builds a local SQLite graph of a repo on disk — a local write,
    # like nest_scan; no network, so WRITE not EXECUTE.
    "code_graph_index": WRITE,
    # Human-loop writes: enqueue/resolve queue items, create an attestation. Store
    # writes, no egress — WRITE.
    "human_required_enqueue": WRITE, "human_required_resolve": WRITE,
    "human_attestation_create": WRITE,
    # ── execute ─────────────────────────────────────────────────────────────
    "task_submit": EXECUTE, "task_status": EXECUTE, "task_list": EXECUTE,
    "agent_route": EXECUTE, "agent_dispatch_result": EXECUTE,
    "integration_call": EXECUTE,              # export-gated (see EGRESS_TOOLS)
    "willow_web_search": EXECUTE, "willow_web_fetch": EXECUTE,
    "willow_institutional_search": EXECUTE,   # export-gated (see EGRESS_TOOLS)
    "federation_call": EXECUTE,               # export-gated (see EGRESS_TOOLS); fork/exec at server uid
    "fork_create": WRITE, "fork_join": WRITE, "fork_log": WRITE,
    "fork_merge": WRITE, "fork_delete": WRITE,
    "envelope_apply": EXECUTE,
    # ── admin (never sudo) ────────────────────────────────────────────────────
    "schema_confirm_mapping": ADMIN, "gap_purge_topic": ADMIN, "gap_promote": ADMIN,
}

# Tools whose whole purpose is server-process / sandbox egress. Unlocked by the
# `execute` class ONLY on a non-read-only tier, and still require the manifest's
# own-line grant (task_net / integration_call are excluded from full_access on
# purpose). The tier is a *third* gate, never a replacement for the own-line one.
EGRESS_TOOLS: frozenset = frozenset({
    "integration_call", "willow_web_search", "willow_web_fetch",
    "willow_institutional_search", "federation_call",
})

# Cumulative class sets by trust level. Mirrors session_binder.TRUST_LEVELS:
#   0 Exiled (read_only, entry denied)  1 Rookie (read_only)
#   2 Steady                            3 Veteran            4 Elder
_TIER_CLASSES: dict[int, frozenset] = {
    0: frozenset(),                                   # Exiled — entry_allowed=False upstream
    1: frozenset({READ, QUERY}),                      # Rookie — read only
    2: frozenset({READ, QUERY, WRITE}),               # Steady
    3: frozenset({READ, QUERY, WRITE, EXECUTE}),      # Veteran
    4: frozenset({READ, QUERY, WRITE, EXECUTE, ADMIN}),  # Elder
}

# Which trust levels are read-only (write/execute/admin stripped even if the
# class map somehow lists them) — belt-and-suspenders mirror of TRUST_LEVELS.
_READ_ONLY_LEVELS: frozenset = frozenset({0, 1})


def classify(tool_name: str) -> str | None:
    """The privilege class of a guarded tool, or None if it isn't classified
    (an ungated helper like whoami/diagnostic_summary — the ceiling ignores it)."""
    return TOOL_CLASS.get(tool_name)


def tier_permits(trust_level: int, tool_name: str, *, read_only: bool | None = None) -> bool:
    """True if a *verified* trust level may exercise `tool_name`.

    A tool with no class (not in TOOL_CLASS) is not something the ceiling
    governs — return True and let the manifest ACL be the only word on it. All
    @_guarded tools are classified (test-enforced), so in practice this only
    waves through genuinely ungated helpers.

    `read_only` overrides the level's default read-only flag when the caller
    already knows it (from the bound session); otherwise it's derived from the
    level. A read-only tier is capped at read/query no matter its number.
    """
    cls = TOOL_CLASS.get(tool_name)
    if cls is None:
        return True
    try:
        level = int(trust_level)
    except (TypeError, ValueError):
        return False
    classes = _TIER_CLASSES.get(level, frozenset())
    if cls not in classes:
        return False
    ro = read_only if read_only is not None else (level in _READ_ONLY_LEVELS)
    if ro and cls in (WRITE, EXECUTE, ADMIN):
        return False
    # Egress stays double-gated on the tier axis: never from a read-only tier.
    # (The manifest own-line grant + consent + lease are checked elsewhere.)
    if tool_name in EGRESS_TOOLS and ro:
        return False
    return True


def unlocked_tools(trust_level: int, *, read_only: bool | None = None) -> frozenset:
    """The full set of classified tools this trust level may exercise."""
    return frozenset(
        t for t in TOOL_CLASS if tier_permits(trust_level, t, read_only=read_only)
    )


def classes_for_tier(trust_level: int) -> frozenset:
    """The privilege CLASSES a tier unlocks — the willow-gate vocabulary, not the
    tool names. `unlocked_tools` answers "which tools"; this answers "which
    classes", which is what a check-in header declares in its `tools` field.

    Unknown levels return the empty set rather than raising: the ceiling is a
    fail-closed lookup everywhere else in this module, and a caller building a
    declaration from a bad level should declare nothing, not crash.
    """
    return _TIER_CLASSES.get(trust_level, frozenset())
