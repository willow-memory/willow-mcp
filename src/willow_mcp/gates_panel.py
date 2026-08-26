"""willow_mcp/gates_panel.py — every authorization gate, in the egress
lease's shape: on/off, plus how long the "on" is good for.

`lease.py` is the one gate in this codebase with a clock on it — a
`willow-mcp net-status` reader sees "active, expires in 1743s" instead of a
bare boolean. Every other gate (manifest permissions, `task_net`,
`integration_net`, `consent.*`, identity bindings, schema-mapping
confirmation, strict trust root, severance, human-orchestrator attestation)
is a standing boolean
scattered across its own file and its own CLI command or hand-edit, and the
only place that reads all of them together is `diagnostic_summary`'s
problem list — built for "why did a call just fail", not "show me
everything, at a glance, before I start."

This module is that second view. `collect()` builds one `GateRow` per gate
by calling the *same* read functions `diagnostic_summary` already calls —
it adds no new state and changes no enforcement. `render_tui()` and
`render_html()` turn that into a terminal table or a static HTML page,
respectively; both give every "on" gate a countdown-shaped timer field, even
the ones that never expire (labelled `standing`) or that only change at
process start (labelled `process`), because a consistent shape is the point
of showing them together.

**Actionability is deliberately uneven.** A row's `action_cli` is either an
existing operator-only local CLI command (`grant-net`, `revoke-net`,
`confirm-binding`, `worker`) or the new `allow-permission`/`deny-permission`
pair this module's sibling `manifest_admin.py` adds for the one gate that
had no operator affordance before. Gates this process cannot honestly
flip — `consent.*` is read-only in willow-mcp by design (see
`consent.py`'s module docstring: a consumer that writes the policy it is
checked against is not a gate), and `strict_trust_root` / severance /
human-orchestrator attestation are environment variables read once at
process start — carry an `action_note` naming the file or env var to edit
instead, rather than a fake button. Nothing here is an MCP tool; like
`net-status` and `diagnostic_summary`, it is run by the operator on the
host that owns `$WILLOW_HOME`.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

from . import build_lease, consent, gates_html, lease, paths
from .gate import (
    INTEGRATION_NET_PERMISSION,
    MCP_FEDERATION_PERMISSION,
    WEB_NET_PERMISSION,
    NET_PERMISSION,
    PERMISSION_GROUPS,
    _apps_root,
    _load_manifest,
)
from .heartbeat import read_workers
from .human_session import ORCHESTRATOR_APP_ID, human_orchestrator_attested


@dataclass
class GateRow:
    id: str
    #: The real, exact identifier — a permission group name, a manifest
    #: capability, etc. Never change what this holds: gates_actions.py reads
    #: it to know *what to actually toggle* (e.g. which permission string to
    #: pass to manifest_admin.set_permission), and action_cli commands quote
    #: it verbatim. `friendly` below is the display-only translation.
    label: str
    scope: str                       # "global" or an app_id
    state: str                       # "on" | "off" | "warn"
    detail: str
    remaining_seconds: Optional[int] = None
    expires_at: Optional[str] = None
    #: "lease" (has a real deadline) | "standing" (never expires) |
    #: "process" (only changes at process start) | "n/a" (not a grant at all)
    timer_shape: str = "n/a"
    action_cli: Optional[str] = None
    action_note: Optional[str] = None
    #: Plain-language translation of `label`, for someone who doesn't know
    #: what a "manifest permission group" is. Display-only — every renderer
    #: shows this as the heading and `label` as a secondary technical
    #: reference, never the other way around, so `--json`/CLI output stays
    #: exact. Falls back to a humanized version of `label` for anything
    #: `FRIENDLY_LABELS` doesn't yet cover (see `_friendly()`).
    friendly: str = ""
    #: What this row is FOR, not what it's called — "egress" (consent, the
    #: lease, task_net/integration_net), "permissions" (the ~20 routine
    #: manifest groups), "identity" (bindings), or "system" (worker,
    #: strict_trust_root, severance, human_orchestrator). Display-only, used
    #: to group/tab the UI instead of one undifferentiated list — see
    #: `_category()`.
    category: str = ""
    #: What "on"/"off" actually MEANS for this row, in words — a bare ON/OFF
    #: reads the same whether "on" is good news or bad, and a viewer who
    #: doesn't already know this codebase has no way to tell GRANTED from
    #: RUNNING from ALLOWED without reading the detail text. Display-only;
    #: `state` itself (the thing gates_actions.py branches on) never changes.
    state_label: str = ""

    def __post_init__(self) -> None:
        if not self.friendly:
            self.friendly = _friendly(self.label)
        if not self.category:
            self.category = _category(self.id, self.label)
        if not self.state_label:
            self.state_label = _state_label(self.id, self.state)


#: Plain-language translation for every permission group / capability name a
#: `perm.*` row can carry (see `gate.PERMISSION_GROUPS` and the two
#: capability flags). Keyed on the exact string so it stays in sync with
#: whatever gate.py actually grants — a name added there without an entry
#: here just falls back to `_humanize()` rather than erroring.
FRIENDLY_LABELS: dict[str, str] = {
    "store_read": "View saved notes",
    "store_write": "Save and edit notes",
    "store_all": "Full access to saved notes",
    "knowledge_read": "Search what it has learned",
    "knowledge_write": "Teach it new things",
    "knowledge_curate": "Flag or retract bad knowledge",
    "task_queue": "Run tasks",
    "agent_dispatch": "Assign work to helpers",
    "dispatch_read": "See assigned work",
    "dispatch_write": "Assign and complete work",
    "orchestrator": "Direct the whole team",
    "fleet_read": "See the helper team",
    "grove_read": "See fleet chat channels and messages",
    "grove_write": "Post, reply, and flag in fleet chat",
    "grove_all": "Full access to fleet chat",
    "frank_write": "Append to the tamper-evident ledger",
    "tool_oracle_read": "See unanswered tool-routing requests",
    "tool_oracle_route": "Find the right tool from a description",
    "tool_oracle_seal": "Teach it which tool a phrase means",
    "envelope_apply": "Apply a pre-approved authority envelope",
    "envelope_read": "See pre-approved authority envelopes and pending proposals",
    "envelope_write": "Propose, ratify, and reject authority envelopes",
    "envelope_read_discards": "See auto-propose discards (envelopes that failed to file)",
    "context": "Remember short-term notes",
    "audit": "See its own activity log",
    "gap_read": "See open questions",
    "gap_write": "Log and answer open questions",
    "gap_purge": "Bulk-clear a whole topic of open questions",
    "gap_promote": "Make an answer official knowledge",
    "schema_admin": "Configure database field mapping",
    "nest_read": "See what's in the Nest and its review queue",
    "nest_write": "Sort a file dump, file it into place, and promote its structure",
    "commitment_read": "See upcoming commitments and what needs attention",
    "commitment_write": "Record calendar commitments and acknowledge changes",
    "code_graph_read": "Search and trace the code symbol graph",
    "code_graph_write": "Index a repository into the code symbol graph",
    "human_loop_read": "See what needs a human and what's been signed off",
    "human_loop_write": "Flag work for a human and record sign-offs",
    "markdownai_read": "Read and render MarkdownAI documents",
    "markdownai_write": "Write MarkdownAI documents",
    "markdownai_directives": "Run MarkdownAI directives (database/web/env)",
    "fork_read": "List and inspect branch/PR work units",
    "fork_write": "Create, log, merge, and delete work units",
    "lineage_read": "Trace where things came from",
    "lineage_write": "Record where things came from",
    "friction_read": "See relationship-friction flags",
    "friction_write": "Scan a transcript for relationship friction",
    "binding": "Prove which agent is calling (signed check-in)",
    "full_access": "Full access to everything",
    "integration_read": "Check outside-service status",
    "integration_call": "Talk to outside services",
    "web_read": "Search and fetch the open web (guarded)",
    "web_net": "Allow open-web search/fetch for this app",
    "task_net": "Request internet access (for tasks)",
    "integration_net": "Request internet access (for outside services)",
    "federation_read": "See discovered and ratified MCP servers",
    "federation_call": "Call a tool on a ratified downstream MCP server",
    "mcp_federation": "Allow this app to spawn/call downstream MCP servers",
    "consent.internet": "Allow internet access, fleet-wide",
    # cloud_llm is enforced as of 2026-07-28 — model_egress.denial() gates the
    # Nest sinks on it. `consent.lan` was REMOVED 2026-07-29 rather than
    # enforced: it named a confinement the sandbox does not implement, so there
    # is no row for it to label. See consent._REMOVED_KEYS.
    "consent.cloud_llm": "Off-machine AI inference",
    # consent.federation is enforced from introduction — federation_egress.py
    # gates every federated call on it alongside mcp_federation and a live
    # lease. See docs/design/federated-mcp-gating.md Decision 3.
    "consent.federation": "Allow willow-mcp to fork/exec downstream MCP servers",
    "strict_trust_root": "Extra-strict security mode",
    "enforce_binding": "Require signed agent identity (registered agents)",
    "announce": "Announce actions louder for less-trusted callers",
    "severance": "Kept separate from other Willow installs",
    "human_orchestrator": "Requires a human in charge",
    "task worker": "Task runner",
    "egress lease": "Temporary internet access",
}


def _humanize(name: str) -> str:
    """Fallback for any technical name with no entry in FRIENDLY_LABELS:
    snake_case / dotted -> "Title case words". Not a translation, just
    something less alarming than a raw identifier until one is added above."""
    return name.replace("_", " ").replace(".", " ").strip().capitalize()


def _friendly(label: str) -> str:
    return FRIENDLY_LABELS.get(label, _humanize(label))


def _category(row_id: str, label: str) -> str:
    """Which UI group this row belongs to. `task_net`/`integration_net` are
    `perm.*` rows by id shape but belong with the lease and consent — they're
    the capability half of the same egress decision, not routine access
    control — so they're pulled into "egress" by label rather than by id
    prefix alone."""
    if row_id.startswith("binding."):
        return "identity"
    if row_id.startswith("consent.") or row_id.startswith("lease."):
        return "egress"
    if row_id.startswith("build."):
        return "build"
    if row_id.startswith("perm."):
        if label in (NET_PERMISSION, INTEGRATION_NET_PERMISSION, WEB_NET_PERMISSION,
                     MCP_FEDERATION_PERMISSION):
            return "egress"
        return "permissions"
    return "system"  # worker, strict_trust_root, severance, human_orchestrator


#: state_label lookup, keyed by row-id prefix (checked in order) and then
#: by `state`. "warn" isn't universal — only the worker row uses it — so
#: each table only needs the states that row type can actually be in.
_STATE_LABELS: dict[str, dict[str, str]] = {
    "perm.": {"on": "GRANTED", "off": "NOT GRANTED"},
    "consent.": {"on": "ALLOWED", "off": "BLOCKED"},
    "lease.": {"on": "ACTIVE", "off": "NONE"},
    "build.": {"on": "ACTIVE", "off": "NONE"},
    "binding.": {"on": "CONFIRMED", "off": "PENDING"},
    "worker": {"on": "RUNNING", "warn": "STALLED", "off": "STOPPED"},
    "strict_trust_root": {"on": "ENABLED", "off": "DISABLED"},
    "severance": {"on": "ENABLED", "off": "DISABLED"},
    "human_orchestrator": {"on": "ENABLED", "off": "DISABLED"},
}


def _state_label(row_id: str, state: str) -> str:
    for prefix, table in _STATE_LABELS.items():
        if row_id == prefix or row_id.startswith(prefix):
            if state in table:
                return table[state]
            break
    return state.upper()


def list_app_ids() -> list[str]:
    """Every app with a manifest directory — excludes the two reserved
    non-app subtrees `lease.py`/`identity_binding.py` keep under the same root."""
    root = _apps_root()
    if not root.is_dir():
        return []
    skip = {"_net_leases", "_identity_bindings", "_build_leases"}
    return sorted(p.name for p in root.iterdir() if p.is_dir() and p.name not in skip)


def _global_rows() -> list[GateRow]:
    rows: list[GateRow] = []

    c = consent.read_consent()
    disagreeing = set((c.get("disagreement") or {}).get("keys") or [])
    for key in consent.CONSENT_KEYS:
        on = c["consent"].get(key, False)
        detail = f"source={c.get('source')}"
        if key in disagreeing:
            detail += f" — DISAGREES with mirror: {c['disagreement']}"
        rows.append(GateRow(
            id=f"consent.{key}", label=f"consent.{key}", scope="global",
            state="on" if on else "off", detail=detail, timer_shape="standing",
            action_note=(f"read-only in willow-mcp by design — edit "
                         f"{c['canonical_path']} (authored by willow-2.0) "
                         "or use Grove's settings pane"),
        ))

    strict = lease.strict_trust_root()
    rows.append(GateRow(
        id="strict_trust_root", label="strict_trust_root", scope="global",
        state="on" if strict else "off",
        detail="refuses egress when this process can write its own lease/manifest keys",
        timer_shape="process",
        action_note=("set WILLOW_MCP_STRICT_TRUST_ROOT=1 in the server's environment "
                     "and restart — read once at process start"),
    ))

    enforce_binding = os.environ.get("WILLOW_MCP_ENFORCE_BINDING", "").strip().lower() in (
        "1", "true", "yes", "on")
    rows.append(GateRow(
        id="enforce_binding", label="enforce_binding", scope="global",
        state="on" if enforce_binding else "off",
        detail=("registered agents must present a valid signed per-call credential and "
                "clear the trust-tier ceiling; unregistered apps stay manifest-only"
                if enforce_binding else
                "willow-gate binding is observed only — registered agents are logged, "
                "not gated (Phase 2 behavior)"),
        timer_shape="process",
        action_note=("set WILLOW_MCP_ENFORCE_BINDING=1 in the server's environment and "
                     "restart — only after every registered agent's client can sign "
                     "(an un-instrumented client cannot reach a gated tool)"),
    ))

    from . import announce as _announce
    announce_on = _announce.enabled()
    rows.append(GateRow(
        id="announce", label="announce", scope="global",
        state="on" if announce_on else "off",
        detail=(f"graduated announcement volume on the operator log — audit_level="
                f"{_announce.audit_level()} (louder for less-trusted callers; every "
                f"denial/discrepancy escalated)"
                if announce_on else
                "receipt loudness policy off — decisions are logged to the receipt "
                "trail but not announced on the operator channel"),
        timer_shape="process",
        action_note=("set WILLOW_MCP_ANNOUNCE=1 (and optionally "
                     "WILLOW_MCP_AUDIT_LEVEL=minimal) in the server's environment "
                     "and restart"),
    ))

    asserted = paths.severance_asserted()
    rows.append(GateRow(
        id="severance", label="severance", scope="global",
        state="on" if asserted else "off",
        detail=(f"fleet isolation claim — fleet_home={paths.fleet_home()}, "
                f"fleet_pg_db={paths.fleet_pg_db() or None}"
                if asserted else "fleet isolation claim — not asserted, single-trust-domain install"),
        timer_shape="process",
        action_note=("set WILLOW_MCP_FLEET_HOME / WILLOW_MCP_FLEET_PG_DB in the "
                     "server's environment and restart"),
    ))

    attested = human_orchestrator_attested()
    rows.append(GateRow(
        id="human_orchestrator", label="human_orchestrator", scope="global",
        state="on" if attested else "off",
        detail=f"gates dispatch_send/verify_handoff/agent_clear for app_id={ORCHESTRATOR_APP_ID!r}",
        timer_shape="process",
        action_note=("set WILLOW_HUMAN_ORCHESTRATOR=1 in the orchestrator's own MCP "
                     "server env and restart — never on specialist seats"),
    ))

    workers = read_workers()
    alive = workers.get("alive", 0)
    total = len(workers.get("workers", []))
    rows.append(GateRow(
        id="worker", label="task worker", scope="global",
        state="on" if alive else ("warn" if total else "off"),
        detail=(f"{alive} alive / {total} known" +
                ("" if alive else " — nothing will drain task_submit")),
        timer_shape="n/a",
        action_cli=None if alive else "willow-mcp worker --lane fast",
    ))

    return rows


def _app_rows(app_id: str) -> list[GateRow]:
    rows: list[GateRow] = []
    manifest = _load_manifest(app_id)
    perms = set((manifest or {}).get("permissions") or [])

    capability_flags = (NET_PERMISSION, INTEGRATION_NET_PERMISSION, WEB_NET_PERMISSION,
                        MCP_FEDERATION_PERMISSION)
    for group in sorted(PERMISSION_GROUPS) + list(capability_flags):
        on = group in perms
        detail = ("capability flag — see also this app's egress lease below"
                   if group in capability_flags else "manifest permission group")
        rows.append(GateRow(
            id=f"perm.{app_id}.{group}", label=group, scope=app_id,
            state="on" if on else "off", detail=detail, timer_shape="standing",
            action_cli=f"willow-mcp {'deny' if on else 'allow'}-permission {app_id} {group}",
        ))

    lst = lease.read_lease(app_id)
    status = lst["status"]
    if status == "active":
        rows.append(GateRow(
            id=f"lease.{app_id}", label="egress lease", scope=app_id, state="on",
            detail=f"issuer={lst.get('issuer')} reason={lst.get('reason') or '(none)'}",
            remaining_seconds=lst["remaining_seconds"], expires_at=lst["expires_at"],
            timer_shape="lease", action_cli=f"willow-mcp revoke-net {app_id}",
        ))
    else:
        detail = {
            "none": "no lease on disk", "expired": "expired",
            "malformed": lst.get("error", "malformed"),
            "mismatch": lst.get("error", "app_id mismatch"),
        }.get(status, status)
        rows.append(GateRow(
            id=f"lease.{app_id}", label="egress lease", scope=app_id, state="off",
            detail=detail, timer_shape="lease",
            action_cli=f'willow-mcp grant-net {app_id} --ttl 30m --reason "..."',
        ))

    return rows


def _binding_rows() -> list[GateRow]:
    rows: list[GateRow] = []
    root = paths.identity_bindings_dir()
    if not root.is_dir():
        return rows
    for f in sorted(root.glob("*.json")):
        try:
            record = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue  # a torn or hand-mangled file is not a binding
        confirmed = bool(record.get("confirmed"))
        detail = f"subject={record.get('subject_id')} email={record.get('email')}"
        if record.get("email_drift"):
            detail += " — EMAIL DRIFT, verify before trusting"
        # `idp` since the rename; `issuer` on records written before it. This
        # panel reads binding files straight off disk rather than through
        # identity_binding.load_binding, so it needs the fallback itself —
        # otherwise every pre-rename binding renders "via None".
        idp = record.get("idp") or record.get("issuer")
        rows.append(GateRow(
            id=f"binding.{f.stem}", label=f"identity binding ({idp})",
            friendly=f"Signed-in account (via {idp})",
            scope=record.get("app_id") or "(unbound)",
            state="on" if confirmed else "off", detail=detail, timer_shape="standing",
            action_cli=(None if confirmed else
                        f"willow-mcp confirm-binding --idp {idp} "
                        f"--subject {record.get('subject_id')} --app-id <app_id>"),
        ))
    return rows


def _build_lease_rows() -> list[GateRow]:
    """One row per earn-first tool family, plus any lease outside the roster.

    Same shape as `_app_rows`'s lease row — a "lease" timer_shape with a real
    deadline when active, an `action_cli` pointing at `grant-build` when not.
    A lease held on a family not in `EARN_FIRST_ROSTER` is still surfaced;
    silent invisibility is what a status readout must not do.
    """
    rows: list[GateRow] = []
    on_disk = {row["tool"]: row for row in build_lease.list_leases()}
    seen: set[str] = set()

    def _row(family: str, blurb: str) -> GateRow:
        lst = on_disk.get(family)
        if lst is None:
            return GateRow(
                id=f"build.{family}", label="build lease", scope=family,
                friendly=f"Build {family}", state="off",
                detail=f"{blurb} — no lease on disk (family is 'dry')",
                timer_shape="lease",
                action_cli=f'willow-mcp grant-build {family} --ttl 30m --reason "..."',
            )
        status = lst["status"]
        if status == "active":
            return GateRow(
                id=f"build.{family}", label="build lease", scope=family,
                friendly=f"Build {family}", state="on",
                detail=f"{blurb} — issuer={lst.get('issuer')} "
                       f"reason={lst.get('reason') or '(none)'}",
                remaining_seconds=lst["remaining_seconds"],
                expires_at=lst["expires_at"], timer_shape="lease",
                action_cli=f"willow-mcp revoke-build {family}",
            )
        detail = {
            "expired": f"{blurb} — expired",
            "malformed": f"{blurb} — {lst.get('error', 'malformed')}",
            "mismatch": f"{blurb} — {lst.get('error', 'tool name mismatch')}",
        }.get(status, f"{blurb} — {status}")
        return GateRow(
            id=f"build.{family}", label="build lease", scope=family,
            friendly=f"Build {family}", state="off",
            detail=detail, timer_shape="lease",
            action_cli=f'willow-mcp grant-build {family} --ttl 30m --reason "..."',
        )

    for family, blurb in build_lease.EARN_FIRST_ROSTER:
        rows.append(_row(family, blurb))
        seen.add(family)

    # Anything the operator granted on a family not yet in the roster still
    # appears — the earn-check CLI treats these as "extras" for the same
    # reason.
    for extra in sorted(set(on_disk) - seen):
        rows.append(_row(extra, "(not in EARN_FIRST_ROSTER — one-off grant)"))

    return rows


def collect(app_id: str = "") -> list[GateRow]:
    """Every gate row. Pass `app_id` to scope the per-app rows to one app;
    omit it to show every app under `mcp_apps/`."""
    rows = _global_rows() + _binding_rows() + _build_lease_rows()
    for a in ([app_id] if app_id else list_app_ids()):
        rows.extend(_app_rows(a))
    return rows


# ── rendering ────────────────────────────────────────────────────────────────

_ANSI = {"on": "\033[97;42m", "off": "\033[97;41m", "warn": "\033[30;43m", "reset": "\033[0m"}


#: Display order and heading for each category — egress first (the one
#: with a clock and the most consequence), permissions last (the long,
#: mostly-boring routine-access list nobody needs to see before anything
#: else). Both renderers (TUI, HTML) iterate this instead of a flat list.
CATEGORY_ORDER: list[tuple[str, str]] = [
    ("egress", "Egress & network"),
    ("build", "Earn-first build leases"),
    ("system", "System"),
    ("identity", "Identity"),
    ("permissions", "Permissions"),
]


def group_by_category(rows: list[GateRow]) -> list[tuple[str, str, list[GateRow]]]:
    """Rows bucketed into CATEGORY_ORDER, skipping empty categories."""
    buckets: dict[str, list[GateRow]] = {key: [] for key, _ in CATEGORY_ORDER}
    for r in rows:
        buckets.setdefault(r.category, []).append(r)
    return [(key, title, buckets[key]) for key, title in CATEGORY_ORDER if buckets[key]]


def _timer_text(row: GateRow) -> str:
    if row.timer_shape == "lease":
        if row.remaining_seconds and row.remaining_seconds > 0:
            h, rem = divmod(row.remaining_seconds, 3600)
            m, s = divmod(rem, 60)
            return f"expires in {h}h{m:02d}m{s:02d}s" if h else f"expires in {m}m{s:02d}s"
        return "no active grant"
    if row.timer_shape == "standing":
        return "standing — no expiry"
    if row.timer_shape == "process":
        return "process-lifetime — restart to change"
    return "—"


def render_tui(rows: list[GateRow], color: bool = True) -> str:
    lines = ["willow-mcp gates — every authorization gate, egress-lease shaped\n"]
    if not rows:
        return "\n".join(lines) + "(nothing to show)"

    scope_w = max(len(r.scope) for r in rows)
    label_w = max(len(r.friendly) for r in rows)
    timer_w = max(len(_timer_text(r)) for r in rows)
    button_w = max(len(r.state_label) for r in rows)
    indent = button_w + 3  # matches the "[BUTTON] " prefix width, for action lines

    for key, title, group in group_by_category(rows):
        lines.append(f"\n== {title} " + "=" * max(1, 60 - len(title)))
        for r in group:
            button = r.state_label.center(button_w)
            if color:
                button = f"{_ANSI.get(r.state, '')}{button}{_ANSI['reset']}"
            lines.append(
                f"[{button}] {r.scope:<{scope_w}}  {r.friendly:<{label_w}}  "
                f"{_timer_text(r):<{timer_w}}  {r.label} — {r.detail}"
            )
            if r.action_cli:
                lines.append(f"{'':>{indent}}-> {r.action_cli}")
            elif r.action_note:
                lines.append(f"{'':>{indent}}-> {r.action_note}")
    return "\n".join(lines)


_BODY_SCRIPTS_TEMPLATE = """
const ROWS = __ROWS_JSON__;
const GENERATED_AT = __GENERATED_AT_JSON__;

function elapsedSeconds() {
  return Math.floor((Date.now() - Date.parse(GENERATED_AT)) / 1000);
}

renderDashboard(ROWS, elapsedSeconds);
setInterval(() => renderDashboard(ROWS, elapsedSeconds), 1000);
"""


def render_html(rows: list[GateRow], generated_at: str) -> str:
    rows_payload = [
        {
            "id": r.id, "label": r.label, "friendly": r.friendly, "category": r.category,
            "state": r.state, "state_label": r.state_label, "scope": r.scope,
            "detail": r.detail, "remaining_seconds": r.remaining_seconds,
            "timer_shape": r.timer_shape, "action_cli": r.action_cli,
            "action_note": r.action_note,
        }
        for r in rows
    ]
    # json.dumps output is safe to inline in a <script> block except for the
    # literal substring "</script>", which would close the tag early.
    rows_json = json.dumps(rows_payload).replace("</script>", "<\\/script>")
    body_scripts = (
        _BODY_SCRIPTS_TEMPLATE
        .replace("__ROWS_JSON__", rows_json)
        .replace("__GENERATED_AT_JSON__", json.dumps(generated_at))
    )
    return gates_html.page(
        title="willow-mcp gates",
        subtitle='Every authorization gate, shown the way the egress lease already shows '
                 'itself — on/off, plus how long the "on" is good for. Generated once; '
                 're-run <code>willow-mcp gates --html</code> for fresh state. Countdown '
                 'timers tick client-side from the moment this file was generated.',
        top_extra="",
        body_scripts=body_scripts,
    )
