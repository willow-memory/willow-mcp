"""willow-mcp Claude Code hook — PreToolUse.

Ten guards:
- The willow seat does not use Shell (2026-09-14, gap 715d89fe3c90): for the
  human-orchestrator seat every Bash command is blocked, and the refusal
  names the fleet tool that replaces it — Read / search_code / detect_changes
  for reads, task_submit for execution, git_push_execute / pr_open_execute /
  git_pull_execute for the git acts that leave the box. Specialist seats are
  not affected; they keep the routing table below (blocks).
- Bash reaching for raw psql/psycopg2/sqlite3 against a database or store
  willow-mcp owns, instead of going through the MCP tools (blocks).
- A Write/Edit/MultiEdit whose target file *is* a willow-mcp-owned SQLite
  store (store.db/vault.db/kart.db/mcp_receipt.db) — the non-Bash path to the
  same crossing: no DB client is invoked at all, so the raw-client scan above
  never sees it (blocks).
- In Claude Code remote sessions (#164): when SessionStart recorded no live MCP
  gate, bare psql/sqlite3/curl are blocked outright (not merely redirected).
- Bash habits that duplicate MCP tools or Kart's sandboxed execution —
  filesystem reads (ls/grep/find/cat), git/gh mutation, python heredoc,
  raw network egress (curl/wget/pip/npm/ssh/scp), background/detached
  processes (nohup/disown/trailing `&`), bare script/build execution
  (python/node scripts, make), and bulk filesystem mutation (mkdir/rm/mv/
  cp/chmod/tar) — warn or block with redirect hints (trimmed from fleet
  mcp_routing).
- task_submit calls that hand-embed a Kart network directive (`# allow_net`
  / `# allow_localhost`) in the task text — the server strips these (B-21),
  so it does nothing; the correct path is allow_net=True + the task_net
  permission (warns).
- The IDE-native web tools, now that `willow_web_*` ships: WebSearch and
  WebFetch are blocked with a redirect, so a fetch goes through the seat that
  records it rather than around it (blocks). Wired by its own
  `WebSearch|WebFetch` matcher in deploy/claude-settings.json.
- Corpus-first (gap corpus-first-jeles-nestor / 38a0351f2527): a seat about to
  search the web — native WebSearch or the governed willow_web_search, the
  tool the guard above redirects native traffic onto — is reminded to try the
  fleet's own verified organs first (knowledge_search, the jeles-corpus
  federation, nestor for a sealed answer) and to say which tier answered.
  Composes with the guard above rather than replacing it: on native
  WebSearch, which is hard-blocked, the reminder is appended to that same
  block; on a direct willow_web_search call it is the sole decision, and it
  is always a warn — the corpus can miss, and web is then a fine, if
  unverified, fallback (warns/composes, never blocks on its own).
- Any tool call that would write the keys authorizing this agent's own egress
  or re-grant its own write seat: minting a lease under `mcp_apps/_net_leases/`,
  running `willow-mcp grant-net` or `dev-net` (the local/dev one-command
  convenience that grants the same three keys — #287; via Bash *or* smuggled
  into Kart task text), running `willow-mcp allow-permission` to grant an egress
  capability, the Grove relay capability, or a write-capable group (that CLI
  edits the manifest the path-keyed guard below never sees — #304), or editing
  a manifest to add an egress capability (`task_net` / `integration_net` /
  `web_net` / `mcp_federation`), the Grove relay capability (`grove_relay`), or
  any write-capable permission group (blocks).
- Spawn guard (sealed rule c9ca1a09, pair 72f528ab / record b4a8cbe7, gap
  20e6d23971dc): the harness `Agent` tool, when the spawn prompt OR
  description names a fleet seat by ENTERING it — `session_enter(app_id=
  "<seat>"`, a case-insensitive `app_id`/`APP_ID`/JSON `"app_id": "<seat>"`
  shape (straight or curly quotes), "You are <Display name>" / "You're
  <Display name>" / "Enter as <Display name>" framing (markdown-bolded or
  not), `<Display name>,` opening the text, or a `personas/<seat>.md`
  reference. A bare `app_id=<seat>` that appears only as an argument to a
  read-only lookup call (`handoff_read`, `dispatch_read`, `session_read`,
  `store_get`, …) is a MENTION, not an entry, and is not matched. The
  orchestrator seat (`willow`) is a spawn target only under the two
  strongest framings (`session_enter(` or a "You are"/"You're"/"Enter as"
  sentence) — a bare `app_id=willow` mention inside a lookup never refuses a
  non-seat spawn. Any other named seat whose role appears in
  `specialists.json`'s `model_hint_session` field (the same field the
  fleet's "no self-assigned models" guarantee already names — one source,
  not a second table) must be spawned with `model=` set to that role's
  pinned value — missing or mismatched blocks. `subagent_type="fork"`
  (matched case-insensitively) is refused for ANY named seat regardless of
  the table, since a fork inherits the caller's model and cannot carry a
  pin. A prompt/description naming no known seat (Explore, Plan, a plain
  general-purpose spawn) is untouched. Cursor dialect is explicitly out of
  scope for this one guard (see check_agent_spawn's docstring) — the other
  nine guards above are unaffected (blocks; see check_agent_spawn).

That egress-keys guard above (bullet 9) is the sudo invariant (FRANK `90e52ab7`) enforced where the
agent actually acts: *a model may REQUEST egress, never CONFIRM it.* It is a
guardrail, not a control — a hook lives in the agent's own harness and an agent
that bypasses it faces no OS-level obstacle on a single-uid host. The control is
`chown` plus `WILLOW_MCP_STRICT_TRUST_ROOT` (B-32). This makes the boundary
visible at the moment it would be crossed, which is where a mistake gets caught
and where a deliberate crossing stops being deniable.

See docs/design/hooks-and-skills.md §4 for the design and scope.

Protocol: reads a JSON object from stdin
({"tool_name": ..., "tool_input": {...}, "session_id": ...}), optionally
prints a JSON decision to stdout ({"decision": "block"|"warn", "reason":
"..."}), always exits 0 — the decision is the printed JSON, not the exit
code. No output means allow, no comment.
"""
import json
import os
import re
import shlex
import sys
from typing import Optional

# Shared reason-string constants live in hooks/_constants.py so the federation
# server id, the verified-organs ladder, and the brokered-push hint don't drift
# between this file and the bundle twin at src/willow_mcp/bundle/hooks/. The
# hook is invoked as a script (python3 ${CLAUDE_PLUGIN_ROOT}/hooks/…) so the
# hooks/ directory is not on sys.path by default; add it before importing.
_HOOK_DIR = os.path.dirname(os.path.abspath(__file__))
if _HOOK_DIR not in sys.path:
    sys.path.insert(0, _HOOK_DIR)
from _constants import (  # noqa: E402
    JELES_FEDERATION_SERVER,
    WEB_ORDER,
    GIT_PUSH_HINT,
)

# Matches a shell client (psql, or a python -c reaching for psycopg2/sqlite3)
# together with something naming a willow-mcp-owned store: the WILLOW_PG_DB/
# WILLOW_STORE_ROOT env var names themselves, or the literal table/path
# willow-mcp creates (knowledge, records, mcp_receipt.db). A bare `sqlite3`
# or `psql` invocation with no such marker isn't ours to block — the host
# may have unrelated databases.
# Known limits (this is a tripwire, not an OS control — see module docstring):
# it catches shell-native access via a named client to a marker-bearing target.
# It does NOT catch a write performed inside a `python -c` one-liner (no client
# token / no shell write-verb), an owned store reached by a bare absolute path
# whose collection isn't named knowledge/records, or a DB client not listed
# below. The real control is `chown` + WILLOW_MCP_STRICT_TRUST_ROOT (B-32).
_CLIENT_RE = re.compile(r"\b(psql|psycopg[23]?|asyncpg|pg8000|sqlite3)\b")
_OWNED_MARKER_RE = re.compile(
    r"WILLOW_PG_DB|WILLOW_STORE_ROOT|\bknowledge\b|\brecords\b"
    r"|(?:mcp_receipt|vault|kart|store)\.db"
)

# The non-Bash path to the same crossing: a Write/Edit/MultiEdit whose target
# file *is* one of willow-mcp's own SQLite stores. No DB client is invoked —
# the tool overwrites the file's bytes directly — so _CLIENT_RE above, which
# only scans command-line/script text for a client invocation, never sees
# this at all. Matched on the filename itself (path-separator- or
# start-anchored, so "backup_store.db" doesn't false-positive on "store.db"),
# not a resolved real path: a relative or symlinked target is still this file
# by the name a human/agent would recognize it under.
_OWNED_DB_FILE_RE = re.compile(r"(?:^|[/\\])(?:mcp_receipt|vault|kart|store)\.db$")

_TOOL_REDIRECTS = {
    "knowledge": "knowledge_search / kb_at / kb_startup_continuity (read) or "
                  "knowledge_ingest / kb_journal / kb_promote (write, requires "
                  "schema_confirm_mapping first) or knowledge_flag / "
                  "knowledge_retract (knowledge_curate)",
    "records": "store_get / store_list / store_search / store_search_all (read) or "
               "store_put / store_update / store_delete (write)",
}

_TASK_SUBMIT = "task_submit(app_id=..., task='…')"
_TASK_SUBMIT_NET = "task_submit(app_id=..., task='…', allow_net=True)"
# Brokered push (operator-ruling-2026-09-10-kart-push-is-brokered / KB 482AE83A):
# Kart or the seat *initiates*; willow-mcp holds the credential and runs git.
# willow-bot App installation tokens are the APK path (gap 5ecb87cfdf56).
# GIT_PUSH_HINT (hooks/_constants.py) is the fuller reason string that also
# names the broker and the willows-bot token; _GIT_PUSH_EXECUTE below is kept
# as the tight call-shape callers pattern-match on.
_GIT_PUSH_EXECUTE = "git_push_execute(app_id=..., repo='org/name', branch=..., remote='origin')"

# Read-only git/gh — allowed on the operator desk (no Kart round-trip).
_GIT_INSPECT_RE = re.compile(
    r"(?:^|&&\s*)git(?:\s+-C\s+\S+)?\s+"
    r"(status|log|diff|show|branch|rev-parse|describe|shortlog|remote|fetch)\b",
    re.IGNORECASE,
)
_GH_INSPECT_RE = re.compile(
    r"(?:^|&&\s*)gh\s+"
    r"(pr\s+(view|list|checks|status|diff)|issue\s+(view|list)|run\s+list|repo\s+view)\b",
    re.IGNORECASE,
)
_GIT_MUTATION_RE = re.compile(
    r"\bgit(?:\s+-C\s+\S+)?\s+"
    r"(add|commit|push|pull|merge|rebase|checkout|switch|restore|reset|clean|"
    r"clone|cherry-pick|revert|stash|tag|worktree\s+(add|remove)|am)\b",
    re.IGNORECASE,
)
_GH_MUTATION_RE = re.compile(
    r"\bgh\s+"
    r"(pr\s+(create|merge|close|ready|review|edit)|issue\s+create|"
    r"repo\s+create|release\s+create)\b",
    re.IGNORECASE,
)

# The willow human-orchestrator seat. Since 2026-09-14 this seat does not use
# Shell at all — see check_seat_shell: reads go through Read and the code
# graph, execution through task_submit, and git through the broker verbs.
# (Before that date the seat was EXEMPT from the git/gh routing below, on the
# reasoning that repo maintenance is its job; the broker verbs made that
# reasoning obsolete and the operator retired the exemption.) The self-grant
# guard (egress keys, leases, manifest task_net) runs BEFORE routing and is
# NEVER lifted. The signal is the server env the SessionStart hook exports
# into the session (.mcp.json / CLAUDE_ENV_FILE).
_ORCHESTRATOR_APP_ID = "willow"

# git/gh routing entries for specialist seats. Push is always steered (broker).
_ROUTE_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b")
_ROUTE_GIT_PULL_RE = re.compile(r"\bgit\s+pull\b")
_ROUTE_GIT_MUT_RE = re.compile(
    r"\bgit\s+(add|commit|checkout|merge|rebase|worktree|clone|stash|reset|"
    r"restore|switch|clean|cherry-pick|revert|tag)\b")
_ROUTE_GH_RE = re.compile(r"\bgh\s")
# Long-running steward loop belongs on a tracked worker, not the agent Shell.
_ROUTE_WILLOW_BOT_STEWARD_LOOP_RE = re.compile(
    r"(?:^|&&|;|\|)\s*willow-bot-steward\s+loop\b"
)
# Kart (task_submit) is the sandboxed, tracked execution surface — anything
# below reaches the network, backgrounds/detaches a process, or mutates the
# filesystem in bulk, all outside that tracking, when run raw in this Bash
# tool. Anchored to command position (start, or after &&/;/|) so a command
# that merely *names* the verb — a commit message, an echo, a --reason
# string — is not caught; only an actual invocation is.

# curl/wget duplicate willow_web_fetch (the guarded, recorded fetch path) —
# same relationship as the native WebFetch tool check_native_web blocks.
# End-anchored on (\s|$), not \b: a bare \b also fires between a word char
# and a following '.', so \bmake\b would match the *filename* make.py — the
# same class of false positive ls/tree/pwd already guard against below.
_ROUTE_WEB_FETCH_RE = re.compile(r"(?:^|&&|;|\|)\s*(curl|wget)(?:\s|$)")
# Installing a dependency reaches the package registry over the network —
# the same crossing as `git push`, just a different verb.
_ROUTE_PKG_INSTALL_RE = re.compile(
    r"(?:^|&&|;|\|)\s*(pip3?\s+install(?:\s|$)|npm\s+install(?:\s|$)|npm\s+i\s|"
    r"yarn\s+add(?:\s|$)|poetry\s+add(?:\s|$)|uv\s+add(?:\s|$)|uv\s+pip\s+install(?:\s|$))"
)
_ROUTE_REMOTE_RE = re.compile(r"(?:^|&&|;|\|)\s*(ssh|scp)(?:\s|$)")
# A process backgrounded/detached in the agent's own Bash tool is invisible
# to everything else in the session; Kart tracks async work instead. The
# trailing bare `&` is negative-lookbehind-guarded so `a && b` (command
# chaining) doesn't trip it — only an actual backgrounding `&` at end-of-command.
_ROUTE_BACKGROUND_RE = re.compile(
    r"(?:^|&&|;|\|)\s*(nohup|setsid)(?:\s|$)|\bdisown\b|(?<!&)&\s*$"
    r"|\bscreen\s+-dm\b|\btmux\s+new-session\s+-d\b"
)
_ROUTE_SCRIPT_RE = re.compile(
    r"(?:^|&&|;|\|)\s*(?:python3?|node)\s+(?:-\S+\s+)*\S+\.(?:py|js|mjs|ts)\b"
    r"|(?:^|&&|;|\|)\s*make(?:\s|$)"
)
_ROUTE_FS_MUTATE_RE = re.compile(
    r"(?:^|&&|;|\|)\s*(mkdir|rm|mv|cp|chmod|chown|tar)(?:\s|$)"
)

# Shell habits → (decision, hint). Trimmed product port of fleet mcp_routing.BASH_TO_MCP.
_BASH_ROUTING: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^\s*ls(\s|$)"), "warn",
     f"store_list / store_search for Willow data · filesystem → {_TASK_SUBMIT}"),
    (re.compile(r"^\s*(cat|head|tail)\s"), "warn",
     "Use the IDE Read tool for repo files · shell-only paths → task_submit"),
    # Anchored to command position (start, or after &&/;/|) so a command that
    # merely *names* psql/sqlite3 — a commit message, an echo, a --reason string
    # — is not blocked; only an actual invocation is. (The raw-store block in
    # check_bash is the real guard; this is the prefer-MCP nudge.)
    (re.compile(r"(?:^|&&|;|\|)\s*psql\b"), "block",
     "knowledge_search / store_search — Postgres via MCP, not shell"),
    (re.compile(r"(?:^|&&|;|\|)\s*sqlite3\b"), "block",
     "store_get / store_list / store_search — SQLite store via MCP"),
    (re.compile(r"^\s*pwd\s*$"), "warn", "cwd is in context; fleet_status for roots"),
    (re.compile(r"^\s*tree(\s|$)"), "warn", f"directory tree → {_TASK_SUBMIT}"),
    (_ROUTE_GIT_PUSH_RE, "block", f"git push → {GIT_PUSH_HINT}"),
    (_ROUTE_GIT_PULL_RE, "block", f"git pull → {_TASK_SUBMIT_NET}"),
    (_ROUTE_GIT_MUT_RE, "block", f"git mutation → {_TASK_SUBMIT}"),
    (_ROUTE_GH_RE, "block", f"gh (mutations / net) → {_TASK_SUBMIT_NET}"),
    (_ROUTE_WILLOW_BOT_STEWARD_LOOP_RE, "block",
     f"willow-bot-steward loop → {_TASK_SUBMIT} (or seat/willow-seat.sh pr-watch-loop on the host)"),
    # Anchored to command position (same as psql/sqlite3). An echo/printf/commit
    # that merely *names* a python heredoc must not trip — only an actual
    # invocation (gap a1416fb1b8b1 / H1 act-vs-text).
    # `-\\S*` (not `-\\S+`): bare `python3 - <<` is stdin-from-heredoc and must
    # block too — measured miss 2026-09-13 (gap aad87628554c).
    (re.compile(r"(?i)(?:^|&&|;|\|)\s*python3?\s+(?:-\S*\s+)*<<"), "block",
     f"Python heredoc → Kart {_TASK_SUBMIT} · look-ups via code_graph_* / nestor_ask"),
    (re.compile(r"(?i)\bgrep\b|\brg\b"), "warn",
     f"knowledge_search / store_search · symbols → code_graph_search · {_TASK_SUBMIT}"),
    (re.compile(r"(?i)\bfind\s"), "warn",
     f"code_graph_search / knowledge_search · {_TASK_SUBMIT}"),
    (_ROUTE_WEB_FETCH_RE, "block",
     "willow_web_fetch (MCP) — guarded fetch, not raw {curl,wget}. "
     f"For a verified answer, prefer the ladder first: {WEB_ORDER}."),
    (_ROUTE_PKG_INSTALL_RE, "block", f"package install reaches the network → {_TASK_SUBMIT_NET}"),
    (_ROUTE_REMOTE_RE, "block", f"remote network access → {_TASK_SUBMIT_NET}"),
    (_ROUTE_BACKGROUND_RE, "warn",
     f"backgrounded/detached process is untracked outside this session → {_TASK_SUBMIT}"),
    (_ROUTE_SCRIPT_RE, "warn", f"script/build execution → {_TASK_SUBMIT}"),
    (_ROUTE_FS_MUTATE_RE, "warn", f"scripted/bulk filesystem change → {_TASK_SUBMIT}"),
]

def _env_declares_orchestrator() -> bool:
    if os.environ.get("WILLOW_HUMAN_ORCHESTRATOR", "").strip() == "1":
        return True
    return os.environ.get("WILLOW_APP_ID", "").strip().lower() == _ORCHESTRATOR_APP_ID


def _project_dir() -> Optional[str]:
    """The project root for seat detection (.mcp.json).

    Claude Code sets CLAUDE_PROJECT_DIR on every hook invocation. Cursor does
    not — project sync wraps hook commands with WILLOW_PROJECT_ROOT instead
    (and some Cursor builds set CURSOR_PROJECT_DIR). Prefer the harness signal
    when present; fall back to the env the Cursor hooks.json injects.
    """
    return (
        os.environ.get("CLAUDE_PROJECT_DIR")
        or os.environ.get("CURSOR_PROJECT_DIR")
        or os.environ.get("WILLOW_PROJECT_ROOT")
        or None
    )


def _mcp_json_declares_orchestrator(project_dir: str) -> bool:
    """True when the project's .mcp.json runs a willow-mcp server as the willow
    orchestrator seat. This is the production signal: the harness spawns this
    hook WITHOUT the session's WILLOW_* env (only CLAUDE_* reaches it), so the
    seat is read from the file the SessionStart hook writes, not the env.
    Fail-safe: any missing/malformed file yields False (git stays routed)."""
    try:
        with open(os.path.join(project_dir, ".mcp.json")) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return False
    servers = cfg.get("mcpServers")
    if not isinstance(servers, dict):
        return False
    for server in servers.values():
        env = (server or {}).get("env") if isinstance(server, dict) else None
        if not isinstance(env, dict):
            continue
        if str(env.get("WILLOW_HUMAN_ORCHESTRATOR", "")).strip() == "1":
            return True
        if str(env.get("WILLOW_APP_ID", "")).strip().lower() == _ORCHESTRATOR_APP_ID:
            return True
    return False


def _is_orchestrator_seat() -> bool:
    """True when this hook runs for the willow human-orchestrator seat. Only the
    git/gh routing nudges are lifted for it — never the self-grant guard, which
    runs first and governs egress for every seat. Reading the seat from
    .mcp.json is not a trust boundary (an agent that forged it would still hit
    the unlifted self-grant guard), so a file signal is sufficient here."""
    if _env_declares_orchestrator():   # honored if a harness ever propagates it
        return True
    project = _project_dir()
    return bool(project and _mcp_json_declares_orchestrator(project))


def _git_gh_inspect_allowed(command: str) -> bool:
    c = (command or "").strip()
    if not c:
        return False
    if _GIT_MUTATION_RE.search(c) or _GH_MUTATION_RE.search(c):
        return False
    return bool(_GIT_INSPECT_RE.search(c) or _GH_INSPECT_RE.search(c))


# ── the willow seat does not use Shell ──────────────────────────────────────
#
# Until 2026-09-14 this hook LIFTED the git/gh routing for the orchestrator
# seat ("repo maintenance IS that seat's job") and said nothing about any other
# command. On that day the seat ran Shell five times — git diff, pytest,
# python3 -c twice, wc/tail — and the hook blocked none of them; the operator
# did, twice: "use the mcps", "use kart, use the fucking mcps that the hooks
# should be fucking blocking you from". Every one of those acts has a fleet
# tool now: reads go through Read / search_code / detect_changes, execution
# through task_submit (Kart, with the repo's .git bound), and the three git
# acts that leave the box through the broker — git_push_execute,
# pr_open_execute, git_pull_execute. So for this seat the rule is the
# operator's, not a nudge: Shell is refused, and the refusal names the door.
# The exemption is gone with it (gap 715d89fe3c90). Specialist seats keep the
# routing table below — theirs is a different question.

_SEAT_SHELL_REASON = "willow-mcp: the willow seat does not use Shell (operator, 2026-09-14)"

_SEAT_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bgit\s+push\b"),
     "git_push_execute(app_id=..., checkout=..., repo='org/name', branch=...) — the broker pushes"),
    (re.compile(r"\bgh\s+pr\s+create\b"),
     "pr_open_execute(app_id=..., repo='org/name', head=..., base=..., title=..., body=...) — the bot opens it"),
    (re.compile(r"\bgh\s+pr\s+merge\b"),
     "the merge is the operator's act; watch it with integration_call(name='github', method='GET', ...)"),
    (re.compile(r"\bgit\s+(pull|fetch)\b"),
     "git_pull_execute(app_id=..., checkout=..., repo='org/name') or gitsync_sweep — the broker brings it home"),
    (re.compile(r"\bgit\s+(status|log|diff|show|branch|rev-parse|describe|shortlog|remote)\b"),
     "detect_changes(project=..., base_branch=...) for the working tree; "
     "task_submit(app_id=..., task='git -C <repo> ...') for the rest"),
    (re.compile(r"\bgh\s"),
     "integration_call(name='github', method='GET', path='/repos/...') to read GitHub; "
     "pr_open_execute / git_push_execute to act"),
    (re.compile(r"\bgit\b"),
     "task_submit(app_id=..., task='cd <repo> && git ...') — Kart has the repo's .git bound"),
    # Execution before reads: a pipeline that runs something and tails the
    # output is execution, whatever it is piped through.
    (re.compile(r"(?:^|&&|;|\|)\s*(python3?|pytest|node|npm|make|ruff|pip3?)(?:\s|$)"),
     f"{_TASK_SUBMIT} — Kart runs it sandboxed and returns the output"),
    (re.compile(r"(?:^|&&|;|\|)\s*(cat|head|tail|less|more)(?:\s|$)"),
     "the Read tool (offset/limit for a slice)"),
    (re.compile(r"(?:^|&&|;|\|)\s*(grep|rg|ag|find|fd)(?:\s|$)"),
     "search_code(pattern=..., project=...) / search_graph(...) on the code graph"),
    (re.compile(r"(?:^|&&|;|\|)\s*(ls|tree|pwd|wc|du|stat)(?:\s|$)"),
     "the Read tool for a file, search_code(mode='files') for a listing, "
     f"{_TASK_SUBMIT} for anything else"),
    (re.compile(r"(?:^|&&|;|\|)\s*(systemctl|journalctl)(?:\s|$)"),
     "fleet_health / diagnostic_summary; unit state and journals are not readable "
     "from the seat yet (gap 158600e03598) — ask the operator for the status line"),
]


def check_seat_shell(command: str) -> Optional[tuple[str, str]]:
    """Refuse Shell for the willow seat and name the tool that replaces it.
    None for every other seat (their routing table still applies)."""
    if not _is_orchestrator_seat():
        return None
    c = (command or "").strip()
    for pattern, replacement in _SEAT_REPLACEMENTS:
        if pattern.search(c):
            return "block", f"{_SEAT_SHELL_REASON} — use {replacement}"
    return "block", f"{_SEAT_SHELL_REASON} — use {_TASK_SUBMIT} for execution, the Read tool " \
                    f"and the code graph (search_code / search_graph) for reads"


def check_bash_routing(command: str) -> Optional[tuple[str, str]]:
    """Return (decision, reason) when a Bash habit should redirect to MCP, else None."""
    if not command:
        return None
    seat = check_seat_shell(command)
    if seat:
        return seat
    if _git_gh_inspect_allowed(command):
        return None
    for pattern, decision, hint in _BASH_ROUTING:
        if pattern.search(command):
            return decision, f"willow-mcp: prefer MCP tools — {hint}"
    if _GIT_MUTATION_RE.search(command) or _GH_MUTATION_RE.search(command):
        return "block", f"willow-mcp: prefer MCP tools — git/gh mutation → {_TASK_SUBMIT}"
    return None


_WEB_SEARCH_REDIRECT = (
    f"Prefer verified organs first: {WEB_ORDER}. "
    "If the ladder misses and you actually need the open web, use "
    "willow_web_search (MCP) — not native WebSearch. Requires the 'web_net' "
    "manifest permission + operator consent.internet + a live egress lease; "
    "if this seat doesn't hold one, ask the operator to grant it "
    "(willow-mcp grant-net <app_id> --ttl 30m --reason ...) rather than "
    "retrying the native tool."
)
_WEB_FETCH_REDIRECT = (
    f"Prefer verified organs first: {WEB_ORDER}. "
    "If the ladder misses and you actually need to fetch a URL, use "
    "willow_web_fetch (MCP) for guarded URL fetch with external-guard scan — "
    "not native WebFetch. Requires the 'web_net' manifest permission + "
    "operator consent.internet + a live egress lease; if this seat doesn't "
    "hold one, ask the operator to grant it (willow-mcp grant-net <app_id> "
    "--ttl 30m --reason ...) rather than retrying the native tool."
)

# ── grant-aware wording, without a second reader of grant state ────────────
#
# An earlier version of this redirect probed WILLOW_HOME directly (manifest
# permission, consent file, lease file) to decide whether to name willow_web_*
# outright or say "ask the operator" instead. Cross-model audit found that
# probe was a split-brain in the making: it read $WILLOW_HOME/settings.global.json
# while the real gate (consent.read_consent) prefers the canonical
# $WILLOW_HOME/config/settings.global.json and honors WILLOW_SETTINGS_GLOBAL;
# it didn't validate lease ttl_seconds the way lease.read_lease does; it never
# denied on a corrupt canonical file the way the real gate does; and it didn't
# know about the 4th key (strict_trust_root), PGP manifest verification,
# deny_tools, or WILLOW_MCP_APPS_ROOT. Every one of those gaps could make the
# probe say "granted" when web_egress.egress_denial() would actually refuse —
# naming a door that then 401s, exactly the failure this guard exists to avoid.
#
# The fix is not a more faithful re-implementation (the hook cannot import
# willow_mcp and runs in the agent's own harness — see the _SEAT_PRIV_RE note
# above — so any second reader here WILL drift from the real gate again as it
# grows PGP checks, a 5th key, etc). Per the fleet's standing rule to eliminate
# split-brains rather than keep re-syncing two copies of one state, the redirect
# no longer probes grant state at all: it always names willow_web_* (the
# guidance is correct whether or not the grant is held) and always notes that
# an ungranted seat should ask the operator rather than retry the native tool.
# This can never claim "granted" falsely, because it never claims it at all.


def check_native_web(tool_name: str) -> Optional[tuple[str, str]]:
    """Block (not warn) IDE-native WebSearch/WebFetch now that willow_web_*
    ships. Decided 2026-07-31, after §4's open question of whether this
    guard — the only one gating a capability rather than an authority
    boundary — still warrants a hard block: it does, because the native
    tools are not a worse *style* of the same action, they are a different
    *channel* that skips every check the MCP path enforces. willow_web_fetch/
    willow_web_search go through web_egress.egress_denial() (the three-key
    gate: web_net + consent.internet + a live lease), and web_fetch.fetch_url
    additionally rejects private/loopback hosts (SSRF) and applies the
    sandwich-defense wrap against prompt injection in fetched content. Native
    WebFetch/WebSearch run entirely outside willow-mcp and get none of that —
    a warn would let an agent route around egress governance and SSRF
    protection with one more tool call, not just a less-preferred one.

    Grant-aware without a grant probe (2026-09-11, revised): the message
    always names the willow_web_* verb AND always tells an ungranted seat to
    ask the operator — see the module note above for why this hook does not
    (and should not) maintain its own reader of grant state."""
    if tool_name == "WebSearch":
        return "block", f"willow-mcp: {_WEB_SEARCH_REDIRECT}"
    if tool_name == "WebFetch":
        return "block", f"willow-mcp: {_WEB_FETCH_REDIRECT}"
    return None


# gap corpus-first-jeles-nestor / 38a0351f2527: nothing today prompts a seat to
# consult the fleet's own verified organs — knowledge_search, the
# operator-ratified jeles-corpus federation (federation server 8cae3d1dcdf4),
# and nestor for a sealed answer — before it reaches for the open web or
# answers from model recall. Ties to the sealed rule "ask Nestor, then the
# box, then remote, and say which tier answered."
#
# The hookable surface: a "factual question" is not itself a tool call, so
# there is nothing to hang a check on until the seat actually reaches for the
# web. The concrete, catchable moment is a web-search PreToolUse — native
# WebSearch (this repo already hard-blocks that channel via check_native_web,
# redirecting to willow_web_search) and willow_web_search itself, the governed
# tool the redirect lands on and the one an agent may call directly. That is
# the last point before the corpus gets skipped, on either channel.
#
# WebFetch/willow_web_fetch are deliberately NOT covered: fetching a URL the
# caller already has in hand is not the "I need a fact, where do I look first"
# decision this hook targets — check_native_web's channel guard still applies
# to it unchanged.
_CORPUS_FIRST_REMINDER = (
    "willow-mcp: before searching the open web, consult the fleet's own "
    "verified organs first — knowledge_search (local knowledge base), the "
    f"jeles-corpus federation (federation_call to server {JELES_FEDERATION_SERVER}), "
    "and nestor_ask / nestor_resolve for a sealed answer. Order: nestor "
    "(sealed) -> box (knowledge_search / jeles federation) -> remote (web) — "
    "and say which tier answered. The corpus can miss; web search is a fine "
    "fallback then, but say the result is unverified. This is a reminder, "
    "not a block."
)


def _is_web_search_tool(tool_name: str) -> bool:
    """True for the native WebSearch tool or the governed willow_web_search MCP
    tool, bare or MCP-qualified (e.g. mcp__willow-mcp__willow_web_search) —
    the two shapes a web search can arrive in. Matched the same way
    _is_task_submit matches task_submit below."""
    return (
        tool_name == "WebSearch"
        or tool_name == "willow_web_search"
        or tool_name.endswith("__willow_web_search")
    )


def check_corpus_first(tool_name: str) -> Optional[tuple[str, str]]:
    """Remind — never block — a seat about to search the web to try the
    fleet's verified organs first. Always a warn: the corpus can genuinely
    miss, so hard-blocking the web fallback would be wrong (unlike
    check_native_web's block, which governs the *channel*, not the *order*,
    and is not softened by this). Composes with check_native_web in main():
    on native WebSearch (which check_native_web already hard-blocks and
    redirects to willow_web_search), this reminder is appended to that same
    block reason rather than issuing a second, conflicting decision; on a
    direct willow_web_search call — the tool the redirect lands on, and the
    one an agent may call without ever touching native WebSearch — it is the
    sole (warn) decision. Fail-safe by construction: a plain string compare
    with no external state, so a hook fault here cannot hard-block a caller
    that reaches this function at all."""
    if _is_web_search_tool(tool_name):
        return "warn", _CORPUS_FIRST_REMINDER
    return None


# The command-string scan below cannot see a raw client that lives inside a
# *script file*: `python3 drop.py` / `bash drop.sh` whose body opens a raw sqlite
# connection against an owned store shows nothing on the command line. This
# is the file-indirection gap the module's known-limits note names (a write
# performed inside a script, not a `-c` one-liner). Read the invoked script and
# apply the same two-key test (raw client + owned-store marker) to its contents.
# Still a tripwire, not a control — a path built at runtime or an imported wrapper
# evades it; the durable control is B-32 — but it ends the "the command string was
# clean" deniability that let a script route around the guard.
#
# One level, decided (2026-07-31): a script whose own body shells out to a
# *second* script that reaches the store is not caught, and that is the
# deliberate stopping point, not an oversight. The threat model here is an
# agent reaching for a raw client out of habit, and a habit doesn't produce a
# two-hop indirection chain — writing one takes deliberate effort, which is
# already the "no OS-level obstacle" case this module's docstring disclaims;
# the durable control for it is B-32, not a deeper regex. Catching a second
# hop would also mean recursively re-running this same brittle heuristic
# against the second script's source (and the third, if that shells out too),
# compounding a regex-based guess for a case outside what a tripwire owes.
# See docs/design/hooks-and-skills.md's 2026-07-31 addendum;
# test_check_bash_allows_a_two_level_script_chain pins this boundary.
_SCRIPT_INVOKE_RE = re.compile(
    r"(?:^|&&|;|\|)\s*(?:cd\s+(?P<cwd>[^\s;&|]+)\s*&&\s*)?"
    r"(?:python3?|bash|sh|zsh)\s+(?:-\S+\s+)*(?P<script>[^\s;&|]+\.(?:py|sh))\b"
)
# A real DB *use* in the file — not the bare token, which appears in comments,
# regexes (this hook's own source), and docs. Requires an actual open/connect or
# a store client construction, so a file that merely names "sqlite3" is not caught.
_SCRIPT_DB_USE_RE = re.compile(
    r"\bimport\s+sqlite3\b|sqlite3\.connect\s*\(|"
    r"psycopg2?\.connect\s*\(|psycopg\.connect\s*\(|asyncpg\.(?:connect|create_pool)\s*\(|"
    r"create_engine\s*\(|\bSqliteStore\s*\(|\bpsql\s+-"
)


def _repo_scripts_dir() -> Optional[str]:
    """This repo's own scripts/ directory, if resolvable — anchored on
    CLAUDE_PROJECT_DIR (what the harness sets on every hook invocation) or
    cwd as a fallback, same anchor _mcp_json_declares_orchestrator uses."""
    root = _project_dir() or os.getcwd()
    d = os.path.join(root, "scripts")
    return d if os.path.isdir(d) else None


def _is_repo_scripts_path(path: str) -> bool:
    """True when `path` resolves inside this repo's committed scripts/ tree.

    Found live (2026-07-31): 17 files under scripts/ — sandbox-bootstrap.sh
    (the README's documented one-command setup) plus diagnostics/ratification/
    reconstruction tooling — all legitimately touch a raw DB client against an
    owned-store marker as ordinary infrastructure work (creating the database,
    applying schema, before any MCP tool exists to call instead). That is a
    different act from an agent reaching for a raw client out of habit mid
    session, which is what this guard exists to catch. A script already
    committed under scripts/ went through the same review this hook file did;
    a script an agent is about to write in the working tree did not — that is
    the line this exemption draws, by path, not by content. (Still a tripwire:
    an agent that edited one of these files first could still ride this
    exemption — the durable control for that is B-32, same as everywhere else
    in this module.)"""
    scripts_dir = _repo_scripts_dir()
    if not scripts_dir:
        return False
    try:
        real_scripts = os.path.realpath(scripts_dir)
        real_path = os.path.realpath(path)
    except OSError:
        return False
    return real_path == real_scripts or real_path.startswith(real_scripts + os.sep)


def _script_reaches_owned_store(command: str) -> Optional[str]:
    """Block `python3 file.py` / `bash file.sh` whose file reaches a willow-mcp
    owned store via a raw client — the same crossing as a shell client, one file
    deeper. Fail-open on an unreadable target (tripwire, not a control)."""
    for m in _SCRIPT_INVOKE_RE.finditer(command):
        script, cwd = m.group("script"), m.group("cwd")
        if os.path.isabs(script):
            candidates = [script]
        else:
            candidates = [os.path.join(cwd, script)] if cwd else []
            candidates += [os.path.join(os.getcwd(), script), script]
        for path in candidates:
            try:
                with open(path, "r", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            if _is_repo_scripts_path(path):
                break
            if _SCRIPT_DB_USE_RE.search(text) and _OWNED_MARKER_RE.search(text):
                return (
                    f"willow-mcp: {os.path.basename(path)} reaches a willow-mcp-owned "
                    f"store via a raw DB client — blocked one file deeper, same as a "
                    f"shell client. Use the MCP tools (store_*, knowledge_*, lineage_*, "
                    f"kb_*) instead of scripting raw DB access. (tripwire; real control B-32)"
                )
            break  # read it and it's clean → this invocation is fine
    return None


_REMOTE_POSTURE_FILE = "remote_posture.json"
_REMOTE_FAIL_CLOSED_MSG = (
    "willow-mcp: remote enforcement — Willow MCP gate is not live "
    "(see SessionStart banner). Raw psql/sqlite3/curl are denied without "
    "the gate. Fix: bash scripts/sandbox-bootstrap.sh and ensure .mcp.json "
    "+ PreToolUse hooks are wired; then use store_*/knowledge_*/kb_* MCP tools."
)
# Bare clients in remote sessions when the gate is absent (#164) — not the
# owned-store marker path in check_bash(), which only fires when a willow
# store/db name appears on the command line.
_FAIL_CLOSED_SHELL_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:psql|sqlite3)\b|(?:^|[;&|]\s*)curl\b",
    re.IGNORECASE,
)


def _load_remote_posture() -> Optional[dict]:
    candidates: list[str] = []
    wh = os.environ.get("WILLOW_HOME")
    if wh:
        candidates.append(os.path.join(wh, "enforcement", _REMOTE_POSTURE_FILE))
    project = _project_dir()
    if project:
        candidates.append(os.path.join(project, ".willow", "enforcement", _REMOTE_POSTURE_FILE))
    for path in candidates:
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return None


def _remote_mcp_gate_absent() -> bool:
    if os.environ.get("CLAUDE_CODE_REMOTE", "").strip().lower() != "true":
        return False
    posture = _load_remote_posture()
    if posture is None:
        return True
    return not posture.get("mcp_live", False)


def check_bash_remote_fail_closed(command: str) -> Optional[str]:
    """Block raw DB/network clients in CCR when SessionStart recorded no live gate."""
    if not command or not _remote_mcp_gate_absent():
        return None
    if _FAIL_CLOSED_SHELL_RE.search(command):
        return _REMOTE_FAIL_CLOSED_MSG
    return None


def check_bash(command: str) -> Optional[str]:
    """Return a block reason if `command` reaches for a willow-mcp-owned store via
    a raw shell client — on the command line, or inside a script it invokes."""
    if not command:
        return None
    if _CLIENT_RE.search(command) and _OWNED_MARKER_RE.search(command):
        client = _CLIENT_RE.search(command).group(1)
        for marker, redirect in _TOOL_REDIRECTS.items():
            if marker in command:
                return (
                    f"willow-mcp: direct {client} access to its own store is blocked — "
                    f"use the MCP tools instead ({redirect})."
                )
        return (
            f"willow-mcp: direct {client} access to a willow-mcp-owned store is "
            f"blocked — use the matching MCP tool (store_*, knowledge_*, kb_*) instead."
        )
    # File-indirection gap: the raw client lives inside an invoked script.
    return _script_reaches_owned_store(command)


# Kart sandbox directives the worker honors — matched exactly as the worker does
# (`line.strip() == <directive>`). task_submit strips caller-supplied occurrences
# unconditionally (B-21), so embedding one is a no-op; this guard steers callers.
_NET_DIRECTIVES = {"# allow_net", "# allow_localhost"}
_DB_DIRECTIVES = {"# allow_db"}
_KART_DIRECTIVES = _NET_DIRECTIVES | _DB_DIRECTIVES


def check_task_submit_self_grant(tool_input: dict) -> Optional[str]:
    """Return a block reason if a task's shell text mints an egress key.

    Kart task text is shell, so `task_submit(task="willow-mcp grant-net ...")` is
    the same crossing as running it in Bash. The sandbox happens to stop it today
    (`mcp_apps/` is `bound_ro`, B-14, so the write fails with EROFS) — but a guard
    that only works because of a mount option somewhere else is not a guard.
    """
    return check_bash_self_grant((tool_input or {}).get("task", "") or "")


def check_task_submit(tool_input: dict) -> Optional[str]:
    """Return a warn reason if a task_submit call hand-embeds a Kart network
    directive in its task text, else None (allow). This never blocks — the
    server safely strips the directive; the warning steers the caller to the
    real path (allow_net=True + task_net permission)."""
    task = (tool_input or {}).get("task", "") or ""
    embedded = sorted({
        line.strip() for line in task.splitlines() if line.strip() in _KART_DIRECTIVES
    })
    if not embedded:
        return None
    directives = ", ".join(f"`{d}`" for d in embedded)
    net_bits = [d for d in embedded if d in _NET_DIRECTIVES]
    db_bits = [d for d in embedded if d in _DB_DIRECTIVES]
    parts = []
    if net_bits:
        parts.append(
            "run a task with network egress, pass allow_net=True and grant the "
            "'task_net' permission in the app's manifest (not part of task_queue or "
            "full_access). '# allow_localhost' cannot be self-granted at all"
        )
    if db_bits:
        parts.append(
            "run a task with local Postgres access, pass allow_db=True and grant the "
            "'task_db' permission in the app's manifest (not part of task_queue or "
            "full_access)"
        )
    return (
        f"willow-mcp: {directives} embedded in task text is ignored — the server "
        "strips Kart sandbox directives from caller-supplied task text (B-21). To "
        + "; ".join(parts) + "."
    )


# The egress keys, as they appear on disk. Minting either is the escalation the
# sudo invariant forbids: request and confirm are separate authorities, and the
# agent holds only the first.
_LEASE_DIR_RE = re.compile(r"mcp_apps/(?:_net_leases|_build_leases)\b")
# The identity keystore ($WILLOW_HOME/gate/): per-agent HMAC secrets + the trust
# registry. Minting/rotating an identity or a trust ceiling by writing these is
# the same operator-only authority as minting a lease — an agent may request
# standing, never write its own secret (D2). Reading is not blocked.
_KEYSTORE_RE = re.compile(r"gate/(?:secrets\b|registry\.json)")
_GRANT_CMD_RE = re.compile(
    r"\bwillow-mcp\s+(?:grant-net|dev-net|grant-build|sign-net-task|register-agent|revoke-agent|rotate-agent|consent\s+(?:set|reconcile)|roster\s+sync)\b"
    r"|\bwillow_mcp\s+(?:grant-net|dev-net|grant-build|sign-net-task|register-agent|revoke-agent|rotate-agent)\b"
    r"|\b(?:lease\.grant|build_lease\.grant|sign_envelope|agent_registry\.(?:register_agent|revoke))\s*\("
    r"|\bconsent_admin\.(?:write_consent|set_key|reconcile)\s*\("
    r"|\bfleet_roster\.sync\s*\("
)
# #304: `willow-mcp allow-permission <app> <perm>` edits a manifest under the
# hood, so granting an egress capability or a write-capable group through it is
# the same self-grant the manifest-file branches below already refuse — but that
# guard keys on the manifest.json *path*, which this CLI never names, so it
# slipped through. Match the command and inspect the permission argument;
# `deny-permission` (de-escalation) and granting a read-only group are
# deliberately NOT matched. A quoted permission (`"web_net"`) is tolerated.
_ALLOW_PERMISSION_GRANT_RE = re.compile(
    r"\bwillow[-_]mcp\s+allow-permission\s+\S+\s+[\"']?([A-Za-z0-9_]+)"
)
# orchestrator/context/binding are write-capable groups that _SEAT_PRIV_QUOTED_RE
# only catches when quoted (prose-safety); here the perm is an exact CLI token,
# so the three are safe to name directly.
_ALLOW_PERMISSION_SEAT_BARE = frozenset({"orchestrator", "context", "binding"})
_MANIFEST_RE = re.compile(r"mcp_apps/[^/\s\"']+/manifest\.json")
# The server-process / sandbox egress capabilities, plus the Grove relay lock.
# These are NOT permission groups — they are one-off capability flags (gate.py
# NET_PERMISSION/DB_PERMISSION/INTEGRATION_NET_PERMISSION/WEB_NET_PERMISSION/
# MCP_FEDERATION_PERMISSION/GROVE_RELAY_PERMISSION) and no group implies them,
# which is the point: each "must be granted on its own line". `task_net` was
# the only one matched here; `integration_net`, `web_net`, and `mcp_federation`
# authorize egress from the *server* process, which gate.py identifies as the
# more privileged lane, and were silently absent (mcp_federation — fork/exec
# of a downstream MCP server, Decision 3 — added when #285 landed the
# federation lane). `grove_relay` unlocks posting to Grove as a different
# identity than the caller's own — same "operator grants it, agent never
# self-grants it" shape as the egress lanes, not a heavier privilege than
# them, just the same class of own-line capability. test_pre_tool_use_hook.py
# pins every gate capability flag to this guard or the seat guard, so the
# next one cannot go missing the same way.
_NET_CAP_RE = re.compile(r"\b(task_net|integration_net|web_net|mcp_federation|grove_relay)\b")
# Reading a lease or a manifest is not escalation — `net-status` and
# `diagnostic_summary` both do it, and blocking `cat` would be the false-positive
# class B-18 removed. Only a command that plausibly *writes* one is the crossing.
_WRITE_VERB_RE = re.compile(r">>?|\b(tee|cp|mv|install|touch|dd|truncate)\b|\bsed\s+-i\b")

_SELF_GRANT_REASON = (
    "willow-mcp: this invokes an operator-only policy mutation or authorizes your "
    "own egress. An agent may REQUEST egress, another grant, or a roster change; it "
    "may never CONFIRM it itself (sudo invariant, FRANK 90e52ab7). Leases, consent "
    "changes, and signed task envelopes are made by the operator, at their own "
    "terminal, with "
    "`willow-mcp grant-net <app_id> --ttl 30m --reason ...`, and `task_net` is "
    "added to a manifest by the operator, not by the app that wants it. `dev-net` "
    "(#287) is the same operator-only grant sequence in one command — it is "
    "friction reduction for the *sequence*, not a new path around any of these "
    "locks, so it is refused here exactly like grant-net. "
    "Ask for the grant; do not write the file. (B-32)"
)

_KEYSTORE_REASON = (
    "willow-mcp: this writes the identity keystore ($WILLOW_HOME/gate/ — per-agent "
    "HMAC secrets and the trust registry). Minting or rotating an identity or a "
    "trust ceiling is operator-only, done at the operator's terminal with "
    "`willow-mcp register-agent / rotate-agent / revoke-agent`; no tool and no app "
    "may write its own secret or raise its own trust. An agent may REQUEST "
    "standing, never CONFIRM it (sudo invariant, D2). Reading is fine; writing is not."
)

# Sealed rule c9ca1a09: the file that decides the Agent-spawn model pin —
# specialists.json's own model_hint_session field, either the bundle copy or
# a top-level config/ shadow — is not fleet-writable. Matches both filenames
# so a reintroduced spawn_models.json (the split-brain the rework removed)
# stays guarded too, not just the file that replaced it.
_SPAWN_CONFIG_RE = re.compile(r"(?:^|/)(?:bundle/)?config/(?:spawn_models|specialists)\.json$")
_SPAWN_CONFIG_REASON = (
    "willow-mcp: this writes specialists.json — the file whose model_hint_session "
    "field the Agent-spawn guard reads to decide a seat's pinned model (sealed "
    "rule c9ca1a09, pair 72f528ab). A seat editing its own pin table to raise or "
    "drop a pin is the same self-grant class the manifest guard above refuses: an "
    "agent may REQUEST a repin, never CONFIRM it itself (sudo invariant, FRANK "
    "90e52ab7). Ask the operator to ratify the change; do not write the file."
)


# "Retaking the seat": adding a WRITE-capable permission group (or widening
# store_scope to everything) to a manifest re-grants the very authority the
# SessionStart bootstrap strips back to read-only. Same sudo-invariant class as
# task_net — an agent may REQUEST the seat, never CONFIRM it itself. Matched on
# the group tokens (and a bare "*" store_scope) as they appear in a manifest's
# JSON, so a Write/Edit or a shell redirect into the file both trip it.
#
# This list MUST stay in step with gate.PERMISSION_GROUPS, and for a long time
# did not: it named ten of the forty-two groups, so `dispatch_write`,
# `human_loop_write`, `frank_write`, `markdownai_directives` ("the dangerous
# half", gate.py:241-249), `orchestrator` (which expands to seven writes) and
# eleven more were self-grantable with the guardrail silent. The hook cannot
# import willow_mcp — it runs in the agent's harness, stdlib only — so the list
# is literal here and pinned from the other side by
# tests/test_pre_tool_use_hook.py::test_seat_guard_covers_every_write_capable_group,
# which reads gate.PERMISSION_GROUPS and fails when a new group appears in
# neither column. Add a group there and the test tells you which column it needs.
_SEAT_PRIV_RE = re.compile(
    r"\b(agent_dispatch|code_graph_write|commitment_write|dispatch_write|"
    r"envelope_apply|envelope_write|federation_call|fork_write|frank_write|friction_write|full_access|"
    r"gap_promote|gap_purge|gap_write|governance_propose|governance_sync|grove_all|grove_write|human_loop_write|integration_call|"
    r"knowledge_curate|knowledge_write|lineage_write|markdownai_directives|markdownai_write|"
    r"nest_write|schema_admin|store_all|store_write|task_db|task_queue|"
    r"tool_oracle_route|tool_oracle_seal)\b"
)
# `orchestrator`, `context` and `binding` are also write-capable groups, but
# unlike the names above they are ordinary English words that occur in manifest
# descriptions, commit messages and paths ("the orchestrator seat", "identity
# binding"). A bare-word match would fire on prose — the false-positive class
# B-18 removed. Require them to appear the way a permission actually does: as a
# quoted string. The cost is that `sed -i 's/x/context/'` slips through; the
# compound names above keep bare-word matching precisely because they do not.
_SEAT_PRIV_QUOTED_RE = re.compile(r"[\"'](orchestrator|context|binding)[\"']")
_SCOPE_ALL_RE = re.compile(r'"store_scope"\s*:\s*\[\s*"\*"\s*\]')

# Literal tool names that expand from write-capable groups and do NOT also
# appear in a read-only group. Gap 7c3f45e495b4 / H3: `allow-permission app
# decision_propose` (or a manifest listing `"store_put"`) must refuse the same
# as granting `governance_propose` / `store_write`. Hook is stdlib-only, so the
# set is literal; tests/test_pre_tool_use_hook.py pins it against
# gate.PERMISSION_GROUPS so a new write tool cannot land unguarded.
_SEAT_WRITE_TOOLS = frozenset({
    "__mai_directives__",
    "agent_clear", "agent_dispatch_result", "agent_route",
    "code_graph_index",
    "commitment_acknowledge", "commitment_ingest",
    "context_expire", "context_get", "context_list", "context_save",
    "decision_propose",
    "dispatch_accept", "dispatch_send",
    "envelope_apply", "envelope_propose", "envelope_ratify", "envelope_reject",
    "federation_call",
    "fork_create", "fork_delete", "fork_join", "fork_log", "fork_merge",
    "frank_append",
    "friction_scan",
    "gap_delete", "gap_log", "gap_promote", "gap_purge_topic", "gap_resolve", "gap_retopic",
    "grove_ack", "grove_bus_send", "grove_flag", "grove_heartbeat",
    "grove_reply", "grove_send_message", "grove_unflag",
    "handoff_write_v4",
    "human_attestation_create", "human_required_enqueue", "human_required_resolve",
    "integration_call",
    "kb_ingest", "kb_journal", "kb_promote",
    "knowledge_flag", "knowledge_ingest", "knowledge_retract",
    "lineage_link", "lineage_record",
    "mai_execute_directive", "mai_get_env", "mai_invalidate_cache", "mai_write_file",
    "nest_correct_classification",
    "nest_intake_file", "nest_intake_scan", "nest_intake_skip", "nest_promote", "nest_scan",
    "nestor_tool_route", "nestor_tool_seal",
    "net_authority_drain",
    "schema_confirm_mapping", "seal_drain",
    "session_bind", "session_handoff_write", "session_reconcile",
    "store_delete", "store_purge_collection", "store_put", "store_update",
    "task_list", "task_status", "task_submit",
    "verify_handoff",
})
_SEAT_WRITE_TOOL_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(t) for t in sorted(_SEAT_WRITE_TOOLS)) + r")\b"
)

_SEAT_ESCALATION_REASON = (
    "willow-mcp: this edits a manifest to add a WRITE-capable permission group "
    "(store_write / store_all / knowledge_write / knowledge_curate / lineage_write / schema_admin / "
    "nest_write / gap_write / gap_promote / gap_purge / friction_write / task_db / "
    "task_queue / dispatch_write / human_loop_write / frank_write / envelope_apply / envelope_write / "
    "fork_write / commitment_write / code_graph_write / agent_dispatch / grove_write / grove_all / "
    "integration_call / federation_call / markdownai_write / markdownai_directives / orchestrator / "
    "context / binding / tool_oracle_route / tool_oracle_seal / governance_propose / governance_sync / full_access) or widen store_scope to "
    '"*" — "retaking the seat". The SessionStart bootstrap restores every seat to '
    "read-only by default; re-granting write authority is an operator act, not a "
    "self-grant. An agent may REQUEST the seat, never CONFIRM it itself (sudo "
    "invariant, FRANK 90e52ab7). Ask the operator to grant it; do not write the file."
)

_ALLOW_PERMISSION_REASON = (
    "willow-mcp: `willow-mcp allow-permission` is a local, operator-only CLI that "
    "edits the app's manifest — granting an egress capability (task_net / "
    "integration_net / web_net / mcp_federation), the Grove relay capability "
    "(grove_relay), or a write-capable permission group (or orchestrator / "
    "context / binding) through it is the same self-grant the manifest-file "
    "guard already refuses, one command deeper (#304). An agent may REQUEST "
    "standing, never CONFIRM it (sudo invariant, FRANK 90e52ab7). Ask the "
    "operator to run it. `deny-permission` and granting a read-only group stay "
    "allowed."
)


# ── fail-closed carve-out (operator ruling, closes audit 2AA60817) ──────────
#
# REWORK of the shape-checking parser this replaced: that parser looked ONLY at
# a parsed command-position invocation, which means anything that reaches the
# grant verb WITHOUT putting it at command position — a newline-separated
# command, an executed heredoc body, `$(...)`/backticks, a `(...)` subshell or
# `{ ...; }` group, a leading `FOO=bar` assignment, `echo '...' | bash`, an
# unstripped wrapper (`timeout`, `xargs`, `doas`, `ssh`, `uv run`, …), or
# `python -m willow_mcp allow-permission ...` — slipped straight through.
# Cross-model audit 2AA60817 confirmed a real grant invocation got through
# every one of those shapes. The operator ruled: do not chase the exhaustive
# parser; invert it.
#
# The design is now inverted:
#   1. The raw substring scan (_GRANT_CMD_RE / _ALLOW_PERMISSION_GRANT_RE) is
#      the PRIMARY denier again, run unconditionally against the whole raw
#      command text — no tokenising, no heredoc stripping, no command-position
#      requirement. A `.search()` over the raw string does not care what shape
#      carried the verb to it, so every bypass above still trips it.
#   2. Parsing is used ONLY to SUPPRESS that denial, and only for the two
#      shapes actually measured as false positives:
#        3cc11d282b4a — the verb/permission lives inside the quoted message
#                        argument of a `git commit -m`/`-F` invocation.
#        7ede165e5a29 — the verb/permission is an argument to a read-only
#                        command (grep/rg/cat/less/head/tail/…), not something
#                        that command runs.
#      Suppression only fires when, after masking exactly those two shapes out
#      of the command, the raw scan no longer matches at all. Anything left
#      over — a grant elsewhere in the same command, an unrecognised shape, a
#      parse failure — leaves the denial standing. Ambiguity denies.
_READ_ONLY_COMMANDS = frozenset({
    "grep", "egrep", "fgrep", "rg", "cat", "less", "more", "head", "tail",
    "zcat", "zless", "bat",
})
# -m/-F (and their long forms) on a `git commit` invocation: the only place a
# grant verb is data, not code, in a shape worth carving out.
_GIT_COMMIT_MSG_ARG_RE = re.compile(
    r"(?P<flag>-{1,2}(?:m|message|F|file)\s*=?\s*)(?P<q>[\"'])(?P<msg>.*?)(?P=q)",
    re.DOTALL,
)

# A leading `git` global option or two before the `commit` subcommand — e.g.
# `git -C /path commit`, `git --no-pager commit`. Conservative on purpose:
# only options that take no further inline argument (or a small enumerated
# set that takes one token, like -C/-c) are walked past, so this never
# mistakes an unrelated `git <verb>` for `git commit`.
_GIT_GLOBAL_OPT_WITH_ARG = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})


def _find_git_commit_token_index(tokens: list[str]) -> Optional[int]:
    """Return the index of the `commit` token in a `git ...` invocation's
    token list, walking past leading git global options, or None if this
    is not recognisably a `git commit` invocation."""
    if not tokens or os.path.basename(tokens[0]) != "git":
        return None
    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "commit":
            return i
        if tok.startswith("--") and "=" in tok:
            i += 1
            continue
        if tok in _GIT_GLOBAL_OPT_WITH_ARG:
            i += 2
            continue
        if tok.startswith("-") and tok != "-":
            i += 1
            continue
        # First non-option token that isn't "commit" — this isn't a
        # `git commit` invocation (e.g. `git -C /path log`).
        return None
    return None


# ALLOWLIST, not a blocklist (round-5 rework, closing Opus re-audit
# 5701FFBD): round-4's `_LIVE_EXEC_OPERATOR_RE` named the live-execution
# shapes it knew about ($(, backtick, <() and missed the ones it didn't —
# `>(` (output process substitution) and `${ cmd; }` (bash 5.3 funsub) both
# slip a real self-grant through undetected, and a blocklist of shell
# operators is never complete; the next one is just another name away.
#
# So invert it: a carve-out may only blank a region that is INERT — one
# that contains NONE of the characters a shell gives special evaluated
# meaning to. Command substitution ($(), backticks), process substitution
# (<(), >()), brace/funsub groups ({ ;}), pipelines (|), sequencing (;, &),
# redirection (<, >), and escaping (\) all REQUIRE one of these characters
# to exist at all — so refusing to blank whenever ANY of them is present
# closes the whole class of "the shell evaluates this before the outer
# command sees it" bypasses at once, including operators nobody has named
# yet. A bare literal newline is included too: it is a command separator
# exactly like `;`.
#
# This is deliberately conservative, not merely sufficient: a message that
# both names a grant verb in prose AND contains, say, `$(date)` for an
# unrelated reason still gets denied, because the whole region is refused
# once any of these characters appears — there is no attempt to distinguish
# a "safe" occurrence of one of these characters from a "live" one.
# Ambiguity denies. See test_ambiguous_commit_message_with_prose_and_subst_denies.
_UNSAFE_CHARS_RE = re.compile(r"[$`(){}<>|;&\\\n]")


def _split_subcommands_with_spans(command: str) -> list[tuple[int, int]]:
    """Split on top-level `;`, `|`, `||`, `&&`, and newlines — the same set a
    shell treats as a command boundary — while respecting quotes, and return
    (start, end) offsets into `command` for each subcommand span so callers
    can rebuild the string with only specific spans altered.

    Splitting is precision-only here: it decides which spans are eligible for
    the two recognised safe shapes below. It is never used to decide whether
    the raw scan fires — that always runs against the untouched whole string.
    """
    spans: list[tuple[int, int]] = []
    quote: Optional[str] = None
    i, n = 0, len(command)
    start = 0
    while i < n:
        c = command[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < n:
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c in ("\n", ";"):
            spans.append((start, i))
            i += 1
            start = i
            continue
        if c == "&" and i + 1 < n and command[i + 1] == "&":
            spans.append((start, i))
            i += 2
            start = i
            continue
        if c == "|":
            spans.append((start, i))
            i += 2 if (i + 1 < n and command[i + 1] == "|") else 1
            start = i
            continue
        i += 1
    spans.append((start, n))
    return spans


def _mask_subcommand_if_safe(sub: str) -> str:
    """Return `sub` with a recognised safe shape's data blanked out (same
    length, so offsets are irrelevant to the caller), or `sub` unchanged if it
    is not recognisably one of the two carve-out shapes. Unchanged is the
    fail-closed default — anything that doesn't parse cleanly into one of
    these two shapes stays exactly as written, so the raw scan still sees it.
    """
    try:
        tokens = shlex.split(sub)
    except ValueError:
        return sub
    if not tokens:
        return sub
    head = os.path.basename(tokens[0])
    if head in _READ_ONLY_COMMANDS:
        # The keyword this subcommand contains, if any, is an argument the
        # reader scans — never something it runs — UNLESS the region isn't
        # inert: it contains a shell-evaluated character ($, `, (, ), <, >,
        # {, }, |, ;, &, \, or a newline). Any of those means the shell may
        # evaluate part of this text before the outer command ever sees its
        # arguments, so blanking would delete the live grant text and leave
        # the re-scan with nothing to find. Refuse to blank: let the denial
        # from the raw scan stand.
        if _UNSAFE_CHARS_RE.search(sub):
            return sub
        return " " * len(sub)
    if os.path.basename(tokens[0]) == "git" and _find_git_commit_token_index(tokens) is not None:
        # Only the quoted -m/-F message text is data; the rest of the
        # invocation (git, any global options, commit, any other flags) is
        # left as-is. As above, if the message region that would be blanked
        # is not inert (contains a shell-evaluated character), refuse to
        # blank it — the shell evaluates that part before the outer `git
        # commit` does, so blanking would erase the only text carrying the
        # live grant. This is the ambiguity-denies case: a message that both
        # names a grant verb in prose AND contains e.g. `$(date)` is denied,
        # on purpose — no attempt is made to tell a "safe" occurrence of
        # these characters from a "live" one.
        def _blank_message(m: "re.Match[str]") -> str:
            msg = m.group("msg")
            if _UNSAFE_CHARS_RE.search(msg):
                return m.group(0)
            return m.group("flag") + m.group("q") + " " * len(msg) + m.group("q")

        return _GIT_COMMIT_MSG_ARG_RE.sub(_blank_message, sub)
    return sub


def _mask_recognised_safe_shapes(command: str) -> str:
    """Blank out exactly the two recognised false-positive shapes (git commit
    -m/-F message text; a read-only command's arguments) subcommand by
    subcommand, leaving everything else — including anything unrecognised —
    untouched."""
    pieces: list[str] = []
    prev_end = 0
    for start, end in _split_subcommands_with_spans(command):
        pieces.append(command[prev_end:start])
        pieces.append(_mask_subcommand_if_safe(command[start:end]))
        prev_end = end
    pieces.append(command[prev_end:])
    return "".join(pieces)


def _raw_self_grant_scan(command: str) -> Optional[str]:
    """The primary denier: an unconditional substring/regex scan of the whole
    raw command text for a grant-minting invocation. This is master's
    pre-parser behavior, restored — it does not care what shape (newline,
    heredoc, `$()`, backticks, subshell, group, leading assignment, pipe into
    an executor, or an unstripped wrapper) carried the verb into the string;
    if the verb is anywhere in the text, it fires."""
    if _GRANT_CMD_RE.search(command):
        return _SELF_GRANT_REASON
    for _m in _ALLOW_PERMISSION_GRANT_RE.finditer(command):
        perm = _m.group(1)
        if (
            _NET_CAP_RE.fullmatch(perm)
            or _SEAT_PRIV_RE.fullmatch(perm)
            or perm in _ALLOW_PERMISSION_SEAT_BARE
            or perm in _SEAT_WRITE_TOOLS
        ):
            return _ALLOW_PERMISSION_REASON
    return None


def check_bash_self_grant(command: str) -> Optional[str]:
    """Block a command that mints a lease/envelope, grants itself task_net, or
    edits a manifest to retake a write-capable seat.

    Writes only. `cat`ting a lease, `willow-mcp net-status`, and `revoke-net` are
    all fine — reading a key is not holding one, and giving one up is never
    escalation.

    The grant-command guards run the raw substring scan unconditionally
    (fail-closed carve-out, audit 2AA60817) and suppress that denial only when
    masking out exactly the two measured false-positive shapes — a git commit
    -m/-F message, or a read-only command's argument (gaps 3cc11d282b4a,
    7ede165e5a29) — makes the scan stop matching entirely. Any grant text left
    over after masking, or any shape the masker doesn't recognise, leaves the
    denial standing. The write-verb/path/keystore/manifest branches below still
    scan the raw command and are unchanged.
    """
    if not command:
        return None
    reason = _raw_self_grant_scan(command)
    if reason is not None:
        masked = _mask_recognised_safe_shapes(command)
        if masked != command and _raw_self_grant_scan(masked) is None:
            reason = None
    if reason is not None:
        return reason
    if not _WRITE_VERB_RE.search(command):
        return None
    if _LEASE_DIR_RE.search(command):
        return _SELF_GRANT_REASON
    if _KEYSTORE_RE.search(command):
        return _KEYSTORE_REASON
    if _MANIFEST_RE.search(command) and _NET_CAP_RE.search(command):
        return _SELF_GRANT_REASON
    if _MANIFEST_RE.search(command) and (
        _SEAT_PRIV_RE.search(command)
        or _SEAT_PRIV_QUOTED_RE.search(command)
        or _SEAT_WRITE_TOOL_RE.search(command)
        or _SCOPE_ALL_RE.search(command)
    ):
        return _SEAT_ESCALATION_REASON
    return None


_OWNED_DB_FILE_REASON = (
    "willow-mcp: this writes directly to a willow-mcp-owned SQLite store file — "
    "the non-Bash path to the same crossing a raw DB client would be (blocked one "
    "tool deeper, same as check_bash). Use the matching MCP tool (store_*, "
    "knowledge_*, kb_*) instead of touching the file directly."
)


def check_owned_db_file_write(tool_input: dict) -> Optional[str]:
    """Block a Write/Edit/MultiEdit whose target file is a willow-mcp-owned
    SQLite store — see _OWNED_DB_FILE_RE."""
    path = str((tool_input or {}).get("file_path", "") or "")
    if path and _OWNED_DB_FILE_RE.search(path):
        return _OWNED_DB_FILE_REASON
    return None


def check_trust_root_write(tool_input: dict) -> Optional[str]:
    """Block a Write/Edit that mints a lease, writes an identity secret, slips
    `task_net` into a manifest, or edits the spawn guard's own pin table.

    The path is `os.path.normpath`-ed before every path regex below
    (`_LEASE_DIR_RE`, `_KEYSTORE_RE`, `_SPAWN_CONFIG_RE`, `_MANIFEST_RE`) —
    normpath collapses a doubled separator (`config//specialists.json`) and a
    `.` segment (`config/./specialists.json`) alike, so a caller cannot slip
    a guarded write past these anchored-on-`$` patterns with either spelling
    (regex-boundary defect, Loki re-audit 2026-09-21)."""
    tool_input = tool_input or {}
    path = str(tool_input.get("file_path", "") or "")
    if not path:
        return None
    normalized = os.path.normpath(path)
    if _LEASE_DIR_RE.search(normalized):
        return _SELF_GRANT_REASON
    if _KEYSTORE_RE.search(normalized):
        return _KEYSTORE_REASON
    if _SPAWN_CONFIG_RE.search(normalized):
        return _SPAWN_CONFIG_REASON
    if _MANIFEST_RE.search(normalized):
        # Only the permissions that carry escalation. Editing a manifest for any
        # other reason is ordinary work and must not be blocked.
        written = " ".join(str(tool_input.get(k, "") or "")
                           for k in ("content", "new_string", "new_str"))
        if _NET_CAP_RE.search(written):
            return _SELF_GRANT_REASON
        if (
            _SEAT_PRIV_RE.search(written)
            or _SEAT_PRIV_QUOTED_RE.search(written)
            or _SEAT_WRITE_TOOL_RE.search(written)
            or _SCOPE_ALL_RE.search(written)
        ):
            return _SEAT_ESCALATION_REASON
    return None


_SPAWN_GUARD_RULE = "c9ca1a09"

# Fallback specialist rows, used only when config/specialists.json can't be
# read (deleted, malformed, or this hook copy has no config/ sibling — see
# _bundle_config_candidates). A missing registry must not silently disable
# the spawn guard for every seat; it degrades to this literal set instead.
# Kept in step with the shipped registry by
# tests/test_pre_tool_use_hook.py::test_fallback_specialists_track_the_registry.
_FALLBACK_SPECIALISTS = [
    {"agent_id": "hanuman", "display_name": "Hanuman", "role": "builder", "human_only": False},
    {"agent_id": "loki", "display_name": "Loki", "role": "auditor", "human_only": False},
    {"agent_id": "jeles", "display_name": "Jeles", "role": "librarian", "human_only": False},
    {"agent_id": "ada", "display_name": "Ada", "role": "operator", "human_only": False},
    {"agent_id": "skirnir", "display_name": "Skirnir", "role": "witness", "human_only": False},
    {"agent_id": "vishwakarma", "display_name": "Vishwakarma", "role": "architect", "human_only": False},
    {"agent_id": "heimdallr", "display_name": "Heimdallr", "role": "gatekeeper", "human_only": False},
    {"agent_id": "binder", "display_name": "The Binder", "role": "records", "human_only": False},
    {"agent_id": "willow", "display_name": "Willow", "role": "orchestrator", "human_only": True},
]

# Role -> required Agent-spawn session model, sealed pair c9ca1a09. Mirrors
# specialists.json's own model_hint_session field; used only if that file
# can't be read at all (see _load_spawn_models).
_FALLBACK_SPAWN_MODELS = {"builder": "sonnet", "auditor": "opus"}

# The harness's short session-model aliases. specialists.json's
# model_hint_session field is overloaded: for most rows it's a literal
# Anthropic model id (e.g. "claude-haiku-4-5-20251001") or null, meaning
# "inherit the caller's default" — neither is a spawn-guard pin. Only a row
# whose value is one of these short aliases is read as a pin, which is how
# a single field serves both purposes without a second table (finding:
# split-brain between specialists.json and a duplicate spawn_models.json).
_SHORT_MODEL_ALIASES = frozenset({"sonnet", "opus", "haiku"})


def _bundle_config_candidates(filename: str) -> list[str]:
    """Where a bundle config JSON lives relative to THIS file. This module
    ships at two paths that must stay byte-identical
    (src/willow_mcp/bundle/hooks/pre_tool_use.py and the top-level
    hooks/pre_tool_use.py mirror tested against it), and each copy reaches
    the SAME real bundle config by a different relative path — never both.
    The bundle copy has config/ as a direct sibling of hooks/; that is the
    only candidate that exists in a real install, so if it's there, it's the
    one path returned. The top-level mirror has no sibling config/ at all —
    it's a test-only copy, not an install shape — so it walks up to the repo
    root and back down to the bundle's own config/ instead. Picking one
    shape rather than trying both (one of which is always a dead path in any
    given install) keeps production reading exactly the one real file.
    Tests may monkeypatch this whole function to point at a fixture
    directory instead of either real path."""
    hook_dir = os.path.dirname(os.path.abspath(__file__))
    sibling_config = os.path.join(hook_dir, "..", "config")
    if os.path.isdir(sibling_config):
        return [os.path.join(sibling_config, filename)]
    return [os.path.join(hook_dir, "..", "src", "willow_mcp", "bundle", "config", filename)]


def _load_json_config(filename: str) -> Optional[dict]:
    """Best-effort stdlib-only JSON load, same fail-safe shape as
    _load_remote_posture above: a missing/malformed file at any candidate
    path is silently skipped, never raised."""
    for path in _bundle_config_candidates(filename):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            continue
    return None


def _load_specialist_rows() -> "tuple[list[dict], bool]":
    """Load specialist + orchestrator rows from config/specialists.json.
    Returns (rows, used_fallback)."""
    data = _load_json_config("specialists.json")
    rows: list = []
    if isinstance(data, dict):
        for row in data.get("specialists") or []:
            if isinstance(row, dict) and row.get("agent_id"):
                rows.append(row)
        orch = data.get("orchestrator_seat")
        if isinstance(orch, dict) and orch.get("agent_id"):
            rows.append(orch)
    if rows:
        return rows, False
    return _FALLBACK_SPECIALISTS, True


def _load_spawn_models() -> dict:
    """Role -> required Agent-spawn model, derived from the SAME
    specialists.json rows _load_specialist_rows reads — one source, not a
    duplicated spawn_models.json (the split-brain the rework closed). A
    row's model_hint_session pins its role only when the value is one of
    _SHORT_MODEL_ALIASES; a full Anthropic model id or null is a session
    hint for something else, not a spawn-guard pin. Config, not code
    (sealed pair c9ca1a09): editing specialists.json changes the guard's
    behaviour with no code edit — see
    test_pre_tool_use_hook.py::test_agent_spawn_table_reads_specialists_json_not_code.
    Falls back to _FALLBACK_SPAWN_MODELS only when specialists.json can't be
    read at all."""
    rows, used_fallback = _load_specialist_rows()
    if used_fallback:
        return dict(_FALLBACK_SPAWN_MODELS)
    table: dict = {}
    for row in rows:
        role = row.get("role")
        hint = row.get("model_hint_session")
        if role and isinstance(hint, str) and hint in _SHORT_MODEL_ALIASES:
            table[role] = hint
    return table or dict(_FALLBACK_SPAWN_MODELS)


# Matches an app_id shape naming a seat: `app_id="<seat>"`, `app_id: <seat>`,
# `APP_ID="<seat>"`, JSON `"app_id": "<seat>"`, straight or curly quotes.
# Case-insensitive on the keyword AND the seat id — `_detect_specialist_seat`
# looks the captured text up in a lower-cased id table. Anchored on the
# keyword so this can't match an unrelated word that merely contains
# "app_id".
_APP_ID_RE = re.compile(
    r'app_id["\']?\s*[=:]\s*["\'‘’“”]?([A-Za-z][A-Za-z0-9_-]*)',
    re.IGNORECASE,
)

# The read-only lookup calls a prompt or description can legitimately quote
# an app_id into as an ARGUMENT, not an entry — handoff_read(app_id="hanuman")
# names hanuman as the packet to read, not a seat to become. Masked out
# before the bare-app_id detection tier runs (see _mask_read_only_calls) so
# these never trip it; session_enter is deliberately absent from this set —
# it is the entry call, scanned first, at full priority, never masked.
_READ_ONLY_LOOKUP_CALLS = frozenset({
    "handoff_read", "dispatch_read", "session_read", "store_get",
    "store_list", "store_search", "store_search_all", "dispatch_list",
    "task_status", "task_list", "whoami", "verify_handoff",
    "kb_journal_read", "specialist_get", "specialist_list",
    "diagnostic_summary", "fleet_status", "fleet_health",
})


# The paren-less prose shape ("Run handoff_read with app_id=hanuman") names
# the same lookup call but never opens a `(...)` argument list at all, so the
# paren-depth masking below never sees it. Matched separately and only the
# `app_id=<seat>` fragment is blanked, not the call name — a read-only call
# named without parens is still a lookup, not an entry, and must not trip the
# bare-app_id tier either. Bounded to a short run of non-sentence-ending text
# between the call name and app_id= so this cannot reach across an unrelated
# later sentence.
_READ_ONLY_PROSE_APP_ID_RE = re.compile(
    r'(?:(?<=__)|\b)(?:' + '|'.join(re.escape(t) for t in _READ_ONLY_LOOKUP_CALLS) + r')\b'
    r'(?!\s*\()'
    r'[^\n.;(]{0,40}?(app_id\s*[=:]\s*[\'"]?[A-Za-z][A-Za-z0-9_-]*)',
    re.IGNORECASE,
)


def _mask_read_only_calls(text: str) -> str:
    """Blank the parenthesised argument text of any _READ_ONLY_LOOKUP_CALLS
    invocation in `text`, so a bare app_id=<seat> that appears only as an
    argument to a lookup cannot trip the bare-app_id detection tier. Uses a
    simple paren-depth counter, not a full parser — good enough for the
    single-call-per-mention shapes this guard sees in a prompt/description.
    A second pass then blanks the paren-LESS prose shape ("Run handoff_read
    with app_id=hanuman") the same way — masking only the app_id=<seat>
    fragment, since the call name itself carries no seat framing."""
    if not text:
        return text
    names_pattern = re.compile(
        r'\b(?:' + '|'.join(re.escape(t) for t in _READ_ONLY_LOOKUP_CALLS) + r')\s*\('
    )
    out: list = []
    pos = 0
    n = len(text)
    for m in names_pattern.finditer(text):
        if m.start() < pos:
            continue
        out.append(text[pos:m.end()])
        depth = 1
        j = m.end()
        while j < n and depth:
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
            j += 1
        out.append(" " * (j - m.end()))
        pos = j
    out.append(text[pos:])
    masked = "".join(out)

    def _blank_app_id(m: "re.Match[str]") -> str:
        start, end = m.span(1)
        prefix_len = start - m.start()
        return m.group(0)[:prefix_len] + " " * (end - start)

    return _READ_ONLY_PROSE_APP_ID_RE.sub(_blank_app_id, masked)


def _find_session_enter_seat(text: str, by_id: dict) -> Optional[dict]:
    """Highest-priority tier: the seat named INSIDE a session_enter(...)
    call's own arguments — the entry call itself, not a mention of the seat
    elsewhere in the same text. Fixes the order bug where a caller citing
    another seat's packet by app_id (`dispatch_read(app_id="hanuman", ...)`)
    ahead of its own `session_enter(app_id="loki")` got pinned to the wrong
    seat's model.

    Walks paren DEPTH from the `session_enter(` opening to its matching
    close (multi-line; the same counting approach _mask_read_only_calls
    uses) instead of a `[^)]*` regex, so a nested paren inside the call's
    own arguments — the canonical `session_id=str(uuid4())` shape — does
    not truncate the argument span before app_id is reached (regex-boundary
    defect, Loki re-audit 2026-09-21)."""
    n = len(text)
    for m in re.finditer(r"session_enter\s*\(", text, re.IGNORECASE):
        depth = 1
        j = m.end()
        while j < n and depth:
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
            j += 1
        if depth:
            # No matching close in this text — nothing to scan.
            continue
        args = text[m.end():j - 1]
        am = _APP_ID_RE.search(args)
        if am is None:
            continue
        seat = by_id.get(am.group(1).lower())
        if seat is not None:
            return seat
    return None


def _find_you_are_seat(text: str, rows: list) -> Optional[dict]:
    """"You are <Display name>" / "You're <Display name>" / "Enter as
    <Display name>" framing, case-insensitive, tolerant of markdown bolding
    around the name. Returns the seat matched EARLIEST in the text, not the
    first ROW that happens to match anywhere — a prompt quoting a later
    speaker's own framing (e.g. an auditor's prompt reporting "the packet
    whose prompt said 'You are Hanuman'") must not out-rank the seat
    actually named first (regex-boundary defect, Loki re-audit 2026-09-21).
    A trailing word character or apostrophe is excluded (`(?![\\w'])`) so
    "You are Willow's auditor" / "You are Willowbrook support" do not match
    "Willow"; a trailing "?" is also excluded so a question like "You are
    Loki? no — ask claude-code-guide" is not read as entry framing."""
    best: Optional[dict] = None
    best_pos: Optional[int] = None
    for row in rows:
        for name in filter(None, (row.get("display_name"), row.get("agent_id"))):
            pat = re.compile(
                r"\b(?:you are|you're|enter as)\s+\**%s\**(?![\w'?])" % re.escape(name),
                re.IGNORECASE,
            )
            m = pat.search(text)
            if m is not None and (best_pos is None or m.start() < best_pos):
                best_pos = m.start()
                best = row
    return best


def _find_comma_start_seat(text: str, rows: list) -> Optional[dict]:
    """`<Display name>,` (or bare `<agent_id>`) opening the text — "Hanuman,
    build the thing. Enter as the builder seat first." — checked against
    each of `prompt` and `description` separately, since either can open
    this way. A trailing word character, apostrophe, or hyphen is excluded
    (`(?![\\w'-])`) so a compound word ("Hanuman-style build notes",
    "Hanuman's seat") does not read as addressing the seat directly
    (regex-boundary defect, Loki re-audit 2026-09-21)."""
    if not text:
        return None
    stripped = text.lstrip()
    for row in rows:
        for name in filter(None, (row.get("display_name"), row.get("agent_id"))):
            pat = re.compile(r"^\**%s\**(?![\w'-])\b[,:]?" % re.escape(name), re.IGNORECASE)
            if pat.match(stripped):
                return row
    return None


def _find_persona_path_seat(text: str, by_id: dict) -> Optional[dict]:
    """A `personas/<seat>.md` reference — "Read personas/hanuman.md and
    adopt it" is entry framing even with no app_id= or "You are" in sight."""
    m = re.search(r"personas/([A-Za-z0-9_-]+)\.md", text, re.IGNORECASE)
    if m is None:
        return None
    return by_id.get(m.group(1).lower())


def _find_bare_app_id_seat(text: str, by_id: dict) -> Optional[dict]:
    """Weakest tier: a bare app_id=<seat> with no other framing at all
    (`{"app_id": "hanuman"}`, `app_id: hanuman` alone). Callers must mask
    read-only lookup calls out of `text` first (see _mask_read_only_calls).
    A mention on a line that also says "grep" ("grep app_id=loki in tests")
    is a search reference, not an entry, and is skipped."""
    for m in _APP_ID_RE.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line = text[line_start: line_end if line_end != -1 else len(text)]
        if re.search(r"\bgrep\b", line, re.IGNORECASE):
            continue
        seat = by_id.get(m.group(1).lower())
        if seat is not None:
            return seat
    return None


# Tier names, strongest first — see _detect_specialist_seat. Only the two
# strongest are enough to refuse the human_only orchestrator seat; a bare
# mention (app_id=, persona path, comma-start) of `willow` in a lookup
# prompt must not hard-refuse a non-seat spawn.
_TIER_SESSION_ENTER = "session_enter"
_TIER_YOU_ARE = "you_are"
_TIER_COMMA_START = "comma_start"
_TIER_PERSONA_PATH = "persona_path"
_TIER_BARE_APP_ID = "bare_app_id"
_HUMAN_ONLY_TIERS = frozenset({_TIER_SESSION_ENTER, _TIER_YOU_ARE})


def _detect_specialist_seat(prompt: str, description: str, rows: list) -> Optional["tuple[dict, str]"]:
    """Find the fleet seat a spawn's prompt OR description names by
    ENTERING it, and which tier matched (see the _TIER_* constants). Scans
    both fields — a fork's description ("hanuman builds") can carry the same
    framing its prompt does. Returns None when neither field names a known
    seat by entry — an ordinary Explore/Plan/general-purpose spawn, or a
    prompt that only MENTIONS a seat inside a read-only lookup call, is not
    this guard's business."""
    by_id = {row["agent_id"].lower(): row for row in rows if row.get("agent_id")}
    combined = "\n".join(t for t in (prompt, description) if t)
    if not combined:
        return None

    seat = _find_session_enter_seat(combined, by_id)
    if seat is not None:
        return seat, _TIER_SESSION_ENTER

    seat = _find_you_are_seat(combined, rows)
    if seat is not None:
        return seat, _TIER_YOU_ARE

    for text in (prompt, description):
        seat = _find_comma_start_seat(text, rows)
        if seat is not None:
            return seat, _TIER_COMMA_START

    seat = _find_persona_path_seat(combined, by_id)
    if seat is not None:
        return seat, _TIER_PERSONA_PATH

    seat = _find_bare_app_id_seat(_mask_read_only_calls(combined), by_id)
    if seat is not None:
        return seat, _TIER_BARE_APP_ID

    return None


def check_agent_spawn(tool_input: dict) -> Optional["tuple[str, str]"]:
    """Sealed rule c9ca1a09 (pair 72f528ab, record b4a8cbe7, gap
    20e6d23971dc): a specialist Agent spawn must carry the model its role is
    pinned to, and a fork can never carry one at all — a spawn is a one-shot
    decision with no cheap do-over once the wrong model is loaded, so this
    always blocks rather than warns. Refuses:

    - the orchestrator seat (willow) as a spawn target, but ONLY when named
      by the two strongest framings (session_enter(...) or a "You are" /
      "You're" / "Enter as" sentence) — a bare app_id=willow mention (a
      lookup argument, a persona-path reference, or text that merely opens
      with the word "Willow") is not an attempt to become the seat and is
      not refused this way;
    - subagent_type="fork" (case-insensitive) naming any other specialist
      seat by any framing tier — a fork inherits the parent's model and
      cannot be pinned;
    - a pinned-role seat (role present in specialists.json's
      model_hint_session, via _load_spawn_models) spawned with no model, or
      a model that isn't the table's value for that role.

    Detection scans prompt AND description — see _detect_specialist_seat —
    and prefers the seat named inside a session_enter(...) call over any
    other mention in the same text. A prompt/description naming no known
    seat by entry (Explore, Plan, an unpinned general-purpose spawn, or a
    prompt that only mentions a seat inside a read-only lookup call) passes
    through untouched.

    Cursor dialect is explicitly OUT of scope for this one guard: Cursor's
    equivalent-tool payload shape for a specialist spawn (tool name and
    argument keys) is not established, so main() only wires this to the
    Claude Code `Agent` tool_name. The other nine guards in this module are
    unaffected and still route through cursor_permission_for_guard as
    before.

    Stated limits (Loki re-audit 2026-09-21) — detection is regex over
    prompt/description text, not semantic understanding, and these shapes
    pass through undetected:

    - base64 (or other) encoding of the seat-naming text;
    - zero-width characters or markdown formatting split MID-WORD through a
      seat's name (e.g. a zero-width space inside "Han​uman"), as
      opposed to markdown bolding AROUND a whole name, which IS detected;
    - variable indirection — `seat = "hanuman"; session_enter(app_id=seat)`,
      or a variable assigned earlier and referenced later — since the guard
      never evaluates the prompt as code, only pattern-matches its literal
      text;
    - a stateless fork with an empty description and a prompt like "continue
      as before": the hook has no memory of a prior turn's "You are Hanuman"
      framing, so a fork resuming a specialist persona by implication rather
      than restating it passes through unrefused. This is a property of the
      hook running once per tool call with no session state, not a gap in
      any one regex.

    Two prose shapes were found and are NOT limits — they are masked out
    before the bare-app_id tier runs (see _mask_read_only_calls /
    _READ_ONLY_PROSE_APP_ID_RE): a read-only lookup call named without
    parentheses ("Run handoff_read with app_id=hanuman") is masked the same
    as its parenthesised form; a display name directly followed by a
    hyphen or apostrophe at the start of text ("Hanuman-style build notes")
    is excluded from the comma-start tier as a compound word, not an
    address to the seat."""
    tool_input = tool_input or {}
    prompt = str(tool_input.get("prompt", "") or "")
    description = str(tool_input.get("description", "") or "")
    subagent_type = str(tool_input.get("subagent_type", "") or "").strip().lower()
    model = str(tool_input.get("model", "") or "")
    rows, used_fallback = _load_specialist_rows()
    detected = _detect_specialist_seat(prompt, description, rows)
    if detected is None:
        return None
    seat, tier = detected
    agent_id = seat.get("agent_id", "")
    note = (
        " (specialists.json unreadable — literal fallback registry used)"
        if used_fallback else ""
    )
    if seat.get("human_only"):
        if tier not in _HUMAN_ONLY_TIERS:
            # A bare mention of the orchestrator seat (lookup argument,
            # persona path, comma-start) is not an attempt to enter it.
            return None
        return "block", (
            f"willow-mcp: sealed rule {_SPAWN_GUARD_RULE} — the '{agent_id}' "
            "seat is the human-orchestrator seat and is never an Agent spawn "
            f"target{note}. Dispatch it a packet instead."
        )
    role = seat.get("role", "")
    required = _load_spawn_models().get(role)
    if subagent_type == "fork":
        hint = f', model="{required}"' if required else ""
        return "block", (
            f"willow-mcp: sealed rule {_SPAWN_GUARD_RULE} — this prompt/description "
            f"names the '{agent_id}' seat with subagent_type=\"fork\"{note}, and a "
            "fork cannot carry a model pin. Retry with "
            f'subagent_type="general-purpose"{hint}.'
        )
    if required and model != required:
        return "block", (
            f"willow-mcp: sealed rule {_SPAWN_GUARD_RULE} — the '{agent_id}' "
            f"seat (role '{role}') is pinned to model=\"{required}\"{note}, "
            f"got model={model!r}. Retry with "
            f'subagent_type="general-purpose", model="{required}".'
        )
    return None


def _is_file_write(tool_name: str) -> bool:
    return tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit")


def _is_task_submit(tool_name: str) -> bool:
    # Matches the bare tool name and the MCP-qualified form
    # (e.g. mcp__willow-mcp__task_submit / mcp__willow-mcp-serve__task_submit).
    return tool_name == "task_submit" or tool_name.endswith("__task_submit")


def main() -> None:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        sys.exit(0)

    from willow_mcp.cursor_hook_io import (
        extract_shell_command,
        is_cursor_dialect,
        is_cursor_mcp_event,
        is_cursor_shell_event,
        normalize_cursor_mcp_payload,
    )

    if is_cursor_shell_event(payload):
        command = extract_shell_command(payload)
        if command.strip():
            from willow_mcp.cursor_hook_io import run_cursor_shell_guards

            run_cursor_shell_guards(
                command,
                check_bash_self_grant=check_bash_self_grant,
                check_bash_remote_fail_closed=check_bash_remote_fail_closed,
                check_bash=check_bash,
                check_bash_routing=check_bash_routing,
            )
        from willow_mcp.cursor_hook_io import emit_cursor_permission

        emit_cursor_permission("allow")
        sys.exit(0)

    cursor_dialect = is_cursor_dialect(payload)
    if is_cursor_mcp_event(payload):
        payload = normalize_cursor_mcp_payload(payload)

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    tool_base = tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name

    native = check_native_web(tool_base)
    corpus = check_corpus_first(tool_base)
    if native:
        decision, route_reason = native
        # compose, don't clobber: check_native_web already hard-blocks native
        # WebSearch and redirects to willow_web_search — append the
        # corpus-first reminder to that same decision instead of emitting a
        # second, conflicting one (only one decision reaches the caller).
        if corpus:
            route_reason = f"{route_reason} {corpus[1]}"
        if cursor_dialect:
            from willow_mcp.cursor_hook_io import cursor_permission_for_guard

            cursor_permission_for_guard(decision, route_reason)
            sys.exit(0)
        print(json.dumps({"decision": decision, "reason": route_reason}))
    elif corpus:
        decision, reason = corpus
        if cursor_dialect:
            from willow_mcp.cursor_hook_io import cursor_permission_for_guard

            cursor_permission_for_guard(decision, reason)
            sys.exit(0)
        print(json.dumps({"decision": decision, "reason": reason}))
    elif tool_name in ("Bash", "Shell"):
        command = tool_input.get("command", "") or extract_shell_command(payload)
        reason = (
            check_bash_self_grant(command)
            or check_bash_remote_fail_closed(command)
            or check_bash(command)
        )
        if reason:
            if cursor_dialect:
                from willow_mcp.cursor_hook_io import cursor_permission_for_guard

                cursor_permission_for_guard("block", reason)
                sys.exit(0)
            from willow_mcp.cursor_hook_io import emit_claude_block

            emit_claude_block(reason)
        else:
            routed = check_bash_routing(command)
            if routed:
                decision, route_reason = routed
                if cursor_dialect:
                    from willow_mcp.cursor_hook_io import cursor_permission_for_guard

                    cursor_permission_for_guard(decision, route_reason)
                    sys.exit(0)
                if decision == "block":
                    from willow_mcp.cursor_hook_io import emit_claude_block

                    emit_claude_block(route_reason)
                else:
                    from willow_mcp.cursor_hook_io import emit_claude_warn

                    emit_claude_warn(route_reason)
            elif cursor_dialect:
                from willow_mcp.cursor_hook_io import emit_cursor_permission

                emit_cursor_permission("allow")
                sys.exit(0)
    elif _is_file_write(tool_name) or _is_file_write(tool_base):
        reason = check_owned_db_file_write(tool_input) or check_trust_root_write(tool_input)
        if reason:
            if cursor_dialect:
                from willow_mcp.cursor_hook_io import cursor_permission_for_guard

                cursor_permission_for_guard("block", reason)
                sys.exit(0)
            from willow_mcp.cursor_hook_io import emit_claude_block

            emit_claude_block(reason)
    elif _is_task_submit(tool_name) or _is_task_submit(tool_base):
        blocked = check_task_submit_self_grant(tool_input)
        if blocked:
            if cursor_dialect:
                from willow_mcp.cursor_hook_io import cursor_permission_for_guard

                cursor_permission_for_guard("block", blocked)
                sys.exit(0)
            from willow_mcp.cursor_hook_io import emit_claude_block

            emit_claude_block(blocked)
        else:
            reason = check_task_submit(tool_input)
            if reason:
                if cursor_dialect:
                    from willow_mcp.cursor_hook_io import cursor_permission_for_guard

                    cursor_permission_for_guard("warn", reason)
                    sys.exit(0)
                from willow_mcp.cursor_hook_io import emit_claude_warn

                emit_claude_warn(reason)
    elif tool_name == "Agent" or tool_base == "Agent":
        spawned = check_agent_spawn(tool_input)
        if spawned:
            _decision, reason = spawned
            if cursor_dialect:
                from willow_mcp.cursor_hook_io import cursor_permission_for_guard

                cursor_permission_for_guard(_decision, reason)
                sys.exit(0)
            from willow_mcp.cursor_hook_io import emit_claude_block

            emit_claude_block(reason)
    if cursor_dialect:
        from willow_mcp.cursor_hook_io import emit_cursor_permission

        emit_cursor_permission("allow")
    sys.exit(0)


if __name__ == "__main__":
    main()
