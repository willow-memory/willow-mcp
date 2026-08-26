"""willow-mcp Claude Code hook — PreToolUse.

Seven guards:
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

That third guard is the sudo invariant (FRANK `90e52ab7`) enforced where the
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
import sys
from typing import Optional

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

# The willow human-orchestrator seat. Repo maintenance — commit, push, PR — IS
# that seat's job, so the git/gh routing nudges toward task_submit are pure
# friction for it. The self-grant guard (egress keys, leases, manifest task_net)
# runs BEFORE routing and is NEVER lifted, for this or any seat, so exempting the
# routing steering surrenders no authority. The signal is the server env the
# SessionStart hook exports into the session (.mcp.json / CLAUDE_ENV_FILE).
_ORCHESTRATOR_APP_ID = "willow"

# The git/gh routing entries, named so the loop can lift exactly these for the
# orchestrator seat (and nothing else) without matching on hint text.
_ROUTE_GIT_NET_RE = re.compile(r"\bgit\s+(push|pull)\b")
_ROUTE_GIT_MUT_RE = re.compile(
    r"\bgit\s+(add|commit|checkout|merge|rebase|worktree|clone|stash|reset|"
    r"restore|switch|clean|cherry-pick|revert|tag)\b")
_ROUTE_GH_RE = re.compile(r"\bgh\s")

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
    (_ROUTE_GIT_NET_RE, "block", f"git network → {_TASK_SUBMIT_NET}"),
    (_ROUTE_GIT_MUT_RE, "block", f"git mutation → {_TASK_SUBMIT}"),
    (_ROUTE_GH_RE, "block", f"gh (mutations / net) → {_TASK_SUBMIT_NET}"),
    (re.compile(r"(?i)python3?\s+.*<<"), "block", f"Python heredoc → {_TASK_SUBMIT}"),
    (re.compile(r"(?i)\bgrep\b|\brg\b"), "warn",
     f"knowledge_search / store_search · symbols → code_graph_search · {_TASK_SUBMIT}"),
    (re.compile(r"(?i)\bfind\s"), "warn",
     f"code_graph_search / knowledge_search · {_TASK_SUBMIT}"),
    (_ROUTE_WEB_FETCH_RE, "block", "willow_web_fetch (MCP) — guarded fetch, not raw {curl,wget}"),
    (_ROUTE_PKG_INSTALL_RE, "block", f"package install reaches the network → {_TASK_SUBMIT_NET}"),
    (_ROUTE_REMOTE_RE, "block", f"remote network access → {_TASK_SUBMIT_NET}"),
    (_ROUTE_BACKGROUND_RE, "warn",
     f"backgrounded/detached process is untracked outside this session → {_TASK_SUBMIT}"),
    (_ROUTE_SCRIPT_RE, "warn", f"script/build execution → {_TASK_SUBMIT}"),
    (_ROUTE_FS_MUTATE_RE, "warn", f"scripted/bulk filesystem change → {_TASK_SUBMIT}"),
]

# Exactly the git/gh routing steers the orchestrator seat is exempt from.
_GIT_GH_ROUTING = frozenset({_ROUTE_GIT_NET_RE, _ROUTE_GIT_MUT_RE, _ROUTE_GH_RE})


def _env_declares_orchestrator() -> bool:
    if os.environ.get("WILLOW_HUMAN_ORCHESTRATOR", "").strip() == "1":
        return True
    return os.environ.get("WILLOW_APP_ID", "").strip().lower() == _ORCHESTRATOR_APP_ID


def _project_dir() -> Optional[str]:
    """The project root, from CLAUDE_PROJECT_DIR. The harness sets it on every
    hook invocation; it is the one reliable pointer to where .mcp.json lives."""
    return os.environ.get("CLAUDE_PROJECT_DIR") or None


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


def check_bash_routing(command: str) -> Optional[tuple[str, str]]:
    """Return (decision, reason) when a Bash habit should redirect to MCP, else None."""
    if not command or _git_gh_inspect_allowed(command):
        return None
    orchestrator = _is_orchestrator_seat()
    for pattern, decision, hint in _BASH_ROUTING:
        if pattern.search(command):
            # The orchestrator seat is not steered off git/gh; every other
            # routing entry (psql/sqlite3/ls/…) still applies to it.
            if orchestrator and pattern in _GIT_GH_ROUTING:
                continue
            return decision, f"willow-mcp: prefer MCP tools — {hint}"
    if not orchestrator and (_GIT_MUTATION_RE.search(command) or _GH_MUTATION_RE.search(command)):
        return "block", f"willow-mcp: prefer MCP tools — git/gh mutation → {_TASK_SUBMIT}"
    return None


_WEB_SEARCH_REDIRECT = (
    "Use willow_web_search (MCP) for open-web search — not native WebSearch. "
    "Requires web_net + consent.internet + operator egress lease."
)
_WEB_FETCH_REDIRECT = (
    "WebFetch is blocked — use willow_web_fetch (MCP) for guarded URL fetch "
    "with external-guard scan. Requires web_net + consent.internet + lease."
)


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
    protection with one more tool call, not just a less-preferred one."""
    if tool_name == "WebSearch":
        return "block", f"willow-mcp: {_WEB_SEARCH_REDIRECT}"
    if tool_name == "WebFetch":
        return "block", f"willow-mcp: {_WEB_FETCH_REDIRECT}"
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
_LEASE_DIR_RE = re.compile(r"mcp_apps/_net_leases\b")
# The identity keystore ($WILLOW_HOME/gate/): per-agent HMAC secrets + the trust
# registry. Minting/rotating an identity or a trust ceiling by writing these is
# the same operator-only authority as minting a lease — an agent may request
# standing, never write its own secret (D2). Reading is not blocked.
_KEYSTORE_RE = re.compile(r"gate/(?:secrets\b|registry\.json)")
_GRANT_CMD_RE = re.compile(
    r"\bwillow-mcp\s+(?:grant-net|dev-net|sign-net-task|register-agent|revoke-agent|rotate-agent|consent\s+(?:set|reconcile)|roster\s+sync)\b"
    r"|\bwillow_mcp\s+(?:grant-net|dev-net|sign-net-task|register-agent|revoke-agent|rotate-agent)\b"
    r"|\b(?:lease\.grant|sign_envelope|agent_registry\.(?:register_agent|revoke))\s*\("
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
    r"gap_promote|gap_purge|gap_write|grove_all|grove_write|human_loop_write|integration_call|"
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

_SEAT_ESCALATION_REASON = (
    "willow-mcp: this edits a manifest to add a WRITE-capable permission group "
    "(store_write / store_all / knowledge_write / knowledge_curate / lineage_write / schema_admin / "
    "nest_write / gap_write / gap_promote / gap_purge / friction_write / task_db / "
    "task_queue / dispatch_write / human_loop_write / frank_write / envelope_apply / envelope_write / "
    "fork_write / commitment_write / code_graph_write / agent_dispatch / grove_write / grove_all / "
    "integration_call / federation_call / markdownai_write / markdownai_directives / orchestrator / "
    "context / binding / tool_oracle_route / tool_oracle_seal / full_access) or widen store_scope to "
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


def check_bash_self_grant(command: str) -> Optional[str]:
    """Block a command that mints a lease/envelope, grants itself task_net, or
    edits a manifest to retake a write-capable seat.

    Writes only. `cat`ting a lease, `willow-mcp net-status`, and `revoke-net` are
    all fine — reading a key is not holding one, and giving one up is never
    escalation.
    """
    if not command:
        return None
    if _GRANT_CMD_RE.search(command):
        return _SELF_GRANT_REASON
    for _m in _ALLOW_PERMISSION_GRANT_RE.finditer(command):
        perm = _m.group(1)
        if (_NET_CAP_RE.fullmatch(perm) or _SEAT_PRIV_RE.fullmatch(perm)
                or perm in _ALLOW_PERMISSION_SEAT_BARE):
            return _ALLOW_PERMISSION_REASON
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
    """Block a Write/Edit that mints a lease, writes an identity secret, or slips
    `task_net` into a manifest."""
    tool_input = tool_input or {}
    path = str(tool_input.get("file_path", "") or "")
    if not path:
        return None
    if _LEASE_DIR_RE.search(path):
        return _SELF_GRANT_REASON
    if _KEYSTORE_RE.search(path):
        return _KEYSTORE_REASON
    if _MANIFEST_RE.search(path):
        # Only the permissions that carry escalation. Editing a manifest for any
        # other reason is ordinary work and must not be blocked.
        written = " ".join(str(tool_input.get(k, "") or "")
                           for k in ("content", "new_string", "new_str"))
        if _NET_CAP_RE.search(written):
            return _SELF_GRANT_REASON
        if (_SEAT_PRIV_RE.search(written) or _SEAT_PRIV_QUOTED_RE.search(written)
                or _SCOPE_ALL_RE.search(written)):
            return _SEAT_ESCALATION_REASON
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

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}

    native = check_native_web(tool_name)
    if native:
        decision, route_reason = native
        print(json.dumps({"decision": decision, "reason": route_reason}))
    elif tool_name == "Bash":
        command = tool_input.get("command", "")
        reason = (
            check_bash_self_grant(command)
            or check_bash_remote_fail_closed(command)
            or check_bash(command)
        )
        if reason:
            print(json.dumps({"decision": "block", "reason": reason}))
        else:
            routed = check_bash_routing(command)
            if routed:
                decision, route_reason = routed
                print(json.dumps({"decision": decision, "reason": route_reason}))
    elif _is_file_write(tool_name):
        reason = check_owned_db_file_write(tool_input) or check_trust_root_write(tool_input)
        if reason:
            print(json.dumps({"decision": "block", "reason": reason}))
    elif _is_task_submit(tool_name):
        blocked = check_task_submit_self_grant(tool_input)
        if blocked:
            print(json.dumps({"decision": "block", "reason": blocked}))
        else:
            reason = check_task_submit(tool_input)
            if reason:
                print(json.dumps({"decision": "warn", "reason": reason}))
    sys.exit(0)


if __name__ == "__main__":
    main()
