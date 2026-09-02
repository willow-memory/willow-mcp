#!/usr/bin/env bash
# fleet-standup.sh — stand up willow-mcp, jeles and nestor together, idempotently.
#
# DEV-ONLY, and one layer above `sandbox-bootstrap.sh`. That script proves
# willow-mcp works *alone*; this one proves the three packages are wired to
# **each other** — one venv, one SOIL store, one gate, one hash chain — and
# ends by checking every seam rather than asserting it.
#
#   bash scripts/fleet-standup.sh
#
# It does, in order (each step safe to re-run):
#   1. locate the three checkouts                    (JELES_REPO / NESTOR_REPO)
#   2. fetch tags in each, so hatch-vcs versions resolve and pins are satisfiable
#   3. run sandbox-bootstrap.sh                      (venv, $WILLOW_HOME, Postgres)
#   4. pip install -e the jeles and nestor checkouts INTO that same venv
#   5. seat `nestor` in the gate                     ($WILLOW_HOME/mcp_apps/nestor)
#   6. write $WILLOW_HOME/fleet.env                  (the shared environment)
#   7. run scripts/fleet_seams.py                    (six seams, pass/fail)
#
# Knobs:
#   JELES_REPO    path to the Jeles checkout      (default: ../Jeles, ../jeles)
#   NESTOR_REPO   path to the Nestor checkout     (default: ../Nestor, ../nestor)
#   WILLOW_HOME   where fleet state lives         (default: <repo>/.willow)
#   WILLOW_FLEET_REFRESH_REGISTRY=1
#                 overwrite $WILLOW_HOME/config/specialists.json from the
#                 product bundle (keeps a backup). Needed on a home scaffolded
#                 before the librarian seat was granted gap_write — see step 5.
#   WILLOW_SKIP_PG=1  SOIL-only; the FRANK seam then reports SKIP, not PASS.
#
# Anything not found is reported and skipped: a two-of-three stand-up is a real
# and useful state, and pretending otherwise is how a missing half goes unnoticed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VENV="$REPO_ROOT/.venv"
PY="$VENV/bin/python3"
export WILLOW_HOME="${WILLOW_HOME:-$REPO_ROOT/.willow}"
export WILLOW_STORE_ROOT="${WILLOW_STORE_ROOT:-$WILLOW_HOME/store}"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
warn() { printf '   \033[33m! %s\033[0m\n' "$*"; }

# ── 1. locate the sibling checkouts ───────────────────────────────────────────
say "locate checkouts"

find_repo() {           # find_repo VARNAME candidate...
  local var="$1"; shift
  local set_to="${!var:-}"
  if [ -n "$set_to" ]; then
    [ -d "$set_to" ] && { echo "$set_to"; return 0; }
    return 1
  fi
  local c
  for c in "$@"; do
    [ -d "$c" ] && { (cd "$c" && pwd); return 0; }
  done
  return 1
}

PARENT="$(dirname "$REPO_ROOT")"
JELES_REPO="$(find_repo JELES_REPO "$PARENT/Jeles" "$PARENT/jeles" || true)"
NESTOR_REPO="$(find_repo NESTOR_REPO "$PARENT/Nestor" "$PARENT/nestor" || true)"

echo "willow-mcp  $REPO_ROOT"
if [ -n "$JELES_REPO" ]; then echo "jeles       $JELES_REPO"
else warn "jeles not found — set JELES_REPO=/path/to/Jeles (gap + corpus seams will fail)"; fi
if [ -n "$NESTOR_REPO" ]; then echo "nestor      $NESTOR_REPO"
else warn "nestor not found — set NESTOR_REPO=/path/to/Nestor (FRANK + bridge seams will skip)"; fi

# ── 2. tags, so the version numbers are real ─────────────────────────────────
say "fetch tags"
# Not cosmetic. jeles and willow-mcp both take their version from the git tag via
# hatch-vcs, and a tagless clone (`git clone --depth`, or a fresh CI checkout)
# builds as 0.1.devN — which does NOT satisfy willow-mcp's own `jeles>=0.5.1`,
# so `pip install -e` of both leaves a resolver conflict that looks like a bad
# pin and is really a missing `git fetch --tags`.
for repo in "$REPO_ROOT" ${JELES_REPO:+"$JELES_REPO"} ${NESTOR_REPO:+"$NESTOR_REPO"}; do
  name="$(basename "$repo")"
  if ! git -C "$repo" rev-parse --git-dir >/dev/null 2>&1; then
    warn "$name is not a git checkout — skipping"
    continue
  fi
  if git -C "$repo" remote get-url origin >/dev/null 2>&1; then
    git -C "$repo" fetch --tags --quiet origin 2>/dev/null || warn "$name: tag fetch failed (offline?)"
  fi
  echo "$name $(git -C "$repo" describe --tags 2>/dev/null || echo '(no tags — version will be 0.1.devN)')"
done

# ── 3. the hub ────────────────────────────────────────────────────────────────
say "willow-mcp sandbox"
bash "$REPO_ROOT/scripts/sandbox-bootstrap.sh"

# ── 4. the other two, into the SAME venv ─────────────────────────────────────
say "install jeles + nestor (editable, same venv)"
# One venv on purpose. willow-mcp imports jeles in-process for institutional
# search, and nestor's recipes import jeles' corpus — across two venvs those
# imports resolve to whatever PyPI last published, so the checkout you are
# editing is not the code that runs, and nothing says so.
declare -a specs=()
[ -n "$JELES_REPO" ]  && specs+=("-e" "${JELES_REPO}[mcp]")
[ -n "$NESTOR_REPO" ] && specs+=("-e" "$NESTOR_REPO")
if [ ${#specs[@]} -gt 0 ]; then
  "$PY" -m pip install -q "${specs[@]}"
fi
"$PY" - <<'PY'
import importlib, os
from importlib.metadata import PackageNotFoundError, version
for mod, dist in (("willow_mcp", "willow-mcp"), ("jeles", "jeles"), ("nestor", "nestor")):
    try:
        m = importlib.import_module(mod)
        v = version(dist)
    except (ImportError, PackageNotFoundError) as exc:
        print(f"  {dist:12} NOT INSTALLED ({type(exc).__name__})")
        continue
    print(f"  {dist:12} {v:24} {os.path.dirname(m.__file__ or '')}")
PY
"$PY" -m pip check || warn "dependency conflicts above — usually a missing 'git fetch --tags'"

if [ -n "$NESTOR_REPO" ]; then
  say "nestor established-knowledge lane"
  "$PY" - <<'PY' || warn "established lane install failed (non-fatal)"
try:
    from nestor.established import install, installed
    install()
    print("  tier-1.5 recognizer:", "installed" if installed() else "NOT installed")
except Exception as exc:
    raise SystemExit(str(exc))
PY
fi

# ── 5. seats in the gate ─────────────────────────────────────────────────────
say "gate seats"
# willow-mcp authorizes every tool call against
# $WILLOW_HOME/mcp_apps/<app_id>/manifest.json. Two seats matter here:
#
#   jeles   a seeded specialist. Carries gap_write as of 2.4 — without it,
#           jeles' forward_gap() is denied and (before this release) said
#           nothing about it.
#   nestor  NOT a seeded specialist, and deliberately not: nestor is a package
#           that mirrors its ledger into FRANK, not a dispatchable agent with a
#           persona. So its manifest is operator-local — written here, never
#           compiled from the registry, and left alone by `compile-agents`.
REGISTRY="$WILLOW_HOME/config/specialists.json"
BUNDLE_REGISTRY="$("$PY" -c 'import willow_mcp,os;print(os.path.join(os.path.dirname(willow_mcp.__file__),"bundle","config","specialists.json"))')"
if [ "${WILLOW_FLEET_REFRESH_REGISTRY:-0}" = "1" ] && [ -f "$BUNDLE_REGISTRY" ]; then
  cp -f "$REGISTRY" "$REGISTRY.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
  cp -f "$BUNDLE_REGISTRY" "$REGISTRY"
  echo "refreshed $REGISTRY from the product bundle (backup kept)"
fi
"$VENV/bin/willow-mcp-compile" --force >/dev/null && echo "manifests compiled"

if ! "$PY" -c "
import json,sys
p=json.load(open('$WILLOW_HOME/mcp_apps/jeles/manifest.json'))
sys.exit(0 if 'gap_write' in p.get('permissions',[]) else 1)" 2>/dev/null; then
  warn "the jeles seat has no gap_write — its gap forwarding will be denied."
  warn "This home was scaffolded before that grant; re-run with WILLOW_FLEET_REFRESH_REGISTRY=1"
  warn "(or add \"gap_read\",\"gap_write\" to the jeles row in $REGISTRY)."
fi

NESTOR_MANIFEST="$WILLOW_HOME/mcp_apps/nestor/manifest.json"
if [ -f "$NESTOR_MANIFEST" ]; then
  echo "nestor seat already present — left as-is"
else
  mkdir -p "$(dirname "$NESTOR_MANIFEST")"
  cat > "$NESTOR_MANIFEST" <<'JSON'
{
  "app_id": "nestor",
  "human_only": false,
  "role": "verifier",
  "permissions": [
    "fleet_read",
    "frank_write",
    "gap_read"
  ],
  "deny_tools": [
    "task_submit",
    "kb_promote",
    "knowledge_ingest",
    "gap_promote"
  ],
  "store_scope": [
    "nestor_*"
  ]
}
JSON
  echo "seated nestor: frank_write (mirror its ledger), fleet_read (verify the chain),"
  echo "               gap_read (import the backlog). No gap_write and no gap_promote —"
  echo "               nestor reads what the fleet doesn't know; it doesn't answer for it."
fi

# ── 6. the shared environment ────────────────────────────────────────────────
say "fleet env"
# Every seam below keys off these. WILLOW_STORE_ROOT in particular is the one
# that fails silently when unset: jeles falls back to ~/.willow/store, willow-mcp
# serves $WILLOW_HOME/store, and both work perfectly on two different databases.
FLEET_ENV="$WILLOW_HOME/fleet.env"
{
  echo "# Written by scripts/fleet-standup.sh. Source before using the fleet:"
  echo "#     . $FLEET_ENV"
  echo "export WILLOW_HOME=$WILLOW_HOME"
  echo "export WILLOW_STORE_ROOT=$WILLOW_STORE_ROOT"
  echo "export WILLOW_PG_DB=${WILLOW_PG_DB:-willow}"
  echo "export WILLOW_PG_USER=${WILLOW_PG_USER:-${USER:-$(id -un)}}"
  echo "# The gate seat each package calls as. jeles' own default is 'ask-jeles',"
  echo "# which willow-mcp does not seed — so it must be said out loud here."
  echo "export JELES_CORPUS_APP_ID=jeles"
  echo "export NESTOR_FRANK_APP_ID=nestor"
  echo "#"
  echo "# WILLOW_APP_ID is deliberately NOT exported here. It is client-scoped —"
  echo "# 'the seat THIS client is driving' — so a fleet-wide value is read by"
  echo "# every package in the process that falls back to it. Exporting"
  echo "# WILLOW_APP_ID=willow re-seated nestor's FRANK mirror as the"
  echo "# orchestrator, which willow-mcp refuses (frank_append as 'willow'"
  echo "# requires a human-orchestrator host). Set it per client, per shell:"
  echo "#     WILLOW_APP_ID=hanuman <your mcp client>"
  [ -n "$NESTOR_REPO" ] && echo "export NESTOR_REPO=$NESTOR_REPO"
  [ -n "$JELES_REPO" ]  && echo "export JELES_REPO=$JELES_REPO"
  echo "export PATH=$VENV/bin:\$PATH"
} > "$FLEET_ENV"
echo "wrote $FLEET_ENV"

# ── 7. does it actually join up? ─────────────────────────────────────────────
say "seams"
set +u; . "$FLEET_ENV"; set -u
# In a condition, so `set -e` does not abort here — a failing seam check must
# still reach the summary below and exit with its own status, rather than
# killing the script one line before it can say anything about why.
if "$PY" "$REPO_ROOT/scripts/fleet_seams.py"; then
  rc=0
else
  rc=$?
fi

echo
if [ $rc -eq 0 ]; then
  echo "Fleet is up. Source the env in any shell that talks to it:"
  echo
  echo "    . $FLEET_ENV"
  echo
  echo "Server command:  $PY -m willow_mcp"
  echo "Re-check seams:  $PY $REPO_ROOT/scripts/fleet_seams.py"
else
  echo "A seam is broken — the fleet is NOT wired up. Detail is in the table above."
  echo "Re-check after fixing:  $PY $REPO_ROOT/scripts/fleet_seams.py"
fi
exit $rc
