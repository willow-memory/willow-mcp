#!/usr/bin/env bash
# manifest-grant as a system unit under the trust owner — the installer.
#
# Sealed 1bd6fd29 (2026-09-22): "Setup is the installer's (root, once, detects
# rather than asks). Operations are Willow's, executed by the trust-owner apply
# half under a sealed pair. The operator's only keyboard act is the seal."
# Sealed 1fdfbdf3 (2026-09-21): the system unit under the trust owner, the
# preconditions INSTALL.md (beside this file) narrates in prose.
# Sealed 31f5d3af (2026-09-22): "The active envelope register
# (constitutional/pre-approved.json) and the federation registry
# (mcp_apps/_federation/servers.json) are owned by the trust owner, mode
# 0644, no ACLs, detach-signed under WILLOW_PGP_FINGERPRINT — the same
# trust shape as a seat manifest. [...] envelope_propose writes a
# broker-owned proposals file; ratify moves a proposal into the signed
# register; revoke, retirement, and federation.ratify write only through
# the trust-owner apply half, which re-signs on every write."
# This script is the setup half, collapsed to one root act. It never asks a
# question: every judgement left to the operator is detected here and either
# acted on or reported as a stop.
#
#   sudo bash install.sh --expect-head <40-hex sha>
#                                   # installs from THAT commit (see the pin below)
#   sudo bash install.sh --check --expect-head <sha>
#                                   # detect-only, change nothing (reports the
#                                   # trust-owner interpreter checks too)
#   sudo bash install.sh --provision-venv --expect-head <sha>
#                                   # (re)build ONLY the trust-owner venv
#                                   # (/opt/willow-operator/venv) and check it;
#                                   # does not touch the unit or the box
#   sudo bash install.sh --record-trust-identity --expect-head <sha>
#                                   # a plain install that ALSO writes the first
#                                   # D1 trust-identity record, only after a clean
#                                   # read-only audit (see INSTALL.md, D1)
#   sudo bash install.sh --re-record-trust-identity [--confirm TOKEN] --expect-head <sha>
#                                   # accept a changed trust-directory identity
#                                   # (diff + audit + a typed or --confirm token)
#   (also --rotate [--retire FPR ...] and --check-signatures, each with
#   --expect-head <sha>; --dry-run-sign needs neither root nor a pin)
#
# Rework 6 (Loki pre-deploy audit of 4d7ccbf..8963929, F1-F4): every mode takes
# --expect-head, the full 40-hex sha of the commit to install, copied from
# GitHub -- NOT from the working tree (the checkout's .git is writable by the
# operator uid and by Kart tasks, so its own HEAD proves nothing). The script
# clones the checkout, then makes THE CLONE be that commit (a moved ref cannot
# redirect it) and re-execs the clone's own copy of this file, so every line of
# privileged shell and every inline python heredoc is read from the pinned
# commit. See "THE PRE-REEXEC SECTION" below for the (small) part that still
# runs from the copy you typed.
#
# Idempotent: every step converges; re-running after a stop is the intended
# recovery. Nothing here reads the broker's env file ($H/env, 0600, provider
# secrets) except WILLOW_PG_DB. The signing fingerprint lives in its own
# trust-owner-owned, world-readable file (dispatch 0CB0C85C:
# $WILLOW_HOME/constitutional/trust.env) — a fingerprint is public, only a
# key's private half is a secret, so it does not belong beside provider keys.
#
# Amendment (pair 1bd6fd29, install.sh audit pass): two prior steps guessed at
# names an auditor would flag —
#   * the request half's broker PUBLIC key filename was discovered with a
#     glob (*.pub / *public*); it is always
#     manifest_grant_executor._broker_public_key_path's own name,
#     broker_public_key.pub — used directly below, no glob.
#   * the broker's --user serve unit was discovered with a glob
#     ('willow-mcp*.service', excluding manifest-grant); the package already
#     names its own unit (reloader.DEFAULT_UNIT /
#     unit_reload_executor._BROKER_UNIT_STEMS): willow-mcp-serve.service,
#     with the bare willow-mcp.service kept as the other spelling those
#     modules also accept. Tried in that order below, no glob.
#
# Rework (Loki audit BFCC5C79, findings F1/F2/F3/F7 — sealed 31f5d3af unblocked
# the register-ownership half):
#   * F1/F2: paths.trusted_read gained a trust-owner+signature branch
#     (src/willow_mcp/paths.py); the envelope register and federation
#     registry now move to trust-owner ownership here instead of a broker
#     ACL — no setfacl on constitutional/ anymore. proposals[]/archived[] are
#     split out to a broker-owned proposals.json BEFORE the register is
#     chowned (below), so envelope_propose keeps writing as the broker,
#     unaffected.
#   * F3: step 6 (re-sign) now also covers the active register and the
#     federation registry, not just seat manifests — the gap that made the
#     first post-fingerprint-change federation.ratify silently drop every
#     other ratified server (mcp_federation._read_registry_file() treats a
#     non-verifying signature as an empty registry, and ratify() does not
#     check the flag). src/willow_mcp/trust_owner_verbs.py's apply half also
#     gained a defensive check refusing EACCES before ever reaching
#     mcp_federation.ratify() if the registry does not verify, as a backstop.
#   * F7: an interpreter check up front (the trust owner's own venv python is
#     used from step 1 on, not just step 6b); the trust owner's traversal of
#     $H itself is checked and fixed (o+x is traversal-only, never exposes
#     $H's own contents); every fixed /tmp name replaced with mktemp (a
#     predictable name in world-writable /tmp is a symlink race); step 6b
#     (withdraw stale pending/) now runs BEFORE the broker restart, not
#     after — restarting first would let a freshly-restarted broker accept a
#     brand-new request into pending/ in the window before 6b runs, and 6b's
#     blanket withdrawal cannot tell a new valid request from a stale one by
#     content alone; and a note that the installer can restart the --user
#     SERVE unit but has no way to reach a stdio-attached desk session (a
#     per-session subprocess it does not own) — the desk must reconnect by
#     hand, named honestly in INSTALL.md rather than implied by the restart
#     step succeeding.
#
# Rework 2 (Loki audit 54E3DFC0, findings R1/R2 — BLOCKING): rework 1's step
# 1 chowned the register FILE to the trust owner but left its DIRECTORY
# ($H/constitutional) operator-owned. paths.trusted_read checks the PARENT
# directory first, so the trust-owner unit was refused before it ever read
# the file (R1) — and because the broker still owned the directory, its own
# writes (propose/reject/ratify, envelope_authoring._save_registry as it
# then was) could still `os.replace` over the "trust-owner-owned" file and
# silently flip it back to broker ownership (R2). "owned by the trust owner
# ... the broker never writes either file" (sealed 31f5d3af) cannot hold
# while the broker owns the directory the file lives in. Fixed: the
# constitutional/ DIRECTORY itself now chowns to the trust owner (0755, no
# ACL) alongside the file; the broker's proposals sidecar moves OUT of that
# directory entirely, into its own broker-owned $H/proposals/ (a sibling,
# never a file inside constitutional/ that the broker could not create,
# rewrite, or unlink in the first place). envelope_authoring.py's write path
# split accordingly: propose()/reject() touch ONLY the sidecar; ratify() is
# the one broker-side act that still touches the register (writes both,
# signs under WILLOW_PGP_FINGERPRINT via --local-user, never gpg's ambient
# default key — R2's other measured defect); revoke() (trust-owner apply
# half only) touches only the register.
#
# Amendment 2 (dispatch A9BF01A9, amending BD5843FD — the operator's first
# real run of this script, and what happened in the hour after):
#   * Step 1c's sync (gap c1395b307421) and its signing used to be TWO acts,
#     separated by steps 2-5 — measured: a pre-existing gpg bug (below) died
#     in that window and left the box with a replaced-but-unsigned
#     syscall-table.json, refused outright by paths.trusted_read and locked
#     harder than before the install ran. sync_constitutional.py's
#     sync_and_sign() now does both in one act, verifies immediately, and
#     rolls back to the exact previous bytes AND .sig on any failure — the
#     signing key setup (formerly step "3") moved ahead of step 1c
#     (now "1b") so $FPR exists before that atomic step needs it.
#   * Carried 338bbdb ("fix(deploy): step 6's sign temp file no longer
#     belongs to the wrong uid") — the gpg bug itself: `SIG_TMP=$(mktemp)`
#     ran as root, `as_to gpg -o "$SIG_TMP"` ran as the trust owner, which
#     cannot open a root-owned file for writing. Fixed everywhere signing
#     happens (step 6's two loops, and sync_and_sign's sign_fn) by never
#     handing gpg a path to open: `--output -` writes to gpg's own stdout,
#     and root's own `>` redirection is what actually owns the fd.
#   * Seeded the envelope.ratify bootstrap envelope (gap 18affe49e198, new
#     step "1d") — with row 24 present, envelope_propose(verb=
#     'envelope.ratify') succeeds but nothing could ever ratify it: no
#     ACTIVE envelope governs envelope.ratify, and the only way to create
#     one is envelope.ratify. Only root, once, spans both uids this
#     deadlock needs; deploy/manifest-grant/seed_envelope_ratify.py calls
#     the same envelope_authoring.ratify_proposal_row the real apply half
#     uses. Idempotent.
#   * install.sh and sync_constitutional.py are now mode 0755 in git —
#     `sudo <path>` (as opposed to `sudo bash <path>`) failed with EACCES on
#     a tracked 0644 script.
#
# Rework 3 (operator rulings Q7=A and Q13, 2026-10-11; Loki audit BFCC5C79 F7
# lineage): the interpreter the trust owner runs was $H/venvs/willow-mcp/bin/
# python -- owned and writable by the operator uid (the one the shell, the bot
# and the agents run as), and an EDITABLE install pointing at the operator's
# checkout -- so any of them could rewrite code that then ran as the trust
# owner. The trust owner now has its own venv at /opt/willow-operator/venv:
# built here as root (step 0a / --provision-venv) from a non-editable wheel,
# root:root 755/644, and the preflight (tvc_report, below) REFUSES unless the
# interpreter, every path component to it (symlinks resolved), and everything
# inside the venv is root-owned and unwritable by any other uid, carries no
# non-root write ACL, and is not an editable install. See INSTALL.md.
#
# Rework 4 (follow-ups to the venv split): the privileged steps run from the
# venv (willow_mcp.install_steps.*), not the checkout; every interpreter call
# is `-I`; the venv's dependencies and the wheel's build backend install only
# from the hash-pinned trust-venv*.requirements.txt files (`pip install
# --require-hashes --only-binary=:all: --no-deps`, wheel built with
# --no-build-isolation in a throwaway build venv). See INSTALL.md.
#
# Rework 5 (the unit, timer and env are code too): the service runs as the trust
# owner, so willow-mcp-manifest-grant.service, .timer and manifest-grant.env are
# no longer installed from $HERE (the operator-writable working tree). They come
# from the same root-owned clone of the committed HEAD the venv is built from
# (ensure_head_clone, one per run, made by the pre-reexec section); the clone's commit must equal the venv's
# .built-from-head stamp; the WHOLE unit, timer and env are checked against an
# allowlist of the directives the committed files carry (mg_*); and after the
# install the files really in /etc are compared to what was rendered from HEAD
# (--check reports drift). Commit before you install: an uncommitted edit to any
# of the three is not installed.

set -euo pipefail

# ==============================================================================
# THE PRE-REEXEC SECTION -- the only part of this file that runs from the copy
# you invoked (the working tree: writable by the operator uid, the bot and the
# agents, and NOT pinned to anything). Loki pre-deploy audit F1: nothing used to
# say WHICH commit root built, and this script itself, with its inline python
# heredocs, was read from that tree. Now:
#
#   1. mg_pre_reexec (below) requires --expect-head <40-hex sha> in every mode,
#      checks it is root, clones the checkout with a neutralized git
#      (mg_git, F2), makes the clone BE that commit (a moved ref, branch, tag or
#      HEAD in the checkout cannot redirect it), and then
#   2. `exec`s the CLONE'S OWN copy of this file. That copy re-verifies that it
#      is the clone's file (root-owned tree, clean, HEAD == the marker ==
#      --expect-head), does NOT clone again, reinstalls the cleanup trap, and
#      only then reads on past this section.
#
# EXACTLY what runs from the unpinned copy, and nothing else (the residual the
# operator reviews -- `sha256sum` this file, or read this section):
#   * this header, `set -euo pipefail`, say/stop, the variable defaults below;
#   * the DEFINITIONS (no side effects) between `# BEGIN pre-reexec` and
#     `# END pre-reexec`: mg_git, mg_expect_head, mg_clone_problems,
#     mg_reexec_problems, ensure_head_clone, mg_pre_reexec;
#   * the one call `mg_pre_reexec 0 "$@"` at the end of this section: it scans
#     the arguments for --expect-head, checks `id -u`, takes $0's directory as the
#     checkout, runs mktemp, mg_git clone / rev-parse / checkout, and `exec`s;
#   * with PATH pinned to /usr/bin:/bin for all of it (sudo's own PATH is
#     restored for the pinned copy), so the binaries are bash, env, id, mktemp,
#     readlink, stat, find, git, rm -- root-owned system tools, assumed;
#   * `--dry-run-sign` only: it skips the call above and the file is read on, to
#     the variable assignments (one `id -u "$OPERATOR"`) and a `cat` of
#     explanatory text, then exits 0. It touches nothing and needs no root.
# Every other line of this file (functions, steps, heredocs) is parsed ONLY
# after the exec, from the clone. A syntax error below this section therefore
# cannot even be reached from the unpinned copy.
# ==============================================================================
say()  { printf '%s\n' "$*"; }
stop() { printf 'STOP: %s\n' "$*" >&2; exit 2; }

HEAD_CLONE=""
HEAD_SHA=""
TVC_BUILD=""
MG_GIT_GLOBAL=/dev/null   # the "global" git config mg_git points at; only ensure_head_clone ever changes it, for one call
MG_INSTALL_REL=deploy/manifest-grant/install.sh   # the file this is, inside the clone

# BEGIN pre-reexec
# mg_git ARGS... -- EVERY git command root runs goes through this one function
# (tests/test_manifest_grant_pinned_head.py scans for a bare `git`). Loki F2:
# the root clone used to consult operator-writable git configuration. Here:
#   * `env -i` + PATH=/usr/bin:/bin + HOME=/nonexistent: no inherited GIT_*,
#     no ~/.gitconfig, no XDG config, no GIT_EXEC_PATH/GIT_SSH/... from sudo;
#   * GIT_CONFIG_NOSYSTEM=1 + GIT_CONFIG_SYSTEM=/dev/null + GIT_CONFIG_GLOBAL=
#     $MG_GIT_GLOBAL (/dev/null; a root-written file holding only
#     safe.directory for the ONE clone call -- see ensure_head_clone): the system
#     and global config are empty or ours (NOSYSTEM alone does not cover
#     GIT_CONFIG_SYSTEM on every git; the pair is belt and braces);
#   * -c core.fsmonitor=false -c core.hooksPath=/dev/null: no fsmonitor program
#     and no hook directory, whatever a repo's own config says (the root clone's
#     own config is written by this git, but the SOURCE repo's config is
#     operator-writable and is read by the upload-pack side of the clone);
#   * --no-pager (+ no tty under env -i): core.pager is never run;
#   * -c protocol.allow=never -c protocol.file.allow=always: the only transport
#     is the local file one (no ssh/http/ext:: helper can be named by a config).
# `clone --no-local` (ensure_head_clone) is the other half: see there.
mg_git() {
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$MG_GIT_GLOBAL" GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 \
    git --no-pager -c core.fsmonitor=false -c core.hooksPath=/dev/null \
        -c protocol.allow=never -c protocol.file.allow=always "$@"
}

# mg_expect_head ARGS... -- scan the command line for --expect-head and print its
# value, lowercased, when it is a FULL 40-hex sha. Otherwise print why and
# return 1. Missing, repeated, short/abbreviated (git would resolve an
# abbreviation to whatever object the writable .git offers), a ref name, or
# anything non-hex are all refused. `--retire` consumes its value the way the
# real parser (below) does, so `--retire --expect-head` cannot hide the flag.
mg_expect_head() {
  local LC_ALL=C raw="" n=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --expect-head)
        [ $# -ge 2 ] || { printf '%s\n' "--expect-head needs a value (the full 40-hex sha of the commit to install)"; return 1; }
        raw=$2; n=$((n + 1)); shift 2 ;;
      --retire) shift; [ $# -eq 0 ] || shift ;;
      *) shift ;;
    esac
  done
  [ "$n" -gt 0 ] || { printf '%s\n' "--expect-head <40-hex sha> is required in every mode (no default, and not read from the checkout)"; return 1; }
  [ "$n" -eq 1 ] || { printf '%s\n' "--expect-head given $n times"; return 1; }
  case "$raw" in
    '' | *[!0-9a-fA-F]*) printf '%s\n' "--expect-head must be hexadecimal only, got '${raw:0:60}'"; return 1 ;;
  esac
  [ "${#raw}" -eq 40 ] || { printf '%s\n' "--expect-head must be the FULL 40-hex commit sha (an abbreviation or a ref is refused), got ${#raw} characters"; return 1; }
  printf '%s\n' "${raw,,}"
}

# mg_clone_problems BUILD ROOT_UID -- the temp dir that holds the clone: owned by
# ROOT_UID and not group/other-writable, its parent likewise (or sticky, like
# /tmp), and nothing inside it owned by another uid or group/other-writable.
# One `find`, not a per-file loop.
mg_clone_problems() {
  local build=$1 ru=$2 out st u m
  [ -d "$build" ] && [ ! -L "$build" ] || { printf '%s is not a plain directory\n' "$build"; return 0; }
  st=$(stat -c '%u %a' -- "$(dirname -- "$build")" 2>/dev/null) || { printf 'cannot stat the parent of %s\n' "$build"; return 0; }
  u=${st%% *}; m=${st#* }
  [ "$u" = "$ru" ] || printf 'the parent of %s is owned by uid %s, not %s\n' "$build" "$u" "$ru"
  if [ $(( 8#$m & 022 )) -ne 0 ] && [ $(( 8#$m & 01000 )) -eq 0 ]; then
    printf 'the parent of %s is group/other-writable (mode %s) and not sticky\n' "$build" "$m"
  fi
  out=$(find "$build" \( \( -type l ! -uid "$ru" \) -o \( ! -type l \( ! -uid "$ru" -o -perm /022 \) \) \) -print 2>/dev/null | head -8 || true)
  [ -z "$out" ] || printf '%s\n' "$out" | sed 's/^/not owned by the installing uid or writable by others: /'
  return 0
}

# mg_reexec_problems ROOT_UID EXPECT SELF -- what the re-exec'd copy checks about
# itself before it trusts anything: the marker MG_REEXEC equals --expect-head;
# SELF (this file) is the clone's own deploy/manifest-grant/install.sh by
# realpath; the clone's directory is root-owned and unwritable; the clone's HEAD
# is EXPECT; and the clone has no modified, untracked or ignored file (so the
# file read, and every file built from it, is the committed one).
mg_reexec_problems() {
  local ru=$1 expect=$2 self=$3 build=${MG_REEXEC_BUILD:-} p head st
  if [ "${MG_REEXEC:-}" != "$expect" ]; then
    printf 're-exec marker %s is not --expect-head %s\n' "${MG_REEXEC:-<none>}" "$expect"; return 0
  fi
  [ -n "$build" ] && [ -d "$build/src" ] || { printf 'the re-exec marker names no clone (%s)\n' "${build:-<none>}"; return 0; }
  if [ "$(readlink -f -- "$self" 2>/dev/null || true)" != "$(readlink -f -- "$build/src/$MG_INSTALL_REL" 2>/dev/null || true)" ]; then
    printf '%s is not the clone'"'"'s own %s\n' "$self" "$build/src/$MG_INSTALL_REL"; return 0
  fi
  p=$(mg_clone_problems "$build" "$ru")
  [ -z "$p" ] || { printf '%s\n' "$p"; return 0; }
  head=$(mg_git -C "$build/src" rev-parse --verify --quiet "HEAD^{commit}" 2>/dev/null || true)
  [ "$head" = "$expect" ] || { printf 'the clone HEAD is %s, not %s\n' "${head:-<unreadable>}" "$expect"; return 0; }
  st=$(mg_git -C "$build/src" status --porcelain --untracked-files=all --ignored 2>&1 | head -3 || true)
  [ -z "$st" ] || printf 'the clone is not exactly its commit: %s\n' "${st%%$'\n'*}"
  return 0
}

# ensure_head_clone EXPECT -- the ONE root-owned clone, of commit EXPECT only.
# Called from the main shell (sets globals and the EXIT trap that removes the
# temp dir), by the PRE-REEXEC copy only; the re-exec'd copy never clones.
#   * --no-local: git's own pack transport (upload-pack on the source, index-pack
#     on the clone), not a copy/hardlink of the source's objects/ directory. A
#     plain local clone takes the object files verbatim -- a loose object whose
#     bytes do not hash to its name is accepted until something re-hashes it --
#     whereas index-pack re-hashes every object it receives, so an object forged
#     under EXPECT's name is simply absent from the clone and the run stops.
#     (upload-pack does read the source repo's config, in mg_git's neutral
#     environment; the hooks/programs a config can name are not run by it, and
#     tests/test_manifest_grant_pinned_head.py plants fsmonitor, pager,
#     packObjectsHook and a hooksPath in the source and checks none runs.)
#   * --no-checkout, then `checkout --detach EXPECT`: the clone's HEAD and
#     branches are whatever the (operator-writable) source advertised, so the
#     work tree is made from EXPECT explicitly, never from where HEAD points.
#   * EXPECT must be a COMMIT object present in the clone (`^{commit}` peels a
#     tag, so a tag's own sha fails the equality), and HEAD is read back.
#   * no fsck: index-pack's re-hash is the property needed, and
#     transfer.fsckObjects would refuse legitimate old history.
ensure_head_clone() {
  local expect=$1 got real
  [ -z "$HEAD_CLONE" ] || return 0
  command -v git >/dev/null 2>&1 || stop "git is required to read willow-mcp's committed HEAD from the checkout"
  TVC_BUILD=$(mktemp -d /tmp/willow-mg-install.XXXXXXXX)
  trap 'rm -rf "${TVC_BUILD:-}"' EXIT
  # upload-pack runs inside the OPERATOR'S repository as root, and git refuses a
  # repository owned by another uid unless safe.directory names it. `-c
  # safe.directory=` does not reach that child (git strips GIT_CONFIG_PARAMETERS
  # for a local connection), so a root-written "global" file names exactly this
  # one directory (upload-pack opens it as <dir>/.git, so both spellings), for
  # this one call. Measured: without it, "detected dubious ownership in
  # repository" stops the clone.
  real=$(cd "$CHECKOUT" && pwd -P) || stop "cannot enter $CHECKOUT"
  case "$real" in *[\"\\]* | *$'\n'*) stop "refusing a checkout path with a quote, backslash or newline in it: $real" ;; esac
  printf '[safe]\n\tdirectory = "%s"\n\tdirectory = "%s/.git"\n' "$real" "$real" > "$TVC_BUILD/safe.gitconfig"
  MG_GIT_GLOBAL="$TVC_BUILD/safe.gitconfig" mg_git clone --quiet --no-local --no-checkout "$CHECKOUT" "$TVC_BUILD/src" \
    || stop "could not clone $CHECKOUT to read commit ${expect:0:12} from"
  got=$(mg_git -C "$TVC_BUILD/src" rev-parse --verify --quiet "$expect^{commit}" || true)
  [ "$got" = "$expect" ] \
    || stop "commit $expect (--expect-head) is not a commit in $CHECKOUT's refs: push/fetch it there, or check the sha you copied (a ref moved in the checkout cannot stand in for it)"
  mg_git -C "$TVC_BUILD/src" checkout --quiet --detach "$expect" \
    || stop "could not check out $expect in the HEAD clone"
  HEAD_SHA=$(mg_git -C "$TVC_BUILD/src" rev-parse --verify "HEAD^{commit}") || stop "could not read the commit of the HEAD clone"
  [ "$HEAD_SHA" = "$expect" ] || stop "the HEAD clone is at $HEAD_SHA, not the --expect-head $expect"
  HEAD_CLONE="$TVC_BUILD/src"
}

# mg_pre_reexec ROOT_UID ARGS... -- the whole pre-reexec behaviour. Production
# calls it with 0 (tests pass their own uid and a fixture; nothing is read from
# the environment except the re-exec marker the previous copy sets).
#   not yet re-exec'd: validate, clone, verify, exec the clone's copy (never returns);
#   re-exec'd (MG_REEXEC / MG_REEXEC_BUILD set): verify THIS file is the clone's
#   and adopt the clone (globals + cleanup trap), then return so the pinned copy
#   reads on. A marker that fails verification is a stop: that is the loop guard
#   (a stale marker in the unpinned copy, a forged one, a second exec all stop).
mg_pre_reexec() {
  local ru=$1 orig_path=$PATH out expect
  local PATH=/usr/bin:/bin
  shift
  [ "$(id -u)" = "$ru" ] || stop "run as root (sudo bash install.sh --expect-head <40-hex sha> [mode])"
  out=$(mg_expect_head "$@") || stop "$out"
  expect=$out
  if [ -n "${MG_REEXEC:-}${MG_REEXEC_BUILD:-}" ]; then
    out=$(mg_reexec_problems "$ru" "$expect" "$0")
    [ -z "$out" ] || stop "re-exec check failed (not running on): $out"
    TVC_BUILD=$MG_REEXEC_BUILD
    HEAD_CLONE="$TVC_BUILD/src"
    HEAD_SHA=$expect
    trap 'rm -rf "${TVC_BUILD:-}"' EXIT
    unset MG_REEXEC MG_REEXEC_BUILD
    return 0
  fi
  HERE=$(cd "$(dirname "$0")" && pwd)
  CHECKOUT=$(cd "$HERE/../.." && pwd)   # deploy/manifest-grant/ -> checkout root
  ensure_head_clone "$expect"
  [ -f "$HEAD_CLONE/$MG_INSTALL_REL" ] \
    || stop "$MG_INSTALL_REL is not in commit ${expect:0:12}: that commit predates the pinned installer"
  # The pinned copy starts from an empty environment (`env -i`), plus the fixed
  # allowlist below and PATH/MG_REEXEC/MG_REEXEC_BUILD. Nothing else of the
  # typed copy's environment reaches it: not BASH_ENV/ENV/SHELLOPTS/BASHOPTS
  # (a non-interactive bash reads those before line 1 of the script), not
  # LD_PRELOAD/LD_LIBRARY_PATH (the dynamic loader reads them before any code),
  # not IFS (bash inherits it from the environment; it would only apply at the
  # script's own expansions, and now never reaches the copy at all), nor
  # PYTHON*, GIT_*, PS4, CDPATH, GLOBIGNORE, TMPDIR and the rest. --noprofile
  # --norc skips the profile/rc files. Allowlist, each passed only if set:
  #   SUDO_USER -- `OPERATOR=${SUDO_USER:-sean-campbell}`: whose vault, uid and
  #     user systemd manager the installer acts on; without it the operator
  #     silently defaults to the wrong account.
  # Considered and left out: SUDO_UID/SUDO_GID/HOME/LOGNAME/USER (never read;
  # the script derives the uid with `id -u "$OPERATOR"`, as_op/as_to go through
  # `sudo -u`, which sets its own HOME), TERM/LANG/LC_* (cosmetic; the script
  # sets LC_ALL=C itself where it parses output), TMPDIR (bare `mktemp` then
  # uses /tmp), XDG_RUNTIME_DIR/DBUS_SESSION_BUS_ADDRESS (as_op sets them),
  # GNUPGHOME (as_to sets it), PIP_*/PYTHONNOUSERSITE (set by the script).
  local keep=() v
  # shellcheck disable=SC2043  # a one-name allowlist today; the loop is where a name is added
  for v in SUDO_USER; do
    if [ -n "${!v+x}" ]; then keep+=("$v=${!v}"); fi
  done
  exec /usr/bin/env -i ${keep[@]+"${keep[@]}"} \
    PATH="$orig_path" MG_REEXEC="$HEAD_SHA" MG_REEXEC_BUILD="$TVC_BUILD" \
    "$BASH" --noprofile --norc "$HEAD_CLONE/$MG_INSTALL_REL" "$@" \
    || stop "could not exec the clone's install.sh"
}
# END pre-reexec

if [ "${1:-}" != "--dry-run-sign" ]; then
  mg_pre_reexec 0 "$@"
fi


# BEGIN operator-check
# mg_operator_problems NAME [HOME_BASE] -- why NAME is not a real, non-root, regular
# user whose home is /home/NAME, one reason per line; silent when it is (Loki R2).
# $SUDO_USER is the only thing that names the operator, and everything below
# (H, the vault, `sudo -u`, chown, the user systemd manager) is derived from it,
# so it is checked before any of that is used: a plain login name, a uid in the
# human range (>= 1000, not 65534/nobody), and a real directory (not a symlink)
# at HOME_BASE/NAME owned by that uid. HOME_BASE is /home in production; a test
# passes a temp dir.
mg_operator_problems() {
  local op=$1 base=${2:-/home} u h owner
  [[ $op =~ ^[a-z_][a-z0-9_-]*$ ]] || { printf 'operator name %q is not a plain login name ([a-z_][a-z0-9_-]*)\n' "$op"; return 0; }
  u=$(id -u -- "$op" 2>/dev/null) || { printf 'operator %s is not a known user (id -u failed)\n' "$op"; return 0; }
  [[ $u =~ ^[0-9]+$ ]] || { printf 'operator %s has a non-numeric uid %q\n' "$op" "$u"; return 0; }
  if [ "$u" -lt 1000 ] || [ "$u" -eq 65534 ]; then
    printf 'operator %s has uid %s: not a regular user (need >= 1000 and not 65534)\n' "$op" "$u"; return 0
  fi
  h=$base/$op
  if [ -L "$h" ] || [ ! -d "$h" ]; then
    printf 'operator home %s is not a real directory\n' "$h"; return 0
  fi
  owner=$(stat -c %u -- "$h" 2>/dev/null) || owner=""
  [ "$owner" = "$u" ] || printf 'operator home %s is owned by uid %s, not %s\n' "$h" "${owner:-?}" "$u"
  return 0
}
# END operator-check

OPERATOR=${SUDO_USER:-sean-campbell}
# --dry-run-sign touches nothing and needs no root (it only prints the sign
# sequence), so it keeps the bare `id -u` and does not require a real /home/NAME;
# every mode that acts on the box checks the operator first.
if [ "${1:-}" != "--dry-run-sign" ]; then
  out=$(mg_operator_problems "$OPERATOR")
  [ -z "$out" ] || stop "operator check failed (SUDO_USER=${SUDO_USER:-<unset>}): $out"
fi
OPERATOR_UID=$(id -u "$OPERATOR")
H=/home/$OPERATOR/sean-data-vault/willow-operator-box
TRUST_OWNER=willow-operator
GNUPGHOME_TO=/var/lib/willow-mcp/manifest-grant/gnupg
ETC=/etc/willow-mcp
SYSD=/etc/systemd/system   # where the unit and the timer are installed
# Dispatch 0CB0C85C (amending B291C0C7/E29CCFC7): a fingerprint is public --
# only a key's PRIVATE half is a secret. $H/env is 0600 (every provider API
# key); the trust-owner apply unit (uid willow-operator) cannot read it, so a
# second copy in /etc/willow-mcp/manifest-grant.env existed only so that unit
# could see the fingerprint -- and nothing ever checked the two copies still
# agreed (Loki A38D41C2, F8).
#
# Rework #3 (dispatch FA4F79AC, 2026-09-23; operator ruling, verbatim: "it
# should be in the vault with the rest of the keys") routed TRUST_ENV
# through a separately-configured WILLOW_VAULT_BOX. Rework #4 (dispatch
# 10F9E837, Loki audit 23DE8AA9, F-C) reverted that: WILLOW_VAULT_BOX is a
# variable the BROKER's own process env can set too, and once it is set
# anywhere other than $H, this script (root, sudo environment, normally
# stripped) and the broker (its own env) can resolve DIFFERENT files as
# "the" trust source -- worse than the rename-away hole it tried to close.
# TRUST_ENV is a fixed $H/constitutional/trust.env, exactly matching
# src/willow_mcp/paths.py's trust_config_path() (no env-var indirection on
# either side) -- trust-owner-owned, 0644, WORLD-READABLE: every verifying
# process (broker, serve, desk, the trust-owner apply unit, this script)
# reads the SAME file at the SAME fixed path, and only the trust owner (or
# root) can write it.
#
# THE RENAME-AWAY HOLE (Loki audit D06A0EF3) is UNCHANGED by this and still
# open: $H is broker-owned, mode 700, so the broker can rename
# constitutional/ away and recreate it empty. See paths.trust_config_path()'s
# own docstring and INSTALL.md for the argument and the (larger,
# out-of-scope) root step that would close it.
TRUST_ENV="$H/constitutional/trust.env"
# F-B (Loki audit 23DE8AA9): a --rotate whose old-key retire fails
# (warned, not persisted) used to be silently reverted by the next plain
# install, which deleted the NEW key -- see sign_and_publish_trust's own
# retire branch and step 1b below. This marker is the named state that
# survives a warning: the fingerprint a failed retire could not remove,
# retried at the top of every run until it succeeds.
STALE_KEY_MARKER="$H/constitutional/.stale_trust_key"
KEY_UID='willow-mcp manifest-grant (trust owner) <manifest-grant@willow-operator-box>'
BROKER_PUBLIC_KEY_NAME=broker_public_key.pub   # manifest_grant_executor._broker_public_key_path
BROKER_UNIT_CANDIDATES=(willow-mcp-serve.service willow-mcp.service)  # reloader.DEFAULT_UNIT / unit_reload_executor._BROKER_UNIT_STEMS
# The trust owner's OWN interpreter (operator rulings Q7=A "split" and Q13,
# 2026-10-11; Loki audit BFCC5C79 F7 lineage). It used to be
# $H/venvs/willow-mcp/bin/python -- a tree owned and writable by the operator
# uid, the same uid the bot, the agents and the operator shell run as, so any
# of them could rewrite code that then ran as the trust owner. It now lives
# OUTSIDE every operator-writable tree:
#   * /opt/willow-operator/venv -- /opt is the FHS home for add-on software;
#     /etc/willow-mcp is configuration and /var/lib/willow-mcp/manifest-grant
#     is the trust owner's own WRITABLE state (its gnupg home, a unit
#     ReadWritePaths) -- an interpreter must be in neither, or the uid that
#     runs it could rewrite it;
#   * root:root, 755 dirs / 644 files, a NON-editable install of this
#     checkout (a built wheel, never `pip install -e`), created below by this
#     script running as root;
#   * built from the system python, whose real path the preflight also checks.
# PY is the one variable every step uses; willow-mcp-manifest-grant.service
# must name the same path in ExecStart= (the preflight stops if it does not).
TRUST_VENV=/opt/willow-operator/venv
TRUST_PY_BASE=/usr/bin/python3.14   # what the operator's box already resolves to (root-owned system python)
# The least the apply path imports (traced 2026-10-11: `python -m willow_mcp
# manifest-grant apply` and the trust_owner_verbs / manifest_grant_executor /
# mcp_federation / envelope_authoring modules it calls need psycopg2 and
# cryptography only -- not mcp, starlette, kartikeya, jeles, nestor, ratatosk,
# forge or willow-gate). Everything third-party that goes into the venv, and
# every build tool that builds the wheel, is installed ONLY from the two
# hash-pinned files below (read from the committed HEAD, never from the working
# tree) with `pip install --require-hashes --only-binary=:all: --no-deps`; no
# range specifier is ever handed to pip. Their ranges are the .in files, which
# tests/test_trust_venv_preflight.py keeps equal to pyproject.toml's.
TRUST_REQS_REL=deploy/manifest-grant/trust-venv.requirements.txt
TRUST_BUILD_REQS_REL=deploy/manifest-grant/trust-venv.build-requirements.txt
PY="$TRUST_VENV/bin/python"
TVC_STAMP=.built-from-head   # inside the venv: the commit its wheel was built from

as_op() { sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$OPERATOR_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$OPERATOR_UID/bus" "$@"; }
as_to() { sudo -u "$TRUST_OWNER" GNUPGHOME="$GNUPGHOME_TO" "$@"; }

# ------------------------------------------- the trust owner's interpreter check
# Operator rulings Q7=A / Q13 (2026-10-11). The trust owner executes $PY, so
# nothing a less-trusted uid can write may sit on the way to it or inside it.
# Every function below prints one problem per line and returns 0 -- an empty
# result is "clean". They take the uid that counts as "root" and the path the
# walk starts from as ARGUMENTS (production: 0 and /) so
# tests/test_trust_venv_preflight.py can run them against a tmp tree as an
# unprivileged user; nothing here reads either from the environment.
# BEGIN trust-venv-check

# tvc_components ANCHOR PATH -- ANCHOR, then every prefix of PATH down to it.
tvc_components() {
  local anchor=$1 path=$2 cur rest part
  local -a parts
  if [ "$anchor" = / ]; then
    cur=""; rest=${path#/}; printf '/\n'
  else
    anchor=${anchor%/}
    case "$path" in "$anchor"|"$anchor"/*) ;; *) return 1 ;; esac
    cur=$anchor; rest=${path#"$anchor"}; rest=${rest#/}; printf '%s\n' "$anchor"
  fi
  IFS=/ read -ra parts <<<"$rest"
  for part in ${parts[@]+"${parts[@]}"}; do
    [ -n "$part" ] || continue
    cur="$cur/$part"
    printf '%s\n' "$cur"
  done
  return 0
}

# tvc_chain_paths ANCHOR FILE -- the lexical chain AND the symlink-resolved
# chain (readlink -f) of FILE; a resolved path outside ANCHOR is walked from /.
tvc_chain_paths() {
  local anchor=$1 file=$2 real target a
  real=$(readlink -f -- "$file" 2>/dev/null || true)
  for target in "$file" "$real"; do
    [ -n "$target" ] || continue
    a=$anchor
    case "$target" in "$a"|"$a"/*) ;; *) a=/ ;; esac
    tvc_components "$a" "$target" || true
  done | awk '!seen[$0]++'
  return 0
}

# tvc_chain_problems ANCHOR FILE ROOT_UID -- a component not owned by ROOT_UID,
# or (non-symlink) writable by group or other.
tvc_chain_problems() {
  local anchor=$1 file=$2 ru=$3 c st u rest m ft
  [ -e "$file" ] || { printf 'no such file: %s\n' "$file"; return 0; }
  if [ -z "$(readlink -f -- "$file" 2>/dev/null || true)" ]; then
    printf 'cannot resolve %s with readlink -f\n' "$file"; return 0
  fi
  while IFS= read -r c; do
    st=$(stat -c '%u %a %F' -- "$c" 2>/dev/null) || { printf 'cannot stat %s\n' "$c"; continue; }
    u=${st%% *}; rest=${st#* }; m=${rest%% *}; ft=${rest#* }
    if [ "$u" != "$ru" ]; then
      printf '%s is owned by uid %s, not %s\n' "$c" "$u" "$ru"
    fi
    if [ "$ft" != "symbolic link" ] && [ $(( 8#$m & 022 )) -ne 0 ]; then
      printf '%s is group/other-writable (mode %s)\n' "$c" "$m"
    fi
  done < <(tvc_chain_paths "$anchor" "$file")
  return 0
}

# tvc_acl_problems ANCHOR FILE VENV -- a non-root ACL entry with write on the
# chain or anywhere in the venv. Fails closed when getfacl is missing.
tvc_acl_problems() {
  local anchor=$1 file=$2 venv=$3 out
  local -a chain
  # $TRUST_VENV is a root-owned symlink to its release directory (the atomic
  # swap, provision_trust_venv); getfacl -R must walk the tree it points at.
  venv=$(readlink -f -- "$venv" 2>/dev/null || printf '%s' "$venv")
  command -v getfacl >/dev/null 2>&1 || {
    printf 'the ACL check cannot be performed: getfacl is not installed (install the acl package)\n'; return 0; }
  mapfile -t chain < <(tvc_chain_paths "$anchor" "$file")
  {
    out=$(getfacl -p -- ${chain[@]+"${chain[@]}"} 2>&1) || { printf 'getfacl failed on the path chain: %s\n' "${out%%$'\n'*}"; return 0; }
    printf '%s\n' "$out"
    out=$(getfacl -R -p -s -- "$venv" 2>&1) || { printf 'getfacl failed on %s: %s\n' "$venv" "${out%%$'\n'*}"; return 0; }
    printf '%s\n' "$out"
  } | awk '
    /^# file: /      { f = substr($0, 9); next }
    /^getfacl failed|^the ACL check/ { print; next }
    {
      line = $0; sub(/^default:/, "", line)
      n = split(line, a, ":")
      if ((a[1] == "user" || a[1] == "group") && a[2] != "" && a[2] != "root" && substr(a[3], 2, 1) == "w")
        printf "%s has a non-root write ACL entry: %s\n", f, $0
    }' | awk '!seen[$0]++'
  return 0
}

# tvc_tree_problems VENV ROOT_UID -- anything inside the venv not owned by
# ROOT_UID, or (non-symlink) writable by group or other.
tvc_tree_problems() {
  local venv=$1 ru=$2 out
  # -H: $TRUST_VENV is a root-owned symlink to its release directory; a bare
  # `find <symlink>` would inspect the link and walk nothing.
  out=$(find -H "$venv" \( \( -type l ! -uid "$ru" \) -o \( ! -type l \( ! -uid "$ru" -o -perm /022 \) \) \) -print 2>/dev/null || true)
  [ -z "$out" ] || printf '%s\n' "$out" | head -8 | sed 's/^/not root-owned or writable by others: /'
  return 0
}

# tvc_installed_version VENV -- the willow_mcp version the venv's dist-info names.
tvc_installed_version() {
  local d f v
  for d in "$1"/lib/python*/site-packages "$1"/lib64/python*/site-packages; do
    for f in "$d"/willow_mcp-*.dist-info; do
      [ -d "$f" ] || continue
      v=${f##*/willow_mcp-}; printf '%s\n' "${v%.dist-info}"; return 0
    done
  done
  return 0
}

# tvc_editable_problems VENV -- willow_mcp absent, or ANY editable install in
# the venv (not only willow_mcp): an __editable__/_editable_impl_ marker, an
# .egg-link, easy-install.pth, a direct_url.json with "editable": true, a
# .pth line that resolves outside the venv, or ANY executable .pth line (one
# starting `import `/`import<TAB>`: a path hook that sys.path.insert()s ahead of
# the standard library).
tvc_editable_problems() {
  local venv=$1 vreal d f line t sp=0
  for d in "$venv"/lib/python*/site-packages "$venv"/lib64/python*/site-packages; do
    [ -d "$d" ] && sp=1
  done
  vreal=$(readlink -f -- "$venv" 2>/dev/null || printf '%s' "$venv")
  for d in "$venv"/lib/python*/site-packages "$venv"/lib64/python*/site-packages; do
    [ -d "$d" ] || continue
    for f in "$d"/__editable__* "$d"/_editable_impl_* "$d"/*.egg-link "$d"/easy-install.pth; do
      [ -e "$f" ] && printf 'editable-install marker: %s\n' "$f"
    done
    for f in "$d"/*.dist-info/direct_url.json; do
      [ -f "$f" ] || continue
      if grep -Eq '"editable"[[:space:]]*:[[:space:]]*true' "$f"; then
        printf 'editable install (direct_url.json): %s\n' "$f"
      fi
    done
    for f in "$d"/*.pth; do
      [ -f "$f" ] || continue
      while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue ;; esac
        # site.py EXECUTES a .pth line that starts with `import ` / `import<TAB>`
        # at every interpreter start, before any script runs. Live finding
        # (operator box, 2026-10-11): _ratatosk_checkout.pth = `import
        # ratatosk_path_hook`, whose module did sys.path.insert(0, <a checkout
        # Kart tasks can write>) -- ahead of the standard library. No allowlist:
        # a clean build of this venv (willow-mcp, psycopg2-binary, cryptography,
        # cffi, pycparser; no setuptools) creates no .pth file at all.
        case "$line" in
          import\ *|import$'\t'*) printf '%s has an executable line (runs at interpreter start): %s\n' "$f" "${line:0:80}"; continue ;;
        esac
        case "$line" in /*) t=$(readlink -m -- "$line") ;; *) t=$(readlink -m -- "$d/$line") ;; esac
        case "$t" in "$vreal"|"$vreal"/*) ;; *) printf '%s puts %s on sys.path, outside the venv\n' "$f" "$t" ;; esac
      done < "$f"
    done
  done | awk '!seen[$0]++'
  [ -n "$(tvc_installed_version "$venv")" ] || printf 'willow_mcp is not installed in %s (no willow_mcp-*.dist-info)\n' "$venv"
  [ "$sp" = 1 ] || printf 'no site-packages under %s\n' "$venv"
  return 0
}

# ---- the standard library and the site hooks the interpreter loads (Loki F3) ----
# The venv's python runs with `-I` (no cwd, no PYTHON* variables, no user site)
# but still imports, at start, from: the standard library of the BASE
# interpreter the venv was made from, its lib-dynload, any sitecustomize /
# usercustomize module on that path, and the venv's own site-packages. The
# checks above cover the venv; the functions below cover the rest, all BEFORE
# any interpreter is executed (tvc_import_problems runs last).

# tvc_stdlib_dirs BASE -- the directories holding BASE's standard library, from
# its NAME and resolved path alone; nothing is executed. CPython derives its
# prefix from where the executable lives (<prefix>/bin/pythonX.Y), and the
# library is <prefix>/<platlibdir>/pythonX.Y: lib on Debian/Ubuntu, lib64 on
# Fedora/RHEL, so both are listed when present. Prints nothing (return 1) when
# BASE is not named pythonX.Y or no such directory exists.
tvc_stdlib_dirs() {
  local base=$1 name real prefix d ver found=1
  name=${base##*/}
  [[ $name =~ ^python([0-9]+\.[0-9]+)$ ]] || return 1
  ver=${BASH_REMATCH[1]}
  real=$(readlink -f -- "$base" 2>/dev/null || true)
  [ -n "$real" ] || return 1
  prefix=${real%/*}; prefix=${prefix%/*}
  for d in "$prefix/lib/python$ver" "$prefix/lib64/python$ver"; do
    [ -d "$d" ] && { printf '%s\n' "$d"; found=0; }
  done
  return "$found"
}

# tvc_pyvenv_problems VENV BASE -- pyvenv.cfg, read the way site.py reads it.
# site.py defaults include-system-site-packages to TRUE when the key is absent
# and lets the last occurrence win, so: the key must be present and its last
# value `false`; `home` must be the directory BASE lives in; `version` (if
# given) must be BASE's X.Y; and no bin/pyvenv.cfg may shadow the venv's own
# (site.py looks beside the executable first). With it false, neither
# /usr/lib/python3/dist-packages nor /usr/local/lib/pythonX.Y/dist-packages is
# added to sys.path (tvc_import_problems confirms sys.path once it runs).
tvc_pyvenv_problems() {
  local venv=$1 base=$2 cfg line key val inc="" home="" ver="" name bver
  cfg="$venv/pyvenv.cfg"
  name=${base##*/}; bver=${name#python}
  [ ! -e "$venv/bin/pyvenv.cfg" ] && [ ! -L "$venv/bin/pyvenv.cfg" ] || printf '%s exists: it would be read instead of %s\n' "$venv/bin/pyvenv.cfg" "$cfg"
  [ -f "$cfg" ] || { printf 'no pyvenv.cfg in %s: not a venv, so the system site-packages would be on sys.path\n' "$venv"; return 0; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in *=*) ;; *) continue ;; esac
    key=${line%%=*}; val=${line#*=}
    key=${key#"${key%%[![:space:]]*}"}; key=${key%"${key##*[![:space:]]}"}
    val=${val#"${val%%[![:space:]]*}"}; val=${val%"${val##*[![:space:]]}"}
    case "${key,,}" in
      include-system-site-packages) inc=${val,,} ;;
      home) home=$val ;;
      version) ver=$val ;;
    esac
  done < "$cfg"
  case "$inc" in
    false) ;;
    true) printf 'pyvenv.cfg: include-system-site-packages = true (the system site-packages and dist-packages would be on sys.path)\n' ;;
    '') printf 'pyvenv.cfg has no include-system-site-packages line (site.py then defaults to true)\n' ;;
    *) printf 'pyvenv.cfg: include-system-site-packages = %s, not false\n' "${inc:0:20}" ;;
  esac
  if [ -z "$home" ]; then
    printf 'pyvenv.cfg has no home line\n'
  elif [ "$(readlink -f -- "$home" 2>/dev/null || printf '%s' "$home")" != "$(readlink -f -- "$(dirname -- "$base")" 2>/dev/null || true)" ]; then
    printf 'pyvenv.cfg: home = %s, not the directory of the base interpreter %s\n' "$home" "$base"
  fi
  case "$ver" in
    '') ;;
    "$bver"|"$bver".*) ;;
    *) printf 'pyvenv.cfg: version = %s, not the base interpreter'"'"'s %s\n' "$ver" "$bver" ;;
  esac
  return 0
}

# tvc_stdlib_problems ANCHOR BASE ROOT_UID -- the standard library directories:
# the path chain to each (every component root-owned, none group/other-writable;
# /usr/lib being among them also means nobody can create a python3XX.zip next to
# the library, which is on sys.path), and one `find` over the tree for any entry
# not owned by ROOT_UID or (non-symlink) group/other-writable; plus the
# resolved target of every symlink that points OUT of the tree (Debian links
# sitecustomize.py to /etc/pythonX.Y/), each on its own chain.
tvc_stdlib_problems() {
  local anchor=$1 base=$2 ru=$3 d t sreal
  local -a dirs
  mapfile -t dirs < <(tvc_stdlib_dirs "$base" || true)
  [ "${#dirs[@]}" -gt 0 ] || { printf 'cannot locate the standard library of %s (expected <prefix>/lib/pythonX.Y beside its bin/)\n' "$base"; return 0; }
  for d in "${dirs[@]}"; do
    tvc_chain_problems "$anchor" "$d" "$ru"
    tvc_tree_problems "$d" "$ru"
    sreal=$(readlink -f -- "$d")
    while IFS= read -r t; do
      [ -n "$t" ] || continue
      case "$t" in "$sreal"|"$sreal"/*) continue ;; esac
      tvc_chain_problems "$anchor" "$t" "$ru"
      [ ! -d "$t" ] || tvc_tree_problems "$t" "$ru"
    done < <(find "$d" -type l -exec readlink -f -- {} + 2>/dev/null | sort -u || true)
  done | awk '!seen[$0]++'
  return 0
}

# tvc_site_hooks VENV BASE -- every sitecustomize*/usercustomize* the interpreter
# could import, one path per line: in the standard library, its lib-dynload and
# the venv's site-packages (the only directories on sys.path in -I mode).
tvc_site_hooks() {
  local venv=$1 base=$2 d f n
  local -a roots
  mapfile -t roots < <(tvc_stdlib_dirs "$base" || true)
  for d in ${roots[@]+"${roots[@]}"}; do roots+=("$d/lib-dynload"); done
  for d in "$venv"/lib/python*/site-packages "$venv"/lib64/python*/site-packages; do roots+=("$d"); done
  for d in ${roots[@]+"${roots[@]}"}; do
    for n in sitecustomize usercustomize; do
      for f in "$d/$n" "$d/$n".*; do
        if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\n' "$f"; fi
      done
    done
  done | awk '!seen[$0]++'
  return 0
}

# tvc_site_hook_problems ANCHOR VENV BASE ROOT_UID -- each hook found, resolved
# with readlink -m: the file (or, when the link dangles, its directory) must sit
# on a chain of root-owned, not group/other-writable components.
tvc_site_hook_problems() {
  local anchor=$1 venv=$2 base=$3 ru=$4 f t
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    t=$(readlink -m -- "$f" 2>/dev/null || true)
    if [ -z "$t" ]; then printf 'cannot resolve %s\n' "$f"
    elif [ -e "$t" ]; then tvc_chain_problems "$anchor" "$t" "$ru"
    else tvc_chain_problems "$anchor" "$(dirname -- "$t")" "$ru"
    fi
  done < <(tvc_site_hooks "$venv" "$base") | awk '!seen[$0]++'
  return 0
}

# tvc_stdlib_acl_problems ANCHOR VENV BASE -- tvc_acl_problems over the standard
# library (chain + recursive) and over every site hook's resolved target.
tvc_stdlib_acl_problems() {
  local anchor=$1 venv=$2 base=$3 d f t
  {
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      tvc_acl_problems "$anchor" "$d" "$d"
    done < <(tvc_stdlib_dirs "$base" || true)
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      t=$(readlink -m -- "$f" 2>/dev/null || true)
      if [ -e "$t" ]; then tvc_acl_problems "$anchor" "$t" "$t"; fi
    done < <(tvc_site_hooks "$venv" "$base")
  } | awk '!seen[$0]++'
  return 0
}

# tvc_import_problems VENV PY [ALLOWED_DIR ...] -- run only AFTER every check above
# passed (the interpreter is then root-owned): the apply path imports, from
# inside the venv, and every sys.path entry the interpreter really built lies in
# the venv or in an ALLOWED_DIR (the checked standard library); a not-yet-existing
# python3XX.zip beside the library is allowed (its directory was chain-checked).
tvc_import_problems() {
  local venv=$1 py=$2 out line loc vreal r ok d
  shift 2
  out=$("$py" -I -c 'import sys, psycopg2, cryptography, willow_mcp, willow_mcp.cli_manifest_grant, willow_mcp.trust_owner_verbs, willow_mcp.manifest_grant_executor, willow_mcp.mcp_federation, willow_mcp.envelope_authoring; [print("SYSPATH " + p) for p in sys.path]; print(willow_mcp.__file__)' 2>&1) \
    || { printf 'the apply path does not import: %s\n' "${out##*$'\n'}"; return 0; }
  vreal=$(readlink -f -- "$venv" 2>/dev/null || printf '%s' "$venv")
  while IFS= read -r line; do
    case "$line" in SYSPATH\ *) ;; *) continue ;; esac
    line=${line#SYSPATH }
    r=$(readlink -m -- "${line:-.}" 2>/dev/null || true)
    ok=""
    case "$r" in "$vreal"|"$vreal"/*) ok=1 ;; esac
    for d in "$@"; do
      d=$(readlink -f -- "$d" 2>/dev/null || true)
      case "$r" in "$d"|"$d"/*) ok=1 ;; esac
      if [ ! -e "$r" ] && [ "${r%/*}" = "${d%/*}" ]; then ok=1; fi
    done
    [ -n "$ok" ] && [ -n "$line" ] || printf 'sys.path holds %s, outside the venv and the checked standard library\n' "${line:-<the current directory>}"
  done <<<"$out"
  loc=$(readlink -f -- "${out##*$'\n'}" 2>/dev/null || true)
  case "$loc" in "$vreal"/*) ;; *) printf 'willow_mcp imports from %s, outside the venv\n' "$loc" ;; esac
  return 0
}

# tvc_requirements_problems FILE -- FILE must be a plain hash-pinned list and
# nothing else: `name==version \`, `--hash=sha256:<64 hex>` lines and comments.
# No pip option (--index-url, --find-links, -r, -e, ...), no URL or path
# requirement, no range, no unhashed entry: a requirements file can redirect
# pip, and root installs whatever it says.
tvc_requirements_problems() {
  local f=$1 n
  [ -f "$f" ] || { printf 'no such file: %s\n' "$f"; return 0; }
  # (no {64} interval: mawk, Debian's default awk, may not support it; a sha256
  # line is 4 spaces + "--hash=sha256:" + 64 hex = 82 chars, 84 with " \")
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    /^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9._+!-]+ \\$/ { cur = $1; hashes[cur] = 0; total++; next }
    /^    --hash=sha256:[0-9a-f]+( \\)?$/ && (length($0) == 82 || length($0) == 84) {
      if (cur == "") { printf "line %d: a hash before any requirement\n", NR; next }
      hashes[cur]++; if ($0 !~ / \\$/) cur = ""; next }
    { printf "line %d is not a pinned name==version or a sha256 hash: %.60s\n", NR, $0 }
    END { for (n in hashes) if (hashes[n] == 0) printf "%s has no --hash=sha256 entry\n", n
          if (total == 0) print "no requirements in the file" }
  ' "$f" | head -8
  n=$(grep -c -- '--hash=sha256:' "$f" || true)
  [ "$n" -gt 0 ] || printf '%s carries no --hash=sha256: entry\n' "$f"
  return 0
}

# tvc_emit LABEL PROBLEMS -- one report line per check; 1 when PROBLEMS is set.
tvc_emit() {
  if [ -z "$2" ]; then printf '  [ok]   %s\n' "$1"; return 0; fi
  printf '  [FAIL] %s\n' "$1"
  printf '%s\n' "$2" | head -8 | sed 's/^/           - /'
  return 1
}

# tvc_report VENV PY ROOT_UID ANCHOR BASE -- one line per check; 0 only if all pass.
# BASE is the system interpreter the venv was built from (TRUST_PY_BASE); the
# standard-library checks (F3) are derived from it without executing anything.
tvc_report() {
  local venv=$1 py=$2 ru=$3 anchor=$4 base=${5:-} rc=0 p real v
  local -a sdirs
  real=$(readlink -f -- "$py" 2>/dev/null || true)
  p=""
  if [ ! -e "$py" ]; then p="no such file: $py"
  elif [ -z "$real" ] || [ ! -f "$real" ]; then p="$py does not resolve to a regular file"
  elif [ ! -x "$py" ]; then p="$py is not executable"
  fi
  tvc_emit "interpreter exists and is executable ($py)" "$p" || rc=1
  if [ -n "$p" ]; then
    printf '  [skip] path chain, ACLs, venv tree, editable-install, standard-library and import checks (no interpreter to check)\n'
    return 1
  fi
  p=$(tvc_chain_problems "$anchor" "$py" "$ru")
  tvc_emit "every path component from $anchor to the interpreter (symlinks resolved) is owned by uid $ru and not group/other-writable" "$p" || rc=1
  p=$(tvc_acl_problems "$anchor" "$py" "$venv")
  tvc_emit "no non-root write ACL on the path chain or inside the venv" "$p" || rc=1
  p=$(tvc_tree_problems "$venv" "$ru")
  tvc_emit "everything inside $venv is owned by uid $ru and not group/other-writable" "$p" || rc=1
  p=$(tvc_editable_problems "$venv")
  v=$(tvc_installed_version "$venv")
  tvc_emit "willow_mcp ${v:-?} is a regular install; nothing in the venv is editable or puts a path outside it on sys.path" "$p" || rc=1
  # F3: what the interpreter loads that is NOT in the venv. No interpreter runs here.
  if [ -z "$base" ]; then
    p="no base interpreter was given, so the standard library cannot be located"
  else
    p=$(tvc_pyvenv_problems "$venv" "$base")
  fi
  tvc_emit "pyvenv.cfg: include-system-site-packages = false, home and version are the base interpreter's (no system dist-packages on sys.path)" "$p" || rc=1
  if [ -n "$base" ]; then
    p=$(tvc_stdlib_problems "$anchor" "$base" "$ru")
  fi
  tvc_emit "the standard library of ${base:-?} (path chain, tree, symlink targets) is owned by uid $ru and not group/other-writable" "$p" || rc=1
  if [ -n "$base" ]; then
    p=$(tvc_stdlib_acl_problems "$anchor" "$venv" "$base")
  fi
  tvc_emit "no non-root write ACL on the standard library, its path chain or the site hooks" "$p" || rc=1
  if [ -n "$base" ]; then
    p=$(tvc_site_hook_problems "$anchor" "$venv" "$base" "$ru")
  fi
  tvc_emit "sitecustomize / usercustomize (stdlib, lib-dynload, venv site-packages), if any, resolve to root-owned files on unwritable path chains" "$p" || rc=1
  if [ "$rc" = 0 ]; then
    mapfile -t sdirs < <(tvc_stdlib_dirs "$base" || true)
    p=$(tvc_import_problems "$venv" "$py" ${sdirs[@]+"${sdirs[@]}"})
    tvc_emit "the manifest-grant apply path imports from inside the venv, and every sys.path entry is in the venv or the checked standard library" "$p" || rc=1
  else
    printf '  [skip] the apply-path import check (not executing an interpreter that failed the checks above)\n'
  fi
  return "$rc"
}
# ------------------------------------------------ the units and env, whole
# Rework 5. The service, the timer and manifest-grant.env are installed by root
# into /etc and the service then RUNS as the trust owner, so they are code: they
# are read ONLY from the root-owned clone of the committed HEAD (never from the
# operator-writable working tree) and validated WHOLE, not just ExecStart=.
# The allowlists below are the directive sets the committed files carry today;
# a line outside them, a duplicate, a missing line, a continuation backslash, or
# a directive in the wrong section is a problem. Every function prints one
# problem per line and returns 0 (empty = clean). Paths and names are ARGUMENTS
# so tests/test_trust_venv_preflight.py runs them against tmp trees.
MG_SERVICE=willow-mcp-manifest-grant.service
MG_TIMER=willow-mcp-manifest-grant.timer
MG_ENV=manifest-grant.env
MG_MARKER=trust-provisioned   # D4: $ETC/trust-provisioned, root:root 0644
MG_DEPLOY_REL=deploy/manifest-grant   # inside the checkout / the HEAD clone

# mg_ini_problems FILE SPEC -- FILE against SPEC, lines "KIND<TAB>SECTION<TAB>TEXT":
# R = this exact line, exactly once, in SECTION; O = same, at most once;
# K = a line starting TEXT (a key and its "="), exactly once, any value.
# SECTION is "[Name]" or "" (a section-less env file). Comments (# ;) and blank
# lines are skipped; anything else, including indented directives, must match.
mg_ini_problems() {
  [ -e "$1" ] || { printf 'no such file: %s\n' "$1"; return 0; }
  MG_SPEC=$2 awk '
    BEGIN {
      n = split(ENVIRON["MG_SPEC"], sp, "\n")
      for (i = 1; i <= n; i++) {
        if (sp[i] == "") continue
        split(sp[i], f, "\t")
        secs[f[2]] = 1
        if (f[1] == "K") key[f[2] SUBSEP f[3]] = 1; else exact[f[2] SUBSEP f[3]] = 1
        order[++m] = f[1] SUBSEP f[2] SUBSEP f[3]
      }
      sec = ""
    }
    /\\$/ { printf "line %d ends in a backslash (a continuation): %.60s\n", FNR, $0; next }
    /^[ \t]*$/ || /^[#;]/ { next }
    /^\[.*\]$/ {
      if (!($0 in secs)) printf "line %d: section %s is not expected\n", FNR, $0
      sec = $0; next }
    {
      if (!(sec in secs)) { printf "line %d: a directive outside the expected sections (%s): %.60s\n", FNR, sec, $0; next }
      idx = index($0, "="); k = (idx > 0) ? substr($0, 1, idx) : $0
      if ((sec SUBSEP $0) in exact) { id = sec SUBSEP $0 }
      else if ((sec SUBSEP k) in key) { id = sec SUBSEP k }
      else { printf "line %d: not an allowed line in %s: %.70s\n", FNR, (sec == "" ? "the file" : sec), $0; next }
      if (++seen[id] > 1) printf "line %d: %.70s appears more than once in %s\n", FNR, $0, (sec == "" ? "the file" : sec)
    }
    END {
      for (i = 1; i <= m; i++) {
        split(order[i], o, SUBSEP)
        if (o[1] != "O" && !((o[2] SUBSEP o[3]) in seen))
          printf "missing from %s: %s\n", (o[2] == "" ? "the file" : o[2]), o[3]
      }
    }' "$1" | head -8
  return 0
}

# mg_line KIND SECTION TEXT -- one spec line.
mg_line() { printf '%s\t%s\t%s\n' "$1" "$2" "$3"; }

# mg_service_problems UNIT PY TRUST_OWNER H GNUPGHOME ETC -- the whole service
# unit: the directive set the committed unit carries, User/Group the trust
# owner, ExecStart exactly "$PY -I -m willow_mcp manifest-grant apply", the two
# Environment= lines and the one EnvironmentFile= expected, every hardening
# directive present, and NO other line (so no ExecStartPre/Post/Stop*/Reload,
# no second ExecStart, no drop-in style extras).
mg_service_problems() {
  local py=$2 to=$3 h=$4 gnupg=$5 etc=$6 spec
  spec=$(
    mg_line K '[Unit]' 'Description='
    mg_line R '[Unit]' 'After=network.target postgresql.service'
    mg_line R '[Unit]' "RequiresMountsFor=$h"
    mg_line R '[Service]' 'Type=oneshot'
    mg_line R '[Service]' "User=$to"
    mg_line R '[Service]' "Group=$to"
    mg_line R '[Service]' 'UMask=0027'
    mg_line R '[Service]' "EnvironmentFile=$etc/$MG_ENV"
    mg_line R '[Service]' "Environment=\"WILLOW_HOME=$h\""
    mg_line R '[Service]' "Environment=\"GNUPGHOME=$gnupg\""
    mg_line R '[Service]' "ExecStart=$py -I -m willow_mcp manifest-grant apply"
    mg_line R '[Service]' 'NoNewPrivileges=true'
    mg_line R '[Service]' 'PrivateTmp=true'
    mg_line R '[Service]' 'ProtectSystem=strict'
    mg_line R '[Service]' 'ProtectHome=read-only'
    mg_line R '[Service]' "ReadWritePaths=$h/manifest_grants"
    mg_line R '[Service]' "ReadWritePaths=$h/mcp_apps"
    mg_line R '[Service]' "ReadWritePaths=$h/constitutional"
    mg_line R '[Service]' "ReadWritePaths=$(dirname -- "$gnupg")"
    mg_line R '[Service]' 'ProtectKernelTunables=true'
    mg_line R '[Service]' 'ProtectControlGroups=true'
    mg_line R '[Service]' 'RestrictSUIDSGID=true'
    mg_line R '[Service]' 'LockPersonality=true'
  )
  mg_ini_problems "$1" "$spec"
}

# mg_timer_problems TIMER -- only the committed [Timer]/[Install] keys; Unit=,
# if present, must name the service.
mg_timer_problems() {
  local spec
  spec=$(
    mg_line K '[Unit]' 'Description='
    mg_line R '[Timer]' 'OnBootSec=2min'
    mg_line R '[Timer]' 'OnUnitActiveSec=60s'
    mg_line O '[Timer]' "Unit=$MG_SERVICE"
    mg_line R '[Install]' 'WantedBy=timers.target'
  )
  mg_ini_problems "$1" "$spec"
}

# mg_env_problems ENV TRUST_OWNER ETC PGDB -- only the expected keys, with the
# expected values; WILLOW_PG_DB must be exactly PGDB ("" for the committed
# template, the rendered database name for the file that gets installed). A
# newline smuggled into PGDB shows up as a line outside the set.
mg_env_problems() {
  local spec
  spec=$(
    mg_line R '' "WILLOW_KEYRING=$3/verifiers.public.json"
    mg_line R '' "WILLOW_SEAL_RING=$3/verifiers.public.json"
    mg_line R '' "WILLOW_PG_DB=$4"
    mg_line R '' "WILLOW_PG_USER=$2"
    mg_line R '' 'WILLOW_MCP_STRICT_TRUST_ROOT=1'
  )
  mg_ini_problems "$1" "$spec"
}

# mg_render_env SRC PGDB -- the env file as installed: the template with any
# WILLOW_PGP_FINGERPRINT= line dropped and WILLOW_PG_DB= set to PGDB. Plain
# `read` and `printf %s` -- no sed, so PGDB (read from the operator-writable
# $H/env) is never interpreted as a replacement string.
mg_render_env() {
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      WILLOW_PGP_FINGERPRINT=*) ;;
      WILLOW_PG_DB=*) printf 'WILLOW_PG_DB=%s\n' "$2" ;;
      *) printf '%s\n' "$line" ;;
    esac
  done < "$1"
  return 0
}

# mg_installed_problems RENDERED INSTALLED OWNER GROUP MODE -- what is really
# in /etc against what was rendered from the committed HEAD: absent, a symlink,
# other bytes, other owner or mode.
mg_installed_problems() {
  local st
  [ -e "$2" ] || [ -L "$2" ] || { printf 'absent: %s\n' "$2"; return 0; }
  [ ! -L "$2" ] || { printf '%s is a symlink\n' "$2"; return 0; }
  cmp -s "$1" "$2" || printf '%s has other contents than the committed HEAD renders\n' "$2"
  st=$(stat -c '%U:%G %a' -- "$2" 2>/dev/null || true)
  [ "$st" = "$3:$4 $5" ] || printf '%s is %s, expected %s:%s %s\n' "$2" "${st:-unreadable}" "$3" "$4" "$5"
  return 0
}

# mg_marker_problems MARKER H TRUST_OWNER ROOT_USER ROOT_GROUP -- D4 (Loki
# D06A0EF3, docs/design/rename-away-hole.md): the root-owned marker the
# broker's uid cannot erase. Valid = a regular file (no symlink), root:root
# 0644, in a directory chain (its parent and grandparent) that is root-owned
# and not group/other-writable, with exactly `willow_home=<realpath of $H>`
# and `trust_owner_uid=<uid of the trust owner>`. Mirrors the reader in
# src/willow_mcp/trust_marker.py; the two must agree.
mg_marker_problems() {
  local m=$1 h=$2 to=$3 ru=${4:-root} rg=${5:-root} st d mode want_home want_uid lines
  [ ! -L "$m" ] || { printf '%s is a symlink\n' "$m"; return 0; }
  [ -f "$m" ] || { printf '%s is not a regular file\n' "$m"; return 0; }
  st=$(stat -c '%U:%G %a' -- "$m" 2>/dev/null || true)
  [ "$st" = "$ru:$rg 644" ] || printf '%s is %s, expected %s:%s 644\n' "$m" "${st:-unreadable}" "$ru" "$rg"
  d=$(dirname -- "$m")
  for d in "$d" "$(dirname -- "$d")"; do
    if [ -L "$d" ] || [ ! -d "$d" ]; then printf '%s is not a plain directory\n' "$d"; continue; fi
    st=$(stat -c '%U %a' -- "$d" 2>/dev/null || true)
    mode=${st#* }
    if [ "${st%% *}" != "$ru" ]; then printf '%s is owned by %s, expected %s\n' "$d" "${st%% *}" "$ru"; fi
    if [ -z "$mode" ] || [ $(( 8#$mode & 8#022 )) -ne 0 ]; then printf '%s is group/other-writable or unreadable (%s)\n' "$d" "${mode:-?}"; fi
  done
  want_home=$(readlink -f -- "$h" 2>/dev/null || true)
  want_uid=$(id -u "$to" 2>/dev/null || true)
  [ -n "$want_home" ] && [ -n "$want_uid" ] || { printf 'cannot resolve %s or trust owner %s\n' "$h" "$to"; return 0; }
  lines=$(cat -- "$m" 2>/dev/null || true)
  [ "$lines" = "willow_home=$want_home
trust_owner_uid=$want_uid" ] || printf '%s does not read exactly willow_home=%s and trust_owner_uid=%s\n' "$m" "$want_home" "$want_uid"
  return 0
}

# mg_write_marker MARKER H TRUST_OWNER ROOT_USER ROOT_GROUP -- write the marker
# atomically (temp file beside it, 0644, root:root, mv) and validate what
# landed; returns 1 (nothing left half-written) if it does not validate.
mg_write_marker() {
  local m=$1 h=$2 to=$3 ru=${4:-root} rg=${5:-root} tmp p home uid
  home=$(readlink -f -- "$h" 2>/dev/null || true)
  uid=$(id -u "$to" 2>/dev/null || true)
  [ -n "$home" ] && [ -n "$uid" ] || { printf 'cannot resolve %s or trust owner %s\n' "$h" "$to" >&2; return 1; }
  tmp=$(mktemp -- "$(dirname -- "$m")/.trust-provisioned.XXXXXX") || return 1
  printf 'willow_home=%s\ntrust_owner_uid=%s\n' "$home" "$uid" > "$tmp" || { rm -f -- "$tmp"; return 1; }
  chmod 0644 -- "$tmp" && chown "$ru:$rg" -- "$tmp" || { rm -f -- "$tmp"; return 1; }
  # validate the temp file BEFORE it replaces anything: a bad write must not
  # clobber an existing valid marker
  p=$(mg_marker_problems "$tmp" "$h" "$to" "$ru" "$rg")
  [ -z "$p" ] || { printf '%s\n' "$p" >&2; rm -f -- "$tmp"; return 1; }
  mv -f -- "$tmp" "$m" || { rm -f -- "$tmp"; return 1; }
  p=$(mg_marker_problems "$m" "$h" "$to" "$ru" "$rg")
  [ -z "$p" ] || { printf '%s\n' "$p" >&2; return 1; }
}

# mg_stamp_problems STAMPFILE HEADSHA -- the venv and the units must come from
# the same commit: the venv's recorded build commit is the HEAD clone's.
mg_stamp_problems() {
  local built
  [ -n "$2" ] || { printf 'the HEAD clone has no commit sha\n'; return 0; }
  [ -f "$1" ] || { printf '%s is absent: the venv records no build commit\n' "$1"; return 0; }
  built=$(cat -- "$1" 2>/dev/null || true)
  [ "$built" = "$2" ] || printf 'the venv was built from %s, the units come from the HEAD clone %s\n' "${built:-<empty>}" "$2"
  return 0
}

# mg_emit OK_LABEL FAIL_LABEL PROBLEMS -- a report line; 1 when PROBLEMS is set.
mg_emit() {
  if [ -z "$3" ]; then printf '  [ok]   %s\n' "$1"; return 0; fi
  printf '  [FAIL] %s\n' "$2"
  printf '%s\n' "$3" | head -8 | sed 's/^/           - /'
  return 1
}

# mg_report CLONE PY TRUST_OWNER H GNUPGHOME ETC SYSD STAMP HEADSHA PGDB [ROOT_USER ROOT_GROUP] --
# one line per check (0 only if all pass): the committed units and env, the
# env as it will be rendered, the stamp, and the files really in /etc against
# the render. An installed file that is not there yet is [info], not a failure.
# ROOT_USER/ROOT_GROUP (default root/root) are the account that must own the
# installed files; production never passes them (tests do, to run unprivileged).
mg_report() {
  local clone=$1 py=$2 to=$3 h=$4 gnupg=$5 etc=$6 sysd=$7 stamp=$8 sha=$9 pgdb=${10}
  local ru=${11:-root} rg=${12:-root}
  local src="$clone/$MG_DEPLOY_REL" rc=0 p
  p=$(mg_stamp_problems "$stamp" "$sha")
  mg_emit "the venv was built from the commit the units are read from (${sha:0:12})" "the venv and the units come from different commits" "$p" || rc=1
  p=$(mg_service_problems "$src/$MG_SERVICE" "$py" "$to" "$h" "$gnupg" "$etc")
  mg_emit "committed $MG_SERVICE carries exactly the expected directives (User/Group $to, ExecStart $py)" "committed $MG_SERVICE is not the expected unit" "$p" || rc=1
  p=$(mg_timer_problems "$src/$MG_TIMER")
  mg_emit "committed $MG_TIMER carries only the expected keys" "committed $MG_TIMER is not the expected timer" "$p" || rc=1
  p=$(mg_env_problems "$src/$MG_ENV" "$to" "$etc" "")
  mg_emit "committed $MG_ENV carries only the expected keys" "committed $MG_ENV is not the expected env file" "$p" || rc=1
  p=$(mg_env_problems <(mg_render_env "$src/$MG_ENV" "$pgdb") "$to" "$etc" "$pgdb")
  mg_emit "$MG_ENV renders to only the expected keys" "$MG_ENV does not render to the expected keys" "$p" || rc=1
  if [ -e "$sysd/$MG_SERVICE" ] || [ -L "$sysd/$MG_SERVICE" ]; then
    p=$(mg_installed_problems "$src/$MG_SERVICE" "$sysd/$MG_SERVICE" "$ru" "$rg" 644)
    mg_emit "installed unit matches committed HEAD" "installed unit differs from committed HEAD ($sysd/$MG_SERVICE)" "$p" || rc=1
  else
    printf '  [info] %s is not installed yet; a plain install installs it from the committed HEAD\n' "$sysd/$MG_SERVICE"
  fi
  if [ -e "$sysd/$MG_TIMER" ] || [ -L "$sysd/$MG_TIMER" ]; then
    p=$(mg_installed_problems "$src/$MG_TIMER" "$sysd/$MG_TIMER" "$ru" "$rg" 644)
    mg_emit "installed timer matches committed HEAD" "installed timer differs from committed HEAD ($sysd/$MG_TIMER)" "$p" || rc=1
  else
    printf '  [info] %s is not installed yet\n' "$sysd/$MG_TIMER"
  fi
  if [ -e "$etc/$MG_ENV" ] || [ -L "$etc/$MG_ENV" ]; then
    p=$(mg_installed_problems <(mg_render_env "$src/$MG_ENV" "$pgdb") "$etc/$MG_ENV" "$ru" "$to" 640)
    mg_emit "installed env matches the render of committed HEAD" "installed env differs from the render of committed HEAD ($etc/$MG_ENV)" "$p" || rc=1
  else
    printf '  [info] %s is not installed yet\n' "$etc/$MG_ENV"
  fi
  # D4: the trust-provisioned marker. Absent is [info] (a box that has not
  # been through step 6 yet, or one that never will); present-but-wrong is a
  # [FAIL] -- the reader refuses an invalid marker, it never reads it as absent.
  if [ -e "$etc/$MG_MARKER" ] || [ -L "$etc/$MG_MARKER" ]; then
    p=$(mg_marker_problems "$etc/$MG_MARKER" "$h" "$to" "$ru" "$rg")
    mg_emit "trust-provisioned marker $etc/$MG_MARKER is valid (rename-away protection ON)" "trust-provisioned marker $etc/$MG_MARKER is invalid (every PGP reader on this box refuses until it is repaired)" "$p" || rc=1
  else
    printf '  [info] %s is absent: rename-away protection (Loki D06A0EF3) is OFF; a plain install writes it after step 6\n' "$etc/$MG_MARKER"
  fi
  return "$rc"
}
# END trust-venv-check

# ---- the atomic swap (Q50, 2026-10-11) -----------------------------------------
# Rebuilding the venv in place left a window (observed on the box during the
# 8b53488 deploy: a manifest-grant timer tick found $TRUST_VENV half-deleted and
# failed `No module named willow_mcp`). Now $TRUST_VENV is a root-owned SYMLINK
# to a release directory beside it:
#   /opt/willow-operator/venv            -> venv.rel.<random>   (the live one)
#   /opt/willow-operator/venv.rel.<random>   a complete venv, built AT that
#                                            permanent name, so its baked-in
#                                            path (pyvenv.cfg, shebangs) never
#                                            changes after the swap
# The unit's `ExecStart=/opt/willow-operator/venv/bin/python ...` line stays
# valid: the symlink is transparent to the kernel and to CPython (it finds
# pyvenv.cfg beside the path it was exec'd by). The preflight already walks the
# lexical AND the readlink -f chain of the interpreter and requires every
# component, symlinks included, to be root-owned (a symlink's own mode is
# ignored, only its owner counts), and /opt/willow-operator is a root:root 755
# directory, so only root can repoint it. The first run on a box whose
# $TRUST_VENV is still a real directory swaps with renameat2(RENAME_EXCHANGE),
# which trades the directory and the symlink in one step; the old directory is
# deleted only afterwards.

TVC_STAGE=""            # the release directory being built; removed on any failure before the swap
TVC_SWAP_PY=$TRUST_PY_BASE   # runs the rename; a plain assignment, never read from the environment
TVC_OWNER=root:root          # tests override it; production is root:root

# tvc_stop MESSAGE -- discard the unfinished release directory, then stop.
tvc_stop() {
  if [ -n "$TVC_STAGE" ]; then rm -rf -- "$TVC_STAGE"; TVC_STAGE=""; fi
  stop "$@"
}

# tvc_rename MODE SRC DST -- one renameat2(2): MODE is exchange (RENAME_EXCHANGE,
# both must exist) or noreplace (RENAME_NOREPLACE). Never falls back to a
# non-atomic copy: a filesystem without the flag is an error.
tvc_rename() {
  "$TVC_SWAP_PY" -I -c '
import ctypes, os, sys
mode, src, dst = sys.argv[1:4]
flags = {"exchange": 2, "noreplace": 1}[mode]
libc = ctypes.CDLL(None, use_errno=True)
if libc.renameat2(-100, os.fsencode(src), -100, os.fsencode(dst), flags) != 0:
    sys.stderr.write("renameat2(%s, %s): %s\n" % (src, dst, os.strerror(ctypes.get_errno())))
    sys.exit(1)
' "$1" "$2" "$3"
}

# tvc_build_stage STAGE REQS WHEEL -- the venv, the hash-pinned dependencies and
# the wheel, built at STAGE's own permanent path. $TRUST_VENV is not touched.
tvc_build_stage() {
  local stage=$1 reqs=$2 wheel=$3
  chown "$TVC_OWNER" "$stage" && chmod 755 "$stage" || tvc_stop "could not set the release directory $stage root:root 755"
  ( umask 022; "$TRUST_PY_BASE" -I -m venv "$stage" ) \
    || tvc_stop "could not create the venv with $TRUST_PY_BASE (Debian/Ubuntu: apt install python3-venv)"
  ( umask 022; "$stage/bin/python" -I -m pip install --quiet --require-hashes --only-binary=:all: --no-deps -r "$reqs" ) \
    || tvc_stop "pip could not install the hash-pinned dependencies from ${reqs#"$TVC_BUILD/src/"} into $stage (a hash mismatch refuses the install); $TRUST_VENV is unchanged"
  ( umask 022; "$stage/bin/python" -I -m pip install --quiet --no-deps --no-index "$wheel" ) \
    || tvc_stop "could not install ${wheel##*/} into $stage; $TRUST_VENV is unchanged"
  printf '%s\n' "$HEAD_SHA" > "$stage/$TVC_STAMP" \
    || tvc_stop "could not record the commit the venv was built from"
  chown -R "$TVC_OWNER" "$stage" && chmod -R u=rwX,go=rX "$stage" || tvc_stop "could not set $stage root:root, go-w"
}

# tvc_publish STAGE ROOT_UID ANCHOR -- check STAGE with the FULL preflight at its
# own path, swap it in with one rename, check again at $TRUST_VENV (the chain
# now holds the symlink), roll back by the same rename if that fails, and only
# then delete what was live. Production: tvc_publish "$stage" 0 /.
tvc_publish() {
  local stage=$1 ru=$2 anchor=$3 live=$TRUST_VENV link old had=""
  stage=$(readlink -f -- "$stage")
  tvc_report "$stage" "$stage/bin/python" "$ru" "$anchor" "$TRUST_PY_BASE" \
    || tvc_stop "the venv just built at $stage failed its own preflight -- see the FAIL lines above; $TRUST_VENV is unchanged"
  link="$live.swap.$$"
  rm -rf -- "$link"
  ln -s -- "${stage##*/}" "$link" || tvc_stop "could not create the symlink $link"
  if [ -e "$live" ] || [ -L "$live" ]; then
    had=1
    tvc_rename exchange "$link" "$live" || { rm -f -- "$link"; tvc_stop "could not swap $stage in at $live; $live is unchanged"; }
  else
    tvc_rename noreplace "$link" "$live" || { rm -f -- "$link"; tvc_stop "could not move $stage into place at $live"; }
  fi
  TVC_STAGE=""   # live now; from here a failure rolls back, it does not just delete
  if ! tvc_report "$live" "$live/bin/python" "$ru" "$anchor" "$TRUST_PY_BASE"; then
    if [ -n "$had" ]; then
      tvc_rename exchange "$link" "$live" || stop "swapped-in venv failed its preflight at $live and the rollback rename failed -- repair $live by hand ($link holds the previous one)"
      rm -f -- "$link"
    else
      rm -f -- "$live"
    fi
    rm -rf -- "$stage"
    stop "the venv at $live failed its preflight after the swap; the previous venv was put back"
  fi
  if [ -n "$had" ]; then
    if [ -L "$link" ]; then
      old=$(readlink -f -- "$link" || true)
      rm -f -- "$link"
      case "$old" in "$live".rel.*) [ "$old" = "$stage" ] || rm -rf -- "$old" ;; esac
    else
      rm -rf -- "$link"
    fi
  fi
  # release directories a crashed earlier run left behind (never the live one)
  for old in "$live".rel.* "$live".swap.*; do
    [ -e "$old" ] || [ -L "$old" ] || continue
    [ "$(readlink -f -- "$old" 2>/dev/null)" = "$stage" ] || rm -rf -- "$old"
  done
  say "  $live -> ${stage##*/} (swapped with one rename; the previous venv removed afterwards)"
}

# provision_trust_venv [force] -- root builds $TRUST_VENV from this checkout.
# Skipped when the venv already passes every check, unless forced
# (--provision-venv). Rebuilds from the checkout's COMMITTED HEAD (a local
# clone, so the build writes nothing into the operator-writable checkout and
# runs no operator-writable build code beyond the commit being installed).
provision_trust_venv() {
  local force=${1:-} problems head_built reqs build_reqs f
  local -a wheels
  # The privileged steps (rotate_resign, sync_constitutional,
  # seed_envelope_ratify, the constitutional seed bundle) now run FROM the
  # venv, so a venv built from an older HEAD would run older steps than the
  # checkout holds: skip only when it passes every check AND was built from the
  # checkout's current HEAD (the stamp is written below, inside the venv).
  if [ -z "$force" ] && tvc_report "$TRUST_VENV" "$PY" 0 / "$TRUST_PY_BASE" >/dev/null 2>&1; then
    head_built=$(cat "$TRUST_VENV/$TVC_STAMP" 2>/dev/null || true)
    if [ -n "$HEAD_SHA" ] && [ "$HEAD_SHA" = "$head_built" ]; then
      say "== 0a. trust-owner venv $TRUST_VENV already passes every check and was built from HEAD ${HEAD_SHA:0:12} -- not rebuilt (sudo bash install.sh --provision-venv --expect-head <sha> rebuilds it from that commit)"
      return 0
    fi
    say "== 0a. trust-owner venv $TRUST_VENV passes its checks but its recorded build commit (${head_built:0:12}) is not the checkout HEAD (${HEAD_SHA:0:12}) -- rebuilding so the privileged steps and the units match the checkout"
  fi
  say "== 0a. build the trust-owner venv at $TRUST_VENV (root:root, non-editable, from the committed HEAD ${HEAD_SHA:0:12})"
  [ -x "$TRUST_PY_BASE" ] || stop "$TRUST_PY_BASE is not executable -- the trust-owner venv is built from the root-owned system python (edit TRUST_PY_BASE in install.sh if this box's system python is another version)"
  problems=$(tvc_chain_problems / "$TRUST_PY_BASE" 0)
  [ -z "$problems" ] || stop "the base interpreter $TRUST_PY_BASE is itself not root-owned and unwritable: $problems"
  # F3: root runs this interpreter below (the build venv, `-m venv`), so the
  # standard library and the site hooks it loads are checked first, no
  # interpreter executed.
  problems=$(tvc_stdlib_problems / "$TRUST_PY_BASE" 0; tvc_stdlib_acl_problems / "$TRUST_VENV" "$TRUST_PY_BASE")
  [ -z "$problems" ] || stop "the standard library of the base interpreter $TRUST_PY_BASE is not root-owned and unwritable (or carries a non-root write ACL): $problems"
  # Both hash-pinned files come from the committed HEAD in the root-owned clone.
  reqs="$TVC_BUILD/src/$TRUST_REQS_REL"; build_reqs="$TVC_BUILD/src/$TRUST_BUILD_REQS_REL"
  for f in "$reqs" "$build_reqs"; do
    problems=$(tvc_requirements_problems "$f")
    [ -z "$problems" ] || stop "${f#"$TVC_BUILD/src/"} is not a plain hash-pinned requirements file (committed HEAD): $problems"
  done
  export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONNOUSERSITE=1
  # Throwaway build venv (root-owned temp dir, deleted on exit). The build
  # backend (hatchling, hatch-vcs and their dependencies) is installed into it
  # from the hash-pinned file; the wheel is then built with --no-build-isolation
  # --no-index, so nothing unpinned is fetched while root builds.
  ( umask 022; "$TRUST_PY_BASE" -I -m venv "$TVC_BUILD/buildvenv" ) \
    || stop "could not create the build venv with $TRUST_PY_BASE (Debian/Ubuntu: apt install python3-venv)"
  ( umask 022; "$TVC_BUILD/buildvenv/bin/python" -I -m pip install --quiet --require-hashes --only-binary=:all: --no-deps -r "$build_reqs" ) \
    || stop "pip could not install the hash-pinned build tools from ${build_reqs#"$TVC_BUILD/src/"} (a hash mismatch refuses the install)"
  ( umask 022; "$TVC_BUILD/buildvenv/bin/python" -I -m pip wheel --quiet --no-deps --no-build-isolation --no-index --wheel-dir "$TVC_BUILD/wheels" "$TVC_BUILD/src" ) \
    || stop "could not build a willow-mcp wheel from the committed HEAD ${HEAD_SHA:0:12}"
  mapfile -t wheels < <(find "$TVC_BUILD/wheels" -maxdepth 1 -name 'willow_mcp-*.whl')
  [ "${#wheels[@]}" = 1 ] || stop "expected exactly one willow_mcp wheel, found ${#wheels[@]}"
  # Build into a sibling release directory and swap it in with ONE rename(2);
  # $TRUST_VENV is never deleted, emptied or half-built (see tvc_publish).
  install -d -o root -g root -m 755 "$(dirname "$TRUST_VENV")"
  TVC_STAGE=$(mktemp -d "$TRUST_VENV.rel.XXXXXXXX") || stop "could not create a release directory beside $TRUST_VENV"
  tvc_build_stage "$TVC_STAGE" "$reqs" "${wheels[0]}"
  say "  installed ${wheels[0]##*/} (non-editable) + the hash-pinned dependencies in ${TRUST_REQS_REL##*/} into ${TVC_STAGE}"
  tvc_publish "$TVC_STAGE" 0 /
}

# enforce_trust_interpreter -- the preflight: refuse (stop) unless every check passes.
enforce_trust_interpreter() {
  local up
  tvc_report "$TRUST_VENV" "$PY" 0 / "$TRUST_PY_BASE" \
    || stop "trust-owner python interpreter at $PY failed the preflight (FAIL lines above): it must exist, be executable, sit on a path no non-root uid can write, and be a non-editable install -- Loki audit BFCC5C79 F7, operator rulings Q7=A/Q13. A plain 'sudo bash install.sh --expect-head <sha>' or 'sudo bash install.sh --provision-venv --expect-head <sha>' builds it."
  # The units and the venv come from one commit, and the committed unit, timer
  # and env are each exactly the expected directive set (mg_*, above).
  up=$(mg_stamp_problems "$TRUST_VENV/$TVC_STAMP" "$HEAD_SHA")
  [ -z "$up" ] || stop "$up -- the units and the venv must come from the same commit; sudo bash install.sh --provision-venv --expect-head <sha> rebuilds the venv from that commit"
  up=$(mg_service_problems "$HEAD_CLONE/$MG_DEPLOY_REL/$MG_SERVICE" "$PY" "$TRUST_OWNER" "$H" "$GNUPGHOME_TO" "$ETC")
  [ -z "$up" ] || stop "$MG_SERVICE (committed HEAD ${HEAD_SHA:0:12}) is not the expected unit -- it must carry exactly the allowlisted directives and name the same interpreter as install.sh: $up"
  up=$(mg_timer_problems "$HEAD_CLONE/$MG_DEPLOY_REL/$MG_TIMER")
  [ -z "$up" ] || stop "$MG_TIMER (committed HEAD ${HEAD_SHA:0:12}) is not the expected timer: $up"
  up=$(mg_env_problems "$HEAD_CLONE/$MG_DEPLOY_REL/$MG_ENV" "$TRUST_OWNER" "$ETC" "")
  [ -z "$up" ] || stop "$MG_ENV (committed HEAD ${HEAD_SHA:0:12}) is not the expected env file: $up"
}

# ------------------------------------------------------- --dry-run-sign
# A real two-uid run of the signing steps cannot be exercised in Kart
# (single-uid sandbox) or by any test fixture that fakes the interpreter
# under one uid — exactly the gap that let the mktemp-owned-by-root bug
# through in the first place (2026-09-22, first live install; fixed below,
# 338bbdb). This prints the EXACT command sequence signing runs, uid by
# uid, for a reader to check by eye instead of by running it — no root
# required, touches nothing, needs no real box.
if [ "${1:-}" = "--dry-run-sign" ]; then
  cat <<DRYRUN
--dry-run-sign: the sign sequence, one file, every loop is identical in shape.
Three processes, two uids -- read top to bottom:

  SIG_TMP=\$(mktemp)
      # uid: root (this script). Creates a 0600 file THIS process owns.
      # Nothing here yet involves $TRUST_OWNER.

  as_to gpg --batch --yes --detach-sign --armor --local-user "\$FPR" --output - "<file>" > "\$SIG_TMP"
      # uid: root opens \$SIG_TMP for writing (the ">" redirection is
      # evaluated by THIS shell, before sudo runs) -- root now holds an
      # already-open, root-owned file descriptor.
      # uid: $TRUST_OWNER (via "sudo -u $TRUST_OWNER", inside as_to) runs gpg.
      # gpg writes its detached signature to ITS OWN stdout (--output -),
      # never touching \$SIG_TMP's path at all -- gpg as $TRUST_OWNER never
      # needs permission on that path, because it never opens it. The bytes
      # land in \$SIG_TMP because that fd (root's) is what stdout was
      # connected to before gpg ever started.
      # This is the fix for "gpg: can't create '/tmp/tmp.xxx': Permission
      # denied" -- SIG_TMP used to be handed to gpg as a path (-o \$SIG_TMP),
      # which gpg-as-$TRUST_OWNER cannot open for writing.

  install -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 644 "\$SIG_TMP" "<file>.sig"
      # uid: root. Installs the signature at its live path, correctly owned.

  rm -f "\$SIG_TMP"
      # uid: root. Cleans up its own temp file.

Run once per mcp_apps/*/manifest.json, and once each for the active register
(constitutional/pre-approved.json) and the federation registry
(mcp_apps/_federation/servers.json) -- same four lines, same two uids.
syscall-table.json is signed separately and atomically, in the SAME act as
it is synced (sync_constitutional.py's --sign-as path, called from step 1c,
via this same sign_fn/verify_fn shape) -- not here, and not by step 6.
DRYRUN
  exit 0
fi

# ------------------------------------------------------------- argument parsing
# Dispatch B291C0C7 ("one signing key, one source of truth"): --rotate and
# --check-signatures are new; --retire is repeatable and only meaningful with
# --rotate. --dry-run-sign was already handled above (it exits before this
# point on its own, and needs no root).
CHECK_ONLY=""
ROTATE=""
CHECK_SIGNATURES=""
PROVISION_VENV=""
RECORD_FIRST=""              # --record-trust-identity (D1: the first record)
RERECORD=""                  # --re-record-trust-identity (D1)
RERECORD_CONFIRM=""          # --confirm TOKEN
CHECK_FAILED=""
RETIRE_FPRS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK_ONLY="--check"; shift ;;
    --check-signatures) CHECK_SIGNATURES=1; shift ;;
    --rotate) ROTATE=1; shift ;;
    --provision-venv) PROVISION_VENV=1; shift ;;
    --record-trust-identity) RECORD_FIRST=1; shift ;;
    --re-record-trust-identity) RERECORD=1; shift ;;
    --confirm)
      [ $# -ge 2 ] || stop "--confirm requires the token --re-record-trust-identity printed"
      case "$2" in -*|'') stop "--confirm requires the token --re-record-trust-identity printed (got '${2:0:40}')" ;; esac
      RERECORD_CONFIRM=$2; shift 2 ;;
    --expect-head)
      # already validated (full 40-hex, exactly once) and equal to the clone's
      # commit by the pre-reexec section; the value is consumed here.
      [ $# -ge 2 ] || stop "--expect-head requires the full 40-hex commit sha"
      shift 2 ;;
    --retire)
      [ $# -ge 2 ] || stop "--retire requires a fingerprint argument"
      RETIRE_FPRS+=("$2"); shift 2 ;;
    *) stop "unknown argument: $1 (known: --expect-head SHA, --check, --check-signatures, --provision-venv, --rotate, --retire FPR, --record-trust-identity, --re-record-trust-identity, --confirm TOKEN, --dry-run-sign)" ;;
  esac
done

# Loki audit A38D41C2, F6: a flag combination must mean what it says, or
# refuse rather than silently doing something else. `--retire` alone (no
# `--rotate`) used to be parsed and then ignored, falling through into the
# full mutating plain install; `--check --rotate` used to mutate anyway,
# because `--check`'s own gate only fired AFTER `--rotate` had already
# exited. Both are refused up front, before anything is touched.
if [ "${#RETIRE_FPRS[@]}" -gt 0 ] && [ -z "$ROTATE" ]; then
  stop "--retire only makes sense with --rotate (there is no key being replaced to retire the old one for). Did you mean: sudo bash install.sh --rotate --retire ${RETIRE_FPRS[0]} --expect-head <sha>?"
fi
if [ -n "$CHECK_ONLY" ] && [ -n "$ROTATE" ]; then
  stop "--check and --rotate are mutually exclusive: --check inspects and changes nothing, --rotate mutates. Use --check-signatures first if you want a read-only pre-check, then --rotate."
fi

if [ -n "$PROVISION_VENV" ] && [ -n "$CHECK_ONLY$ROTATE$CHECK_SIGNATURES" ]; then
  stop "--provision-venv builds the trust-owner venv and nothing else; it cannot be combined with --check, --check-signatures or --rotate"
fi
# D1 (bite 2): the first record is a plain install's act; a re-record is its own mode.
if [ -n "$RECORD_FIRST" ] && [ -n "$CHECK_ONLY$ROTATE$CHECK_SIGNATURES$PROVISION_VENV$RERECORD" ]; then
  stop "--record-trust-identity is a flag of the plain install (audit, then step 1-7, then the first record); it cannot be combined with --check, --check-signatures, --rotate, --provision-venv or --re-record-trust-identity"
fi
if [ -n "$RERECORD" ] && [ -n "$CHECK_ONLY$ROTATE$CHECK_SIGNATURES$PROVISION_VENV" ]; then
  stop "--re-record-trust-identity is its own mode; it cannot be combined with --check, --check-signatures, --rotate or --provision-venv"
fi
if [ -n "$RERECORD_CONFIRM" ] && [ -z "$RERECORD" ]; then
  stop "--confirm only goes with --re-record-trust-identity"
fi

# ---------------------------------------------------------------- preflight
[ "$(id -u)" = 0 ] || stop "run as root (sudo bash install.sh --expect-head <40-hex sha>)"
say "== pinned: this is the clone's own install.sh at commit $HEAD_SHA (--expect-head matched); nothing from here on is read from the working tree"
# --provision-venv: build and check the trust-owner venv, touch nothing else, so
# the venv can be audited BEFORE the unit is repointed at it (the unit and the
# rest of the box change only on a plain install).
if [ -n "$PROVISION_VENV" ]; then
  provision_trust_venv force
  exit 0
fi
[ -d "$H" ] || stop "operator box not found at $H"
id "$TRUST_OWNER" >/dev/null 2>&1 || stop "user $TRUST_OWNER does not exist — trust_root_setup has not run on this box"
# The units and the env template are read from the committed HEAD (the one
# root-owned clone the pre-reexec section made, pinned by --expect-head), never
# from the working tree.
for f in "$MG_ENV" "$MG_SERVICE" "$MG_TIMER"; do
  [ -f "$HEAD_CLONE/$MG_DEPLOY_REL/$f" ] || stop "$MG_DEPLOY_REL/$f is not in the committed HEAD ${HEAD_SHA:0:12} -- commit it first (an uncommitted file is never installed)"
done
[ -f "$ETC/verifiers.public.json" ] || stop "$ETC/verifiers.public.json absent — the net-signer's public ring is a precondition (manifest-grant.env names it)"
PG_DB=$(grep -E '^WILLOW_PG_DB=' "$H/env" | tail -1 | cut -d= -f2- || true)
[ -n "$PG_DB" ] || stop "WILLOW_PG_DB not set in $H/env"
# The trust owner's interpreter (F7, Q7=A/Q13): used from step 1 on, so a bad
# one stops here, before anything is touched. --check reports every line and
# continues (exit 2 at the end); --rotate / --check-signatures only enforce it
# (they never build); a plain install builds it first when it is missing or
# fails a check, then enforces. (--re-record-trust-identity only enforces too.)
if [ -n "$CHECK_ONLY" ]; then
  say "== trust-owner interpreter $PY"
  tvc_report "$TRUST_VENV" "$PY" 0 / "$TRUST_PY_BASE" || CHECK_FAILED=1
  say "== units and env from the committed HEAD ${HEAD_SHA:0:12}"
  mg_report "$HEAD_CLONE" "$PY" "$TRUST_OWNER" "$H" "$GNUPGHOME_TO" "$ETC" "$SYSD" "$TRUST_VENV/$TVC_STAMP" "$HEAD_SHA" "$PG_DB" || CHECK_FAILED=1
else
  [ -n "$ROTATE$CHECK_SIGNATURES$RERECORD" ] || provision_trust_venv
  enforce_trust_interpreter
fi

# governed_files: every file trusted-owner-signed under WILLOW_PGP_FINGERPRINT
# that --rotate must re-sign and --check-signatures reads — one list, used by
# both, so they can never silently drift apart. Prints one path per line;
# absent paths are printed too (both callers treat "absent" as its own state,
# never an error).
governed_files() {
  for a in "$H"/mcp_apps/*/; do
    [ -f "$a/manifest.json" ] && printf '%s\n' "$a/manifest.json"
  done
  printf '%s\n' "$H/constitutional/pre-approved.json"
  printf '%s\n' "$H/constitutional/syscall-table.json"
  printf '%s\n' "$H/mcp_apps/_federation/servers.json"
  printf '%s\n' "$H/constitutional/frank_head_anchor.json"
  # Loki audit A38D41C2, F10: an UNRATIFIED seed's signature IS the
  # ratification act on a trust root (seed_loader.py: pending status is
  # "advisory only", never mirrored or promoted) -- re-signing a pending
  # seed under the trust owner's key during a routine key rotation would
  # silently ratify it. Only seeds whose own ratification.status is
  # "ratified" are governed; a seed this can't parse is treated as NOT
  # ratified (skip, never include on a read failure).
  for s in "$H"/seeds/*.json; do
    [ -e "$s" ] || continue
    if "$PY" -I - "$s" <<'PYEOF'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
status = str((doc.get("seed") or {}).get("ratification", {}).get("status") or "pending").lower()
sys.exit(0 if status == "ratified" else 1)
PYEOF
    then
      printf '%s\n' "$s"
    fi
  done
}

# strip_pgp_pin: the serve unit's own WILLOW_PGP_FINGERPRINT= pin, if any.
# Dispatch B291C0C7, fixed for real shape per Loki audit A38D41C2 F1: called
# from BOTH the plain-install flow (step 3) and --rotate (F5 -- a standalone
# --rotate used to exit before step 3 ever ran, so it never stripped a pin
# and never restarted the broker even though its own final message told the
# operator to). One function, one behavior, no drift between the two
# callers.
strip_pgp_pin() {
  say "== strip the serve unit's own WILLOW_PGP_FINGERPRINT pin, if any"
  local dropin="/home/$OPERATOR/.config/systemd/user/willow-mcp-serve.service.d/pgp.conf"
  if [ ! -f "$dropin" ]; then
    say "  no pin found at $dropin"
    return 0
  fi
  # Loki A38D41C2, F1 (BLOCKING) and its re-audit residual (93D0F057):
  # systemd's Environment= directive is not line-shaped the way a bare
  # sed regex can safely match -- it takes a SPACE-SEPARATED list of
  # shell-quoted NAME=VALUE tokens on one line
  # (`Environment="FOO=1" "WILLOW_PGP_FINGERPRINT=..."`), tolerates space
  # around the `=` (`Environment = "..."`), and a naive per-line regex
  # either matches nothing (deletes nothing, reports "stripped" falsely)
  # or -- worse -- deletes an ENTIRE line that also carries an unrelated
  # variable. Tokenized properly with shlex (the same approach
  # env_fingerprint.py already uses for this exact directive) via the
  # trust-owner python: strip ONLY the WILLOW_PGP_FINGERPRINT= token from
  # each Environment= line, rebuild the line from whatever tokens remain,
  # and drop the line entirely only if nothing remains on it.
  "$PY" -I - "$dropin" <<'PYEOF'
import re, shlex, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
had_trailing_newline = text.endswith("\n")
lines = text.split("\n")
out = []
changed = False
env_re = re.compile(r'^(\s*)Environment\s*=\s*(.*)$')
bare_re = re.compile(r'^\s*WILLOW_PGP_FINGERPRINT=')
for line in lines:
    if bare_re.match(line):
        # The pre-systemd-drop-in shape this install once wrote directly
        # (no Environment= wrapper at all) -- still matched for anything
        # left over from before the drop-in existed.
        changed = True
        continue
    m = env_re.match(line)
    if not m:
        out.append(line)
        continue
    indent, rest = m.groups()
    try:
        tokens = shlex.split(rest, posix=True)
    except ValueError:
        out.append(line)  # can't safely tokenize -- leave it, never guess
        continue
    kept = [t for t in tokens if not t.startswith("WILLOW_PGP_FINGERPRINT=")]
    if len(kept) == len(tokens):
        out.append(line)
        continue
    changed = True
    if not kept:
        continue  # drop the whole line
    out.append(indent + "Environment=" + " ".join(f'"{t}"' for t in kept))
new_text = "\n".join(out)
if had_trailing_newline and not new_text.endswith("\n"):
    new_text += "\n"
if changed:
    open(path, "w", encoding="utf-8").write(new_text)
print("CHANGED" if changed else "UNCHANGED")
PYEOF
  if grep -qE 'WILLOW_PGP_FINGERPRINT=' "$dropin"; then
    stop "$dropin still names WILLOW_PGP_FINGERPRINT after the strip -- the tokenizer did not match its actual shape. Not reporting success; fix strip_pgp_pin() in install.sh and rerun. Contents: $(cat "$dropin")"
  fi
  local remainder
  remainder=$(grep -vE '^\s*(#|\[Service\]\s*$|\s*$)' "$dropin" || true)
  if [ -z "$remainder" ]; then
    rm -f "$dropin"
    say "  removed $dropin (it pinned WILLOW_PGP_FINGERPRINT and nothing else) -- verified gone"
  else
    say "  stripped WILLOW_PGP_FINGERPRINT= from $dropin (other settings left in place) -- verified gone"
  fi
  as_op systemctl --user daemon-reload
}

# restart_broker: an env/trust change, not a pull -- the reloader will not do
# this one. Shared by the plain install and --rotate (F5), same reason as
# strip_pgp_pin above. Only reaches the --user SERVE unit; a stdio-attached
# desk (an editor/CLI session) is not a systemd unit this script can signal
# at all, and — Loki A38D41C2, F2 — reconnecting that session does NOT pick
# up a new fingerprint if the project's own .mcp.json pins one in its env
# block: that pin must be removed (desk-owned; see INSTALL.md) before a
# reconnect helps.
restart_broker() {
  say "== broker restart (trust config changed)"
  local restarted=""
  local u
  for u in "${BROKER_UNIT_CANDIDATES[@]}"; do
    if as_op systemctl --user list-unit-files --no-legend "$u" 2>/dev/null | grep -q "^$u"; then
      as_op systemctl --user restart "$u" && say "  restarted $u" && restarted=1
      break
    fi
  done
  [ -n "$restarted" ] || say "  no known willow-mcp --user service found (${BROKER_UNIT_CANDIDATES[*]}) — restart the broker by hand if it runs another way"
  say "  NOTE: a stdio-attached desk (an editor/CLI session, not the --user unit)"
  say "  cannot be restarted by this script. If its project's .mcp.json pins"
  say "  WILLOW_PGP_FINGERPRINT in the env block, reconnecting is NOT enough --"
  say "  that pin must be removed first (desk-owned), or the reconnected"
  say "  session will conflict with $TRUST_ENV and refuse to boot."
}

# retire_stale_key_if_marked: F-B (Loki audit 23DE8AA9) -- a failed retire
# used to be ONLY a printed WARNING, forgotten the moment the script exited.
# sign_and_publish_trust's retire branch now records the fingerprint it
# could not remove at $STALE_KEY_MARKER instead; this function retries that
# retire at the top of every run (plain install and --rotate both call it,
# right after GNUPGHOME_TO exists), clearing the marker on success and
# reprinting the SAME named warning (not a silent no-op) on repeat failure.
# Idempotent, harmless when no marker exists.
retire_stale_key_if_marked() {
  [ -f "$STALE_KEY_MARKER" ] || return 0
  local stale
  stale=$(cat "$STALE_KEY_MARKER" 2>/dev/null || true)
  if [ -z "$stale" ]; then
    rm -f "$STALE_KEY_MARKER"
    return 0
  fi
  say "== retiring the previous trust-owner key a prior run could not remove ($stale)"
  if as_to gpg --batch --yes --delete-secret-and-public-key "$stale" 2>/dev/null; then
    rm -f "$STALE_KEY_MARKER"
    say "  retired $stale -- $STALE_KEY_MARKER cleared"
  else
    say "  STILL could not retire $stale from $GNUPGHOME_TO -- $STALE_KEY_MARKER remains;"
    say "  retire it by hand (as_to gpg --batch --yes --delete-secret-and-public-key $stale)"
    say "  or rerun once the cause is fixed. Trust itself is unaffected either way: step 1b"
    say "  always prefers whatever fingerprint \$TRUST_ENV already names."
  fi
}

# write_trust_marker -- D4 (Loki D06A0EF3). Run right after sign_and_publish_trust
# (the step that makes $TRUST_ENV real): writes $ETC/trust-provisioned, the
# root-owned fact the broker cannot erase, so a rename-away of constitutional/
# becomes a fail-closed refusal instead of "enforcement off". Refuses to
# write it unless $TRUST_ENV carries a real 40-hex fingerprint (an empty
# fingerprint on a marked box is refused by the reader, so the marker would
# lock the box out). Never touches vault material: it writes one file in $ETC.
write_trust_marker() {
  mg_trust_env_fpr "$TRUST_ENV" >/dev/null \
    || stop "$TRUST_ENV carries no 40-hex WILLOW_PGP_FINGERPRINT after publishing: refusing to write the trust-provisioned marker (a marked box with no fingerprint refuses every PGP read)"
  mg_write_marker "$ETC/$MG_MARKER" "$H" "$TRUST_OWNER" root root \
    || stop "could not write a valid $ETC/$MG_MARKER"
  say "  wrote $ETC/$MG_MARKER (root:root 0644): rename-away protection ON for $(readlink -f "$H")"
}

# ------------------------------------------------ D1: the trust-identity record
# docs/design/d1-trust-dir-identity.md, bite 2. /etc/willow-mcp/trust-identity pins
# the (fsid, inode) of $H, constitutional/, mcp_apps/ and manifest_grants/ plus
# the public trust fingerprint; root writes it, nothing at runtime reads it yet
# (bites 3-5), so a record changes no behaviour except the three guards here:
#   * identity_precheck -- BEFORE step 1's `chown -R` and before --rotate's
#     re-sign: a recorded box whose live trust directories differ from the record
#     (or whose record is invalid, or a recorded directory is gone) stops, so root
#     cannot launder a planted tree into trust-owner ownership;
#   * the FIRST record is never written silently (Q-D1-1): a read-only audit runs
#     before step 1 and must be all-clean, and --record-trust-identity must be
#     given (see write_trust_identity);
#   * --re-record-trust-identity is the only way to accept a changed identity.
# The bytes of the record come from willow_mcp.trust_identity.render_record, run
# from the pinned trust-owner venv ($PY -I -m ...), not re-implemented here.
# BEGIN trust-identity
MG_IDENTITY=trust-identity   # $ETC/trust-identity
MG_ROOT_USER=root            # who must own the marker: a plain assignment, tests override it
MG_ROOT_GROUP=root
TI_STEP=willow_mcp.install_steps.trust_identity_record
# (RECORD_FIRST, RERECORD and RERECORD_CONFIRM are the argument defaults, above.)
TI_STATE=""                  # absent | valid, set by identity_precheck
TI_AUDIT_RC=""               # 0 clean, 1 not, set by identity_audit
TI_SNAPSHOT=""               # the identity digest the audit saw

# mg_trust_env_fpr FILE -- the 40-hex WILLOW_PGP_FINGERPRINT FILE carries (the one
# write_trust_marker requires); returns 1 when it carries none.
mg_trust_env_fpr() {
  local line
  line=$(grep -E '^(export )?WILLOW_PGP_FINGERPRINT=[0-9A-Fa-f]{40}$' -- "$1" 2>/dev/null | tail -1) || return 1
  [ -n "$line" ] || return 1
  printf '%s\n' "${line##*=}"
}

# ti_run ARGS... -- the pinned venv's identity step (root, -I).
ti_run() { "$PY" -I -m "$TI_STEP" "$@"; }

# identity_hint -- what to do about a mismatch; never "delete the record".
identity_hint() {
  printf '%s\n' \
    "If this change is NOT expected (a rename-away and plant): do not run a plain install; as root move the planted directory aside and the genuine one back (same inode: the record matches again)." \
    "If it IS legitimate (a restore, an rsync, a moved \$H, filesystem repair): verify the tree first (sudo bash install.sh --check-signatures --expect-head <sha>), then accept it with: sudo bash install.sh --re-record-trust-identity --expect-head <sha>." \
    "Never delete $ETC/$MG_IDENTITY to make this go away."
}

# identity_audit -- the read-only audit (owners, modes, kinds, the D4.5/F1 shapes,
# and every governed file verifying under the trust fingerprint). Prints it; sets
# TI_AUDIT_RC (0 only if every line is [ok]) and TI_SNAPSHOT. Changes nothing.
identity_audit() {
  local fpr out rc=0 sigout src=0 bad
  local -a gfiles
  TI_AUDIT_RC=0; TI_SNAPSHOT=""
  fpr=$(mg_trust_env_fpr "$TRUST_ENV" 2>/dev/null || true)
  out=$(ti_run audit --home "$H" --trust-owner-uid "$(id -u "$TRUST_OWNER")" --operator-uid "$OPERATOR_UID" --fingerprint "$fpr") || rc=$?
  printf '%s\n' "$out" | grep -v '^snapshot=' || true
  TI_SNAPSHOT=$(printf '%s\n' "$out" | sed -n 's/^snapshot=//p' | tail -1)
  [ "$rc" -eq 0 ] || TI_AUDIT_RC=1
  if [ -z "$fpr" ]; then
    say "  [FAIL] no governed-file signature check: $TRUST_ENV carries no 40-hex fingerprint"
    TI_AUDIT_RC=1
    return 0
  fi
  mapfile -t gfiles < <(governed_files)
  sigout=$(as_op "$PY" -I -m willow_mcp.install_steps.rotate_resign --check --fingerprint "$fpr" "${gfiles[@]}" 2>&1) || src=$?
  bad=$(printf '%s\n' "$sigout" | grep -E '^  /' | grep -vE ': (OK — verifies|absent)' || true)
  if [ "$src" -eq 0 ] && [ -z "$bad" ]; then
    say "  [ok]   every governed file verifies under the trust fingerprint $fpr (the --check-signatures read)"
  else
    say "  [FAIL] governed files that do not verify under the trust fingerprint $fpr (--check-signatures)"
    printf '%s\n' "${bad:-rotate_resign exited $src: ${sigout##*$'\n'}}" | head -8 | sed 's/^ */           - /'
    TI_AUDIT_RC=1
  fi
  return 0
}

# identity_precheck -- BEFORE step 1 (plain) or the re-sign (--rotate). Sets
# TI_STATE. Record absent: fine (a first record needs the flag, below). Record
# valid and matching the live tree: fine. Anything else: stop with the diff.
identity_precheck() {
  local fpr out rc=0
  fpr=$(mg_trust_env_fpr "$TRUST_ENV" 2>/dev/null || true)
  out=$(ti_run precheck --home "$H" --fingerprint "$fpr") || rc=$?
  case "$rc" in
    0)
      case "${out%%$'\n'*}" in
        ABSENT) TI_STATE=absent ;;
        MATCH)  TI_STATE=valid; say "  trust-identity record valid and matches the live trust directories" ;;
        *) stop "unexpected output from the trust-identity pre-check: ${out:0:200}" ;;
      esac ;;
    10)
      stop "the live trust directories differ from $ETC/$MG_IDENTITY -- nothing was changed (no chown, no mkdir, no re-sign):
$(printf '%s\n' "$out" | tail -n +2 | sed 's/^/    /')
$(identity_hint)" ;;
    11)
      stop "$ETC/$MG_IDENTITY is invalid -- nothing was changed: ${out#INVALID: }
$(identity_hint)" ;;
    *) stop "the trust-identity pre-check failed to run (exit $rc): ${out:0:300}" ;;
  esac
  return 0
}

# identity_gate_first -- plain install, before step 1, when no record exists. Always
# prints the audit; with --record-trust-identity it must be clean and the marker
# must already be valid (an already-provisioned box), else stop with nothing written.
identity_gate_first() {
  [ "$TI_STATE" = absent ] || return 0
  local mp
  mp=$(mg_marker_problems "$ETC/$MG_MARKER" "$H" "$TRUST_OWNER" "$MG_ROOT_USER" "$MG_ROOT_GROUP" 2>&1 || true)
  if [ -n "$mp" ] || [ ! -e "$ETC/$MG_MARKER" ]; then
    [ -z "$RECORD_FIRST" ] || stop "--record-trust-identity needs an already-provisioned box (a valid $ETC/$MG_MARKER from an earlier install) so there is something to audit before step 1 changes it; run a plain install first, then --check, then this${mp:+ ($(printf '%s' "$mp" | head -1))}"
    say "  no trust-identity record, and no valid marker yet: the first record needs a provisioned box (plain install, then --record-trust-identity)"
    return 0
  fi
  say "== trust-identity: no record yet -- read-only audit of the live box (nothing is changed by it)"
  identity_audit
  if [ -z "$RECORD_FIRST" ]; then
    say "  no record will be written by this run. Read the audit above; when it is all [ok] run: sudo bash install.sh --record-trust-identity --expect-head <sha>"
    TI_AUDIT_RC=1   # never let a later step treat an un-flagged audit as consent
    return 0
  fi
  [ "$TI_AUDIT_RC" = 0 ] && [ -n "$TI_SNAPSHOT" ] \
    || stop "the audit above is not all [ok]: the first trust-identity record is NOT written and step 1 did not run. Fix what it names (a plain install without the flag repairs ownership), then rerun with --record-trust-identity"
  say "  audit clean -- the first record will be written at step 6, after the marker, if the identity is unchanged"
}

# write_trust_identity [rotate] -- right AFTER write_trust_marker (the reader needs
# a valid marker): keep a valid record current, or write the first one when the
# gate allowed it. Never writes a first record without --record-trust-identity and
# a clean audit; never absorbs a changed directory identity (only --re-record does).
write_trust_identity() {
  local fpr
  [ -n "$TI_STATE" ] || stop "internal: the trust-identity pre-check did not run before the trust marker was written"
  fpr=$(mg_trust_env_fpr "$TRUST_ENV") || stop "$TRUST_ENV carries no 40-hex fingerprint: not writing the trust-identity record"
  case "$TI_STATE" in
    valid)
      ti_run write --mode rewrite --home "$H" --fingerprint "$fpr" ${1:+--allow-fingerprint-change} \
        || stop "could not keep $ETC/$MG_IDENTITY current (see above); the marker is written, the old record stands"
      ;;
    absent)
      if [ -n "$RECORD_FIRST" ] && [ "$TI_AUDIT_RC" = 0 ]; then
        ti_run write --mode first --home "$H" --fingerprint "$fpr" --expect-snapshot "$TI_SNAPSHOT" \
          || stop "the first trust-identity record was not written (see above); nothing else about the box depends on it yet"
      else
        say "  [info] no trust-identity record (D1): after reading the audit, run: sudo bash install.sh --record-trust-identity --expect-head <sha>"
      fi ;;
    *) stop "internal: unknown trust-identity state '$TI_STATE'" ;;
  esac
}

# identity_no_recreate -- step 1 `install -d`s these; with a valid record they must
# already exist (the pre-check proved it a moment ago; this closes the window).
identity_no_recreate() {
  local d
  [ "$TI_STATE" = valid ] || return 0
  for d in constitutional mcp_apps manifest_grants; do
    { [ -d "$H/$d" ] && [ ! -L "$H/$d" ]; } \
      || stop "$H/$d is a recorded trust directory and is gone: refusing to re-create it (Q-D1-6) -- an incident, not a setup step; nothing changed"
  done
}

# identity_check_report -- the --check lines; returns 1 on a FAIL.
identity_check_report() {
  local fpr out rc=0 mp
  say "== trust-identity record (D1)"
  fpr=$(mg_trust_env_fpr "$TRUST_ENV" 2>/dev/null || true)
  out=$(ti_run check --home "$H" --fingerprint "$fpr") || rc=$?
  printf '%s\n' "$out"
  case "$rc" in
    0) return 0 ;;
    4)
      mp=$(mg_marker_problems "$ETC/$MG_MARKER" "$H" "$TRUST_OWNER" "$MG_ROOT_USER" "$MG_ROOT_GROUP" 2>&1 || true)
      if [ -z "$mp" ] && [ -e "$ETC/$MG_MARKER" ]; then
        say "== read-only audit before the first record"
        identity_audit
        [ "$TI_AUDIT_RC" = 0 ] || return 1
      fi
      return 0 ;;
    *) return 1 ;;
  esac
}
# END trust-identity

# sign_and_publish_trust: the ONE code path for "change what is trusted" --
# Loki re-audit 93D0F057, N1: the plain install used to publish trust.env at
# step 1b and re-sign at step 6, many steps and several stop points later
# (the migration stop, a sync failure, the seed stop, postgres peer auth,
# the pending/ refusal) -- any one of them left trust switched with nothing
# re-signed. --rotate already had the safe order (sign+verify -> THEN
# publish -> THEN retire); this is that same sequence, extracted so BOTH the
# plain install and --rotate call it instead of maintaining two orderings
# that can drift apart. Also closes the other half of N1: the plain
# install's own step 6 never covered frank_head_anchor.json or the ratified
# seeds (only --rotate's governed_files() did) -- calling THIS function from
# the plain install covers them too, since governed_files() always has.
sign_and_publish_trust() {
  local new_fpr="$1"
  local old_fpr="$2"   # may be empty -- nothing to retire
  mapfile -t FILES < <(governed_files)
  say "  re-signing ${#FILES[@]} governed path(s) under $new_fpr (trust NOT switched yet)"
  if ! "$PY" -I -m willow_mcp.install_steps.rotate_resign --sign-as "$TRUST_OWNER" --gnupg-home "$GNUPGHOME_TO" \
       --fingerprint "$new_fpr" "${FILES[@]}"; then
    stop "re-signing failed -- rotate_resign.py already restored every file it touched this run to its previous signature, and $TRUST_ENV was not written, so the box is exactly as it was before this step started. Nothing to revert by hand; fix the failure above and retry."
  fi
  as_op "$PY" -I -m willow_mcp.install_steps.rotate_resign --check --fingerprint "$new_fpr" "${FILES[@]}" \
    || stop "post-sign verification found a file that does not verify under $new_fpr -- see the table above. $TRUST_ENV was not written; the box still trusts whatever it trusted before. Fix the mismatch and retry."
  say "  every governed file verifies under $new_fpr -- safe to switch trust now"

  TRUST_TMP=$(mktemp)
  printf 'WILLOW_PGP_FINGERPRINT=%s\n' "$new_fpr" > "$TRUST_TMP"
  install -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 644 "$TRUST_TMP" "$TRUST_ENV"
  rm -f "$TRUST_TMP"
  say "  wrote $new_fpr to $TRUST_ENV -- trust switched"

  if [ -n "$old_fpr" ] && [ "$old_fpr" != "$new_fpr" ]; then
    if as_to gpg --batch --yes --delete-secret-and-public-key "$old_fpr"; then
      say "  retired previous trust-owner key $old_fpr from $GNUPGHOME_TO"
      # (not `[ -f ... ] && rm`: with no marker that list ends the function with
      # status 1 and `set -e` killed --rotate here, before the trust marker, the
      # D1 record and the broker restart -- seen in the first root run of D1)
      rm -f -- "$STALE_KEY_MARKER"
    else
      # F-B (Loki audit 23DE8AA9): a bare warning here used to be the ONLY
      # record of this failure -- forgotten the instant the script exited,
      # and step 1b's OLD key-UID lookup would then find $old_fpr again on
      # the next plain install and silently revert this rotation. Persist
      # it as a named state retire_stale_key_if_marked() retries every run.
      printf '%s\n' "$old_fpr" > "$STALE_KEY_MARKER"
      say "  WARNING: could not retire $old_fpr from $GNUPGHOME_TO -- recorded at"
      say "  $STALE_KEY_MARKER; the next run retries it automatically, and \$TRUST_ENV"
      say "  still names $new_fpr regardless (step 1b will not revert to $old_fpr)."
      say "  Retire it by hand any time: as_to gpg --batch --yes --delete-secret-and-public-key $old_fpr"
    fi
  fi
}

# ---------------------------------------------------------- --check-signatures
# Item 5 (B291C0C7): one read that tells the desk whether a migration or
# rotation actually landed everywhere, rather than trusting the mutating
# step's own exit code. Read-only — touches nothing. Runs as the operator:
# the operator's own keyring is what step 1b/--rotate import the trust
# owner's PUBLIC key into, so a plain (no --homedir) gpg --verify as that
# uid is the same trust a real reader (paths.trusted_read, run by the
# broker) exercises.
#
# Loki re-audit 93D0F057, N4: this is supposed to be the FIRST step of a
# migration -- but trust.env does not exist on a box that has never been
# through this install, which is exactly the state a first-run check needs
# to work from. No longer stops when trust.env is absent: falls back to
# rotate_resign.py --check's report-only mode (no --fingerprint), which
# names who signed each file right now without needing anything to compare
# against.
if [ -n "$CHECK_SIGNATURES" ]; then
  say "== --check-signatures: which fingerprint does each governed file verify under"
  CUR_FPR=$(grep -E '^WILLOW_PGP_FINGERPRINT=' "$TRUST_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)
  mapfile -t FILES < <(governed_files)
  if [ -z "$CUR_FPR" ]; then
    say "  $TRUST_ENV not set (or does not exist yet) -- report-only mode: naming"
    say "  who signed each governed file right now, nothing to compare against."
    as_op "$PY" -I -m willow_mcp.install_steps.rotate_resign --check "${FILES[@]}"
    exit $?
  fi
  # Loki A38D41C2, F8: root can read BOTH $H/env (0600) and $TRUST_ENV
  # (0644) -- this is the one place that CAN catch the two copies drifting
  # apart, since neither the broker nor the trust-owner apply unit alone
  # can see both. A leftover WILLOW_PGP_FINGERPRINT= line in $H/env after
  # migration means either the migration in step 1b never ran on this box,
  # or something wrote it back -- surfaced here, not silently ignored.
  STALE_HOME_FPR=$(grep -E '^(export[[:space:]]+)?WILLOW_PGP_FINGERPRINT=' "$H/env" 2>/dev/null | tail -1 | sed -E 's/^(export[[:space:]]+)?WILLOW_PGP_FINGERPRINT=//' || true)
  if [ -n "$STALE_HOME_FPR" ]; then
    say "  WARNING: $H/env still names WILLOW_PGP_FINGERPRINT=$STALE_HOME_FPR -- the fingerprint's one source is now $TRUST_ENV ($CUR_FPR). A leftover value in \$H/env is inert to pgp.py (which no longer reads that file for this key) UNLESS something exports it into a process's own environment, in which case it competes with $TRUST_ENV and pgp.expected_fingerprint() refuses. Remove the line from $H/env (rerun a plain install to migrate it automatically) or confirm nothing sources it."
  fi
  as_op "$PY" -I -m willow_mcp.install_steps.rotate_resign --check --fingerprint "$CUR_FPR" "${FILES[@]}"
  exit $?
fi

# ------------------------------------------------ --re-record-trust-identity
# D1 (docs/design/d1-trust-dir-identity.md section 4.1, Q-D1-8): the ONLY way to
# accept a changed identity of $H, constitutional/, mcp_apps/ or manifest_grants/
# (a restore from backup, an rsync, a moved $H, filesystem repair, or a damaged
# record). Root, --expect-head and the env -i re-exec like every mode. It writes
# nothing until: (1) the old record (or its invalidity) is shown against the live
# tree, (2) the same read-only audit as the first record is all [ok] (a restored
# tree must verify under the trust fingerprint), and (3) the operator types the
# token of the exact record about to be written -- "rr-" and 12 hex of its digest,
# so it commits to the diff shown and changes with the inodes. On a terminal the
# token is typed at a /dev/tty prompt; without one the run prints it and exits 3,
# and `--confirm <token>` repeats the run (the token is recomputed from the live
# tree, so a tree that changed between the two runs does not match). Without a
# match: no write.
if [ -n "$RERECORD" ]; then
  say "== --re-record-trust-identity: accept the live trust-directory identity (D1)"
  RR_FPR=$(mg_trust_env_fpr "$TRUST_ENV") || stop "$TRUST_ENV carries no 40-hex fingerprint: not re-recording"
  p=$(mg_marker_problems "$ETC/$MG_MARKER" "$H" "$TRUST_OWNER" "$MG_ROOT_USER" "$MG_ROOT_GROUP" 2>&1 || true)
  { [ -z "$p" ] && [ -e "$ETC/$MG_MARKER" ]; } || stop "$ETC/$MG_MARKER is not valid, so no record can stand beside it; repair the marker first (a plain install): ${p%%$'\n'*}"
  say "== 1. the old record against the live tree"
  ti_run diff --home "$H" --fingerprint "$RR_FPR" || stop "cannot read the live trust directories (a recorded directory missing or a symlink?) -- restore the tree first; nothing written"
  say "== 2. read-only audit of the live box"
  identity_audit
  [ "$TI_AUDIT_RC" = 0 ] || stop "the audit above is not all [ok]: nothing written. Fix what it names, then rerun"
  say "== 3. confirm"
  RR_RC=0
  ti_run write --mode rerecord --home "$H" --fingerprint "$RR_FPR" ${RERECORD_CONFIRM:+--confirm "$RERECORD_CONFIRM"} || RR_RC=$?
  case "$RR_RC" in
    0) say "done. $ETC/$MG_IDENTITY re-recorded; sudo bash install.sh --check --expect-head <sha> should now report it valid and matching." ; exit 0 ;;
    3) say "nothing written: confirmation required (see the token above)"; exit 3 ;;
    *) stop "the trust-identity record was not written (see above)" ;;
  esac
fi

# -------------------------------------------------------------------- --rotate
# Dispatch B291C0C7 ("one signing key, one source of truth"), amending
# A9BF01A9. Operator ruling (verbatim): "I kinda wanna delete both these keys
# and just set one new one that applies correctly, instead of split brain."
# Order is the whole point — see the module docstring on rotate_resign.py for
# why re-signing is one atomic batch, not N independent gpg calls, and why the
# old key is retired ONLY after every file verifies under the new one.
if [ -n "$ROTATE" ]; then
  say "== --rotate: generate a new trust-owner signing key, re-sign everything, THEN switch trust, THEN retire"
  # D1: compare the live trust directories to the record BEFORE any re-sign (a
  # re-sign over a planted tree would launder it). Stops with the diff.
  identity_precheck

  # 1. a NEW key, always — the whole point of --rotate is a fresh key, never
  # reusing whatever the trust owner's GNUPGHOME already holds. The OLD key
  # is left in GNUPGHOME (never deleted) until every governed file verifies
  # under the new one, below.
  install -d -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 700 "$(dirname "$GNUPGHOME_TO")" "$GNUPGHOME_TO"
  retire_stale_key_if_marked
  ROTATE_UID="$KEY_UID $(date -u +%Y%m%dT%H%M%SZ)"
  as_to gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key "$ROTATE_UID" ed25519 sign never
  NEW_FPR=$(as_to gpg --batch --list-keys --with-colons "$ROTATE_UID" | awk -F: '/^fpr/{print $10; exit}')
  [ -n "$NEW_FPR" ] || stop "key generation appeared to succeed but no fingerprint was found for it"
  say "  generated $NEW_FPR"
  OLD_FPR=$(grep -E '^WILLOW_PGP_FINGERPRINT=' "$TRUST_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)
  say "  previous fingerprint (from $TRUST_ENV): ${OLD_FPR:-<none>}"

  # 2. the public half into the operator's keyring. This does NOT switch
  # trust by itself — pgp.expected_fingerprint() decides trust by reading
  # $TRUST_ENV, never by which keys happen to sit in a keyring — so importing
  # early, before anything is re-signed, is safe: the running broker still
  # trusts $OLD_FPR (from $TRUST_ENV, untouched so far) throughout steps 2-3.
  as_to gpg --batch --armor --export "$NEW_FPR" | sudo -u "$OPERATOR" gpg --batch --import
  echo "$NEW_FPR:6:" | sudo -u "$OPERATOR" gpg --batch --import-ownertrust
  say "  imported $NEW_FPR into $OPERATOR's keyring"

  # 3-5. re-sign+verify as one atomic batch, THEN switch trust, THEN retire
  # the old trust-owner key — the ONE shared sequence (Loki re-audit
  # 93D0F057, N1); see sign_and_publish_trust's own definition for why the
  # order is the whole point (F3: the old cut wrote trust before signing,
  # so a running broker's trust flipped to a key nothing was signed under
  # yet — "the register is signed by a key the broker does not trust", the
  # 2026-09-23 incident, verbatim).
  sign_and_publish_trust "$NEW_FPR" "$OLD_FPR"
  write_trust_marker
  write_trust_identity rotate

  for fpr in "${RETIRE_FPRS[@]}"; do
    if sudo -u "$OPERATOR" gpg --batch --yes --delete-key "$fpr"; then
      say "  retired $fpr from $OPERATOR's keyring"
    else
      say "  WARNING: could not retire $fpr from $OPERATOR's keyring — retire it by hand"
    fi
  done

  # 6. strip the serve unit's own pin and restart it — Loki A38D41C2, F5:
  # a standalone --rotate used to exit here without ever doing either, even
  # though the final message told the operator to restart. Shared functions
  # with the plain-install flow below (strip_pgp_pin/restart_broker) so the
  # two paths cannot drift apart again.
  strip_pgp_pin
  restart_broker

  say
  say "done. New fingerprint: $NEW_FPR."
  say "v1 PGP session-attestation sidecars signed under the old key are now invalid — see INSTALL.md."
  say "Any stdio-attached desk session still needs reconnecting by hand — see the restart_broker"
  say "note above if its project's .mcp.json pins a fingerprint."
  exit 0
fi

# ------------------------------------------------- 0. why is mcp_apps 65534?
say "== 0. mcp_apps ownership and mount"
stat -c '%U:%G %u %a %n' "$H" "$H/mcp_apps" "$H"/mcp_apps/*/manifest.json 2>/dev/null | head
FSTYPE=$(findmnt -nT "$H/mcp_apps" -o FSTYPE)
OPTS=$(findmnt -nT "$H/mcp_apps" -o OPTIONS)
say "mount: fstype=$FSTYPE options=$OPTS"
case "$FSTYPE" in
  fuse*|exfat|vfat|msdos|ntfs*|nfs*|cifs|smb*)
    stop "mcp_apps sits on $FSTYPE, which squashes ownership — chown will not stick. The pair needs a different home for mcp_apps (e.g. /var/lib/willow-mcp/mcp_apps with WILLOW_MCP_APPS_ROOT pointing at it). Nothing changed." ;;
esac
case "$OPTS" in *all_squash*|*idmapped*) stop "mcp_apps mount options ($OPTS) remap ownership — same stop as above." ;; esac
say "plain $FSTYPE — ownership will stick; continuing"
if [ "$CHECK_ONLY" = "--check" ]; then
  identity_check_report || CHECK_FAILED=1
  if [ -n "$CHECK_FAILED" ]; then
    say "check-only: stopping before any change -- a check above reported [FAIL] (an interpreter [FAIL]: --provision-venv rebuilds the venv; an installed unit/timer/env [FAIL]: a plain install replaces them from the committed HEAD)"
    exit 2
  fi
  say "check-only: stopping before any change"
  exit 0
fi

# ------------------------------------------- D1 pre-check, BEFORE anything changes
# Step 1 below runs `chown -R` over whatever sits at $H/mcp_apps and `install -d`
# over the other recorded paths. With a trust-identity record present that is
# only safe on the tree that was recorded: a planted directory (rename-away) would
# be laundered into trust-owner ownership. Compare first; a difference, an invalid
# record or a vanished recorded directory stops here with nothing changed. With no
# record: print the read-only audit (it must be clean, and --record-trust-identity
# given, for step 6 to write the first one).
say "== trust-identity pre-check (D1)"
identity_precheck
identity_gate_first

# --------------------------------------------------------- 1. ownership, ACLs
say "== 1. ownership and traversal"
identity_no_recreate
# Rework (Loki audit B00BD43E, F3, 2026-09-22): the traverse ACL on $H lets
# the trust owner open BY NAME anything world-readable beneath it, not just
# mcp_apps/manifest_grants/constitutional/ — nestor.db.ledger.jsonl (664),
# consent.json, settings.global.json, and the 755 trees handoffs/,
# dispatch/, deposits/, gitsync/, willow-bot/, upstream_steward/,
# worker_heartbeat/ are all reachable by name once $H itself is
# traversable. $H/env carries every provider key and is read by this unit
# only as root (EnvironmentFile=), never directly by uid 994 — but if its
# mode is not 600, the SAME traverse ACL that lets the trust owner reach
# mcp_apps/ would also let it open $H/env by name. Stop rather than assume
# (Loki: "the operator must stat it before rerunning the installer").
ENV_MODE=$(stat -c %a "$H/env")
[ "$ENV_MODE" = "600" ] || stop "$H/env is mode $ENV_MODE, not 600 — the traverse ACL below (F3, gap 035d287206e1) would let $TRUST_OWNER open it by name once granted. chmod 600 $H/env and rerun."
say "  $H/env is 600 — safe to grant traverse"
# F7 (Loki audit BFCC5C79), tightened (gap 035d287206e1, 2026-09-22): the
# trust owner must be able to TRAVERSE $H itself to reach mcp_apps/,
# manifest_grants/, constitutional/ below it. The prior fix here was
# conditional (`sudo -u $TRUST_OWNER test -x "$H" || chmod o+x "$H"`) and
# world-executable when it did fire -- measured on the box: after a real
# install, $H was STILL `710` (group execute-only, OTHER has no bits at
# all), so `test -x` must have passed via a group match rather than
# proving what a genuinely unrelated uid can do, and the conditional chmod
# never ran. An ACL is what the seal actually asked for (pair 1bd6fd29:
# "the operator's only keyboard act is the seal" -- not "and hope the
# trust owner's group membership lines up"): unconditional, idempotent,
# and grants EXACTLY the trust owner traverse-only, never "other" broadly
# the way `chmod o+x` does. nestor.db itself is NOT read by the apply half
# any more (Loki audit B00BD43E, F1: it is a WAL database a read-only
# opener under ProtectHome=read-only cannot open — the request half now
# embeds the sealed row's own bytes in the signed pending record instead;
# no ACL on nestor.db is granted here any more).
setfacl -m "u:$TRUST_OWNER:x" "$H"
say "  granted setfacl u:$TRUST_OWNER:x on $H (traverse only — contents stay as they were; see"
say "  INSTALL.md for the full list of what becomes name-reachable beneath it)"
chown -R "$TRUST_OWNER:$TRUST_OWNER" "$H/mcp_apps"
chmod -R u=rwX,g=rX,o=rX "$H/mcp_apps"
install -d -o "$OPERATOR" -g "$OPERATOR" -m 755 "$H/manifest_grants" "$H/manifest_grants/pending" "$H/manifest_grants/done" "$H/manifest_grants/failed"
setfacl -R -m "u:$TRUST_OWNER:rwx" -m "d:u:$TRUST_OWNER:rwx" "$H/manifest_grants"
# the request half's broker PUBLIC key — always this name (no glob); existing
# pending files were written 0600 by the broker (uid 1000)
[ -e "$H/manifest_grants/$BROKER_PUBLIC_KEY_NAME" ] && \
  setfacl -m "u:$TRUST_OWNER:r" "$H/manifest_grants/$BROKER_PUBLIC_KEY_NAME"
for req in "$H"/manifest_grants/pending/*.json; do
  [ -e "$req" ] && setfacl -m "u:$TRUST_OWNER:r" "$req"
done

# ---- F1/F2 (sealed 31f5d3af, rework 2 per Loki audit 54E3DFC0 R1/R2): the
# active envelope register's OWN DIRECTORY moves to trust-owner ownership,
# not just the file inside it — paths.trusted_read checks the PARENT
# directory first, and an operator-owned parent refuses the trust-owner
# unit before it reads a single byte (measured: R1). "owned by the trust
# owner ... the broker never writes either file" cannot hold while the
# broker owns the DIRECTORY the file lives in: os.replace by the directory
# owner rewrites the file and flips its ownership back, which is exactly
# what R2 measured. So: constitutional/ (dir AND file) -> trust owner,
# 0755/0644, no ACL; the broker's proposals sidecar moves OUT to a
# directory of its own ($H/proposals/, paths.envelope_proposals_path) that
# the broker actually owns end to end — never a file inside the trust
# owner's directory, which the broker could not create, rewrite, or
# unlink in the first place. Split FIRST, while constitutional/ is still
# operator-owned and this script (root) can write both destinations
# freely; chown constitutional/ itself only after the split lands.
install -d -o "$OPERATOR" -g "$OPERATOR" -m 755 "$H/proposals"
REG="$H/constitutional/pre-approved.json"
PROPOSALS="$H/proposals/proposals.json"
if [ -f "$REG" ]; then
  SPLIT_TMP=$(mktemp)
  "$PY" -I - "$REG" "$PROPOSALS" > "$SPLIT_TMP" <<'PYEOF'
import json, os, sys
reg_path, prop_path = sys.argv[1:3]
doc = json.load(open(reg_path))
proposals = doc.pop("proposals", [])
archived = doc.pop("archived", [])
doc.setdefault("active", [])
if os.path.exists(prop_path):
    existing = json.load(open(prop_path))
else:
    existing = {"proposals": [], "archived": []}
existing.setdefault("proposals", []).extend(proposals)
existing.setdefault("archived", []).extend(archived)
json.dump(existing, open(prop_path, "w"), indent=2, sort_keys=True)
json.dump(doc, open(reg_path, "w"), indent=2, sort_keys=True)
print(f"moved {len(proposals)} proposal(s), {len(archived)} archived row(s) to {prop_path}")
PYEOF
  cat "$SPLIT_TMP"
  rm -f "$SPLIT_TMP"
  chown "$OPERATOR:$OPERATOR" "$PROPOSALS"
  chmod 600 "$PROPOSALS"
else
  say "  no existing register at $REG — nothing to migrate; the trust-owner apply half creates one on first envelope.revoke or manifest.retire write"
fi
# Now the DIRECTORY itself, not just the file — R1's exact fix. Not -R:
# syscall-table.json is handled on its own two steps down (gap
# c1395b307421), synced from the checkout's bundle and chowned there —
# chowning the directory alone would not touch its CONTENT, which is the
# actual defect this step exists to fix. Nothing else under
# constitutional/ is touched by this chown; review_queue.json and
# frank_head_anchor.json (paths.trusted_read's file-level check is
# euid-based, unaffected by their parent's ownership — only the PARENT
# needs to resolve to euid-or-trust-owner, which chowning the directory
# alone already gives it) are deliberately left as they were.
install -d -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 755 "$H/constitutional"
chown "$TRUST_OWNER:$TRUST_OWNER" "$H/constitutional"
chmod 755 "$H/constitutional"
if [ -f "$REG" ]; then
  chown "$TRUST_OWNER:$TRUST_OWNER" "$REG"
  chmod 644 "$REG"
fi

# RENAME-AWAY, still open (Loki audit D06A0EF3), read-only report -- $H is
# broker-owned mode 700 (the broker's own working home), so the broker can
# rename constitutional/ away and recreate it empty; a rename needs write
# only on the PARENT. Rework #3 (dispatch FA4F79AC) tried closing this by
# routing TRUST_ENV through a separately-configured WILLOW_VAULT_BOX --
# reverted by rework #4 (dispatch 10F9E837, Loki audit 23DE8AA9, F-C): a
# location a broker's own process env can steer is a worse problem than
# the one it tried to solve. TRUST_ENV is back to a fixed
# $H/constitutional/trust.env, matching paths.trust_config_path() exactly
# (no env-var indirection on either side). Closing the rename-away hole
# for real needs $H ITSELF to resolve to a root-provisioned location for
# every process that shares this box -- a larger deploy/architecture
# change, out of this dispatch's scope; reported here, not silently
# assumed closed.
H_UID=$(stat -c %u "$H")
if [ "$H_UID" = "$OPERATOR_UID" ]; then
  if [ -f "$ETC/$MG_MARKER" ] && [ -z "$(mg_marker_problems "$ETC/$MG_MARKER" "$H" "$TRUST_OWNER" root root)" ]; then
    say "  NOTE: $H is owned by the broker (uid $OPERATOR_UID), but the root-owned marker"
    say "  $ETC/$MG_MARKER is valid: a rename-away of constitutional/ is now a fail-closed"
    say "  refusal, not 'enforcement off' (Loki D06A0EF3, D4). NOT closed: rollback to an"
    say "  older genuine trust-owner copy, renaming \$H or an ancestor, and the outage"
    say "  itself (next: D1, fd reads plus a root-owned (dev, ino) record) -- see INSTALL.md."
  else
    say "  NOTE: $H is owned by the broker (uid $OPERATOR_UID) and no valid"
    say "  $ETC/$MG_MARKER exists yet -- the rename-away fail-open (Loki D06A0EF3) is"
    say "  NOT closed until step 6 writes the marker. See INSTALL.md (D4)."
  fi
else
  say "  $H is not broker-owned -- the rename-away hole is closed"
fi
# federation.ratify (row 23) writes mcp_apps/_federation/servers.json —
# already under mcp_apps/, already trust-owner-owned by the recursive chown
# above; a _federation/ that does not exist yet is created on demand by the
# apply process itself (runs as $TRUST_OWNER), so it is born correctly
# owned, mode 0644, no ACL.

# ------------------------------------------- 1b. the trust owner's signing key
# Moved ahead of step 1c (dispatch A9BF01A9, amending BD5843FD): step 1c's
# atomic sync-and-sign needs $FPR to exist BEFORE it writes anything, so the
# key must be established first. This is the same step that used to run as
# "3.", unchanged in content, only in position.
say "== 1b. signing key owned by $TRUST_OWNER"
install -d -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 700 "$(dirname "$GNUPGHOME_TO")" "$GNUPGHOME_TO"
retire_stale_key_if_marked

# F-B (Loki audit 23DE8AA9): on a box that already HAS a $TRUST_ENV, that
# file already names the one fingerprint this box trusts -- prefer it
# explicitly over guessing by $KEY_UID substring, which returns the FIRST
# matching key GNUPGHOME_TO happens to hold. That lookup used to win even
# after a --rotate: the rotated key's UID is "$KEY_UID <timestamp>", so a
# plain install's substring search still found the OLDER key first,
# re-signed everything under it, republished it to $TRUST_ENV, and then
# deleted the NEWER key as "old_fpr" -- silently reverting a completed
# rotation. $TRUST_ENV is the one source of truth; every path that resolves
# a fingerprint on an already-provisioned box must agree with it.
TRUST_ENV_FPR=$(grep -E '^WILLOW_PGP_FINGERPRINT=' "$TRUST_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)
FPR=""
if [ -n "$TRUST_ENV_FPR" ] && as_to gpg --batch --list-secret-keys --with-colons "$TRUST_ENV_FPR" >/dev/null 2>&1; then
  FPR="$TRUST_ENV_FPR"
  say "  $TRUST_ENV already names $FPR, and its secret key is present -- using it (F-B)"
else
  FPR=$(as_to gpg --batch --list-keys --with-colons "$KEY_UID" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}' || true)
  if [ -z "$FPR" ]; then
    as_to gpg --batch --pinentry-mode loopback --passphrase '' \
      --quick-gen-key "$KEY_UID" ed25519 sign never
    FPR=$(as_to gpg --batch --list-keys --with-colons "$KEY_UID" | awk -F: '/^fpr/{print $10; exit}')
    say "generated $FPR"
  else
    say "key already present: $FPR"
  fi
fi
# public half into the broker's keyring, trusted ultimately (the gate verifies against it)
as_to gpg --batch --armor --export "$FPR" | sudo -u "$OPERATOR" gpg --batch --import
echo "$FPR:6:" | sudo -u "$OPERATOR" gpg --batch --import-ownertrust

# Dispatch 0CB0C85C: the fingerprint's one source is $TRUST_ENV
# (trust-owner-owned, world-readable — constitutional/ is already
# trust-owner-owned by step 1, above), never $H/env (0600, secrets).
#
# Loki re-audit 93D0F057, N1: $TRUST_ENV is NOT written here any more —
# doing so this early is the exact F3 pattern (trust switches before
# anything is re-signed under it). The key is only GENERATED/resolved
# here; sign_and_publish_trust (called after 1c/1d/2-5, once every
# governed file already verifies under $FPR) is what actually writes
# $TRUST_ENV, the one place trust switches, for both this plain-install
# path and --rotate.
OLD_TRUST_FPR=$(grep -E '^WILLOW_PGP_FINGERPRINT=' "$TRUST_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)

# Migration (0CB0C85C): leave nothing behind in $H/env — a second copy is
# the defect this whole PR removes. Fails closed rather than silently
# discarding: if $H/env still names a DIFFERENT fingerprint than the one
# about to be published, stop and ask the operator to reconcile by hand
# rather than guessing which is right.
OLD_HOME_FPR=$(grep -E '^(export[[:space:]]+)?WILLOW_PGP_FINGERPRINT=' "$H/env" 2>/dev/null | tail -1 | sed -E 's/^(export[[:space:]]+)?WILLOW_PGP_FINGERPRINT=//' || true)
if [ -n "$OLD_HOME_FPR" ] && [ "$OLD_HOME_FPR" != "$FPR" ]; then
  stop "$H/env still names WILLOW_PGP_FINGERPRINT=$OLD_HOME_FPR, disagreeing with the key about to be published ($FPR) — this is exactly the split brain this PR removes. Reconcile by hand (decide which is right, edit $H/env, then rerun) rather than letting install.sh silently discard one."
fi
if grep -qE '^(export[[:space:]]+)?WILLOW_PGP_FINGERPRINT=' "$H/env"; then
  sed -i -E '/^(export[[:space:]]+)?WILLOW_PGP_FINGERPRINT=/d' "$H/env"
  say "  removed WILLOW_PGP_FINGERPRINT from $H/env (now $TRUST_ENV only)"
fi

# ---- gap c1395b307421: sync + SIGN syscall-table.json, in the SAME ACT
# Amendment (dispatch A9BF01A9, amending BD5843FD): measured on the box —
# the prior shape here synced (this step) and signed (step 6, several steps
# and real wall-clock time later) as TWO acts. A pre-existing gpg bug in
# step 6 died in the window between them, leaving the box with a REPLACED
# but UNSIGNED syscall-table.json: paths.trusted_read correctly refused it
# outright ("trust-owner-owned but its detached signature does not
# verify"), and no verb could be proposed at all — locked harder than
# before the install ran. ANY interruption in that window — this bug or a
# different one — produces the same lock. Fixed by making sync_constitutional.
# py's --sign-as path do both in one process, one file write, immediately
# verified, with an automatic rollback to the exact previous bytes AND the
# exact previous .sig if signing or verification fails (sync_and_sign(),
# tested directly with fake sign/verify callables — the two-uid gpg
# boundary itself stays untested here, same limit this script's own
# chown/ACL steps have always had; see the PR body for which CI leg covers
# it). syscall-table.json is signed HERE, once — no longer re-signed in
# step 6's loop below.
say "== 1c. sync + sign constitutional policy files from the checkout bundle (one act)"
# The seed policy files come from the INSTALLED package (root-owned, built from
# the checkout's committed HEAD), never from the operator-writable checkout: the
# trust owner signs what this step copies.
WILLOW_PKG_DIR=$("$PY" -I -c 'import os, willow_mcp; print(os.path.dirname(willow_mcp.__file__))') \
  || stop "cannot locate the installed willow_mcp package under $PY"
BUNDLE_CONSTITUTIONAL="$WILLOW_PKG_DIR/bundle/constitutional"
"$PY" -I -m willow_mcp.install_steps.sync_constitutional "$BUNDLE_CONSTITUTIONAL" "$H/constitutional" \
  --sign-as "$TRUST_OWNER" --gnupg-home "$GNUPGHOME_TO" --fingerprint "$FPR" \
  || stop "constitutional bundle sync/sign failed — see the STOP line above; sync_and_sign() has already restored the box's constitutional/ to exactly what it was before this step ran"

# nestor.db (gap 035d287206e1, F1, rework per Loki audit B00BD43E): the
# apply half no longer reads this at all — it is a WAL database, and a
# read-only opener under this unit's ProtectHome=read-only cannot create
# the -shm sidecar a WAL reader needs (measured: every permission shape
# gives either "unable to open database file" or "attempt to write a
# readonly database", or silently hides rows still sitting in the WAL under
# immutable=1). The request half (broker, uid 1000, which CAN read
# nestor.db without any of these constraints) now embeds the sealed row's
# own verified bytes in the signed pending record instead; the apply half
# re-verifies the ed25519 signature over those embedded bytes. No ACL on
# nestor.db is granted here any more — the prior `setfacl u:$TRUST_OWNER:r
# nestor.db` line is gone.

# ---- gap 18affe49e198: seed the envelope.ratify bootstrap envelope
# Amendment (dispatch A9BF01A9): with row 24 now present (step 1c, just
# above), envelope_propose(verb='envelope.ratify') succeeds but
# envelope_ratify_request still refuses ENOENT — the request half needs an
# ACTIVE envelope governing envelope.ratify, and the only way to activate
# one is envelope.ratify. No principal but root, once, at install time, can
# break this (the broker can read its own proposals sidecar but cannot
# write the trust-owner register; the trust owner can write the register
# but cannot read the broker-owned 0600 sidecar — Loki 42B3B46F, U1).
# deploy/manifest-grant/seed_envelope_ratify.py calls
# envelope_authoring.ratify_proposal_row — the SAME function the real
# envelope.ratify apply half calls — rather than hand-building the active
# register row's shape a second time. Idempotent: an existing active grant
# for (envelope.ratify, willow) means this prints that and changes nothing;
# it disturbs no other active envelope. Runs as the trust owner (needs
# write access to the register) with $FPR so the register write is signed;
# see the module's own docstring for why its bounds are the unbounded
# {"proposal_ids": ["*"]} wildcard rather than a proposal-id-bounded shape.
say "== 1d. seed the envelope.ratify bootstrap envelope"
as_to WILLOW_HOME="$H" WILLOW_PGP_FINGERPRINT="$FPR" "$PY" -I -m willow_mcp.install_steps.seed_envelope_ratify \
  || stop "seeding the envelope.ratify bootstrap envelope failed — see the STOP line above; ratify_proposal_row() refuses before any write on every failure path, so the register is untouched"

# ---------------------------------------------------- 2. retire the --user unit
say "== 2. retire the --user unit"
as_op systemctl --user disable --now willow-mcp-manifest-grant.timer 2>/dev/null || true
as_op systemctl --user stop willow-mcp-manifest-grant.service 2>/dev/null || true
rm -f "/home/$OPERATOR/.config/systemd/user/willow-mcp-manifest-grant.service" \
      "/home/$OPERATOR/.config/systemd/user/willow-mcp-manifest-grant.timer"
as_op systemctl --user daemon-reload

# -------------------------------------------- 3. strip stale per-file pgp pins
# Dispatch B291C0C7 ("one signing key, one source of truth"): $TRUST_ENV is
# the only place WILLOW_PGP_FINGERPRINT is ever set now —
# pgp.expected_fingerprint() refuses at first use if the process environment
# disagrees with it, never silently prefers either. A systemd drop-in
# pinning it a SECOND place is exactly the split brain measured 2026-09-23.
# strip_pgp_pin is shared with --rotate above (Loki A38D41C2, F5) — see its
# definition for the F1 fix (the real drop-in shape) and the verify-after-
# strip discipline.
strip_pgp_pin

# ---------------------------------------------------------- 4. env file, units
say "== 4. $ETC and system units"
install -d -m 755 "$ETC"
# Dispatch 0CB0C85C: WILLOW_PGP_FINGERPRINT is no longer rendered into this
# file at all — the trust-owner apply unit now reads $TRUST_ENV directly
# (trust-owner-owned, world-readable; the SAME file everything else reads),
# so the second copy this file used to carry — the exact drift Loki audit
# A38D41C2's F8 measured, since uid willow-operator could never read $H/env
# to check it against the source — is gone, not merely re-synced.
# Rework 5: the template, the unit and the timer are read from the committed
# HEAD clone (the pre-reexec section's ensure_head_clone), rendered/validated there, installed from
# there, and then the files really in /etc are compared to that render.
MG_SRC="$HEAD_CLONE/$MG_DEPLOY_REL"
MG_STAGE="$TVC_BUILD/stage"
install -d -m 700 "$MG_STAGE"
mg_render_env "$MG_SRC/$MG_ENV" "$PG_DB" > "$MG_STAGE/$MG_ENV"
p=$(mg_env_problems "$MG_STAGE/$MG_ENV" "$TRUST_OWNER" "$ETC" "$PG_DB")
[ -z "$p" ] || stop "$MG_ENV rendered from the committed HEAD ${HEAD_SHA:0:12} carries more than the expected keys (is WILLOW_PG_DB in $H/env a single plain line?): $p"
install -o root -g "$TRUST_OWNER" -m 640 "$MG_STAGE/$MG_ENV" "$ETC/$MG_ENV"
install -o root -g root -m 644 "$MG_SRC/$MG_SERVICE" "$SYSD/$MG_SERVICE"
install -o root -g root -m 644 "$MG_SRC/$MG_TIMER"   "$SYSD/$MG_TIMER"
p=$(
  mg_installed_problems "$MG_SRC/$MG_SERVICE" "$SYSD/$MG_SERVICE" root root 644
  mg_installed_problems "$MG_SRC/$MG_TIMER" "$SYSD/$MG_TIMER" root root 644
  mg_installed_problems "$MG_STAGE/$MG_ENV" "$ETC/$MG_ENV" root "$TRUST_OWNER" 640
)
[ -z "$p" ] || stop "what is installed differs from the committed HEAD ${HEAD_SHA:0:12}: $p"
systemctl daemon-reload

# ------------------------------------------------------- 5. postgres role
say "== 5. postgres role for $TRUST_OWNER on $PG_DB"
sudo -u postgres psql -v ON_ERROR_STOP=1 -qc "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='$TRUST_OWNER') THEN CREATE ROLE \"$TRUST_OWNER\" LOGIN; END IF; END \$\$;"
sudo -u postgres psql -v ON_ERROR_STOP=1 -qd "$PG_DB" -c "GRANT CONNECT ON DATABASE \"$PG_DB\" TO \"$TRUST_OWNER\";" \
  -c "GRANT USAGE ON SCHEMA public TO \"$TRUST_OWNER\";" \
  -c "GRANT SELECT, INSERT ON frank_ledger TO \"$TRUST_OWNER\";"
sudo -u "$TRUST_OWNER" psql -d "$PG_DB" -qtc 'select 1' >/dev/null || stop "peer auth for $TRUST_OWNER on $PG_DB failed — check pg_hba.conf"

# --------------------------- 6. re-sign everything, THEN publish trust.env
# Loki re-audit 93D0F057, N1: this used to be N independent gpg calls (seat
# manifests, then the register and federation registry in a second loop),
# with $TRUST_ENV already written back in step 1b — so any stop between 1b
# and here (the 1c sync failure, the 1d seed stop, step 5's postgres peer
# auth) left trust already switched with nothing re-signed. It also never
# covered frank_head_anchor.json or the ratified seeds (only --rotate's
# governed_files() did). sign_and_publish_trust is the SAME atomic
# sign-verify-then-publish sequence --rotate uses (Loki A38D41C2 F3/F7):
# one code path for "change what is trusted", so this finding cannot recur
# by the two paths drifting apart again. $OLD_TRUST_FPR (captured in step
# 1b, before this ran) is almost always empty (first install) or equal to
# $FPR (an idempotent re-run reuses the existing GNUPGHOME key) — retiring
# only fires when they genuinely differ.
say "== 6. re-sign everything under $FPR, then publish $TRUST_ENV"
sign_and_publish_trust "$FPR" "$OLD_TRUST_FPR"
write_trust_marker
write_trust_identity

# ------------------ 6b. guard: no request minted before this install may apply
# Sealed 33654f35 (2026-09-22): d23a3726's pending request "is withdrawn, not
# applied". The general rule behind it: step 6 just re-signed every manifest,
# so every request already in pending/ carries a pre_state recorded under the
# OLD fingerprint and would refuse `edrift` on the first tick anyway — except
# where it would not: a seat named in an old request that still has a manifest
# on disk gets granted before the desk has said whether that seat still
# exists (jeles, ae23d366). Move every pre-existing request to failed/ with
# its own reason; the desk re-requests under the new fingerprint and the
# current seat set. The timer is not enabled while pending/ is non-empty.
#
# F7 (Loki audit BFCC5C79): this step runs BEFORE the broker restart below,
# not after — restarting first would let a freshly-restarted broker accept a
# brand-new request into pending/ in the window before this step runs, and
# the blanket withdrawal below cannot tell a new valid request from a stale
# one by content alone.
#
# The withdrawn record is written in the EXACT shape
# manifest_grant_executor._move(f, root/"failed", {**record, "result": out})
# produces — the original record's own fields spread at the TOP level, plus a
# "result" key — never a "request"-nested wrapper. manifest_grant_status just
# does `{"state": ..., **record}`; a differently-shaped record still reads as
# "failed" there, but every other reader (a future manifest_grant_retry, a
# human grepping failed/) expects the same flat shape every other failure in
# this queue already has, so this is not a special case.
say "== 6b. withdraw every request minted before this install"
for req in "$H"/manifest_grants/pending/*.json; do
  [ -e "$req" ] || continue
  pid=$(basename "$req" .json)
  "$PY" -I - "$req" "$H/manifest_grants/failed/$pid.json" "$FPR" <<'PYEOF'
import json, sys, datetime
src, dst, fpr = sys.argv[1:4]
rec = json.load(open(src))
result = {
    "ok": False,
    "error": "estale_presigned",
    "reason": (
        "withdrawn by install.sh: every manifest was re-signed under "
        f"{fpr} after this request recorded its pre_state; the seat set "
        "may also have changed (sealed 33654f35, ae23d366). Re-request "
        "under a current sealed pair."
    ),
    "withdrawn_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
out = {**rec, "result": result}
json.dump(out, open(dst, "w"), indent=2, sort_keys=True)
PYEOF
  rm -f "$req"
  chown "$TRUST_OWNER:$TRUST_OWNER" "$H/manifest_grants/failed/$pid.json"
  say "  withdrew $pid -> failed/ (estale_presigned)"
done
REMAINING=$(find "$H/manifest_grants/pending" -maxdepth 1 -name '*.json' | wc -l)
[ "$REMAINING" = 0 ] || stop "pending/ still holds $REMAINING request(s); refusing to enable the timer"

# ------------------------------- restart the broker: an env change, not a pull
# F7 (Loki audit BFCC5C79): restarts the --user SERVE unit only — see
# restart_broker's own definition (shared with --rotate, Loki A38D41C2 F5)
# for the stdio-desk caveat.
restart_broker

# --------------------------------------------------------- 7. start, first tick
say "== 7. enable and tick once"
systemctl enable --now willow-mcp-manifest-grant.timer
systemctl start willow-mcp-manifest-grant.service
journalctl -u willow-mcp-manifest-grant.service -n 40 --no-pager

say
say "done. Every request minted before this install now reads failed/estale_presigned"
say "(manifest_grant_status shows which). From the desk: manifest_grant_request (or one of"
say "envelope_revoke_request / manifest_retire_request / manifest_create_request /"
say "federation_ratify_request) under a current sealed pair — the next tick applies it."
