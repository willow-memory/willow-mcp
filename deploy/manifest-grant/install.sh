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
#   sudo bash install.sh            # run from the directory holding the units
#   sudo bash install.sh --check    # detect-only, change nothing
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

set -euo pipefail

OPERATOR=${SUDO_USER:-sean-campbell}
OPERATOR_UID=$(id -u "$OPERATOR")
H=/home/$OPERATOR/sean-data-vault/willow-operator-box
TRUST_OWNER=willow-operator
GNUPGHOME_TO=/var/lib/willow-mcp/manifest-grant/gnupg
ETC=/etc/willow-mcp
# Dispatch 0CB0C85C (amending B291C0C7/E29CCFC7): a fingerprint is public --
# only a key's PRIVATE half is a secret. $H/env is 0600 (every provider API
# key); the trust-owner apply unit (uid willow-operator) cannot read it, so a
# second copy in /etc/willow-mcp/manifest-grant.env existed only so that unit
# could see the fingerprint -- and nothing ever checked the two copies still
# agreed (Loki A38D41C2, F8). TRUST_ENV lives beside the active register and
# syscall table (constitutional/ is already trust-owner-owned, 0755) --
# trust-owner-owned, 0644, WORLD-READABLE: every verifying process (broker,
# serve, desk, the trust-owner apply unit, this script) reads the SAME file,
# and only the trust owner (or root) can write it.
TRUST_ENV="$H/constitutional/trust.env"
KEY_UID='willow-mcp manifest-grant (trust owner) <manifest-grant@willow-operator-box>'
HERE=$(cd "$(dirname "$0")" && pwd)
CHECKOUT=$(cd "$HERE/../.." && pwd)   # deploy/manifest-grant/ -> checkout root
BROKER_PUBLIC_KEY_NAME=broker_public_key.pub   # manifest_grant_executor._broker_public_key_path
BROKER_UNIT_CANDIDATES=(willow-mcp-serve.service willow-mcp.service)  # reloader.DEFAULT_UNIT / unit_reload_executor._BROKER_UNIT_STEMS
PY="$H/venvs/willow-mcp/bin/python"

say()  { printf '%s\n' "$*"; }
stop() { printf 'STOP: %s\n' "$*" >&2; exit 2; }
as_op() { sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$OPERATOR_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$OPERATOR_UID/bus" "$@"; }
as_to() { sudo -u "$TRUST_OWNER" GNUPGHOME="$GNUPGHOME_TO" "$@"; }

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
RETIRE_FPRS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK_ONLY="--check"; shift ;;
    --check-signatures) CHECK_SIGNATURES=1; shift ;;
    --rotate) ROTATE=1; shift ;;
    --retire)
      [ $# -ge 2 ] || stop "--retire requires a fingerprint argument"
      RETIRE_FPRS+=("$2"); shift 2 ;;
    *) stop "unknown argument: $1 (known: --check, --check-signatures, --rotate, --retire FPR, --dry-run-sign)" ;;
  esac
done

# Loki audit A38D41C2, F6: a flag combination must mean what it says, or
# refuse rather than silently doing something else. `--retire` alone (no
# `--rotate`) used to be parsed and then ignored, falling through into the
# full mutating plain install; `--check --rotate` used to mutate anyway,
# because `--check`'s own gate only fired AFTER `--rotate` had already
# exited. Both are refused up front, before anything is touched.
if [ "${#RETIRE_FPRS[@]}" -gt 0 ] && [ -z "$ROTATE" ]; then
  stop "--retire only makes sense with --rotate (there is no key being replaced to retire the old one for). Did you mean: sudo bash install.sh --rotate --retire ${RETIRE_FPRS[0]}?"
fi
if [ -n "$CHECK_ONLY" ] && [ -n "$ROTATE" ]; then
  stop "--check and --rotate are mutually exclusive: --check inspects and changes nothing, --rotate mutates. Use --check-signatures first if you want a read-only pre-check, then --rotate."
fi

# ---------------------------------------------------------------- preflight
[ "$(id -u)" = 0 ] || stop "run as root (sudo bash install.sh)"
[ -d "$H" ] || stop "operator box not found at $H"
id "$TRUST_OWNER" >/dev/null 2>&1 || stop "user $TRUST_OWNER does not exist — trust_root_setup has not run on this box"
for f in manifest-grant.env willow-mcp-manifest-grant.service willow-mcp-manifest-grant.timer; do
  [ -f "$HERE/$f" ] || stop "missing $HERE/$f"
done
[ -f "$ETC/verifiers.public.json" ] || stop "$ETC/verifiers.public.json absent — the net-signer's public ring is a precondition (manifest-grant.env names it)"
[ -x "$PY" ] || stop "trust-owner python interpreter not found or not executable at $PY — venvs/willow-mcp must exist before this script does anything"
PG_DB=$(grep -E '^WILLOW_PG_DB=' "$H/env" | tail -1 | cut -d= -f2- || true)
[ -n "$PG_DB" ] || stop "WILLOW_PG_DB not set in $H/env"

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
    if "$PY" - "$s" <<'PYEOF'
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
  # Loki A38D41C2, F1 (BLOCKING): the real drop-in line is
  # Environment="WILLOW_PGP_FINGERPRINT=..." (systemd's Environment=
  # directive, optionally quoted) -- NOT a bare WILLOW_PGP_FINGERPRINT= at
  # line start. The old regex matched nothing on the real file, deleted
  # nothing, and printed "stripped" anyway. Both shapes are matched now,
  # and the strip is VERIFIED afterward -- a step that reports success it
  # did not achieve is worse than no step at all.
  sed -i -E \
    -e '/^WILLOW_PGP_FINGERPRINT=/d' \
    -e '/^Environment="?WILLOW_PGP_FINGERPRINT=/d' \
    "$dropin"
  if grep -qE '(^|=)"?WILLOW_PGP_FINGERPRINT=' "$dropin"; then
    stop "$dropin still names WILLOW_PGP_FINGERPRINT after the strip -- the regex did not match its actual shape. Not reporting success; fix strip_pgp_pin() in install.sh and rerun. Contents: $(cat "$dropin")"
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

# ---------------------------------------------------------- --check-signatures
# Item 5 (B291C0C7): one read that tells the desk whether the rotation
# actually landed everywhere, rather than trusting --rotate's own exit code.
# Read-only — touches nothing. Runs as the operator: the operator's own
# keyring is what step 1b/--rotate import the trust owner's PUBLIC key into,
# so a plain (no --homedir) gpg --verify as that uid is the same trust a real
# reader (paths.trusted_read, run by the broker) exercises.
if [ -n "$CHECK_SIGNATURES" ]; then
  say "== --check-signatures: which fingerprint does each governed file verify under"
  CUR_FPR=$(grep -E '^WILLOW_PGP_FINGERPRINT=' "$TRUST_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)
  [ -n "$CUR_FPR" ] || stop "WILLOW_PGP_FINGERPRINT not set in $TRUST_ENV — nothing to check against"
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
  mapfile -t FILES < <(governed_files)
  as_op "$PY" "$HERE/rotate_resign.py" --check --fingerprint "$CUR_FPR" "${FILES[@]}"
  exit $?
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

  # 1. a NEW key, always — the whole point of --rotate is a fresh key, never
  # reusing whatever the trust owner's GNUPGHOME already holds. The OLD key
  # is left in GNUPGHOME (never deleted) until every governed file verifies
  # under the new one, below.
  install -d -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 700 "$(dirname "$GNUPGHOME_TO")" "$GNUPGHOME_TO"
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

  # 3. re-sign and verify every governed file — one atomic batch
  # (rotate_resign.py: a failure on file N rolls back every file this run
  # already re-signed, not just N; Ctrl-C/SIGTERM mid-batch roll back too —
  # Loki A38D41C2, F7). $TRUST_ENV is NOT touched yet, so the running broker
  # still trusts $OLD_FPR while this runs. If this step fails or is
  # interrupted, $TRUST_ENV was never written, so there is NOTHING to revert
  # by hand — the box is exactly as it was before --rotate started, which is
  # the fix for F3 (the old cut wrote $TRUST_ENV/$H/env FIRST, so a running
  # broker's trust flipped to the new key before anything was signed under
  # it — "the register is signed by a key the broker does not trust", the
  # 2026-09-23 incident, verbatim).
  mapfile -t FILES < <(governed_files)
  say "  re-signing ${#FILES[@]} governed path(s) under $NEW_FPR (trust NOT switched yet)"
  if ! "$PY" "$HERE/rotate_resign.py" --sign-as "$TRUST_OWNER" --gnupg-home "$GNUPGHOME_TO" \
       --fingerprint "$NEW_FPR" "${FILES[@]}"; then
    stop "re-signing failed — rotate_resign.py already restored every file it touched this run to its previous signature, and \$TRUST_ENV was never written, so the box is exactly as it was before --rotate started. The old key ($OLD_FPR) was NOT retired. Nothing to revert by hand; fix the failure above and rerun --rotate."
  fi
  as_op "$PY" "$HERE/rotate_resign.py" --check --fingerprint "$NEW_FPR" "${FILES[@]}" \
    || stop "post-rotate verification found a file that does not verify under $NEW_FPR — see the table above. \$TRUST_ENV was never written, so the box still trusts $OLD_FPR and nothing is half-switched. The old key was NOT retired; fix the mismatch and rerun --rotate."
  say "  every governed file verifies under $NEW_FPR — safe to switch trust now"

  # 4. ONLY NOW — everything is already signed AND verified under the new
  # key — switch trust: write $TRUST_ENV. This is the narrowest possible
  # window where $TRUST_ENV's write could be interrupted mid-write; if it
  # is, the file becomes unreadable/malformed, which pgp.py now (F4) fails
  # CLOSED on rather than silently disabling enforcement — never a state
  # where the register is trusted-but-wrongly-signed, which is what F3
  # measured.
  TRUST_TMP=$(mktemp)
  printf 'WILLOW_PGP_FINGERPRINT=%s\n' "$NEW_FPR" > "$TRUST_TMP"
  install -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 644 "$TRUST_TMP" "$TRUST_ENV"
  rm -f "$TRUST_TMP"
  say "  wrote $NEW_FPR to $TRUST_ENV — trust switched"

  # 5. only now — trust has switched and every file already verifies —
  # retire the old keys.
  if [ -n "$OLD_FPR" ] && [ "$OLD_FPR" != "$NEW_FPR" ]; then
    if as_to gpg --batch --yes --delete-secret-and-public-key "$OLD_FPR"; then
      say "  retired previous trust-owner key $OLD_FPR from $GNUPGHOME_TO"
    else
      say "  WARNING: could not retire $OLD_FPR from $GNUPGHOME_TO — retire it by hand (as_to gpg --batch --yes --delete-secret-and-public-key $OLD_FPR)"
    fi
  fi
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
[ "$CHECK_ONLY" = "--check" ] && { say "check-only: stopping before any change"; exit 0; }

# --------------------------------------------------------- 1. ownership, ACLs
say "== 1. ownership and traversal"
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
  "$PY" - "$REG" "$PROPOSALS" > "$SPLIT_TMP" <<'PYEOF'
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
FPR=$(as_to gpg --batch --list-keys --with-colons "$KEY_UID" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}' || true)
if [ -z "$FPR" ]; then
  as_to gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key "$KEY_UID" ed25519 sign never
  FPR=$(as_to gpg --batch --list-keys --with-colons "$KEY_UID" | awk -F: '/^fpr/{print $10; exit}')
  say "generated $FPR"
else
  say "key already present: $FPR"
fi
# public half into the broker's keyring, trusted ultimately (the gate verifies against it)
as_to gpg --batch --armor --export "$FPR" | sudo -u "$OPERATOR" gpg --batch --import
echo "$FPR:6:" | sudo -u "$OPERATOR" gpg --batch --import-ownertrust

# Dispatch 0CB0C85C: the fingerprint's one source is $TRUST_ENV
# (trust-owner-owned, world-readable — constitutional/ is already
# trust-owner-owned by step 1, above), never $H/env (0600, secrets). Written
# by root, then chowned to the trust owner — same shape as the register.
TRUST_TMP=$(mktemp)
printf 'WILLOW_PGP_FINGERPRINT=%s\n' "$FPR" > "$TRUST_TMP"
install -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 644 "$TRUST_TMP" "$TRUST_ENV"
rm -f "$TRUST_TMP"
say "  published $FPR to $TRUST_ENV"

# Migration (0CB0C85C): leave nothing behind in $H/env — a second copy is
# the defect this whole PR removes. Fails closed rather than silently
# discarding: if $H/env still names a DIFFERENT fingerprint, stop and ask
# the operator to reconcile by hand rather than guessing which is right.
OLD_HOME_FPR=$(grep -E '^(export[[:space:]]+)?WILLOW_PGP_FINGERPRINT=' "$H/env" 2>/dev/null | tail -1 | sed -E 's/^(export[[:space:]]+)?WILLOW_PGP_FINGERPRINT=//' || true)
if [ -n "$OLD_HOME_FPR" ] && [ "$OLD_HOME_FPR" != "$FPR" ]; then
  stop "$H/env still names WILLOW_PGP_FINGERPRINT=$OLD_HOME_FPR, disagreeing with $TRUST_ENV's $FPR — this is exactly the split brain this PR removes. Reconcile by hand (decide which is right, edit $H/env, then rerun) rather than letting install.sh silently discard one."
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
BUNDLE_CONSTITUTIONAL="$CHECKOUT/src/willow_mcp/bundle/constitutional"
"$PY" "$HERE/sync_constitutional.py" "$BUNDLE_CONSTITUTIONAL" "$H/constitutional" \
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
as_to WILLOW_HOME="$H" WILLOW_PGP_FINGERPRINT="$FPR" "$PY" "$HERE/seed_envelope_ratify.py" \
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
ENV_TMP=$(mktemp)
# Dispatch 0CB0C85C: WILLOW_PGP_FINGERPRINT is no longer rendered into this
# file at all — the trust-owner apply unit now reads $TRUST_ENV directly
# (trust-owner-owned, world-readable; the SAME file everything else reads),
# so the second copy this file used to carry — the exact drift Loki audit
# A38D41C2's F8 measured, since uid willow-operator could never read $H/env
# to check it against the source — is gone, not merely re-synced.
sed -E -e '/^WILLOW_PGP_FINGERPRINT=/d' \
       -e "s|^WILLOW_PG_DB=.*|WILLOW_PG_DB=$PG_DB|" "$HERE/manifest-grant.env" > "$ENV_TMP"
install -o root -g "$TRUST_OWNER" -m 640 "$ENV_TMP" "$ETC/manifest-grant.env"
rm -f "$ENV_TMP"
install -o root -g root -m 644 "$HERE/willow-mcp-manifest-grant.service" /etc/systemd/system/
install -o root -g root -m 644 "$HERE/willow-mcp-manifest-grant.timer"   /etc/systemd/system/
systemctl daemon-reload

# ------------------------------------------------------- 5. postgres role
say "== 5. postgres role for $TRUST_OWNER on $PG_DB"
sudo -u postgres psql -v ON_ERROR_STOP=1 -qc "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='$TRUST_OWNER') THEN CREATE ROLE \"$TRUST_OWNER\" LOGIN; END IF; END \$\$;"
sudo -u postgres psql -v ON_ERROR_STOP=1 -qd "$PG_DB" -c "GRANT CONNECT ON DATABASE \"$PG_DB\" TO \"$TRUST_OWNER\";" \
  -c "GRANT USAGE ON SCHEMA public TO \"$TRUST_OWNER\";" \
  -c "GRANT SELECT, INSERT ON frank_ledger TO \"$TRUST_OWNER\";"
sudo -u "$TRUST_OWNER" psql -d "$PG_DB" -qtc 'select 1' >/dev/null || stop "peer auth for $TRUST_OWNER on $PG_DB failed — check pg_hba.conf"

# --------------------------- 6. re-sign every seat manifest under the new key
# Fix (2026-09-22, first real two-uid install; 338bbdb): `SIG_TMP=$(mktemp)`
# here runs as ROOT (this whole script), producing a 0600 root-owned file —
# but `as_to` runs gpg as the trust owner (uid 994), which cannot open a
# root-owned file for writing even via `-o`. The fake-interpreter test that
# exercised this control flow ran everything as one uid and could not see
# it; the operator's first live run did (`gpg: can't create
# '/tmp/tmp.xxx': Permission denied`). Fixed by never handing gpg a path to
# open at all: `--output -` writes the signature to gpg's own stdout, and
# `> "$SIG_TMP"` is THIS shell's (root's) redirection, evaluated and opened
# before `as_to`'s `sudo -u <trust owner>` ever runs — the fd is already
# open and root-owned by the time gpg (as the trust owner) inherits and
# writes to it, so the child uid's permissions on the PATH never matter. No
# temp file is ever owned by the trust-owner uid, on success or on failure.
say "== 6. re-sign every manifest under $FPR"
for a in "$H"/mcp_apps/*/; do
  [ -f "$a/manifest.json" ] || continue
  s=$(basename "$a")
  SIG_TMP=$(mktemp)
  as_to gpg --batch --yes --detach-sign --armor --local-user "$FPR" --output - "$a/manifest.json" > "$SIG_TMP"
  install -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 644 "$SIG_TMP" "$a/manifest.json.sig"
  rm -f "$SIG_TMP"
  say "  signed $s"
done
# F3 + F1/F2: the active register and the federation registry carry the same
# trust-owner-owned, detached-signed shape as a seat manifest now — re-sign
# them here too, or every reader (paths.trusted_read's new signature branch;
# mcp_federation._read_registry_file) refuses them as unsigned/stale the
# moment the fingerprint changes. Missing the federation registry here was
# exactly Loki's F3: the first post-install federation.ratify would otherwise
# read "no ratified servers" and silently drop every existing entry.
# gap c1395b307421 / dispatch A9BF01A9: syscall-table.json does NOT join
# this loop — it is synced AND signed atomically back in step 1c
# (sync_and_sign(), before $FPR even needed to exist yet at the OLD step 3's
# position). Re-signing it again here would be redundant on every run and,
# worse, re-introduces exactly the two-acts-not-one shape this PR exists to
# close if this loop ever runs on its own between 1c and a failure.
for f in "$REG" "$H/mcp_apps/_federation/servers.json"; do
  [ -f "$f" ] || continue
  SIG_TMP=$(mktemp)
  as_to gpg --batch --yes --detach-sign --armor --local-user "$FPR" --output - "$f" > "$SIG_TMP"
  install -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 644 "$SIG_TMP" "$f.sig"
  rm -f "$SIG_TMP"
  say "  signed $(basename "$f")"
done

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
  "$PY" - "$req" "$H/manifest_grants/failed/$pid.json" "$FPR" <<'PYEOF'
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
