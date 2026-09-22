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
# recovery. Nothing here reads the broker's env file except the two values
# the unit needs (WILLOW_PG_DB) and the fingerprint it writes back.
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

set -euo pipefail

OPERATOR=${SUDO_USER:-sean-campbell}
OPERATOR_UID=$(id -u "$OPERATOR")
H=/home/$OPERATOR/sean-data-vault/willow-operator-box
TRUST_OWNER=willow-operator
GNUPGHOME_TO=/var/lib/willow-mcp/manifest-grant/gnupg
ETC=/etc/willow-mcp
KEY_UID='willow-mcp manifest-grant (trust owner) <manifest-grant@willow-operator-box>'
HERE=$(cd "$(dirname "$0")" && pwd)
CHECK_ONLY=${1:-}
BROKER_PUBLIC_KEY_NAME=broker_public_key.pub   # manifest_grant_executor._broker_public_key_path
BROKER_UNIT_CANDIDATES=(willow-mcp-serve.service willow-mcp.service)  # reloader.DEFAULT_UNIT / unit_reload_executor._BROKER_UNIT_STEMS
PY="$H/venvs/willow-mcp/bin/python"

say()  { printf '%s\n' "$*"; }
stop() { printf 'STOP: %s\n' "$*" >&2; exit 2; }
as_op() { sudo -u "$OPERATOR" XDG_RUNTIME_DIR="/run/user/$OPERATOR_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$OPERATOR_UID/bus" "$@"; }
as_to() { sudo -u "$TRUST_OWNER" GNUPGHOME="$GNUPGHOME_TO" "$@"; }

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
# F7 (Loki audit BFCC5C79), tightened (gap 035d287206e1, 2026-09-22): the
# trust owner must be able to TRAVERSE $H itself to reach mcp_apps/,
# manifest_grants/, constitutional/, and nestor.db below it. The prior fix
# here was conditional (`sudo -u $TRUST_OWNER test -x "$H" || chmod o+x
# "$H"`) and world-executable when it did fire -- measured on the box:
# after a real install, $H was STILL `710` (group execute-only, OTHER has
# no bits at all), so `test -x` must have passed via a group match rather
# than proving what a genuinely unrelated uid can do, and the conditional
# chmod never ran. An ACL is what the seal actually asked for (pair
# 1bd6fd29: "the operator's only keyboard act is the seal" -- not "and
# hope the trust owner's group membership lines up"): unconditional,
# idempotent, and grants EXACTLY the trust owner traverse-only, never
# "other" broadly the way `chmod o+x` does.
setfacl -m "u:$TRUST_OWNER:x" "$H"
say "  granted setfacl u:$TRUST_OWNER:x on $H (traverse only — contents stay as they were)"
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
# Now the DIRECTORY itself, not just the file — R1's exact fix. Not -R: a
# syscall-table.json living alongside the register can stay BROKER-owned
# (paths.trusted_read's file-level check is euid-based, unaffected by its
# parent's ownership — only the PARENT needs to resolve to euid-or-trust-
# owner, which chowning the directory alone already gives it) and is
# deliberately left untouched here.
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

# nestor.db (gap 035d287206e1): the apply half reads this directly and by
# name — seal_handler._nestor_db_path() resolves WILLOW_NESTOR_DB, which
# the unit's own Environment= sets to $H/nestor.db — to RE-verify a sealed
# pair's actual bytes fresh at apply time (manifest_grant_executor's own
# rule: nothing already checked at request time is trusted twice). This
# file stays OPERATOR-owned (it is Nestor's own ledger, not this queue's to
# take over) — an ACL grants read, never write; the apply half never writes
# nestor.db.
if [ -f "$H/nestor.db" ]; then
  setfacl -m "u:$TRUST_OWNER:r" "$H/nestor.db"
  say "  granted setfacl u:$TRUST_OWNER:r on $H/nestor.db (read-only)"
fi

# ---------------------------------------------------- 2. retire the --user unit
say "== 2. retire the --user unit"
as_op systemctl --user disable --now willow-mcp-manifest-grant.timer 2>/dev/null || true
as_op systemctl --user stop willow-mcp-manifest-grant.service 2>/dev/null || true
rm -f "/home/$OPERATOR/.config/systemd/user/willow-mcp-manifest-grant.service" \
      "/home/$OPERATOR/.config/systemd/user/willow-mcp-manifest-grant.timer"
as_op systemctl --user daemon-reload

# ------------------------------------------- 3. the trust owner's signing key
say "== 3. signing key owned by $TRUST_OWNER"
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
# the broker's env must name the SAME fingerprint
if grep -qE '^WILLOW_PGP_FINGERPRINT=' "$H/env"; then
  sed -i -E "s|^WILLOW_PGP_FINGERPRINT=.*|WILLOW_PGP_FINGERPRINT=$FPR|" "$H/env"
else
  printf 'WILLOW_PGP_FINGERPRINT=%s\n' "$FPR" >> "$H/env"
fi

# ---------------------------------------------------------- 4. env file, units
say "== 4. $ETC and system units"
install -d -m 755 "$ETC"
ENV_TMP=$(mktemp)
sed -E -e "s|^WILLOW_PGP_FINGERPRINT=.*|WILLOW_PGP_FINGERPRINT=$FPR|" \
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
say "== 6. re-sign every manifest under $FPR"
for a in "$H"/mcp_apps/*/; do
  [ -f "$a/manifest.json" ] || continue
  s=$(basename "$a")
  SIG_TMP=$(mktemp)
  as_to gpg --batch --yes --detach-sign --armor --local-user "$FPR" -o "$SIG_TMP" "$a/manifest.json"
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
for f in "$REG" "$H/mcp_apps/_federation/servers.json"; do
  [ -f "$f" ] || continue
  SIG_TMP=$(mktemp)
  as_to gpg --batch --yes --detach-sign --armor --local-user "$FPR" -o "$SIG_TMP" "$f"
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
# F7: this restarts the --user SERVE unit only. A stdio-attached desk (a
# per-session subprocess the desk's own MCP client spawned — Claude Code,
# Cursor, any editor session) is NOT a systemd unit this script can reach at
# all; it keeps running with the OLD WILLOW_PGP_FINGERPRINT in its own
# process environment until the operator reconnects that session by hand.
# Said here rather than implied by this step's success.
say "== broker restart (WILLOW_PGP_FINGERPRINT changed in $H/env)"
RESTARTED=""
for u in "${BROKER_UNIT_CANDIDATES[@]}"; do
  if as_op systemctl --user list-unit-files --no-legend "$u" 2>/dev/null | grep -q "^$u"; then
    as_op systemctl --user restart "$u" && say "  restarted $u" && RESTARTED=1
    break
  fi
done
[ -n "$RESTARTED" ] || say "  no known willow-mcp --user service found (${BROKER_UNIT_CANDIDATES[*]}) — restart the broker by hand if it runs another way"
say "  NOTE: a stdio-attached desk (an editor/CLI session, not the --user unit)"
say "  cannot be restarted by this script — it must reconnect (restart the"
say "  session) by hand to pick up the new WILLOW_PGP_FINGERPRINT."

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
