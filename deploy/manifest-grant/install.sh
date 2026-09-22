#!/usr/bin/env bash
# manifest-grant as a system unit under the trust owner — the installer.
#
# Sealed 1bd6fd29 (2026-09-22): "Setup is the installer's (root, once, detects
# rather than asks). Operations are Willow's, executed by the trust-owner apply
# half under a sealed pair. The operator's only keyboard act is the seal."
# Sealed 1fdfbdf3 (2026-09-21): the system unit under the trust owner, the
# preconditions INSTALL.md (beside this file) narrates in prose.
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
# Step 1 also gained ACL lines for the two more trust roots the four new
# verbs (envelope.revoke, manifest.retire, manifest.create, federation.ratify
# — rows 19-22, sealed 1bd6fd29) touch beyond mcp_apps/manifest_grants:
#   * envelope.revoke (row 19) writes $H/constitutional/pre-approved.json —
#     NOT under mcp_apps, so the mcp_apps chown/ACL below never reaches it;
#     given its own ACL lines.
#   * federation.ratify (row 22) writes mcp_apps/_federation/registry.json —
#     already under mcp_apps/, already covered by the recursive chown in
#     step 1; a directory that does not exist yet at install time is created
#     on demand by the apply process itself (running as the trust owner), so
#     it is born correctly owned. Noted, no extra ACL line needed.

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
BROKER_UNIT_CANDIDATES="willow-mcp-serve.service willow-mcp.service"  # reloader.DEFAULT_UNIT / unit_reload_executor._BROKER_UNIT_STEMS

say()  { printf '%s\n' "$*"; }
stop() { printf 'STOP: %s\n' "$*" >&2; exit 2; }
as_op() { sudo -u "$OPERATOR" XDG_RUNTIME_DIR=/run/user/$OPERATOR_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$OPERATOR_UID/bus "$@"; }
as_to() { sudo -u "$TRUST_OWNER" GNUPGHOME=$GNUPGHOME_TO "$@"; }

# ---------------------------------------------------------------- preflight
[ "$(id -u)" = 0 ] || stop "run as root (sudo bash install.sh)"
[ -d "$H" ] || stop "operator box not found at $H"
id "$TRUST_OWNER" >/dev/null 2>&1 || stop "user $TRUST_OWNER does not exist — trust_root_setup has not run on this box"
for f in manifest-grant.env willow-mcp-manifest-grant.service willow-mcp-manifest-grant.timer; do
  [ -f "$HERE/$f" ] || stop "missing $HERE/$f"
done
[ -f "$ETC/verifiers.public.json" ] || stop "$ETC/verifiers.public.json absent — the net-signer's public ring is a precondition (manifest-grant.env names it)"
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
say "== 1. ownership and ACLs"
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
# envelope.revoke (row 19, sealed 1bd6fd29) writes $H/constitutional/pre-approved.json —
# NOT under mcp_apps, so the chown/setfacl above never reaches it.
install -d -o "$OPERATOR" -g "$OPERATOR" -m 755 "$H/constitutional"
setfacl -m "u:$TRUST_OWNER:rwx" -m "d:u:$TRUST_OWNER:rwx" "$H/constitutional"
[ -e "$H/constitutional/pre-approved.json" ] && \
  setfacl -m "u:$TRUST_OWNER:rw" "$H/constitutional/pre-approved.json"
# federation.ratify (row 22) writes mcp_apps/_federation/registry.json — already
# under mcp_apps/, already covered above; a _federation/ that does not exist
# yet is created on demand by the apply process itself (runs as $TRUST_OWNER),
# so it is born correctly owned. No extra line needed here.

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
sed -E -e "s|^WILLOW_PGP_FINGERPRINT=.*|WILLOW_PGP_FINGERPRINT=$FPR|" \
       -e "s|^WILLOW_PG_DB=.*|WILLOW_PG_DB=$PG_DB|" "$HERE/manifest-grant.env" > /tmp/manifest-grant.env
install -o root -g "$TRUST_OWNER" -m 640 /tmp/manifest-grant.env "$ETC/manifest-grant.env"
rm -f /tmp/manifest-grant.env
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
  as_to gpg --batch --yes --detach-sign --armor --local-user "$FPR" -o "/tmp/$s.manifest.json.sig" "$a/manifest.json"
  install -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 644 "/tmp/$s.manifest.json.sig" "$a/manifest.json.sig"
  rm -f "/tmp/$s.manifest.json.sig"
  say "  signed $s"
done

# ------------------------------- restart the broker: an env change, not a pull
say "== broker restart (WILLOW_PGP_FINGERPRINT changed in $H/env)"
RESTARTED=""
for u in $BROKER_UNIT_CANDIDATES; do
  if as_op systemctl --user list-unit-files --no-legend "$u" 2>/dev/null | grep -q "^$u"; then
    as_op systemctl --user restart "$u" && say "  restarted $u" && RESTARTED=1
    break
  fi
done
[ -n "$RESTARTED" ] || say "  no known willow-mcp --user service found ($BROKER_UNIT_CANDIDATES) — restart the broker by hand if it runs another way"

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
# The withdrawn record is written in the EXACT shape
# manifest_grant_executor._move(f, root/"failed", {**record, "result": out})
# produces — the original record's own fields spread at the TOP level, plus a
# "result" key — never a "request"-nested wrapper. manifest_grant_status just
# does `{"state": ..., **record}`; a differently-shaped record still reads as
# "failed" there, but every other reader (a future manifest_grant_retry, a
# human grepping failed/) expects the same flat shape every other failure in
# this queue already has, so this is not a special case.
say "== 6b. withdraw every request minted before this install"
PY=$H/venvs/willow-mcp/bin/python
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
