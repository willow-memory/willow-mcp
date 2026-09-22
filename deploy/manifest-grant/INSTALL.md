# manifest-grant as a system unit under the trust owner — install (operator act)

Sealed `1fdfbdf3` (2026-09-21): the system unit under the trust owner, its
preconditions. Sealed `1bd6fd29` (2026-09-22): "Setup is the installer's
(root, once, detects rather than asks). Operations are Willow's, executed by
the trust-owner apply half under a sealed pair. The operator's only keyboard
act is the seal." — the seven numbered steps this document used to walk
through one keyboard line at a time are no longer the operator's to type;
`install.sh` (beside this file) collapses them into one root act:

    sudo bash install.sh            # do it
    sudo bash install.sh --check    # detect-only, change nothing — stops
                                     # after step 0, before any mutation

This document is now the human-readable account of what `install.sh` does
and why, in the same order the script runs it — read it to know what the
root act is about to do, or to recover by hand if a step stops. Every `H`
below is the operator box:

    H=/home/sean-campbell/sean-data-vault/willow-operator-box

## Preflight

The script refuses to start unless: it is run as root; `$H` exists; the
`willow-operator` trust-owner user already exists (`trust_root_setup` has
run on this box); the three unit/env files sit beside `install.sh`;
`/etc/willow-mcp/verifiers.public.json` (the net-signer's public ring) is
already present; and `$H/env` names `WILLOW_PG_DB`.

## 0. Find out why mcp_apps reads uid 65534 — before touching ownership

    stat -c '%U:%G %u %a %n' $H $H/mcp_apps $H/mcp_apps/*/manifest.json | head
    findmnt -T $H/mcp_apps -o TARGET,SOURCE,FSTYPE,OPTIONS

If the mount squashes ownership (fuse, exfat/vfat, NFS with `all_squash`, a
user-namespace mount) `install.sh` stops rather than chown something that
will not stick — the pair needs a different home for `mcp_apps` (e.g.
`/var/lib/willow-mcp/mcp_apps` with `WILLOW_MCP_APPS_ROOT` pointing at it).
`--check` stops here, after this step, before anything below is touched.

## 1. Ownership and ACLs

    chown -R willow-operator:willow-operator $H/mcp_apps
    chmod -R u=rwX,g=rX,o=rX $H/mcp_apps          # broker (uid 1000) still reads manifests
    setfacl -R -m u:willow-operator:rwx -m d:u:willow-operator:rwx $H/manifest_grants
    setfacl -m u:willow-operator:r $H/manifest_grants/broker_public_key.pub   # always this name — no glob

The request half's broker PUBLIC key filename is not guessed: it is always
`broker_public_key.pub` (`manifest_grant_executor._broker_public_key_path`'s
own name). A pending request already on disk was written `0600` by uid
1000; the default ACL above does not reach an existing file, so `install.sh`
grants read on every file already in `pending/` too.

Since pair `1bd6fd29` the same queue drains four more verbs beyond
`manifest.grant` (`envelope.revoke`, `manifest.retire`, `manifest.create`,
`federation.ratify` — syscall-table rows 19-22), and one of them writes
OUTSIDE `mcp_apps/`:

    install -d -o $OPERATOR -g $OPERATOR -m 755 $H/constitutional
    setfacl -m u:willow-operator:rwx -m d:u:willow-operator:rwx $H/constitutional

`envelope.revoke` (row 19) writes `$H/constitutional/pre-approved.json`
directly — the chown/ACL on `mcp_apps` above never reaches it, so it gets
its own line. `federation.ratify` (row 22) writes
`mcp_apps/_federation/registry.json`, which IS already under `mcp_apps/` and
so is already covered; if `_federation/` does not exist yet at install time,
the apply process creates it on demand, running as `willow-operator`
already, so it is born correctly owned — no extra ACL line needed for it.

## 2. Retire the --user unit

    systemctl --user disable --now willow-mcp-manifest-grant.timer
    systemctl --user stop willow-mcp-manifest-grant.service
    rm ~/.config/systemd/user/willow-mcp-manifest-grant.{service,timer}
    systemctl --user daemon-reload

The `--user` unit this replaces failed every tick with `ewronguser`:
`mcp_apps` is not owned by the broker's uid, and a non-root `--user` manager
cannot switch identity — systemd's own manual is explicit about this. The
request/apply split was always an audit-trail boundary, never a privilege
one, on a box with no uid split; this system unit is the uid split actually
landing.

## 3. The signing key the service uid owns

    install -d -o willow-operator -g willow-operator -m 700 /var/lib/willow-mcp/manifest-grant/gnupg
    sudo -u willow-operator GNUPGHOME=/var/lib/willow-mcp/manifest-grant/gnupg \
      gpg --batch --pinentry-mode loopback --passphrase '' \
          --quick-gen-key 'willow-mcp manifest-grant (trust owner) <manifest-grant@willow-operator-box>' ed25519 sign never
    # -> FPR, exported into the broker's (operator's) keyring, trusted ultimately

`install.sh` reuses an existing key of this name if one is already there
(idempotent — re-running after a stop is the intended recovery), generates
one only if absent, and rewrites `WILLOW_PGP_FINGERPRINT` in the broker's
own `$H/env` to match.

## 4. Env file, units

    install -d -m 755 /etc/willow-mcp
    # manifest-grant.env, with WILLOW_PGP_FINGERPRINT and WILLOW_PG_DB filled in
    install -o root -g willow-operator -m 640 manifest-grant.env /etc/willow-mcp/manifest-grant.env
    install -o root -g root -m 644 willow-mcp-manifest-grant.{service,timer} /etc/systemd/system/
    systemctl daemon-reload

## 5. Postgres role for the apply half

    # a willow-operator role, peer-auth on the local socket, with the broker
    # role's read grants on the FRANK tables plus INSERT
    sudo -u willow-operator psql -d $WILLOW_PG_DB -c 'select 1'   # must succeed

## 6. Re-sign every seat manifest once under the new fingerprint

The pre-state check refuses a manifest whose current signature does not
verify under `WILLOW_PGP_FINGERPRINT`. `install.sh` signs every
`mcp_apps/*/manifest.json` under the fresh key as the trust owner, then
restarts the broker's own `--user` unit (tried as `willow-mcp-serve.service`
first, then the bare `willow-mcp.service` spelling — the package's own known
names, `reloader.DEFAULT_UNIT` / `unit_reload_executor._BROKER_UNIT_STEMS`,
no glob) — an env change, not a pull, so the reloader will not do this one.

## 6b. Withdraw every request minted before this install

Sealed `33654f35` (2026-09-22): a pending request that predates step 6 is
withdrawn, not applied. Step 6 just re-signed every manifest, so every
request already sitting in `pending/` carries a `pre_state` recorded under
the OLD fingerprint — and the seat set it names may itself be stale (the
Jeles seat retirement, `ae23d366`, is the concrete case this closes: an old
request naming a seat that still physically has a manifest on disk must
never be granted before the desk has said whether that seat still exists).

`install.sh` moves every file left in `pending/` to `failed/<pair_id>.json`
with `result.error = "estale_presigned"`, in the EXACT shape
`manifest_grant_executor._move` itself produces for every other failure —
the original record's fields spread at the top level, plus a `result` key,
never a `request`-nested wrapper — so `manifest_grant_status` (and every
other reader) sees it as an ordinary `failed` entry, no special-casing.
`estale_presigned` is on `manifest_grant_executor.TERMINAL_ERRORS`: not
retryable. The fix is a fresh request under a current sealed pair, never a
replay of `pre_state` that installing just made stale by definition. The
script refuses to enable the timer while `pending/` is still non-empty
after this step.

## 7. Start, and read the first tick

    systemctl enable --now willow-mcp-manifest-grant.timer
    systemctl start willow-mcp-manifest-grant.service   # one tick now, don't wait 60s
    journalctl -u willow-mcp-manifest-grant.service -n 40 --no-pager

Then from the desk: `manifest_grant_status(<pair_id>)` for whichever request
the desk re-submits under a current sealed pair (`manifest_grant_request`,
or one of `envelope_revoke_request` / `manifest_retire_request` /
`manifest_create_request` / `federation_ratify_request` — all five share
this one queue). Every request that predates this install now reads
`failed/estale_presigned`; `failed/` with a transient cause elsewhere in the
queue is `manifest_grant_retry`-able, `estale_presigned` is not.
