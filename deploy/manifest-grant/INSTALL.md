# manifest-grant as a system unit under the trust owner — install (operator act)

Sealed `1fdfbdf3` (2026-09-21): the system unit under the trust owner, its
preconditions. Sealed `1bd6fd29` (2026-09-22): "Setup is the installer's
(root, once, detects rather than asks). Operations are Willow's, executed by
the trust-owner apply half under a sealed pair. The operator's only keyboard
act is the seal." Sealed `31f5d3af` (2026-09-22): the active envelope
register and the federation registry move to the same trust-owner-owned,
detach-signed shape a seat manifest already has — the seven numbered steps
this document used to walk through one keyboard line at a time are no longer
the operator's to type; `install.sh` (beside this file) collapses them into
one root act:

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
already present; **the trust owner's own python interpreter exists and is
executable at `$H/venvs/willow-mcp/bin/python`** (Loki audit BFCC5C79, F7 —
this is used from step 1 on, not just the withdrawal step, so a missing
interpreter now stops before anything is touched rather than partway
through); and `$H/env` names `WILLOW_PG_DB`.

## 0. Find out why mcp_apps reads uid 65534 — before touching ownership

    stat -c '%U:%G %u %a %n' $H $H/mcp_apps $H/mcp_apps/*/manifest.json | head
    findmnt -T $H/mcp_apps -o TARGET,SOURCE,FSTYPE,OPTIONS

If the mount squashes ownership (fuse, exfat/vfat, NFS with `all_squash`, a
user-namespace mount) `install.sh` stops rather than chown something that
will not stick — the pair needs a different home for `mcp_apps` (e.g.
`/var/lib/willow-mcp/mcp_apps` with `WILLOW_MCP_APPS_ROOT` pointing at it).
`--check` stops here, after this step, before anything below is touched.

## 1. Ownership, traversal, and the envelope-register migration

    # F7: o+x on $H itself is traversal-only — it does not expose $H's own
    # listing or contents, only lets a non-owner pass through to what is
    # below it (mcp_apps/, manifest_grants/, constitutional/).
    sudo -u willow-operator test -x $H || chmod o+x $H

    chown -R willow-operator:willow-operator $H/mcp_apps
    chmod -R u=rwX,g=rX,o=rX $H/mcp_apps          # broker (uid 1000) still reads manifests
    setfacl -R -m u:willow-operator:rwx -m d:u:willow-operator:rwx $H/manifest_grants
    setfacl -m u:willow-operator:r $H/manifest_grants/broker_public_key.pub   # always this name — no glob

The request half's broker PUBLIC key filename is not guessed: it is always
`broker_public_key.pub` (`manifest_grant_executor._broker_public_key_path`'s
own name). A pending request already on disk was written `0600` by uid
1000; the default ACL above does not reach an existing file, so `install.sh`
grants read on every file already in `pending/` too.

**Sealed `31f5d3af`, unblocked by the desk after Loki audits BFCC5C79/
54E3DFC0's F1/F2/R1/R2: the active envelope register's DIRECTORY (not just
the file) moves to trust-owner ownership — `0755`/`0644`, NO ACLs,
detach-signed — the same trust shape a seat manifest already has**
(`paths.trusted_read` gained a trust-owner-plus-signature branch: a file not
owned by this process's own euid is trusted when it is owned by the trust
owner, carries no group/other write bit, and its own `<file>.sig` verifies
under `WILLOW_PGP_FINGERPRINT`). Rework 1 chowned only the FILE and left
`constitutional/` itself operator-owned — `trusted_read` checks the PARENT
directory first, so the trust-owner unit was refused before it read a byte
(R1), and because the broker still owned the directory its own writes could
still `os.replace` over the "trust-owner-owned" file and flip it back (R2).
Fixed: the directory chowns too, and the broker's proposals sidecar moves
OUT of `constitutional/` entirely — a broker-owned FILE inside a
trust-owner-owned DIRECTORY is one the broker could never create, rewrite,
or unlink at all, so the sidecar needs a directory of its own:

    REG=$H/constitutional/pre-approved.json
    PROPOSALS=$H/proposals/proposals.json
    # (install.sh runs this split as root via the trust owner's own python,
    # BEFORE constitutional/ is chowned, then:)
    chown $OPERATOR:$OPERATOR $PROPOSALS && chmod 600 $PROPOSALS
    chown willow-operator:willow-operator $H/constitutional && chmod 755 $H/constitutional
    chown willow-operator:willow-operator $REG && chmod 644 $REG

`envelope_authoring.propose()`/`reject()` write ONLY `$H/proposals/
proposals.json` now — never the register, at all, ever, regardless of which
uid calls them. `ratify()` is the one broker-side act the sealed text names
as touching the register; it writes both files and signs the register under
`WILLOW_PGP_FINGERPRINT` via `--local-user` (never gpg's ambient default
key — the other defect R2 measured). `syscall-table.json`, if it lives
alongside the register, is deliberately left broker-owned: `trusted_read`'s
file-level check is euid-based and does not care who owns the PARENT, so a
broker-owned file in a trust-owner-owned directory still reads fine for the
broker; only the register file itself needs to be trust-owner-owned and
signed.

`federation.ratify` (row 23) writes `mcp_apps/_federation/servers.json` —
already under `mcp_apps/`, already trust-owner-owned by the recursive chown
above; a `_federation/` that does not exist yet is created on demand by the
apply process itself (runs as `willow-operator` already), so it is born
correctly owned, mode `0644`, no ACL — nothing extra to do for it here.

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

## 6. Re-sign every seat manifest, the register, and the federation registry

The pre-state check refuses a manifest whose current signature does not
verify under `WILLOW_PGP_FINGERPRINT`; after pair `31f5d3af`,
`paths.trusted_read`'s trust-owner branch does the exact same refusal for the
envelope register, and `mcp_federation._read_registry_file` does it for the
federation registry. `install.sh` signs every `mcp_apps/*/manifest.json`
under the fresh key as the trust owner, **and now also
`constitutional/pre-approved.json` and `mcp_apps/_federation/servers.json`**
— Loki audit BFCC5C79's F3: missing the federation registry here meant the
first `federation.ratify` after any fingerprint change would read "no
ratified servers" (`mcp_federation.ratify()` starts its merge from `{}` when
the existing registry's signature does not verify, and does not check the
flag that says so) and silently drop every other entry.
`trust_owner_verbs._apply_federation_ratify` also gained a defensive check
refusing `EACCES` before ever reaching `mcp_federation.ratify()` if the
registry does not verify, as a backstop for every other way its signature
could go stale — but this step is the real fix.

## 6b. Withdraw every request minted before this install

Sealed `33654f35` (2026-09-22): a pending request that predates step 6 is
withdrawn, not applied. Step 6 just re-signed every manifest (and now the
register and federation registry), so every request already sitting in
`pending/` carries a `pre_state` recorded under the OLD fingerprint — and the
seat set it names may itself be stale (the Jeles seat retirement, `ae23d366`,
is the concrete case this closes).

`install.sh` moves every file left in `pending/` to `failed/<pair_id>.json`
with `result.error = "estale_presigned"`, in the EXACT shape
`manifest_grant_executor._move` itself produces for every other failure —
the original record's fields spread at the top level, plus a `result` key,
never a `request`-nested wrapper — so `manifest_grant_status` (and every
other reader) sees it as an ordinary `failed` entry, no special-casing.
`estale_presigned` is on `manifest_grant_executor.TERMINAL_ERRORS`: not
retryable. The fix is a fresh request under a current sealed pair, never a
replay of `pre_state` that installing just made stale by definition. The
script refuses to enable the timer while `pending/` is still non-empty after
this step.

**This step now runs BEFORE the broker restart below, not after** (Loki audit
BFCC5C79, F7): restarting first would let a freshly-restarted broker accept a
brand-new, perfectly valid request into `pending/` in the window before this
step runs, and the blanket withdrawal above cannot tell that new request from
a stale one by content alone — order matters here, not just correctness of
each step in isolation.

## Restart the broker — and what this script cannot restart

    UNITS=$(systemctl --user list-unit-files --no-legend 'willow-mcp-serve.service' 'willow-mcp.service')
    # restarts whichever of those two names is actually installed

An env change, not a pull — the reloader will not do this one. **This only
reaches the `--user` SERVE unit.** A stdio-attached desk — an editor or CLI
session (Claude Code, Cursor, any MCP client that spawned willow-mcp as a
subprocess over stdio) — is not a systemd unit at all; `install.sh` has no
process to signal and no way to reach it. That session keeps running with the
OLD `WILLOW_PGP_FINGERPRINT` in its own environment until the operator
reconnects it by hand (restart the session). Said here explicitly, rather
than left for the operator to discover when a freshly-signed manifest reads
as unsigned to a desk that never restarted.

## 7. Start, and read the first tick

    sudo systemctl enable --now willow-mcp-manifest-grant.timer
    sudo systemctl start willow-mcp-manifest-grant.service   # one tick now, don't wait 60s
    journalctl -u willow-mcp-manifest-grant.service -n 40 --no-pager

Then from the desk: `manifest_grant_status(<pair_id>)` for whichever request
the desk re-submits under a current sealed pair (`manifest_grant_request`,
or one of `envelope_revoke_request` / `manifest_retire_request` /
`manifest_create_request` / `federation_ratify_request` — all five share
this one queue). Every request that predates this install now reads
`failed/estale_presigned`; `failed/` with a transient cause elsewhere in the
queue is `manifest_grant_retry`-able, `estale_presigned` is not.

## What is still an operator act after this install

`envelope_authoring.ratify` (moving a proposal from `$H/proposals/
proposals.json` into the signed active register — reachable from the CLI
and from the `envelope_ratify` MCP tool) still runs as whoever calls it,
not through the trust-owner apply half. Once `constitutional/` is
trust-owner-owned, a plain broker-uid call to `ratify()` now refuses
`EACCES` UP FRONT (Loki audit 367C367A, T1 — a prior draft discovered this
only at the register write itself, after already inking FRANK and deleting
the proposal from the queue; fixed to refuse before touching either file).
Until a trust-owner `envelope.ratify` verb exists (mirroring
`manifest.grant`'s own request/apply split — tracked via `gap_log`, topic
`envelope.ratify apply-half verb`), ratifying a proposal for real needs
`sudo -u willow-operator` from the operator's own terminal, exactly like
the signing key operations this script itself performs (`as_to gpg ...`).

**`sudo -u willow-operator` strips `WILLOW_PGP_FINGERPRINT` from the
environment unless re-exported** (Loki audit 367C367A, T3): `ratify()`
signs the register when PGP enforcement is on, but does NOT refuse when
the fingerprint is unset — it writes the register unsigned and returns
(the same posture every other write in this codebase takes when PGP is
not enforced). A `sudo -u willow-operator` ratify run without re-exporting
the fingerprint silently produces an unsigned register that every OTHER
reader then refuses via `trusted_read`'s signature branch — a clean-looking
ratify followed by a fleet-wide `EUNREACH`. Always:

    sudo -u willow-operator env WILLOW_HOME=$H WILLOW_PGP_FINGERPRINT=$FPR \
      $H/venvs/willow-mcp/bin/python -m willow_mcp envelope ratify <proposal_id>

`propose()` and `reject()` are unaffected — they only ever touch the
broker-owned `$H/proposals/` sidecar, never the register, from any uid.
Named honestly here rather than implied solved by the register's ownership
change alone.
