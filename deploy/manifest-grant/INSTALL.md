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

    sudo bash install.sh                       # do it
    sudo bash install.sh --check               # detect-only, change nothing — stops
                                                 # after step 0, before any mutation
    sudo bash install.sh --check-signatures     # read-only: which fingerprint does
                                                 # each governed file verify under, right now
    sudo bash install.sh --rotate [--retire FPR ...]
                                                 # generate a new trust-owner signing key,
                                                 # re-sign everything, THEN retire old key(s)

Dispatch `B291C0C7` ("one signing key, one source of truth", amending
`A9BF01A9`; reworked by `E29CCFC7`/`0CB0C85C`/`38CA74F2` per Loki audits
`A38D41C2`/`93D0F057`): the operator ratified an envelope, the trust-owner
apply drained it and re-signed `constitutional/pre-approved.json` under a
fingerprint that had just changed — but the serve broker's own `--user` unit
carried a SECOND, stale pin (a `WILLOW_PGP_FINGERPRINT=` line in a systemd
drop-in) that nothing touched, so `paths.trusted_read` refused the whole
register under the broker's process environment even though the file on disk
was signed correctly.

The fingerprint's one source of truth is now
**`$WILLOW_HOME/constitutional/trust.env`** — trust-owner-owned, world-
readable, `0644` — **not** `$H/env` (which is `0600` and holds every
provider API key; a fingerprint is public, only a key's private half is a
secret, so it does not belong behind that mode). `pgp.expected_fingerprint()`
reads `trust.env`, consults the process environment only to catch a leftover
pin that DISAGREES with it, and refuses loudly (naming both values and both
sources) rather than silently trusting either side when they conflict — see
`pgp.PgpFingerprintConflict`. A `trust.env` that is MISSING, unreadable, owned
by the wrong uid, or carries a malformed value is ALSO refused rather than
silently treated as "no enforcement" — see `pgp.PgpSourceUnreadable` — on any
`$WILLOW_HOME` install.sh has already provisioned for trust. Enforcement is
off only when the trust owner wrote that down (an explicit empty value in
`trust.env`), never because something is missing. `install.sh` strips the
serve unit's own stale pin every run (`strip_pgp_pin`, shared by the plain
install and `--rotate`) so nothing but `trust.env` sets this variable on the
box going forward.

This document is now the human-readable account of what `install.sh` does
and why, in the same order the script runs it — read it to know what the
root act is about to do, or to recover by hand if a step stops. Every `H`
below is the operator box:

    H=/home/sean-campbell/sean-data-vault/willow-operator-box

## Migrating today's box: the exact sequence, in order

As of 2026-09-23 the real box looks like this — read this section before
running anything if your box looks the same:

* the serve unit's systemd drop-in pins `WILLOW_PGP_FINGERPRINT=9B6F87BEB4AE56E2…`
* the desk's `willows-grove/.mcp.json` pins the SAME `9B6F…` in its `env` block
* `$H/env` holds `DEE471967EBCFA46…` (a leftover from a prior, since-reworked
  cut of this fix — see `B291C0C7`'s own history)
* the active envelope register (`constitutional/pre-approved.json`) is
  hand-signed under `9B6F…`
* `$H/constitutional/trust.env` does **not exist yet**

Numbered steps. **Step 4 is the point of no return** — everything before it
is read-only or reversible by re-running; step 4 is a real key generation
and the first write to `trust.env`, and nothing after it un-happens on its
own.

1. **Read-only check first.** `sudo bash install.sh --check-signatures`.
   With no `trust.env` yet, this runs in report-only mode (Loki re-audit
   `93D0F057`, N4 — this is exactly the state the check must work from):
   it names which fingerprint currently signs each governed file (today:
   `9B6F…` on the register, nothing on the rest) without needing anything
   to compare against yet. Confirms the box is in the state this section
   describes before anything changes it.
2. **Desk-owned: remove the desk's `.mcp.json` pin and the template's
   default.** `willows-grove/.mcp.json:17`'s `env.WILLOW_PGP_FINGERPRINT`
   entry, and the `f9ed979` template pin in `mcp.template.json`, both
   name `9B6F…` explicitly. Loki audit `A38D41C2`, F2: a desk session
   RECONNECTING does **not** pick up a new fingerprint if its own
   `.mcp.json` still pins one — the pin is read again on every reconnect,
   and `pgp.expected_fingerprint()` then refuses on the conflict between
   that pin and whatever `trust.env` says once it exists. This step is
   the desk's own repo's to make (not `install.sh`'s) — listed here so
   the sequence is complete and in the right order, not because this
   script does it.
3. **Deploy this rework.** Merge/pull the branch carrying `pgp.py`'s
   `trust.env`-based resolution, `install.sh`'s `--rotate`/
   `--check-signatures`/pin-strip fixes, and this document.
4. **`sudo bash install.sh`** — THE POINT OF NO RETURN. Generates (or
   reuses) the trust-owner signing key, re-signs every governed file as
   one atomic batch (Loki re-audit `93D0F057`, N1 — signing happens
   BEFORE `trust.env` is ever written, so a stop anywhere before the
   write leaves the box exactly as it was; see "Ordering" below), THEN
   publishes `trust.env`, strips the serve unit's stale `9B6F…` pin, and
   restarts the `--user` serve unit. `$H/env`'s leftover `DEE4…` line is
   migrated out (deleted) in the same run, with a fail-closed stop if it
   ever disagrees with the key actually being published (see step 1b
   below) rather than silently discarding it.
5. **Confirm.** `sudo bash install.sh --check-signatures` again — now in
   comparison mode (`trust.env` exists): every governed file should read
   `OK`. Also confirms `$H/env` no longer names a leftover fingerprint.
6. **Reconnect the desk.** Only meaningful after step 2 removed its old
   pin — the operator restarts (or reopens) the stdio session by hand;
   `install.sh` cannot reach a per-session stdio subprocess it does not
   own (see "Restart the broker" below).

Where `--rotate` fits: it is the SAME step-4 sequence (generate → sign+
verify → publish → retire), used later for a routine key rotation once
the box already has a `trust.env` — see its own section below. Do not run
`--rotate` today, before step 4 has ever completed once; it generates a
BRAND NEW key unconditionally, which is one key too many for a box that
has never had one at all.

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

**Fixed (gap `035d287206e1`, 2026-09-22): traverse on `$H` itself is now an
unconditional ACL, not a conditional `chmod o+x`.** The prior fix here
(`sudo -u willow-operator test -x $H || chmod o+x $H`, Loki audit
BFCC5C79 F7) measured as insufficient on the real box: after install.sh
ran, `$H` was still `710` (group execute-only, `other` has no bits at
all) — `test -x` must have passed for `willow-operator` via a group
match, not because the trust owner genuinely had its own grant, so the
conditional `chmod` branch never fired and nothing was actually proven
for an unrelated uid. An ACL names the trust owner explicitly and is
unconditional (idempotent to re-run).

**Widening, named honestly (Loki audit B00BD43E, F3):** the traverse ACL on
`$H` lets `willow-operator` open BY NAME anything world-readable beneath it
— not only `mcp_apps/`, `manifest_grants/`, `constitutional/` (the paths
the apply half actually reads). Measured on the box, what becomes
name-reachable once `$H` is traversable:

* world-readable directly under `$H`: `nestor.db.ledger.jsonl` (664, Nestor's
  own ledger in the clear), `consent.json` (644), `settings.global.json`
  (644);
* enterable + listable (755/775) subtrees: `handoffs/` (every seat's
  handoffs), `dispatch/` (every packet), `deposits/`, `gitsync/`,
  `willow-bot/`, `upstream_steward/`, `worker_heartbeat/`, plus the
  intended `mcp_apps/` and `constitutional/`;
* NOT reachable (700/600, or granted read only where actually needed):
  `config/`, `store/`, `venvs/`, `mcp_receipt.db`, `vault.db`, `nestor.db`
  itself (never read by the apply half at all now — see the note below).

`$H/env` carries every provider key and is read by this unit only as root
(`EnvironmentFile=`), never directly by `willow-operator` — but the SAME
traverse ACL that lets the trust owner reach `mcp_apps/` by name would also
let it open `$H/env` by name if that file's own mode ever slipped. The
installer checks this itself and stops rather than assume:

    ENV_MODE=$(stat -c %a "$H/env")
    [ "$ENV_MODE" = "600" ] || stop "..."

If this ever stops the install: `chmod 600 $H/env` and rerun — `install.sh`
never widens `$H/env`'s own mode itself, only checks it.

    # ACL, not chmod — grants EXACTLY the trust owner traverse-only ($H's
    # own listing and contents stay exactly as private as they were).
    setfacl -m u:willow-operator:x $H

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
key — the other defect R2 measured). `syscall-table.json` used to be
deliberately left broker-owned here, since nothing wrote it at install time
— see step 1c below for why that changed.

## 1c. Sync constitutional policy files from the checkout bundle

Gap `c1395b307421`: nothing ever copied the checkout's own
`src/willow_mcp/bundle/constitutional/syscall-table.json` onto an installed
box. Measured 2026-09-22: the box's table was 22 rows, stale by one row
(`24 envelope.ratify`, shipped by PR 628 hours earlier) — one missing row
froze every envelope ratification behind it, because the verb could never
be governed at all (`UnknownVerbError`).

    deploy/manifest-grant/sync_constitutional.py <checkout>/src/willow_mcp/bundle/constitutional $H/constitutional

`constitutional/` holds POLICY (`syscall-table.json`) and LIVE STATE
(`pre-approved.json`, the active envelope register; `review_queue.json`;
`frank_head_anchor.json`) in the same directory — a sync that copied the
whole bundle directory onto the box would destroy the register. So this
step works from an explicit **ALLOWLIST**, currently exactly
`syscall-table.json`:

* every name on the allowlist that the bundle does NOT ship is a hard
  failure — `install.sh` stops, `constitutional/` is untouched;
* every name in the bundle NOT on the allowlist (the bundle's own seed copy
  of `pre-approved.json`, for instance) is skipped and printed as skipped —
  never copied, never touched;
* for the one file it does sync, the script prints the box's row count and
  mtime BEFORE, the checkout bundle's row count, and the box's row count
  AFTER — so a stale table is visible in the installer's own output, not
  something inferred later from a verb refusing `UnknownVerbError`;
* running the step twice changes nothing the second time, and says so
  (`... no-op`).

`syscall-table.json` is chowned to `willow-operator` and re-signed in step
6 below, alongside the register and the federation registry — the same
governance-integrity shape `pre-approved.json` already has under sealed
`31f5d3af`. It was left broker-owned before this step existed because
nothing wrote it at install time; now that this step does, an
edited-but-unsigned governance file would lock the whole box out under a
denial that blames something else, so it gets the same treatment.

`federation.ratify` (row 23) writes `mcp_apps/_federation/servers.json` —
already under `mcp_apps/`, already trust-owner-owned by the recursive chown
above; a `_federation/` that does not exist yet is created on demand by the
apply process itself (runs as `willow-operator` already), so it is born
correctly owned, mode `0644`, no ACL — nothing extra to do for it here.

**`nestor.db`: no ACL at all now (gap `035d287206e1`, F1 — reworked per
Loki audit B00BD43E).** The apply half used to open this directly at apply
time to RE-verify a sealed pair's bytes fresh. Measured on the box:
`nestor.db` is a WAL database, and every permission shape the trust owner
can be given under this unit's `ProtectHome=read-only` either refuses
outright or silently hides rows still sitting in the WAL —

* sidecars (`nestor.db-wal`/`-shm`) present but unreadable: `unable to open
  database file`;
* sidecars absent (the idle, checkpointed state — they come and go with
  Nestor's own writer) and the directory read-only: `attempt to write a
  readonly database`, because a WAL reader must create `-shm` even to read;
* `immutable=1` on the db file dodges the sidecar problem but hides any row
  still sitting in the WAL — an un-checkpointed seal reads as absent
  (`no such table` in Loki's probe);
* it only ever worked with both sidecars present AND readable, which
  `install.sh` never arranges and `ProtectHome=read-only` would not allow
  even if it tried.

The fix moves the read to the side that can actually do it: the REQUEST
half (the broker, uid 1000, unconstrained by `ProtectHome`) reads
`nestor.db` as it always did, and now embeds the sealed row's own verified
bytes — `source_norm`, `target_text`, `verifier`, `seal_sig`, `created_at`
— in the signed pending record (`manifest_grant_executor._sealed_row_fields`,
covered by `broker_sig`). The APPLY half re-runs `net_signer.verify_seal`
against those embedded bytes and the public ring; it never opens
`nestor.db`, so no ACL on it is needed or granted. `WILLOW_NESTOR_DB` is
gone from the unit file. Trade-off named honestly, not hidden: a pair
superseded after its request but before its apply is no longer caught at
apply time — supersession is checked only where `nestor.db` is actually
read, which is now request time only. A pending request can already sit
for minutes before the next tick; this narrows, but does not remove, that
window.

## Rotating the trust-owner signing key: `--rotate` / `--retire` / `--check-signatures`

Dispatch `B291C0C7`. Operator ruling (verbatim): "I kinda wanna delete both
these keys and just set one new one that applies correctly, instead of split
brain." `--rotate` is a SEPARATE mode from the plain install above — it does
not run steps 0-7; it runs `sign_and_publish_trust` (the SAME shared
sequence the plain install's own step 6 calls — Loki re-audit `93D0F057`,
N1: one code path for "change what is trusted", not two that can disagree
about the order), and the order is the whole point:

    sudo bash install.sh --rotate [--retire FPR ...]

1. **Generate a new key, always** — never reuse whatever the trust owner's
   GNUPGHOME already holds, even if a key of the same name-prefix is already
   there. The OLD key (read from `trust.env` BEFORE anything below touches
   it) is left in place, not deleted yet.
2. **Import the new public half into the operator's keyring.** This does
   NOT switch trust by itself — `pgp.expected_fingerprint()` decides trust
   by reading `trust.env`, never by which keys happen to sit in a keyring —
   so doing this before anything is re-signed is safe: the running broker
   still trusts the OLD key throughout the next step.
3. **Re-sign every governed file under the new key, as ONE atomic batch**
   (`rotate_resign.py`, `resign_all()`, called via the shared
   `sign_and_publish_trust`): every `mcp_apps/*/manifest.json`,
   `constitutional/pre-approved.json`, `constitutional/syscall-table.json`,
   `mcp_apps/_federation/servers.json`, `constitutional/frank_head_anchor.json`,
   and every RATIFIED seed under `$H/seeds/*.json` (an unratified seed's
   signature IS its ratification act on a trust root, so a pending one is
   deliberately excluded — re-signing it during a routine rotation would
   silently ratify it). `trust.env` is NOT touched yet, so the running
   broker still trusts the OLD key while this runs. A failure on file N of
   this batch restores every file the batch ALREADY re-signed this run
   (owner and mode included, not just bytes), not just N.
4. **Verify every one under the new fingerprint** (`rotate_resign.py
   --check`, run as the operator).
5. **ONLY NOW — everything is already signed AND verified — publish
   `trust.env`.** This is the ONE moment trust actually switches, and it
   happens strictly after step 4, never before (Loki audit `A38D41C2`, F3:
   the pre-rework cut wrote the fingerprint FIRST, so a running broker's
   trust flipped to a key nothing was signed under yet — "the register is
   signed by a key the broker does not trust", the 2026-09-23 incident,
   verbatim). If steps 3 or 4 fail or are interrupted (Ctrl-C and a
   delivered SIGTERM both roll back identically — Loki `A38D41C2`/`93D0F057`
   F7), `trust.env` was never written, so there is **nothing to revert by
   hand** — the box is exactly as it was before `--rotate` started.
6. **Only now — trust has switched and every file already verifies —
   retire the old key(s):** the previous trust-owner key is deleted from
   the trust owner's own GNUPGHOME; every fingerprint passed as `--retire
   FPR` (repeatable) is deleted from the OPERATOR's keyring. `--retire`
   without `--rotate` refuses outright (Loki `A38D41C2`, F6) — there is no
   key being replaced to retire the old one for.
7. **Strip the serve unit's stale pin and restart it** (`strip_pgp_pin` /
   `restart_broker`, the same shared functions the plain install's step 3
   and post-6b restart use — Loki `A38D41C2`, F5: a standalone `--rotate`
   used to skip both).

`--check-signatures` is read-only and touches nothing: it reads the SAME
governed-file list `--rotate` re-signs and reports, per file, which
fingerprint its `.sig` actually verifies under right now versus the one
named in `trust.env` — the one read that confirms a rotation landed
everywhere, rather than trusting `--rotate`'s own exit code. When
`trust.env` does not exist yet (the box has never been through this install
at all), it runs in report-only mode instead of stopping (Loki `93D0F057`,
N4) — naming who signed each file now, with nothing to compare against;
this is deliberately the FIRST step of the "migrating today's box" sequence
above, so it has to work from exactly that state.

**v1 PGP session-attestation sidecars are NOT re-signed by `--rotate`** and
go invalid the moment the old key retires — they attest a session under the
OLD key by design (a point-in-time signature, not a live pointer), and
sessions attest through the ed25519 keyring, not PGP, going forward. An
already-attested session does not need to re-attest merely because the trust
owner's PGP key rotated; a NEW attestation after a rotate naturally uses
whichever key `WILLOW_PGP_FINGERPRINT` names at the time.

**Legs this script cannot exercise off the real box** (same limit every
signing step in this file has always had): the real two-uid `gpg` signing
boundary (`rotate_resign.py`'s own tests fake `sign_fn`/`verify_fn`);
`systemctl`; deleting a key from a keyring `sudo -u <uid> gpg
--delete-secret-and-public-key` actually reaches. Only a real `--rotate` run
on the box exercises those.

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

## 1b. The signing key the service uid owns

(Renumbered from the original "3." by dispatch `A9BF01A9` — moved ahead of
1c's atomic sync-and-sign, which needs `$FPR` to exist before it writes
anything. The heading below is kept for search continuity; the script's own
`say` line reads `== 1b. signing key owned by ...`.)

    install -d -o willow-operator -g willow-operator -m 700 /var/lib/willow-mcp/manifest-grant/gnupg
    sudo -u willow-operator GNUPGHOME=/var/lib/willow-mcp/manifest-grant/gnupg \
      gpg --batch --pinentry-mode loopback --passphrase '' \
          --quick-gen-key 'willow-mcp manifest-grant (trust owner) <manifest-grant@willow-operator-box>' ed25519 sign never
    # -> FPR, exported into the broker's (operator's) keyring, trusted ultimately

`install.sh` reuses an existing key of this name if one is already there
(idempotent — re-running after a stop is the intended recovery), generates
one only if absent. It does NOT publish `trust.env` here (Loki re-audit
`93D0F057`, N1) — that write happens only after step 6, below, once every
governed file already verifies under this key; see "Ordering" further
down. It DOES migrate any leftover `WILLOW_PGP_FINGERPRINT=` line out of
`$H/env` here, stopping (fail-closed, not silently discarding) if that
leftover value disagrees with the key about to be published.

## 3. Strip the serve unit's own WILLOW_PGP_FINGERPRINT pin, if any

Dispatch `B291C0C7`, fixed for the real shape by Loki audit `A38D41C2` F1
(the first cut's regex matched nothing against the real drop-in). Every
run (plain install or `--rotate`, via the shared `strip_pgp_pin`
function), idempotent:

    PGP_DROPIN=~/.config/systemd/user/willow-mcp-serve.service.d/pgp.conf
    # systemd's Environment= directive is a space-separated list of quoted
    # NAME=VALUE tokens on one line, tolerating space around "=" and a
    # second unrelated assignment sharing the line -- stripped with a
    # small embedded Python tokenizer (shlex-based, the same approach
    # env_fingerprint.py already uses for this exact directive), not a
    # line-shaped sed regex. Only the WILLOW_PGP_FINGERPRINT token is
    # removed; an Environment= line is dropped entirely only if nothing
    # else remains on it. The strip is VERIFIED afterward -- the script
    # stops rather than reporting success it did not achieve.
    systemctl --user daemon-reload

This is the exact file the 2026-09-23 lockout traced to: a second,
independent pin that `install.sh` had never touched, disagreeing with
`trust.env` the moment a rotation changed one and not the other.
`install.sh` deliberately does NOT give the serve unit
`EnvironmentFile=$WILLOW_HOME/env` in its place — that file holds every
provider API key, and it is unnecessary now that `pgp.expected_fingerprint()`
reads `trust.env` directly as the one source of truth.

## 4. Env file, units

    install -d -m 755 /etc/willow-mcp
    # manifest-grant.env, with WILLOW_PG_DB filled in. WILLOW_PGP_FINGERPRINT
    # is NOT rendered here (dispatch 0CB0C85C, dissolving Loki A38D41C2's F8):
    # the trust-owner apply unit reads trust.env directly -- the same file
    # everything else reads -- so there is no second copy of the fingerprint
    # to keep in sync, or to drift, here at all.
    install -o root -g willow-operator -m 640 manifest-grant.env /etc/willow-mcp/manifest-grant.env
    install -o root -g root -m 644 willow-mcp-manifest-grant.{service,timer} /etc/systemd/system/
    systemctl daemon-reload

## 5. Postgres role for the apply half

    # a willow-operator role, peer-auth on the local socket, with the broker
    # role's read grants on the FRANK tables plus INSERT
    sudo -u willow-operator psql -d $WILLOW_PG_DB -c 'select 1'   # must succeed

## 6. Re-sign everything, THEN publish trust.env (`sign_and_publish_trust`)

Rewritten by Loki re-audit `93D0F057`, N1: this used to be `install.sh`'s
OWN loop (N independent `gpg --detach-sign` calls, no rollback), running
AFTER `trust.env` was already published back in step 1b — so any stop
between them (the `$H/env` migration stop, a step-1c sync failure, the
step-1d seed stop, step 5's postgres peer auth, the pending/ refusal in
6b below) left trust already switched with nothing re-signed. It also
never covered `constitutional/frank_head_anchor.json` or the ratified
seeds — only `--rotate`'s own file list did.

Step 6 now calls `sign_and_publish_trust` — the SAME shared function
`--rotate` calls (see its own section above for the full six-step
breakdown: sign as one atomic batch → verify → THEN publish `trust.env`
→ retire the old key if one differed). One code path for "change what is
trusted," so this finding cannot recur by the two paths drifting apart.
Covers every `mcp_apps/*/manifest.json`, `constitutional/pre-approved.json`,
`constitutional/syscall-table.json`, `mcp_apps/_federation/servers.json`,
`constitutional/frank_head_anchor.json`, and every ratified seed —
`governed_files()`'s own list, the single place that enumerates them.

`paths.trusted_read`'s trust-owner branch refuses the envelope register on
a signature that does not verify under `trust.env` (pair `31f5d3af`), and
`mcp_federation._read_registry_file` does the same for the federation
registry — Loki audit BFCC5C79's F3, still closed: missing the federation
registry here would mean the first `federation.ratify` after any
fingerprint change reads "no ratified servers" and silently drops every
other entry. `trust_owner_verbs._apply_federation_ratify` also carries a
defensive check refusing `EACCES` before ever reaching
`mcp_federation.ratify()` if the registry does not verify, as a backstop.

## 6b. Withdraw every request minted before this install

Sealed `33654f35` (2026-09-22): a pending request that predates step 6 is
withdrawn, not applied. Step 6 just re-signed every manifest (and the
register, federation registry, anchor, and ratified seeds) and published a
new `trust.env`, so every request already sitting in `pending/` carries a
`pre_state` recorded under the OLD fingerprint — and the seat set it names
may itself be stale (the Jeles seat retirement, `ae23d366`, is the concrete
case this closes).

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
process to signal and no way to reach it.

**Reconnecting that session is NOT enough by itself** (Loki audit
`A38D41C2`, F2 — corrected here; an earlier draft of this document claimed
otherwise). If the project's own `.mcp.json` pins `WILLOW_PGP_FINGERPRINT`
in its `env` block (as `willows-grove/.mcp.json` does today, per "Migrating
today's box" above), reconnecting just re-reads that SAME pin — the
fingerprint does not come from `trust.env` for that session at all, it
comes from whatever `.mcp.json` says, every time it starts. The pin has to
be removed from `.mcp.json` FIRST (desk-owned, step 2 of the migration
sequence above); only then does reconnecting pick up `trust.env`. A desk
with no such pin (nothing in `env` names `WILLOW_PGP_FINGERPRINT`) reads
`trust.env` fresh on every reconnect and needs nothing further.

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

The desk's own `envelope_ratify` (the direct, sidecar-path act) still
refuses `EACCES` on an installed box for the reason above — that refusal is
unchanged and correct, and is not a shim onto the trust-owner path. The fix
is `envelope.ratify` (gap `d3f79320ccb5`, trust-owner apply half, syscall
table row 24, `envelope_ratify_request` on the desk) — the same
request/apply shape as the other four verbs — and it already exists in code
(`trust_owner_verbs.py`, PR 628). What blocked it on THIS box until step 1c
above was narrower and easier to miss than the code gap: the box's own
`syscall-table.json` did not carry row 24 at all, so `envelope_propose(verb=
'envelope.ratify')` refused `UnknownVerbError` before an envelope over the
verb could even be proposed, let alone ratified — the code existed and the
box could not reach it. Confirm the table synced (`envelope_ratify_request`
stops naming a real reason, not `UnknownVerbError`/`ENOENT`, if it still
does not) before assuming a ratify failure is this gap rather than the
ordinary sealed-pair/digest checks `envelope_ratify_request` itself makes.

`propose()` and `reject()` are unaffected — they only ever touch the
broker-owned `$H/proposals/` sidecar, never the register, from any uid, and
work exactly as before. Named honestly here rather than implied solved by
the register's ownership change alone.
