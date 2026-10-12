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

    sudo bash install.sh --expect-head <sha>     # do it, from THAT commit (commit and push
                                                 # before you install)
    sudo bash install.sh --check --expect-head <sha>
                                                 # detect-only, change nothing — stops
                                                 # after step 0, before any mutation;
                                                 # prints one [ok]/[FAIL] line per
                                                 # trust-owner-interpreter check, one per
                                                 # unit/timer/env check, and any drift of
                                                 # /etc from the committed HEAD; exits 2 if
                                                 # any fails
    sudo bash install.sh --provision-venv --expect-head <sha>
                                                 # build (or rebuild) ONLY the trust-owner
                                                 # venv, check it, touch nothing else
    sudo bash install.sh --check-signatures --expect-head <sha>
                                                 # read-only: which fingerprint does
                                                 # each governed file verify under, right now
    sudo bash install.sh --rotate [--retire FPR ...] --expect-head <sha>
                                                 # generate a new trust-owner signing key,
                                                 # re-sign everything, THEN retire old key(s)
    sudo bash install.sh --record-trust-identity --expect-head <sha>
                                                 # D1: a plain install that ALSO writes the
                                                 # FIRST trust-identity record, only after a
                                                 # clean read-only audit (see "D1" below)
    sudo bash install.sh --re-record-trust-identity [--confirm TOKEN] --expect-head <sha>
                                                 # D1: accept a changed trust-directory
                                                 # identity (diff, audit, typed token)

## Which commit: `--expect-head <40-hex sha>` (Loki pre-deploy audit F1)

**Every mode takes `--expect-head`, with the full 40-hex commit sha, and refuses
to start without it** — plain install, `--check`, `--provision-venv`,
`--rotate`, `--check-signatures` (only `--dry-run-sign`, which prints text and
touches nothing, needs neither root nor a sha). A missing, abbreviated (7 or 39
characters), non-hex or doubled value, a branch or tag name, `HEAD`, and the
form `--expect-head=<sha>` are all refused before anything is cloned. Uppercase hex is
accepted and lowercased.

**Where the sha comes from — not from the checkout.** Take it from GitHub, in a
normal shell on a machine and account that is not the one being installed from:

    git ls-remote https://github.com/willow-memory/willow-mcp <branch>     # the 40-hex on the line for refs/heads/<branch>

or the branch page / the commit page on GitHub (the full sha, not the 7-character
form). The checkout's own `git rev-parse HEAD` is **not** a trustworthy source: its
`.git` is writable by the operator uid (the shell, the bot, the agents) and by
Kart tasks, so HEAD, branches, `packed-refs` and even the object files can be
rewritten, and `rev-parse` then faithfully prints the rewritten answer. The sha is
a check only because it reaches the script from outside the thing it checks. The
commit must also exist in the checkout (`git fetch` first, as the operator, if it
does not); nothing is fetched from the network by the script.

**What the script does with it.** It clones the checkout (`git clone --no-local
--no-checkout`, so every object is re-hashed on receipt and an object forged
under the expected name is simply absent), checks out exactly that sha detached
(a moved HEAD, branch or tag in the checkout cannot redirect it; a sha that is not
a commit in the clone stops the run), and then **`exec`s the clone's own copy of
`deploy/manifest-grant/install.sh`** before any privileged action. That copy
re-verifies that it is the clone's file (root-owned unwritable clone, clean
tree, `HEAD` equal to the sha), does not clone again, and only then reads on:
every line of shell and every inline python heredoc below the pre-reexec
section comes from the pinned commit. The unpinned file you typed runs only
the section marked `THE PRE-REEXEC SECTION` at the top of `install.sh` —
argument scan, the root check, `mktemp`, `mg_git clone / rev-parse / checkout`,
`exec` — with git run under a neutral environment (`env -i`, no system, global
or user config, no hooks, no fsmonitor, no pager, file transport only). That
section is the residual to review. To check the file you are about to run
against the commit you are about to install:

    curl -fsSL https://raw.githubusercontent.com/willow-memory/willow-mcp/<sha>/deploy/manifest-grant/install.sh | sha256sum
    sha256sum deploy/manifest-grant/install.sh                              # the two must match

The initial `sudo` invocation of `install.sh` itself starts before any of this can help: it
relies on sudo's own startup (`env_reset` and sudo's hardcoded
`BASH_ENV`/`ENV`/`SHELLOPTS`/`BASHOPTS` blacklist). To run it as root without
sudo, use `env -i PATH=/usr/bin:/bin bash install.sh --expect-head <sha> ...` so
no startup variable reaches bash. The re-exec into the pinned copy no longer
depends on sudo: it runs under `/usr/bin/env -i` with a fixed allowlist
(`SUDO_USER`, plus `PATH` and the two `MG_REEXEC*` markers) and
`--noprofile --norc`, so `LD_PRELOAD`, `LD_LIBRARY_PATH`, `IFS`, `PYTHON*`,
`GIT_*` and every startup variable are dropped before it runs.

Every command below therefore carries `--expect-head <sha>`; write the same sha
on each (re-run `git ls-remote` if the branch moved).

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
**`$H/constitutional/trust.env`** — trust-owner-owned, world-readable,
`0644` — **not** `$H/env` (which is `0600` and holds every provider API
key; a fingerprint is public, only a key's private half is a secret, so it
does not belong behind that mode).

**Rework #3 (dispatch `FA4F79AC`) tried "the vault" as a separately
configured `WILLOW_VAULT_BOX`; rework #4 (dispatch `10F9E837`, Loki audit
`23DE8AA9`, finding F-C) reverted it.** The problem F-C measured: this
document's own "module constant" claim was false — `paths.trust_config_path()`
resolved through `os.environ['WILLOW_VAULT_BOX']`, a variable the BROKER's
own process sets, same as any other env var. That is not a root-chosen
single answer to "which file decides what this box trusts" — it is a
SECOND lever the broker holds, on top of the file's own ownership and
signature checks. Worse, `install.sh`'s own resolution (root's `sudo`
environment, normally stripped of anything the invoking user exported)
and the broker's resolution (its own process env) could disagree once
`WILLOW_VAULT_BOX` was set anywhere other than `$H` — install.sh writing
trust.env to one path while a broker reads a DIFFERENT one as
authoritative. `trust.env` is now resolved from `$WILLOW_HOME` alone, no
second variable layered on top — `install.sh` mirrors this exactly
(`TRUST_ENV="$H/constitutional/trust.env"`, no `WILLOW_VAULT_BOX`
indirection at all). See `paths.trust_config_path()`'s own docstring for
the full argument.

**The rename-away hole (Loki audit `D06A0EF3`) is UNCHANGED by either
rework and still open on this box until step 6 has written the D4 marker
(see "D4: the trust-provisioned marker" after step 6), which closes its
fail-open half.** `$H` is owned by the broker's own
uid, mode `700`, so the broker can rename `$H/constitutional` away
entirely and put an empty, self-owned directory of the same name back —
`constitutional/` then reads as "never provisioned," trust.env as
"legitimately absent," and enforcement as off. Loki's own alternative
(audit `D06A0EF3`) was a root-owned `/etc/willow-mcp/trust.env`; the
operator's "vault" ruling asked for a different location than `/etc`, but
F-C showed that an ENV-VAR-CHOSEN location cannot deliver the property a
location needs to deliver here, no matter where it points. Closing the
hole for real needs `$WILLOW_HOME` ITSELF — the one address every process
sharing this box already has to agree on for anything to work — to
resolve to a root-provisioned location outside the broker's own writable
tree (e.g. a root-owned bind-mount or symlink target, established once,
outside any single process's env), never a second, independently-set
variable on top of it. That is a larger deploy/architecture change, out
of this dispatch's scope; `install.sh` reports `$H`'s ownership every run
rather than silently assuming it is closed.

`pgp.expected_fingerprint()` reads `trust.env`, consults the process
environment only to catch a leftover pin that DISAGREES with it, and
refuses loudly (naming both values and both sources) rather than silently
trusting either side when they conflict — see `pgp.PgpFingerprintConflict`.
A `trust.env` that is MISSING, unreadable, owned by the wrong uid, or
carries a malformed value is ALSO refused rather than silently treated as
"no enforcement" — see `pgp.PgpSourceUnreadable` — on any `$WILLOW_HOME`
`install.sh` has already provisioned for trust. Enforcement is off only
when the trust owner wrote that down (an explicit empty value in
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

Numbered steps, walked from this exact state, with what is DOWN during
each one and for how long — no step below claims a stronger guarantee
than it actually has (Loki audit `D06A0EF3`, M2).

**The real point of no return is step 3, not step 4 — corrected here (an
earlier draft of this document put it at step 4; wrong).** Steps 1-2 are
read-only or reversible. The moment step 3 deploys this rework's code, the
box is ALREADY provisioned for trust (`constitutional/` is trust-owner-owned
from a PRIOR install run — that never un-happens) but has no `trust.env` —
`pgp.PgpSourceUnreadable` fires for every process that starts or restarts on
the new code from that instant, fleet down, FAILING CLOSED (this is
correct, not a bug — see N2 in `D06A0EF3`), until step 4 completes. Step 4
itself is not a NEW point of no return; it is the step that ENDS the outage
step 3 opened. If step 4 stops partway, the box stays down in the same
fail-closed state — rerunning `install.sh` (idempotent) is the recovery,
not a rollback.

1. **Read-only check first.** `sudo bash install.sh --expect-head <sha> --check-signatures`.
   With no `trust.env` yet, this runs in report-only mode (Loki re-audit
   `93D0F057`, N4 — this is exactly the state the check must work from):
   it names which fingerprint currently signs each governed file (today:
   `9B6F…` on the register, nothing on the rest) without needing anything
   to compare against yet. Confirms the box is in the state this section
   describes before anything changes it. Nothing is down; this step reads
   only.
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
   script does it. **Do not reconnect the desk between this step and step
   4.** With the OLD code still deployed (process-env-only resolution) and
   no pin left in `.mcp.json`, a reconnect in this window runs with NO
   fingerprint at all — enforcement OFF for that session, silently, until
   step 3 deploys the new code (which then refuses to boot unpinned and
   unprovisioned-with-trust.env — see step 3 below) or step 4 completes.
   This is the one window in the whole sequence where enforcement can be
   off without the trust owner having written that down; close it by not
   reconnecting here, not by relying on the code to catch it.
3. **Deploy this rework.** Merge/pull the branch carrying `pgp.py`'s
   `trust.env`-based resolution, `install.sh`'s `--rotate`/
   `--check-signatures`/pin-strip fixes, and this document.
   **THE FLEET GOES DOWN HERE, FAIL-CLOSED, UNTIL STEP 4 COMPLETES** —
   see "The real point of no return" above. Reversible in the sense that
   the code itself can be reverted (nothing has been written to `$VAULT`
   yet), but NOT reversible in the sense of "no outage": the moment this
   step's code is live, every process that starts or restarts on it
   refuses to boot.
4. **`sudo bash install.sh --expect-head <sha>`.** Generates (or reuses) the trust-owner
   signing key; syncs and signs `syscall-table.json` (step 1c) under that
   key explicitly (not through `trust.env`, which does not exist yet —
   see "Ordering" below); seeds the `envelope.ratify` bootstrap envelope
   (step 1d) the SAME way, under the same explicit key, never through
   `pgp.pgp_enabled()` (dispatch `FA4F79AC`, M1 — see "Why step 1d does
   not deadlock" below); re-signs every OTHER governed file as one atomic
   batch; THEN publishes `trust.env`, strips the serve unit's stale
   `9B6F…` pin, and restarts the `--user` serve unit. `$H/env`'s leftover
   `DEE4…` line is migrated out (deleted) in the same run, with a
   fail-closed stop if it ever disagrees with the key actually being
   published (see step 1b below) rather than silently discarding it.
   **A stop anywhere in this step leaves the box fail-closed and down,
   exactly as step 3 already left it — not reverted, not corrupted,
   recoverable by rerunning `install.sh` from the top** (idempotent at
   every sub-step: 1b reuses an existing key, 1c/1d are no-ops on
   already-correct content, the final re-sign batch only touches files
   that do not yet verify). See "N1: the syscall-table residual" below
   for the one sub-step (1c) whose signed-but-not-yet-published state
   this description now accounts for honestly.
5. **Confirm.** `sudo bash install.sh --expect-head <sha> --check-signatures` again — now in
   comparison mode (`trust.env` exists): every governed file should read
   `OK`. Also confirms `$H/env` no longer names a leftover fingerprint.
6. **Reconnect the desk.** Only meaningful after step 2 removed its old
   pin — the operator restarts (or reopens) the stdio session by hand;
   `install.sh` cannot reach a per-session stdio subprocess it does not
   own (see "Restart the broker" below).

### Why step 1d does not deadlock (dispatch `FA4F79AC`, M1)

Loki audit `D06A0EF3` measured: step 1 (a PRIOR install run) already made
`constitutional/` trust-owner-owned — "provisioned" — before this run's
step 1d (seed the `envelope.ratify` bootstrap envelope) has a `trust.env`
to read. Every fresh install hit this, every time, because `trust.env` is
never written until step 6 — not a transient failure a retry clears, an
unconditional deadlock. The fix: step 1d's one write (through
`envelope_authoring.ratify_proposal_row` → `_save_active`) now takes an
explicit `sign_as` fingerprint — root's own already-resolved `$FPR`,
passed via this one process's environment — and signs under it directly,
the same way `rotate_resign.py` and `sync_constitutional.py --sign-as`
already sign install-time writes, rather than asking
`pgp.pgp_enabled()`/`pgp.expected_fingerprint()` whether `trust.env`
(which does not exist yet) says this is trusted. This is install's OWN
internal bootstrap act, root vouching for a value it is about to publish
— never a fallback available to the real `envelope.ratify` apply half,
which still goes through the ordinary `trust.env`-backed check exactly as
before.

This does **not** make "provisioned" and "`trust.env` exists" simultaneous
— that gap is real and is what step 3's outage window (above) documents
honestly. What it fixes is narrower and sufficient: install's OWN forward
progress no longer depends on the trust it has not finished establishing
yet, so the box always reaches step 6 and completes, rather than
deadlocking on itself indefinitely partway through its own bootstrap.

### F-A: a TRULY fresh install (dispatch `10F9E837`, Loki audit `23DE8AA9`)

The `sign_as` fix above closed M1 for any box that already has a register
(`constitutional/pre-approved.json`) — which includes today's box, and
was what `hanuman`'s own first reproduction (dispatch `FA4F79AC`) tested
without noticing it had pre-created that file. Loki's re-audit caught the
gap: a box with NO register at all — nothing has ever written one, not
even a prior seed — still failed at step 1d, one call earlier than M1's
original failure. `seed()` → `envelope_authoring.ratify_proposal_row` →
`_load_active_register()` → `envelopes._load` → `paths.trusted_read`
raised `PermissionError: source path missing` for the register file
itself, regardless of `sign_as` — a correct refusal for a file that
disappeared after existing, wrong for a file that has simply never been
written yet. Fixed at the same seam: `_load_active_register()` now treats
a register that does not exist AT ALL as `{"active": []}` — legitimate
bootstrap, mirroring `_register_writable()`'s own existing carve-out for
a missing DIRECTORY. Both real callers (the `envelope.ratify` apply half,
and install's own seed) go on to WRITE the register via `_save_active`
regardless, so there is no state where "missing" could be mistaken for
signed content this process merely failed to authenticate.

### F-B: a failed `--rotate` retire, and the rerun that used to revert it
(dispatch `10F9E837`, Loki audit `23DE8AA9`)

If `--rotate`'s final retire of the OLD key fails (`as_to gpg ...
--delete-secret-and-public-key` can fail for reasons unrelated to
trust — a locked keyring, a transient error), the prior cut only printed
a `WARNING:` and moved on. The next PLAIN install then re-resolved `$FPR`
at step 1b by a `$KEY_UID` substring search of `GNUPGHOME_TO`, which
returns the FIRST match — the rotated key's own generated UID carries a
timestamp suffix (`"$KEY_UID <timestamp>"`), so the substring search kept
finding the OLDER, pre-rotation key first. That plain install then
re-signed every governed file under the OLD key, republished it to
`trust.env`, and — because the two fingerprints now differed — DELETED
the NEW key as "the old one," silently reverting a completed rotation and
destroying the replacement key in the same run.

Fixed two ways, together:

1. **Step 1b now prefers `trust.env`'s own fingerprint whenever its secret
   key is still present in `GNUPGHOME_TO`**, before ever falling back to
   the `$KEY_UID` substring search. `trust.env` is the one source of
   truth for "what does this box trust" — every path that resolves a
   fingerprint on an already-provisioned box must agree with it, not
   guess by a name pattern that can match more than one key.
2. **A failed retire is now a named, persisted state, not a warning the
   process forgets the instant it exits.** `sign_and_publish_trust`
   writes the un-retired fingerprint to `$H/constitutional/.stale_trust_key`
   when the delete fails; `retire_stale_key_if_marked()` (called at the
   top of both the plain install and `--rotate`, right after
   `GNUPGHOME_TO` exists) retries that retire on every subsequent run,
   clearing the marker on success and reprinting the same named warning
   — never silently — on repeat failure. Trust itself is never at risk
   either way: fix (1) means step 1b keeps trusting whatever `trust.env`
   already names regardless of whether the stale key's retire ever
   succeeds.

### N1: the syscall-table residual (Loki audit `D06A0EF3`)

Step 1c (`sync_constitutional.py --sign-as`) signs `syscall-table.json`
under `$FPR` explicitly — the same explicit-fingerprint discipline as
step 1d above, never through `trust.env` — and, in isolation, is already
atomic: a signing or verification failure inside it restores the file's
exact previous bytes AND its exact previous `.sig`, so a failure DURING
1c itself really does leave the box exactly as it was.

What is NOT true, and this document previously claimed was ("a stop
anywhere before the write leaves the box exactly as it was" — INSTALL.md,
prior draft): a stop AFTER 1c succeeds but BEFORE step 6 publishes
`trust.env` leaves `syscall-table.json` signed under `$FPR` while
`trust.env` (on a REROTATION or migration where a different key was
already published) still names the OLD fingerprint. Every reader refuses
`syscall-table.json` until step 6 completes — fail-closed, not corrupted,
not "as it was." Re-running `install.sh` is safe (1c is idempotent — a
file already synced and correctly signed is a no-op) and completes the
box's provisioning. `syscall-table.json` is not folded into
`governed_files()`'s own re-sign batch, because that batch re-signs
EXISTING content unchanged, while 1c also SYNCS new content from the
checkout bundle — a different, larger act than a re-sign; the atomicity
that matters (this step's own success or exact rollback) is what it has,
not "nothing changes anywhere in the box until the very last write,"
which no multi-file, single-signature scheme in this installer promises
for any of its steps once step 3 has already put the box in the
fail-closed, provisioned-without-trust.env state described above.

Where `--rotate` fits: it is the SAME step-4 sequence (generate → sign+
verify → publish → retire), used later for a routine key rotation once
the box already has a `trust.env` — see its own section below. Do not run
`--rotate` today, before step 4 has ever completed once; it generates a
BRAND NEW key unconditionally, which is one key too many for a box that
has never had one at all.

## The trust owner's own interpreter (operator rulings Q7=A and Q13, 2026-10-11)

The unit and `install.sh` used to run the trust owner with
`$H/venvs/willow-mcp/bin/python`. Measured on the operator's box on
2026-10-11 (read-only `stat`/`getfacl`/`readlink`, `$H` =
`/home/sean-campbell/sean-data-vault/willow-operator-box`):

| Path | Owner | Mode | ACL |
|---|---|---|---|
| `$H` | `sean-campbell:sean-campbell` | 711 | |
| `$H/willow-bot` | `sean-campbell:sean-campbell` | 775 | none |
| `$H/venvs` | `sean-campbell:sean-campbell` | 755 | `user:willow-operator:--x`, `other::r-x` |
| `$H/venvs/willow-mcp` | `sean-campbell:sean-campbell` | 755 | |
| `$H/venvs/willow-mcp/bin/python` | `sean-campbell:sean-campbell` | 777 | symlink; `readlink -f` = `/usr/bin/python3.14` (root-owned system python) |

and the venv itself holds editable installs: `_editable_impl_willow_mcp.pth`
and `willow_mcp-2.90.2.dev2+g2f1ac9385.dist-info/direct_url.json` =
`{"dir_info": {"editable": true}, "url": "file:///home/sean-campbell/github/willow-memory/willow-mcp"}`,
plus `__editable__.nestor-0.1.0.pth` (and its finder), `_editable_impl_jeles.pth`,
`_editable_impl_ratatosk_meaning.pth`, `_editable_impl_willow_reconciler.pth`,
`_ratatosk_checkout.pth` and `a1_coverage.pth`.

So the trust owner executed (a) an interpreter tree owned and writable by
`sean-campbell` — the uid the operator shell, the bot and the agents run as —
and (b) willow-mcp straight out of the operator's checkout, which Kart tasks
hold read-write binds on. Anything that could write either could rewrite code
that then ran as the trust owner: the trust-owner separation (Loki audit
BFCC5C79 F7) was not holding. (The same measurement also shows `venvs/` is
**not** the 700 "NOT reachable" directory this document used to claim; the
list under step 1 now says what the box shows.)

Ruling Q7 = option A ("split"): the trust owner gets its **own** interpreter
venv, separate from the broker's willow-mcp venv (which moves into the bot
tree under D2 — `docs/design/d2-venvs-move.md`). Ruling Q13: this fix goes
ahead of the D2 sequence as its own change, because the gap is open today.

What `install.sh` now builds and requires:

| Property | Value | Why |
|---|---|---|
| Path | `/opt/willow-operator/venv` (`TRUST_VENV`, and `PY=$TRUST_VENV/bin/python`; the unit's `ExecStart=` names the same path and the preflight stops if it does not) | `/opt` is the FHS home for add-on software, outside `$H` and `/home`. `/etc/willow-mcp` is configuration, and `/var/lib/willow-mcp/manifest-grant` is the trust owner's own *writable* state (its gnupg home, a unit `ReadWritePaths=`): an interpreter may sit in neither, or the uid that runs it could rewrite it. Under `ProtectSystem=strict` `/opt` is read-only to the unit as well. |
| Owner / mode | `root:root`, 755 dirs, 644 files (755 for executables) | No non-root uid can write it, the trust owner included. |
| Build | `python3.14 -m venv` (`TRUST_PY_BASE=/usr/bin/python3.14`, what the box's current venv already resolves to), then a **non-editable** install of a wheel built from a local clone of this checkout's committed `HEAD`. The wheel is built in a throwaway root-owned build venv whose backend (hatchling, hatch-vcs and their dependencies) is installed from `trust-venv.build-requirements.txt`, then `pip wheel --no-build-isolation --no-index`; the dependencies go into the trust venv from `trust-venv.requirements.txt` with `pip install --require-hashes --only-binary=:all: --no-deps -r`; the wheel is installed by file with `--no-deps --no-index`. Both requirements files are read from the committed `HEAD` in the root-owned clone, and refused unless every line is a `name==version` pin or a `--hash=sha256:` entry (no `--index-url`, `-r`, URL or range). | The build writes nothing into the operator-writable checkout; the installed code is a copy, not a pointer back at the checkout. |
| Packages | `willow-mcp` (the wheel, `--no-deps`), `psycopg2-binary`, `cryptography` and their transitive dependencies `cffi` and `pycparser`, each pinned by sha256 — nothing else | Traced 2026-10-11: `python -m willow_mcp manifest-grant apply` (`__main__` dispatches before `server` loads) and the modules it calls — `manifest_grant_executor`, `trust_owner_verbs`, `mcp_federation`, `envelope_authoring`, `governance_ledger`, `human_session`, `net_signer`, `pgp` — import `psycopg2` (the FRANK ledger, `db`) and `cryptography` (ed25519 verification of the sealed pair) and no other third-party package. `mcp`, `starlette`, `kartikeya`, `jeles`, `nestor`, `ratatosk`, `forge`, `willow-gate`, `requests` and the reconciler are not pulled in. The preflight's last line imports exactly those modules from inside the venv; add a package to `trust-venv.requirements.in` (and regenerate) only if that import (or a new apply-path module) needs it. |

### Preflight

The script refuses to start unless: it is run as root; `$H` exists; the
`willow-operator` trust-owner user already exists (`trust_root_setup` has
run on this box); the three unit/env files are in the checkout's **committed
HEAD** (see "The unit, timer and env come from the committed HEAD" below);
`/etc/willow-mcp/verifiers.public.json` (the net-signer's public ring) is
already present; `$H/env` names `WILLOW_PG_DB`; and **the trust owner's
interpreter passes every check below** (Loki audit BFCC5C79, F7 — it is used
from step 1 on, so a bad one stops before anything is touched). Each check
prints one `[ok]` or `[FAIL]` line; any `[FAIL]` stops the script (`STOP:`),
and `--check` prints all of them and exits 2 instead of stopping at the first:

1. the interpreter exists, resolves to a regular file and is executable;
2. every path component from `/` to it is owned by root and not group- or
   other-writable — walked twice, once as written and once after
   `readlink -f`, so a symlink into a writable tree is refused too;
3. no non-root ACL entry grants write on any of those components or anything
   inside the venv (`getfacl`; if `getfacl` is missing the check **fails
   closed** — install the `acl` package, which this script already needs for
   `setfacl`);
4. everything inside the venv is owned by root and not group/other-writable;
5. willow-mcp is installed, and nothing in the venv is editable — no
   `__editable__*`/`_editable_impl_*` marker, `.egg-link` or
   `easy-install.pth`, no `direct_url.json` with `"editable": true`, and no
   `.pth` line that puts a path outside the venv on `sys.path`, and no
   *executable* `.pth` line (one starting `import ` or `import<TAB>`, which
   `site.py` runs at every interpreter start) — for **any** package, not
   only willow-mcp. There is no allowlist: a clean build of this venv has no
   `.pth` file at all (setuptools' `distutils-precedence.pth` is refused too;
   the venv never installs setuptools). Live finding on the old venv:
   `_ratatosk_checkout.pth` = `import ratatosk_path_hook`, a module that did
   `sys.path.insert(0, <ratatosk checkout>)` — a checkout Kart tasks can
   write, ahead of the standard library;
6. **`pyvenv.cfg`** (Loki F3), read the way `site.py` reads it: the key
   `include-system-site-packages` must be present and its last value `false`
   (`site.py` defaults an absent key to **true**, which would put
   `/usr/lib/python3/dist-packages` on `sys.path`), `home` must be the directory
   of `TRUST_PY_BASE`, `version` that interpreter's `X.Y`, and no
   `bin/pyvenv.cfg` may exist (it would be read first);
7. **the standard library the interpreter loads** (F3). Located without
   executing anything: `TRUST_PY_BASE` must be named `pythonX.Y`, its
   `readlink -f` gives `<prefix>/bin/pythonX.Y`, and CPython's library is
   `<prefix>/lib/pythonX.Y` (and `<prefix>/lib64/pythonX.Y` where that exists) —
   `/usr/lib/python3.14` on the operator's box (measured: root:root 755, no
   non-root-owned or group/other-writable entry, no extended ACL). Every path
   component down to it (so `/usr/lib` — nobody can drop a `python3XX.zip`
   beside it) is root-owned and not group/other-writable, and **one `find`**
   over the whole tree rejects any entry not owned by root or (non-symlink)
   group/other-writable; the resolved target of every symlink that leaves the
   tree is judged on its own chain and tree (Debian links `sitecustomize.py` to
   `/etc/python3.14/sitecustomize.py`);
8. no non-root write ACL on the standard library, its chain or those targets
   (`getfacl`, fail closed as in 3);
9. **`sitecustomize` / `usercustomize`** (F3): every such file (or directory,
   or compiled module) in the standard library, its `lib-dynload` and the
   venv's `site-packages` — the only places `-I` looks — is resolved with
   `readlink -m` and must itself sit on a root-owned, unwritable chain (a
   dangling link is judged by the directory it would land in);
10. only when 1–9 pass (root never runs an interpreter that failed them): the
   apply path imports, with `-I`, from inside the venv, **and every
   `sys.path` entry the interpreter actually built** lies in the venv or in
   the checked standard library (so a system `dist-packages` that somehow got
   added is caught by looking, not only by reading `pyvenv.cfg`);
11. the venv's `.built-from-head` stamp equals the commit of the root-owned
   HEAD clone the units are read from (refused if they differ: the units and
   the venv must come from the same commit);
12. the committed `willow-mcp-manifest-grant.service` is exactly the
   allowlisted directive set, the `.timer` only its expected keys and
   `manifest-grant.env` only its expected keys (next section).

A plain install builds the venv first when it is missing or fails a check
(step 0a below); `--rotate` and `--check-signatures` only enforce the checks.
Before the build, root's own use of the base interpreter (`python3.14 -I -m
venv`) is covered by checks 7–9 run on `TRUST_PY_BASE`.

### The unit, timer and env come from the committed HEAD

The service runs as the trust owner and root installs it, so
`willow-mcp-manifest-grant.service`, `.timer` and `manifest-grant.env` are
code-equivalent. They used to be copied from the working tree beside
`install.sh` (writable by the operator uid, the bot and the agents) with only
`ExecStart=` checked. Now:

- **One root-owned clone of the pinned commit per run** (`ensure_head_clone`,
  made by the pre-reexec section from `--expect-head`; the re-exec'd copy of
  `install.sh` reuses it and never clones again). The venv's wheel and pinned
  requirements, the unit, the timer and the env template are all read from it
  and from nowhere else; `install.sh` reads nothing privileged from `$HERE`.
  **Commit before you install**: an uncommitted edit to any of the three is
  not installed (and not validated as if it were). The clone's commit must
  equal the venv's `.built-from-head` stamp; a mismatch stops a plain
  install, `--rotate` and `--check-signatures` alike (operator ruling
  2026-10-11: "keep it on all three"). `sudo bash install.sh --expect-head <sha>
  --provision-venv` rebuilds the venv from HEAD.
- **The whole file is validated, not just `ExecStart=`** (`mg_service_problems`,
  `mg_timer_problems`, `mg_env_problems`, in the `trust-venv-check` block of
  `install.sh`). Exact-line allowlists, each line once, per section; a
  comment or blank line is skipped, anything else (including an indented
  directive, a trailing-backslash continuation, a duplicate, a missing line or
  a directive in the wrong section) stops the install.
  - service `[Unit]`: `Description=`, `After=network.target postgresql.service`,
    `RequiresMountsFor=$H`. `[Service]`: `Type=oneshot`, `User=` and `Group=`
    the trust owner, `UMask=0027`, `EnvironmentFile=/etc/willow-mcp/manifest-grant.env`,
    `Environment="WILLOW_HOME=$H"`, `Environment="GNUPGHOME=/var/lib/willow-mcp/manifest-grant/gnupg"`,
    `ExecStart=$PY -I -m willow_mcp manifest-grant apply` (`-I`: isolated mode —
    no current directory on `sys.path`, `PYTHON*` variables and the user site
    ignored; Loki pre-deploy audit F4), `NoNewPrivileges=true`,
    `PrivateTmp=true`, `ProtectSystem=strict`, `ProtectHome=read-only`, four
    `ReadWritePaths=` (`$H/manifest_grants`, `$H/mcp_apps`, `$H/constitutional`,
    `/var/lib/willow-mcp/manifest-grant`), `ProtectKernelTunables=true`,
    `ProtectControlGroups=true`, `RestrictSUIDSGID=true`, `LockPersonality=true`.
    So no `ExecStartPre`/`ExecStartPost`/`ExecStop*`/`ExecReload`/`ExecCondition`,
    no second `ExecStart`, no other `Environment`/`EnvironmentFile`.
  - timer: `[Unit]` `Description=`; `[Timer]` `OnBootSec=2min`,
    `OnUnitActiveSec=60s`, optionally `Unit=willow-mcp-manifest-grant.service`
    (and nothing else); `[Install]` `WantedBy=timers.target`.
  - env (committed, and again as rendered): `WILLOW_KEYRING=` and
    `WILLOW_SEAL_RING=` `/etc/willow-mcp/verifiers.public.json`,
    `WILLOW_PG_DB=` (empty in the template, the database name once rendered),
    `WILLOW_PG_USER=` the trust owner, `WILLOW_MCP_STRICT_TRUST_ROOT=1`. No
    other key. The render is plain shell (`mg_render_env`: drop any
    `WILLOW_PGP_FINGERPRINT=` line, set `WILLOW_PG_DB=`), no `sed`, so the
    value read from `$H/env` is never a replacement string; a newline in it
    would render a second line and the allowlist stops it.
  - Because the unit names `$H` (`WILLOW_HOME`, `RequiresMountsFor=`,
    `ReadWritePaths=`) literally, it only validates on a box whose operator is
    the one `install.sh` derives (`SUDO_USER`, default `sean-campbell`); on
    another operator the install stops here instead of installing a unit that
    points at someone else's box.
- **Drift is checked after the install and by `--check`.** Step 4 compares
  what is really in `/etc/systemd/system` and `/etc/willow-mcp` (bytes, owner,
  mode, not a symlink) with what was rendered from HEAD and stops on any
  difference. `--check` prints `[ok] installed unit matches committed HEAD`
  or `[FAIL] installed unit differs from committed HEAD` (and the same for the
  timer and the env), `[info]` for a file not installed yet, and exits 2 on a
  FAIL. A systemd drop-in directory for the unit (`*.service.d/`) is not
  inspected.

## 0a. Provision the trust-owner venv

### Regenerating the hash-pinned files

`trust-venv.requirements.txt` (runtime) and `trust-venv.build-requirements.txt`
(build backend) are generated from the `.in` files beside them, which hold the
same ranges as `pyproject.toml` (`psycopg2-binary`, `cryptography`; and
`[build-system] requires`). Regenerate them on any machine with network
access, from this directory, with [uv](https://docs.astral.sh/uv/):

    cd deploy/manifest-grant
    uv pip compile --generate-hashes --python-version 3.14 \
        --python-platform x86_64-manylinux_2_28 \
        -o trust-venv.requirements.txt trust-venv.requirements.in
    uv pip compile --generate-hashes --python-version 3.14 \
        --python-platform x86_64-manylinux_2_28 \
        -o trust-venv.build-requirements.txt trust-venv.build-requirements.in

(`pip-compile --generate-hashes --allow-unsafe` from pip-tools works the
same.) Regenerating is a **reviewed change**: a hash here is what root and
the trust owner will run, so the diff goes through a pull request like code.
Read it for new packages (the runtime set must stay `psycopg2-binary`,
`cryptography`, `cffi`, `pycparser`), version jumps, and any line that is not
a `name==version` pin or a `--hash=sha256:` entry. The tests fail if a pin
drifts out of the `pyproject.toml` range, a line lacks a hash, or `install.sh`
installs anything not hash-pinned. The files list every release artifact's
hash for the pinned version (wheels for all platforms and the sdist);
`--only-binary=:all:` makes pip refuse the sdist, so nothing is built from
source on the box. Only `pip` itself, which `python -m venv` seeds from the
root-owned system python, is outside the pinned set.

### Privileged steps run only from this venv

`rotate_resign`, `sync_constitutional` and `seed_envelope_ratify` used to be
scripts beside `install.sh`, run with the trust-owner interpreter from the
operator-writable checkout: whoever could edit them got code run as root or
as the trust owner. They now ship in the willow-mcp wheel as
`willow_mcp.install_steps.<name>` and `install.sh` runs them as
`"$PY" -I -m willow_mcp.install_steps.<name>`, so they live in
`/opt/willow-operator/venv` and are covered by the same tree, ACL and
editable checks. The constitutional seed bundle step 1c syncs is read from
the installed package too, not from the checkout. Every interpreter call in
`install.sh` carries `-I` (no current directory, `PYTHON*` variables or user
site on `sys.path`). The venv records the commit it was built from
(`.built-from-head`); a plain install rebuilds it when that is not the
checkout's `HEAD`, so these steps and the bundle always match the commit you
are installing. Commit before you install: an uncommitted edit to the steps
or the bundle is not used. (The steps' docstrings still name their old
`deploy/manifest-grant/` paths; the files are byte-identical to before the
move.)

    sudo bash install.sh --expect-head <sha> --provision-venv     # rebuild only this, then check it
    sudo bash install.sh --expect-head <sha> --check              # dry-run: every [ok]/[FAIL] line, changes nothing

Needs, on the box: `python3.14` with `venv` (Debian/Ubuntu: `python3.14-venv`),
`git`, `acl`, and network access to the package index for the build. The
rebuild is atomic: the new venv is built in a sibling release directory
(`/opt/willow-operator/venv.rel.<random>`, root:root 755, at the path it will
keep), checked in full there, and `/opt/willow-operator/venv` then becomes a
root-owned symlink to it, swapped with a single `renameat2(2)` (the first run on
a box where `venv` is still a real directory exchanges the two in one step).
The unit's `ExecStart=/opt/willow-operator/venv/bin/python` line is unchanged
and the apply timer never sees a missing interpreter; the old venv is deleted
only after the swap and a second check at the live path, and a failed build or
check leaves the live venv untouched. The unit and the rest of the box
are untouched until a plain `sudo bash install.sh --expect-head <sha>` repoints the unit — so the
venv can be audited first. Re-run `--provision-venv` after pulling new
willow-mcp source (a plain install also rebuilds it when its recorded build
commit is not the checkout's `HEAD`). Not exercised off the real box: root, the network build, the
real two-uid run (see the legs list under `--rotate`).

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
  `config/`, `store/`, `mcp_receipt.db`, `vault.db`, `nestor.db`
  itself (never read by the apply half at all now — see the note below).
  **`venvs/` was listed here and is not:** the box shows it `755`,
  `sean-campbell:sean-campbell`, with `user:willow-operator:--x` and
  `other::r-x` (measured 2026-10-11, table above) — enterable and, through
  `other::r-x`, readable by every uid. That is why the trust owner no longer
  uses anything under `$H/venvs/`.

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

    /opt/willow-operator/venv/bin/python -I -m willow_mcp.install_steps.sync_constitutional <venv site-packages>/willow_mcp/bundle/constitutional $H/constitutional

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

    sudo bash install.sh --expect-head <sha> --rotate [--retire FPR ...]

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
    # Rendered from, and installed from, the root-owned clone of the committed
    # HEAD (never the working tree); validated whole first; compared with /etc
    # afterwards. manifest-grant.env, with WILLOW_PG_DB filled in. WILLOW_PGP_FINGERPRINT
    # is NOT rendered here (dispatch 0CB0C85C, dissolving Loki A38D41C2's F8):
    # the trust-owner apply unit reads trust.env directly -- the same file
    # everything else reads -- so there is no second copy of the fingerprint
    # to keep in sync, or to drift, here at all.
    install -o root -g willow-operator -m 640 <rendered manifest-grant.env> /etc/willow-mcp/manifest-grant.env
    install -o root -g root -m 644 <HEAD>/deploy/manifest-grant/willow-mcp-manifest-grant.{service,timer} /etc/systemd/system/
    # then: installed files == the render of HEAD (bytes, root:root 644 /
    # root:willow-operator 640), else STOP
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

## D4: the trust-provisioned marker (rename-away hole, Loki `D06A0EF3`)

Step 6 (and `--rotate`) ends by writing `/etc/willow-mcp/trust-provisioned`,
`root:root 0644`, atomically (temp file beside it, chmod, chown, `mv`), and
only after `trust.env` carries a real 40-hex fingerprint. Two lines:

    willow_home=<realpath of $H>
    trust_owner_uid=<uid of the trust owner>

What it does. Its mere presence tells every reader this `$WILLOW_HOME` has
been provisioned for trust, a fact the broker's uid cannot erase (it is
root-owned, in a root-owned directory chain). With it present and valid:

* `pgp.pgp_enabled()` is True or it RAISES. A missing, unreadable or empty
  `trust.env`, or a `constitutional/` that is not a plain directory owned by
  the trust owner (a rename-away and plant), refuses instead of reading as
  "enforcement off". The gate denies the seat's manifest; the broker refuses
  to start (`refusing to start`, exit 1).
* `paths.trusted_read` drops the own-euid branch for governance inputs: the
  envelope register, the syscall table, the FRANK head anchor and anything
  else read through it must be owned (file and parent) by the trust owner or
  root, and the file must carry a verifying signature. The fleet roster
  (`$H/fleet.json`, broker-owned) keeps the old shape.
* `WILLOW_MCP_APPS_ROOT`, `WILLOW_CHARTER_REPO`, `WILLOW_ENVELOPE_REGISTRY`
  and `WILLOW_SYSCALL_TABLE` are ignored for trust inputs (the default path
  under `$H` is used) with one loud `ERROR` log line per variable per process.
* A process whose `$WILLOW_HOME` realpath differs from the marker's refuses
  trust-sensitive reads, rather than running unenforced.

An invalid marker (symlink, not root-owned, group/other-writable, bad parent,
malformed) is refused, never read as absent. `--check` prints `[ok]` for a
valid marker, `[FAIL]` for an invalid one, and `[info]` when absent.

Removing the marker re-opens the bootstrap fail-open (an absent `trust.env` in
a non-trust-owner `constitutional/` reads as "never provisioned"). Do not
remove it to "fix" an outage; repair the cause.

What it does not close: rollback to an older genuine trust-owner copy,
renaming `$H` or an ancestor, and the outage itself (next step: D1, fd reads
plus a root-owned `(fsid, ino)` record; see the D1 section below). `manifest_grants/` stays in `$H`.

Outage recovery (accepted, operator ruling Q38): if something renames
`constitutional/` away, every PGP reader refuses with an error naming
`D06A0EF3` and the marker. As root: move the planted directory aside, move
the genuine trust-owner-owned `constitutional/` back (or restore it), then
`sudo deploy/manifest-grant/install.sh --check`, and restart the broker.
If only `trust.env` is gone, re-run the install (step 6 rewrites it, then
the marker). Do not edit the marker by hand; install.sh rewrites it.

## D1: the trust-identity record (rename-away hole, option D1, bite 2)

`docs/design/d1-trust-dir-identity.md` is the design. D4 (above) makes a missing
or foreign-owned `constitutional/` a refusal, but it cannot tell WHICH
valid-looking directory it is looking at: a uid-1000 process that owns `$H` can
rename `mcp_apps/` aside and plant a tree carrying copied, genuinely signed
manifests. D1 pins the identity of the containers in a second root-owned file.

**Bite 2 (this section) makes the record exist and keeps it honest. Nothing at
runtime reads it yet** (bites 3 to 5), so a record changes no behaviour of the
broker, the gate or the apply half. What it does change is `install.sh`: three
guards below.

### What the record is

`/etc/willow-mcp/trust-identity`, `root:root 0644`, in the same root-owned
directory chain as the marker, written atomically (temp file beside it, `0644`,
`root:root`, validated by re-parsing, `mv`) by `willow_mcp.install_steps.
trust_identity_record` from the pinned trust-owner venv, so its bytes are exactly
`trust_identity.render_record`'s. Seven `key=value` lines:

    version=1
    willow_home=<realpath of $H>
    home=fsid:<hex> ino:<n> uid:<n> mode:<octal>[ igen:<n>]
    dir.constitutional=fsid:... ino:... uid:... mode:...
    dir.mcp_apps=fsid:... ino:... uid:... mode:...
    dir.manifest_grants=fsid:... ino:... uid:... mode:...
    trust_fingerprint=<the 40-hex trust.env carries>

It is written only AFTER the marker (a record without a valid marker is invalid),
in step 6 of a plain install and after `--rotate`. `mode` of `manifest_grants/`
includes the group bits of the trust owner's `rwx` ACL mask, as `stat` shows
them. It holds directory identities and a public fingerprint, no vault material;
`$H/env`, `vault.db`, `broker_signing_key` and keys are never opened by any of it.

### The first record: audit, then an explicit flag (operator ruling Q-D1-1)

A plain install on a box that has a valid marker and NO record does not write
one. Before step 1 (so before `chown -R` can make a planted tree look genuine) it
prints a **read-only audit** of the box as found, and says so. The first record
is written only when you rerun with `--record-trust-identity` AND that run's
audit is all `[ok]`; if it is not, install.sh stops before step 1 with nothing
written. The audit checks:

| Line | What it checks |
|---|---|
| D4 marker | valid, binds this `$H` and the trust owner's uid |
| `$H` | a plain directory (not a symlink), owned by the operator, not group/other-writable |
| `constitutional/`, `mcp_apps/` | plain directories owned by the trust owner, not group/other-writable |
| `manifest_grants/` and `pending/ done/ failed/` | plain directories owned by the operator, not other-writable (the group bits carry the ACL mask, so they are not flagged) |
| `constitutional/` tree | no symlink or special file; the governed files (`trust.env`, `pre-approved.json`, `syscall-table.json`, `frank_head_anchor.json` and their `.sig`) owned by the trust owner or root, not group/other-writable. Other files there (`review_queue.json`, ...) are listed `[info]`, not failed |
| `mcp_apps/` tree | no symlink or special file anywhere (the seats, `_federation`, `_net_leases`, `_identity_bindings`, `_retired`), every entry trust-owner or root owned and not group/other-writable (the D4.5 gate shape and the F1 lease/binding shape) |
| seats | every `manifest.json` has its `.sig`, parses, and does not declare another seat's `app_id` (D4.5). A manifest with no `app_id` is noted, allowed (Q47) |
| `trust.env` | a regular file naming one 40-hex fingerprint |
| signatures | every governed file verifies under that fingerprint (the `--check-signatures` read, run as the operator) |
| identity found | the `(fsid, inode, uid, mode[, igen])` the record would pin, printed for you to read |

Why a flag and not a typed confirmation for the first record: the first record
protects against a box that is already hijacked when it is recorded, and the
control for that is the audit, which the run enforces itself; the flag is the
operator's consent, per invocation, and works from a non-interactive `sudo`
(a typed prompt would make the plain install interactive). The audit's identity
digest is carried to step 6, which writes only if the inode of `$H` and of each
recorded directory is still what the audit saw. The flag is only for a plain
install; it is refused with `--check`, `--rotate`, `--provision-venv`,
`--check-signatures` and `--re-record-trust-identity`, and on a box with no
valid marker (there is nothing yet to audit before step 1 changes it).

First-write procedure, exactly:

    sudo bash install.sh --expect-head <sha>                          # deploys this commit's venv and installer;
                                                                      # prints the audit and the suggestion; writes no record
    sudo bash install.sh --check --expect-head <sha>                  # prints "[info] trust-identity record absent" and the audit again
    # read the audit. Every line [ok]? Then:
    sudo bash install.sh --record-trust-identity --expect-head <sha>  # audit again, stop if not clean, else the install and the first record
    sudo bash install.sh --check --expect-head <sha>                  # [ok]   trust-identity record valid and matches live

If the audit is not clean, fix what it names (a plain install without the flag
repairs ownership of `mcp_apps/` and `constitutional/` in step 1) and read it
again. A box that failed the audit on something you do not understand is the
case the audit exists for: investigate before recording.

### The pre-check (every plain install and `--rotate` on a recorded box)

With a record present, install.sh compares the live `$H`, `constitutional/`,
`mcp_apps/` and `manifest_grants/` to it BEFORE step 1 (before any `chown -R`,
`setfacl` or `install -d`) and, for `--rotate`, before any key is generated or
anything is re-signed. A difference in `(fsid, inode)`, uid, mode or the
fingerprint, a recorded directory that is gone (never re-created: Q-D1-6), or an
invalid record stops with the diff and the recovery text, nothing changed.
Matching: the run goes on and, at step 6, keeps the record current (an
unchanged box writes nothing; `--rotate` may move only `trust_fingerprint`; a
plain install may move nothing). The `trust_root_setup` hardening sweep
(`apply_trust_root_hardening`, `repair_runtime_permissions`) likewise refuses to
`mkdir` a recorded directory (or a missing parent of one) on a recorded box.

### `--check`

    [ok]   trust-identity record valid and matches live
    [FAIL] trust-identity record differs from the live trust directories      (+ one "- dir: field old -> new" line each)
    [FAIL] trust-identity record is invalid (a recorded box refuses on an invalid record, ...)   (+ the reason)
    [info] trust-identity record absent (run with --record-trust-identity after the audit)

`absent` on a box with a valid marker is followed by the audit (a FAIL there
fails `--check`). `--check` exits 2 on any `[FAIL]`, like the other checks.

### Accepting a changed identity: `--re-record-trust-identity`

The only way. Root, `--expect-head`, the `env -i` re-exec, like every mode; it
never builds the venv. In order, it: (1) shows the live identity and the old
record against it (every changed field), or says the old record is invalid;
(2) runs the same read-only audit (a restored tree must verify under the trust
fingerprint) and stops if it is not clean; (3) asks for a confirmation and, only
on an exact match, writes atomically.

The confirmation is a token, `rr-` and 12 hex of the digest of the exact record
about to be written, so it commits to the diff you were shown and changes with
the inodes. On a terminal you type it at a `/dev/tty` prompt. Without one the
run prints it and exits 3, writing nothing; rerun the same command with
`--confirm <token>`. The token is recomputed from the live tree on that second
run, so a tree that changed in between does not match. This does not stop a
script from running twice; it stops the one-line blind re-record (a pasted
command, a recovery loop) from accepting a state nobody looked at.

    sudo bash install.sh --check-signatures --expect-head <sha>       # first: do the signatures verify?
    sudo bash install.sh --re-record-trust-identity --expect-head <sha>
    # read the diff and the audit; type the token, or rerun with --confirm <token>
    sudo bash install.sh --check --expect-head <sha>

### Recovering from a mismatch outage

A record that stops a plain install or `--rotate` is the design working. Do not
run a plain install to "fix" it, and **never delete `/etc/willow-mcp/
trust-identity`** (that only removes the check; a recorded box with a damaged
or missing record is investigated, not reset).

1. Find out what changed (`--check` prints the diff).
2. A rename-away and plant: as root `mv` the planted directory aside and the
   genuine one back. The same inode matches the record again; no re-record.
3. A restore from backup, an `rsync`/`cp -a`, a moved `$H`, filesystem repair, or
   a damaged record file: verify the tree (`--check-signatures`), then
   `--re-record-trust-identity` above.
4. Do not delete the old directory before re-recording (inode reuse, design
   section 1.1 row 7).

What the guards cannot do: exercise real root, real `/etc` or the real gpg keyring
in the test suite. The commit report records a root run in a sandbox with a fake
trust-owner user and a temporary `$H`.

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
