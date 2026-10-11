# The rename-away hole: options for a root-owned trust root

Contents: §1 The hole, precisely · §2 Why F-C rejected the env-var fix · §3 Options (A root-owned subtree outside `$H`, B root-owned `$H`, C fd and `openat2` checks, D better options) · §4 Comparison · §5 Recommendation · §6 Questions for the operator · §7 Operator rulings

Status: **design options for the operator to rule on. No code, no unit, no install step, no file on the box is changed by this document.** Written 2026-10-11 against `master` at `fd9bbad`. Operator ruling (2026-10-11): "yes" to making this the next design chunk, starting with a design doc with options.

**D4: implemented in 846f97a, pending Loki** (branch `fix/d4-trust-marker`, not pushed; a narrow Loki audit happens before the marker is written on the box). Nothing is deployed by merging: the marker appears only when the operator runs the installer.


Vault rule: `$H` (`/home/sean-campbell/sean-data-vault/willow-operator-box`) is the operator's data-vault box, and the vault is the operator's key. Nothing here reads, moves, rotates, re-keys or adds vault material. The trust-bearing files at issue (`constitutional/`, `mcp_apps/`, `trust.env`) are governance files and a public fingerprint, not key material, but they do sit inside the vault box today. Where an option relocates them, or leaves them where they are but changes who owns the path, §3 says so, and that step is an explicit operator act. The trust owner's GPG keyring is already outside `$H` (`/var/lib/willow-mcp/manifest-grant/gnupg`) and no option touches it. `$H/env`, `$H/vault.db`, `$H/config/`, and `manifest_grants/broker_signing_key` stay exactly where they are in every option.

Evidence labels. **Proven** = read in the code or the installer at the cited line, or stated as a measured live fact by the operator on 2026-10-11. **Inferred** = follows from Proven facts plus Linux semantics but was not executed or traced end to end. I ran nothing on the box.

## §1 The hole, precisely

### §1.1 The mechanism

`$H` is `sean-campbell:sean-campbell` mode 711 (uid 1000, the broker/operator uid), plus the ACL `u:willow-operator:x` that `install.sh` grants (`deploy/manifest-grant/install.sh:1724`). `rename(2)` needs write permission on the parent directory only, not on the entry, so any process running as uid 1000 can `rename $H/constitutional $H/constitutional.aside` and `mkdir $H/constitutional`, whatever the ownership and mode of `constitutional/` itself. The same holds for `mcp_apps/` and `manifest_grants/`, both of which are trust-owner-owned or trust-owner-ACL'd children of a broker-owned parent. Proven: `$H` ownership (live fact) and the installer's own report (`install.sh:1818-1822`); the rename semantics are POSIX.

Who can do this: any process on the host running as uid 1000 and not inside the Kart sandbox: the operator shell, willow-bot, the desk, the broker (`run_mcp.sh`), any agent CLI. Kart tasks bind `$H/willow-bot`, `constitutional`, `nestor.db` read-only and overlay `mcp_apps` read-only, so a Kart task cannot rename them (live fact; Inferred that a read-only bind of a child does not stop a rename of the child inside a writable parent, but `$H` itself is not bound writable into Kart, so the parent is unwritable there).

A second, stronger form: every ancestor of `$H` (`/home/sean-campbell/sean-data-vault/`, `/home/sean-campbell/`) is under the same uid's home. Inferred (the path is under sean-campbell's home; I did not stat the ancestors): uid 1000 can rename `$H` itself, or an ancestor, and plant a whole replacement box. This matters for the options: any fix that keeps the trust path under `$H` and does not check against something outside the broker's tree is bypassed one level up.

### §1.2 Read paths that the trust owner or the broker believes

| # | Read | Where (file:line) | What it believes | Evidence |
|---|---|---|---|---|
| H1 | `WILLOW_PGP_FINGERPRINT` from `$H/constitutional/trust.env` | `pgp.py:232` `_read_trust_config_fingerprint`, path from `paths.py:218` `trust_config_path` | If `trust.env` is absent and `constitutional/` is not trust-owner-owned, the answer is `""` (enforcement off). | Proven |
| H2 | "Provisioned?" probe | `pgp.py:200` `_trust_config_dir_already_provisioned`: `dir_path.stat().st_uid == trust_owner_uid` | A planted broker-owned `constitutional/` returns `False`, which is read as "never provisioned here, legitimate bootstrap", so H1 returns `""` and `pgp_enabled()` (`pgp.py:390`) is False. It does not raise. | Proven |
| H3 | Seat manifests | `gate.py:747-785` `_read_manifest`; signature checked only `if pgp.pgp_enabled()` (`gate.py:776-777`) | With enforcement off (H2), any `mcp_apps/<app>/manifest.json` that parses is accepted. | Proven |
| H4 | Envelope register, syscall table | `envelopes.py:~39` `_load` -> `paths.py:21` `trusted_read`; also `constitutional.py:114` `_load_live`, `frank_head_anchor.py:86` | `trusted_read` accepts a file and parent owned by the caller's own euid with no group/other write bit. The signature branch applies only to files owned by the trust owner. A broker-planted register is broker-owned, so it passes in a broker process. In a trust-owner process (euid `willow-operator`) the same planted tree is refused (parent uid is neither euid nor trust owner). | Proven |
| H5 | Trust-config ownership check | `pgp.py:98` `_trust_config_ownership_ok` | Rejects a broker-owned `trust.env` when a trust owner resolves, so the broker cannot plant its own fingerprint file. The hole is not "swap in a different fingerprint"; it is "make the file not exist where the probe cannot tell". | Proven |
| H6 | Trust-owner apply | unit `ReadWritePaths=` for `manifest_grants`, `mcp_apps`, `constitutional` (`willow-mcp-manifest-grant.service:81-83`); executor `_grants_root` (`manifest_grant_executor.py:965-969`) uses `paths.willow_home() / "manifest_grants"` | Applies by path. A planted `mcp_apps/` or `manifest_grants/` owned by uid 1000 is not writable by the trust owner without a permission change by the broker (which the broker can make on its own planted dir). | Proven (paths); Inferred (outcome) |
| H7 | Root override levers | `paths.py:541-545` `mcp_apps_root` honours `WILLOW_MCP_APPS_ROOT`; `paths.py:599-604` `constitutional_dir` honours `WILLOW_CHARTER_REPO`; `envelopes.py:23` honours `WILLOW_ENVELOPE_REGISTRY` | Same class as the lever F-C removed from `trust.env`: an env var steers where trust inputs are read from. | Proven (they exist); whether any process's env can be set by an attacker is out of scope here |

### §1.3 What an attacker achieves

| Goal | How | Result | Evidence |
|---|---|---|---|
| Turn PGP enforcement off for every reader on the box | Rename `constitutional/` aside, `mkdir constitutional` (broker-owned) | H2 -> `""`; `pgp_enabled()` False for the broker, desk, and (because the check keys off the directory owner) the trust-owner process too | Proven (code); the live run is Inferred |
| Forge seat manifests | After the step above, rename `mcp_apps/` aside and plant `mcp_apps/<seat>/manifest.json` with any permissions, unsigned | H3 accepts it. Forged grants (for example `groups` for a seat) without any human ruling | Proven chain; Inferred end to end |
| Forge the envelope register or syscall table in a broker process | Plant `constitutional/pre-approved.json` owned by the broker | `trusted_read` euid branch accepts it (H4). The trust owner's own `trusted_read` refuses it | Proven |
| Forge manifests while trust.env is intact | Plant an unsigned or self-signed manifest in a renamed `mcp_apps/` | Refused: `verify_detached` checks against the fingerprint in `trust.env` and the broker holds no private key for it. Nothing forged gets through | Proven (`gate.py:776-777`, `pgp.py:540-600`) |
| Roll back to older genuine state | Rename the current `mcp_apps/` aside, rename an older genuine trust-owner-owned copy back (if one exists, for example from a prior rename-aside) | Old signed manifests verify. There is no freshness or version binding in the detached-signature check I read | Inferred (I did not look for a monotonic counter) |
| Move a signed manifest between seats | With `mcp_apps/` renamed, copy `A/manifest.json` + `.sig` to `B/` | Verifies if nothing in the manifest binds it to its directory name | Inferred; not traced (does the gate compare `data["app_id"]` to the directory?) |
| Make the trust owner apply grants to the wrong tree | Plant `manifest_grants/` and `mcp_apps/` with permissive ACLs for `willow-operator` | The trust-owner unit would write manifests into a broker-controlled tree. It still re-verifies the seal and the FRANK citation against Nestor and the ledger (`manifest_grant_executor.py:1202-1265`), so a forged request needs a ruling that exists. The broker's request signature is an audit trail, not a boundary (module note, `manifest_grant_executor.py:36-60`) | Inferred; the apply path was not traced end to end |
| Denial of service | Rename anything aside | Every reader fails closed or errors. This costs the operator a recovery, not a compromise | Proven for the paths above |

### §1.4 What the existing GPG signing already covers, and where it stops

Detached signatures make manifest forgery impossible only while `trust.env` is intact and trusted. Every forgery path above runs through H1/H2 first (disable enforcement), or through replay of genuinely signed bytes. So, honestly:

* `mcp_apps/` rename-away alone is harmless for forgery and harmful only for rollback and cross-seat replay (both Inferred). The hole is carried by `constitutional/`.
* `constitutional/` rename-away is the fail-open: the "absent means off" semantics (`pgp.py:232-262`) were an install-bootstrap convenience and are now an attacker's switch.
* `trusted_read`'s own-euid branch (`paths.py:62`) means a broker process believes a broker-planted governance file, so signing does not protect that read.

## §2 Why F-C rejected the env-var fix

Source: `deploy/manifest-grant/INSTALL.md:96-134`, `paths.py:218-266`, `pgp.py:200-262`, `install.sh:420-440, 1802-1825`.

| Step | What happened |
|---|---|
| Rework #3 (dispatch `FA4F79AC`) | Operator: "it should be in the vault with the rest of the keys". `trust.env` was routed through `WILLOW_VAULT_BOX` (`operator_secrets_root()`). |
| Loki audit `23DE8AA9`, finding F-C (dispatch `10F9E837`, rework #4) | `WILLOW_VAULT_BOX` is read from `os.environ` of the broker's own process, so it is a second lever on top of the file's own ownership and signature checks. Worse, `install.sh` (root's stripped `sudo` env) and the broker (its own env) could disagree on which file is authoritative, so the installer writes one `trust.env` while a broker reads another. The doc's own "module constant" claim was false. |
| Result | Reverted: `trust.env` is `$WILLOW_HOME/constitutional/trust.env` only (`paths.py:266`), and `install.sh` mirrors it (`install.sh:439`). |
| What F-C did not say | That the location is wrong, only that an env-var-chosen location cannot deliver the property. The property needed: "which file decides what this box trusts" has a root-chosen single answer that no process the attacker controls can steer or recreate. Loki's own alternative (`D06A0EF3`) was a root-owned `/etc/willow-mcp/trust.env`. |
| Standing constraint | Closing the hole needs `$WILLOW_HOME`, or the trust inputs' resolution, to point at a root-provisioned location outside the broker's writable tree, set once outside any single process's env. Not a second variable. |

H7 shows the same class of lever still exists for `mcp_apps` and the register (`WILLOW_MCP_APPS_ROOT`, `WILLOW_CHARTER_REPO`, `WILLOW_ENVELOPE_REGISTRY`). Whichever option is chosen should say what happens to them on a provisioned box (see Q5).

## §3 Options

Common facts used below. uid 1000 = broker/operator/bot/desk. `willow-operator` = trust owner (uid 994 per the installer comment). Kart sandbox binds are in `kart-sandbox.json` on the box. "Operator acts" are root or operator steps on the live box, in order. Sizes are rough: S under a day of code and tests, M a few days, L a week or more.

### §3.A Root-owned trust subtree outside `$H`

**Idea.** Move the three trust-bearing trees out of the broker's writable tree and read them from a fixed, root-provisioned path.

| Item | Statement |
|---|---|
| What moves where | `$H/constitutional/` -> `/var/lib/willow-mcp/trust/constitutional/` (includes `trust.env`, `pre-approved.json`, `syscall-table.json` and their `.sig`). `$H/mcp_apps/` -> `/var/lib/willow-mcp/trust/mcp_apps/`. `$H/manifest_grants/` is **not** moved in the first form (see "manifest_grants" below). `$H/proposals/` stays broker-owned in `$H` (already a sibling by design, `paths.py:envelope_proposals_dir`). |
| Ownership | `/var/lib/willow-mcp/trust` `root:root 755`. `constitutional/` and `mcp_apps/` `willow-operator:willow-operator 755`, files 644 (what `install.sh` already makes them, `install.sh:1727-1728, 1795-1799`). `.../trust/` itself is root-owned so neither uid 1000 nor `willow-operator` can rename `constitutional` or `mcp_apps` (the trust owner can rewrite inside, not rename the children). |
| Path resolution | A fixed root-provisioned path, never an env var. Two forms: (1) compiled in as a module constant in `paths.py`; (2) read from `/etc/willow-mcp/paths.conf` (`root:root 644`), which a reader opens only after checking its own owner/mode and its ancestors (root-owned, not group/other-writable, no symlink). Form (2) lets the box choose its path without a rebuild; form (1) removes a file to get wrong. Both fall back to `$WILLOW_HOME/...` only when the root-owned marker is absent (single-uid dev boxes, CI, tests). The marker lives in `/etc`, which uid 1000 cannot edit, so its presence is not something the broker can remove. |
| Reads and writes after | Broker, bot, desk: read `trust/` (world-readable; they already read manifests and the register). They cannot write or rename anything there. Trust owner: writes inside `constitutional/` and `mcp_apps/` (the apply half, `rotate_resign`, `sync_constitutional`, `seed_envelope_ratify`). Kart: sees whatever the Kart config binds; repoint the binds to the new paths read-only. |
| Code changes | `src/willow_mcp/paths.py` (`mcp_apps_root`, `constitutional_dir`, `trust_config_path`, a new `trust_root()`); `pgp.py` (`_trust_config_dir_already_provisioned`: with the marker present, "absent" and "not trust-owned" both raise, never `""`); `paths.py` `trusted_read` (marker present: no own-euid branch for governance inputs); `deploy/manifest-grant/install.sh` (step 1 targets, `TRUST_ENV`, the `H_UID` NOTE becomes a real check); unit `ReadWritePaths=` (`willow-mcp-manifest-grant.service:81-83`) and `mg_line` allowlist; `trust_root_setup.py` (it assumes the trust dirs are under `willow_home()`, lines 96-130); `build_lease.py:75`, `mcp_federation.py:361`, `sandbox_confirm.py:203`, `server.py:8082`, `registry.py:159` follow `paths.mcp_apps_root()` and need no change if that function changes; `tests/test_manifest_grant_deploy.py`, `tests/test_pgp_fingerprint_source.py` and fixtures that build a fake `$WILLOW_HOME`. |
| Operator migration (in order) | 1. Land the code and the installer with the old path still honoured (marker absent), release. 2. Stop the serve unit, the grant timer, and the desk sessions that read the trust tree. 3. As root, `install -d -m 755 -o root -g root /var/lib/willow-mcp/trust`. 4. `cp -a` (not `mv`) `$H/constitutional` and `$H/mcp_apps` into it, preserving owner and mode. 5. Run `install.sh --check-signatures` against the new tree to prove every signature still verifies under `trust.env`. 6. Write the marker (`/etc/willow-mcp/paths.conf`). 7. Restart the units. 8. Only after a clean `--check` and a soak: rename the old `$H/constitutional` and `$H/mcp_apps` to `*.moved-<date>` and later remove them. Vault note: step 4 copies governance files out of the vault box; step 8 removes the old copies. Both are operator acts and neither touches key material. This also reverses the placement the operator asked for in `FA4F79AC` ("in the vault with the rest of the keys"), so it needs an explicit ruling (Q1). |
| Rollback | Delete the marker; readers fall back to `$H`. The old directories are kept until step 8, so up to then rollback is one `rm`. After step 8, `cp -a` back. |
| Kart effect | Kart's `bind_ro` entries for `constitutional` and the `mcp_apps` overlay change source to `/var/lib/willow-mcp/trust/...` while still presenting the same in-sandbox path if the Kart config supports a different source and target (Inferred; the config shape was not read). `manifest_grants/`, `config/`, `env` stay unbound. |
| D2 (venvs into the bot) | Orthogonal. Neither moves `$H/venvs`. The venv containment root in `pip_sync_executor.py`/`package_upgrade_executor.py` (d2 §2) does not read the trust tree. A smaller interaction: the d2 plan's `trust_root_setup` tighten-sweep must be taught the new root or it will sweep the wrong directory. |
| manifest_grants | Left in `$H` in this form. The broker legitimately writes `manifest_grants/pending/` and holds `broker_signing_key` there, so it cannot become root-owned without a split. Rename-away on it is DoS plus Inferred forged requests, and the apply half re-verifies the seal against Nestor and the ledger, so I do not rate it part of the fail-open. A later split (root/trust-owned parent, broker-writable `pending/` child) is possible and not required for the fail-open. The signing key stays where it is either way. |
| Risk | Medium. Trust-owner write paths and Kart binds are path-based in several places; a missed one fails closed (the apply or sync step errors) rather than open. Moving the files is the only vault-adjacent act. |
| Size | **M-L** (about 8 source files, installer, unit, tests; one migration). |
| Closes the hole | Fully for `constitutional/` and `mcp_apps/`, including the "rename `$H` or an ancestor" form, because the readers no longer look under `$H` for trust at all. |

### §3.B Make `$H` itself root-owned with carve-outs

| Item | Statement |
|---|---|
| What moves where | Nothing moves. `$H` becomes `root:willow-operator 711` (or similar); `constitutional/`, `mcp_apps/` stay trust-owner-owned; each directory the broker needs gets `chown sean-campbell` as a carve-out child. |
| What the broker/bot/desk lose | The right to create or rename any top-level entry of `$H`. From the installer and INSTALL.md the broker writes directly under `$H`: `nestor.db` and its `-wal`/`-shm`/journal files, `nestor.db.ledger.jsonl`, `consent.json`, `settings.global.json`, `env` (edited by the operator), `mcp_receipt.db`, `vault.db`, plus whole subtrees (`handoffs/`, `dispatch/`, `deposits/`, `gitsync/`, `willow-bot/`, `store/`, `config/`, `proposals/`, `manifest_grants/`, `worker_heartbeat/`, `venvs/`). SQLite needs to create sibling journal files in the database's directory, so `nestor.db` and `vault.db` would each need to move into a carve-out directory, which moves vault material. Every new top-level file or directory any tool adds in future breaks. Operator shell work at the box root (the operator is uid 1000) also needs root. |
| Operator migration | Enumerate and carve out every top-level entry; move the SQLite databases into subdirectories (a vault-material move: explicit operator act); change path code for each moved file; `chown root $H`; rework `install.sh` step 1 (which today runs `install -d -o $OPERATOR` and `setfacl` at `$H`). |
| Code changes | Every `willow_home() / "x.db"` style path for moved files (many; I did not enumerate, grep `willow_home()` across `src/` is the starting point); `install.sh`; `home_init.py`; `trust_root_setup.py`. |
| Rollback | `chown` `$H` back to uid 1000 (the carve-out directories keep working). Moved databases need moving back. |
| Kart / D2 | Kart binds are path-based and would break wherever a file moved. D2 (`willow-bot/venvs`) is under a carve-out, so it survives; `$H/venvs/` legacy would need its own carve-out. |
| Does it close the hole | Only for entries directly under `$H`. It does nothing about `$H` itself being renamed one level up (`sean-data-vault/` is under the operator's home). Closing that needs the box path to move under a root-owned parent, which is Option A with extra steps. |
| Risk | High. Wide blast radius, and a vault-material move is the entry price. |
| Size | **L**, and the broadest regression surface of the four. |

### §3.C Verify by file descriptor and `openat2`, move nothing

| Item | Statement |
|---|---|
| What changes | Readers (`trusted_read`, `pgp._read_trust_config_fingerprint`, `gate._read_manifest`, the trust-owner apply) open the trust inputs with `openat2(2)` using `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, hold the file descriptor, `fstat` it, and verify owner/mode on the descriptor and on every parent via `fstat` of descriptors opened component by component (`O_PATH|O_DIRECTORY|O_NOFOLLOW`). Reads happen from the descriptor, never by re-opening the path. Python 3.14 has no `openat2` wrapper; it needs `ctypes` or `os.open` with `dir_fd` and `O_NOFOLLOW` per component (a portable equivalent of `RESOLVE_NO_SYMLINKS`). `RESOLVE_BENEATH` is Linux 5.6+; the box kernel was not checked. |
| What it closes | Precisely: **symlink substitution and TOCTOU between check and use**. `trusted_read` today checks `path.is_symlink()` and `stat()` and later `read_text()` by path, so a swap between the check and the read is possible (Proven by reading `paths.py:50-70` plus `envelopes.py:~39-41`, where the read is a separate call). With descriptors that window closes. |
| What it does not close | **Rename-away.** After `constitutional/` is renamed aside and a fresh directory planted, every component still resolves cleanly, with no symlink, in the new tree. The descriptor then names the *planted* directory, which is broker-owned, and the check says "owner is not the trust owner". That is exactly the probe H2 already makes. The problem is not that the check is racy; it is what a failed check *means* (`""`, unprovisioned). C alone does not change that meaning, because a reader has no persistent record outside the broker's tree that this box was ever provisioned. A reader cannot tell "never provisioned" from "attacker replaced it". |
| TOCTOU, precisely | C removes check-then-open races within one read. It does not remove "the directory was swapped before the read started" and it does not remove "swapped back after". |
| Code changes | `paths.py`, `pgp.py`, `gate.py`, `envelopes.py`, `constitutional.py`, `frank_head_anchor.py`, the install steps. About 6-8 files. |
| Operator effort | None on the box (code only). |
| Risk / Size | Low risk, **M**. Valuable as hardening, insufficient as the fix. |
| Closes the hole | No. Symlink and race only. See D1 for what has to be added to make it close. |

### §3.D Better options

#### D1. C plus a root-owned identity record (no files move)

Record, in a root-owned file `/etc/willow-mcp/trust-anchor.conf` (`root:root 644`), the identity of each trust directory as it stands on the box: `(st_dev, st_ino, uid)` for `$H/constitutional` and `$H/mcp_apps`, written by `install.sh` as root after step 1. Readers (with C's descriptor discipline) open the directory, `fstat` it, and compare `(dev, ino)` to the record. A planted directory has a different inode, so it is refused. The presence of the `/etc` record also changes what "absent or not trust-owned" means: with a record, it is a refusal, never `""`.

| Item | Statement |
|---|---|
| What moves | Nothing. |
| Ownership | Record is root-owned. `$H` unchanged. |
| Closes | The fail-open (enforcement off), the forged-register read in a broker process, and planting generally: all become fail-closed refusals. The broker can still rename the real directory away, which is DoS. Rolling back to an older genuine trust-owned copy also fails, because its inode differs from the record. |
| Does not close | Denial of service. Recovery requires root to re-record after a legitimate change (restore from backup, filesystem copy, `cp -a`), because inode numbers do not survive those. `(st_dev, st_ino)` is brittle across a filesystem migration, a btrfs subvolume swap, or a `rsync` of the vault box. Inode reuse is a theoretical risk only while the original is still on disk (it is, if renamed aside). |
| Code | C (M) + a record reader + an `install.sh` step that writes it + the `--check` line + tests: **M**. |
| Operator migration | Land code (record absent, behaviour unchanged). As root: run the installer's new record step, then the new marker means refuse-on-absent. Rollback: delete the record. |
| Kart / D2 | No change: no path moves. |
| Vault | Reads `stat` of two governance directories. No vault material touched. |

#### D2. Bind-mount a root-provisioned directory over the trust paths (systemd mount unit)

Backing store: `/var/lib/willow-mcp/trust/{constitutional,mcp_apps}` as in Option A, but `$H/constitutional` and `$H/mcp_apps` stay as the **mount points**, so no consumer's path changes (Kart binds, unit `ReadWritePaths=`, desk, `WILLOW_HOME` contract all keep working). A mount point cannot be renamed or removed (`rename(2)` returns `EBUSY`; Inferred from POSIX and Linux behaviour, not tested here) and uid 1000 cannot unmount (needs `CAP_SYS_ADMIN` in the host mount namespace; an unprivileged user namespace changes only that process's own view).

| Item | Statement |
|---|---|
| What moves | Backing files `cp -a` to `/var/lib/willow-mcp/trust/`, then `mount --bind` over the existing directories via `*.mount` units (`Where=$H/constitutional`, `What=/var/lib/...`), `RequiresMountsFor=` on the consumers. The original contents under the mount points are shadowed, not deleted. |
| Ownership | As in Option A for the backing directories; the mount point directories stay broker-owned empty shells. |
| Limit that matters | Renaming an **ancestor** of a mount point is allowed. uid 1000 can still rename `$H` (or `sean-data-vault/`) and plant a whole replacement tree with no mounts and no fingerprint. So D2 alone does not close the hole at the `$H` level, and an unmounted mount point looks like an empty broker-owned directory ("never provisioned") to the current readers. |
| Fix for that limit | Add one reader check that does not depend on the path under `$H`: with the root-owned marker present, `fstat` the directory at `$WILLOW_HOME/constitutional` and compare `(st_dev, st_ino)` to the backing directory's `(st_dev, st_ino)` (a bind mount presents the source's identity). A planted tree fails the comparison; the marker's presence makes the failure a refusal. This is D1's check made self-maintaining: the record is the live backing directory, so a legitimate restore does not need a re-record, and a bind mount survives `cp`/`rsync` of the vault box because the source is not in the vault box. |
| Code | One check in `paths.py`/`pgp.py` (the identity comparison, ~40 lines + tests), the marker, `install.sh` writes the mount units and the marker. Considerably less than A because no path constants move: **M**. |
| Operator migration | Steps 1-5 of A (copy, verify signatures), then install the mount units, `systemctl daemon-reload`, start the mounts, restart consumers, write the marker. Rollback: stop and disable the mounts (the shadowed original contents reappear unchanged), delete the marker. |
| Kart | Kart binds the same in-sandbox path; `bwrap` bind of a path that is itself a bind mount works (Inferred). |
| D2 (venvs) | No interaction. |
| Risk | Boot ordering (consumers must wait on the mounts; a missing mount shows an empty directory, which the marker check turns into a refusal rather than an open door), and `$H` on a vault filesystem that squashes ownership is not involved because the backing is on the root filesystem. |
| Vault | The mount shadows part of the vault box; governance files are copied out of it. A deliberate operator act. Nothing is moved, re-keyed or deleted until the operator removes the shadowed originals. |

#### D3. Sticky bit on `$H` (rejected)

`chmod +t $H` stops a user deleting or renaming entries they do not own. `constitutional/` and `mcp_apps/` are owned by `willow-operator`, so uid 1000 could no longer rename them. But the broker owns `$H` itself, and the sticky bit applies to non-owners of the *entry*: the owner of the directory may remove or rename any entry in it (`rename(2)` / `unlink(2)` sticky semantics: allowed if the caller owns the file *or the directory*). So sticky does nothing against the directory's owner, which is uid 1000. It would work if `$H` were root-owned (Option B) or on a root-owned intermediate parent (Option A). Rejected as a stand-alone fix.

#### D4. Do the existing GPG signing and a stronger "provisioned" rule suffice? (partial, honest)

This is the cheapest bite and the one the analysis in §1.4 points to.

| Item | Statement |
|---|---|
| Change | Make "provisioned" a fact that lives where the broker cannot erase it: a root-owned marker `/etc/willow-mcp/trust-provisioned` (empty or one line) written by `install.sh` as root. With it present: `pgp._read_trust_config_fingerprint` raises when `trust.env` is absent or its directory is not trust-owner-owned (never `""`); `paths.trusted_read` drops the own-euid branch for governance inputs and requires trust-owner ownership plus signature. |
| Closes | The fail-open and the forged-register read: both become refusals. Forgery of manifests is already impossible while `trust.env` is intact (§1.3), and now `trust.env` cannot be made to disappear silently. |
| Does not close | Rollback to an older genuine trust-owner-owned directory; cross-seat replay of signed manifests (Inferred, not traced); DoS. |
| Moves | Nothing. Vault untouched. |
| Code | `pgp.py`, `paths.py`, `install.sh` (write the marker, make the NOTE at line 1818 report it), tests: **S**. |
| Why it is not the whole answer | An attacker who cannot make the box trust something false can still make it trust something *old*, and can still take the box down. |

## §4 Comparison

| | A. Root-owned subtree outside `$H` | B. Root-owned `$H` | C. fd + `openat2` only | D1. C + `/etc` identity record | D2. Bind mount + identity check | D4. Root marker, fail closed |
|---|---|---|---|---|---|---|
| Closes enforcement-off fail-open | Yes | Yes (for top-level entries) | **No** | Yes | Yes | Yes |
| Closes forged register / planted `constitutional/` | Yes | Yes | **No** | Yes | Yes | Yes |
| Closes rollback to older genuine copy | Yes | Yes | No | Yes (inode differs) | Yes | **No** |
| Closes rename of `$H` or an ancestor | Yes | **No** | No | Yes (identity compare) | Yes (with the check) | Yes (marker forces refusal) |
| Leaves DoS by rename | No (cannot rename) | No | n/a | **Yes** (fail-closed) | No (mount point) | **Yes** (fail-closed) |
| Closes symlink / check-then-use races | Not by itself | Not by itself | Yes | Yes | Yes | No |
| Operator effort | High: copy, verify, marker, restart, retire old | Very high | None | Low-medium: one root step, re-record after restores | Medium: copy, mount units, marker | Low: one root file |
| Code size | M-L | L | M | M | M | S |
| What it breaks | Path-based trust-owner writes and Kart binds if missed | Everything that writes under `$H` | Nothing visible | Restores and rsync invalidate the record until re-recorded | Boot ordering if mounts are not awaited | Dev/CI boxes if they ever have the marker; none otherwise |
| Vault impact | Governance files copied out of the vault box; operator act; reverses the "in the vault" wording | Moves the two SQLite databases (vault material) | None | None (reads `stat`) | Governance files copied out; the originals shadowed | None |

## §5 Recommendation

**Staged: D4 now, then D1 (fd-based reads plus a root-owned `(dev, ino)` record). A and D2 are out by operator ruling Q36 ("keep them in the vault box").** The original text below recommended D2 as the second bite; that rests on moving the backing store out of the vault box, which the ruling excludes. Confidence: **68%** that this ordering is the right one for this box (the uncertainty is mostly the unmeasured bits: the Kart config shape, whether `RESOLVE_BENEATH` matters at all if D2 lands, and whether the operator wants the files physically out of the vault box, in which case A is the answer and the others are stepping stones).

Why.

* The measured fail-open is in the *meaning of absent* (`pgp.py:232-262`) and in `trusted_read`'s own-euid branch (`paths.py:62`). Both are fixable by a fact the broker cannot erase. That fact is a root-owned `/etc` marker. This is a small, reversible code change that moves nothing.
* It does not fix rollback or the "rename an ancestor" form of the attack; D2's identity comparison does, without changing any consumer's path, so Kart binds, `ReadWritePaths=`, `WILLOW_HOME` and the desk keep working. A requires all of them to change.
* B is the wrong tool: it breaks the broker and does not cover ancestors.
* C is worth doing later as hardening, but on its own it solves a different problem (races, symlinks).

**Smallest first bite (D4, size S).**

1. `install.sh` as root writes `/etc/willow-mcp/trust-provisioned` after step 1 (`root:root 644`), and its NOTE at `install.sh:1818` reports the marker rather than the current "NOT closed" text for the fail-open half (the NOTE keeps saying that rollback and ancestor-rename remain until D2).
2. With the marker present, `pgp._read_trust_config_fingerprint` raises `PgpSourceUnreadable` when `trust.env` is absent or `constitutional/` is not trust-owner-owned.
3. With the marker present, `paths.trusted_read` requires trust-owner ownership plus signature for governance inputs (no own-euid branch).
4. Tests: planted `constitutional/` in a tmp `$WILLOW_HOME` with the marker (fake marker path via the same hook the tests already use for `trust_config_path`, never an env var in production) -> refusal.

No vault material moves. Nothing is deployed by merging that change; the marker appears only when the operator runs the installer.

Honest note on the second bite: D2 puts the trust files' backing store outside the vault box. If the operator would rather keep it as a pure check with nothing copied, D1 (identity record) is the option with no relocation, at the price of re-recording after restores.

## §6 Questions for the operator

Rulings needed.

1. **Location (vault wording).** `FA4F79AC` said the trust file belongs "in the vault with the rest of the keys". Options A and D2 put the backing governance files under `/var/lib/willow-mcp/trust/` and shadow or remove the copies in the vault box. Is that acceptable, or must `constitutional/` and `mcp_apps/` physically stay in the vault box (then D4 plus D1 only)? Trust.env is a public fingerprint, not a key.
2. **First bite.** Approve D4 (root marker, fail closed, nothing moves) as the next change on its own?
3. **Second bite.** After D4, do you want D2 (bind mount plus identity check), D1 (identity record, nothing moves), or A (relocate the readers to a fixed root path)?
4. **Denial of service.** D1 and D4 make a rename-away a fail-closed outage that a root re-provision fixes. Is that acceptable, versus D2/A where the rename cannot happen?
5. **Env levers.** On a provisioned box (marker present), should `WILLOW_MCP_APPS_ROOT`, `WILLOW_CHARTER_REPO` and `WILLOW_ENVELOPE_REGISTRY` be ignored for the trust inputs, with a loud log line if set? This is the same class as F-C.
6. **manifest_grants.** Leave in `$H` (my recommendation; the broker writes `pending/` and holds `broker_signing_key` there), or schedule a later split with a root/trust-owner parent and a broker-writable `pending/`?
7. **Loki.** Should the D4 change get a narrow Loki audit before the marker is written on the box (it changes what "absent" means for every PGP reader), as Q13's venv change did?
8. **Unverified items to settle by reading, before D2/A.** The kernel version (for `openat2`), the Kart config's source-versus-target binding shape, whether the gate compares a manifest's `app_id` to its directory (cross-seat replay), and whether any freshness binding exists on signed manifests. I did not run any of these.

## §7 Operator rulings (2026-10-11)

| Q | Ruling |
|---|---|
| Q35 | D4 approved, dispatch. A narrow Loki audit happens before the marker is written on the box. |
| Q36 | "keep them in the vault box". `constitutional/` and `mcp_apps/` physically stay in `$H`. That rules out option A and the D2 backing-store move. The follow-on after D4 is D1 (fd-based reads plus a root-owned `(dev, ino)` record). |
| Q37 | On a provisioned box, `WILLOW_MCP_APPS_ROOT`, `WILLOW_CHARTER_REPO` and `WILLOW_ENVELOPE_REGISTRY` are ignored for trust inputs, with a loud log line (once per process per variable) if set. Implemented, and extended to `WILLOW_SYSCALL_TABLE` (same class; steers the syscall table). |
| Q38 | A fail-closed outage on rename-away is acceptable for now. |
| Q39 | `manifest_grants/` stays in `$H` for now. |

Q36 was open when this document was written; the ruling above settles it and supersedes the Q36 wording in §6 item 1.
