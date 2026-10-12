# D1: fd-based reads and a root-owned identity record for the trust directories

Contents: §1 What D1 adds over D4 · §2 The record · §3 The read path · §4 Failure modes and recovery · §5 Interaction · §6 Bites · §7 Risks and open questions

Status: **design for the operator to rule on. No code, no unit, no install step and no file on the box is changed by this document.** It is option D1 of `docs/design/rename-away-hole.md` (§3.D, §5) worked into a buildable design. Written 2026-10-11 against `master` at `2ef4419`.

Rulings in force (rename-away-hole.md §7, and the operator's later word): Q36 `constitutional/` and `mcp_apps/` stay in the vault box `$H`. Q38 a fail-closed outage on rename-away is acceptable. Q39 `manifest_grants/` stays in `$H`. D4 (the root-owned marker `/etc/willow-mcp/trust-provisioned`) is deployed (`2ef4419`, Loki VERIFIED 92%). The trust-owner interpreter is `/opt/willow-operator/venv`, installed only through `install.sh --expect-head <sha>`.

Vault rule: nothing here reads, moves, rotates or adds vault material. The record is one new file in `/etc/willow-mcp/`, written by root, holding directory identities and a public fingerprint. `$H/env`, `$H/vault.db`, `broker_signing_key` and the trust owner's keyring are not touched.

Evidence labels. **Proven** = read in code or installer at the cited line. **Inferred** = follows from Proven facts plus Linux semantics, not executed. Percentages mark guesses. I ran nothing on the box; the kernel version and Kart's bwrap arguments were not read.

## §1 What D1 adds over D4

D4 changed what a failed check *means* for `constitutional/` (`pgp.py:249` `_require_provisioned_shape`, `trust_marker.py:162` `active_marker`). It did not give any reader a way to tell *which* trust-owner-owned or valid-looking directory it is looking at.

### §1.1 The gap D4 leaves, in order of weight

| # | Attack on a D4 box | Why D4 does not stop it | Evidence | D1 |
|---|---|---|---|---|
| 1 | **Planted `mcp_apps/` carrying copied genuine signed manifests.** uid 1000 renames `mcp_apps/` aside, `mkdir`s its own, copies `<seat>/manifest.json` + `.sig` bytes it read earlier (644, world-readable) | `gate._read_manifest` (`gate.py:747-803`) checks `manifest_path.exists()`, `json.loads`, then `pgp.verify_detached`. No ownership check on `mcp_apps/`, its children or the files. The signature verifies because `trust.env` is intact | Proven (code); Inferred end to end | **Closes** (the planted dir's inode is not the recorded one) |
| 2 | **Rollback.** The same planted `mcp_apps/` holds an *older* signed manifest (a seat's former, wider permissions) | Detached signatures carry no freshness; no counter in `verify_detached` (`pgp.py:628`) | Proven (no counter in what I read); Inferred that none exists elsewhere | **Closes** |
| 3 | **Cross-seat replay.** Copy `A/manifest.json` + `.sig` to `B/` in the planted tree | `_read_manifest` never compares the manifest's own `app_id` to the directory name (no such comparison in `gate.py:747-803`) | Proven (absence in the function); Inferred (not searched repo-wide) | **Closes** via the planted tree (1). Inside the genuine tree only the trust owner can copy, so it is not an attack there. A separate hardening (compare `app_id` to the directory) is a different bite and is not D1 |
| 4 | **Genuine older trust-owner-owned directory renamed back.** The rename-away hole's "rollback" row. It needs an older trust-owner-owned copy to exist: only possible if the broker renamed a genuine directory aside earlier and kept it | A trust-owner-owned directory with correct shape passes `_require_provisioned_shape` and `_trusted_read_provisioned` (`paths.py:92`) | Proven (shape checks only); Inferred (the scenario) | **Closes** if the genuine directory it swaps back has a different inode than the record (it will, once the box was re-provisioned in between). It does not close it if nothing re-provisioned: renaming the *current* directory aside and straight back is a no-op identity-wise, and that is correct |
| 5 | **Root reprovision launders a planted tree.** After an attack, a root `install.sh` step 1 runs `chown -R willow-operator:willow-operator "$H/mcp_apps"` (`install.sh`, step 1, just before the `manifest_grants` `install -d`) over whatever sits at that path. The planted directory and its attacker-chosen contents become trust-owner-owned, which is the "trust owner tricked into owning a planted directory" case. D4 then accepts it | `chown -R` has no notion of "is this the directory I provisioned" | Proven (the `chown -R`); Inferred (outcome) | **Closes** only if `install.sh` consults the record before step 1 and refuses on mismatch (§2.4). This is the part of D1 that lives in the installer, not the reader |
| 6 | **Ancestor rename.** uid 1000 owns `/home/sean-campbell/` and renames an ancestor of `$H`, planting a whole replacement box | `trust_marker.py:172-173` compares `os.path.realpath($WILLOW_HOME)` to a string. A replacement box at the same path has the same realpath | Inferred (I did not stat the ancestors) | **Closes** by recording `$H`'s own identity and checking it first (§3.1). Ancestors themselves are not recorded: any change that yields a different `$H` is caught at `$H` |
| 7 | **Inode reuse.** A recorded inode number is freed and a planted directory receives it | Not applicable to D4 | Inferred: ext4 reuses inode numbers; an attacker cannot free a trust-owner-owned, non-empty directory's inode (no write on it), but a root cleanup of an old directory frees one | **Narrowed**, not closed. The record includes a second discriminator where the filesystem offers one (§2.2), and §4 forbids deleting the old directory before re-recording |
| 8 | Denial of service by rename-away | Fail-closed outage (Q38 accepts it) | Proven | Not closed, by ruling. D1 makes more renames an outage, not fewer |

### §1.2 What D1 does not close

| Not closed | Why | Evidence |
|---|---|---|
| The trust owner itself compromised | The trust owner can write inside the recorded directories by design. D1 pins identity of the *containers*, not what the trust owner puts in them | Proven (design) |
| Root compromised | Root writes the record and can rewrite it | Proven (design) |
| A genuine file replaced by an older genuine file *inside* a recorded directory | Only the trust owner can write there. An attacker with only uid 1000 cannot. If the trust owner is made to do it, that is the apply half's own re-verification problem (`manifest_grant_executor.py:1202-1265`) | Proven (permissions); Inferred (apply path) |
| `manifest_grants/` content forgery | Q39 leaves it in `$H`. The broker legitimately writes `pending/` and holds `broker_signing_key` there. D1 can pin the directory's identity (§2.1) but not its contents | Proven (`manifest_grant_executor.py:654-668`, `:965-969`) |
| Env-var levers | Already handled by Q37 (`trust_marker.py:199` `trust_input_env`). D1 does not change it | Proven |
| A mount placed over a recorded path | Needs root. Out of scope, same as any root act | Proven (design) |

Honest summary: D4 makes a *missing or foreign-owned* `constitutional/` a refusal. It does not protect `mcp_apps/` at all against a broker-owned planted tree carrying copied valid signatures (row 1), and that is the largest hole left. D1 closes rows 1-6 and narrows row 7.

## §2 The record

### §2.1 Where: a separate file, `/etc/willow-mcp/trust-identity`

Recommendation: **a separate root-owned file beside the D4 marker, not an extension of it.** 85%.

| Reason | Detail |
|---|---|
| The marker's format is parsed strictly in two places | `install.sh` `mg_marker_problems` requires the file to read *exactly* `willow_home=...` and `trust_owner_uid=...` (`install.sh:1099-1119`), and `trust_marker._parse` reads two keys. Adding lines would make an old reader or an old `--check` report an invalid marker. An invalid marker refuses every PGP read (`trust_marker.py:133-159`). A format extension would turn a version skew into an outage |
| Independent bites | A separate file lets bite 1 land with "no record = no-op" and lets the record be absent on a D4-only box without touching D4's guarantees (§6) |
| One owner of one fact | The marker says "this home was provisioned, by this trust owner". The record says "these are the directories". Different change cadence: the record changes on re-record, the marker only on re-provision of home or owner |

Path is a compiled-in constant in a new module, never an env var (the F-C lesson, `trust_marker.py:49-51`). Same validity rules as the marker: regular file, root-owned, not group/other-writable, parent and grandparent root-owned and not group/other-writable (`trust_marker.py:90-100`, `:124-159`). The record is read through the same `os.open(..., O_NOFOLLOW)` + `fstat` shape the marker reader uses. Three states, never collapsed: **absent** (today's behaviour), **valid**, **invalid** (raises, never read as absent). A record that exists while the D4 marker is absent is treated as invalid (a record without a marker is a state nothing legitimate writes).

### §2.2 Format

One `key=value` per line, UTF-8, same dialect as the marker so one small parser serves both. Versioned. Example:

    version=1
    willow_home=/home/sean-campbell/sean-data-vault/willow-operator-box
    home=fsid:<hex> ino:<n> uid:<n> mode:<octal>
    dir.constitutional=fsid:<hex> ino:<n> uid:<trust-owner-uid> mode:<octal>
    dir.mcp_apps=fsid:<hex> ino:<n> uid:<trust-owner-uid> mode:<octal>
    dir.manifest_grants=fsid:<hex> ino:<n> uid:<n> mode:<octal>
    trust_fingerprint=<40 hex>

| Field | Why | Decision |
|---|---|---|
| `ino` (`st_ino`) | The primary identity; `rename(2)` preserves it | Required |
| `fsid` (from `os.statvfs().f_fsid`) | Names the *filesystem*, so a restore onto a different filesystem is a mismatch | Required. Used **instead of recording raw `st_dev`**: see §5.2 |
| `st_dev` | Renumbers across reboots and device enumeration for `/dev/sdX`, nvme and LVM minors (Inferred, 75%); differs inside overlay and some bind mounts | **Not recorded, not compared.** A reader compares each child's `st_dev` to its parent's at walk time instead (a mount-point crossing inside the trusted chain is refused, §3.2) |
| `uid`, `mode` | Already enforced by the D4 shape; recording them makes `--check` say *what* changed | Recorded, informational; the enforcing check stays the D4 shape |
| `i_generation` (ext4 `FS_IOC_GETVERSION` ioctl) | Defeats inode-number reuse | Optional, recorded when the ioctl works on the directory, compared only when present in the record. Needs an ioctl through `ctypes`/`fcntl`. 60% it works unprivileged on a directory fd on this ext4; fall back to absent |
| birth time (`statx` `btime`) | A second reuse discriminator | Not recorded in v1: Python 3.14 has no `os.statx` wrapper (70%), so it needs a `ctypes` syscall. Revisit only if the operator wants stronger reuse protection (Q-D1-5) |
| `trust_fingerprint` | The 40-hex fingerprint `trust.env` carried at provisioning, a public value (INSTALL.md D4 section: it is a fingerprint, not key material) | Recommended on: a rolled-back or hand-edited `trust.env` in the *genuine* directory would mismatch an independent root-owned copy. Written from the same `install.sh` code that publishes `trust.env` (`install.sh:1639`). Reader compares after parsing `trust.env`. Not strictly D1, cheap, and it is the root-owned pin Loki's `D06A0EF3` asked for without moving the file. Q-D1-4 |

### §2.3 Which directories and files are recorded

| Path (relative to `$H`) | Recorded? | Reason |
|---|---|---|
| `$H` itself | Yes (`home=`) | Catches ancestor rename and a replacement box (§1.1 row 6) |
| `constitutional/` | Yes | Holds `trust.env`, `pre-approved.json`, `syscall-table.json`, anchors. Its replacement is the original fail-open |
| `mcp_apps/` | Yes | Gate reads every seat manifest below it; row 1-3 |
| `mcp_apps/<app>/` | **No** | Created and retired by the trust owner at runtime (`trust_owner_verbs.py:517-523` retire renames `<app>` to `_retired/<app>-<pair>`; `manifest_admin.py:307` `mkdir` for a publish). Recording them would turn every `manifest_create`/`retire` into an outage. They need no record: only the trust owner can create or rename anything inside the recorded `mcp_apps/`, so a seat directory's identity is only as forgeable as `mcp_apps/` itself, which is pinned. The reader still requires each component to be trust-owner/root-owned and not group/other-writable (the existing D4 shape, applied per component by `fstat`, §3.2) |
| `mcp_apps/_federation/`, `_retired/`, `_net_leases/`, `_identity_bindings/` | **No** | Same reason; `_federation` is lazily created (`mcp_federation.py:361`, `:369`). Not recorded; checked by shape inside the pinned parent |
| `manifest_grants/` | Yes, enforced on the **trust-owner write side** only | Q39 keeps it in `$H`. The trust-owner apply writes into it; a planted broker tree there is the "make the trust owner write into the wrong tree" row of the hole doc §1.3. The broker's reads and writes of `pending/` are not blocked by it, since its identity does not change in normal operation |
| `manifest_grants/{pending,done,failed}`, `broker_signing_key` | No | Broker-written, churn by design (`manifest_grant_executor.py:1721-1741`) |
| Individual manifests, `.sig`, `trust.env`, register, syscall table | **No per-file inode** | Replaced by atomic rename on every legitimate publish (`manifest_grant_executor.py:992`, `manifest_admin.py:313-` `publish_signed_pair`, `install.sh:1639`). A per-file record would break every publish. Their integrity is the detached signature, which D1 does not replace |
| `trust.env` content | Yes, as `trust_fingerprint=` only | See §2.2 |

### §2.4 Who writes it and when

Only `install.sh`, as root, through a new `mg_write_identity` modelled on `mg_write_marker` (`install.sh:1125-1141`: temp file beside the target, `chmod 0644`, `chown root:root`, validate the temp, `mv`, validate the result, never leave a half file). Called from the existing `write_trust_marker` (`install.sh:1604`), which already runs at plain install step 6 (`install.sh:1744`) and after `--rotate` (`install.sh:2140`).

Every legitimate path that creates, replaces or retires a recorded directory or its recorded pin, and what keeps the record correct:

| # | Legitimate path | Changes a recorded directory's identity? | How the record stays correct |
|---|---|---|---|
| 1 | First install / provision (`install.sh` step 1: `chown -R`, `install -d`) | Creates them (or adopts existing ones) | Record is written at step 6, after the dirs exist and `trust.env` is real. Between step 1 and step 6 there is no record, so D1 is a no-op, as D4 is until step 6 |
| 2 | Plain re-install on a provisioned box | No (`install -d` on an existing directory keeps the inode; `chown -R` keeps inodes) | **Before step 1**, if a record exists, `install.sh` compares the live `$H`, `constitutional/`, `mcp_apps/`, `manifest_grants/` to it. Match: proceed and rewrite an identical record. Mismatch: **stop**, print which directory and old vs new, do not run `chown -R` (that is the laundering path of §1.1 row 5). The operator must pass an explicit flag (§4) |
| 3 | `--rotate` (new key, re-sign, new `trust.env`) | No directory changes; `trust.env` content changes | `write_trust_marker` rewrites the record, so `trust_fingerprint` follows. Same pre-check as row 2 before any re-sign |
| 4 | `manifest_create` / `manifest_retire` by the trust owner (`trust_owner_verbs.py:517-523`, `manifest_admin.py:307`, `manifest_grant_executor.py:1557-`) | Only creates/renames **children** of `mcp_apps/` | Nothing to update; children are unrecorded (§2.3). No outage, no root act |
| 5 | Federation ratify (`trust_owner_verbs.py:947`, `mcp_federation.py:369` `mkdir`) | Creates `mcp_apps/_federation/` on first use | Unrecorded child; nothing to update |
| 6 | `sync_constitutional`, `seed_envelope_ratify`, envelope amend/ratify (`constitutional.py:818,851`, `envelope_authoring.py:496-571`) | Write files, and `mkdir` of the **parent** of a file under `constitutional/` | The parent is `constitutional/` itself, which exists; `mkdir(exist_ok=True)` does not change it. A *new subdirectory* of `constitutional/` is unrecorded |
| 7 | `trust_root_setup` tighten sweep (`trust_root_setup.py:96-130,644,728`) | Changes mode/owner; `mkdir` on missing dirs | Inodes unchanged for existing dirs. A `mkdir` of a missing recorded dir would create a new inode: but a missing recorded directory is a refusal before the sweep matters, so the sweep must not recreate one (Q-D1-6 for the sweep on a provisioned box) |
| 8 | Operator restores from backup or `rsync`s a trust dir | **Yes** | Not automatic. A root re-record step (§4). This is the intended outage |
| 9 | Operator moves `$H` (new disk, new path, new home) | **Yes**, and the marker's `willow_home` also changes | Existing D4 re-provision (marker rewrite) plus re-record, same command |
| 10 | Filesystem repair (`fsck` re-linking `lost+found`), snapshot rollback | Possibly yes | Treated as row 8 |

Race to note: the trust-owner timer runs `manifest-grant apply` as a oneshot (`willow-mcp-manifest-grant.service:62-80`, `Type=oneshot`). I did not check whether `install.sh` stops the timer around a re-record; it need not, because directory identities do not change in rows 2-3. The record write is atomic (`mv`), so a reader sees the old or the new record, never a mix; during an `install.sh` re-record the directories do not change identity (rows 2-3), so old and new records name the same inodes.

## §3 The read path

### §3.1 One helper, one walk

A new module `src/willow_mcp/trust_identity.py` (name is a placeholder) owns everything below. Everything else calls it; no call site opens a trust path by name any more.

    open_trust_file(rel_under_home: str) -> OpenedTrustFile   # holds the fd; read bytes, fstat
    read_trust_bytes(rel_under_home: str) -> bytes
    read_trust_pair(rel_under_home: str) -> (data_bytes, sig_bytes | None)

Algorithm, for `rel_under_home = "mcp_apps/seat/manifest.json"`:

1. `record = trust_identity.active_record()`. Absent: return the legacy behaviour (today's path-based read, unchanged). Invalid: raise. Valid: continue.
2. Open the filesystem root: `fd = os.open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC)`.
3. For each component of the record's `willow_home` (a realpath, so no symlinks should occur): `os.open(name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, dir_fd=fd)`, then `os.fstat`; require a directory, not group/other-writable *except* where the existing D4 shape allows (ancestors of `$H` are the operator's and are not required to be root-owned; they are not trusted, only walked). A component that is a symlink fails `O_NOFOLLOW` with `ELOOP`: refuse.
4. At `$H`: compare `(fsid, ino)` to `home=`. Mismatch: raise `TrustIdentityError` (fail-closed; never "absent").
5. Next component: if it is a recorded name (`constitutional`, `mcp_apps`, `manifest_grants`), compare `(fsid, ino)` to the record. Below a recorded directory, apply the **D4 shape per component** (uid in `{trust_owner_uid, 0}`, no group/other write bit, directory or regular file), the same rule `_trusted_read_provisioned` enforces by path today (`paths.py:92-118`), but on the `fstat` of the fd just opened, not on a second path stat.
6. Each step's `fstat.st_dev` must equal its parent's `st_dev` below `$H` (no mount crossing inside the trusted chain). `$H` and its ancestors are exempt: `$H` may legitimately be its own mount (Q36 left it in the vault box; the operator's `RequiresMountsFor=` on the unit, `willow-mcp-manifest-grant.service:`, hints at a separate mount, Inferred 55%).
7. Final component: `os.open(name, O_RDONLY|O_NOFOLLOW|O_CLOEXEC, dir_fd=parent)`, `fstat` it (regular file, shape), read **from that fd**. Close every intermediate fd except the final one.

### §3.2 openat2 where available, a plain walk where not

| Mode | Used when | What it does | Why |
|---|---|---|---|
| **A: openat2** | A one-time probe succeeds | After step 5 verifies the *last recorded directory's* fd, the rest of the path under it is opened with a single `openat2(dirfd, rel, {O_RDONLY\|O_CLOEXEC, resolve = RESOLVE_BENEATH\|RESOLVE_NO_SYMLINKS\|RESOLVE_NO_MAGICLINKS\|RESOLVE_NO_XDEV})`, then `fstat` of the result. The kernel does the per-component symlink and escape refusal atomically | Fewer syscalls, no Python-side race between components |
| **B: per-component walk** | The probe fails | Steps 2-7 above for every component, `O_NOFOLLOW` each | Same guarantee, more syscalls |

Mode B is the reference implementation and the one that is tested everywhere. Mode A is an optimisation that must produce the same result; a test runs both against the same fixtures. In neither mode is the *anchor* done with `RESOLVE_BENEATH` from `/`: the identity compare at `$H` and the recorded children is what carries the security property, and `RESOLVE_BENEATH` from a directory fd below `$H` only refuses `..` and symlink escape.

Detection. Python 3.14's `os.open` has no `resolve` argument (70%; verify on the box's interpreter), so mode A is a `ctypes` call to `syscall(SYS_openat2 = 437, dirfd, path, &open_how, sizeof(open_how))`. Probe once per process, lazily, with `openat2(AT_FDCWD or an fd of "/", "/", RESOLVE_BENEATH)`:

| Probe result | Meaning | Action |
|---|---|---|
| fd returned | Kernel >= 5.6 and the syscall allowed | Mode A; cache the result |
| `ENOSYS` | Kernel < 5.6, or the syscall is filtered | Mode B; cache |
| `EPERM` / `EACCES` (seccomp filter returning an error) | Container or sandbox filter | Mode B; cache. Not treated as an attack |
| `EINVAL` | The `open_how` struct or flags are not understood | Mode B; cache |
| `ctypes` unavailable / architecture without a known syscall number (non-x86_64/aarch64) | Cannot call | Mode B |

The probe result is logged once (info). The current dev kernel reports `6.18.44-fc-v114` (Proven: `uname -r` in this session) but the box's kernel is unknown, so mode B is a hard requirement of the design, not a fallback nobody exercises. The unit has no `SystemCallFilter` (`willow-mcp-manifest-grant.service:78-87`, Proven), so openat2 is not blocked there.

### §3.3 TOCTOU analysis

| Window | Today | With D1 |
|---|---|---|
| Between `trusted_read(path)` and `path.read_text()` | Two separate path resolutions (`envelopes.py:42-43`; `constitutional.py:114-115`; `frank_head_anchor.py:86` then `:96`). A swap between them is possible. `trusted_read` returns `None`, it hands back no handle | Closed: the bytes come from the fd that was `fstat`-verified |
| Between the owner/mode check and `read_text` in `_read_trust_config_fingerprint` (`pgp.py:355-400`: `_require_provisioned_shape`, `path.exists()`, `_trust_config_ownership_ok`, `path.stat()`, `path.read_text()`) | Four path resolutions | Closed: one walk, one fd, one read |
| Manifest and signature are two files | `_read_manifest` reads `manifest.json` (`gate.py:769`), then `verify_detached` hands **paths** to `gpg` (`pgp.py:628-690`, `str(sig_path), str(file_path)`) | The helper returns both byte strings from verified fds. `verify_detached` gets a bytes path: `gpg --verify /dev/fd/<sigfd> /dev/fd/<datafd>` with `pass_fds` (Inferred 80% that gpg accepts `/dev/fd/N` for both; the fallback is a private `0700` temp dir holding copies, which the existing public-key branch already creates, `pgp.py:663-672`) |
| `signed_pair_lock` (`pgp.py:583-`) takes the directory lock by path (`os.open(directory, ...)`) | Opens the directory by name | The helper opens the directory fd first; the lock is taken on that fd (`fcntl.flock(fd)` on the verified directory) so the lock object is the verified object |
| Directory swapped *before* the walk | Read believed | Refused at the identity compare |
| Directory swapped *after* the walk, while the fd is held | n/a | The fd still names the verified inode: later renames do not redirect an open fd. The bytes read are the verified file's bytes |
| Same directory renamed aside and back between two reads | n/a | Allowed: identity is by inode, and it is the same inode. This is correct, not a gap |

What D1 cannot do: if a verified file is *replaced in place by the trust owner* between two reads, the second read sees the new file. That is a legitimate publish; the cache keys on `(inode, mtime_ns, size)` (`pgp.py:383-390`) and keeps working.

### §3.4 Call sites that change

All route through the helper. Each keeps its exception contract (`PermissionError` for `trusted_read`, `PgpSourceUnreadable` for the trust-config read, a manifest denial for the gate); the helper's error maps into the existing type at each site, never to "absent".

| # | File:function | Today | After |
|---|---|---|---|
| 1 | `paths.py:21` `trusted_read` and `:92` `_trusted_read_provisioned` | Path checks, returns `None` | Gains a sibling `trusted_read_bytes(path, *, governance=True) -> bytes`. `trusted_read` stays for non-governance callers (fleet roster, `fleet_roster.py:21`) and delegates the provisioned branch to the helper |
| 2 | `envelopes.py:_load` (`:39-45`) | `trusted_read(path)` then `read_text` | `trusted_read_bytes` then `json.loads` |
| 3 | `constitutional.py:_load_live` (`:111-119`) | same | same change. The bundle read at `:103` is package code, unchanged |
| 4 | `frank_head_anchor.py:read_anchor` (`:86`, `:96`) | `trusted_read` then `read_text` | `trusted_read_bytes` |
| 5 | `pgp.py:_read_trust_config_fingerprint` (`:291-`) and `_trust_config_ownership_ok` (`:98`), `_require_provisioned_shape` (`:249`) | Path stats and `read_text` | With a record, the shape check and the read are one helper call; `_require_provisioned_shape` stays for the record-absent D4 case |
| 6 | `gate.py:_read_manifest` (`:747-803`) | `exists`, `read_text`, `verify_detached(path)` | `read_trust_pair("mcp_apps/<app>/manifest.json")` then verify from bytes. `_apps_root()` (`gate.py:33`) keeps its D4 lever handling |
| 7 | `pgp.py:verify_detached` (`:628`) | Paths to `gpg` | New optional `data=`/`sig=` bytes parameters; path form unchanged for the record-absent case |
| 8 | `pgp.py:signed_pair_lock` (`:583`) and `manifest_admin.publish_signed_pair` (`manifest_admin.py:291-`) | Lock by directory path | Lock on a verified directory fd (trust-owner write side) |
| 9 | `gate.py:verify_all_manifests` (`:~842-881`), boot sweep | Per-seat via `_read_manifest` | Inherits (6) |
| 10 | Trust-owner apply: `manifest_grant_executor.py:_grants_root` (`:965-969`) and the publish call (`:1557-`), `trust_owner_verbs.py` retire (`:517-523`) and create | Path writes under `willow_home()` | Open the recorded directory's fd first, compare identity, then write with `dir_fd=` (`os.replace(src_name, dst_name, src_dir_fd=, dst_dir_fd=)`). This is the **write-side** twin of the read walk and is the largest part of the work (§6, bite 5) |
| 11 | Read-only consumers of `paths.mcp_apps_root()` (`build_lease.py:75`, `mcp_federation.py:361`, `sandbox_confirm.py:203`, `server.py:8082`, `registry.py:159`, per the hole doc §3.A) | Path joins | Not switched in D1. They read, then trust a signature or a trusted_read of their own. Listed so the operator knows they are not covered; Q-D1-7 |

Sizes and the order are in §6. A test enumerating `trusted_read`, `read_text` and `Path.open` over trust paths (a grep-style test, like the existing docs-scanning tests) keeps a new call site from bypassing the helper.

## §4 Failure modes and recovery

Every mismatch is **fail-closed**: a refusal with the directory, the recorded `(fsid, ino)` and the found one, and the recovery command. Nothing in D1 can turn enforcement off. The reader's state machine has three outcomes only (valid / absent-record = D4 behaviour / invalid-or-mismatch = refuse), and absent-record on a box that has a D4 marker is D4's behaviour, which is itself fail-closed on `constitutional/`.

| Event | Result | Operator recovery |
|---|---|---|
| Restore `constitutional/` or `mcp_apps/` from backup | New inode: mismatch, refusal | Verify the restored tree is the intended one (`install.sh --check-signatures`), then `sudo bash install.sh --expect-head <sha> --re-record-trust-identity` |
| `rsync`/`cp -a` of a trust directory | New inode: mismatch | Same |
| `mv` of `mcp_apps/` on the same filesystem and back | Same inode: **no** mismatch | None needed |
| Filesystem move (new disk, `$H` moved to another mount) | New `fsid` and inode: mismatch; the D4 marker's `willow_home` may also change | Re-provision per the existing D4 procedure, with the new flag |
| Inode reuse / `fsck` renumbering | Reuse can pass an inode-only check; `i_generation` (when recorded) or `fsid` catches some. A renumbering is a mismatch | Same as a restore |
| A legitimate re-provision (key rotation) | No directory change: no mismatch | None: `--rotate` rewrites the record's `trust_fingerprint` |
| Planted tree after rename-away | Mismatch | **Do not run a plain install.** It will refuse at its pre-check (§2.4 row 2). As root: `mv` the planted directory aside, `mv` the genuine one back (same inode: valid again). If the genuine one is gone, restore it and re-record |
| Record file damaged or replaced | Invalid record: every governed read refuses | Root rewrites it with `--re-record-trust-identity` |
| Record deleted by root | Absent record: D4 behaviour only (weaker, not off) | `--check` reports `[info]`/`[FAIL]` (§4.1); a plain install writes it back |

### §4.1 install.sh surface

| Mode | Behaviour |
|---|---|
| Plain install / `--rotate` with a record present | Pre-check before step 1 (§2.4 row 2). Mismatch is a `stop` naming the directory and old vs new identity. Match rewrites the record |
| Plain install, record absent, marker present | Writes the record at step 6 from what is on disk. Safe on first D1 rollout: this is the legitimate "record the box as it stands" moment. The operator is told to run `--check` first (the box may already be hijacked, §7 Q-D1-1) |
| `--re-record-trust-identity` (new, root only, `--expect-head` required like every mode, `install.sh:265`) | Shows the live identity of each recorded directory next to the old record, the owner/mode of each, and the count of manifests that verify under `trust.env` (reuses `--check-signatures`), and requires an interactive typed confirmation of the operator's own words. Then writes the record. It is the only way to accept a changed identity. Never reachable from the broker, the trust-owner unit or `sudo -u` env (the re-exec runs under `env -i`, `2ef4419`) |
| `--check` | New lines: record present and valid / absent (`[info]`) / invalid (`[FAIL]`); each recorded directory matches or `[FAIL]` with old vs new; `trust_fingerprint` matches `trust.env`; openat2 probe result is printed (informational) |

`--re-record-trust-identity` takes a flag, not an env var (consistent with `--rotate` etc.); it needs the same `--expect-head` pin, and the human's recorded authorization (CLAUDE.md rule 5) is the operator's own act, not the agent's.

## §5 Interaction

### §5.1 D4 marker

The record is read only when a valid marker exists (a record with no marker is invalid, §2.1). Order in `active_marker` callers: marker first (`trust_marker.py:162`), then the record, then the walk. `trust_input_env` (Q37) is unchanged and runs before: the lever-ignoring logic already hands D1 the default path under `$WILLOW_HOME`. The record's `willow_home` must equal the marker's; a difference is invalid.

### §5.2 Kart and `st_dev`

Facts (operator, 2026-10-11): Kart binds `$H` children read-only at the same paths and sees `/etc/willow-mcp`. I did not read the bwrap arguments.

| Question | Analysis | Evidence |
|---|---|---|
| Do `st_ino` values match inside bwrap for a bind-mounted child? | Yes. A bind mount presents the same inode of the same superblock | Inferred (VFS semantics), 90% |
| Does `st_dev` match? | For a bind mount on the same filesystem, `st_dev` is the superblock's device number, identical to outside. It differs for overlayfs and for a different superblock | Inferred, 80%. The overlay Kart uses for `mcp_apps` (hole doc §1.1) would give a different `st_dev` and a synthetic or different `st_ino` |
| Is `st_dev` stable across reboots? | Not guaranteed for `/dev/sdX`, nvme or LVM minors | Inferred, 75% |
| `f_fsid` (`statvfs`) | Ext4 derives it from the filesystem UUID: stable across reboots, identical for every bind mount of that filesystem, different for overlay | Inferred, 75% (it is a long-standing ext4 behaviour, not checked on this box) |

Decision: **record `(fsid, ino)` and do not record or compare `st_dev`.** `fsid` also names the filesystem across reboots, so the record survives device renumbering. For Kart:

| Kart view | What D1 does | Why |
|---|---|---|
| `constitutional/` bound read-only (a plain bind) | Identity compare passes in the sandbox (same `fsid`, same `ino`) | Inferred |
| `mcp_apps` overlay | Compare would mismatch (different superblock) and refuse every manifest read inside Kart | Inferred. **Unknown whether any Kart task reads manifests or governed files at all.** Q-D1-2 |
| Mitigation if Kart needs the read | A sandbox-aware branch cannot be a heuristic (a broker-settable "I'm in a sandbox" flag is a lever). The record gets an optional `kart.mcp_apps=fsid:... ino:...` line describing the overlay's identity if the operator confirms it is stable, else Kart tasks read nothing governed. Do not guess | Inferred |
| Launcher-side check | The thing Kart binds is chosen **outside** the sandbox by the launcher, by path, from the broker's uid. A planted `constitutional/` would be bound, and then trusted inside. D1 closes this only if the Kart launcher resolves the bind source through the same helper (open and verify, then bind `/proc/self/fd/N` if bwrap supports `--bind-fd`, 50%; else bind the verified path immediately after the compare, a narrow race). Not in D1's first bites (§6 bite 6, optional). Not read |

### §5.3 Trust-owner apply unit

`ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=` for `manifest_grants`, `mcp_apps` and `constitutional` (`willow-mcp-manifest-grant.service:79-83`). systemd implements each `ReadWritePaths=` as a bind mount in the unit's mount namespace; on one ext4 filesystem `fsid` and `ino` match the outside view (Inferred, 85%). `/etc/willow-mcp` is readable in the unit (`ProtectSystem=strict` makes `/etc` read-only, not hidden; the unit already reads `/etc/willow-mcp/manifest-grant.env`, `:66`). The unit has no `SystemCallFilter`, so openat2 works. The unit runs `python -I` from `/opt/willow-operator/venv`, so the new module ships in the venv build only through `install.sh --expect-head <sha>` / `--provision-venv`: **the trust-owner process gets the new reader only after a root install of the commit**, and a D1 commit not yet installed leaves the apply half on the old path-based code. The reader and the record must agree on version: the helper treats `version=` greater than it understands as invalid (refuse), which is the safe skew direction (old code never sees a new record; if it does and ignores it, it behaves as D4, §6 bite ordering).

### §5.4 Broker, desk, tests

| Item | Effect |
|---|---|
| Broker (`run_mcp.sh`, uid 1000) | Reads through the helper. A mismatch makes `pgp.pgp_enabled()` raise at boot (`server.py:12500-12613` "refusing to start", Proven that the path exists for `PgpSourceUnreadable`), the same outcome D4 already produces for a missing `trust.env` |
| `verify_all_manifests` boot sweep (`gate.py:~842`) | Reports one problem per seat if the identity check fails, so the log names the cause |
| Tests | The existing marker tests redirect `_MARKER_PATH` and `_ROOT_UID` by monkeypatch (`trust_marker.py:34-35`); the record module follows the same seam (no env var). A temp-dir fixture creates real directories, records their `(fsid, ino)`, then `rename`s and plants to exercise each row of §1.1. A fixture runs the helper in mode A and mode B against the same tree (skip mode A when the probe says unsupported); a monkeypatch forces the probe to return `ENOSYS` to prove the fallback. `tests/test_trust_marker.py`, `tests/test_trust_marker_install.py` and `tests/test_manifest_grant_deploy.py` are the neighbours. The installer functions are bash; the existing install tests source them, and `mg_write_identity` follows suit |

## §6 Bites

Each bite is independently safe: it can merge and deploy alone and leaves the box no worse than before it. Nothing deploys until the operator runs `install.sh` for the trust-owner venv.

| # | Bite | What it does | Safe alone because | Size |
|---|---|---|---|---|
| 1 | **Helper and record reader, no callers** | `trust_identity.py`: record parser/validator (three states), `(fsid, ino)` compare, mode B walk, mode A with probe, `read_trust_bytes`, the error type. Heavy tests on tmp dirs | No call site uses it; absent record is a no-op by construction | M |
| 2 | **install.sh writes the record** | `mg_write_identity`, `mg_identity_problems`, call from `write_trust_marker`, `--check` lines, pre-check before step 1 (refuse on mismatch), `--re-record-trust-identity`. INSTALL.md section. Bash tests | The record exists but nothing reads it, so the box behaves exactly as D4. The pre-check is the first behavioural change and only ever refuses a root install that would launder a planted tree | M |
| 3 | **Switch the three `trusted_read` readers** | `envelopes._load`, `constitutional._load_live`, `frank_head_anchor.read_anchor`, plus `trusted_read_bytes` | Absent record: unchanged. Present record: a mismatch refuses these three reads, fail-closed. Smallest radius: files in `constitutional/` | S |
| 4 | **Switch the PGP trust config and the gate** | `pgp._read_trust_config_fingerprint` (incl. `trust_fingerprint` pin), `gate._read_manifest`, `verify_detached(data=, sig=)`, `signed_pair_lock` on a directory fd | This is the bite that closes §1.1 rows 1-3. It is where a false mismatch costs the most (every seat denied). Deploy only after `--check` reports the record valid on the live box | M |
| 5 | **Write side of the trust-owner apply** | `manifest_grant_executor` and `trust_owner_verbs` open the recorded dir fd and write with `dir_fd=`; `manifest_grants/` identity enforced here | Without it, a planted `manifest_grants/` still receives trust-owner writes (§1.1 hole-doc row). Larger because the apply code writes in many places (`:654-668`, `:985-999`, `:1721`) | L |
| 6 | **Optional: Kart launcher and read-only consumers** | Resolve Kart bind sources through the helper; switch the §3.4 row 11 readers | Only if Q-D1-2 says Kart reads governed files or the operator wants the launcher check | M |
| 7 | **Docs and a no-bypass test** | A grep-style test that no module outside the helper opens a trust path by name; INSTALL.md and the hole doc status line | Docs and tests only | S |

Status (updated as bites land):

| Bite | Status |
|---|---|
| 1 | landed in the commit `feat(trust): D1 bite 1 — trust-identity record reader and fd-walk helper (no callers)`: `src/willow_mcp/trust_identity.py` + `tests/test_trust_identity.py`, no callers (a test guards that until bite 3) |

Recommended order: 1, 2, run `--check` on the box and read the report, 3, 4, 5, 7; 6 on request. Bites 3 and 4 are the first that can refuse a live read, so the operator should have a valid record and a passing `--check` before them. The hole doc status line is owned by another agent's edit in flight, so this document does not edit it.

## §7 Risks and open questions

| # | Risk | Mitigation in this design |
|---|---|---|
| R1 | A false mismatch denies every seat (a record that is wrong on day one) | Bite 2 ships before any reader; `--check` shows the live-vs-record table; bites 3 and 4 are separate merges |
| R2 | The first record is taken from a box already hijacked | The record is only as honest as the box at recording time. `--check-signatures` and a look at owner/mode come before the first record |
| R3 | Operators get used to `--re-record-trust-identity` and run it blindly | The flag shows the diff, requires typed confirmation, and a re-record is logged to the install transcript. It cannot make D1 weaker than D4 |
| R4 | `openat2` unavailable or filtered | Mode B is the reference; probe is cached (§3.2) |
| R5 | `gpg` rejecting `/dev/fd/N` | Fallback to a private temp dir (already used at `pgp.py:663`) |
| R6 | Older trust-owner venv (not re-provisioned) reads a newer record | Version field; unknown version is invalid for new code, ignored by old code which then behaves as D4 (weaker, not off) |

Questions for the operator, each with a recommendation. Q-numbers are local to this document.

| # | Question | Recommendation | Confidence |
|---|---|---|---|
| Q-D1-1 | Before the first record is written, should a read-only audit of the live box (owners, modes, inodes, `--check-signatures`) be a required step? | Yes: run `--check`, record, then ship bite 3. The record is a snapshot of what is on disk at that moment | 90% |
| Q-D1-2 | Does any Kart task read `mcp_apps/` manifests or governed `constitutional/` files from inside the sandbox? If yes, the overlay needs its own recorded identity or an explicit exemption | Ask the Kart owner; default to "Kart reads nothing governed" until shown otherwise, and keep bite 6 optional | 55% that Kart does not need it |
| Q-D1-3 | One separate file `/etc/willow-mcp/trust-identity` (recommended) or extend the D4 marker? | Separate file (§2.1) | 85% |
| Q-D1-4 | Include `trust_fingerprint` (a public 40-hex value) in the record as a root-owned pin? | Yes. It is the pin Loki's `D06A0EF3` asked for, without moving `trust.env` out of `$H` (Q36) | 75% |
| Q-D1-5 | Is inode-number-plus-`fsid` enough, or add `i_generation` / birth time against inode reuse? | Add `i_generation` when the ioctl works (best-effort); skip `statx` birth time in v1 | 65% |
| Q-D1-6 | The `trust_root_setup` tighten sweep (`trust_root_setup.py:644,728`) `mkdir`s missing directories. On a recorded box, a missing recorded directory must be a refusal, not recreated. Accept? | Yes: a missing recorded directory is an incident, not a setup step | 85% |
| Q-D1-7 | Switch the read-only `mcp_apps_root()` consumers (§3.4 row 11) in D1, or leave them as is? | Leave for now; they sit behind signatures or their own `trusted_read`. Revisit with bite 6 | 65% |
| Q-D1-8 | Is `--re-record-trust-identity` with a typed confirmation the right operator step, or should re-record be a separate script (`scripts/`)? | A mode of `install.sh`, so it inherits `--expect-head`, the re-exec and the `env -i` allowlist | 80% |
| Q-D1-9 | Add a gate check that a manifest's own `app_id` equals its directory name (closes §1.1 row 3 inside a tree the broker controls even without D1)? | Yes, as its own tiny change outside D1; it is independent and S-sized | 70% |
| Q-D1-10 | Is `$H` on its own mount (affects the `st_dev`-equals-parent rule in §3.1 step 6)? | Check `findmnt -nT "$H"` on the box; the rule is exempt at `$H` either way | 60% that it is not a separate mount |

Not decided here and left to the operator: whether D2-style relocation is ever revisited (Q36 says no for now), and the timing of bites against Loki's review queue.

## §8 Operator rulings (2026-10-11)

| Q | Ruling |
|---|---|
| Q-D1-9 (as "D4.5") | Yes: dispatched as its own change ahead of D1 (gate ownership check under the marker, and `app_id` must equal the directory name) |
| Q-D1-1 | Yes: a read-only audit of the live box before the first record is written |
| Q-D1-2 | Hold: whether any Kart task reads `mcp_apps/` or governed files is not ruled; bite 6 stays optional |
| Q-D1-3 | Agreed: a separate record file, `/etc/willow-mcp/trust-identity` |
| Q-D1-4 | Yes: the public `trust_fingerprint` pin goes in the record |
| Q-D1-5 | Agreed: `i_generation` best-effort, no birth time in v1 |
| Q-D1-6 | Yes: on a recorded box a missing recorded directory is refused, not re-created |
| Q-D1-8 | `install.sh` mode: re-record is `--re-record-trust-identity`, inheriting `--expect-head` and the `env -i` re-exec |
| Q47 (D4.5 `app_id`) | A manifest without `app_id` stays allowed under the marker for now; backfill `app_id` later for jeles-corpus, willow-bot, willow-mcp and willow-seal-watch (the four live manifests that lack it, 2026-10-11) through the trust-owner path, then deny an absent `app_id` under the marker |
| Q49/Q50 (2026-10-11) | F1 lease/binding ownership under the marker and an atomic venv swap, folded in 6925f8b and the commit that adds this row without a further audit (operator ruling Q51) |
| Q-D1-10 | Answered: `findmnt -nT "$H"` = `/  /dev/mapper/ubuntu--vg-ubuntu--lv ext4 rw,relatime`. `$H` is on the root filesystem (LVM), not its own mount |
