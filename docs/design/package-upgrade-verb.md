# `package.upgrade` — an offline install of a tagged release into a broker venv

**Status:** built and tested, **UNSEALED**. Unlike every governed verb row
added since row 15 (`unit.reload`), this one carries no Nestor-sealed
governing decision id — see below, and syscall-table.json row 25's own
`note`. Dispatch 28D6C18E briefed the first cut; Loki's audit (dispatch
CD187906) returned BLOCKERS; rework 1 (dispatch 15773FE5) closed those but
Loki's re-check (dispatch C7138BBA) returned BLOCKERS again — N1, N2, N3;
rework 2 (dispatch CACC28EB) closed those but Loki's re-check (dispatch
3CBE8D7E) returned BLOCKERS again — R1, R2, R3. This document describes
the THIRD rework, built across dispatches C2EB023A and 500FCEFB.

**THREE drafted governing-decision pairs are stale and must not be sealed
as written: `f8de1fcb`** (drafted against the FIRST cut), **`5db480c7`**
(drafted against rework 1, `15773FE5` @ `3501e7d`), **and any pair drafted
against rework 2** (`CACC28EB` @ `778c60f`, closed by `3CBE8D7E`). The
exact final behaviour, for the desk to redraft against NOW, is this
document in full.

There is still no `docs/design` document for row 17 (`unit.install`) to sit
"next to" — checked again this dispatch, still true. This file stands alone.

## The gap (c1b4a8d006dc)

kartikeya `master` carries #67 (the scanner fix) and #68 (the process-tree
kill). The broker venv (`$WILLOW_HOME/venvs/willow-mcp`) still runs
kartikeya 0.3.2 — a non-editable site-packages install with neither fix. Kart
mounts that venv **read-only**. No desk verb installs a release, so a merged
fix never reaches the running processes, and the only remedy was a terminal
command — exactly the failure this repo's own rule forbids.

## Why rework 1 was reopened (Loki C7138BBA)

Rework 1's own claim — "the wheel is built in Kart" — was false. Loki's
probe (`QDTY2G0Q`) showed `build_wheel()` ran as a broker subprocess with
`env={**os.environ}`: the broker's OWN provider keys and `NESTOR_SEAL_KEY`
(when set) reached the build, and the build-python candidates
(`ratatosk/.venv`, `willow-gate/.venv`) sat in checkouts Kart could ALSO
write to. `Kart PC744HA4` (rework 1's live proof) only showed the build
*works* in Kart — the shipped code never actually *ran* it there. Three
findings, all blockers:

* **N1** — the build does not run in Kart at all.
* **N2** — even if it did, a Kart-writable build venv cannot be trusted;
  its OUTPUT has to be verified, not its provenance. The `EBUILD`
  availability probe also ran a candidate interpreter from the broker
  BEFORE any envelope check — the exact host-exec class
  `kart-sandbox-host-exec-2026-09-27.py` closed for `nestor/.venv` and
  `Jeles/.venv`, reopened here.
* **N3** — only the pip-install call caught `subprocess.TimeoutExpired`.
  A timeout from `git archive`, the post-install verify, or a systemd
  restart escaped uncaught: the citation was spent, no receipt was
  written, and nothing was rolled back.

Plus one should-fix from the SAME audit, closed here: **F8d** — a restart
of `willow-mcp-worker-fast`/`-batch` kills whatever Kart task that lane's
worker is mid-execution (no SIGTERM handler in `worker.py`); the verb now
refuses `EBUSY` unless `force_restart=True` is passed.

## What changed in this rework, and why

### N1 — the build now runs in Kart, for real

`package_upgrade_executor.run_kart_build()` submits the build as a genuine
`task_submit` call — network-isolated, the `fast` lane by default (a
single-package wheel build proved to finish in low tens of seconds against
kartikeya in rework 1's own live proof, so it need not queue behind
longer batch jobs) — and awaits it by polling `task_status`. Both are
called as the SAME in-process functions an external MCP client's
`task_submit`/`task_status` calls would run: `server.task_submit` and
`server.task_status`, imported lazily to avoid a circular import. Reading
their bodies confirms neither depends on a live MCP request `Context` —
they are plain `@_guarded` functions reading/writing Postgres — so calling
them directly from `execute_package_upgrade`, with the SAME `app_id` that
is performing the upgrade, runs through the identical gate/sanitize/
rate-limit/receipt pipeline an external call would. If that `app_id` holds
no `task_queue` capability, `task_submit` refuses and `run_kart_build`
reports that refusal as `EBUILD` naming exactly what came back — the verb
never invents a bypass.

The build's output (the source extraction AND the built wheel) lives under
this checkout's OWN `worktrees/` directory
(`_default_build_scratch_root()`, override via `WILLOW_MCP_BUILD_SCRATCH`
or the `work_dir` parameter) — the one location `kart-sandbox.json` already
binds READ-WRITE for every Kart task, confirmed empirically against the
live sandbox manifest during this dispatch. No new sandbox configuration
was needed.

The Kart task text itself (`_build_task_script`) is a small inline Python
heredoc: it probes each configured candidate build-python for EVERY
declared `[build-system].requires` import name, inside its OWN subprocess
call — the broker never runs a candidate interpreter itself — picks the
first candidate with everything importable, and runs
`pip wheel --no-index --no-build-isolation --no-deps`, with
`SETUPTOOLS_SCM_PRETEND_VERSION` pinned from the tag (a `git archive` tree
has no `.git` for hatch-vcs/setuptools_scm to read a version from).

### N2 — the build's OUTPUT is verified, not its provenance

Since Kart can write to any build-python candidate's own checkout, trusting
"the build ran offline" is not enough — a planted `.pth` file or a
rewritten `hatchling` could still produce a poisoned wheel. Rather than try
to make a Kart-writable venv trustworthy, this rework makes the venv's
trust IRRELEVANT: `verify_wheel_against_source()` diffs the wheel against
the git-archived source at the resolved sha, byte for byte, before a
single byte of it is installed:

* Every `.py` module inside the wheel must be byte-identical to the same
  relative path in the source (checked against both a flat layout and a
  `src/` layout).
* No `.pth` file anywhere in the wheel (`EBUILD`).
* No path with no matching source file (`EBUILD` — the "planted extra
  module" shape).
* `console_scripts` in the wheel's own `entry_points.txt` must exactly
  match `[project.scripts]` read from `pyproject.toml` at the resolved sha
  (`EBUILD` on mismatch).
* METADATA `Name`/`Version` must match the package/tag (`EVERIFY`).
* The wheel must be pure Python — `py3-none-any` filename tag AND
  `Root-Is-Purelib: true` in its own `WHEEL` metadata (`ENOTPURE`
  otherwise). **kartikeya IS pure Python** — no C extension, no compiled
  artifact of its own — so this refusal should never fire for it in
  practice; it exists so a poisoned build backend cannot smuggle a
  platform-specific payload past a pure source diff.

Non-`.py`, non-dist-info content (package data) is checked for EXISTENCE
at the same source path only, not byte content — a stated bound: legitimate
build tooling can transform a data file, and this verb does not model
that.

No hard-coded, box-specific build-python path remains anywhere in the
source. `_build_python_candidates()` reads
`WILLOW_PACKAGE_BUILD_PYTHON`/`WILLOW_PACKAGE_BUILD_PYTHONS` only; an
unconfigured box refuses `EBUILD` by name (a preflight refusal — no
subprocess, no citation spent) rather than guess a path from the box this
verb happened to be written on.

### N3 — the whole act phase is now one try/except

Every step from the citation through the restart loop — the archive, the
Kart build wait, verify, backup, install, the post-install verify, each
systemd restart — now runs inside ONE `try:` block in
`execute_package_upgrade`. Every early "refuse" inside that block is now a
`raise _CitedActFailure(...)` instead of a `return`, so there is exactly
ONE `except` that decides what happens on ANY exit: it rolls back
(unconditionally — a no-op when nothing was backed up yet) and writes a
cited FRANK receipt, whether the exception is `_CitedActFailure`,
`subprocess.TimeoutExpired` (from `git archive`, the Kart build wait, or a
systemd call), or a bare `OSError` (a `_backup_entries` failure). Nothing
downstream of the citation can short-circuit past it the way rework 1's
scattered early-returns did.

### F8d — a restart refuses when its lane is busy

`worker.py` has no SIGTERM handler, so restarting
`willow-mcp-worker-fast`/`-batch` kills whatever Kart task that lane's
worker is mid-execution outright. Before determining `build_root` (and
therefore before the citation), the verb checks, for every unit it WOULD
restart, whether that unit's own lane (`willow-mcp-worker-<lane>.service`
→ `<lane>`) has a `running` row in the Kart queue
(`server._lane_running_task_ids`, a new internal read, NOT an MCP tool) and
refuses `EBUSY` unless `force_restart=True` — which is recorded on the
receipt either way. This check is deliberately a PREFLIGHT refusal: it is a
pure read, so it spends nothing, and — just as importantly — it never rolls
back an install that already succeeded, because it runs BEFORE the act
phase, not after. A lane that goes busy in the instant between this check
and the actual restart (which still happens later, after install) is a
stated, unfixed residual — closing that fully needs a lock outside this
dispatch's scope. `_lane_running_task_ids` fails CLOSED: if the Kart queue
cannot even be read, it returns `None` and the caller refuses `EBUSY`
rather than guessing the lane is idle.

## Carried over unchanged from rework 1

**B2 — the ONE grant-spending citation, before any mutation.** Still the
single `authorize_and_cite` call, still after every preflight refusal and
the envelope check, still before the act phase begins. A citation-failure
(`EDQUOT` racing another call, `EEXPIRED`, a revocation) still spends
nothing.

**B3 — rollback covers the install, staged then swapped per entry.**
Console-script shims are backed up in numbered slots (a site-packages
package dir and its own shim share a name in a flat scheme — the first
cut's real bug). Restore stages beside the target and swaps with one
`os.replace` per entry — atomic per file/tree, not a single multi-entry
transaction.

**F6 — the resolved sha, never the tag name.** Archive, dependency, and
build-requires reads all use the tag's resolved commit sha. A tracked
symlink in the tree is refused (`ENOSRC`). Stated bound, unchanged: a
locally-moved tag (`git tag -f`) pointing at a different commit that is
ALSO reachable from `origin/HEAD` still passes.

**F7/F8a/F8c** — the install is wheel-only, `--no-index --no-deps
--isolated`, under a scrubbed environment; restarts are filtered to units
whose OWN `ExecStart` names the upgraded venv; a dead worker after restart
reports `ok:false`.

## Mutation-proof evidence (this dispatch)

Kart-run mutations, each applied to a committed copy, exercised, and
restored (`git checkout --`, `git status --porcelain` empty afterward):

* **N1** — `run_kart_build` mutated to call `build_wheel`-style in-process
  execution instead of `submit_fn`/`status_fn` → the "no execution in the
  broker" test (`test_resolve_build_import_names_never_executes_anything`)
  and `test_run_kart_build_submits_and_awaits`'s call-count assertions on
  `submit_fn`/`status_fn` catch it.
* **N2** — `verify_wheel_against_source`'s byte-comparison mutated away →
  `test_verify_wheel_everify_on_modified_module` goes red.
* **N3** — the outer `except` in `execute_package_upgrade` narrowed back to
  `except subprocess.TimeoutExpired` only (dropping `_CitedActFailure` and
  `OSError`) → `test_ebuild_when_kart_build_task_fails` and
  `test_everify_mismatch_rolls_back_real_files_and_console_scripts` both
  go red (an uncaught path becomes an unhandled Python exception, not a
  clean refusal — red either way, matching the shape N3 itself names).
* **F8d** — `_lane_busy_refusal`'s `None`-is-closed check inverted →
  `test_lane_busy_refusal_fails_closed_when_queue_unreadable` goes red.

See the closing handoff for the pasted red output of each.

## Refusal order (preflight, before any citation)

`EINVAL` → `ENOSRC` (clone / tag / symlinked tree) → `EVENV` → `EPERM` →
`ENOIMPORTERS` → `EDEPS` → `EBUILD` (unrecognised requirement, or no build
python configured) → `EBUSY` (a unit's own lane is running, no
`force_restart`) → `EBUILDROOT` (no Kart-writable scratch root). The ONE
grant-spending citation follows immediately once the envelope check
passes; every failure after that point — including a Kart build failure or
timeout, `EINSTALL`, `EVERIFY`, `ENOTPURE`, or any exception the N3
try/except catches — is cited (see B2).

## Why rework 2 was reopened (Loki 3CBE8D7E)

Rework 2 closed N1/N2/N3, but Loki's next audit found the fix incomplete
in a different way: N2's *verifier* compared the wheel against a
reference the untrusted build could still write.

* **R1** — `src_dir`, `wheel_dir`, and `backup_dir` were all still under
  this checkout's own Kart-writable `worktrees/.wheels/<sha>` (the
  broker's own `willow_mcp` is an editable install of that checkout, and
  its `worktrees/` is `bound_rw` in the live Kart sandbox). The build
  process N2 already treats as untrusted has write access to `src_dir`,
  so it could rewrite the reference AND the wheel together and still pass
  `verify_wheel_against_source`. Three doors in the same class: (a) a
  TOCTOU between verify reading the wheel and pip re-reading the same
  Kart-writable path, with the sha256 never re-checked; (b) rollback
  copying from a Kart-writable `backup_dir` into `$WILLOW_HOME/venvs/
  willow-mcp`, letting a Kart task choose what the broker restores into
  its own venv; (c) the kartikeya clone itself was `bound_rw` (only
  `.git/config`/`.git/hooks` read-only), so `_resolve_tag`'s own
  `refs/tags/*`/`refs/remotes/origin/*` reads were Kart-writable.
* **R2** — rollback was destructive in the window before the backup
  existed: `_rollback()` removed every related entry unconditionally,
  THEN restored whatever `backups` held. A timeout between verify and the
  backup finishing (P1), or an `OSError` from `_backup_entries` itself
  (P2, triggerable from any Kart task by pre-planting a file at the
  predictable `backup_dir/0`), deleted the live package with nothing to
  put back.
* **R3** — only `_CitedActFailure`, `TimeoutExpired`, and `OSError` were
  caught. A non-dict `task_status` result (`AttributeError`, P3) and a
  malformed wheel (`zipfile.BadZipFile`, P4) both escaped the act phase
  uncited.

## What changed in rework 3, and why

### R1 — nothing the broker trusts sits where Kart can write it

`_resolve_tag_from_origin` resolves the tag's commit sha with
`git ls-remote` against the clone's own remote URL — using the SAME
App-token fetch config `pull_executor` already uses (a broker act, no
lease) — never from the local clone's `refs/tags/*`. A local tag that
disagrees with origin is refused (`ENOSRC`), never silently overridden.
The reachability check no longer needs the local clone at all past
reading its remote URL: the resolved sha and origin's default branch are
fetched into a fresh, throwaway, BROKER-PRIVATE bare mirror, and the
ancestry check runs there.

Everything the broker verifies, installs, or restores from now lives
under `_private_root` — `$WILLOW_HOME/package_upgrade/<sha>/` — which
Kart cannot see: the sandbox binds `$WILLOW_HOME` children BY NAME
(`store`, `dispatch`, `handoffs`, `mcp_apps`, `constitutional`,
`venvs/*`, …), never the whole vault, so an unlisted child is simply
absent from every Kart task's view — confirmed against three live
sandbox manifests captured during this rework (Kart tasks LACJC5T0,
USAB3FXV, SLV1BWHZ): `package_upgrade` appears in none of their
`bound_ro`/`bound_rw` lists. The Kart build still gets its OWN copy of
the source (it has to — it needs something to build), under the ordinary
Kart-writable build root; but verification never looks at that copy
again once the private archive exists. The wheel is copied into the
private dir, hashed there, verified there, re-hashed immediately before
`pip install` (refusing on any mismatch — closing the TOCTOU), and that
exact private copy is what gets installed. Backups live under
`<private_root>/backup` — never under the Kart-writable build root.

### R2 — rollback only ever acts on a COMPLETE backup

`_backup_entries` now writes a completion manifest
(`_write_backup_manifest`) ONLY after every copy has succeeded; a partial
or missing manifest means `_rollback_from_manifest` (via
`_load_backup_manifest`) does nothing at all — never guesses, never
half-restores. Once a complete manifest DOES exist, it is safe to remove
whatever is live RIGHT NOW (including anything the install created AFTER
the backup, e.g. a differently-named dist-info) before restoring — the
manifest is the guarantee that there is always something correct to put
back. A pre-existing file at a backup slot is handled by clearing the
broker-owned backup directory before each run.

### R3 — every act-phase exception is caught, not three classes

The try/except now ends in a final `except Exception`, still rolling back
through the same manifest-guarded path and citing a FRANK receipt that
records the exception's own type name (`exception_type`, errno
`EUNEXPECTED`). `run_kart_build`'s non-dict-status check moved inside the
polling loop, immediately after `status_fn()`, rather than only firing
after the timeout elapsed.

### Verifier gaps closed (3CBE8D7E item 3 / 500FCEFB item 1)

* Every file under a declared package root is compared byte-for-byte
  against source, not only `.py` files — a package data file that exists
  in both trees but differs in content now refuses, where it previously
  passed on existence alone.
* Omission: a source module missing from the wheel refuses (`EVERIFY`),
  not only the reverse direction.
* Matching is restricted to declared package roots, so a byte-identical
  repo-root file (`tests/x.py`) cannot pass as package content.
* `entry_points.txt` must equal `[project.scripts]` exactly — names AND
  targets — with no `gui_scripts` entry and no group besides
  `console_scripts` permitted.
* Any member path with a `..` component is refused.
* The wheel's RECORD is validated against its actual contents.

### Should-fix, closed here

`restarted` is now named on every act-phase FAILURE receipt
(`_cited_failure`), not only on success, so a partially-completed restart
is visible on a failure receipt too.

## Mutation-proof evidence (rework 3)

Kart-run mutations, each applied to a fresh `git archive HEAD` copy under
`/tmp`, exercised, and discarded (the tracked worktree itself never
touched — `git status --porcelain` empty after every run):

* **R1** — the local-tag-vs-origin disagreement check neutered → the
  expected `ENOSRC` becomes an unexpected `EBUILD` (an `AssertionError`).
* **R2** — the manifest-completeness gate in `_rollback_from_manifest`
  neutered → `TypeError: 'NoneType' object is not iterable` inside
  `_restore_backup` (rollback tried to act without a real manifest).
* **R3** — the catch-all narrowed back to `except OSError` → a
  `zipfile.BadZipFile` escapes uncaught.
* **M18** (archive by tag name, not resolved sha) — `_archive_tag`'s
  `sha` argument swapped for `tag` → the git call's own ref argument is
  `'v0.3.4'`, not the resolved `'deadbeef1234'`.
* **M19** (deps read at tag name, not resolved sha) — same swap on
  `declared_dependencies`'s ref → same shape red on `git show`.
* **M20** (pip-install timeout rollback removed) — `except
  subprocess.TimeoutExpired` renamed to a class that never matches →
  `EUNEXPECTED` instead of the expected `ETIMEDOUT`.
* **M24** (build-requires importability check dropped) —
  `resolve_build_import_names`'s refusal branch neutered →
  `KeyError: 'import_names'`.
* **M28b** (extra non-.py file in a package root) — the `if extra:`
  refusal neutered → an unmatched extra file is accepted (`ok: True`)
  instead of refused `EBUILD`.
* **M32** (wheel METADATA name check dropped) — the name-mismatch
  condition neutered → `EBUILD` (wrong path, wrong reason) instead of
  the expected `EVERIFY`.
* **M33** (the act-phase `except OSError` branch removed) — narrowed to a
  class that never matches → `EUNEXPECTED` instead of the expected `EIO`.
* **M35** (build subprocess env reverts to `os.environ`) — the pip-wheel
  subprocess call's `env=env` swapped for `env=os.environ` →
  `'env=os.environ'` appears in the generated script text.

See the closing handoff for the pasted red output of each.

## Where the code lives

| File | Responsibility |
|---|---|
| `src/willow_mcp/package_upgrade_executor.py` | The verb itself: resolve, refuse, submit-and-await the Kart build, verify the wheel against source, install, verify, reload, receipt |
| `src/willow_mcp/server.py` (`package_upgrade_execute`, `_lane_running_task_ids`) | The `@mcp.tool` wrapper (gated `envelope_apply`, now takes `force_restart`), and the new internal F8d lane-running read |
| `src/willow_mcp/bundle/constitutional/syscall-table.json` (row 25) | The verb table entry — UNSEALED, see its own `note` |
| `tests/test_package_upgrade.py` | Refusals (incl. `EBUILD`/`ENOIMPORTERS`/`EBUSY`/`EBUILDROOT`), `run_kart_build` unit tests, `verify_wheel_against_source` unit tests (ENOTPURE/EVERIFY/EBUILD each), the offline/scrub invariants, the granted path, rollback (incl. console scripts, timeout, `EINSTALL`, an archive timeout, a systemd restart timeout), citation-before-mutation, F8/F8d reload tests |
| `tests/test_syscall_row_25_package_upgrade.py` | Bounds-signature exactness, row density, the UNSEALED note |
