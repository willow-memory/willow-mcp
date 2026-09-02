# willow-mcp — Bug Log

A single running log of bugs found in willow-mcp, across all sessions. One row
per bug. This is the durable record; FRANK ledger entries, GitHub issues, and
`SECURITY_AUDIT.md` are the source material it's backfilled from and links to.

**Keep this current.** When a bug is found, add a row (Open). When it's fixed,
flip Status to Fixed and fill the Fix + Ref. Don't delete rows — a Fixed/Stale
row is the history. Security findings live in full in `SECURITY_AUDIT.md`; this
log carries a one-line entry and points there rather than duplicating.

**Conventions**
- **ID** — sequential `B-NN`, assigned in rough order of discovery. Stable; never reused.
- **Sev** — P0 (auth/data defeat) · P1 (integration/blocking) · P2 (reliability/correctness) · P3 (completeness/DX/test).
- **Status** — `Open` · `Fixed` · `Documented` (known, worked-around in docs, no code fix) · `Stale` (never real in current code) · `Wontfix`.
- **Ref** — canonical pointer: `L-*` = SECURITY_AUDIT finding · `PR #n` · `issue #n` · `FRANK <id>`.

## Summary

| ID | Sev | Status | Component | One-line | Ref |
|----|-----|--------|-----------|----------|-----|
| B-14 | P0 | Fixed | Kart sandbox / trust root | Kart bwrap had R+W to `$WILLOW_HOME/mcp_apps` (manifests + identity bindings) — untrusted runtime could rewrite the ACLs that gate it. Fixed: `mcp_apps` now `bound_ro` in bwrap | FRANK `baf2f63a`, `293b2130`; willow-2.0#777; probe `MAGSU06N` |
| B-15 | P3 | Fixed | knowledge / kb | `kb_startup_continuity` silently returned empty — filtered on a `tags`/`domain='continuity'` shape the adopted DB lacks. Fixed: read tags from the jsonb `content->'tags'` blob + always emit `_continuity_filter` | issue #20; probe `707E561A` |
| B-16 | P3 | Fixed | server pipeline | `_sanitize` fired before the permission gate — a denied caller could trip sanitizer errors first. Fixed: `_guarded` now runs gate → sanitize → rate | FRANK `90960b8b`; probe `4D9139B8` |
| B-17 | P2 | Fixed | schema / tasks | `task_status` never surfaced completion time — the adopted `tasks` table had no `completed_at` column. Fixed: added the column + a self-populating trigger on the shared DB, and mapped it; `steps` stays unmapped (still no such column) | this session; probe `R2BSZ9FZ` |
| B-18 | P3 | Fixed | diagnostics | `diagnostic_summary` returned verdict `degraded` when the caller merely omitted `app_id`. Fixed: missing `app_id` is a `caller_input` warn (surfaced in `problems` + manifest sub-check) that no longer degrades the verdict | this session; probe `E3265B66` |
| B-19 | P2 | Fixed | task interface / Kart | `task_submit` had no `allow_net`. Fixed: `allow_net=True` gated by a new `task_net` manifest permission (not in full_access) appends the worker's `# allow_net` directive | this session; probe `5H1M355V` |
| B-20 | P3 | Fixed | repo metadata / docs | GitHub "About" description read "Superseded by Willow 2.0 … now live in the monorepo" — stale, contradicting the active 2.0.0 repo; visible to anyone (surfaced in an external review). Fixed via `gh repo edit --description`; repo confirmed not archived | this session; DeepSeek review |
| B-21 | P0 | Fixed | task interface / Kart | `task_net` gate bypassable via task text — the worker reads egress policy from a `# allow_net` line in the stored task, but `task_submit` gated & appended that line only behind `if allow_net:`, so a `task_queue`-only caller could embed the directive with `allow_net=False` and get ungated egress (also `# allow_localhost`). Fixed: strip caller-supplied directive lines unconditionally before the gated append | this session; L-NET-01; PR #32; PR #31 review §2a |
| B-22 | P1 | Fixed | packaging / Kart | Product shipped **no task executor** — `pyproject` advertised a "Kart task queue" but no worker/sandbox was in the package; a clean `pip install` left every task `pending`. Fixed: Kart extracted as the published **`kartikeya`** package (PyPI) and made a hard dependency; `willow-mcp worker` + `WillowMcpTaskQueue` (Pg/SQLite) drain the queue | this session; `docs/design/kart-lift-spec.md`; PRs #35, #36; kartikeya 0.0.1 |
| B-23 | P3 | Fixed | process / skills+hooks | Task-queue surface (`task_submit`/`task_net`, B-19; `# allow_net` footgun, B-21) shipped with no skill or hook, violating the "hooks/skills ship with the tool" rule (`docs/design/hooks-and-skills.md` §2). Fixed: added `skills/kart-tasks.md` + a `task_submit` matcher on `pre_tool_use.py` warning on hand-embedded net directives | this session; operator-caught |
| B-24 | P0 | Fixed | db / store | `store_*` tools (put/get/list/update/search/delete/search_all) had no cross-app isolation — `app_id` was discarded after the permission gate, `db.py` never scoped by it, so any app with `store_read`/`store_write`/`full_access` could read/write/delete every other app's SOIL data. Fixed: opt-in `store_scope` manifest field (exact/prefix-wildcard collection allowlist), checked by all six single-collection tools + `store_search_all`; unscoped apps keep the shared-fleet-store default | L-ISO-01; PR #31 review §2b; this session |
| B-25 | P1 | Fixed | gate / store | `gate.store_scope()` **failed open**: an invalid `app_id`, a missing/unparseable manifest, or a malformed `store_scope` all returned `None` — *unrestricted* — with only a log warning. `"store_scope": "myapp_*"` (a string, the obvious typo for this field) silently granted full store access to an operator who believed the app was confined, inverting `gate.py`'s own header contract ("Fail-closed: missing app_id, missing manifest … → deny"). Fixed: all three paths return `[]` (deny-all); explicit `null` still means "no policy declared". Malformed scope logs at `ERROR` | follow-up to B-24; this session |
| B-26 | P2 | Fixed | task interface / worker | Task queue had **no liveness signal** — `task_submit` returned `{"status":"pending"}` identically whether a worker was about to run it or none existed, so a stranded queue was indistinguishable from a busy one. Fixed: `willow-mcp worker` publishes a heartbeat via kartikeya's `on_heartbeat` seam; `fleet_health` gains `workers`/`stranded`, `diagnostic_summary` gains a `worker` check | Kart lift stage 4; this session |
| B-27 | P3 | Fixed | packaging / docs | Three code paths told operators to `pip install willow-mcp[worker]` — an extra that **does not exist**; `kartikeya` has been a hard dependency since B-22, so the advice was unrunnable | found during B-26; this session |
| B-28 | P3 | Fixed (fleet) | schema / tasks | `completed_at` stayed null on **failed** tasks under B-17's original trigger (fires only on `'completed'`). **Repo DDL is correct**; fleet `willow_20` re-applied from `docs/schema/tasks.postgres.sql` 2026-07-31 (`failed` + `completed` both stamp). | observed live, probe `1T8G5WG5`; follow-up to B-17 |
| B-29 | P0 | Fixed | gate / consent | `allow_net` egress was gated **only** by the `task_net` manifest capability — the operator's standing `consent.internet` gated nothing. The fleet flag `consent_internet_gates_allow_net` was declared `implemented: false, status: deferred`, so the switch existed and was wired to nothing. Fixed: two-key gate (`task_net` **and** `consent.internet`), read fail-closed | egress-membrane design; FRANK `cc553729`; this session |
| B-30 | P1 | Fixed | consent / config | The two consent files **disagreed** and the one an operator would naturally edit appeared inert. `consent.json` said `internet: false, lan: false`; `settings.global.json` said `true, true`. **First diagnosis was wrong:** `consent.json` is not a legacy leftover but a **write-only mirror** — `save_global_settings(sync_legacy=True)` (the default) and Grove's consent toggle both rewrite it on every save, while it is *read* only when the canonical file is absent. So it drifts silently and a delete does not stick. Resolved by re-syncing the mirror from canonical; the misleading "delete the legacy file" advice is gone from `diagnostic_summary` and `consent.py` | observed live; corrected 2026-07-09 |
| B-31 | P1 | Open | consent / willow-2.0 | `global_settings.py` **fails open**: `DEFAULT_CONSENT` is all-`True`, and `_normalize_consent()` returns those defaults for any non-dict — a missing, truncated, or malformed consent block resolves to *all permitted*. Same inversion as B-25. willow-mcp now reads fail-closed independently; the writer is unfixed and out of this repo | cross-repo (willow-2.0); this session |
| B-32 | P1 | Fixed | gate / sudo invariant | Host-side self-grant closed when operator runs **`willow-mcp harden-trust-root`**: `chown` trust roots (`mcp_apps/`, `config/`) to a dedicated unix user, world-readable modes for MCP read paths, and `WILLOW_MCP_STRICT_TRUST_ROOT=1` in MCP env. Confirm authority (`grant-net`, `consent set`) runs as that user via `sudo -u <owner>`. Pre-harden: mitigated by leases + PreToolUse hook + `diagnostic_summary.self_writable`. **issue #231 addendum:** the tooling above existed but no concrete "which uid runs what, in what order" deployment runbook did — added `docs/deploy/dedicated-uid-deployment.md` (stdio-shared-uid and serve-mode-separated-uid shapes) plus `trust_root_setup.uid_separation_report()` / `diagnostic_summary.checks.uid_separation` (a plain ownership-identity readout next to, never substituting for, `self_writable`), surfaced in `doctor`/`harden-trust-root` CLI output. Purely additive and informational — not wired into `problems`/the verdict, `WILLOW_MCP_STRICT_TRUST_ROOT` stays off by default, and none of it has been exercised on a real multi-uid host (every sandbox this shipped from runs single-uid) | FRANK `90e52ab7`; L-NET-02; `trust_root_setup.py`; issue #231 |
| B-33 | P1 | Fixed | consent / Kart sandbox | The documented fleet-wide egress off switch was **writable from inside bwrap**. B-14 bound `mcp_apps/` `ro`; consent policy files beside it were not. **Fixed:** kartikeya `collect_mcp_trust_ro_overlays` overlays `settings.global.json` (root + `config/`), `consent.json` (root + `config/`), and `mcp_apps/` as `bound_ro` inside bwrap (kartikeya#6, 0.0.4; `config/consent.json` added 0.0.5). willow-mcp's floor was raised to `kartikeya>=0.0.5` for this fix and has since moved on (today `kartikeya>=0.0.9,<1.0.0` — see `pyproject.toml`); the contract is regression-tested rather than trusted to the pin (`tests/test_b33_consent_sandbox.py`). **Scoped honestly:** closes the **sandbox lane** for consent key 2 only — host-side agent can still edit policy files (B-32 class); an attacker still needs `task_net` (ro) and a live lease (protected) | probed from inside bwrap 2026-07-09; fixed kartikeya 2026-07-21; PR #125 |
| B-34 | ~~P0~~ | Stale | gate / orchestrator seat | ~~`human_only` is a dead field and `WILLOW_HUMAN_ORCHESTRATOR` is read by no code. Any agent holding `app_id=willow` can dispatch, verify, and clear.~~ **FALSE. The gate exists, is wired, and fires.** `human_session.py:41` reads `WILLOW_HUMAN_ORCHESTRATOR`; `server.py:201` calls `orchestrator_write_denial(effective, tool_name, serve_mode=…)` and `:202` returns it; the denial string `orchestrator_human_required` is at `human_session.py:60`, not absent. Two layers, conflated in the original: `gate.py` is the **manifest ACL** (it does contain the three tools), `human_session.py` is the **host attestation** applied after it. Observed firing on a live `dispatch_send` by the willow seat, 2026-07-09T12:26Z (FRANK `66bfd8b3`). **Root cause of the false alarm:** the probe called `diagnostic_summary()` with no `app_id`, so `is_orchestrator_app(None)` short-circuited `orchestrator_write_denial` to `None` — the gate was tested by not being the identity it guards. Withdrawn by root before any patch; had it been actioned, a working trust boundary would have been rewritten or deleted. Moved to *Stale* | filed 2026-07-09 (willow seat); refuted and withdrawn same day — FRANK `c4f7bec5`, `e4759e8b` |
| B-35 | P1 | Open | governance / envelope registry | **Metered envelopes are unmetered; the citation the meter derives from is never written.** `envelopes/pre-approved.json` mandates `use_count_source: "frank"` — a count *derived* by tallying `envelope_citation` ledger entries, deliberately not stored ("a stored counter is mutable state an agent could touch"). The strings `envelope_citation` and `envelope_id` have **zero** matches across all of willow-2.0. `ledger_read()` (`core/pg_bridge.py:3214`) filters by project + limit only. So `max_count: 20` (`env-pr.merge-willow2-master`) and `max_count: 40` (`env-dispatch-fleet-sessions`) enforce nothing, `EDQUOT` can never fire, and verb 13 `envelope.apply` — the act that licenses the orchestrator seat — is `enforced_by: null`. Cross-repo (willow + willow-2.0); logged here because `gap_log` is gate-denied to `app_id=willow` (B-36) | found 2026-07-09 (willow seat); `syscall-table.json` invariants §13–19 |
| B-36 | P2 | **Resolved (PR12, 2026-08-26)** | gate / permission groups | Original: `gap_log`/`gap_list`/`gap_resolve` (PR #54) and `kb_startup_continuity` gate-denied for `app_id=willow` — the seat whose job is noticing couldn't call the tool built for noticing. **Recommendation was "do not widen the group"** and that discipline was preserved: the shared `orchestrator` permission group is unchanged; PR12 widened willow's OWN permissions list in `bundle/config/specialists.json` instead. `gap_write` now grants `gap_log`/`gap_list`/`gap_resolve` to willow directly (the skill doc contradiction between "do not widen orchestrator" and "willow already had gap_write" reconciled in the same PR — different axes: shared group vs. willow-only list). `kb_startup_continuity` is in `knowledge_read` and was already permitted via willow's original `knowledge_read` grant. Underlying store/DB severance point is unchanged (still a live SOIL collection under `WILLOW_HOME`) but ACL is no longer the friction | found 2026-07-09 (willow seat); resolved by PR12 enabled-operator alignment; see `docs/design/permissions-matrix.md` §4 |
| B-37 | P0 | Fixed | kart / egress | `# allow_net` is now a request only. Kartikeya 0.0.2 requires a host authorizer for every network row and denies missing attribution/envelope/verifier or callback failure before shell launch. willow-mcp supplies execution-time capability, consent, lease, strict trust-root, Ed25519 signature, exact normalized task hash, expiry, and atomic nonce-replay checks. The signed envelope travels through TaskRow and SQLite/Postgres without inventing legacy authority; signing is an interactive local CLI with no MCP surface. | work order `60CB6361`; FRANK `8683cd84`, `41c2375a`; follow-up to B-19/B-21/B-29/B-32 |
| B-38 | P2 | Fixed | diagnostics / severance | The severance check shipped in PR #57 asserted **three** surfaces — `store`, `postgres`, `trust_root` — and egress was not one of them. An install could be perfectly severed (own store, own database, trust root beyond reach, verdict `ok`) and still reach the internet, because the shell tool its operator actually calls takes `allow_net` as a **parameter** (B-37). Severance from a fleet's *state* is not severance from a fleet's *network*. **Fixed:** `_diag_severance` now asserts a fourth surface, `egress` (`_egress_severance`), that this process cannot forge the three-key network gate — reusing the manifest + lease-root paths and adding the two the `trust_root` message named but never measured: the `consent.internet` switch and the Ed25519 verification key (checkable only once B-37 moved the signing key beyond write reach). Strict-on + a forgeable key or unprotected verifier → `error` (breaks, like trust_root); strict-off → `unknown`/`warn` (degrades, never breaks, B-18) — so the 2026-07-09 install now reports `partial`, not `ok`. | found 2026-07-09 (hanuman); FRANK `8683cd84`; PR #57; unblocked by B-37; fixed 2026-07-20 |
| B-39 | P1 | Fixed | docs / tool schema | `task_submit` and consent documentation once overstated submit-time checks as a fleet-wide network gate. The text was corrected when found; B-37 now closes the underlying executor defect with signed per-task authorization and execution-time policy checks. | found 2026-07-09 (willow seat); supersedes B-33 doc clause; closed structurally by B-37 |
| B-40 | P1 | Fixed | worker / packaging | `willow-mcp worker` unstartable with **every published kartikeya** — the f1e8c9b guard imports `sandbox.resolve_sandbox_config`, which no PyPI release (≤0.0.7) ships, and the ImportError was fatal on every lane (including dev fast lanes the guard itself would allow), re-breaking B-22's shipped-drainer guarantee; the error's remedy ("Upgrade kartikeya") was unrunnable, same class as B-27. Fixed: fallback names the policy source itself by mirroring `load_sandbox_config`'s search order; production lanes still refuse the vendored default with the same message. Residual: bump the pin + drop the fallback once kartikeya ships the API | issue #165 (closed); PR #172 |
| B-41 | P2 | Fixed | deploy / claude-code-web | MCP server spawned with **no `WILLOW_*` env** in Claude Code web — the SessionStart hook wrote env to `$CLAUDE_ENV_FILE`, which shells inherit but the client-spawned stdio server does not; it defaulted `WILLOW_HOME` to `~/.willow` (no manifests) and gate-denied `session_enter` for every seat. B-12's bug class in a new lane. Fixed: `session-start.sh` generates the gitignored `.mcp.json` with the resolved env embedded (B-12's "env-freeze" polish); hook invoked via `bash` so a mode-stripped clone still boots. Follow-ups on the same seam: worker auto-start + guarded schema auto-confirm (`sandbox_confirm.py`), so a cold container boots the full stack | issue #166 (closed — operator kept the web-lane orchestrator flag); PR #172 |
| B-42 | P3 | Fixed | tests / schema | `tests/test_egress_row_gate_postgres.py` hardcoded the adopted fleet's `id` column, so all 6 tests failed (`UndefinedColumn: "id"`) against a sandbox bootstrapped from the repo's own `docs/schema/tasks.postgres.sql` (`task_id`) — and its fixture wiped the live table via `DELETE FROM tasks`. Fixed: every test parametrized over BOTH layouts inside a dedicated pytest schema (`search_path`), so the schema-adapted row-gate contract is exercised on each and live data is never touched; 6 tests → 12 | issue #167 (closed by merge); PR #173 |
| B-43 | P1 | Fixed | security / mai | mai directives executed **ungated** when the tools were registered — `@db` arbitrary SQL on the willow Postgres, `@http` open SSRF, `@env` any-env-var exfiltration, and internal `render()` calls ran all of it with no authorization anywhere in `mai/`. Fixed: three manifest groups (`markdownai_read`/`_write`/`_directives`, none in `full_access`), app_id threaded through all ten tools + `render()` (ungated render yields refusal text), `@db` requires a manifest-allowlisted `"mai_connections"` name, `@http` honors `consent.internet` + SSRF blocklist, `@env` default-denies behind `WILLOW_MAI_ENV_ALLOW`; 18 abuse tests | issues #161/#153; PR #173 |
| B-44 | P0 | Fixed | egress / trust root | The egress private signing key was `chmod 600` but owned by the agent's own uid — on a single-uid host, reading it needs no forgery at all: the agent signs with the real authority, collapsing the three-key egress gate to the two it can already write (task_net, consent). `harden-trust-root` never touched it (the key lives outside `$WILLOW_HOME` by design, so it wasn't one of `trust_root_directories()`) and `self_writable_trust_paths()`/B-38's severance check only ever asked whether the key could be *written*, not *read* — a hardened install could report `self_writable: []` while the key sat fully exposed. Fixed: `apply_egress_key_hardening()` chowns the egress directory to the trust owner at 0700/0600 (owner-only, stricter than the 0755/0644 policy roots use, since manifests/leases must stay world-readable for the gate but the signing key must not), wired into `harden-trust-root`; `lease.egress_key_readable_by_self()` + `path_is_self_readable()` measure it and feed both `_diag_net_lease` and B-38's `_egress_severance`, so a readable key now shows up in `self_writable`/`forgeable_keys` and breaks the verdict under strict mode, same as a forgeable manifest | issue #182; part of the #181 kill chain |
| B-45 | P0 | Fixed | gate / identity | App manifests were honored as-is with no signature check — a writable `mcp_apps/<app>/manifest.json` let an agent self-grant any permission group or forge a fleet-operator-trust identity outright (demonstrated: `mcp_apps/steve/manifest.json` → `whoami` reports `steve`). The P1 slice of the LOCKED `docs/design/pgp-and-persona.md` (2026-07-09) — "manifest `.sig` check in `gate.permitted()` when fingerprint env set" — specified exactly this fix and was never implemented; `pgp.py`'s sign/verify primitives existed but nothing called them for manifests. Fixed: `gate._load_manifest()` now runs `pgp.verify_detached()` against `manifest.json.sig` whenever `WILLOW_PGP_FINGERPRINT` is set, returning `None` (the same "deny" every caller already fail-closes on) for a missing, tampered, or wrong-signer signature — no per-call-site change needed. Unset (the default), behavior is byte-for-byte unchanged: no product `pgp_enforced` toggle, matching the locked design's explicit rejection of one. New `willow-mcp sign-manifest <app_id>` CLI (operator-terminal only, same `WILLOW_IN_KART`/isatty guard as `sign-net-task`). Verified against a real, disposable Ed25519 GPG key (not mocked) end to end via both pytest and the actual `willow-mcp` console script under a real pty: sign → trusted; tamper after signing → denied; forge an unsigned identity → denied; reuse one manifest's `.sig` against another → denied; valid signature from the wrong key → denied | issue #183; part of the #181 kill chain |
| B-46 | P1 | Fixed | trust root / secrets | `willow-mcp repair-runtime-perms` — a step in the documented, recommended B-32 hardening flow — **downgraded** `vault.key` (the Fernet key decrypting OAuth client secrets/Apple's p8 key in `vault.db`) and `mcp_token.json` (persisted OAuth bearer tokens) from their own `0600` default to world-readable `0644`. Found during a #181 audit of existing hardening coverage for gaps of the same class #182 found: `vault.key`/`vault.db`/`mcp_token.json` sit at `$WILLOW_HOME`'s top level, not under a scaffolded directory, so the generic `runtime_writable_home_children()` sweep caught them and applied the same world-readable mode it gives ordinary runtime state (store/, dispatch/, …) — verified live by creating a real vault and watching `repair_runtime_permissions()` flip `vault.key` from `0600` to `0644`. Fixed: these three filenames now get owner-only `0700`/`0600` instead — they stay owned by the *runtime* user (unlike the egress key, the running server legitimately reads them, so they can't move to the trust owner), just at a stricter mode. New `trust_root_setup.secret_file_exposure()` reports any of the three that are currently group/world-readable, folded into `audit_trust_root()`'s `hardened` bool and the `willow-mcp doctor` CLI's warning output (which previously only printed when `forgeable` was non-empty — a secret-file-only exposure computed `hardened: false` but printed nothing) | issue #228; found during #181 audit |
| B-47 | P1 | Documented | deploy / MCP config | The repo's `.cursor/mcp.json` (`willow-mcp` namespace) launches with default `WILLOW_HOME=~/.willow` and no `WILLOW_PGP_FINGERPRINT` / `WILLOW_MCP_ENFORCE_BINDING`, while an operator's separately-configured, hardened global Cursor config is a different trust posture under the same product — easy to "test green" on the unhardened repo desk while believing the hardened one was verified. This repo commits no fleet secrets to the unhardened config by design (there's nothing to move here); documented in README.md's "MCP config" section as dev-only, with the fix direction spelled out (set `WILLOW_PGP_FINGERPRINT`/`WILLOW_MCP_ENFORCE_BINDING` in this file's own `env` block if you need enforcement while developing) | red-team 2026-07-31 (cursor `willow-mcp` vs `~/.cursor/mcp.json` `willow`); issue #235 |
| B-48 | P1 | Documented | gate / dispatch | `dispatch_write` is not binding-gated and not human-attested — any stdio caller passing `app_id=hanuman` (or any manifest with `dispatch_write`) can `dispatch_send` and create real packets with no per-call credential (demonstrated live, `dispatch_id=7BE854FD`, hanuman→loki). Traced: `_enforce_binding_gate` already applies uniformly to `dispatch_write` when `WILLOW_MCP_ENFORCE_BINDING=1` — it's a no-op for an *unregistered* app_id by design (fail-closed for an un-instrumented client, not silent bypass). Closes today only when the operator both enables binding and registers every builder seat — same two-step deployment gap as #231's uid separation, not a code bug. Making `dispatch_write` refuse unregistered app_ids unconditionally was considered and deferred: a breaking default-posture change for any install with unregistered builder agents, bigger than this one finding warrants alone. Documented as a residual in `willow-gate-seam.md` D6 | red-team 2026-07-31; permissions-matrix hanuman row; issue #236 |
| B-49 | P2 | Documented | gate / binding | Ungated `whoami` leaks any manifest when binding is off — already covered by `docs/design/willow-gate-seam.md` D3's own "CLOSED" section: `_own_identity_denial` gates it exactly when `WILLOW_MCP_ENFORCE_BINDING=1` and the app is registered, no-op otherwise (the accepted trusted-host stdio model, same posture as every other tool). Reconciled, not a new gap | red-team 2026-07-31; `willow-gate-seam.md` D3; issue #237 (closed) |
| B-50 | P2 | Fixed | deploy / schema_maps | `task_submit` passed the gate then died writing schema maps under `mcp_apps/<app>/schema_maps/` with `EACCES` once `mcp_apps/` was actually trust-root-hardened to the operator uid (B-45/#183's whole point) — the runtime process can never create a subdirectory under a `0755`, operator-owned parent, regardless of what's excluded from any chown sweep. Was a documented, deliberate placement (`schema-adaptation.md` §3.2 original), not an oversight — the two designs (schema_maps-under-mcp_apps, mcp_apps-gets-hardened) simply conflicted once both were actually applied together. Fixed (operator-approved amendment to the LOCKED `product-layout.md`): `schema_maps/<app_id>/` relocated to its own top-level `$WILLOW_HOME` root, sibling to `store/` — a runtime-writable directory that was never under `mcp_apps/` in the first place, so the conflict can't happen | red-team 2026-07-31; same class as B-41 env freeze; issue #238 |
| B-51 | P0 | Fixed | dispatch / gate | `dispatch_write` granted `verify_handoff` + `agent_clear` to builder seats — same group as `dispatch_send`, so any manifest with `dispatch_write` could self-verify and self-clear its own dispatch with zero orchestrator/human involvement (demonstrated live: `hanuman` forged send → `loki` accept/handoff → `hanuman` `verify_handoff`+`agent_clear`, no `WILLOW_HUMAN_ORCHESTRATOR`, no binding, no PGP). Fixed: `verify_handoff`/`agent_clear` removed from the `dispatch_write` group in `gate.py` — they remain reachable only via `orchestrator`, which is human-attestation-gated (`ORCHESTRATOR_WRITE_TOOLS`). `dispatch_write` still grants `dispatch_send`/`dispatch_accept`/`handoff_write_v4`/`session_handoff_write`, the send/accept/close-out lifecycle a builder legitimately needs over its own work | red-team 2026-07-31; extends B-48; issue #240 |
| B-52 | P1 | Fixed | dispatch / filesystem | **`$WILLOW_HOME/dispatch/` is operator-writable** — a local uid can `mkdir` a packet (`DEADBEEF`) with arbitrary `meta.json`; it appeared in `dispatch_list` and could target `to_app=willow` for social engineering at `session_enter` / accept time (recipient check still applied). Not MCP-forged; bypassed all gate logic for packet *existence*. Fixed: `dispatch_send` now HMAC-SHA256-signs every meta.json field (runtime-held key, `dispatch_signing.py`, custodied via the existing `_SECRET_FILE_NAMES` convention); `dispatch_read`/`dispatch_list` verify it — a packet with no signature (`legacy_unsigned`, pre-fix packets) is excluded from the normal trusted list and surfaced separately with `unverified: true`, hard-rejected only under `WILLOW_MCP_STRICT_TRUST_ROOT=1`; a present-but-wrong signature (`invalid`, forged or tampered) is always refused. Residual, same as every entry in this class: same-uid still means the attacker can read the key too — full closure needs the uid separation of #231 | red-team 2026-07-31; issue #241 |
| B-53 | P0 | Fixed | human_session / dispatch | `orchestrator_human_required` was incomplete for `app_id=willow`: only `dispatch_send`, `verify_handoff`, `agent_clear`, `frank_append`, `envelope_apply` were in `ORCHESTRATOR_WRITE_TOOLS` — `dispatch_accept` and `handoff_write_v4` were not, even though `session_enter` itself refuses a dispatch_id for `app_id=willow` up front (that guard lived only there). Demonstrated live: stdio `app_id=willow` (no `WILLOW_HUMAN_ORCHESTRATOR`) accepted real packet `96F54DA7` and completed it via `handoff_write_v4`. Fixed: both added to `ORCHESTRATOR_WRITE_TOOLS`; the denial message now names whichever tool was actually called instead of a fixed three-tool list, so it can't drift again as the set grows | red-team 2026-07-31; issue #239 |
| B-54 | P1 | Fixed | dispatch / ACL | `dispatch_read` / `handoff_read` had no packet-level ACL — any app with `dispatch_read` could read **any** `dispatch_id` (demonstrated: `hanuman` read `A0939A8C` handoff with commit SHAs, PR URLs, CI notes). Gate checked tool permission, not whether the caller was `from_app` / `to_app` / `reply_to`. Fixed: `dispatch.is_dispatch_party()` checks the caller against the packet's own `meta.json`; `server.py`'s `dispatch_read`/`handoff_read` wrappers deny with `not_party_to_dispatch` (no packet content in the denial) unless the caller is a party or the orchestrator | red-team 2026-07-31; issue #242 |
| B-55 | P1 | Fixed | dispatch / TOCTOU | Pending `assignment.md` was mutable on disk by the operator uid between `dispatch_send` and specialist/orchestrator read (append demonstrated on `96F54DA7`; reverted) — same writable `dispatch/` root as B-52, prompt-injection / instruction-smuggling without touching MCP. Fixed: `dispatch_send` now records a sha256 of `assignment.md` in `meta.json`; `dispatch_read` (and everything that calls it internally — `dispatch_accept`, `handoff_write_v4`) verifies it and returns `assignment_tampered` on mismatch. Not full closure — dispatch/ is still operator-writable (B-52's own residual) — but the tamper is now detected and refused instead of silently trusted | red-team 2026-07-31; issue #243 |
| B-56 | P0 | Open | egress / host | **Egress signing key readable on this workstation** — `~/.config/willow-mcp/egress/private.pem` is mode `600` but owned by the same uid as the agent/MCP process (`EGRESS_KEY_READABLE` probe). Collapses the third egress key locally (#182 class); unrelated to MCP ACL | red-team 2026-07-31; issue #182; issue #244 |
| B-57 | P1 | Fixed | store / trust root | `repair_runtime_permissions()` left store `.db` files (`store.db` per SOIL collection, `kart.db`, `mcp_receipt.db`) world-readable `0755`/`0644` — the client-side hook (`hooks/pre_tool_use.py`'s `_OWNED_DB_FILE_RE`) was the only thing stopping a same-uid read, exactly what issue #232 named ("the hook fires, not that the OS refuses the write"). Found in passing: `mcp_receipt.db` was only ever *chowned*, never *chmodded*, by its own dedicated block — a real gap independent of #232's main ask. Fixed: `store_root()` gets the same owner-only `0700`/`0600` treatment `_SECRET_FILE_NAMES` gives `vault.key` (B-46); `mcp_receipt.db` added to `_SECRET_FILE_NAMES` itself; `kart.db` hardened wherever `WILLOW_STORE_ROOT` actually resolves it to. New `trust_root_setup.store_db_files()`/`store_db_exposure()` (mode-bit hygiene, same shape as `secret_file_exposure()`) feed `audit_trust_root()`'s `hardened` bool and a new, purely-informational `diagnostic_summary.checks.store_db_perms` (never wired into `problems`/the verdict, B-18 discipline, same as #231's `uid_separation`). Like #231, changes nothing for today's single-uid installs (the runtime uid already owns these files); only closes the gap once uid separation is actually deployed — real closure still needs a real multi-uid host, none of which this sandbox has | issue #232; depends on #231 |
| B-01 | P0 | Fixed | oauth / gate | Serve-mode OAuth identity never bound to `app_id`; `app_id` taken from caller args, not the authenticated session | L-AUTH-02 |
| B-02 | P1 | Fixed | integration | No `safe_integration.py` — server invisible to Willow orchestration | L-INT-01 |
| B-03 | P2 | Fixed | server / rate limit | Unbounded `_buckets` dict keyed on raw caller `app_id` before validation | L-DOS-01 |
| B-04 | P2 | Fixed | db / knowledge | Empty/whitespace search query builds malformed SQL, unhandled crash | L-BUG-01 |
| B-05 | P2 | Fixed | db / Store | `Store._conn()` lock doesn't cover `execute`/`commit` — concurrent calls can interleave | L-CONC-01 |
| B-06 | P2 | Fixed | tests | Coverage was 1 of 7 source files — auth/gate/rate paths untested | L-TEST-01 |
| B-07 | P3 | Fixed | cli | `willow-mcp setup` referenced in docs/HTML but never implemented | L-DOC-01 |
| B-10 | P2 | Fixed | schema / knowledge | Confirmed `knowledge` mapping selected the `content` provenance blob as canonical text; real title/summary never surfaced; `domain` null | FRANK `90960b8b`/`88d13197`, issue #20, PR #21 |
| B-11 | P2 | Fixed | schema confirm | `schema_confirm_mapping` confirmed on name-match alone (assertion, not evidence) — no rendered sample shown | PR #21 |
| B-12 | P3 | Documented | serve / deploy | systemd `--user` serve unit doesn't inherit shell `WILLOW_PG_DB`/`WILLOW_STORE_ROOT`/`WILLOW_HOME` → serve reads `table_not_found` on data stdio sees | PR #18 |
| B-13 | P3 | Fixed | tests | Rate-limit tests shared one `app_id`, exhausting the token bucket → cross-test failures | (in-tree; `_buckets` reset in fixtures) |
| B-58 | P2 | Fixed | code_graph / indexer | `ast.walk` double-counts class methods — methods added once as `module.Class.method` (ClassDef branch) and again as `module.method` (FunctionDef branch); comment "Skip if inside a class" at line 147 checks nothing. `ON CONFLICT DO UPDATE` prevents crash but produces incorrect FQNs and inflated symbol counts | audit 2026-08-24; branch `claude/hanuman-bugfix-b58-b59-b64` |
| B-59 | P2 | Fixed | db / soil_heartbeat | `soil_heartbeat.py:112` uses `INSERT OR REPLACE INTO records` — the exact pattern `db.py:173` moved away from (deletes+re-inserts, resetting `deleted` to 0 and `created_at`). Inconsistent with the documented security fix | audit 2026-08-24; branch `claude/hanuman-bugfix-b58-b59-b64` |
| B-60 | P2 | Fixed | tool_oracle | `_store()` destructures `_nestor()` result without None check — raises `TypeError: cannot unpack non-iterable NoneType` when Nestor is unavailable. Callers guard, but `_store()` itself does not | audit 2026-08-24; fixed 2026-08-24 |
| B-61 | P2 | Fixed | oauth / serve | Google and Apple sign-in error handlers render raw `f"{exc}"` into HTML response (`oauth.py:589,646`). If exception contains internal details (stack traces, URLs), leaks sensitive info to browser | audit 2026-08-24; branch `claude/loki-security-b61-b62` |
| B-62 | P2 | Fixed | session_inject | `_MARKER` at `session_inject.py:14` is a predictable, world-readable `/tmp/willow-session-inject-marker.json`. Multi-user collision; another process can tamper to replay or suppress injections | audit 2026-08-24; branch `claude/loki-security-b61-b62` |
| B-63 | P2 | Fixed | federation | `_ServerConnection._ensure_started()` at `mcp_federation_client.py:330` checks `self._thread is not None` without a lock. Two concurrent callers can both start threads. `connect()`/`list_tools()`/`call_tool()` call it directly | audit 2026-08-24; fixed 2026-08-24 |
| B-64 | P3 | Fixed | code_graph / indexer | `_index_file()` uses `executemany()`/`execute()` for symbols/edges/indexed-files inserts but never calls `conn.commit()`. Data lost if caller does not commit and connection closes | audit 2026-08-24; branch `claude/hanuman-bugfix-b58-b59-b64` |
| B-65 | P1 | Fixed | kart sandbox / work root | **`WILLOW_ROOT` was bound read-write, so a sandboxed task could edit the code that decides what tasks may do.** B-14 overlaid `mcp_apps/` and B-33 overlaid the consent kill switch; neither covered the *code that reads them*. Probed from inside a real task 2026-09-02: `src/willow_mcp/gate.py` (the manifest ACL), `pyproject.toml` (the `kartikeya>=` floor that ships B-14/B-33's own overlays), `.git` and `.gitignore` all **WRITABLE**, while `mcp_apps/` and `consent.json` were correctly read-only — the policy files protected and the code honouring them not. B-33's sentence one layer down. **Fixed:** kartikeya#37 binds `WILLOW_ROOT` read-only and makes `{{WILLOW_ROOT}}/worktrees` the writable lane, adds `ensure_work_root()` (a missing bind target is dropped, not created, and nothing inside a read-only root can make it), drops `.venv-dev` from `bind_try` (a writable venv rewrites the `.pth` resolving the product package — the same hole through another door), and logs a read-only path promoted to read-write (RW wins a collision regardless of order; **two per-repo rw entries for `WILLOW_ROOT` were live on the box** and would have silently undone the fix while the config still read correct). **Second defect found in the same pass:** `WILLOW_ROOT` was never set in any of the three worker units, so it was *inferred* — and on an editable install that resolves to `<repo>/src`, which protected `gate.py` while leaving `pyproject.toml`/`.git`/`.venv` outside the mount and pointed the writable lane at `src/worktrees`, which does not exist. Now pinned explicitly in all three units. **Scoped honestly:** closes the **sandbox lane** only — a host-side agent can still edit the same files (B-32 class). Verified after, from inside a task: whole repo read-only, work root writable and usable | probed from inside bwrap 2026-09-02; kartikeya#37; grove#35 |
| B-08 | P2 | Stale | packaging | `requirements.txt` unpinned — never existed in current `pyproject.toml` layout | L-REQ-01 |
| B-09 | P2 | Stale | gate | Silent fallback on missing SAP gate — `openclaw_sap_gate` gone in rewritten `gate.py` | L-AUTH-01 |

## Open

- **B-31 · P1** — **willow-2.0's consent reader fails open.**
  ```python
  DEFAULT_CONSENT = {"internet": True, "cloud_llm": True, "lan": True}
  def _normalize_consent(raw):
      if not isinstance(raw, dict):
          return dict(DEFAULT_CONSENT)   # unparseable consent -> permitted
  ```
 A missing, truncated, or malformed consent block resolves to *everything
 permitted*. willow-mcp's reader (`src/willow_mcp/consent.py`) is fail-closed;
 the **writer** lives in willow-2.0. Fix: `DEFAULT_CONSENT` all-`False` and
 deny-all from `_normalize_consent` on a non-dict.

- **B-35 · P1** — Metered envelopes never accumulate FRANK `envelope_citation`
  rows, so `max_count` on pre-approved envelopes does not enforce. Cross-repo
  (willow + willow-2.0). Summary table row has full detail.

- **B-36 · P2 · Resolved (PR12, 2026-08-26)** — willow now holds `gap_write` on
  its own permissions line (`bundle/config/specialists.json`) so `gap_log`/
  `gap_list`/`gap_resolve` are reachable; `kb_startup_continuity` was already
  permitted via `knowledge_read`. The shared `orchestrator` permission group
  is deliberately unchanged (recommendation "do not widen the group" preserved
  — the widening lives on willow's own axis, not the shared one). See
  `docs/design/permissions-matrix.md` §4 and `bundle/skills/gaps.md`.

- **B-56 · P0** — **Local egress key exposure** on this host
  (`~/.config/willow-mcp/egress/private.pem` readable by MCP uid). **Fix:** #182
  custody (`harden-trust-root` / operator-owned key); not an MCP code path.

## Fixed

- **B-60 · P2 (2026-08-24)** — **`tool_oracle._store()` crashed when Nestor
  unavailable.** `_store()` destructured `_nestor()` result without None check.
  Fixed: added None guard at top of `_store()`, returning None when Nestor is not
  installed instead of raising `TypeError`.

- **B-63 · P2 (2026-08-24)** — **Race condition in federation client
  `_ensure_started()`.** Two concurrent callers could both see
  `self._thread is None` and both start threads. Fixed: added instance-level
  `self._start_lock` wrapping the entire `_ensure_started()` body.

- **B-58 · P2 (2026-08-24)** — **Code graph indexer double-counted class
  methods.** `ast.walk` traverses flat; methods appeared both as
  `module.Class.method` and `module.method`. Fixed: track `class_method_ids`
  set, skip in the FunctionDef branch. Branch `claude/hanuman-bugfix-b58-b59-b64`.

- **B-59 · P2 (2026-08-24)** — **`soil_heartbeat.py` used `INSERT OR REPLACE`.**
  Fixed: aligned with `db.py`'s `INSERT ... ON CONFLICT ... DO UPDATE SET`
  pattern. Branch `claude/hanuman-bugfix-b58-b59-b64`.

- **B-61 · P2 (2026-08-24)** — **OAuth error leaked raw exception into HTML.**
  Fixed: generic error message returned; exception logged server-side via
  `logger.exception()`. Branch `claude/loki-security-b61-b62`.

- **B-62 · P2 (2026-08-24)** — **Session inject marker in shared `/tmp`.**
  Fixed: moved to `$WILLOW_HOME/run/session-inject-marker.json` via a
  `_marker_path()` function. Branch `claude/loki-security-b61-b62`.

- **B-64 · P3 (2026-08-24)** — **Missing `conn.commit()` in code graph indexer.**
  Fixed: added `conn.commit()` at end of `_index_file()`. Branch
  `claude/hanuman-bugfix-b58-b59-b64`.

- **B-42 · P3 (2026-07-23, PR #173)** — **the egress row-gate tests assumed the
  fleet's schema, not the repo's.** The fixture mapped `task_id → id` and ran
  raw SQL against whatever live `tasks` table it found (including
  `DELETE FROM tasks`) — red 6/6 on any database built from
  `docs/schema/tasks.postgres.sql`, which is exactly what the sandbox bootstrap
  produces. **Fixed by parametrizing every test over BOTH layouts** (repo
  `task_id` and fleet `id`) inside a dedicated pytest schema pointed at by
  `search_path`, so the code under test's unqualified `FROM tasks` resolves to
  the fixture's table: the schema-adapted contract is now exercised on each
  layout, live data is never touched, and the choice follows the issue's own
  argument (the adaptation layer serves both layouts; the tests should too).
  6 tests → 12; sandbox suite fully green for the first time.

- **B-43 · P1 (2026-07-23, PR #173)** — **mai directives executed ungated**
  (issues #161/#153, the security-hardening half). One-line entry per the
  header convention: full detail lives in the summary row above and issue #161;
  design notes in the `security(mai)` commits on PR #173. Abuse-tested:
  `tests/test_mai_directive_gate.py`.

- **B-44 · P0 (2026-07-31)** — **egress private key readable by the agent's own
  uid, collapsing the three-key gate to two** (issue #182, part of the #181
  red-team kill chain). One-line entry per the header convention: full detail
  in the summary row above. `harden-trust-root` now covers the key directory
  at owner-only mode; `_diag_net_lease`/`_egress_severance` measure read
  exposure, not just write. Tested: `test_lease.py`, `test_trust_root_setup.py`,
  `test_diagnostic_summary.py`, `test_severance.py`.

- **B-45 · P0 (2026-07-31)** — **manifests were unsigned, writable JSON —
  identity and capability were forgeable** (issue #183, part of the #181 red-
  team kill chain). One-line entry per the header convention: full detail in
  the summary row above; the design was already LOCKED in
  `docs/design/pgp-and-persona.md` (2026-07-09) and simply never wired.
  Tested: `test_gate.py` (mocked wiring), `test_pgp_manifest_signing.py`
  (real, disposable Ed25519 GPG key — sign/tamper/forge/reuse/wrong-signer,
  end to end through both pytest and the real `willow-mcp` console script
  under a pty).

- **B-46 · P1 (2026-07-31)** — **`repair-runtime-perms` downgraded `vault.key`
  and `mcp_token.json` from `0600` to world-readable `0644`** (issue #228,
  found during a #181 audit). One-line entry per the header convention:
  full detail in the summary row above. Also fixed `willow-mcp doctor`'s own
  CLI output, which silently dropped a secret-file-only exposure (it only
  printed the trust-root warning block when `forgeable` was non-empty).
  Tested: `test_trust_root_setup.py` (dry-run action strings + a real,
  unmocked `Vault().init()` proving the actual before/after mode change) and
  `tests/test_at_m1_kill_chain.py`, a new acceptance suite replaying the
  #181 kill chain's testable steps against current code end to end.

- **B-53 · P0 (2026-08-01)** — **`orchestrator_human_required` was incomplete
  for `app_id=willow`** (issue #239, red-team 2026-07-31). `dispatch_accept`
  and `handoff_write_v4` were missing from `ORCHESTRATOR_WRITE_TOOLS`, so
  stdio `app_id=willow` with no `WILLOW_HUMAN_ORCHESTRATOR` could accept and
  complete a real dispatch packet — `session_enter`'s own "human-only, never
  dispatch entry" refusal only covered `session_enter`, not the two tools
  called directly. Fixed: both added; the denial message now names the actual
  tool rather than a fixed list, so it can't silently drift again as the set
  grows. Tested: `tests/test_human_orchestrator.py` (unit), a new
  `tests/test_at_m2_dispatch_lifecycle.py` replaying the red-team scenario
  end to end through the real MCP tool wrappers.

- **B-51 · P0 (2026-08-01)** — **`dispatch_write` granted `verify_handoff` +
  `agent_clear` to builder seats** (issue #240, red-team 2026-07-31, extends
  B-48). Same permission group as `dispatch_send`, so any manifest with
  `dispatch_write` (hanuman, loki, jeles, ada) could verify and clear its own
  dispatch with zero orchestrator/human involvement — self-certifying work
  the design always meant the orchestrator to check (`handoff_write_v4`'s own
  docstring: "the orchestrator checks both in verify_handoff before releasing
  you via agent_clear"). Demonstrated live: `hanuman` forged send → `loki`
  accept/handoff → `hanuman` `verify_handoff` (verified=true) → `hanuman`
  `agent_clear`. Fixed: `verify_handoff`/`agent_clear` removed from the
  `dispatch_write` group in `gate.py`; still reachable only via `orchestrator`
  (already human-attestation-gated). `dispatch_write` keeps
  `dispatch_send`/`dispatch_accept`/`handoff_write_v4`/`session_handoff_write`
  — the lifecycle a builder legitimately needs over its own work. Tested:
  `tests/test_gate.py` (permission-group split),
  `tests/test_at_m2_dispatch_lifecycle.py` (a builder self-verifying/
  self-clearing is denied; the orchestrator still can with attestation).

- **B-54 · P1 (2026-08-01)** — **`dispatch_read`/`handoff_read` had no
  packet-level ACL** (issue #242, red-team 2026-07-31). Any app with
  `dispatch_read` could read any `dispatch_id`'s full content, not just
  packets it was `from_app`/`to_app`/`reply_to` on — demonstrated: `hanuman`
  read unrelated packet `A0939A8C`'s handoff (commit SHAs, PR URLs, CI
  notes). Fixed: new `dispatch.is_dispatch_party()`, checked in `server.py`'s
  `dispatch_read`/`handoff_read` wrappers, with an orchestrator bypass;
  denial (`not_party_to_dispatch`) carries no packet content. Tested:
  `tests/test_dispatch_stack.py` (unit),
  `tests/test_at_m2_dispatch_lifecycle.py` (unrelated app denied,
  from_app/to_app/reply_to/orchestrator all allowed).

- **B-55 · P1 (2026-08-01)** — **Pending `assignment.md` was mutable on disk**
  between `dispatch_send` and read/accept (issue #243, red-team 2026-07-31,
  same writable `dispatch/` root as B-52) — append demonstrated on real
  packet `96F54DA7`, reverted. Fixed: `dispatch_send` now records a sha256 of
  `assignment.md` in `meta.json`; `dispatch_read` verifies it and returns
  `assignment_tampered` on mismatch, which `dispatch_accept`/`handoff_write_v4`
  inherit for free since both call `dispatch_read` internally. Not full
  closure -- `dispatch/` is still operator-writable, same residual as B-52 --
  but tampering is now detected and refused rather than silently trusted.
  Tested: `tests/test_at_m2_dispatch_lifecycle.py` (tamper detected on direct
  read and blocks accept; an untampered packet still reads fine).

- **B-52 · P1 (2026-08-11)** — **Filesystem dispatch packet injection**
  (issue #241, red-team 2026-07-31). `$WILLOW_HOME/dispatch/` is
  operator-writable — a local uid could `mkdir` a packet directory and drop
  an arbitrary `meta.json`; the earlier partial mitigation
  (`_meta_is_well_formed()`) rejected only the trivial bare-`{}` case, so a
  hand-written `meta.json` with the right field names (demo `DEADBEEF`,
  `to_app=willow`) still showed up in `dispatch_list` indistinguishable from
  a real packet. Fixed: `dispatch_send` now HMAC-SHA256-signs every
  meta.json field except the signature itself (`dispatch_signing.py`), keyed
  by a runtime-held secret. Key custody deliberately reuses the
  `_SECRET_FILE_NAMES` convention (`trust_root_setup.py`) rather than the
  egress key's outside-WILLOW_HOME/interactive-CLI-only posture (B-37) —
  `dispatch_send` itself must be able to sign on every call, so the key is a
  new top-level `$WILLOW_HOME/dispatch_signing.key`, auto-created 0600 on
  first use, given the SAME owner-only custody `vault.key` gets under
  `repair-runtime-perms`/`harden-trust-root`. `dispatch_read` (and
  `dispatch_accept`/`handoff_write_v4`/`session_enter`, which all call it
  internally) verifies the signature before trusting anything else in the
  packet; `dispatch_list` splits its result into `dispatches` (signature
  verified) and a separate `unverified` array (`unverified: true` +
  `signature_status`) rather than either silently dropping or silently
  trusting a bad packet. Legitimate status transitions
  (`dispatch_accept`/`agent_clear`/etc, via `dispatch_set_status`) re-sign
  meta.json rather than self-invalidating it; any OTHER edit to meta.json
  invalidates the signature (`signature_status: invalid`) and is always
  refused on read, strict mode or not — same posture as B-55's
  `assignment_tampered`. **Back-compat:** a packet with no `signature` field
  at all (`legacy_unsigned` — written before this fix, or a forged packet
  that simply omits the field) is excluded from the normal `dispatches` list
  and surfaced only in `unverified` by default; under
  `WILLOW_MCP_STRICT_TRUST_ROOT=1` it is hard-rejected outright (not even
  listed as unverified) on the theory that a hardened host has no excuse for
  an unsigned packet still in flight. A legacy packet that goes through a
  real lifecycle transition (`dispatch_accept`, etc.) is signed going
  forward rather than staying permanently second-class. **Residual, same
  class as every other B-3x entry:** on a single-uid host the attacker uid
  that can hand-write `meta.json` can also read `dispatch_signing.key` (it
  must be runtime-readable for `dispatch_send` to work) and forge a valid
  signature too — full closure still needs #231's uid separation; this
  closes the "bare forgery with no key at all" hole the red-team actually
  demonstrated, raising the bar rather than claiming the residual doesn't
  exist. Tested: `tests/test_dispatch_stack.py` (send→read→list round trip
  verifies; DEADBEEF-style forgery excluded from `dispatches` and flagged
  `legacy_unsigned`; strict-mode hard-reject; tampering an already-signed
  meta.json is refused; status transitions re-sign and stay valid; a legacy
  packet gets signed on its first real lifecycle transition).

- **B-50 · P2 (2026-08-01)** — **`schema_maps/` writes EACCES'd once
  `mcp_apps/` was actually trust-root-hardened** (issue #238, red-team
  2026-07-31, same class as B-41). `schema_maps/<app_id>/` was documented and
  shipped under `mcp_apps/<app_id>/` (`schema-adaptation.md` §3.2 original)
  — a deliberate placement, not an oversight, that simply conflicted with
  `mcp_apps/` also being the trust-root-hardened, operator-owned directory
  B-45/#183 depends on: the runtime process legitimately writing schema
  maps can never create a subdirectory under a `0755`, operator-owned
  parent. Fixed (operator-approved amendment to the LOCKED `product-
  layout.md`): `schema_maps/<app_id>/` relocated to its own top-level
  `$WILLOW_HOME` root, sibling to `store/` -- outside `mcp_apps/` entirely,
  so the conflict can't recur. Also fixed a latent test-isolation gap this
  surfaced: several `test_server.py`/`test_sandbox_confirm.py` fixtures
  isolated `WILLOW_MCP_APPS_ROOT` but never `WILLOW_HOME` -- harmless while
  schema_maps lived under the isolated apps root, but once it moved to
  depend on `WILLOW_HOME` directly, those fixtures were silently sharing
  conftest's one session-wide default `WILLOW_HOME`, so a mapping confirmed
  in one test bled into the next test reusing the same app_id. Tested:
  `tests/test_schema_profile.py` (path structurally outside `mcp_apps_root()`;
  `mapping_path()` never creates `mcp_apps_root()` as a side effect, verified
  to go red on the pre-fix code and restored), `tests/test_tree_view.py`.

- **B-49 · P2 (2026-08-01)** — **Reconciled, not a new gap** (issue #237,
  red-team 2026-07-31). `docs/design/willow-gate-seam.md` D3 already covers
  "ungated `whoami` leaks manifest when binding is off" in its own explicit
  "CLOSED" section: `_own_identity_denial` gates it exactly when
  `WILLOW_MCP_ENFORCE_BINDING=1` and the app is registered, no-op otherwise
  -- the accepted trusted-host stdio model, same posture as every other
  tool in this gate. Nothing to fix; closed the issue with a pointer to
  the existing doc section.

- **B-47 · P1 (2026-08-01)** — **Two MCP desks, two trust models** (issue
  #235, red-team 2026-07-31). The repo's committed `.cursor/mcp.json`
  spawns `willow-mcp` with implicit `~/.willow` and no PGP/binding env,
  while an operator's separately-configured, hardened global Cursor
  desk is a different trust posture under the same product -- easy to
  "test green" on the unhardened repo desk while believing the hardened
  one was verified. This repo commits no fleet secrets to the unhardened
  config by design, so there was nothing to move; documented instead --
  README.md's "MCP config" section now states plainly that this config
  is dev-only, names exactly which env vars are missing and what each
  absence means, and points at setting them in this file's own `env`
  block if enforcement is needed while developing.

- **B-48 · P1 (2026-08-01)** — **`dispatch_write` is not binding-gated and
  not human-attested** (issue #236, red-team 2026-07-31). Any stdio caller
  passing `app_id=hanuman` (or any manifest with `dispatch_write`) can
  `dispatch_send` with no per-call credential -- demonstrated live,
  `dispatch_id=7BE854FD`. Traced: `_enforce_binding_gate` already applies
  uniformly to `dispatch_write` when `WILLOW_MCP_ENFORCE_BINDING=1` -- it's
  a no-op for an unregistered app_id by design (fail-closed for an
  un-instrumented client, not a silent bypass). Closes today only when the
  operator both enables binding and registers every builder seat -- the
  same two-step deployment gap as #231's uid separation, not a code bug.
  Making `dispatch_write` refuse unregistered app_ids unconditionally was
  considered and deferred: a breaking default-posture change for any
  install with unregistered builder agents, bigger than this one finding
  warrants alone. Documented as a residual in `willow-gate-seam.md` D6.

- **B-40 · P1 (2026-07-23)** — **the worker could not start on a clean install.**
  The f1e8c9b guard (refuse a production lane on an unobservable sandbox policy)
  imports `kartikeya.sandbox.resolve_sandbox_config` and treats the ImportError
  as deliberately fatal — but no published kartikeya ships that API (PyPI latest
  0.0.7 exposes `load_sandbox_config` only), so the fatality fired on **every**
  lane, including dev fast lanes the guard itself passes
  `require_fleet_config=False`. This silently re-broke B-22's close-out claim
  that a base install ships a working drainer, and the error's named remedy
  ("Upgrade kartikeya") was unrunnable — the B-27 class again: an instruction
  believed because it was written down. Found standing up the web sandbox:
  worker exited at startup, `fleet_health` correctly reported `stranded: true`
  (B-26's signal earning its keep). **Fix:** `check_sandbox_config` falls back to
  naming the policy source itself by mirroring `load_sandbox_config`'s
  documented search order (`$KART_SANDBOX_CONFIG` →
  `$WILLOW_HOME/kart-sandbox.json` → vendored default); production lanes still
  refuse the vendored default with the identical 3am-actionable message
  (`test_worker_sandbox_seam` green both with and without the new API), dev
  lanes proceed with a loud stderr warning. Remove the fallback once a kartikeya
  release ships the reporting API and the pin is bumped. Also found: the sandbox
  venv carried kartikeya 0.0.5 despite the `>=0.0.7` pin — stale editable env.
  Issue #165.

- **B-41 · P2 (2026-07-23)** — **the web-sandbox MCP server booted blind.** The
  SessionStart hook persisted `WILLOW_*` env by appending to `$CLAUDE_ENV_FILE`,
  asserting in its own comment that "the client-spawned MCP server (and any
  shell you open) inherits it — this is why .mcp.json needs no env block."
  Shells inherit it; the MCP server does not — the client spawns the stdio
  server from `.mcp.json` alone. Observed live: `diagnostic_summary.checks.env`
  all `null`, `WILLOW_HOME` defaulted to an empty `~/.willow`, and every seat's
  `session_enter` gate-denied for want of a manifest. B-12's class in a new lane
  (systemd unit there, Claude Code web here), and B-30's lesson again — the
  write path was believed, the read path never verified. **Fix:**
  `session-start.sh` now generates the gitignored `.mcp.json` **with the
  resolved env embedded**, after the vault-restore block so vault-supplied
  values land in it; `WILLOW_HUMAN_ORCHESTRATOR=1` rides along only when
  `WILLOW_APP_ID=willow` per `skills/session-start.md` (operator decided
  2026-07-23 to keep the attestation in the web lane — parity with
  `.mcp.json.example`, session still human-supervised; closes issue #166's
  review note); `settings.json` invokes the hook via `bash` so the exec bit
  the contents API cannot carry is no longer load-bearing. Issue #166.

- **B-30 · P1 (2026-07-09)** — **the two consent files disagreed, and the first
  diagnosis of *why* was wrong.** On this host:
  ```
  consent.json          internet: false,  lan: false
  settings.global.json  internet: true,   lan: true    <- governs
  ```
  **What this bug was originally recorded as:** a legacy flat file, imported by
  `load_global_settings()` only when the canonical file is absent, therefore inert
  — "a file that looks exactly like the off switch, doing nothing." The suggested
  fix was *reconcile the two, or delete the legacy file.*

  **What it actually is.** `consent.json` is a **mirror**, and a live one:
  ```python
  def save_global_settings(data, *, path=None, sync_legacy: bool = True) -> None:
      ...
      if sync_legacy:
          _write_legacy_consent(out["consent"])     # rewritten on EVERY save
  ```
  Every caller in `global_settings.py` passes `sync_legacy=True`, and Grove's
  settings pane (`panes/settings.py`) mirrors it on every consent toggle. So the
  file is continuously **written** and almost never **read** — read only as the
  canonical file's absent-fallback.

  That asymmetry is the hazard, and it is a sharper one than "inert." A write-only
  mirror **drifts silently**: hand-edit it and nothing reads your edit, nothing
  corrects it, and it sits looking authoritative until some unrelated save quietly
  overwrites it. The disagreement observed here was not a dead file — it was a
  **stale mirror**, produced by a hand-edit that no subsequent save had yet clobbered.
  And the advice to "delete the legacy file" was *wrong*: the next
  `save_global_settings()` or Grove toggle recreates it. A delete that looks like a
  fix and silently comes back is worse than no advice.

  **Resolved** by re-syncing the mirror from the canonical block via willow-2.0's own
  writer (`_write_legacy_consent(read_consent())`) — canonical untouched, effective
  policy unchanged, `diagnostic_summary` back to `ok` with `disagreement: null`.
  Note the one real consequence: `consent.json` is willow-mcp's fallback if
  `settings.global.json` ever goes missing, and that fallback went from `false`
  (deny) to `true` (permit). Consistent with the operator's stated intent, and
  academic anyway given B-31 (willow-2.0's `DEFAULT_CONSENT` is all-`True`), but it
  is a permission-raising side effect of a "cosmetic" repair and is recorded as one.

  **Fixed in code, not just on this host:** `consent.py`'s header and `legacy_path()`
  no longer describe the file as a leftover; `diagnostic_summary`'s `consent` problem
  now says *stale mirror*, warns that deleting it will not keep it gone, and gives
  the re-sync one-liner as the fix. The `error` severity stays — a divergence still
  means one of the two files is lying about the operator's intent, and willow-mcp
  still refuses to guess which.

  **Lesson.** "Legacy" was a word in a docstring, believed without reading the
  writer. The read path was checked; the write path was not. Same class as B-27
  (`pip install willow-mcp[worker]` — an extra that never existed, believed because
  it was written down).

- **B-29 · P0 (this session)** — **operator consent gated nothing.** Egress was
  authorized solely by the `task_net` capability in an app's manifest. The
  operator's standing consent — `consent.internet` in
  `$WILLOW_HOME/settings.global.json` — was read by no gate anywhere. The fleet
  settings file has carried the wiring instruction the whole time, as a flag
  declaring its own absence:
  ```json
  "consent_internet_gates_allow_net": {
    "enabled": false, "implemented": false, "status": "deferred",
    "targets": ["kart_worker", "kart_sandbox", "sap_gate"],
    "note": "Wire settings.global.json consent.internet to kart # allow_net ..."
  }
  ```
  and `flag_enabled()` requires both `enabled` and `implemented`, so it was inert
  by construction. The design was settled long before the code: the egress
  membrane (FRANK `05611965 → 90e52ab7 → cc553729 → 0ba6a33f`, mapped in
  `willow/design/egress-membrane-constitutional-map.md`) names consent a
  time-boxed lease, and the sudo invariant separates *requesting* egress from
  *confirming* it.
  **Fix:** `allow_net=True` is now a **two-key** operation. The manifest's
  `task_net` says *this app may ever request egress* (a capability, granted once).
  The operator's `consent.internet` says *egress is permitted right now* (a
  switch). Both must hold or the call returns `consent_denied` before any write.
  Flipping one boolean stops egress fleet-wide without touching a single manifest
  — which is the whole point.
  **Fail-closed, deliberately diverging from the writer** (see B-31): new
  `src/willow_mcp/consent.py` reads the policy and treats *anything* it cannot
  read as an explicit `true` as denial — absent file, unparseable file, non-bool
  value (`"true"`, `1`, `"yes"`). A corrupt canonical file denies and does **not**
  fall back to the older, laxer legacy file. willow-mcp only ever **reads** this
  policy; a gate that authors the policy it is checked against is not a gate.
  **Disagreement is surfaced, never resolved** (B-30): when both files declare the
  same key with different values, `diagnostic_summary` raises an `error`-severity
  `consent` problem naming both. Keys only one file declares are *not* reported as
  conflicts — a file that omits a key is silent on it, not in disagreement about
  it. That distinction was caught by the end-to-end run, not by a unit test, and
  has a regression test now.
  **A false-green test was found and fixed.** `_app_with_perms` set only
  `WILLOW_MCP_APPS_ROOT`, leaving `WILLOW_HOME` pointed at the developer's real
  `~/.willow`. The existing `task_net` success tests therefore passed by reading
  the *operator's live consent file* (`internet: true`) — and would have failed on
  CI, where no such file exists. The fixture now pins `WILLOW_HOME` to `tmp_path`
  and tests state consent explicitly. Verified by running the whole suite with
  `WILLOW_HOME` pointed at an empty directory (the CI shape) as well as the
  developer shape: **301 passing in both**.
  **Verified end-to-end**, not just by unit test: with an app holding `task_net`
  throughout, flipping `consent.internet` false denied egress; deleting the policy
  denied; corrupting it denied; `"true"` as a string denied; a corrupt canonical
  file beside a permissive legacy file denied; and a genuine conflict on a shared
  key was reported while the canonical value still governed.
  **Residual:** this closes the *egress* key only. `consent.lan` and
  `consent.cloud_llm` are read and reported but gate nothing yet — `# allow_localhost`
  is never self-grantable (B-21) and willow-mcp makes no cloud-LLM calls. The
  lease semantics (turn / session / ≤3h, FRANK `cc553729`) are **not** implemented:
  consent here is a standing boolean, not a leased grant that expires. See B-32
  for why a boolean the agent can also write is a mitigation rather than a fix.

- **B-26 · P2 (this session)** — the task queue had no way to answer "is anything
  going to run this?". `task_submit` returned `{"status": "pending"}` whether a
  worker was one poll away from claiming the row or no worker existed anywhere,
  and `fleet_health` reported only queue depth — a `pending: 40` could mean a
  healthy backlog or a dead fleet. `skills/kart-tasks.md` had to warn about this
  in prose because there was no signal to check. Stage 4 of the Kart lift spec
  (`docs/design/kart-lift-spec.md` §8) called for exactly this and was left open
  when B-22 closed. **Fix:** `kartikeya`'s worker loop already calls an
  `on_heartbeat(lane=…, tick_ok=…)` seam every tick and willow-mcp passed nothing;
  new `heartbeat.py` implements it as an atomic per-process JSON write under
  `$WILLOW_HOME/worker_heartbeat/`, wired into `_cmd_worker` (with `reap()` on
  start and `close()` on exit). `read_workers()` classifies each record `alive` /
  `stale` (process up, loop wedged) / `dead` (pid gone). `fleet_health` gains
  `workers` and a `stranded` boolean (**pending work + zero live workers**);
  `diagnostic_summary` gains a `worker` check and raises a named `worker` problem
  with the `willow-mcp worker` command as its fix.
  **Deliberate:** the problem fires only on `alive == 0 AND pending > 0`. Warning
  on "no worker" alone would make `degraded` the resting verdict for every
  store/knowledge-only install — the same false-positive class B-18 removed.
  **Security posture:** heartbeats are advisory telemetry, never authorization. No
  gate reads them. `$WILLOW_HOME` is `bound_rw` to the Kart sandbox, so a sandboxed
  task *can* forge a heartbeat file; reads therefore verify the recorded pid is a
  live process on the recording host, so a forged file naming a dead pid reads
  `dead`. The trust root remains `mcp_apps/`, which is `bound_ro` (B-14).
  **Verified** end-to-end against a real `kartikeya` worker draining a real
  SqliteTaskQueue: heartbeat `alive` while running → task `completed` → clean
  `close()` removes the file (absent, not stale) → a forged fresh record with a
  dead pid reads `dead`, `alive: 0`, and is reaped. 22 new tests
  (`tests/test_heartbeat.py`, plus `fleet_health` stranded/not-stranded cases in
  `test_server.py`); suite 257 → 279, all passing.

- **B-27 · P3 (this session)** — `pip install willow-mcp[worker]` appeared in three
  places (`task_queue.py`'s module docstring and `_require_kartikeya`'s error,
  `server.py`'s `_cmd_worker` error and the `worker` subcommand help) as the
  remedy for a missing `kartikeya`. **No such extra exists.** `pyproject.toml` had
  no `[project.optional-dependencies]` table at all when this was found, and
  B-22's close-out had made kartikeya a *hard* dependency — then
  `kartikeya>=0.0.1,<0.1.0`, today `kartikeya>=0.0.9,<1.0.0` — precisely so a
  base install ships a drainer. (The table exists now, for `nest` and `web`;
  there is still no `worker` extra, and by design there never will be.) So the
  one message an operator sees when the worker can't start told
  them to run a command that errors. Residue of the pre-B-22 draft, where the
  extra was the plan. **Fix:** all four sites now say `pip install willow-mcp` (or
  `pip install -e .` from a checkout), and the docstring states the dependency is
  hard, explaining that the lazy import survives only for an uninstalled source
  checkout. Found by checking the docstring against `pyproject.toml` rather than
  trusting it — it read as stale prose and was in fact a broken instruction.

- **B-24 · P0 (this session)** — `store_*` tools had no cross-app isolation.
  Any app granted `store_read`/`store_write`/`store_all`/`full_access` could
  read, write, or delete **every other app's** SOIL store data, not just its
  own — `store_search_all` made this explicit by searching across all
  collections by design. `context_*` solved this correctly (`ctx__<app_id>`
  prefix, `server.py:1047-1048`); `store_*` never got the same treatment.
  First flagged in an external review (`docs/design/mcp-review-2026-07-08.md`
  §2b) as "worth a decision, not asserted as a bug" since it might be
  intentional shared scratch space; re-confirmed on a follow-up pass with no
  README or code comment anywhere stating that's the intent. **Fix:** rather
  than a blanket per-app rename (which would have broken the *documented,
  intentional* fleet-sharing use of `WILLOW_STORE_ROOT` — confirmed live via
  `diagnostic_summary` that collections like `agents`/`hanuman`/`knowledge`/
  `session` are genuinely shared with the wider fleet, not an accident), added
  an **opt-in** `store_scope` manifest field: `db.collection_in_scope()`
  matches exact names or `prefix*` wildcards; `gate.collection_permitted()`
  reads it from the manifest; all six single-collection `store_*` tools check
  it before touching storage; `store_search_all` confines its sweep to the
  scope instead of searching everything. Unscoped apps (no `store_scope` in
  their manifest) are completely unaffected — the shared-fleet-store default
  is preserved, verified by a dedicated regression test. Documented in
  README's Authorization section with a worked example. See `SECURITY_AUDIT.md`
  L-ISO-01 for the full writeup. 24 new tests across `test_gate.py`/
  `test_store.py`/`test_server.py` (252 total, all passing).
  **Residual (not blocking, deliberate):** this closes the *mechanism* gap,
  not the *default* — an app with `full_access` and no `store_scope` still
  sees everything, same as before. Flipping the default to isolate-by-default
  would be a breaking change requiring every existing manifest to be migrated
  and is left as a follow-up decision, not bundled into this fix.
  **Independent verification (2026-08-01, Felipe Castro Quiles):** pulled from
  GitHub, ran `sandbox-bootstrap` in SOIL-only mode (clean, degraded behavior
  worked as expected), then separately attempted to bypass `store_scope` with
  cross-app reads "a few different ways" — blocked every time. B-24/B-25
  holding under live testing outside this repo's own suite, not just its
  own tests.

- **B-22 · P1 (this session)** — willow-mcp shipped **no Kart executor**: the
  package advertised a "Kart task queue" and exposed `task_submit`/`task_status`/
  `task_list`/`fleet_health`, but no worker/sandbox/drainer was in the repo, so a
  clean `pip install` left every task `pending` forever (it only ran because an
  out-of-repo, often stale, willow-2.0 Kart was present). **Fixed** by extracting
  the mature willow-2.0 Kart as a standalone, host-agnostic package — **`kartikeya`**
  (github.com/willow-memory/kartikeya, **published to PyPI as 0.0.1**) — with the
  sandbox/worker/execute core decoupled from all fleet imports behind a
  `TaskQueue` backend seam (bundled SQLite reference impl + Postgres). willow-mcp
  now: depends on `kartikeya` (hard dep, `>=0.0.1,<0.1.0`); ships
  `WillowMcpTaskQueue` (Postgres over the adopted `tasks` table, atomic
  `FOR UPDATE SKIP LOCKED`; SQLite fallback when no PG); the `willow-mcp worker`
  subcommand; and `docs/schema/tasks.postgres.sql`. A clean
  `pip install willow-mcp` now ships a working queue drainer. Verified: clean-venv
  `pip install kartikeya` imports + `kart` CLI resolves; kartikeya standalone e2e
  green (submit → worker → completed); willow-mcp integration tests run
  unconditionally. Plan: `docs/design/kart-lift-spec.md`; extraction PRs on the
  kartikeya repo; willow-mcp PRs #35 (integration) + #36 (hard dep / close-out).
  **Residual (not blocking):** the full real-bwrap end-to-end with network egress
  on/off must be validated on a bare host — the dev Kart sandbox can't nest
  bubblewrap, so its tests run with `WILLOW_KART_NO_BWRAP=1`.

- **B-23 · P3 (this session)** — the task-queue tool surface shipped without
  its companion skill/hook, breaking the standing rule that a footgun/workflow
  tool ships its skill+hook in the *same* PR (`docs/design/hooks-and-skills.md`
  §2). `task_submit` + the `task_net` capability (B-19) and the `# allow_net`
  directive footgun (B-21) are exactly that case and had neither. **Fix:** added
  `skills/kart-tasks.md` (submit/poll workflow, the `allow_net`/`task_net`
  permission model, and the worker-liveness caveat that a submission ≠ an
  execution) and extended `hooks/pre_tool_use.py` with a `task_submit` matcher
  that *warns* when a caller hand-embeds a `# allow_net`/`# allow_localhost` line
  (a no-op post-B-21) and points them at the real path. Registered both in
  `.claude-plugin/plugin.json`. Operator-caught, not review-caught.
- **B-21 · P0 (this session)** — `task_net` capability gate was bypassable via
  the task text itself, defeating the separation B-19 established. The Kart
  worker (`willow-2.0/core/kart_sandbox.py`) decides network policy purely by
  scanning the *stored task text* for a directive line — egress on any
  `line.strip() == "# allow_net"`, loopback on `"# allow_localhost"`. In
  `task_submit`, both the `task_net` permission check **and** the `# allow_net`
  append lived behind the same `if allow_net:` guard, and nothing inspected
  caller-supplied `task` text. So a caller holding only `task_queue` could
  submit `task="curl …\n# allow_net"` with the default `allow_net=False`: the
  gate never fired (it's keyed off the *argument*, not the *text*), the
  directive was stored verbatim, and the worker granted egress. `# allow_localhost`
  was never gated at all. **Fix:** strip any caller-supplied line matching
  either directive (worker's exact `line.strip() ==` semantics) from `task`
  **unconditionally**, before the permission-gated append — so `# allow_net` can
  only ever enter through the path that already checked `task_net`, and
  `# allow_localhost` can never be self-granted. Full detail in
  `SECURITY_AUDIT.md` (L-NET-01). Regression tests in `tests/test_server.py`
  (`…strips_caller_supplied_net_directive_when_denied`,
  `…strips_caller_supplied_localhost_directive`,
  `…permitted_net_survives_caller_directive_dedup`); full suite 205→208.
- **B-20 · P3 (this session)** — the GitHub repo "About" description read
  *"Superseded by Willow 2.0 — MCP, SOIL, Postgres KB, and Kart now live in the
  monorepo."* That was true when willow-mcp was being folded in, but is now
  stale and contradicts reality: this repo is the active 2.0.0 home (README
  presents it as a live standalone tool, PRs landing). It lives in GitHub repo
  metadata, not the git tree, so a file grep misses it — it surfaced only via an
  external review (DeepSeek) reading the repo page. Fixed with
  `gh repo edit --description "Agent-neutral MCP server with persistent memory
  (SOIL + Postgres KB) and a sandboxed task queue. Manifest-based ACL; works
  with any stdio MCP client."` Repo confirmed **not archived** (`isArchived=false`).
  Note: the published PyPI 1.2.0 description is separate (release held) and does
  not carry this note.
- **B-17 · P2 (this session)** — `task_status` now surfaces task completion
  time. Root cause: the adopted `tasks` table genuinely had **no**
  `completed_at` column (the null was not an unmapped-but-present column — the
  data wasn't there). Fix (operator chose the upstream option): added the column
  and a self-populating trigger on the shared fleet DB, then mapped the field.
  ```sql
  ALTER TABLE tasks ADD COLUMN IF NOT EXISTS completed_at timestamptz;
  CREATE OR REPLACE FUNCTION set_task_completed_at() RETURNS trigger AS $$
  BEGIN
    IF NEW.status = 'completed' AND NEW.completed_at IS NULL
       AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM 'completed') THEN
      NEW.completed_at := now();
    END IF;
    RETURN NEW;
  END; $$ LANGUAGE plpgsql;
  CREATE TRIGGER trg_task_completed_at BEFORE INSERT OR UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION set_task_completed_at();
  ```
  willow-mcp itself needed no code change (`completed_at` was already a canonical
  `_TASK_FIELDS` entry); the confirmed tasks mapping artifact was updated to map
  it. `steps` stays unmapped — that column still doesn't exist, which is correct.
  Forward-only: pre-existing completed rows keep `completed_at` null (their true
  completion time is unknown; no backfill from `updated_at`, which fires on any
  update). **Verified**: probe `R2BSZ9FZ` completed with
  `completed_at: 2026-07-08T12:12:41`, and `_unmapped` is now just `["steps"]`.
- **B-19 · P2 (this session)** — `task_submit` can now run network-bearing
  tasks. It gained an `allow_net` parameter gated by a new `task_net` capability
  permission in `gate.py` — deliberately **not** part of `task_queue` or
  `full_access`, so a broad grant never silently carries sandbox network egress
  (same separation spirit as B-14). When granted, `task_submit` appends the Kart
  worker's `# allow_net` directive (`core/kart_sandbox.py task_allows_network`)
  to the task text, so the willow-2.0 worker builds the sandbox with egress
  enabled. Without the permission, `allow_net=True` returns `net_denied` before
  any write. **Verified** end-to-end: probe `5H1M355V` (task_net app,
  `allow_net=True`) ran with `network_mode: full`; control `TNH4B9FQ`
  (`allow_net=False`) ran `isolated`; a `full_access`-only app was denied.
  Operator note: grant `task_net` host-side only, never via the sandbox (B-14).
- **B-18 · P3 (this session)** — `diagnostic_summary` no longer returns verdict
  `degraded` just because the caller omitted `app_id`. That case was a caller
  omission, not an install defect (store/Postgres/schema/bindings all `ok`), yet
  it folded into the one field meant to answer "is this install wired
  correctly." Fix: the missing-`app_id` manifest warn is tagged `caller_input`;
  it still surfaces in `problems` and the `manifest` sub-check (`status: warn`,
  `reason: no_app_id`), but `_derive_verdict` ignores caller-input warns, so the
  verdict stays `ok` when every probed subsystem is healthy. A real manifest
  warn (empty permissions → every call denied) is not `caller_input` and still
  degrades. **Verified** via probe `E3265B66`: `diagnostic_summary(app_id="")` →
  `verdict: ok`, `manifest.status: warn`, `problems: [(manifest, warn, caller_input=True)]`.
- **B-15 · P3 (issue #20)** — `kb_startup_continuity` no longer silently
  returns empty on the adopted `willow_20` DB. The old filter keyed off a
  `domain='continuity'` value (the `domain`/`project` column is ~all-null — no
  such value) and a top-level `tags` column that doesn't exist; tags actually
  live inside the jsonb `content` blob (physically the `content` column, which
  is unmapped as a canonical field because canonical `content` maps to
  `summary` — B-10). Fix: when there's no top-level `tags` column but a jsonb
  `content` column is present (discovered by introspection, not assumed), read
  continuity atoms from `content->'tags' @> '["continuity"]'`. The result now
  always carries a `_continuity_filter` listing exactly what was searched, so an
  empty result reads as "genuinely nothing to continue" rather than "the query
  couldn't target this schema" (fail-loud). **Verified** via probe `707E561A`:
  returns the 9 continuity-tagged atoms that the old path missed. Tests added in
  `test_server.py` (jsonb path, top-level-tags preference, fail-closed).
- **B-16 · P3 (FRANK `90960b8b`)** — `_sanitize` no longer runs before the
  permission gate. `_guarded` now runs **gate → sanitize → rate → dispatch →
  receipt**: an unpermitted caller gets a clean permission denial as the first
  signal instead of a sanitizer error for a call it was never allowed to make.
  Gate still validates the app_id shape and precedes the rate check, so
  L-DOS-01 is preserved. **Verified** via probe `4D9139B8`: unpermitted app +
  illegal collection → gate denial (was sanitize error); permitted app + illegal
  collection still hits the sanitizer. Ordering + control tests in
  `test_server.py`.
- **B-14 · P0 (FRANK `baf2f63a`/`293b2130`, willow-2.0#777)** — Kart bwrap
  sandbox no longer has R+W to willow-mcp's on-disk trust root. The host stdio
  server and the Kart sandbox share `$WILLOW_HOME`, and `mcp_apps/` (per-app
  `manifest.json` ACLs **and** `_identity_bindings/` confirmed OAuth bindings)
  used to sit inside the sandbox's read-write mount — so an untrusted runtime
  could rewrite its own manifest to self-escalate past `gate.py`, or mint/flip a
  `confirmed:true` identity binding the host serve process would honor
  (defeating L-AUTH-02's "confirmation is stdio/host-only" control). Fixed on
  the willow-2.0 side: `$WILLOW_HOME/mcp_apps` is now an explicit `bound_ro`
  mount nested inside the `bound_rw` `.willow` parent, so the trust root is
  read-only even though its parent is writable. **Verified** 2026-07-08 via Kart
  probe `MAGSU06N`: `touch mcp_apps/_b14_probe` → `Read-only file system`;
  sandbox manifest shows `mcp_apps` under `bound_ro`. Load-bearing for the
  fetch-scope gating layer (a scope gate is worthless if the sandboxed fetcher
  can rewrite the scope file). Never author manifests/bindings via the sandbox —
  host-side only.
- **B-01 · L-AUTH-02 (P0)** — serve-mode identity binding implemented
  (`identity_binding.py` + `oauth.py`/`gate.py`/`server.py` wiring +
  `willow-mcp confirm-binding` CLI); `app_id` now resolved from the confirmed
  binding, never caller args. See SECURITY_AUDIT.
- **B-02 · L-INT-01 (P1)** — `safe_integration.py` with `status()` added.
- **B-03 · L-DOS-01 (P2)** — `_guarded` pipeline reordered to
  sanitize→gate→rate→dispatch→receipt; invalid `app_id` denied before it can
  become a `_buckets` key.
- **B-04 · L-BUG-01 (P2)** — early `if not tokens` guard in `Store.search` and
  `knowledge_search`; regression tests added.
- **B-05 · L-CONC-01 (P2)** — `Store` lock widened to an `RLock` covering
  `execute`/`commit`; 8×20 concurrent-write regression test added.
- **B-06 · L-TEST-01 (P2)** — suite grew 12→44 (then further); gate/vault/
  identity/server pipelines now covered.
- **B-07 · L-DOC-01 (P3)** — `willow-mcp setup` (+ `confirm-binding`) CLI
  subcommands implemented; secrets prompted via `getpass`/stdin.
- **B-10 (P2, FRANK `90960b8b`/`88d13197`, issue #20, PR #21)** — knowledge
  mapping re-confirmed with `{content: summary, domain: project}` after review;
  root class fixed by requiring rendered-sample evidence at confirm (B-11).
  Verified `kb_at` returns full title/summary matching the main server.
- **B-11 (P2, PR #21)** — `schema_confirm_mapping` gained `preview=True` +
  `render_sample`: confirm now shows real projected rows before writing, so a
  name-match is checked against actual data. Skill `schema-confirm.md` updated.
- **B-13 (P3, in-tree)** — test fixtures reset `server._buckets` so shared
  `app_id` across `_guarded` calls no longer exhausts the rate limiter.

## Documented (no code fix)

- **B-12 (P3, PR #18)** — serve mode env gap. The systemd `--user` unit is
  started by systemd, not the shell, so `WILLOW_PG_DB`/`WILLOW_STORE_ROOT`/
  `WILLOW_HOME` exported in `.bashrc` don't reach it; serve reads then
  `table_not_found` on data stdio can see. This is expected for an
  externally-configured DB (willow-mcp adapts to a foreign DB by design), not a
  code defect. Documented in README ("Turning serve mode on and off") and
  `skills/willow-serve.md`; fix is `systemctl --user import-environment ...` or
  an `environment.d` file. Candidate future polish: install-time env-freeze into
  the unit.

## Stale (never real in current code)

- **B-08 · L-REQ-01** — predates the `pyproject.toml` layout; no `requirements.txt` exists.
- **B-09 · L-AUTH-01** — `openclaw_sap_gate` removed in the manifest-ACL rewrite of `gate.py`.
- **B-34 · orchestrator human gate** — filed P0 as "the gate does not exist"; the gate exists and
  works. `human_session.py:41` reads `WILLOW_HUMAN_ORCHESTRATOR`; `server.py:201-202` calls
  `orchestrator_write_denial()` and returns it for `dispatch_send` / `verify_handoff` /
  `agent_clear`; the denial text `orchestrator_human_required` lives at `human_session.py:60`.
  Confirmed empirically: it refused a live `dispatch_send` from the willow seat at
  2026-07-09T12:26Z (FRANK `66bfd8b3`), which the withdrawn entry had claimed "rests on a misread."
  The false alarm came from probing with `diagnostic_summary()` and no `app_id`, so
  `is_orchestrator_app(None)` returned `False` and the check never ran — **the gate was tested by
  not being the identity the gate guards.** `gate.permitted()` reading only `permissions` is true
  and irrelevant: the ACL and the host attestation are separate layers. Withdrawn by root
  2026-07-09 before any patch reached the code. FRANK `c4f7bec5` (adjudication), `e4759e8b`
  (authorization).

  *Kept, not deleted.* A false negative about a live membrane is more dangerous than a false
  positive about a dead one: both of B-34's proposed remedies — "wire the key into `_gate`" or
  "delete the field and the doc claim" — would have edited a boundary that already held. The
  lesson is the probe, not the gate.
