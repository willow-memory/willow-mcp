# Fleet cleanup survey — 2026-09-28

- Status: **Survey**. Findings only; nothing in this doc changes code.
- Date: 2026-09-28
- Scope: all nine `willow-memory` repos at their default-branch heads on
  2026-09-28, plus every open GitHub issue in them
- Method:
  - four read-only survey agents in parallel, split by repo size, looking for
    tests no longer needed, stale docs, dead or duplicate code and config, and
    repo hygiene;
  - each agent's strongest claims were re-checked by hand against the code;
    items marked **✔** were re-checked;
  - open issues were read in full and checked against current code;
  - no test suites were run: pytest wasn't installed in the survey environment.
- Next: section E lists the decisions that need an operator ruling, and the
  last section proposes how to batch the work into PRs.

## Headline

**The tests are in good shape.** No test anywhere is skipped forever for a bad
reason, none imports a removed module, and every `allow_localhost` test now
asserts the *retirement*. There is one exception (A1). **The docs are where the
drift is:** status lines, counts, and retired behaviour still described as live.
The survey also found **six real defects**, listed first.

## A. Real defects (fix first)

| # | Repo | What | Evidence |
|---|---|---|---|
| A1 | willow-mcp | **`test_signing_e2e.py` can never run.** It skips the whole module when `create_connected_server_and_client_session` is missing, SDK 2.x removed it, and pyproject pins `mcp>=2`. Signing has no end-to-end coverage. | ✔ `tests/test_signing_e2e.py:15-28` |
| A2 | willow-bot | **`pip install willow-bot` is broken.** The wheel packages only `willow_bot/`, but the `willow-bot` command runs `uvicorn.run("bot:app")` from root-level modules that aren't in the wheel. INSTALL.md:213 admits it; the README install line doesn't. | ✔ `pyproject.toml:54`, `willow_bot/cli.py:15` |
| A3 | willow-gate | **The release workflow calls a script that doesn't exist:** `tools/changelog_dedup.py`. The repo has no `tools/` directory. | ✔ `.github/workflows/release-please.yml:147,203` |
| A4 | willow-reconciler | **A test will fail when willow-mcp sits beside it.** It pins `len(items) == 111`; the real `ideas.md` now parses to 120. CI hides this because the test skips when the sibling repo is absent. | ✔ `tests/test_parse.py:64` |
| A5 | ratatosk | **The Ollama fallback is a model the ladder doesn't list.** `OLLAMA_MODEL` defaults to `llama3.2:1b`, and it is reachable: `listener.py:127` calls `generate()` with no model. | `ratatosk/ollama.py:8` |
| A6 | willows-grove | **The governance docs name envelope files that aren't there.** `syscall-table.json`, `frank_head_anchor.json` and `review_queue.json` are listed under `envelopes/`, and `.gitignore` says `syscall-table.json` "stays tracked". The directory holds only README.md. | ✔ `governance/README.md:24` |

## B. Safe mechanical cleanup (no behaviour change)

| Repo | Item | Action |
|---|---|---|
| willow-mcp | 3 tracked `.pyc` files, despite `.gitignore` ✔ | `git rm --cached` |
| willow-mcp | `deploy/cursor/hooks.json`: no references, and it uses the old entry points | delete |
| willow-mcp | `scripts/bootstrap_cursor_hook_fix.sh`: no references ✔, and it hardcodes a vault path | delete |
| willow-mcp | `.claude/` is gitignored, but three files under it are tracked on purpose | change the ignore rule to `.claude/*` with `!` re-includes |
| willow-gate | `.coverage` is tracked and not ignored ✔ (its own ideas item 22) | untrack it and ignore it |
| willow-gate | `release-please-config.json` has `initial-version` and comments copied from jeles, and v0.1.0 is already cut (item 21) | remove them |
| willow-bot | `losc/checker.py` and `MANIFESTO.md`: nothing imports `losc` ✔ | delete, or re-wire |
| willow-bot | README links `docs/ideas.md`, which doesn't exist ✔ | fix the link |
| willow-bot | `.gitignore` has no guard on `secrets/*` beyond the `.example`; also missing caches and `build/` | add `secrets/*` + `!secrets/*.example` |
| ratatosk | `__init__.py` says `__version__ = "1.1.0"`, but releases are 1.11.x ✔ | derive it from `importlib.metadata`, or delete it |
| ratatosk | `docs/CHANGELOG.md` and `docs/RELEASE_NOTES.md` duplicate the root changelog | delete both |
| willows-grove | `textual` is in `requirements.txt` ✔, but nothing imports it | remove it (keep the extra, or drop it too) |
| willows-grove | `governance/flags/fix-hermes-upstream-remote.sh` is a one-off for another repo | delete |
| willows-grove | a diagram filename contains a comma: `willow-new-user-draftv,02.drawio.png` | rename |
| willow-mcp | `scripts/reconstruction/*` and the `willow-gate-seam-*spike.py` files are one-offs whose work is done | move to an archive |

## C. Docs that say something untrue

**willow-mcp**
- `docs/design/nestor-tool-route.md` says "PROPOSAL … no code yet" ✔, but
  `tool_oracle.py` implements it. `willow-gate-seam.md` has the same problem.
- `session-lifecycle.md:37,356` says "121 MCP tools … kept in sync by
  `test_counts_in_prose.py`" ✔. The real number is ~150, and this file isn't in
  the lint registry. The same unlinted counts appear in `mcp-sdk-2-migration.md`,
  `hooks-and-skills.md` and `README.md:1010`. Drop the numbers or register the
  files.
- `consent-toggles.md:244-273`, `kart-productionization.md:48` and
  `egress-request-seam.md:61` still describe `# allow_localhost` as live.
- `hooks-and-skills.md`, `specialist-registry.md` and `packet-boot-design`
  still say DRAFT, though each has landed.
- `skills/brainstorming.md:48` offers `willow_web_*` as a fallback, but
  `orchestrator-routing.md` retires it for the willow seat.
- `docs/repatriation/README.md` says "left on a branch, no PR", yet it's on
  master.

**willows-grove**
- CLAUDE.md lists web components twice, and several dirs are missing from the
  architecture tables.
- **Two CLAUDE.md *rules* contradict the code. These need an operator ruling, not an
  edit:**
  - **Rule 1** says "No web ports … portless means portless", but the page
    serves on :8766 and MCP on :8767.
  - **Rule 3** says "grove_reader.py is read-only", but it runs INSERT, UPDATE
    and DELETE ✔ (line 672 and others).
- `README.md:28` says "two placeholder routes"; there are 11 routes plus a
  websocket. `test_readme_honesty.py:115` pins the stale wording.
- `docs/OPS_RUNBOOK.md:43-44` lists `python3 app.py` and `python3 -m grove`
  ✔, and neither exists. `docs/ARCHITECTURE.md` and the `grove/__init__.py`
  docstring still describe a Textual TUI.
- Proposals with stale status lines:
  - `2026-09-09-grove-seat-inversion` still says "awaiting ratification" ✔,
    though it's implemented;
  - `mcp-jobs-ladder-test-plan`, `local-inference-seam` and `build-order`
    still assume the `allow_localhost` grant;
  - `governed-path-write-gate` v1 was superseded by v2.

  Update the statuses, and add a `superseded/` folder.
- The runbooks cite `docs/generated/incident-candidates.md`, which doesn't
  exist. `playwright.config.js:9-10` still calls 8766 an "ephemeral CI port".
- `tests.yml` has stale "until PR 8 / PR 9" comments. Four guard steps still use
  the `hashFiles` silent-skip pattern that
  `test_ci_hashfiles_guards_removed.py` was written to remove.

**willow-bot**
- `SECURITY_AUDIT.md` (2026-05-06) no longer matches the code in four places:
  - how credentials resolve at startup;
  - the vault/Fernet path;
  - "no subprocess" (steward uses it);
  - the key default.

  It needs a re-audit, not an edit.
- `BOT-INVENTORY.md` calls the two unused labels "shipped".
- `MOVE-STAY-BORROW.md` lists items as missing that now exist.

**kartikeya**
- README:92 still has the "coming with stage 2" placeholder ✔.
- `release-please.yml` says there is "no CHANGELOG.md"; there is one.
- `security_scan.py:190` says there are "no cgroup limits", but they shipped.
- `DESIGN.md` gives its status as 0.0.7 (the release is 0.4.2), links an audit
  file that doesn't exist, and names an env var nobody reads.
- `ideas.md` item 7 is fixed but not ticked.

**ratatosk**
- The README env table leaves out ~10 variables the code reads.
- `termux/README.md` needs checking against the current deposit dir logic.

**Small repos**
- **`ideas.md` items done but not ticked:**
  - reconciler 21 (ruff half only, so partial);
  - corpus-lens 42 and 44;
  - data-vault 1 and 2.
- **corpus-lens:**
  - `examples/EXAMPLE.md` claims "byte-for-byte reproducible", but the current
    run shows 8 analyzers, not 6. Regenerate it, and add a diff test.
  - The README Status section says "six analyzers", leaves out `consent`, and
    calls guardian consent "unbuilt", though it has shipped in part.
  - "Six invented operators" should be 8.
- **willow-gate:**
  - `docs/HANDOFF.md` describes branch `build/custody-ledger` ✔, which no
    longer exists.
  - `hardening-plan.md` still says DRAFT.
  - A test comment still says "until Tier-4", though Tier 4 shipped.
- **data-vault:**
  - The README tree leaves out `06_intake.sql` and `vault_intake.py`.
  - CONTRIBUTING documents the trailer format as `<corpus>-ideas-N`, but the
    reconciler emits `willow-ideas-N`.
- **reconciler:**
  - The README says "only ever runs `git log`", but `install-hook` writes hooks.
  - ideas item 31 misdescribes CodeQL.

## D. Code cleanup that needs review and tests

| Repo | Item | Note |
|---|---|---|
| kartikeya | `allow_localhost` is still plumbed through as a live parameter: `kart_env` exports `WILLOW_KART_ALLOW_LOCALHOST=1` ✔ (`sandbox.py:953`), with dead kwargs across the runners and `execute.py` | keep only the named refusal |
| kartikeya | `test_task_scan.py:40` asserts `# allow_localhost` scans clean, as if it were live | update it |
| willow-mcp | the dead `localhost=` parameter in `egress_authorization` and the `--localhost` CLI flags | keep refusal stubs only |
| willow-mcp | `VALID_STATUSES` `closed` and `failed` are never written | this is #655 open question 4 |
| willow-mcp | modules nothing in the package imports: `mcp_adapters.py` ✔ (its docstring says it gates federated calls), `lanes.py`, `bound_receipt.py`, `install_project.py`, `hook_parity.py` (a test helper living in src), `safe_integration.py` | decide for each: **wire it or delete it** |
| willow-bot | the two labels are never applied | this ties to #655 §3.5 |
| willow-bot | `requirements.txt` and `pyproject` have drifted: nestor is only in requirements, so `test_semantic` skips on every CI run; loki's psycopg2 isn't declared | consolidate |
| willow-bot | `steward/merge.py` is marked DEPRECATED (2026-09-15) "for one prove window" | schedule its removal |
| willow-bot | the `loki/` watcher looks dormant: no entry point, hardcoded paths, a Draft SPEC, and loki now runs through ratatosk's unit | investigate, then retire it |
| ratatosk | the crown `--listen` path (with `traces.py`), used by the Termux boot script, versus the daemon path systemd uses | investigate whether to converge them |
| willows-grove | `panes/`, down to one module, is pulled in by `grove_reader`; the `tui` extra's comment is false | fold into `grove/` |
| willows-grove | three phantom-file honesty tests, each covering one doc | consolidate into one parametrized test |
| willow-mcp | `test_consent_toggles.py` has four strict xfails marked "not yet enforced" | confirm they are still the plan |

## E. Decisions only the operator can make
1. **Grove CLAUDE.md Rules 1 and 3:** reword them to match the code, or change
   the code to match them?
2. **The unimported willow-mcp modules:** wire each one or delete it,
   especially `mcp_adapters.py`, which #650 builds on.
3. **willow-bot `loki/` and `losc/`:** retire them?
4. **willow-bot's `SECURITY_AUDIT.md`:** a Loki re-audit?
5. **`closed` and `failed` statuses:** this is already #655 Q4.

## F. Open GitHub issues across the fleet (checked against code)

There are six open issues in the nine repos: four in willow-mcp and two in
willow-gate. The other seven repos have none. Each was checked against current
code.

| Issue | Actually open? | Evidence |
|---|---|---|
| [willow-mcp#468](https://github.com/willow-memory/willow-mcp/issues/468): raise the `mcp` floor to the version with the SEP-2322 types | **Yes.** | `pyproject.toml:31` still says `mcp>=2.0.0,<3.0.0`. The issue gives a recipe that needs a machine with network (this container can't install from PyPI). Known: 2.2.0 has all five types. It's small once someone runs the recipe. |
| [willow-mcp#401](https://github.com/willow-memory/willow-mcp/issues/401): `code_graph` stores relative imports as bare names | **Yes.** ✔ | `code_graph/indexer.py:107-112` never reads `node.level`, so `from . import X` stores target `X`. The fix is local: resolve against the importing module's package. |
| [willow-mcp#402](https://github.com/willow-memory/willow-mcp/issues/402): `code_graph_explain` says "callers/callees" but stores no call edges | **Yes.** ✔ | The tool description at `server.py:8686` still says "callers (inbound edges)". The fix is cheap: rename the fields at the tool boundary, per the issue's option 1. This matters because an agent may treat `callers: []` as dead code. |
| [willow-mcp#232](https://github.com/willow-memory/willow-mcp/issues/232): store `.db` files need real OS-level permission enforcement | **Partly.** | The code side has landed: `mcp_receipt.db` was added to `_SECRET_FILE_NAMES`, and there is a `store_db_exposure()` check with a warning. #231, the uid-separation runbook it depended on, closed via #343. What's left is **deployment**: actually running the agent under a separate uid, then extending the AT-M1 kill-chain step 6 to show the OS refuses the write. Either narrow the issue to that residual, or close it once the uid split is live on the box. |
| [willow-gate#18](https://github.com/willow-memory/willow-gate/issues/18): HMAC secret is plaintext in the registry, so identity is forgeable | **Yes, 1 of 4 legs partly done.** | `__init__.py:204` still writes `{"secret": secret.hex()}` to `registry.json`. Server-side reputation exists behind `WILLOW_GATE_ENFORCE_EARNED_RUNGS`, which ships **off**. Asymmetric check-in signing is ideas item 16, still open. Ed25519 exists for bus messages (`message_integrity.py`) but not for check-in. |
| [willow-gate#9](https://github.com/willow-memory/willow-gate/issues/9): `friction_score` is stance-blind (chance on 9,000 pairs) | **No. It looks closable.** | The fix the issue asked for shipped: a stance-aware second signal (`friction_floor.py:99+`, citing #9). `docs/ideas.md` item 4 records it going "from chance to 84% committed accuracy". What's left (wiring it into the pre-tool hook and the check-in `drift` field) is already tracked as ideas item 4. **Close it with a comment pointing there**, after confirming the 84% re-run is recorded. The issue itself calls the eval "the falsifier". |

**Issue housekeeping:** close #9, and narrow #232 to its deployment residual.
Then #401 and #402 make a small, well-defined code PR, and #468 needs one
networked run of the recipe.

## Suggested batching
- **One PR per repo** for sections B and C. Those are docs and hygiene: each
  small, and each still carries the repo's `Persona:` and `Ratified-by:`
  conventions.
- **The defects in A as their own small PRs,** each with a test: A1, A2, A3
  and A4 especially.
- **Section D after the operator's rulings in E.**

ΔΣ=42
