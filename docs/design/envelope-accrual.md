# Envelope accrual — the operator's yes/no as a growing store

*Status: shipping in PRs #372 / #373 / #374 / (this PR) across the identity-in-session and envelope-accrual plans. Design lineage: Nestor §5.8 (`docs/covenant-lineage.md` in the Nestor repo).*

## The problem this closes

Every operator session generates dozens of small decisions — which dispatch shape to grant to Hanuman, which file pattern is fine to write, which envelope to renew. Today those decisions are one-shot: the next session forgets them. When a specialist hits a wall on a missing envelope, the operator learns about it only through prose narration, then hand-edits `$WILLOW_HOME/constitutional/pre-approved.json` in `$EDITOR`, then the specialist tries again.

Multiplied across a real session (20+ decisions is typical), the friction pushes the operator toward one of three failure modes the fleet's own decision record already names:

1. **Approving without looking** — `A1`'s prior in Nestor's dogfood: *"a gate that asks somebody to approve their own work teaches them to approve without looking, which costs more than it buys."*
2. **Building workarounds that aren't gates** — `C8`'s prior: *"The hook worked. The hook they wanted did not exist."*
3. **Abandoning the flow entirely** — the operator disables enforcement, or bypasses the seat, and the trust surface stops mattering.

The envelope-accrual work is the shape that avoids all three by making the human's yes *cash* into a growing store, so the next similar prompt is a confirmation instead of an authoring task.

## What was already in the box (design lineage)

The envelope registry has been fully shipped for months:

- `envelopes.py::EnvelopeAuthority.check` — validates a caller's envelope claim against the registry.
- `envelopes.py::governing_envelope_ids(verb, actor)` — the ambient resolution used by `_enveloped_verb_gate` (`server.py:2915`) for citation-before-act (#333).
- `authorize_and_cite` + `GovernanceLedger.append_citation` — every application of an envelope lands as a FRANK ledger event.

What was missing was the **write side**: no CLI subcommand, no MCP tool, no back-channel. The `proposals[]` slot in `pre-approved.json` was declared and constitutionally documented (*"Agents MAY draft proposals into `pre-approved.json#proposals`; a proposal has no force until root moves it to active"*, `syscall-table.json:233`) — but zero code read or wrote it.

## The Nestor §5.8 pattern being ported

Same shape Nestor uses for translation-memory pairs, applied to a different subject:

| Nestor §5.8 | Willow envelope accrual |
|---|---|
| `memory.add_pair(status="draft")` — agent writes a proposed pair, no force | `envelope_propose` — agent writes a proposed envelope into `proposals[]`, no force |
| `memory.seal(...)` — the human's confirmation, keyring-signed | `envelope_ratify` — operator moves proposal → `active[]`, keyring verifier + operator tty required |
| `memory.reject_pair(reopen_when=...)` — recorded "no" with NEVER / NOT YET | `envelope_reject` — recorded "no" with the same `reopen_when` distinction |
| Fuzzy `nestor decision check` — surface the operator's prior commitments before accepting a new proposal | `envelope_shapes.similar_precedents` (PR7) — surface prior ratifications for similar bounds so the new proposal is pre-filled |
| `attribution_ledger.jsonl` (PR4) — attributable session events | FRANK `envelope_proposed` / `envelope_ratified` / `envelope_rejected` events — attributable authoring events |

Each version of Nestor's covenant *removed* something (`docs/covenant-lineage.md`): a confidence number, a redundant tier, an auto-ratification path. Every removal made the primitive smaller. The envelope-accrual work follows the same discipline — no auto-ratification, no unbounded generalization, no shape that would silently widen without a click.

## The three PRs

### PR5 — foundation (merged into this branch as `afdd675` + `4e85494`)

Five new MCP tools + a CLI + the `envelope_authoring` module:

- `envelope_propose(verb, grantee, bounds, reason, expires_at, max_count)` — WRITE, attribution-gated. Refuses without a keyring verifier active on the current orchestrator session.
- `envelope_ratify(proposal_id)` — WRITE, orchestrator + keyring. Moves proposal → active with `issued_by="root"`.
- `envelope_reject(proposal_id, reason, reopen_when)` — WRITE, same operator gate. NEVER vs NOT YET.
- `envelope_list(grantee, verb)` — READ.
- `envelope_pending_read(oldest_first, limit)` — READ. Operator queue view.
- CLI: `willow-mcp envelope {list,pending,ratify,reject}`. No CLI `propose` — propose is orchestrator-attributed and lives on the MCP tool surface.

Each authoring act writes a FRANK event when Postgres is available; deployments without PG get the on-disk record but no ledger entry (same graceful-degradation pattern `envelope_apply` already uses).

### PR6 — auto-propose + orient hook (this PR)

The back-channel from `_enveloped_verb_gate` to `proposals[]`:

- On **ENOGRANTS** (no envelope governs verb+actor): gate stays permissive (call proceeds unmetered — behavior preserved), AND writes a proposal capturing the actual `call_args` as bounds. The proposal is a queue entry, not a refusal.
- On **check failure** (envelope exists but bounds/quota/expiry don't fit): gate refuses as before, AND writes a proposal so the operator can widen bounds or bump quota with one ratify click rather than diffing errno.reason.fields[] against the current envelope by hand.
- **Dedup by (session, verb, bounds_digest)**: repeat calls with the same shape produce one proposal, not N. Cache is process-local; `clear_auto_propose_cache()` for tests and operator-restart.

Attribution gate: auto-propose fires only when the current session is a keyring-attributed orchestrator session with a verifier on record. Unattributed / specialist-owned processes cannot cause a proposal to appear.

`session_enter`'s orientation block gains `envelope_proposals_pending: {count, oldest_id, oldest_at}` for orchestrator sessions. The operator sees "N proposals waiting" at seat-open, not mid-dispatch after the queue has silently grown.

**Deferred**: specialist-side auto-propose (a specialist's OWN process auto-proposing from its own gate misses, attributed via the dispatch packet's `from_app`). Needs `dispatch_send` to carry the orchestrator's verifier in the signed meta.json — a schema extension not in scope for PR6.

### PR9 — dispatch carries operator attribution (Kart-boundary silence, part A)

The PR6 deferral above. `dispatch_send` now writes `from_verifier` and `from_session` into the signed meta.json (both empty when the orchestrator's own session is unattributed — the no-attribution-to-carry case). On `dispatch_accept` and on `session_enter`'s specialist re-entry branch, the packet's `from_verifier` is lifted onto the specialist's session record (via `session_bind(..., verifier=...)`) and the specialist session is added to the in-process `_attributed_sessions` cache.

The net effect: a specialist that inherits an orchestrator's attribution through the dispatch packet can now trip `_auto_propose_on_gate_miss` from its own process. The resulting queue entry's `proposed_by.verifier` names the ORIGINATING operator, not the specialist that generated the miss — the operator's queue view stays a queue of humans, not of proxying processes. `session_bind`'s existing verifier-preservation contract means no downstream lifecycle transition clobbers the inheritance, and the HMAC signature on meta.json (`dispatch_signing.sign_meta`) covers both new fields so a hand-planted packet cannot forge an operator attribution.

An unattributed dispatch packet (`from_verifier=""`) does NOT attribute the specialist — the silence is preserved rather than laundered.

**Still deferred (Kart-boundary silence, part B)**: a specialist running INSIDE Kart (bwrap-sandboxed shell task, no MCP client at all) still has no path back to the queue. Part A closes the silence for every specialist that runs as its own MCP client, which is the majority in practice today. Part B needs a design decision on the drop-off mechanism (filesystem queue Kart CAN write to? harvester on the host side?) before it's tractable — its own thread.

### PR10 — precedents expanded inline on pending read

`envelope_pending_read` now returns each row with `precedents_expanded`: the full envelope objects behind every id in `precedent_ids` that still resolves. Turns the ratify UX into one glance ("confirm precedents X, Y or override") instead of a two-hop dance through `envelope_list`. Precedent ids that no longer resolve silently drop from the expansion; `precedent_ids` itself stays intact as tamper evidence. Opt-out with `include_precedents=false`.

### PR11 — rejected proposals accrue as precedents (registry `archived[]`)

The operator's *decisions* accrue, not just the ratified subset. Same discipline as Nestor's `reject_match`: a "no with a reopen_when" is a precedent about the shape, not a lesser signal.

- Registry gains an `archived[]` list alongside `active[]` and `proposals[]`. `reject()` moves the rejected row into `archived[]` with `status="rejected"`, `archived_at`, `reject_reason`, `reopen_when`, `rejected_by`, and the bounds intact. Old behavior — deleting the row — was throwing away the operator's most useful signal about future proposals.
- New read: `envelope_authoring.list_archived(grantee=, verb=, status=)`. Filterable, read-only.
- `envelope_shapes.similar_precedents` gains `include_archived=True` (default). Walks both `active[]` and `archived[]`; each result carries `precedent_status` (`"active"` or `"rejected"`) and — for a rejected precedent — the `reopen_when` condition. Score is polarity-blind; the surface renders the polarity.
- `top_precedent_ids` and `list_pending`'s inline precedent expansion (PR10) both extend to include archived rows with the same status decoration.

The natural sequel — "when `ratify` supersedes an existing active envelope for the same (verb, grantee), move the superseded one into `archived[]`" — is a separate design decision (whether ratify should supersede at all is itself unresolved) and out of scope here. Registry growth is a real long-run concern; compaction is left for when the archived list gets large enough to matter.

Historical precedents from the FRANK ledger itself remain out of scope: `envelope_ratified` events store `bounds_digest`, not full bounds, so the ledger walk can identify prior envelope_ids but not score them. That would need either a wire change (bounds inline in the event) or a separate bounds-history store, neither of which are tractable here.

### PR7 — shape similarity + precedent recall (future)

`envelope_shapes.similar_precedents(verb, grantee, bounds)` reads active envelopes + FRANK `envelope_ratified` history, scores each precedent by verb match + grantee overlap + per-field bounds similarity (fnmatch equivalence classes for glob bounds, prefix overlap for path-shaped bounds). `envelope_propose` calls this before writing; the resulting proposal row carries `precedent_ids: [...]` and `pre_filled_bounds: {...}`. The operator's ratify UX shows "similar to envelopes X, Y ratified on D1, D2 — confirm precedents or override."

This is the piece that makes the accrual actually reduce authoring cost. PR5 + PR6 make the loop *possible*; PR7 makes it *cheap*.

## Constraints inherited (do NOT re-solve)

- **`issued_by="root"` invariant preserved.** `envelope_ratify` stamps `"root"` when the operator's verifier passes the keyring check — same "root == the human at the terminal with a keyring-registered key" reading PR1-4 established.
- **Trusted-read discipline preserved.** Reads route through `envelopes._load` → `paths.trusted_read`; writes use atomic-rename with prior-content rollback.
- **`_attributed_sessions` cache-by-path.** Revocation across processes is invisible to a running server — operator restarts to force re-verify (mirrors `nestor.keyring`'s docstring policy).
- **Server verifies, never signs.** Ratify writes are keyring-authenticated the same way `sign-session` sidecars are: operator's client-side signature over the frozen wire message, verified by the server, not signed by it. (Client-side signing for ratify itself is a follow-on if the operator ever runs willow-mcp cross-machine; the same-machine common case satisfies the invariant by having the operator uid own both the process and the keyring.)
- **No auto-ratification.** Every yes still passes through a human. Precedent recall (PR7) pre-fills bounds and cites priors; the confirming click remains.
- **Ledger events are optional.** Postgres-less installs get on-disk envelopes but no ledger stream. Same graceful degradation `envelope_apply` already uses.

## Where the accrual loop closes

Once PR5 + PR6 + PR7 land:

1. Operator opens the willow orchestrator seat. Orient shows "3 proposals waiting" from prior sessions.
2. Operator dispatches Hanuman. Hanuman's call to `dispatch_send` (verb-level-enforced) hits the gate. An envelope exists for `dispatch_send/hanuman` with bounds `{"file_pattern": "src/**"}` but this call wants `{"file_pattern": "docs/**"}`. Gate refuses; auto-propose writes a queue entry with the new bounds.
3. Operator sees the new proposal alongside precedents ("similar to your `docs-writes-for-hanuman` from 2026-08-20"). Confirms with one click; envelope ratifies, FRANK records it, precedent set grows.
4. Next session, when Hanuman needs another docs write, no gate refusal happens because the envelope now covers it. The queue is empty. Orient block shows "0 proposals waiting."
5. When something genuinely new comes up, only IT lands in the queue.

The operator's answering cost per session collapses from "N raw authoring acts" to "N confirmations + occasional overrides." That's the accrual loop paying its rent.

## What this design does NOT do

- **Kart-inside-bwrap propagation.** PR9 closes the specialist-as-MCP-client case (dispatch packet carries operator attribution; specialist inherits it on accept). A specialist running INSIDE Kart's bwrap sandbox has no MCP client at all — no way to call `envelope_propose`, no filesystem drop-off queue today. Closing that pocket needs a drop-off mechanism decided separately.
- **Cross-instance envelope sync.** Single-instance only. Multi-box operators today have separate registries per box.
- **Portable envelopes across fleet repos.** safe-app-store and homestead each have their own registries; unifying them is out of scope.
- **Auto-ratification.** Every yes still passes through a human. Precedent recall pre-fills; the click remains.
- **Extraction of accrual as a Nestor primitive.** Deferred per the "willow-first, extract later" scope choice made when the plan opened. Once PR5-7 prove the shape, extraction into a Nestor recipe is a separate plan.

## References

- Nestor `docs/covenant-lineage.md` — "you may propose; you may not confirm" ancestry
- Nestor `IDEAS.md` §5.8 — per-verifier keyring shipping decision
- Nestor `nestor/keyring.py`, `signing.py`, `memory.add_pair(..., seal_sig=...)` — the primitives being ported
- willow-mcp `docs/design/human-orchestrator.md` — the seat this accrual lives inside
- willow-mcp `docs/design/pgp-and-persona.md` — the identity substrate the attribution rail runs on
