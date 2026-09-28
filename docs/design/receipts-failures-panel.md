# Scope: the "what failed or was refused?" panel

- Status: **Scoped, not ratified** — two bites, each needs its own ratification
  before it is built
- Date: 2026-09-28
- Rulings already given (operator, 2026-09-28):
  - Grove reads receipts **through a new willow-mcp read verb**, never by
    opening the SQLite file;
  - the first panel answers exactly one question: **"What failed or was
    refused?"**
- Bite (a): willow-mcp, a fleet-wide failure-receipt read verb
- Bite (b): willows-grove, a reader, an endpoint and a panel (Watch lens)

## 1. What exists

- **`ReceiptLog`** (`receipts.py`) holds one hash-chained row per tool call in
  `$WILLOW_HOME/mcp_receipt.db`: `ts, app_id, tool, outcome, detail`.
  `verify()` walks the chain and names the first broken link.
- **`receipts_tail`** (`server.py`, group `audit`) reads **only the caller's
  own** rows, and its docstring promises "never another identity's calls". It
  returns `detail` **verbatim**. There is no redaction today, which is safe only
  because a seat only ever sees its own rows.
- **Grove already reads willow-mcp through its seam.** `grove/journal_reader.py`
  calls `kb_journal_read` via `willow_mcp_client` and raises `Unreachable` when
  transport fails or the verb refuses. That is the pattern bite (b) copies.
- **Grove calls as its own seat, `willow-grove`** (`journal_reader._APP_ID`),
  not as the orchestrator. That settles the gating question in §2.2.

### 1.1 What `detail` actually holds

Taken from every `_receipt_log.record(...)` call site in `server.py`:

| outcome | detail written | Safe to show across seats? |
|---|---|---|
| `denied` (gate) | `gate_err["error"]`, a denial message | mostly: a fixed vocabulary, but some embed the app_id or tool |
| `denied` (subject) | `subj_err["error"]` | same |
| `denied` (egress) | `egress.<kind>: <url>` (≤300 chars) | **no**: a URL can carry a query string or a token |
| `rate_limited` | `retry_after=<n>` | yes |
| `error` | `f"{type(e).__name__}: {e}"` | **no**: free exception text, which can include paths, argument values or response bodies |
| `error` | `sanitize: <problem>`, `egress_scan_refused: kinds=…`, `egress_scan_failed: <Type>`, a probe error string | mostly: fixed prefixes |
| other outcomes | `ok`, `bind_enforced`, `bind_observed`, `reconciled`, `reconcile_discrepancy`, `guard.tool_output_escape`, `credential_returned`, `redacted`, `federated_call`, `warn` | not in scope for this panel (§5) |

A fleet-wide view is the **first place one seat's receipts are shown to
another reader**. Redaction is therefore new work in bite (a), not something
that can be reused.

## 2. Bite (a): willow-mcp `receipts_read_fleet`

### 2.1 Shape

```
receipts_read_fleet(app_id, since="", limit=100, outcomes=[]) -> {
  "rows": [{"id", "ts", "app_id", "tool", "outcome", "detail_shape"}],
  "chain": {"ok": bool, "broken_at": id|null, "count": n},
  "window": {"since": ts, "limit": n, "outcomes": [...], "truncated": bool}
}
```

- **Read-only**, newest first.
- **`outcomes`** defaults to the failure set `{"denied", "rate_limited", "error"}`.
  Any value outside the known outcome vocabulary is `EINVAL`, never silently
  ignored.
- **`since`** is an ISO timestamp. It defaults to 24 hours ago and cannot reach
  further back than 30 days (`EINVAL`).
- **`limit`** is capped at 500. `truncated: true` when more rows matched.
- **`chain`** is `ReceiptLog.verify()`, returned with every read. A panel that
  shows failures from a tampered log must be able to say so.

### 2.2 Who may call it

- It goes in a **new permission group, `receipts_fleet`**, holding only
  `receipts_read_fleet`. It is not added to `audit`, which stays the self-scoped
  `receipts_tail` group.
- Grove calls as `willow-grove`, so an orchestrator-only verb would refuse the
  panel's own reader. The group is instead granted by **sealed manifest grant**
  (#646's `manifest.grant` path) to exactly two seats: `willow` (the desk) and
  `willow-grove` (the served page). No other seat gets it by default.
- `receipts_tail` is unchanged. It stays self-scoped, with its docstring and
  tests intact.

### 2.3 Redaction: `detail_shape`, never raw `detail`

The verb never returns `detail`. It returns `detail_shape`, built by an
**allowlist parser**. Anything the parser doesn't recognise is reduced, never
passed through:

| Input `detail` | `detail_shape` |
|---|---|
| a known gate or subject denial message | the denial **code** (the leading token) with app_id and tool stripped |
| `egress.<kind>: <url>` | `egress.<kind>` + URL **host only** (no path, no query, no fragment) |
| `retry_after=<n>` | as is |
| `sanitize: …`, `egress_scan_refused: kinds=…`, `egress_scan_failed: <Type>` | the fixed prefix + the named kinds or type |
| `<ExceptionType>: <free text>` | `<ExceptionType>` + `sha8` of the full text, so identical errors group together without showing their text |
| anything else | `opaque` + `sha8` |

Full `detail` stays reachable the way it is today: each seat through its own
`receipts_tail`.

### 2.4 Tests

- **Refusal:** a seat without `receipts_fleet` is refused (`EPERM`), and so is
  `willow-grove` before it holds the grant.
- **Self-scope unchanged:** `receipts_tail` called by seat A never returns seat
  B's rows, with the existing tests untouched and one added to pin it.
- **Redaction, one test per row of §2.3,** including an egress URL with a query
  token and an exception carrying a filesystem path. Neither may appear anywhere
  in the output. Mutation proof: remove the parser, pass `detail` through, and
  both tests turn red.
- **Bounds:** limit cap, 30-day floor, unknown outcome is `EINVAL`, `truncated`.
- **Chain:** a hand-broken row makes `chain.ok` false with the right
  `broken_at`, and the rows are still returned.

## 3. Bite (b): willows-grove reader, endpoint and panel

This is the Watch lens: Heimdallr's "is the surface telling the truth". It gets
its own PR in willows-grove, following that repo's rules (`Persona:` trailer,
`Ratified-by:` line, `check_changelog_bullet`).

### 3.1 Reader: `grove/receipts_reader.py`

- It follows `journal_reader.py` exactly: it calls `receipts_read_fleet` as
  `willow-grove` through `willow_mcp_client`.
- Transport failure raises `Unreachable("willow-mcp not reachable …")`.
- **A refusal is also `Unreachable`**, with the refusal as its reason. It is
  never an empty list. A missing grant must never render as "nothing failed".
- The reader returns rows and `chain` unchanged. It adds nothing.

### 3.2 Endpoint: `GET /api/receipts/failures?since=&limit=`

The same three-state shape as `/api/envelopes`:

- `200 {"state": "populated", "rows": [...], "chain": {...}, "window": {...}}`
- `200 {"state": "empty", "rows": [], "chain": {...}, "window": {...}}`: the
  read succeeded and nothing failed in the window.
- `503 {"state": "unreachable", "reason": "..."}`

### 3.3 Panel: `web/components/grove-failures-panel.js`

- **Grouped by seat,** newest first. Each row shows time, tool, outcome and
  `detail_shape`.
- **Three distinct renderings:**
  - **populated:** the grouped list;
  - **empty:** "Nothing failed or was refused in the last 24h", with the window
    shown so "empty" is never ambiguous;
  - **unreachable:** the reason, visibly distinct from empty. A refusal reads as
    "not permitted to read receipts", not as a quiet panel.
- **Chain banner:** if `chain.ok` is false, a banner above everything, in every
  state that has a `chain`: "Receipt chain broken at #<id> — rows after it may
  not be trustworthy."

### 3.4 Tests

- The reader's unreachable path: transport down, and verb refused.
- The endpoint's three states.
- A Playwright check that each state renders distinctly, and that the chain
  banner appears on a broken chain. Grove already runs Playwright.

## 4. Order and dependencies

1. Bite (a) lands and is released.
2. **A host act:** seal the `receipts_fleet` grant for `willow` and
   `willow-grove`.
3. Bite (b) lands. Until the grant exists, the panel correctly shows
   **unreachable: not permitted**, which is the honest state and a useful first
   check that the refusal path renders.

## 5. Out of scope

- **Other outcomes.** `reconcile_discrepancy`, `guard.tool_output_escape`,
  `credential_returned`, `redacted` and `warn` are signals worth watching, but
  they are not "failed or refused". They belong to a later panel or an explicit
  ruling (§6).
- **The other questions:** fleet activity, where models are still called, and
  energy. Those are later panels.
- **Trace ids** linking receipts, ratatosk turns and dispatches.
- **Write actions** of any kind from the panel.

## 6. Open questions for the operator

1. Should `reconcile_discrepancy` and `guard.tool_output_escape` count as
   "failed or refused" in this first panel, or wait?
2. Is 24 hours the right default window, and 30 days the right hard floor?
3. Does the desk (`willow`) need `receipts_fleet` too, or only `willow-grove`?

*ΔΣ=42*
