---
kind: doc
name: "guardian-consent-seam-representing-a-subject-who-isnt-the-owner"
description: "Design doc mapping how a shared subject-consent primitive lets willow-mcp, corpus-lens, the Nest, and UTETY represent owner-not-equal-subject consent, guardian roles, and fail-closed disclosure."
---

@markdownai v1.0

# The guardian-consent seam: representing a subject who isn't the owner

Status: **core extracted + binding shipped + gate live.** The stdlib-only core
now has a single **canonical home** at
[`safe-app-store` `libs/subject-consent`](https://github.com/rudi193-cmd/safe-app-store)
(the vendor pattern `willow_mcp.nest` uses for `apps/nest-seed`, chosen over a new
repo). willow-mcp's copy is VENDORED from there and carries a provenance header;
UTETY and corpus-lens adopt the same canonical next — so the primitive is built
once and single-sourced, not forked three ways. Both halves this doc maps exist:

- **Core** — [`src/willow_mcp/subject_consent/core.py`](../../src/willow_mcp/subject_consent/core.py)
  (tests: [`tests/test_subject_consent.py`](../../tests/test_subject_consent.py),
  25 passing, incl. a static no-network/stdlib-only import boundary). Stdlib-only,
  egress-free, owner-agnostic. Answers "did this subject consent to this scope?"
- **Binding** — [`src/willow_mcp/subject_consent_binding.py`](../../src/willow_mcp/subject_consent_binding.py)
  (tests: [`tests/test_subject_consent_binding.py`](../../tests/test_subject_consent_binding.py),
  19 passing). The willow-mcp side the core deferred to: owner-exemption, the
  AND-composed `subject_gate`, and the operator-only `grant`/`revoke` seat
  (refuses off an operator terminal; writes both a ReceiptLog line and the
  subject's disclosure chain). Wired into `server._guarded` as the third gate
  check after `gate.permitted`.

It converges *owner ≠ subject* consent — the one gap corpus-lens named and
refused to ship, the Nest ran straight into, and UTETY already solved in
miniature for a child learner — into one shared primitive all three can depend
on. **The gate is live.** The four subject-touching tools in `TOOL_SUBJECT_SCOPE`
each expose an optional `subject_id` (tests:
[`tests/test_subject_consent_gate_wiring.py`](../../tests/test_subject_consent_gate_wiring.py),
9 passing, driven end-to-end through `_guarded`):

- `knowledge_ingest`, `kb_ingest`, `nest_promote` → require a `kb_promotion` grant
  for a named non-owner subject; a committed write is logged to that subject's
  disclosure chain.
- `lineage_record` → requires the higher `person_inference` grant (corpus-lens's
  quarantined `PERSON_CLAIM_TYPES` bar); a `kb_promotion` grant does **not** open it.

`subject_id` stays empty for the owner's own data (every call today), so the gate
is a no-op there and nothing existing changed. The remaining convergence is
external: **corpus-lens and UTETY consuming this shared core** instead of each
carrying their own — the reason it was built stdlib-only. That is their import to
make, not a willow-mcp change.

What the shipped core provides (and what it pointedly leaves out):

- `grant`/`revoke`/`permitted(store, subject_id, scope)` over a hash-chained,
  append-only consent log — fail-closed on every path that isn't a *verified*
  `granted` (absent store, broken chain, no record, `pending`, `revoked` → `False`).
- `deidentify(text, identifiers)` — de-identify-or-refuse; proves the scrub or
  raises **without ever echoing the surviving value**.
- `record_disclosure`/`read_disclosures` — the per-subject, tamper-evident record
  a guardian can read.
- Scopes are **independent permissions, not a ladder**
  (`local_only`, `process_analysis`, `kb_promotion`, `person_inference` — the
  last name matching corpus-lens's capability); each is granted and checked on
  its own.
- **Not in the core, on purpose:** owner==subject is *not* special-cased (the
  core doesn't know who the owner is); capacity/self-consent judgments are
  deferred; and mutation is a library primitive an operator CLI calls — an app
  can never grant consent on a subject's behalf. Enforcing all three is the
  binding's job.

Home: willow-mcp, beside [`consent.py`](../../src/willow_mcp/consent.py) and
[`gate.py`](../../src/willow_mcp/gate.py). Reference implementation to generalize
from: UTETY's [`utety/core/store.py`](https://github.com/hornbook-knowledge/UTETY) +
`utety/knowledge.py`.

---

## The gap it fills

Every authorization surface in this stack answers one of two questions:

- **`gate.permitted(app_id, tool)`** — *may this app do this?*
- **`consent.permitted("internet")`** — *does the operator permit the system to do this?*

Both are about the **owner** and the **app**. Neither can represent a third
party: **the person the data is *about*, when that person is not the operator.**

This gap is load-bearing across the constellation:

- **corpus-lens** draws a hard line at *owner == subject* and quarantines
  `PERSON_CLAIM_TYPES` behind a `person_inference` capability that the default
  registry may never grant. It named the guardian-consent model (owner ≠ subject)
  as its *"biggest unshipped gap"* and refused to ship it. There is no
  representable way to say *"this claim is about someone else, and here is their
  grant."*
- **The Nest** makes `person` fragments of whoever shows up in a life-dump — a
  co-parent, a child, an ex-partner. Today the wall keeps those out of the shared
  KB by making them *anonymous counts*. But there is no **consent object** for
  those non-owner subjects: the Nest can only ever wall them, never *admit* them
  with a grant.
- **willow-mcp**'s `consent.py` is **capability** consent — the owner flipping
  `internet` / `cloud_llm` / `lan` about their own system. It has the right
  fail-closed discipline (*"absence is not consent"*) but the wrong axis: it says
  nothing about whose data is in play.
- **UTETY** is the only piece that built the missing axis — because a classroom
  *forces* it. The learner is a child; the operator is a parent; COPPA gives no
  school-consent safe harbor (build-plan rule 4). So UTETY carries, in code, a
  consent record *granted by a guardian on a subject's behalf*.

The seam is: **lift UTETY's subject-consent object + its fail-closed
de-identification boundary + its disclosure chain into a shared willow-mcp
primitive**, so the Nest, corpus-lens, and the gate can all ask *"did this person
(or their guardian) agree?"* the same way they already ask *"may this app?"*

---

## Two kinds of consent (the orthogonal axes)

| | **Capability consent** (`consent.py`, exists) | **Subject consent** (this seam, new) |
|---|---|---|
| Question | *May the system do X?* | *Did this person agree to be in the data?* |
| Subject of the grant | the **system** (egress, cloud, LAN) | a **person** (their data, their inference) |
| Granted by | the **owner**, about their own machine | the **subject**, or a **guardian** on their behalf |
| Keyed on | a capability key (`internet`, …) | `(subject_id, scope)` |
| Absence resolves to | **denied** (`_DENY_ALL`) | **denied** (no record ⇒ not permitted) |
| Revocation | flip the switch | `status = revoked`, timestamped, never erased |
| Home | `settings.global.json` | a subject-consent store (below) |

They compose by **AND**, never substitute. A tool that egresses a non-owner
subject's data needs the capability key *and* the subject grant. Same shape as
the three-key egress gate: more keys, never fewer.

---

## The three roles the model must name

Today the stack knows two roles. The seam adds the missing two.

| Role | Who | Represented today by |
|---|---|---|
| **Owner** | the operator running the tool / holding the device | `identity_binding`, the human side of `gate` |
| **App / Agent** | the caller | `app_id` → `gate.permitted` |
| **Subject** | the person the data is *about* | **nothing** (unless subject == owner) |
| **Guardian** | a party empowered to consent *for* a subject who cannot | **nothing** |

`Owner`, `App`, and `Subject` are independent. The whole point of the seam is
that `Subject` is a first-class role, not an alias for `Owner`. `Guardian` exists
because some subjects (a young child) cannot consent for themselves, and someone
must be able to — verifiably, revocably, and on the record.

---

## The model

Generalized directly from UTETY's `learners` table and `set_consent`.

```
Subject
  id                opaque, local; never a name on the wire
  relation_to_owner  self | child | ward | household | other
  can_self_consent   bool     # false for a young child; policy deferred (see gaps)

Consent
  subject_id
  scope             what the grant covers — see scopes below
  status            pending | granted | revoked      # UTETY's exact lifecycle
  granted_by        who granted it (the guardian, or the subject themselves)
  at                timestamp of the transition
  prev_hash, hash   chained — the grant history is tamper-evident, like UTETY's
```

**Scopes** name *what a subject agreed to*, so a grant is never all-or-nothing:

- `local_only` — the subject's data may live on this device (the default a
  household drop-folder assumes for its members).
- `process_analysis` — process/structure derived from the subject's data may be
  computed (corpus-lens over a shared corpus; the Nest's counts).
- `kb_promotion` — de-identified structure about the subject may cross into the
  shared KB (`nest_promote`).
- `person_inference` — a person-shaped claim about the subject may be *made at
  all* (corpus-lens's quarantined `PERSON_CLAIM_TYPES`; the highest bar).

A grant is `(subject, scope, status=granted, granted_by, at)`. Anything not
granted is denied — **the same inversion `consent.py` already enforces.**

### Three mechanisms, all already prototyped in UTETY

1. **The consent gate** — `subject_consent.permitted(subject_id, scope) -> bool`,
   read-only and fail-closed, mirroring `consent.permitted`: absent record,
   unparseable store, `pending`, or `revoked` all resolve to `False`. Mutation
   lives in an admin/CLI path (like `consent_admin`), never a runtime MCP tool —
   an app can never grant consent on a subject's behalf.

2. **The de-identify-or-refuse boundary** — from UTETY's `knowledge.py`: the only
   thing that may cross a sharing boundary about a subject is a *de-identified*
   derivative, and the scrub is **verified or it raises** (`deidentify()` →
   `RuntimeError("de-identification failed to clean the query")`). This is the
   mechanical generalization of the Nest's structure-only bridge and corpus-lens's
   fail-closed egress scan: *content is person; structure is process* becomes
   *identified is person; de-identified is process*.

3. **The disclosure chain** — from UTETY's hash-chained `disclosure` table: a
   tamper-evident, per-subject log of what was done with their data ("what the
   tutor discussed with your child"), detecting both mid-chain edits and tail
   truncation via an anchored head. This generalizes corpus-lens's plain-language
   audit sentence and willow-mcp's `ReceiptLog` into a **subject-scoped** record a
   guardian can read. Revocation is a logged transition, never an erasure.

---

## Where it sits in willow-mcp

A new module `subject_consent.py`, shaped exactly like `consent.py`:

- **Read-only at runtime.** `permitted(subject_id, scope)` and a `disclosure`
  reader. Fail-closed on every path.
- **Mutation isolated** to an operator CLI, never an MCP tool — granting consent
  is an owner-side act, like minting a manifest. The operator-terminal primitives
  `subject_consent_binding.grant()` / `revoke()` (each gated by
  `require_operator_terminal()`) are exposed as `willow-mcp grant-consent
  <subject_id> <scope> --by <guardian>` and `willow-mcp revoke-consent …`;
  `willow-mcp consent-status <subject_id>` is the read-only counterpart (like
  `net-status` for `grant-net`).
- **Composes into `_gate`**, not around it. A tool declares (in its manifest or a
  small registry, like `tier_policy.TOOL_CLASS`) whether it *touches a subject*
  and at what scope. `_guarded` → `_gate` gains a third check after `permitted`
  and the tier ceiling: if the call carries a `subject_id` that is not the owner,
  `subject_consent.permitted(subject_id, required_scope)` must pass. Absent ⇒
  denied, receipted as `subject_consent_denied`.

> **Hard constraint — the core must be stdlib-only and egress-free.** UTETY's
> store imports *no* networking or FFI, enforced by `tests/test_boundaries.py`,
> because it runs on a child's device. If UTETY is to consume this shared
> primitive (it is the reference; it should not fork), the subject-consent *core*
> (`Subject`, `Consent`, the gate, the de-identify contract, the chain) must be
> importable with **zero willow-mcp runtime deps** — no `psycopg2`, no `mcp`. So
> the module is split: a stdlib-only `subject_consent/core.py` (which UTETY can
> vendor or depend on) and a thin willow-mcp binding that wires it into `_gate`
> and `ReceiptLog`. The primitive is homed here but must not drag the engine in
> behind it.

### The seam, layer by layer

| Layer | willow-mcp today | The seam adds |
|---|---|---|
| Identity | owner (`identity_binding`) + app (`app_id`) | **subject** + **guardian** as first-class roles |
| Authorization | `gate.permitted(app_id, tool)` ∩ tier ceiling | ∩ `subject_consent.permitted(subject_id, scope)` for subject-touching tools |
| Boundary | secret redaction in `_guarded`; the Nest's bridge | **de-identify-or-refuse** for any non-owner subject's data |
| Audit | `ReceiptLog` (per app_id) | **disclosure chain** (per subject) — the guardian's readable, tamper-evident record |
| Revocation | flip a capability switch | `status = revoked`, logged to the chain, honored fail-closed |

---

## How each consumer plugs in

- **corpus-lens** — the `person_inference` capability in `guard.py` gains a
  precondition: a `PERSON_CLAIM_TYPE` becomes representable only when a granted
  `Consent(subject, scope=person_inference)` exists *and* the owner token is
  present. corpus-lens stops being "owner == subject, full stop" and becomes
  "subject ≠ owner **iff** consented, and the audit sentence names the grant." The
  wall's honesty discipline is unchanged — it just gains a legitimate door.

- **The Nest** — a `person` fragment can carry an opaque `subject_id`.
  `nest_promote` refuses to cross any structure attributable to a non-owner
  subject without `scope=kb_promotion`; the walled digest's "people who show up"
  stays walled unless `scope=process_analysis` is granted. The **live router is
  owner == subject** (you sorting your own files) — exempt by default; a *shared
  household* drop folder is exactly the case that would require per-member grants.

- **UTETY** — already implements the whole model for a child learner. It becomes
  the **reference**: the shared core is extracted to match its `store.py`
  semantics (`pending|granted|revoked`, `granted_by`, the disclosure chain), and
  UTETY is later refactored to consume the shared core instead of its private
  copy — *only if* the stdlib-only/egress-free constraint above holds.

- **willow-mcp gate** — gains the subject axis beside the app axis. `may this app?`
  and `did this person agree?` are asked at the same choke point, both fail-closed.

---

## Failure modes (fail-closed, deliberately)

- **No consent record ⇒ denied.** Absence is not consent (the exact rule
  `consent.py` already enforces for capabilities). An unparseable store denies;
  it never falls back to a laxer source.
- **Revocation is immediate and permanent-on-the-record.** `revoked` denies from
  that moment; the transition is timestamped and chained. Erasing *when* consent
  was withdrawn would gut the audit trail (UTETY audit B2) — so revocation adds a
  row, never removes one.
- **De-identification is verified or it refuses.** A boundary crossing that cannot
  prove its scrub raises, exactly like `deidentify()`. The scan never emits the
  value it is checking.
- **The disclosure chain is tamper-evident both ways** — mid-chain edit (hash
  links break) and tail truncation (anchored head+count mismatch).

---

## What this deliberately does NOT solve (the honest edges)

This is the section the whole project's ethos demands. Guardian-consent is a
*real* answer to *one* shape of owner ≠ subject. It is not a universal one.

- **The no-one-can-consent case.** A subject who cannot consent and has no
  guardian empowered to — a deceased relative in a life-dump, an ex-partner who
  will not participate. The model **cannot conjure a grant that does not exist.**
  What it *can* do is make their *unconsented* status representable and enforce it
  fail-closed: their data stays `local_only` (owner-scope, never promoted, never
  person-inferred) or is excluded. The seam replaces *silent inclusion* with
  *explicit, enforced exclusion* — an honest improvement, not a resolution.
- **Guardian ≠ good actor.** A guardian can consent abusively (a parent
  surveilling a teen; corpus-lens's origin was a *custody schedule reconstructed
  from keystroke timing*). The model records **who** consented and makes
  revocation and disclosure available — it does **not** adjudicate whether the
  guardian *should* have. The disclosure chain is a mitigation (the act is on the
  record), not a safeguard against a bad guardian.
- **Capacity to self-consent.** When does a subject earn `can_self_consent`
  (a teen, a recovering adult)? The flag is carried; the *policy* (age thresholds,
  capacity judgments) is deferred. UTETY's age-gate is the domain-specific
  instance; a general answer is out of scope here.

Naming these is the point. The seam's job is to make the *representable* honest,
not to pretend the *unrepresentable* away.

---

## Open questions for Sean

1. **Subject identity.** Is `subject_id` a stable opaque handle the owner assigns
   (household roster) — or derived per-corpus (so the same person across two
   corpora is deliberately *not* linkable)? The privacy trade-off is real either
   way.
2. **Where the consent store lives physically.** Beside `consent.py` in
   `$WILLOW_HOME`, or on the subject's own device (UTETY-style, one file per
   person)? The latter is stronger but harder to reach from a fleet tool.
3. **Default relation for the Nest's household case.** When a shared drop folder
   contains a family member's file, is the default `local_only` (safest, requires
   an explicit grant to ever promote) — or is the router simply owner-only until a
   household roster is declared?
4. ~~**The stdlib-only split.** Confirm the core must stay import-clean so UTETY can
   consume it — or accept that UTETY keeps its own copy and only the *semantics*
   are shared (a spec, not a dependency).~~ **RESOLVED 2026-07-20 (operator): the
   vendor middle path.** The core stays import-clean AND is single-sourced — one
   canonical copy in `safe-app-store/libs/subject-consent`, vendored into each
   consumer with a provenance header (not a PyPI dependency, not three independent
   copies). No new repo; the Nest's `nest-seed` pattern. UTETY/corpus-lens vendor
   from the same canonical next.

*This is the map. The wall has always had two halves — "what may leave" (built
four times over) and "whose data is it, and did they agree" (built once, in a
classroom). This seam is where they meet.*

@phase constraints
## Constraints

@constraint severity="critical"
- `grant`/`revoke`/`permitted(store, subject_id, scope)` over a hash-chained,
  append-only consent log — fail-closed on every path that isn't a *verified*
  `granted` (absent store, broken chain, no record, `pending`, `revoked` → `False`).
- `deidentify(text, identifiers)` — de-identify-or-refuse; proves the scrub or
  raises **without ever echoing the surviving value**.
- `record_disclosure`/`read_disclosures` — the per-subject, tamper-evident record
  a guardian can read.
- Scopes are **independent permissions, not a ladder**
  (`local_only`, `process_analysis`, `kb_promotion`, `person_inference` — the
  last name matching corpus-lens's capability); each is granted and checked on
  its own.
- **Not in the core, on purpose:** owner==subject is *not* special-cased (the
  core doesn't know who the owner is); capacity/self-consent judgments are
  deferred; and mutation is a library primitive an operator CLI calls — an app
  can never grant consent on a subject's behalf. Enforcing all three is the
  binding's job.

@constraint severity="critical"
- **corpus-lens** draws a hard line at *owner == subject* and quarantines
  `PERSON_CLAIM_TYPES` behind a `person_inference` capability that the default
  registry may never grant. It named the guardian-consent model (owner ≠ subject)
  as its *"biggest unshipped gap"* and refused to ship it. There is no
  representable way to say *"this claim is about someone else, and here is their
  grant."*
- **The Nest** makes `person` fragments of whoever shows up in a life-dump — a
  co-parent, a child, an ex-partner. Today the wall keeps those out of the shared
  KB by making them *anonymous counts*. But there is no **consent object** for
  those non-owner subjects: the Nest can only ever wall them, never *admit* them
  with a grant.
- **willow-mcp**'s `consent.py` is **capability** consent — the owner flipping
  `internet` / `cloud_llm` / `lan` about their own system. It has the right
  fail-closed discipline (*"absence is not consent"*) but the wrong axis: it says
  nothing about whose data is in play.
- **UTETY** is the only piece that built the missing axis — because a classroom
  *forces* it. The learner is a child; the operator is a parent; COPPA gives no
  school-consent safe harbor (build-plan rule 4). So UTETY carries, in code, a
  consent record *granted by a guardian on a subject's behalf*.

@constraint severity="critical"
**Scopes** name *what a subject agreed to*, so a grant is never all-or-nothing:

- `local_only` — the subject's data may live on this device (the default a
  household drop-folder assumes for its members).
- `process_analysis` — process/structure derived from the subject's data may be
  computed (corpus-lens over a shared corpus; the Nest's counts).
- `kb_promotion` — de-identified structure about the subject may cross into the
  shared KB (`nest_promote`).
- `person_inference` — a person-shaped claim about the subject may be *made at
  all* (corpus-lens's quarantined `PERSON_CLAIM_TYPES`; the highest bar).

@constraint severity="critical"
- **Read-only at runtime.** `permitted(subject_id, scope)` and a `disclosure`
  reader. Fail-closed on every path.
- **Mutation isolated** to an operator CLI, never an MCP tool — granting consent
  is an owner-side act, like minting a manifest. The operator-terminal primitives
  `subject_consent_binding.grant()` / `revoke()` (each gated by
  `require_operator_terminal()`) are exposed as `willow-mcp grant-consent
  <subject_id> <scope> --by <guardian>` and `willow-mcp revoke-consent …`;
  `willow-mcp consent-status <subject_id>` is the read-only counterpart (like
  `net-status` for `grant-net`).
- **Composes into `_gate`**, not around it. A tool declares (in its manifest or a
  small registry, like `tier_policy.TOOL_CLASS`) whether it *touches a subject*
  and at what scope. `_guarded` → `_gate` gains a third check after `permitted`
  and the tier ceiling: if the call carries a `subject_id` that is not the owner,
  `subject_consent.permitted(subject_id, required_scope)` must pass. Absent ⇒
  denied, receipted as `subject_consent_denied`.

@constraint severity="critical"
- **No consent record ⇒ denied.** Absence is not consent (the exact rule
  `consent.py` already enforces for capabilities). An unparseable store denies;
  it never falls back to a laxer source.
- **Revocation is immediate and permanent-on-the-record.** `revoked` denies from
  that moment; the transition is timestamped and chained. Erasing *when* consent
  was withdrawn would gut the audit trail (UTETY audit B2) — so revocation adds a
  row, never removes one.
- **De-identification is verified or it refuses.** A boundary crossing that cannot
  prove its scrub raises, exactly like `deidentify()`. The scan never emits the
  value it is checking.
- **The disclosure chain is tamper-evident both ways** — mid-chain edit (hash
  links break) and tail truncation (anchored head+count mismatch).

@constraint severity="critical"
- **The no-one-can-consent case.** A subject who cannot consent and has no
  guardian empowered to — a deceased relative in a life-dump, an ex-partner who
  will not participate. The model **cannot conjure a grant that does not exist.**
  What it *can* do is make their *unconsented* status representable and enforce it
  fail-closed: their data stays `local_only` (owner-scope, never promoted, never
  person-inferred) or is excluded. The seam replaces *silent inclusion* with
  *explicit, enforced exclusion* — an honest improvement, not a resolution.
- **Guardian ≠ good actor.** A guardian can consent abusively (a parent
  surveilling a teen; corpus-lens's origin was a *custody schedule reconstructed
  from keystroke timing*). The model records **who** consented and makes
  revocation and disclosure available — it does **not** adjudicate whether the
  guardian *should* have. The disclosure chain is a mitigation (the act is on the
  record), not a safeguard against a bad guardian.
- **Capacity to self-consent.** When does a subject earn `can_self_consent`
  (a teen, a recovering adult)? The flag is carried; the *policy* (age thresholds,
  capacity judgments) is deferred. UTETY's age-gate is the domain-specific
  instance; a general answer is out of scope here.
