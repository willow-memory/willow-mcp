# Fleet versioning — what a version number promises

**Status:** settled, except the one question marked OPEN at the end.
**Scope:** the packages listed in `[tool.willow.fleet]` in this repo's
`pyproject.toml`, which is where the roster lives and where
`tests/test_fleet_versioning.py` reads it from. Not `jeles-remote` (a deployed
service, not a package) or `willow-gate` (unpublished).

The release *mechanics* are already uniform and tested — tag-derived versions
via hatch-vcs, `release-type: simple`, `include-component-in-tag: false`,
auto-merge armed on the release PR, changelog rebuilt from the commits. Three
`tests/test_release_wiring.py` files hold that in place.

What was never written down is what the resulting number **means**.

## The problem, and the fix that was wrong

*(Stated as it stood when this was found. Both producers have since flipped the
flag — see "Make the producer's range honest" below, which is the fix that
worked.)*

`willow-mcp/pyproject.toml` pinned `jeles>=0.5.0,<1.0.0`. jeles set
`bump-minor-pre-major: true`, whose effect its own config stated: *"while below
1.0: feat -> minor, fix -> patch, and a breaking change -> minor rather than
1.0.0."* So jeles was configured to ship breaking changes as minor bumps, and
willow-mcp was pinned to accept every minor jeles could produce. **A `<1.0.0`
cap on a pre-1.0 package is not a compatibility range.**

The first version of this document responded by tightening the cap to the next
minor — `jeles>=0.5.1,<0.6.0`. That was withdrawn under review, for four
reasons, in rising order of severity:

1. **It has never had anything to catch.** Across all three repos: zero commits
   with a `!:` type and zero `BREAKING CHANGE:` footers, in 99 jeles commits
   over 8 tags. Meanwhile jeles cut four minors in three days. The protection
   would have fired zero times and the cost four times — each cap bump itself
   requiring a willow-mcp release that auto-merges to PyPI.
2. **It does not catch the realistic break anyway.** release-please classifies
   from the commit *type*, not from behaviour: anything that is not `feat` and
   is not marked breaking falls through to a patch bump. A `refactor:` that
   breaks jeles ships as 0.5.2 and passes `<0.6.0` exactly as it passes
   `<1.0.0`. jeles' own config concedes this — *"a version number is what you
   point at when a refactor turns out to have broken something."* The tight cap
   only helps when the author correctly writes `feat!:`, which is precisely when
   they would have bumped the pin anyway.
3. **This fleet has already been burned by the same shape, from the other
   side.** jeles carries `dependencies = []` with the reason attached: *"pinning
   mcp here made `pip install willow-mcp jeles` unresolvable, because willow-mcp
   requires mcp>=2 while this package required mcp<2."* A narrow cap in
   willow-mcp re-creates that unresolvability for anyone installing willow-mcp
   beside another package that wants a newer jeles. Reproduced under review:
   `ResolutionImpossible`.
4. **It inverted a safety property, which is what settles it.**
   `willow_institutional_search` reaches the network through *jeles'* egress
   guard, not this repo's — the pyproject comment says so. A jeles 0.6.x SSRF
   fix reaches every willow-mcp user on their next upgrade under `<1.0.0`, and
   reaches nobody under `<0.6.0` until willow-mcp cuts a release. The floor was
   raised to 0.5.1 *for* a security fix; capping at `<0.6.0` in the same commit
   would have blocked the next one.

## Rule 1 — cap at the next major, and make the range mean something upstream

Every dependency, fleet or third party, is capped at the producer's next major.
Any other cap needs a comment at the pin saying why —
`cryptography>=42.0,<50.0` spans majors, `uvicorn>=0.29,<1.0` is pre-1.0 and
deliberately not capped at its next minor.

A cap is the right tool when you **cannot test the combination and cannot fix
the producer**. That describes a third party. It does not describe a fleet
package, where the same operator owns both repos and can ship a fix in an hour.
For those, the correct instruments are upstream and in CI, not in the range:

- **Make the producer's range honest — done.** The fix for "a minor may break"
  is not a tighter consumer cap but `bump-minor-pre-major: false` on the
  producer, which makes a breaking change cut 1.0.0 and makes `<1.0.0` a real
  compatibility range. Both jeles and kartikeya now set it false. Measured
  against release-please 17.11.1's `DefaultVersioningStrategy` rather than
  inferred:

  | | breaking | feat | fix / unlabelled |
  |---|---|---|---|
  | jeles 0.5.1 | **1.0.0** | 0.6.0 | 0.5.2 |
  | kartikeya 0.0.9 | **1.0.0** | 0.1.0 | 0.0.10 |
  | nestor-meaning 0.7.0 | **1.0.0** | 0.8.0 | 0.7.1 |

  The price is the property both configs previously prized: reaching 1.0 was a
  decision someone makes rather than one a commit message makes. You cannot
  have both, and across the fleet's whole history — zero breaking changes in 99
  jeles commits over 8 tags — the trigger is rare enough that "1.0 arrives when
  compatibility breaks" reads as a signal rather than a hazard. kartikeya goes
  0.0.9 → 1.0.0 on its first breaking change, which is the point.
- **Test the contract, not the number.** `tests/test_fleet_versioning.py`
  imports the really-installed `jeles` and asserts the surface willow-mcp
  actually uses. Every test in `test_institutional_search.py` monkeypatches
  `search_institutional`, so without this, jeles deleting it would not fail
  anything here.
- **Test against the newest producer in CI.** Detection belongs at CI time for
  the operator, not install time for the user. That option only exists because
  it is a fleet dependency — which is the reason the *loose* rule is right here
  and the tight one is not.

## Rule 2 — what forces a major is the surface each package actually exposes

A major bump is a promise about *callers*, so the surface has to mean the thing
callers hold — different for all three.

| package | the surface | not the surface |
|---|---|---|
| **willow-mcp** | the MCP tool contract — tool names, parameter names and meanings, documented return keys; the seven `[project.scripts]` console entry points; **and the fact that `willow_mcp` is importable and `python -m willow_mcp` runs** | the Python API — module layout, function signatures, anything under `willow_mcp.*` beyond the package importing |
| **jeles** | the importable Python API (`jeles.institutional`, `jeles.sources`, `jeles.corpus`, `jeles.willow_mcp_client`, the shared hit key set), `corpus_server`'s tool contract, **and the host-card schema** (`jeles/cards/*.json` — the `host`/`roles`/`publisher`/`custody`/`jurisdiction`/`status`/`notes` fields and the enum values `roles` and `custody` admit) | internals prefixed `_`, including `_egress`; the `observed` field the schema never shipped |
| **kartikeya** | the `kartikeya`/`kart` CLI and the task-queue schema on disk and in Postgres | the worker internals |
| **nestor-meaning** | the importable Python API (`nestor.answer`, `nestor.cascade`, `nestor.portable`, `nestor.entity.EntityResolver`, `nestor.sqlite_store.SqliteStore`), the `nestor` CLI | internals prefixed `_`; the dogfood store schema |
| **willows-grove** | the Grove MCP tool contract (`grove_reader`, `grove_agent_message`, `grove_mcp_token` — names, parameters, documented return keys), the `grove-serve` console entry point, and the **u2u wire format**: Ed25519-signed `knock`/`consent`/`note` on the LAN | the served page itself — DOM, CSS, Web Component tag names and the 127.0.0.1:8766 route shapes it fetches; reader internals |

willows-grove is the first roster member this repo does not depend on, and its
row is why the roster and the pin rules had to come apart: a released package
owes its callers a defined surface whether or not willow-mcp imports it. Its
surface is also the first that is not mostly Python. The u2u wire format is held
by *other nodes* — a peer that signed a `knock` under 0.9 has no way to learn
that 1.0 changed the envelope — so it belongs in the left column even though
nothing in this tree imports it. The served page is deliberately in the right:
it is loopback-only by design (`safe-app-manifest.json` records no public HTTP
surface), so its markup has no callers to break.

The importability clause in willow-mcp's row is not decoration. Two fleet
packages import it: `jeles/willow_mcp_client.py` probes `import willow_mcp` and
then runs `python -m willow_mcp`, and `kartikeya/sandbox.py` reads
`willow_mcp.__file__` and walks parents to find the repo root, feeding a
sandbox mount-policy decision. An earlier draft of this table said willow-mcp's
modules were free to move because *"nothing imports `willow_mcp.web_fetch` from
outside"* — true, and it does not support the conclusion. **willow-mcp is a
library to the rest of the fleet whatever it is to the outside world**, and the
dependency graph is a cycle: willow-mcp → jeles → willow-mcp.

**The host-card schema joined jeles' row on 2026-08-09, later than the day the
decision was made.** `Jeles/docs/design/host-cards.md` §6.1 (commit `6a08553`,
2026-08-04) decided the schema is part of jeles' public surface — *"a breaking
card change — removing a field, narrowing an enum, changing what a `role`
means — is a jeles major, on the same line as deleting a function"* — and
named this row as the follow-up, before any release shipped a card. jeles
0.7.0 (2026-08-05) then actually shipped `jeles/cards/*.json` — the 84-host
catalog — which is what turned the decision *binding*: jeles sets
`bump-minor-pre-major: false` (Rule 1), so a schema break now cuts 1.0.0
rather than being free to ship as a minor, the same way dropping `observed`
from the draft schema was free only because it happened pre-release (§6.2).
Tracked as a follow-up in #284's body and picked up here as #286. Verified
against both the source checkout and the installed package (jeles 0.7.2, the
version this repo's floor of `>=0.5.1` currently resolves to): `jeles/cards/`
ships all 84 `*.json` files as package data in the wheel, and `roles` /
`custody` are the enum fields host-cards.md §3.1/§3.2 name as consumer-visible
— the same two fields `web_search.py`'s `_card_axis_verdict()` already reads
(#288), pinned against the real installed catalog by
`tests/test_host_card_trust_policy.py`.

## Rule 3 — a patch is the fallback, and that is the remaining hole

- **patch** — everything that is not `feat` and not marked breaking. Not an
  enumeration of `fix`/`security`/`perf`: `refactor:`, `build:` and `deps:` land
  here too, and a refactor is the most likely source of an unlabelled break.
- **minor** — `feat:`.
- **major** — a breaking change, at every version. Below 1.0 that means 1.0.0;
  above it, the next major. A `Release-As:` footer short-circuits all of it, so
  "only a human decides" is true of intent and not of mechanism.

**What this does not promise.** All of it keys off the commit *type*, so the
guarantee holds exactly as far as the discipline of writing `feat!:` or a
`BREAKING CHANGE:` footer. A break mislabelled `refactor:` still ships as a
patch and clears every cap, tight or loose. That is why Rule 1 puts the real
instrument in a contract test rather than in a version range — the range
encodes what the author *said*, and the test checks what the code *does*.

Above 1.0 the pre-major flags are inert: release-please gates both on
`isPreMajor`, which is false from 1.0.0 on. They should be removed at that
point rather than left as decoration — willow-mcp already asserts their absence
in `test_this_package_is_past_1_0_so_no_pre_major_flags`, and both pre-1.0
repos assert the reverse with a note to delete them at 1.0.

## Rule 4 — deprecation must be visible to the client, and never fail-open

Removing a tool parameter looks like a tool-contract break, so by Rule 2 it
looks like a major. It mostly is not, and the reason is worth measuring rather
than assuming. Against the installed `mcp==2.0.0`:

```
{'query':'q','trusted_only':True}   -> ok          (parameter honoured)
{'query':'q','totally_made_up':1}   -> ok          (unknown arg SILENTLY DROPPED)
{'trusted_only':True}               -> ToolError: query Field required
```

**Unknown arguments are discarded without error.** Only a missing *required*
argument fails. So removing an optional parameter is not loud — a stale caller
gets a successful call either way. An earlier draft proposed an "accept and
ignore it for one minor, remove at the next major" lane on the assumption that
removal was the harsh option. It is not, and that lane is strictly worse: it
keeps the parameter in the published JSON schema, where a client still reads it
as available.

Prose in a docstring does not reach the client. Measured: a parameter documented
as deprecated in the docstring produces a byte-identical schema entry to a live
one. The machine-readable form costs one line and is the only version that
works:

```python
trusted_only: Annotated[bool, Field(default=False, deprecated=True,
    description="DEPRECATED and IGNORED since X.Y.0 — ...")] = False
```

**And for a safety parameter, accept-and-ignore is forbidden outright.**
`trusted_only` means "keep results whose hostname matches a hand-curated
institutional suffix list" — a caller passing it is asking to be *restricted*.
Silently ignoring it returns raw web results to a model that believes they were
filtered. This repo shipped that
exact bug and fixed it one release ago; `web_search.py` carries the note that
the handoffs were exempt from the filter, so `trusted_only=True` returned
`google.com`. A deprecation lane that re-creates it deliberately, for a whole
major cycle, is not a lane worth having.

So: an inert parameter may be removed in a minor, or marked
`deprecated=True` in the schema first. A **restricting** parameter is either
removed outright or made to return an explicit error when passed truthy — which
is the only way to get a loud failure out of this SDK.

## Rule 5 — tags, and the setting that fails silently

`vX.Y.Z`, no component prefix, created by release-please from the merged release
PR. `include-component-in-tag` must stay `false` in all three repos. With it
absent release-please defaults to `true` and both halves of the release break at
once, which is what happened on willow-mcp #256:

- the tag becomes `willow-mcp-v2.2.0`, which `release.yml`'s `v*` trigger does
  not match, so the tag is created and **nothing publishes, with no error**; and
- release-please loses track of the previous release, so the PR re-proposed
  roughly 60 already-shipped entries as new.

#256 was closed unmerged, with auto-merge already armed on it. Each repo's
`test_release_wiring.py` now checks the produced tag against its own workflow
trigger.

The version lives in exactly one place: the tag. `hatch-vcs` derives it; no
hardcoded version anywhere. (`willow_mcp.__version__` exists but reads
`importlib.metadata.version`, so it is derived, not a second copy.) willow-mcp
has one real second copy — `.claude-plugin/plugin.json` — updated by
release-please via `extra-files`, because a plugin manifest cannot read a git
tag at runtime. `git show v2.0.1:.claude-plugin/plugin.json` still reads
`2.0.0`, which is why that copy is wired rather than remembered.

## OPEN — when does jeles reach 1.0?

Now largely answered by mechanism rather than by decision: **when something
breaks compatibility.** With `bump-minor-pre-major: false` the automation cuts
1.0.0 on the first `feat!:` or `BREAKING CHANGE:` footer, and there is no longer
a version to "declare".

What remains open is whether to reach it *deliberately* first, with a
`Release-As: 1.0.0`. The argument for is that a 1.0 published on purpose can be
timed against a settled API; the argument against is that nothing currently
demands it — `<1.0.0` is a real compatibility range now, so willow-mcp's pin is
sound either way.

Task #9 (whether willow-mcp's `web_search.py` responsibilities move into jeles)
is the natural moment to revisit, though the blocker is weaker than it looks:
*adding* to jeles is a `feat:` and not breaking, so #9 only forces a major if it
removes or changes an existing signature.
