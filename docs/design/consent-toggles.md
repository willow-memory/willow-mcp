---
kind: doc
name: "consent-toggles-cloud-llm-and-lan"
description: "Plan for the two consent keys that persist, reconcile, and display but gate nothing — what cloud_llm and lan should actually chokepoint, why relabelling them failed, and the mirror-write and migration hazards enforcement creates."
---

@markdownai v1.0

# The two toggles that do nothing: `consent.cloud_llm` and `consent.lan`

Status: **open — plan only.** No production code in this change. The failing
test stubs that record the gap live in
[`tests/test_consent_toggles.py`](../../tests/test_consent_toggles.py).

## The shape of the problem

[`src/willow_mcp/consent.py`](../../src/willow_mcp/consent.py) is not the
problem. It is fail-closed on purpose, it refuses to fall back from a corrupt
canonical file to a laxer mirror, it reports disagreement instead of resolving
it, and it never writes the policy it is checked against. All of that holds.

The problem is arithmetic:

| key | in `CONSENT_KEYS` | read by `read_consent()` | mirrored | shown in the panel | **enforced** |
|---|---|---|---|---|---|
| `internet` | yes | yes | yes | yes | **yes** — 5 call sites |
| `cloud_llm` | yes | yes | yes | yes | **no** |
| `lan` | yes | yes | yes | yes | **no** |

`consent.py:62` declares three keys. `consent.py:186-191` (`permitted()`)
accepts all three. `consent.py:194-199` supplies exactly one helper,
`internet_permitted()`, and only that one has callers:

- [`server.py:1928`](../../src/willow_mcp/server.py) — `task_submit`, key 2 of the Kart egress gate
- [`egress_authorization.py:390`](../../src/willow_mcp/egress_authorization.py) — `ExecutorNetworkAuthorizer`, re-check at shell launch
- [`integrations.py:407`](../../src/willow_mcp/integrations.py) — `egress_denial()` for `integration_call`
- [`web_egress.py:20`](../../src/willow_mcp/web_egress.py) — `egress_denial()` for `willow_web_search` / `willow_web_fetch`
- [`mai/parser.py:240`](../../src/willow_mcp/mai/parser.py) — the `@http` directive

Grepping the whole tree for `permitted("cloud_llm")`, `permitted("lan")`,
`cloud_llm_permitted`, or `lan_permitted` returns nothing outside tests.
**Verified: the brief is correct. Neither key is read by any gated path.**

### Relabelling was tried, and is why this is still open

[`gates_panel.py:159-163`](../../src/willow_mcp/gates_panel.py) carries the
admission and the fix that was attempted:

```python
# B11: cloud_llm / lan are modeled and reconciled but NOT read by any gated
# path (only consent.internet is enforced). Label them as reserved so the
# panel stops implying a protection that toggling them does not provide.
"consent.cloud_llm": "Cloud AI access (reserved — not yet enforced)",
"consent.lan": "Local network access (reserved — not yet enforced)",
```

That string lives in one dictionary in one UI. Everything else still presents
two live switches:

- `gates_panel.py:236-252` still emits `consent.cloud_llm` / `consent.lan` rows
  with `state="ALLOWED"`/`"BLOCKED"` (`_STATE_LABELS` at `:207`) — the *state*
  reads as enforcement even when the *label* says reserved.
- [`server.py:3459-3465`](../../src/willow_mcp/server.py) (`_diag_consent`)
  returns `read_consent()` verbatim into `diagnostic_summary`. Three booleans,
  no reserved marker, consumed by agents and by Grove.
- [`home_init.py:56-61`](../../src/willow_mcp/home_init.py) writes all three
  keys into `settings.global.json` on every new install.
- [`consent_admin.py:91-96`](../../src/willow_mcp/consent_admin.py) *requires*
  exactly all three keys and refuses a write that omits one — the writer treats
  the inert keys as mandatory policy.
- [`README.md:154`](../../README.md) ships the example
  `{ "consent": { "internet": false, "cloud_llm": true, "lan": false } }` —
  an operator who copy-pasted the README has "cloud AI" **on**.
- [`skills/consent.md:44-48`](../../skills/consent.md) and its bundled twin
  `src/willow_mcp/bundle/skills/consent.md:46-47` present all three under the
  heading "Fleet-wide off switch".

And an operator who edits `settings.global.json` in `$EDITOR` — the documented
path, per the panel's own `action_note` at `gates_panel.py:249-251` — never
sees a UI label at all.

A relabel in one renderer does not remove a key from the model, the writer, the
mirror, the diagnostic surface, the README, or the skill. That is why the
recommendations below are ENFORCE and not "label it harder".

---

## `cloud_llm` — what could send data to a cloud LLM?

Every candidate the brief named, checked:

| candidate | file:line | finding |
|---|---|---|
| Kart task sandbox | `server.py:1855-1958`; `kartikeya/sandbox.py:390-401` | Runs arbitrary shell. With `allow_net` a task can `curl` any API, including a model API. Not a *cloud-LLM* chokepoint: a shell's destination is undecidable without content inspection, and this egress already needs `task_net` + `consent.internet` + a live lease + a signed one-use envelope. |
| `web_search` | `web_search.py:22` (DuckDuckGo HTML scrape), `:312-329` (`BraveSearchProvider`, `_IMPLEMENTED = False`) | No model provider. Search, not inference. Gated by `web_egress.egress_denial` → `consent.internet`. |
| `integrations` adapters | `integrations.py:225-296` (live), `:300-364` (stubs) | github, huggingface, jeles, utety live; gmail/slack/notion/drive/datadog/jira are declared stubs that refuse. **No model-provider adapter exists.** `HuggingFaceAdapter` (`:235-241`) is `https://huggingface.co` — the Hub metadata API for models/datasets/files. It is *not* an inference host (`api-inference.huggingface.co` / `router.huggingface.co`), and `base_url` is fixed per the adapter contract so a caller-supplied path cannot re-point the host (`_PATH_RE`, `integrations.py:68`). |
| `mai/parser.py` `@http` | `parser.py:231-260` | Arbitrary URL fetch. Already gated on `consent.internet` at `:240`. Could reach a model API — same undecidability as the shell. |
| anything invoking an external model | grep across `src/`, `pyproject.toml`, `scripts/`, `tools/`, `hooks/`, `deploy/` for `anthropic\|openai\|gemini\|bedrock\|mistral\|cohere\|groq\|replicate\|claude-\|gpt-` | **Zero hits**, other than `secret_scan.py:48-53` and `nest/secrets.py:22-24`, which are regexes that *detect* provider API keys in scanned content. No SDK, no dependency, no base_url, anywhere. |

### The finding

**willow-mcp calls no cloud LLM provider. There is no Anthropic, OpenAI,
Gemini, Bedrock, or hosted-inference client in this repository.**

That is half the answer, and taken alone it points at DELETE. The other half
changes the conclusion:

**willow-mcp does make model-inference calls — three of them — to a host named
by an environment variable, and none of those calls consult any consent key.**

| call site | destination | reachable from |
|---|---|---|
| `nest/embed.py:67-72` (`_post` → `{OLLAMA_HOST}/api/embeddings`) | `nest/embed.py:22`: `os.environ.get("OLLAMA_HOST", "http://localhost:11434")` | `nest_scan` MCP tool, **`use_embed=True` by default** (`server.py:1442`) |
| `nest/llm.py:63-71` (`_http_json` → `{OLLAMA_HOST}/api/chat`) | `nest/llm.py:26`, same env var | `nest_scan(use_llm=True)` (`server.py:1441`) |
| `voice/kokoro_speak.py:118` (POST reply text for TTS) | `voice/kokoro_speak.py:24`: `WILLOW_KOKORO_URL`, default `http://localhost:5000/v1/audio/speech`; overridable at `voice_service.py:33` and `server.py:5735` | the voice daemon |

What travels on the nest path is not metadata. `nest/classify.py:286` embeds
the document body; `nest/llm.py:153` sends the first 6000 characters of file
text; `nest/llm.py:188` base64-encodes whole images. And
[`nest/bridge.py:85`](../../src/willow_mcp/nest/bridge.py) describes the Nest DB
as "the local-only PII zone" holding "a person's legal name, DOB".

Four places assert the property that `consent.cloud_llm` names, and none of
them check it:

- `server.py:1452` — `nest_scan` docstring: *"Nothing leaves the machine; no cloud inference."*
- `nest/llm.py:4` — *"Pure stdlib (urllib + json + base64). No third-party client, no cloud."*
- `docs/NEST.md:41` — *"No cloud inference; nothing leaves the machine."*
- `docs/BUGS.md:344` — *"willow-mcp makes no cloud-LLM calls."*

All four are true of the *default* value of an environment variable and false of
the variable. `export OLLAMA_HOST=https://ollama.example.net` and every one of
them becomes a lie, silently, with no error, no log line, and no gate. The
model that gets the bytes does not have to be Anthropic's for the property the
operator cares about — *"a model off this machine saw my documents"* — to be
violated.

`exposure.py:59` and `:66` already register `cloud_llm` as an exposure
*destination* with a `voice_only` preset, and `server.py:2855` documents it in
the tool surface. The membrane is built for a cloud LLM. Only the sender is
missing.

### Recommendation: **ENFORCE**

Define the key as **"may model inference leave this host?"** — not "is the
destination a brand-name provider", which is unanswerable and would rot the
moment someone self-hosts.

> ## CORRECTION, 2026-07-28 — the chokepoints below cannot carry the gate
>
> Items 1 and 2 name `nest/embed.py:67` and `nest/llm.py:63`. Those are the right
> answer to *where does egress happen* and the wrong answer to *where does the
> check go*.
>
> Both modules were **vendored byte-for-byte** from `safe-app-store`'s
> `libs/nest-pipeline` (box audit A4) under a hash pin and a CI `vendor-sync`
> job when this was written. Since 2026-09-12 their home is this repo
> (safe-app-store is archived and is never an origin again — owner decision;
> see `nest/__init__.py`). The rule that matters survives the move: the library
> is deliberately policy-free — *"Apps that consume it keep their own
> app-specific layers outside this core."* — so a consent check belongs to the
> layer that decides to invoke the pipeline, not inside it.
>
> **The gate therefore sits at willow-mcp's own tool boundary** —
> `model_egress.denial()`, called from `nest_scan` before it imports the
> pipeline. That is also where the false promise was written (`nest_scan`'s
> docstring: *"Nothing leaves the machine; no cloud inference"*), so the check
> and the claim now live on the same lines.
>
> This is a narrower change than planned and it keeps the drift-guard green. It
> is also strictly better placed for a second reason the plan did not anticipate:
> the vendored copy is destined to be *replaced* by the shared library, so a gate
> inside it would have been written into the code slated for deletion.
>
> Consequence for item 2's `/api/tags` note: gating at the tool boundary covers
> the probe automatically, because `nest_scan` returns the denial before any
> `nest` module is imported. The probe is only reachable through tools that are
> themselves gated.

Chokepoints, in order of preference:

1. **`src/willow_mcp/nest/embed.py:67`** — `_post()`, the single funnel for
   every embedding request. Both `embed_document` (`:91`) and `embed_query`
   (`:96`) route through `_embed` → `_post`.
2. **`src/willow_mcp/nest/llm.py:63`** — `_http_json()`, the single funnel for
   `classify_text` (`:141`) and `describe_image` (`:182`). Note
   `installed_models()` at `nest/llm.py:80` and `nest/embed.py:40` opens its own
   socket to `/api/tags` outside those funnels; the guard must cover it or the
   availability probe leaks the host's existence to the same destination.
3. **`src/willow_mcp/voice/kokoro_speak.py:118`** — the debatable one. Kokoro is
   TTS, not an LLM, but the payload is the assistant's reply text and the
   destination is the same shape of env var. Recommendation: gate it under the
   same rule and say so in the key's documentation, because an operator reading
   "Cloud AI access" will assume it covers "the thing that says my words out
   loud". If the human implementing this disagrees, the honest alternative is a
   fourth key, not silence.

The check itself should be one helper, not three ad-hoc conditions, so that
adding a fourth model sink is a one-line change rather than a new gap:

```
consent.cloud_llm_permitted()      # mirrors internet_permitted() at consent.py:194
```

plus a destination classifier so the guard is *proportionate*:

- destination is loopback (`127.0.0.0/8`, `::1`, `localhost`) → **no key
  required.** The bytes never leave the host; this is the default configuration
  and it must keep working untouched, or enforcement breaks every install for
  no security gain.
- destination is private / link-local / CGNAT / ULA → require `consent.lan`
  (see below).
- destination is public → require `consent.internet` **and**
  `consent.cloud_llm`.

That keeps the keys orthogonal: `internet`/`lan` answer *how far may bytes
travel*, `cloud_llm` answers *may a model off this box see them*. `cloud_llm` is
consulted only on model-inference paths — never on `web_fetch`, `integrations`,
`@http`, or Kart, where it would be an unenforceable claim about payload intent.

Deny messages must name the resolved host and the env var that set it. An
operator whose `cloud_llm: false` starts denying needs to learn *why* in one
line, and the answer is always "because `OLLAMA_HOST` points at X".

### Why not DELETE

DELETE is the right answer to "a key that names nothing". This key names
something: three live sockets and four written claims. Deleting it removes the
switch and leaves the claims — `nest_scan` would still promise "no cloud
inference" with nothing checking it, and the exposure membrane would still hold
a `cloud_llm` destination with no key behind it. That is the same failure mode
one layer deeper.

---

## `lan` — what is a "LAN access" in this codebase?

Is there local-network egress distinct from `internet`? **Yes — three places,
and it is precisely the destination class that the internet-facing guards
deliberately block or mislabel.**

| surface | file:line | today |
|---|---|---|
| Kart `# allow_localhost` | `server.py:1861`, `:1915-1934`; `egress_authorization.py:57-58`, `:70-78`, `:384-393` | `network_requested = allow_net or allow_localhost` (`server.py:1917`), then `consent.internet_permitted()` (`:1928`). The executor re-checks the same key (`egress_authorization.py:390`). |
| `$OLLAMA_HOST` | `nest/embed.py:22`, `nest/llm.py:26` | ungated |
| `$WILLOW_KOKORO_URL` | `voice/kokoro_speak.py:24` | ungated |
| `@http` private-range block | `mai/parser.py:133-146` | blocks by **hostname regex** |
| `willow_web_fetch` private block | `web_fetch.py:128-172` (`_is_blocked_host`), `:175-208` (`validate_fetch_url`), `:215-248` (`_get_checking_every_hop`) | **resolves** the name, then blocks by address — re-checked on every redirect hop |
| `gates --serve` bind host | `gates_serve.py:166-175` | ingress, not egress — out of scope for an egress key |

### `# allow_localhost` does not mean localhost

The name promises loopback. The implementation, in
`kartikeya/sandbox.py:390-401`, is the *absence* of `--unshare-net`:

```python
# Isolated: --unshare-net blocks all sockets (including 127.0.0.1:11434 Ollama).
# allow_localhost shares the host net ns so loopback services work, but does NOT
# mount credentials (GAP-B) — unlike allow_net.
if not allow_net and not allow_localhost:
    args.append("--unshare-net")
```

Sharing the host network namespace is not a loopback restriction; there is no
firewall, no netns filter, nothing narrowing the reachable set.
`network_mode = "localhost"` at `kartikeya/sandbox.py:747` is a **string in a
manifest dict**, not an enforcement. kartikeya's own docstring
(`sandbox.py:561-565`) says so plainly: *"it can still reach every service
listening on the host namespace and therefore requires the same attributable
per-task authorization as `allow_net`."* The only real difference from
`allow_net` is that credential env vars are not mounted (`sandbox.py:627`).

So `# allow_localhost` today grants LAN **and** internet reachability under a
name that says neither. It is gated by `consent.internet` — which is not wrong
(it does reach the internet) but leaves `consent.lan` with nothing to do while
the key it *should* own is the one the operator would reach for.

### One private-range guard is name-based; the other stopped being

`mai/parser.py:133-137`:

```python
_BLOCKED_HTTP_HOST_RE = re.compile(
    r"^(localhost|0\.0\.0\.0|127\.|10\.|169\.254\.|192\.168\.|"
    r"172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?|metadata\b)", re.I)
```

Matched against `urlparse(url).hostname` — a *string*, before any resolution.
Gaps: `100.64.0.0/10` (CGNAT, i.e. Tailscale) is absent; IPv6 ULA `fc00::/7` is
absent; `.local` mDNS is absent; and any DNS name that resolves into the LAN
(`nas.home`, `printer`, a split-horizon record) is not matched at all. A LAN
destination therefore reaches the network through the *internet* gate.

`web_fetch.py` **used to be** the same shape and no longer is. Its guard was
rewritten after an audit of jeles' sibling and now resolves before deciding:
`_is_blocked_host` (`:128-172`) calls `getaddrinfo` on a name and tests every
returned address, so a public record pointing at `127.0.0.1` is refused rather
than followed. Three further gaps went with it — percent-escaped hostnames are
decoded and checked in both views (`_dialled_hosts`, `:89-102`), the
octal/decimal/short forms every resolver accepts are normalised through
`inet_aton` (`_as_address`, `:69-86`), and `not addr.is_global` is ORed onto the
explicit list so `100.64.0.0/10` and the NAT64 prefix are covered. Redirects,
which previously bypassed the check entirely because `requests` followed the
chain internally, are now walked by hand with `validate_fetch_url` applied to
each hop (`_get_checking_every_hop`, `:215-248`). Behind a proxy it deliberately
does *not* resolve (`_proxy_dials_for`, `:105-125`): the proxy is the TCP peer,
so resolving locally would refuse legitimate split-horizon hosts for a reason
that is not true — literal addresses are still refused on that path.

Two residuals, stated rather than papered over: resolve-then-connect is two
lookups, so a name that answers public and then private wins a race; and behind
a proxy the destination ACL is the proxy's to enforce. Both are documented at
`validate_fetch_url`'s docstring rather than left implied.

So the LAN-blocking claim below applies to `mai/parser.py` alone.

Neither of these is a `consent.lan` bug — both tools are meant to be open-web
only, and blocking the LAN is correct for them. They are listed because they
show that the codebase already has a concept of "the LAN is a different place",
implemented three times, inconsistently, with no key behind it.

> **Superseded as a description of the code (2026-08-04).** The two guards this
> section quotes no longer exist as written. `web_fetch.py` now resolves names
> before judging them and checks every redirect hop, and `mai/parser.py` has no
> host guard of its own at all — the regex above was deleted and `@http` calls
> `web_fetch.fetch_guarded`, as does `web_search`. The count in the paragraph
> above is the part that aged best: "implemented three times, inconsistently"
> was the defect, and it is now implemented once. The observation this section
> was making — that a destination class is being governed by ad-hoc code rather
> than by a key — still stands, and the recommendation below is untouched.

### Recommendation: **ENFORCE**

`lan` names a real destination class that three live code paths reach and that
no key currently governs. The chokepoints:

1. **`src/willow_mcp/server.py:1917`** — split `network_requested`.
   `allow_net` → `consent.internet`. `allow_localhost` → `consent.lan`
   **and** `consent.internet`, because until kartikeya can actually restrict the
   shared netns to loopback, `# allow_localhost` reaches the public internet
   too. Requiring both is strictly more restrictive than today and is the honest
   encoding of what the sandbox actually does. File the loopback-restriction gap
   against kartikeya; do not encode its name as if it were its behaviour.
2. **`src/willow_mcp/egress_authorization.py:390`** — the executor must apply
   the identical split, keyed on the directive in the signed task text
   (`_NET_DIRECTIVES`, `:58`). Submit-time and execution-time disagreeing about
   which key applies is the exact class of bug B-29 closed for `internet`; it
   must not be reintroduced for `lan`.
3. **`nest/embed.py:67`, `nest/llm.py:63`, `voice/kokoro_speak.py:118`** — the
   same destination classifier as `cloud_llm`. A private/link-local/CGNAT/ULA
   model host requires `consent.lan`; a public one requires `consent.internet` +
   `consent.cloud_llm`.

Same as above, one helper:

```
consent.lan_permitted()
```

### Why not DELETE or KEEP-AS-DECLARED

DELETE loses the only name the codebase has for a class of destination it
already treats specially in four places. KEEP-AS-DECLARED is what
`gates_panel.py:159-163` did; the key is still in `CONSENT_KEYS`, still written
by `home_init.py:59-60`, still *required* by `consent_admin.write_consent`
(`consent_admin.py:93-96`), still returned by `diagnostic_summary`, and still
documented as an off switch in the README and the skill. A declared-only key is
honest only if every surface that can write or display it says so, and there is
no mechanism here that makes that true and keeps it true.

---

## The precedence and mirror problem

`consent.json` is a **write-only mirror**, as `consent.py:35-49` already
explains: willow-2.0's `save_global_settings(..., sync_legacy=True)` rewrites it
from the canonical block on every save, and Grove's settings pane mirrors it on
every consent toggle. willow-mcp reads it only when the canonical file is absent
entirely (`consent.py:153-160`) and otherwise merely reports disagreement
(`:172-180`).

Enforcing `cloud_llm` and `lan` turns that mirror from a reporting curiosity
into a write path from another repository into a security decision. Three
distinct hazards, in increasing order of severity:

**1. The legacy-fallback branch becomes a granting path.** When the canonical
file is absent, `consent.py:157-160` adopts the mirror wholesale. Today the most
that branch can grant is `internet`, which still needs a manifest capability, a
live lease, and a signed per-task envelope before anything egresses — four keys,
one of which the mirror supplies. On the nest path there is **no second key**:
one file, one boolean, and document text leaves for a model. Enforcement must
not land on that asymmetry.

*Recommendation:* treat `cloud_llm` and `lan` as **canonical-only**. Read the
mirror's values, report them in `disagreement` exactly as now, and never let
them *grant* — absent canonical means denied for the new keys, not "consult the
mirror". This narrows the mirror's authority rather than extending it, which is
the direction of travel `consent.py:31-33` already argues for. It is a two-line
change in `_read`'s consumers and it should land in the same commit as the
enforcement, not after.

**2. The fail-open writer materializes `true` into the file the fail-closed
reader trusts.** `consent.py:21-27` documents that willow-2.0's
`DEFAULT_CONSENT` is all-`True` and that `_normalize_consent()` returns those
defaults for any non-dict. Reading fail-closed protects willow-mcp from a
*malformed* block. It does not protect willow-mcp from a writer that reads a
malformed block, substitutes all-`True`, and **saves**. After that save the
canonical file contains a genuine, well-formed `"cloud_llm": true`, and
`_strict_bools` (`consent.py:91-100`) is right to honour it. The mirror check
cannot catch this either: `save_global_settings(sync_legacy=True)` writes both
files from the same substituted block, so canonical and mirror **agree**, and
`disagreement` stays `None`. A fail-closed reader cannot rescue you from a
fail-open writer. This is the hazard that most needs stating before enforcement
lands, because it is the one the module's existing defences do not cover.

**3. There is an existing invariant that would catch it, and it is not
checked.** `consent_admin.write_consent` (`consent_admin.py:91-142`) is
willow-mcp's *only* writer, and it appends an `intent` line and a `committed`
line to `$WILLOW_HOME/config/audit/consent.jsonl` around every change, with
`before_hash`/`after_hash` over the consent dict (`:112-142`). So: **a canonical
`cloud_llm: true` whose `after_hash` appears nowhere in the audit log was
written by something other than willow-mcp.** That is a checkable property.

*Recommendation:* `_diag_consent` (`server.py:3459-3465`) should raise an
`error`-severity problem when an *enforced* key is `true` and no audit line
records a transition to that state — same treatment `disagreement` already gets.
It does not block anything (willow-mcp must not adjudicate whose write is
legitimate — `consent.py:47-49`), but it surfaces "this permission arrived from
outside" instead of silently honouring it. Keep the module's rule: surface,
never resolve.

---

## Migration

### The operator who set `cloud_llm: false` and believes it is protecting them

It is not, and the shape of the non-protection depends on one environment
variable they have probably never looked at.

- On a **default install**, `OLLAMA_HOST` is unset, so it resolves to
  `http://localhost:11434` and nothing left the machine. Their belief was
  accidentally true — true because of a default, not because of their switch.
  Nothing they did caused it and nothing warns them if it stops being true.
- On an install that **exported `OLLAMA_HOST`** to any off-box address — a
  workstation pointing at the GPU box in the next room, a docker-compose
  `OLLAMA_HOST=http://ollama:11434`, a hosted endpoint — their belief has been
  false for as long as that variable has been set. `nest_scan` with default
  arguments (`use_embed=True`, `server.py:1442`) shipped every scanned
  document's text to that host. `use_llm=True` shipped 6000 characters per file
  and whole images.

**What to do today, before any enforcement lands:** check the *server process's*
environment, not the shell's — `OLLAMA_HOST` and `WILLOW_KOKORO_URL`. If either
resolves to anything but loopback, `consent.cloud_llm: false` never applied to
it, and any `nest_scan` run since it was set should be treated as having
disclosed its input to that host.

**When enforcement lands:**

- Loopback installs: **no change.** The carve-out exists so that the common,
  correct configuration is not broken by a security fix that gains it nothing.
- Non-loopback installs with `cloud_llm: false`: model calls begin to **deny**,
  with an error naming the host and the variable. This is the switch finally
  working, and it is still a behaviour change for a running deployment. It
  belongs in `CHANGELOG.md` under a breaking-change heading, not as a bugfix
  line.
- `README.md:154` ships `"cloud_llm": true`. Every operator who copy-pasted that
  block has the key **on** and will get no new protection. That line must change
  in the same PR as the enforcement, and the release note must say "check your
  `settings.global.json`" rather than assuming defaults.

### The operator who has `lan: false` — which is everyone

`home_init.py:56-61` writes `{"internet": false, "cloud_llm": false, "lan": false}`
into every new install. Enforcing `lan` on `# allow_localhost` therefore denies
a mode that works today on **every** deployment that has not hand-edited the
file. That is a much wider blast radius than the `cloud_llm` change and it is not
softened by a loopback carve-out, because `# allow_localhost` *is* the
non-loopback case.

Options, in preference order:

1. Ship the enforcement with a release note and let it deny. Fail-closed is the
   module's whole thesis; an operator who wants localhost tasks flips one
   boolean they already have in their file. Loudest, shortest-lived pain.
2. Ship `lan` enforcement one release behind `cloud_llm`, with a deprecation
   window in which a denial-shaped **warning** is emitted by
   `diagnostic_summary` and the panel — so operators discover the coming change
   from their own tooling rather than from a broken task.

Do **not** default `lan` to `true` for existing installs to smooth the
migration. A consent key that defaults to granted is willow-2.0's
`DEFAULT_CONSENT`, which `consent.py:21-27` exists to reject.

### Existing tests

`tests/test_server.py:779-783` (`_operator_consents`) already writes
`cloud_llm: True, lan: True` for every net test, including
`test_task_submit_allow_localhost_requires_and_binds_signed_authority`
(`:858-882`). The `lan` enforcement will not break them. That is a fixture
accident, not coverage — new tests must state the key under test explicitly
rather than inherit an all-permissive fixture, which is exactly the false-green
shape `docs/BUGS.md:329-336` records for `WILLOW_HOME`.

---

## The general antidote

Both keys got here the same way: a key was added to `CONSENT_KEYS` and no reader
was added with it. Nothing in the code notices. The narrow fix is two helpers;
the durable fix is an invariant:

> **Every key in `CONSENT_KEYS` has a named enforcing helper in `consent.py`.**

`tests/test_consent_toggles.py::test_every_consent_key_has_an_enforcing_helper`
records it. Once enforcement lands, adding a fourth key without a reader fails
the suite instead of shipping a fourth switch that does nothing.
