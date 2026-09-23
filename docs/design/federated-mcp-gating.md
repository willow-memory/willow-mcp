---
kind: doc
name: federated-mcp-gating
description: "How willow-mcp gates a call it makes to a tool on a downstream MCP server. Decided before the client exists, so the gate is not retrofitted into code that assumes it away."
---

@markdownai v1.0

# Gating a federated MCP call

*Status: **LANDED** (client + gate shipped). Decision 3 addendum (2026-09-23):
loopback stdio federation exempt from grant-net for classified local tools.*

*Companion: `permissions-matrix.md` · `egress-request-seam.md` ·
`trust-architecture.md` · `gate.py` · `web_egress.py` · `lease.py`*

@define-concept downstream server: Another MCP server that willow-mcp calls as a
*client*. Almost always a stdio subprocess willow-mcp spawns itself; possibly an
HTTP endpoint. Not a peer node — see §0.

@define-concept federated call: One `tools/call` willow-mcp issues to a
downstream server on behalf of a caller who reached willow-mcp through its own
gate. Two hops, two callers, one uid.

---

## 0. What this is not

There is already a `federation-wire-format.md` in this directory, and it uses the
same word for a different thing. Keeping them apart is the first decision,
because conflating them would import the wrong threat model.

| | `federation-wire-format.md` | this doc |
|---|---|---|
| Axis | node ↔ node | willow-mcp → downstream MCP server |
| Parties | two independently operated stacks, two operators | one host, one operator, one uid |
| Trust | signed grants; *a directive never grants anything* | no wire, no signatures; the subprocess is spawned **by us** |
| Failure | a peer asks for more than its grant | **we** hand a child our whole environment |

The wire-format doc's prime invariant — authority is only ever issued by a node's
own operator — is about refusing what a *stranger* claims. Here there is no
stranger: willow-mcp forks the downstream server, at its own uid, with whatever
environment it chooses to pass. The risk is not that the child lies about its
authority. **It is that we grant it ours by accident.** Different problem, so:
different keys, different doc.

Where they meet is §7.

---

@phase 1-what-exists
## 1. What willow-mcp actually has today

Read off the tree at `934cd60`, not from memory. Everything below is a fact this
design builds on, with the file that holds it.

| Fact | Where |
|---|---|
| `gate.permitted(app_id, tool)` is a **name lookup** — literal tool names, expanded through 43 groups | `gate.py:53`, `gate.py:566` |
| `deny_tools` is an overlay that wins over allows | `permissions-matrix.md` §1 |
| Four capability flags — `task_net`, `task_db`, `integration_net`, `web_net` — each granted on its own manifest line | `gate.py:354–369` |
| **None of the four is a member of any permission group**, `full_access` included | verified; now pinned by a test, §8 |
| `web_egress.egress_denial(app_id)` is four checks in order: permission, `consent.internet`, unexpired lease, `strict_trust_root` | `web_egress.py` (45 lines, whole file) |
| Leases are app-keyed, tz-aware, and capped at `MAX_TTL_SECONDS = 3h` | `lease.py:78` |
| Consent has exactly two live keys: `internet`, `cloud_llm` | `consent.py:62` |
| `external_guard.scan` / `verdict` / `SANDWICH_TEMPLATE` exist and are applied to fetched web text | `external_guard.py`, `web_fetch.py:478–491` |
| `registry.compile_manifests()` **merges** rather than clobbers and reports every override in `overridden` | `registry.py:86` |
| **willow-mcp has no MCP client at all.** It is a server that has never been a client. | — |

That last row is why this doc exists now rather than after. There is nothing to
retrofit yet, and a gate designed against code that already assumes it away is
the more expensive of the two orders.

Two stated commitments in the tree constrain everything below, and both are
load-bearing rather than decorative:

> *"egress is granted on its own line"* — `web_egress.py`, in the denial text the
> operator actually reads.

> *"One lease, sixty connections — the grant should not look cheaper than it
> is."* — the `web_read` comment.

---

@phase 2-decisions
## 2. Decision 1 — gate per downstream tool, never per call

**Rejected:** a single `mcp_call(server, tool, args)` tool gated as one name.

One grant would cover every tool on every downstream server *forever* — including
tools added to a server after the grant was written, by someone who is not the
operator. That is "one lease, sixty connections" with no ceiling at all, and it
inverts the commitment quoted above: the grant would look dramatically cheaper
than it is.

**Decided:** permission names gain a namespace.

```
mcp:<server_id>:<tool>
```

`gate.permitted` does not change — it stays a name lookup, which is the property
that makes it auditable. The names simply get longer. `server_id` is a stable
digest of the server's launch identity (command, args, and the resolved path of
the binary), not its human label, so renaming a server in a config file does not
silently carry its grants over.

Compile these into the existing manifest store via `registry.compile_manifests()`
rather than inventing a second ACL. That function already merges instead of
clobbering and already reports overrides in `overridden` — both properties this
needs, and neither is worth reimplementing next door where the two can drift.

## 3. Decision 2 — the intersection of two ceilings

A federated call is authorized **only** where the caller's manifest grant and an
operator-ratified per-server ceiling agree.

Neither alone is sufficient, and each fails in its own direction:

- **Caller's grant alone** — a `full_access` holder gains unbounded new surface
  the instant a server appears on disk. Authority would arrive by filesystem
  side effect.
- **Downstream's advertised tools alone** — willow-mcp becomes a confused deputy,
  laundering its uid, its `WILLOW_HOME`, and its environment into a call the
  caller could never have made directly.

This is the same shape as the existing binding trust ceiling, and it is the shape
because both hops have to be true at once for the composed call to mean anything.

## 4. Decision 3 — a stdio subprocess is a fourth egress class

willow-mcp already distinguishes three, deliberately, and none of them covers
this:

| Class | Flag | What it authorizes |
|---|---|---|
| Sandbox egress | `task_net` | the network, from inside the netns'd Kart sandbox |
| Adapter egress | `integration_net` | the server process calling out through a registered adapter |
| Open-web egress | `web_net` | server-process HTTP, re-resolved per redirect by `web_fetch` |
| **Subprocess spawn** | **`mcp_federation`** | **fork/exec at server uid** |

A stdio MCP server is strictly more privileged than all three: it is `fork`/`exec`
at the server's uid, with a full filesystem view, no network namespace, and a
child that may hold its own network access and its own credentials.

**Decided:** add `mcp_federation` as a fifth own-line capability flag, plus
`consent.federation` as a third consent key. Reuse `lease.py` **unchanged** — it
is already app-keyed, tz-aware, and 3h-capped, which is exactly the shape needed.

**Explicitly refused:** widening `web_net` to cover this. Its denial text says
"open-web tools", and that sentence is the operator's mental model. Quietly
making it also mean "may fork a process as me" would make the existing grant
retroactively mean more than the operator agreed to — the precise failure this
codebase separated `task_net` from `integration_net` from `web_net` to avoid.

### Decision 3 addendum — lease only for net-bearing federated tools (2026-09-23)

Operator ruling: *nothing internal behind egress.* A stdio downstream on the
same box (jeles-corpus) is still a fourth egress **class** — `mcp_federation`,
per-tool grants, ratification, and `consent.federation` all still apply before
spawn. The app-keyed lease from `lease.py` is unchanged on disk; only **when**
`federation_egress` reads it is narrowed:

| Federated call | Lease required? |
|---|---|
| HTTP / streamable-http downstream | Yes (network peer) |
| Stdio tool in `FEDERATION_LOOPBACK_STDIO_TOOLS` (corpus_search, corpus_ask, …) | No |
| Stdio tool in `FEDERATION_NET_BEARING_TOOLS` (corpus_web_search, …) | Yes |
| Stdio tool not yet classified | Yes (fail closed) |

Implementation: `federation_tool_egress.py` + conditional check in
`federation_egress.egress_denial`. Future `net.egress` envelope row 19 may
codify the same bounds; runtime behavior landed first.

## 5. Decision 4 — four controls with no three-key analogue

The three-key gate does not cover these, because none of the existing lanes
spawns anything.

**(a) Environment allowlist, never inheritance.** This is the sharpest finding
and it is not hypothetical — willow-2.0 does exactly this in the code being
ported in:

```python
# sap/clients/soil_client.py:92, inside StdioServerParameters(...)
env={k: str(v) for k, v in os.environ.items()},
```

```python
# willow/fylgja/_mcp.py:434
env = os.environ.copy()
```

That hands a subprocess `WILLOW_PGP_FINGERPRINT`, `WILLOW_MCP_API_KEY` and
`PGPASSWORD` — all three live in that tree — which is to say it hands a child the
trust root. `WILLOW_PGP_FINGERPRINT` is the switch that turns on manifest
signature enforcement at `gate.py:_load_manifest`; a child holding it holds the
ability to reason about, and lie about, the thing that authorizes its parent.

Inherit **nothing** by default. A server spec names the environment keys it
receives; anything unnamed is absent, not empty.

**(b) Discovery lists, ratification connects.** `.mcp.json` lives in repositories
the agent can write. Write-then-connect is minting your own capability — the same
kill chain `gate._load_manifest` reasons about under #183, arriving through a
different file. So: discovery is **inventory only**, and connecting requires an
operator-ratified entry under the `0700` gate directory, detach-signed the way
the signing seed already is.

**(c) Downstream output *and* downstream tool descriptions are untrusted.**
The output half is obvious and already solved — `external_guard.scan` plus the
sandwich wrap, exactly as `web_fetch.py:478–491` does it.

The half that is easy to miss: **tool names and descriptions are also untrusted
input**, and they arrive earlier. A hostile description is prompt injection aimed
at the orchestrator itself, and any code that splices downstream listings into
willow-mcp's own `list_tools` output would carry it straight into the context
that decides what to call next. Scan at listing time, not only at call time.

**(d) Receipts carry `server_id` and the downstream tool name**, so
`receipts_tail` shows the fan-out rather than a flat local call. Ratification
events go to `governance_ledger` / FRANK.

## 6. Decision 5 — enforce at both hops, from disk, at call time

Check at the tool boundary **and** again at the spawn/connect boundary, reading
facts from disk each time rather than caching what was true at `connect_server`.

Two precedents, both in this fleet, both learned the hard way:

- `web_fetch.validate_hop` re-validates **every redirect** instead of trusting
  the first resolution. A destination that was safe at request time is not
  therefore safe three hops later.
- `core/egress_authority.py` exists **only** because the submitter checked three
  keys and the executor checked none. Task `2E8E5FE0` reached the network with
  `task_net` revoked and its lease expired, because `# allow_net` in a task
  string was honoured on sight. Its own sentence is the doctrine:

  > *"A directive in a task string is a claim; a lease on disk owned elsewhere is
  > a fact."*

A cached connect-time authorization is a claim. Re-reading the lease is a fact.

---

@phase 3-caveat
## 7. The honest caveat

**On a single-uid host, gating a subprocess launch is narrowing, not closing.**

An agent denied a federated call can exec the same binary directly. The gate
raises the cost and creates the record; it does not make the capability
unreachable. The existing lever is
`lease.strict_trust_root()` / `self_writable_trust_paths()` — the same B-32
frontier `egress_authority.py` names in its own docstring rather than letting its
layering imply otherwise.

This section is not throat-clearing. It is here because a fourth key *looks* like
a fourth guarantee, and the difference between "attributed, dated, expiring, and
capability-gated" and "impossible" is the whole of what an operator needs to know
before granting it.

This is also the one place §0's two meanings of "federation" touch: a peer node's
directive is refused because *someone else* issued it, whereas a local subprocess
is constrained only as far as the uid boundary allows. The wire-format doc can
promise refusal. This one can only promise attribution.

---

@phase 4-what-is-pinned
## 8. What is pinned in code today

`federation_egress`, `mcp_federation_client`, and the loopback lease split
(2026-09-23) are live. One premise was checkable before the client existed, and
was not checked at the time: `test_egress_tools_stay_off_full_access` asserted the own-line rule for
`task_net` and `integration_net` — and **omitted `web_net`**, the newest of the
three and the one this design extends.

`tests/test_authority_surface.py` now asserts the property generically: every
capability flag is absent from *every* permission group, not just `full_access`,
and the roster of flags is read off `gate` rather than retyped. `mcp_federation`
inherits the check by existing.

## 9. What this unblocks

The orchestrator substrate (~644 lines, zero new deps). Build order follows from
the decisions rather than from the file list:

1. `mcp_federation` flag + `consent.federation` key + the generic own-line test.
2. Server spec and ratified registry — `env_keys` and discovery-vs-ratification
   from §5(a)/(b) — before anything spawns.
3. `federation_egress.egress_denial(app_id, server_id, tool)`, mirroring
   `web_egress.py` and reusing `lease.py` untouched.
4. The client itself, enforcing at both hops per §6.
5. `external_guard` on listings and results; receipts carrying `server_id`.

Steps 1–3 are the gate. Step 4 is the feature. Doing them in that order is the
entire point of writing this before the client exists.
