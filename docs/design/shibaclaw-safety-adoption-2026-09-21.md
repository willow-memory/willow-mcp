# Spec: Adopt ShibaClaw safety machinery into willow-mcp

- Status: Draft — **P1 landed** (see the P1 status note below); P2/P3 open
- Date: 2026-09-21
- Source: fork audit (rudi193-cmd/ShibaClaw, Apache-2.0)
- Scope: egress target validation, tool-output framing, install gating
- Depends on: web_net/integration_net egress gating, external guard,
  receipt log, gates panel, manifest ACL

## Motivation

The fork audit found ShibaClaw is the one collected fork carrying original
owner-authored engineering, and all of it is safety hardening. ShibaClaw builds
the *mechanisms*; willow-mcp already owns the *enforcement and audit* substrate
(egress gating, receipt log, gates panel, manifest). Each ShibaClaw piece is
best-effort in isolation and becomes enforced-and-audited once wired to a willow
shape. ShibaClaw is Apache-2.0, so the code vendors directly into willow-mcp
under the same licence.

This spec covers three adoptions (P1-P3) and one explicit non-adoption (P4).

## Background: what ShibaClaw provides

| Piece | ShibaClaw location | Core symbols |
| --- | --- | --- |
| SSRF / DNS-rebind guard | `shibaclaw/security/network.py` | `validate_url_target`, `resolve_and_pin`, `_is_private`, `_check_ips` |
| Muzzle (tool-output framing) | `shibaclaw/agent/context.py` | `add_tool_result`, `regenerate_nonce` |
| Install CVE audit | `shibaclaw/security/install_audit.py` | `audit_install`, `AuditResult`, `Vulnerability` |
| ScentBuilder (prompt assembly) | `shibaclaw/agent/context.py` | `ScentBuilder.build_static_prompt` |

## The willow gaps these close

1. **Egress gating authorizes, it does not validate the target.** `web_net` /
   `integration_net` decide *whether* an app_id may call outbound. Nothing
   checks that the resolved destination is not a private/link-local/loopback
   address, and nothing pins the resolved IP. A hostname that resolves to a
   public IP on the gate check and an internal IP on the actual connect (DNS
   rebinding) passes today. This is a real SSRF hole in the outbound path.
2. **External guard scans, it does not frame.** The external guard detects
   injection patterns in fetched content but does not structurally prevent
   injected text from forging the tool-output boundary in the model's context.
3. **No pre-execution gate on package installs** (relevant only if willow
   executes install-shaped shell commands).

---

## P1 (priority: highest) - Egress target validation + IP pinning

> **Status (landed):** most of P1 was already shipped and the port would have
> been redundant. `web_fetch.validate_fetch_url` already refuses the whole
> blocked-range matrix (v4/v6 private, loopback, link-local, reserved,
> multicast, non-global, the metadata address) with hostname *resolution* — not
> ShibaClaw's name-only pattern match — plus IP-literal normalisation
> (`inet_aton` tricks, percent-escapes), a per-hop redirect check, and an
> https→http downgrade refusal. All outbound (web_search, mai/parser,
> mcp_federation) funnels through it. So the port of `network.py`'s
> `validate_url_target` was **not** adopted; it is a subset of what ships.
>
> Two pieces of P1 were genuinely missing and were the ones built:
>
> 1. **IP pinning (the crux).** `validate_fetch_url` resolved at check time and
>    `requests` re-resolved at connect time — the rebind window this spec calls
>    load-bearing. Closed by `web_fetch.resolve_pinned` (keeps the vetted
>    addresses) + `_PinnedHTTPAdapter`, which dials only those addresses and
>    never re-resolves the name. TLS SNI, the certificate hostname and the Host
>    header stay bound to the name (urllib3 keeps those on `.host`; only the
>    socket target moves). The proxy path pins nothing and dials as before.
> 2. **Structured egress-denial receipts.** A refusal used to be a bare
>    `log.warning`, filed by the pipeline as an ordinary `error`. It is now a
>    `denied` receipt carrying `egress.private_target` / `egress.redirect_refused`
>    — an attempted-SSRF row an operator can find, which is P1's "what completes
>    it". (`egress.rebind_mismatch` is unneeded on the direct path: pinning
>    *prevents* the rebind rather than detecting it after the fact.)

### Design

Add a target-validation stage that runs **after** egress gating authorizes an
outbound call and **before** the socket connects, in the `web_net` and
`integration_net` lanes.

- Port `network.py` as `willow_mcp/security/egress_target.py`. Keep
  `validate_url_target(url) -> (ok, reason)` and
  `resolve_and_pin(url) -> PinnedTarget` (hostname, list of vetted IPs).
- The blocked-network set covers IPv4/IPv6 private, loopback, link-local, and
  unique-local ranges. Add the cloud metadata address `169.254.169.254`
  explicitly (already inside `169.254.0.0/16`, but assert it in a test).
- **Pinning is load-bearing:** the caller must connect only to an IP returned by
  `resolve_and_pin`, never re-resolve the hostname. Wire this through the HTTP
  client willow uses for outbound fetches (pin via the connection's resolver or
  an explicit IP + Host header), so the vetted IP is the one dialed.
- Config: a per-namespace allowlist of hostnames/CIDRs that may bypass the
  private-range block (for legitimate internal integrations), defaulting to
  empty and fail-closed.

### willow integration (what completes it)

- **Receipt log:** every block is a `denied` outcome with `reason` (e.g.
  `egress.private_target`, `egress.rebind_mismatch`). Makes attempted SSRF
  auditable, which ShibaClaw drops.
- **Gates panel:** surface a row for the egress-target gate with block counts.
- **friction_scan / gap_*:** repeated blocks from one app_id are a signal.

### Acceptance

- A URL resolving to any blocked range is refused before connect.
- A hostname resolving public-then-private across two lookups connects only to
  the pinned (public) IP or is refused, verified with a stub resolver.
- Metadata endpoint `http://169.254.169.254/...` is blocked.
- Blocks appear in the receipt log with a structured reason.

---

## P2 (priority: high) - Muzzle tool-output framing

> **Status (landed):** `external_guard.frame` replaces the static
> `SANDWICH_TEMPLATE` boundary — which injected text could reproduce
> (`---EXTERNAL DATA END---`) to escape the fence — with a per-result
> `<tool_output_{nonce}>` boundary (`secrets.token_hex(8)`, fresh each call, so
> the payload cannot contain the closing token). Any `tool_output` boundary the
> content *does* carry is neutralised and reported (`escape_fired`). The scan
> still runs first; the frame runs after. Wired into `web_fetch.fetch_url` (the
> `willow_web_fetch` tool) and both `mcp_federation_client` framing sites; the
> legacy `---EXTERNAL DATA START/END---` markers are kept inside the fence as
> human-readable guidance, not as the boundary. A neutralised boundary surfaces
> as `guard_escape` on the result and the guarded pipeline records an additive
> `guard.tool_output_escape` receipt.

### Design

Frame tool/fetch results with a per-iteration random nonce so injected content
cannot impersonate the tool-output boundary.

- Add to the point where tool/fetch results enter agent context, alongside the
  external-guard scan (detection + framing as two layers).
- Mint the nonce with `secrets.token_hex(8)` per agent iteration. Wrap results
  as `<tool_output_{nonce} name="{tool}">...</tool_output_{nonce}>`. Escape any
  occurrence of the closing tag inside the payload.
- Keep the scan first (so detections still fire), then frame.

### willow integration (what completes it)

- **Receipt log:** when the closing-tag escape actually fires, emit a distinct
  event (`guard.tool_output_escape`). A high-signal "something tried to close
  the boundary" indicator ShibaClaw discards.
- Feed repeated escape events into `friction_scan` / `gap_*`.

### Acceptance

- Tool output containing a literal closing tag is escaped and cannot break out.
- The nonce differs per iteration.
- An escape event is recorded in the receipt log.

---

## P3 (priority: medium, conditional) - Install CVE gate

> **Status (landed):** the precondition holds — Kart tasks run arbitrary shell
> through kartikeya's `sandbox.run_shell`, so a task body can carry
> `pip install <pkg>`. `willow_mcp/install_audit.py` adds the gate at SUBMIT
> time in `task_submit` (right after `check_kart_task`), which resolves the
> where-does-the-audit-run question: the broker has the environment to run
> `pip-audit`; the network-isolated sandbox could not. It detects
> pip/npm/yarn/pnpm installs, audits pip specs via `pip-audit -r` (an injectable
> runner seam so tests use a hand-written double), and refuses with an
> `INSTALL-AUDIT:` error + structured `install_audit` block when a resolved
> package carries a vuln at/above `WILLOW_INSTALL_AUDIT_SEVERITY` (default
> `high`). It degrades OPEN — an absent tool, a timeout, or an unparseable
> package list allows the install with a logged warning, exactly like
> `check_kart_task`. npm/yarn/pnpm are detected but allowed-with-caution
> (auditing a bare `npm install <pkg>` needs a lockfile context absent at submit
> time); gates-panel surfacing and a dedicated install manifest capability are
> follow-ons.

Adopt **only if willow executes package-install shell commands.** If it does,
port `install_audit.py` as a pre-exec guard on the shell/exec path: detect
pip/npm/yarn/pnpm install commands, run `pip-audit --json` / `npm audit --json`,
block on a configurable severity threshold, fall back to a logged warning if the
audit tool is absent.

### willow integration

- Gate behind the **manifest ACL** (which app_ids may install at all).
- Allow/block decisions recorded in the **receipt log**; surfaced on the
  **gates panel**.

### Acceptance

- An install command with a CVE at/above threshold is blocked with the CVE list
  in the receipt.
- Missing audit tooling degrades to a warning, not a hard failure.

---

## P4 - ScentBuilder: NOT adopted

willow already owns agent identity via **agent seed** + manifest; do not adopt
ShibaClaw's prompt model. The only reusable idea is the static-vs-runtime prompt
caching split, and only if system-prompt assembly becomes a measured hotspot.
Out of scope for this spec.

---

## Security considerations

- P1 must pin at the connection layer, not merely validate the URL string.
  Validation without pinning still allows rebinding. This is the crux.
- P1's bypass allowlist is fail-closed and per-namespace; an empty allowlist
  must never widen the block set.
- P2 is defense-in-depth, not a replacement for the external-guard scan; ship
  both.
- Trust boundary: these harden the untrusted `client <-> engine` / outbound
  edge. They do not change internal-trusted-backend assumptions.

## Testing

- Unit: blocked-range matrix (v4/v6, loopback, link-local, ULA, metadata),
  rebind stub resolver, nonce uniqueness, escape correctness, CVE-threshold
  decisions.
- Integration: an actor fetch to an internal address is blocked and logged; a
  framed tool result survives an embedded closing tag.
- Follow willow's test policy: real infrastructure, no module mocking. A stub
  resolver is a hand-written test double, not `vi.mock`-style patching.

## Rollout

1. P1 `egress_target.py` + pinning wired into the outbound client, behind a
   per-namespace enable flag, default fail-closed.
2. P2 framing in the tool-result path.
3. P3 only if/when willow gains an install-shell surface.
4. Receipt-log reasons + gates-panel rows land with each piece.

## Out of scope

- ScentBuilder / prompt-assembly changes (P4).
- Any change to internal trusted-backend traffic.
- ShibaClaw's native WebSocket handler and desktop launcher (not safety
  machinery).

## Provenance

Mechanisms ported from rudi193-cmd/ShibaClaw (Apache-2.0). willow contribution
is the enforcement + audit substrate (egress gating, receipt log, gates panel,
manifest) that turns each mechanism from best-effort into gated-and-audited.
