"""Standing operator consent — the standing ring of the three-key egress gate.

`task_net` in an app's manifest says *this app may ever request egress*.
`consent.internet` in `$WILLOW_HOME/settings.global.json` says *the operator
permits egress right now*. An egress lease (`lease.py`) says *this app, until
this time*. A network-bearing task needs **all three**. The manifest key is a
capability, granted once and rarely; the consent key is a switch the operator
flips, without editing a single manifest; the lease is a time-boxed grant that
expires on its own.

All three standing keys are read by `task_submit`, then read again by the
willow-mcp execution authorizer before Kartikeya launches a network shell.
`# allow_net` is only a request: B-37 adds an operator-signed, task-bound envelope
and a fail-closed host verifier at the executor. A direct row insert cannot turn
this consent bit into authority by itself.

This module only ever **reads**. Mutation is isolated in ``consent_admin`` and
reachable only through willow-mcp's interactive operator CLI; runtime MCP tools
remain consumers and cannot write the policy they are checked against.

**Fail-closed, deliberately diverging from the writer.** willow-2.0's
`DEFAULT_CONSENT` is all-`True` and its `_normalize_consent()` returns those
defaults for any non-dict — so a missing, truncated, or malformed consent block
resolves to *permitted*. That is the same inversion as B-25 (`gate.store_scope`
returning "unrestricted" for an unreadable policy). Here, anything we cannot read
as an explicit `true` is `false`. An absent file is not consent. An unparseable
file is not consent. A `"yes"` where a bool belongs is not consent.

Precedence follows the writer's own loader: canonical `settings.global.json` wins
when present; the flat `consent.json` is consulted only when the canonical file is
absent (mirroring `load_global_settings`'s first-load import). A canonical file
that exists but cannot be parsed denies — it does NOT fall back to the flat file,
because a corrupt policy must not be silently replaced by an older, laxer one.

**`consent.json` is a mirror, not a leftover** (B-30). It is tempting to call it
"legacy" and reason no further: we only *read* it as a fallback, so it looks inert.
It is not. willow-2.0's `save_global_settings(..., sync_legacy=True)` — the default,
and what every caller passes — rewrites `consent.json` from the canonical block on
**every save**, and Grove's settings pane mirrors it on every consent toggle. So the
file is continuously *written* and almost never *read*.

That asymmetry is the whole hazard. A write-only mirror drifts silently: hand-edit
`consent.json` and nothing reads your edit, nothing corrects it, and the file sits
there looking exactly like an off switch until the next unrelated save quietly
overwrites it. Deleting it does not help — the next save recreates it. What makes it
safe is that any divergence is *reported*: `read_consent()` compares the keys both
files declare and `diagnostic_summary` raises an `error` naming both values. Surface
the disagreement; never resolve it. Which file states the operator's intent is the
operator's call, and a gate that guesses is not a gate.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from . import paths

logger = logging.getLogger("willow_mcp.consent")

CONSENT_KEYS = ("internet", "cloud_llm", "federation")

#: Retired keys. Read tolerantly, never projected, never grantable.
#:
#: `lan` was removed 2026-07-29 rather than enforced. It was modelled,
#: persisted, mirrored to the legacy file and rendered in the gates panel for
#: months while nothing consulted it — and the plan to enforce it rested on a
#: premise the sandbox does not implement: that `# allow_localhost` is a
#: LAN-scoped mode distinct from full egress.
#:
#: It is not. `kartikeya/sandbox.py` omits `--unshare-net` for BOTH `allow_net`
#: and `allow_localhost`, so the task shares the host network namespace
#: unfiltered; the only difference is that `allow_localhost` gets no credential
#: env. That module's own docstring says it plainly: "it can still reach every
#: service listening on the host namespace and therefore requires the same
#: attributable per-task authorization as allow_net".
#:
#: So there is no "LAN but not internet" capability here to gate. `allow_net`
#: is correctly gated on `consent.internet`. `allow_localhost` is RETIRED
#: (2026-09-23, governance record retire-allow-localhost-2026-09-23, amends
#: this same sealed decision) — `task_submit` refuses it by name before the
#: consent check ever runs, so it is no longer gated on `consent.internet`
#: at all; it is gated on nothing because it does not run. A third key would
#: have implied a confinement the sandbox never provided — which is the
#: defect this key already was, not its cure.
#:
#: Migration is a no-op by construction: `_strict_bools` projects only
#: CONSENT_KEYS, so a settings file still carrying `lan` is ignored rather than
#: rejected, and the next operator write drops it.
#: See docs/design/consent-toggles.md.
_REMOVED_KEYS = ("lan",)

# Every key denied. The value returned whenever consent cannot be positively read.
_DENY_ALL: dict[str, bool] = {k: False for k in CONSENT_KEYS}


def _willow_home() -> Path:
    return paths.willow_home()


def settings_path() -> Path:
    """Canonical fleet settings — config/ preferred; legacy root supported."""
    override = os.environ.get("WILLOW_SETTINGS_GLOBAL")
    if override:
        return Path(override)
    cfg = paths.settings_global_path()
    if cfg.is_file():
        return cfg
    return paths.settings_global_legacy_path()


def legacy_path() -> Path:
    """Flat consent mirror — config/ preferred; legacy root supported."""
    cfg = paths.consent_path()
    if cfg.is_file():
        return cfg
    return paths.consent_legacy_path()


def _strict_bools(raw: object) -> dict[str, bool] | None:
    """Project a consent mapping, treating anything but a real `true` as denial.

    Returns None when `raw` is not a mapping at all — the caller distinguishes
    "no consent block" from "a consent block that denies".
    """
    if not isinstance(raw, dict):
        return None
    # `is True` on purpose: 1, "true", and "yes" are not consent.
    return {k: raw.get(k) is True for k in CONSENT_KEYS}


def _read(path: Path) -> tuple[dict[str, bool] | None, set[str], str | None]:
    """(consent, declared_keys, error). consent is None when the file is absent.

    `declared_keys` are the keys the file actually mentions. A key it omits is
    denied in `consent` (absence is not consent) but must not be reported as
    *disagreeing* with another file — a file that says nothing is not in conflict.
    """
    if not path.is_file():
        return None, set(), None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return None, set(), f"unparseable: {str(e)[:120]}"
    if not isinstance(data, dict):
        return None, set(), "unparseable: top level is not an object"
    # Canonical shape nests under "consent"; the legacy file is flat.
    block = data.get("consent") if isinstance(data.get("consent"), dict) else None
    if block is not None:
        return _strict_bools(block), {k for k in CONSENT_KEYS if k in block}, None
    flat = _strict_bools(data)
    if flat is not None and any(k in data for k in CONSENT_KEYS):
        return flat, {k for k in CONSENT_KEYS if k in data}, None
    return None, set(), "unparseable: no consent keys found"


def read_consent() -> dict:
    """Resolve standing consent, reporting where it came from and what disagrees.

    Never raises. Always returns a `consent` mapping — deny-all whenever the
    policy could not be positively read.
    """
    canonical, legacy = settings_path(), legacy_path()
    check: dict = {
        "canonical_path": str(canonical),
        "legacy_path": str(legacy),
        "source": None,
        "consent": dict(_DENY_ALL),
        "disagreement": None,
    }

    canon_consent, canon_keys, canon_err = _read(canonical)
    legacy_consent, legacy_keys, _legacy_err = _read(legacy)

    if canon_err:
        # Present but unreadable: deny. Do NOT silently fall back to the legacy
        # file — a corrupt policy must not be replaced by an older, laxer one.
        logger.error("consent: %s is %s — denying all consent keys", canonical, canon_err)
        check.update(source="canonical", status="fail", error=canon_err)
        return check

    if canon_consent is not None:
        check["source"] = "canonical"
        check["consent"] = canon_consent
    elif legacy_consent is not None:
        # Mirrors load_global_settings(): legacy is imported only when canonical
        # is absent entirely.
        check["source"] = "legacy"
        check["consent"] = legacy_consent
    else:
        logger.warning("consent: no readable policy at %s or %s — denying all", canonical, legacy)
        check["source"] = "none"
        check["status"] = "warn"
        check["detail"] = "no readable consent policy — all consent keys denied"
        return check

    # Surface, never resolve: the operator decides which file is the truth.
    # Compare only keys BOTH files declare — a file that omits a key is silent on
    # it, not in conflict about it, and reporting otherwise sends the operator
    # hunting a disagreement that does not exist.
    if canon_consent is not None and legacy_consent is not None:
        shared = canon_keys & legacy_keys
        differing = sorted(k for k in shared if canon_consent[k] != legacy_consent[k])
        if differing:
            check["disagreement"] = {
                "keys": differing,
                "canonical": {k: canon_consent[k] for k in differing},
                "legacy": {k: legacy_consent[k] for k in differing},
            }

    check["status"] = "ok"
    return check


def permitted(key: str) -> bool:
    """True only when the operator's standing consent explicitly allows `key`."""
    if key not in CONSENT_KEYS:
        logger.error("consent: unknown key %r — denying", key)
        return False
    return read_consent()["consent"].get(key, False) is True


def internet_permitted() -> bool:
    """The standing, all-apps key of the three-key egress gate. See
    `gate.NET_PERMISSION` for the capability and `lease.active` for the time-boxed
    grant. Read at both submit time and execution time; the signed per-task
    envelope supplies the separate one-use authority (B-37)."""
    return permitted("internet")


def cloud_llm_permitted() -> bool:
    """Standing consent for model inference that leaves this machine.

    Read by `model_egress.denial()`, which gates the Nest tools. Until that
    landed this key was modelled, reconciled, mirrored and displayed while
    **nothing consulted it** — a switch the operator could flip, watch persist,
    and receive no protection from. `gates_panel` labelled it "reserved — not
    yet enforced", which fixed the label and not the toggle, and only for people
    who read the panel rather than the settings file.
    """
    return permitted("cloud_llm")


def federation_permitted() -> bool:
    """Standing consent for willow-mcp to fork/exec a downstream MCP server.

    Read by `federation_egress.egress_denial()`, alongside the
    `mcp_federation` manifest capability and a live lease — the same
    three-key shape `internet_permitted()` and `cloud_llm_permitted()` serve
    their own lanes. See docs/design/federated-mcp-gating.md Decision 3: a
    stdio MCP server is a fourth egress class, so it gets its own standing
    switch rather than being folded into `internet_permitted()` — an operator
    who permits open-web HTTP has not thereby agreed that this box may also
    spawn arbitrary subprocesses at its own uid.
    """
    return permitted("federation")


def retired(key: str) -> bool:
    """Whether `key` is a consent key this build no longer honours.

    `lan_permitted()` used to live here, documenting itself as the one key with
    no caller. That asymmetry is now resolved by removal rather than by
    enforcement — see `_REMOVED_KEYS` for why the sandbox has no LAN-scoped
    capability to gate. Callers that need to explain a retired key to an
    operator ask here instead of carrying their own list.
    """
    return key in _REMOVED_KEYS
