"""Optional Sentry observability for willow-mcp — egress-gated by construction.

willow-mcp's contract is fail-closed egress: an agent reaches the network only
with the ``task_net`` capability, the operator's ``consent.internet``, AND an
unexpired operator-issued lease. A telemetry SDK is *un-gated egress by
default* — on the first unhandled exception ``sentry-sdk`` ships stack-frame
local variables, breadcrumbed DB queries, request bodies, and environment to an
external SaaS. On a server that holds lease tokens, session content, consent
state, and vault paths in exactly those places, a naive
``sentry_sdk.init(dsn=...)`` leaks straight past the gate.

So Sentry is treated here as a *hostile egress destination*:

  * OFF unless ``WILLOW_SENTRY_DSN`` is set (fail-closed, like a missing manifest).
  * ``send_default_pii=False``, ``include_local_variables=False``,
    ``max_breadcrumbs=0`` — the three biggest leak vectors closed structurally.
  * ``before_send`` / ``before_send_transaction`` rebuild a *deny-by-default*
    event: only an explicit allow-list of structural fields survives; every
    value matching a sensitive-key or vault-path pattern is redacted.
  * Registered as the ``sentry`` destination in the exposure membrane at the
    narrowest ``telemetry`` preset (see ``exposure.py``) — so the server's own
    exposure policy also resolves "sentry -> expose nothing".

This module imports ``sentry_sdk`` lazily; if the ``observability`` extra is not
installed it is a no-op. Nothing here calls the network itself — ``sentry_sdk``
owns transport, and that transport still needs real outbound access to reach
ingest (which, on this box, is the operator's decision to grant).
"""
from __future__ import annotations

import os
import re
from typing import Any

from .scrub_reach import get

# --- Deny-by-default allow-lists -------------------------------------------

# Event top-level keys permitted OUT. Anything not listed is dropped.
_ALLOWED_TOP_KEYS = frozenset({
    "event_id", "timestamp", "platform", "level", "logger",
    "transaction", "release", "environment", "exception", "sdk",
})

# Within a stack frame, keep only structural fields — never ``vars``/locals.
_ALLOWED_FRAME_KEYS = frozenset({
    "filename", "module", "function", "lineno", "in_app", "context_line",
})

# What counts as sensitive is the one script's (flatten-2 F12,
# ``onescript/scrub.py``: ``sensitive_key`` for key names, the ``secret_path``
# set for the paths that must never leave the box, ``credentials`` for a
# credential shape in a string; the operator: "Using the onescript at every
# path."). Out of reach, nothing is let through: a key reads as sensitive and a
# string as redacted, because an event that cannot be checked is not sent whole.
_REDACTED = "[redacted-by-willow-membrane]"
_STRING_SETS = ("secret_path", "credentials")


def _sensitive_key(key: Any) -> bool:
    mod, _why = get()
    return True if mod is None else mod.sensitive_key(key)


def _redact_str(value: str) -> str:
    """Redact a string if it exposes a secret path (the whole value) or
    carries a credential shape (that part); otherwise return as-is."""
    mod, _why = get()
    if mod is None:
        return _REDACTED
    return mod.apply(value, _STRING_SETS, marker=_REDACTED)


def _scrub_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Redact values under sensitive keys or secret-path strings, recursively."""
    out: dict[str, Any] = {}
    for key, val in data.items():
        if _sensitive_key(key):
            out[key] = _REDACTED
            continue
        out[key] = _scrub_value(val)
    return out


def _scrub_value(val: Any) -> Any:
    if isinstance(val, dict):
        return _scrub_mapping(val)
    if isinstance(val, (list, tuple)):
        return [_scrub_value(v) for v in val]
    if isinstance(val, str):
        return _redact_str(val)
    return val


def _scrub_frame(frame: dict[str, Any]) -> dict[str, Any]:
    """Keep only structural frame fields; drop locals and redact paths."""
    out: dict[str, Any] = {}
    for key in _ALLOWED_FRAME_KEYS:
        if key in frame:
            out[key] = _redact_str(frame[key]) if isinstance(frame[key], str) else frame[key]
    return out


def _scrub_exception(exc_block: dict[str, Any]) -> dict[str, Any]:
    """Preserve exception type + structural stack; strip values and locals."""
    values = []
    for entry in (exc_block.get("values") or []):
        if not isinstance(entry, dict):
            continue
        new_entry: dict[str, Any] = {}
        if "type" in entry:
            new_entry["type"] = entry["type"]
        if "module" in entry:
            new_entry["module"] = entry["module"]
        # The exception *value* (message) can carry data — redact aggressively.
        if "value" in entry and isinstance(entry["value"], str):
            new_entry["value"] = _redact_str(entry["value"])
        st = entry.get("stacktrace")
        if isinstance(st, dict) and isinstance(st.get("frames"), list):
            new_entry["stacktrace"] = {
                "frames": [_scrub_frame(f) for f in st["frames"] if isinstance(f, dict)]
            }
        values.append(new_entry)
    return {"values": values}


def _scrub_event(event: dict[str, Any], _hint: dict[str, Any] | None = None) -> dict[str, Any]:
    """before_send: rebuild the event from an allow-list. Deny by default."""
    out: dict[str, Any] = {}
    for key in _ALLOWED_TOP_KEYS:
        if key not in event:
            continue
        if key == "exception" and isinstance(event["exception"], dict):
            out["exception"] = _scrub_exception(event["exception"])
        elif key == "transaction" and isinstance(event["transaction"], str):
            out["transaction"] = _redact_str(event["transaction"])
        else:
            out[key] = event[key]
    # Static server name only — never the real hostname.
    out["server_name"] = "willow-mcp"
    return out


def _scrub_transaction(event: dict[str, Any], _hint: dict[str, Any] | None = None) -> dict[str, Any]:
    """before_send_transaction: keep timing shape, drop data-bearing span fields."""
    out: dict[str, Any] = {}
    for key in ("event_id", "timestamp", "start_timestamp", "platform",
                "transaction", "release", "environment", "type", "sdk"):
        if key in event:
            out[key] = _redact_str(event[key]) if isinstance(event[key], str) else event[key]
    spans = []
    for span in (event.get("spans") or []):
        if not isinstance(span, dict):
            continue
        spans.append({
            k: span[k]
            for k in ("op", "start_timestamp", "timestamp", "trace_id", "span_id", "parent_span_id")
            if k in span
        })
    if spans:
        out["spans"] = spans
    out["server_name"] = "willow-mcp"
    return out


def _dsn_host(dsn: str) -> str:
    """Ingest host only — never echo the DSN (it contains a public key)."""
    m = re.search(r"@([^/]+)/", dsn)
    return m.group(1) if m else "unknown"


def init_observability() -> dict[str, Any]:
    """Initialise Sentry iff opted in. Returns a status dict; never raises.

    Fail-closed: no ``WILLOW_SENTRY_DSN`` -> disabled. Extra not installed ->
    disabled. When enabled, every leak vector is closed structurally and the
    ``before_send`` hooks enforce a deny-by-default rebuild on top.
    """
    dsn = os.environ.get("WILLOW_SENTRY_DSN", "").strip()
    if not dsn:
        return {"enabled": False, "reason": "WILLOW_SENTRY_DSN unset (fail-closed default)"}
    try:
        import sentry_sdk
    except ImportError:
        return {
            "enabled": False,
            "reason": "sentry-sdk not installed — pip install 'willow-mcp[observability]'",
        }
    try:
        sentry_sdk.init(
            dsn=dsn,
            send_default_pii=False,
            include_local_variables=False,   # no stack-frame locals cross the wire
            max_breadcrumbs=0,               # breadcrumbs carry DB queries — drop all
            attach_stacktrace=False,
            server_name="willow-mcp",        # static; never the real hostname
            environment=os.environ.get("WILLOW_SENTRY_ENV", "experiment"),
            release=os.environ.get("WILLOW_SENTRY_RELEASE", "willow-mcp@experiment"),
            traces_sample_rate=float(os.environ.get("WILLOW_SENTRY_TRACES", "0") or 0),
            before_send=_scrub_event,
            before_send_transaction=_scrub_transaction,
        )
    except Exception as exc:  # never let telemetry setup take down the server
        return {"enabled": False, "reason": f"init failed: {type(exc).__name__}"}
    return {"enabled": True, "dsn_host": _dsn_host(dsn)}
