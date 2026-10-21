"""clock.py -- the one "now", and the named formats it is written in (flatten-2 F8).

The fleet had one injected clock (``record.Record(clock=...)``, fed by
``--now``) and about thirty private ``_utc_now`` helpers that each read the
wall clock and chose a format on their own. A run can only be reproduced if
"now" comes from ONE place that can be pinned; the format is a separate
question, because a format that was written to disk or into a hash can never
change (D-e). The operator: "Using the onescript at every path."

Where "now" comes from, first match wins:

  1. an explicit ``at`` / ``pinned`` argument (a datetime, or a pin string)
  2. ``$ONESCRIPT_NOW``, modeled on ``SOURCE_DATE_EPOCH``: an ISO 8601 instant
     (``2026-10-20T12:00:00Z``; a ``+hh:mm`` offset is converted; a naive
     string is taken as UTC) or epoch seconds (``1792497600``, fractions ok)
  3. the wall clock, in UTC

A pin that does not parse is an error (``BadPin``), never a quiet fall back to
the real time: a run that meant to be reproducible must not become a live one
unannounced. The CLI's ``--now`` stays what it was, a string used verbatim as
the record's clock (``api.run``); with no ``--now`` the record's clock is
``seconds_z`` here, so ``$ONESCRIPT_NOW`` pins it too. Everything is UTC; no
function here renders a local time.

The formats. One function per format in use, each byte-identical to the helper
it replaced (a golden test pins every one at a fixed instant, with and without
microseconds):

  ``seconds_z``             ``2026-10-20T12:00:00Z``. Microseconds dropped
                            (floored), ``Z``. The one script's record rows
                            (``ts`` in ``record.jsonl``, hash-chained), the
                            beacon's day, Grove's journal ``ts``, willow-mcp's
                            dispatch/handoff/seed/posture/curate/envelope and
                            sign-session stamps (signed, mirrored to
                            Postgres), willow-bot's deterministic runner.
                            ``strftime("%Y-%m-%dT%H:%M:%SZ")``, ``replace(
                            microsecond=0).isoformat().replace("+00:00","Z")``
                            and ``isoformat(timespec="seconds")`` + ``Z`` are
                            all this one string.
  ``isoformat_utc``         ``2026-10-20T12:00:00.123456+00:00`` (the
                            fraction is absent when the microsecond is 0, as
                            ``isoformat`` does). willow-mcp's grant ratify
                            and executor stamps, KB verification and training
                            corpus rows, bound receipts (``issued_at`` /
                            ``expires_at`` sit in the signed payload),
                            njord's provenance, semantic-translator's learn
                            stamp, ask-jeles' learning events.
  ``isoformat_seconds_utc`` ``2026-10-20T12:00:00+00:00``. The xref index's
                            record clock.

``now()`` itself is the datetime for the callers that do arithmetic (bound
receipt expiry, ratatosk envelope ttl) and format afterwards.

Imports only the standard library.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

ENV_NOW = "ONESCRIPT_NOW"

#: The format strings, for a caller that must show which one it persists.
SECONDS_Z = "%Y-%m-%dT%H:%M:%SZ"


class BadPin(ValueError):
    """A pinned "now" that is not an ISO 8601 instant or epoch seconds."""


def parse_pin(text: str) -> datetime:
    """A pin string -> aware UTC datetime. ISO 8601 (``Z`` or offset; naive is
    UTC) or epoch seconds. Raises ``BadPin`` with the text it could not read."""
    s = str(text).strip()
    try:
        if s.lstrip("+-").replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(s), timezone.utc)
        dt = datetime.fromisoformat(s[:-1] + "+00:00" if s[-1:] in "zZ" else s)
    except (ValueError, OverflowError, OSError) as e:
        raise BadPin(
            f"{ENV_NOW} / pin {text!r} is neither an ISO 8601 instant nor epoch seconds"
        ) from e
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def pinned(env=None) -> datetime | None:
    """The instant ``$ONESCRIPT_NOW`` pins, or None when it is unset or empty."""
    raw = (os.environ if env is None else env).get(ENV_NOW, "")
    return parse_pin(raw) if raw.strip() else None


def now(at: datetime | str | None = None, env=None) -> datetime:
    """The one "now": ``at`` (a datetime or pin string), else ``$ONESCRIPT_NOW``,
    else the wall clock. Always an aware UTC datetime."""
    if at is not None:
        if isinstance(at, str):
            return parse_pin(at)
        return (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).astimezone(
            timezone.utc
        )
    return pinned(env) or datetime.now(timezone.utc)


def seconds_z(at: datetime | str | None = None) -> str:
    """``2026-10-20T12:00:00Z`` (see the module docstring for who persists it)."""
    return now(at).replace(microsecond=0).strftime(SECONDS_Z)


def isoformat_utc(at: datetime | str | None = None) -> str:
    """``2026-10-20T12:00:00.123456+00:00`` (``datetime.isoformat`` of UTC)."""
    return now(at).isoformat()


def isoformat_seconds_utc(at: datetime | str | None = None) -> str:
    """``2026-10-20T12:00:00+00:00``."""
    return now(at).isoformat(timespec="seconds")
