"""scrub_reach.py -- willow-mcp's one door to the one script's ``scrub``.

Flatten-2 F12: what must not leave is one rule, ``onescript/scrub.py`` in
willow-bot's one-script (the operator: "Using the onescript at every path.";
D-a: willow-mcp imports it). ``secret_scan``, ``nest/secrets``,
``observability`` and ``push_executor`` each reach it here, through the one
reach (``onescript_reach``), and each says what it does when it is not there.

``get()`` is ``(module, "")`` or ``(None, why)``, with the reach's own "why"
(it names ``ONESCRIPT_HOME``). A caller never falls back to a copy of the old
patterns, and a scrubber that cannot look never passes text on as clean: it
withholds, or refuses, and says why. A found module is kept; a failure is not,
so a later call looks again.
"""
from __future__ import annotations

from willow_mcp import onescript_reach

_module = None


class ScrubUnreachable(RuntimeError):
    """The one script's scrub is not where it was looked for (the message is why)."""


def get():
    """``(scrub module, "")``, or ``(None, why)``."""
    global _module
    if _module is not None:
        return _module, ""
    try:
        _module = onescript_reach.module("scrub")
    except onescript_reach.Unreachable as e:
        return None, str(e)
    return _module, ""


def need():
    """The scrub module, or ``ScrubUnreachable`` with why."""
    mod, why = get()
    if mod is None:
        raise ScrubUnreachable(why)
    return mod
