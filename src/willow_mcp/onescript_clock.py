"""onescript_clock.py -- willow-mcp's one way to reach the one clock.

The clock lives once in the one script's ``onescript/clock.py`` (flatten-2 F8):
``now()``, ``seconds_z()``, ``isoformat_utc()``, pinned by ``$ONESCRIPT_NOW``.
The operator: "Using the onescript at every path."

"2 carry copies" (operator, 2026-10-21): an installed willow-mcp with no
willow-bot beside must keep working. With the one script absent ``clock()``
returns ``clock_local``, a byte copy of ``onescript/clock.py`` held to it by
``tests/test_clock_local_parity.py``. ``SOURCE`` says which answered: ``None``
before the first call, then ``"onescript"`` or ``"carried"``; ``WHY`` holds the
reach's reason when carried. Never silent, never a guessed path.

NOT for the trust owner's code (it never imports an ``onescript_*`` module; see
``tests/test_trust_closure_no_onescript.py``).
"""

from __future__ import annotations

from . import onescript_reach

Unreachable = onescript_reach.Unreachable

SOURCE = None
WHY = None



def clock():
    """The one script's ``onescript.clock`` module, or the carried copy. Asked
    on every call (a clock is cheap, and ``$ONESCRIPT_HOME`` may change)."""
    global SOURCE, WHY
    try:
        mod = onescript_reach.module("clock")
        SOURCE, WHY = "onescript", None
    except onescript_reach.Unreachable as e:
        from . import clock_local as mod

        SOURCE, WHY = "carried", str(e)
    return mod
