"""onescript_canon.py -- willow-mcp's one way to reach the canonical-bytes encodings.

The encodings live once, by name, in the one script's ``onescript/canon.py``
(flatten-2 F7). willow-mcp imports them (D-a) through the one reach
(``onescript_reach.py``, the F6.5 bootstrap). The operator: "Using the
onescript at every path."

``family("sorted_compact_utf8").bytes(obj)`` is the call. The reach is made on
the first call, not at import, so importing willow-mcp never needs the one
script; hashing or signing without it says ``unreachable`` with the reach's
reason (``onescript_reach.Unreachable``, naming ``ONESCRIPT_HOME``). It never
guesses a path and never falls back to a copy of the ``json.dumps`` call: a
digest computed any other way would not be the persisted one.
"""

from __future__ import annotations

from . import onescript_reach

Unreachable = onescript_reach.Unreachable

_canon = None


def family(name: str):
    """One of ``onescript.canon``'s named encodings. Raises ``Unreachable``
    (with why) when the one script is not where it was looked for."""
    global _canon
    if _canon is None:
        _canon = onescript_reach.module("canon")
    return _canon.get(name)
