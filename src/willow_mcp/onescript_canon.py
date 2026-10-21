"""onescript_canon.py -- willow-mcp's one way to reach the canonical-bytes encodings.

The encodings live once, by name, in the one script's ``onescript/canon.py``
(flatten-2 F7). willow-mcp imports them (D-a) through the one reach
(``onescript_reach.py``, the F6.5 bootstrap). The operator: "Using the
onescript at every path."

``family("sorted_compact_utf8").bytes(obj)`` is the call. The reach is made on
the first call, not at import, so importing willow-mcp never needs the one
script.

"2 carry copies" (operator, 2026-10-21): an installed willow-mcp with no
willow-bot beside must keep working. With the one script absent the call uses
``canon_local``, a byte copy of ``onescript/canon.py`` held to it by
``tests/test_canon_local_parity.py``. It SAYS which: ``SOURCE`` is ``None``
until the first call, then ``"onescript"`` or ``"carried"`` (also
``source()``). It never guesses a path and never uses a third way: a digest
computed any other way would not be the persisted one.
"""


from __future__ import annotations

from . import canon_local, onescript_reach

Unreachable = onescript_reach.Unreachable

#: Which canon answered: ``None`` before the first call, then ``"onescript"``
#: (the one script, beside) or ``"carried"`` (``canon_local``). Never silent.
SOURCE = None
#: Why the one script was not used, when ``SOURCE == "carried"``.
WHY = None

_canon = None


def _module():
    global _canon, SOURCE, WHY
    if _canon is None:
        try:
            _canon = onescript_reach.module("canon")
            SOURCE, WHY = "onescript", None
        except onescript_reach.Unreachable as e:
            _canon = canon_local
            SOURCE, WHY = "carried", str(e)
    return _canon


def source() -> str:
    """``"onescript"`` or ``"carried"``, whichever answers the next call."""
    _module()
    return SOURCE


def family(name: str):
    """One of the named encodings (``onescript.canon``'s, or the byte copy's
    when the one script is not beside; see ``SOURCE``)."""
    return _module().get(name)
