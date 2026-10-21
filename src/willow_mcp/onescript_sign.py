"""onescript_sign.py -- willow-mcp's one way to reach the one script's signing rules.

The HMAC seal, the seal message, the public-only keyring rules and the pinned
Ed25519 verifier live once, by name, in the one script's ``onescript/sign.py``
(flatten-2 F14). willow-mcp's non-trust-owner modules import them (D-a)
through the one reach (``onescript_reach.py``, the F6.5 bootstrap). The
operator: "Using the onescript at every path."

"2 carry copies" (operator, 2026-10-21): an installed willow-mcp with no
willow-bot beside must keep working. With the one script absent ``sign()``
returns ``sign_local``, ``onescript/sign.py`` copied with one line changed (its
``from . import canon`` reads ``canon_local``), held to it by
``tests/test_sign_local_parity.py``. ``SOURCE`` says which answered: ``None``
before the first call, then ``"onescript"`` or ``"carried"``.

``onescript_sign.sign().hmac_hex(key, message)`` is the call. The reach is made
on the first call, not at import, so importing willow-mcp never needs the one
script.

NOT for the trust owner's code. The modules the root-owned venv loads
(``keyring``, ``human_session``, ``net_signer``, ``seal_ring``,
``session_signing`` (reached from ``human_session``), ``dispatch_signing``,
``session_binder`` and the rest of the manifest-grant closure) keep their own
signing code and must never import this: the reach puts an operator-writable
checkout on ``sys.path`` (operator ruling 2026-10-21). They are held byte for
byte to ``sign.py`` by ``tests/test_sign_parity.py``, which lives outside the
trust path.
"""

from __future__ import annotations

from . import onescript_reach

Unreachable = onescript_reach.Unreachable

#: Which sign answered: ``None`` before the first call, then ``"onescript"`` or
#: ``"carried"`` (``sign_local``). Never silent.
SOURCE = None
#: Why the one script was not used, when ``SOURCE == "carried"``.
WHY = None

_sign = None


def sign():
    """The one script's ``onescript.sign`` module, or the carried copy when the
    one script is not where it was looked for (see ``SOURCE``)."""
    global _sign, SOURCE, WHY
    if _sign is None:
        try:
            _sign = onescript_reach.module("sign")
            SOURCE, WHY = "onescript", None
        except onescript_reach.Unreachable as e:
            from . import sign_local

            _sign = sign_local
            SOURCE, WHY = "carried", str(e)
    return _sign
