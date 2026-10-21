"""onescript_sign.py -- willow-mcp's one way to reach the one script's signing rules.

The HMAC seal, the seal message, the public-only keyring rules and the pinned
Ed25519 verifier live once, by name, in the one script's ``onescript/sign.py``
(flatten-2 F14). willow-mcp's non-trust-owner modules import them (D-a)
through the one reach (``onescript_reach.py``, the F6.5 bootstrap). The
operator: "Using the onescript at every path."

``onescript_sign.sign().hmac_hex(key, message)`` is the call. The reach is made
on the first call, not at import, so importing willow-mcp never needs the one
script; signing or checking without it says ``unreachable`` with the reach's
reason (``onescript_reach.Unreachable``, naming ``ONESCRIPT_HOME``). It never
falls back to a copy of the rule.

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

_sign = None


def sign():
    """The one script's ``onescript.sign`` module. Raises ``Unreachable`` (with
    why) when the one script is not where it was looked for."""
    global _sign
    if _sign is None:
        _sign = onescript_reach.module("sign")
    return _sign
