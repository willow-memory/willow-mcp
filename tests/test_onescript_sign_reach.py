"""Absence is said: ``bound_receipt``'s sign reach (flatten-2 F14, merge-check gate 5).

``bound_receipt`` signs and checks its HMAC through ``onescript_sign`` (the one
reach to the one script's ``sign.py``). "2 carry copies" (operator, 2026-10-21):
with ``ONESCRIPT_HOME`` pointing nowhere it signs with the carried ``sign_local``
and SAYS so (``onescript_sign.SOURCE == "carried"``, ``WHY`` naming
``ONESCRIPT_HOME``); the value is the HMAC the one script gives. This runs in a
subprocess so no module the parent already imported (and no cached reach) can
stand in for the one script.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1] / "src")

CODE = """
import json
from willow_mcp import bound_receipt, onescript_sign
sig = bound_receipt._one_sign().hmac_hex(b"k" * 32, b"msg")
ok = bound_receipt._one_sign().hmac_equal(sig, sig)
print(json.dumps({"sig": sig, "ok": ok, "source": onescript_sign.SOURCE, "why": onescript_sign.WHY}))
"""


def test_the_sign_reach_signs_with_the_carried_copy_and_says_so(tmp_path):
    """The one script unreachable is said with why (``WHY``), and signing goes on
    with the carried copy, never another way."""
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": SRC,
        "ONESCRIPT_HOME": str(tmp_path / "nowhere"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    r = subprocess.run(
        [sys.executable, "-c", CODE], env=env, capture_output=True, text=True, check=False
    )
    assert r.returncode == 0, r.stderr
    got = json.loads(r.stdout)
    assert got["source"] == "carried", got
    assert "ONESCRIPT_HOME" in got["why"] and "nowhere" in got["why"], got
    assert got["ok"] is True, got
    assert got["sig"] == hmac.new(b"k" * 32, b"msg", hashlib.sha256).hexdigest()
