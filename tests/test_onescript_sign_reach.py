"""Absence is said: ``bound_receipt``'s sign reach (flatten-2 F14, merge-check gate 5).

``bound_receipt`` signs and checks its HMAC through ``onescript_sign`` (the one
reach to the one script's ``sign.py``). With ``ONESCRIPT_HOME`` pointing nowhere
it must say ``unreachable`` with a reason, and never sign another way. This runs
in a subprocess so no module the parent already imported (and no cached reach)
can stand in for the one script.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1] / "src")

CODE = """
import json, sys
from willow_mcp import bound_receipt
out = {}
for name, call in (
    ("sign", lambda: bound_receipt._sign_hmac_sha256(b"k" * 32, {"a": "b"})),
    ("check", lambda: bound_receipt._check_signature(
        {"signature": {"alg": "hmac-sha256", "value": "00"}, "payload": {"a": "b"}}, b"k" * 32)),
):
    try:
        call()
        out[name] = "signed anyway"
    except Exception as e:
        out[name] = [type(e).__name__, str(e)]
print(json.dumps(out))
"""


def test_the_sign_reach_says_unreachable_with_why_and_never_signs_another_way(tmp_path):
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
    for name in ("sign", "check"):
        kind, why = got[name]
        assert kind == "Unreachable", got
        assert "ONESCRIPT_HOME" in why and "nowhere" in why, got
