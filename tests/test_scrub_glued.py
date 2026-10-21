"""A key glued to letters is taken out through every willow-mcp scrub door.

Ported from the retired tests/test_scrub_reach.py (flatten-2 F12): the doors now
use the local copy, src/willow_mcp/scrub_local.py (held to the one script's
onescript/scrub.py by tests/test_scrub_parity.py), and this case must not be
lost with the door it used to run through. The `\\b` anchors the old nest-pipeline
copy kept let `wrap<KEY>wrap` through; the unanchored patterns catch it.
"""
from __future__ import annotations

from willow_mcp import observability as obs
from willow_mcp import push_executor as px
from willow_mcp import secret_scan
from willow_mcp.nest import secrets as nest_secrets

AWS = "AKIA" + "Q" * 16


def test_a_key_glued_to_letters_is_taken_out_through_every_door():
    glued = f"wrap{AWS}wrap"
    out, kinds = secret_scan.redact_egress({"v": glued})
    assert AWS not in out["v"] and kinds == ["aws_access_key_id"]
    assert AWS not in secret_scan.redact_journal_tail(glued)[0]
    assert ("aws_access_key", AWS) in nest_secrets.find_secrets(glued)
    assert AWS not in nest_secrets.redact_text(glued)
    assert AWS not in px._redact(glued)
    assert AWS not in obs._redact_str(glued)
