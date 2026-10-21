"""willow-mcp reaches the canonical-bytes encodings through the one reach
(flatten-2 F7). The bytes themselves are pinned in ``test_canon_goldens.py``;
this holds the reach: found, and said plainly when it is not (never a fallback
to a copy of the ``json.dumps`` call)."""

from __future__ import annotations

import pytest

from willow_mcp import bound_receipt, onescript_canon


def test_family_is_the_one_scripts_named_encoding():
    enc = onescript_canon.family("sorted_compact_utf8")
    assert enc.version == "wgrv-canon-a/v1"
    assert enc({"b": 1, "a": "é"}) == '{"a":"é","b":1}'
    assert onescript_canon.family("wgrv-canon-b/v1").name == "sorted_compact_ascii"


def test_every_family_willow_mcp_uses_exists_in_the_one_script():
    for name in (
        "sorted_compact_utf8",
        "sorted_compact_ascii",
        "sorted_compact_ascii_default_str",
        "compact_utf8",
        "compact_ascii",
        "sorted_spaced_ascii",
    ):
        assert onescript_canon.family(name).name == name


def test_unreachable_is_said_with_why_and_never_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("ONESCRIPT_HOME", str(tmp_path / "nowhere"))
    monkeypatch.setattr(onescript_canon, "_canon", None)
    with pytest.raises(onescript_canon.Unreachable) as e:
        onescript_canon.family("compact_utf8")
    assert "ONESCRIPT_HOME" in str(e.value)
    # a hash that cannot be computed the persisted way is not computed another way
    with pytest.raises(onescript_canon.Unreachable):
        bound_receipt.ledger_entry_hash("p", "ts", "app", "tool", "out", None)


def test_importing_willow_mcp_does_not_need_the_one_script(tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    src = str(Path(onescript_canon.__file__).resolve().parents[1])
    env = {"PATH": "/usr/bin", "PYTHONPATH": src, "ONESCRIPT_HOME": str(tmp_path / "nowhere")}
    r = subprocess.run(
        [sys.executable, "-c", "import willow_mcp.receipts, willow_mcp.bound_receipt, willow_mcp.session_signing"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr


# -- the trust owner's code stays off the reach --------------------------------
#
# Operator ruling 2026-10-21: privileged steps run only code from the root-owned
# venv, never from an operator-writable checkout (tests/test_trust_venv_preflight.py),
# and the one script is a sibling checkout. The modules the trust owner's apply
# path imports (the manifest-grant / envelope / constitutional closure, found by
# following willow_mcp imports from cli_manifest_grant, trust_owner_verbs,
# manifest_grant_executor, mcp_federation, envelope_authoring and install_steps/*)
# therefore keep their own ``json.dumps`` and are held to the named family here.


def _fam(name):
    return onescript_canon.family(name)


def test_trust_owner_modules_keep_their_own_code_and_match_their_family():
    import hashlib

    from willow_mcp import (
        constitutional,
        dispatch_signing,
        egress_authorization,
        envelope_authoring,
        governance_ledger,
        manifest_grant_executor,
        net_signer,
        receipts,
        session_binder,
        session_signing,
        training_corpus,
        trust_owner_verbs,
    )

    cases = [
        {"app_id": "ä☃", "permissions": ["é"], "d": {"k": "\U0001d11e", "b": None, "a": [1]}},
        {},
        {"b": 1, "a": 2, "B": 3, "é": 4},
    ]
    for m in cases:
        a, b = _fam("sorted_compact_utf8"), _fam("sorted_compact_ascii")
        assert egress_authorization._canonical_payload(m) == a.bytes(m)
        assert envelope_authoring._bounds_digest(m) == hashlib.sha256(a.bytes(m)).hexdigest()
        row = {k: m.get(k) for k in trust_owner_verbs._DIGEST_FIELDS}
        assert trust_owner_verbs._proposal_digest(m) == hashlib.sha256(a.bytes(row)).hexdigest()
        assert dispatch_signing._canonical_bytes(dict(m, signature="s")) == b.bytes(m)
        assert manifest_grant_executor._canonical_request_bytes(m) == b.bytes(
            {k: m.get(k) for k in (
                "pair_id", "envelope_id", "citation_id", "apps", "groups",
                "pre_state", "requested_at", "sealed_row",
            )}
        )
        assert constitutional._canonical_json(m) == b(m)
        assert training_corpus._canonical(m) == _fam("sorted_compact_ascii_default_str")(m)
        assert governance_ledger._payload("ev", m) == _fam("sorted_spaced_ascii")(
            {"event_type": "ev", "content": m}
        )
    e = _fam("compact_utf8")
    assert net_signer.seal_message("s é", "t ☃", "v") == e.bytes(["s é", "t ☃", "v"])
    h = hashlib.sha256(e.bytes(["p", "ts", "a", "t", "o", "dé"])).hexdigest()
    assert receipts._entry_hash("p", "ts", "a", "t", "o", "dé") == h
    # session_signing is in the trust closure (human_session imports it), so it
    # keeps its own json.dumps; held to the same family here.
    assert session_signing._message("ä", "s☃", "v", "2026") == e.bytes(["ä", "s☃", "v", "2026"])
    assert session_binder.call_sig(b"k", "s☃", "a", "t", "n") == __import__("hmac").new(
        b"k", _fam("compact_ascii").bytes(["call", "s☃", "a", "t", "n"]), hashlib.sha256
    ).hexdigest()


def test_subject_consent_core_keeps_its_stdlib_charter_and_matches_family_b():
    """core.py runs on the child's device with no package-local import
    (test_subject_consent.py::test_core_imports_stdlib_only), so it keeps its
    own ``json.dumps``; it is ``sorted_compact_ascii`` byte for byte."""
    from willow_mcp.subject_consent import core

    for m in ({"a": "é☃", "b": [1, None]}, {}, {"b": 1, "a": 2, "B": 3}):
        assert core._canonical(m) == _fam("sorted_compact_ascii").bytes(m)
