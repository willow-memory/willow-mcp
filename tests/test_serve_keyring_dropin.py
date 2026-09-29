"""Tests for the serve keyring resolution (amendment 16BAEFD8/785E55E3,
reworked per Loki 5003520D REVISE -- "resolve, don't install"). Build item
1: unit.install refuses every `.d/` drop-in outright, including against the
broker's own unit -- no drop-in install path exists any more. Build item 5
(server.py's diagnostic_summary): a pending syscall-table amendment that
cannot be verified reads `problem`, never `ok`. The amendment: a
`keyring_drift` check comparing the source ring to the public ring, with a
distinct `same_file` state when they resolve to one file (F5).
"""
import json
import os

import pytest

from willow_mcp import reloader
from willow_mcp import server
from willow_mcp import unit_install_executor as uix

PARENT_UNIT = "willow-mcp-serve.service"
DROPIN_UNIT = "willow-mcp-serve.service.d/keyring.conf"
DROPIN_SRC = "willow-memory/willow-mcp@deploy/willow-mcp-serve.service.d/keyring.conf.template"

PUBKEY_HEX = "11" * 32
PUBKEY_HEX_2 = "22" * 32


# -- Remove item 1: the drop-in install path is gone; `.d/` is refused ------

def test_unit_re_still_refuses_every_dropin_shape():
    assert uix._UNIT_RE.match(PARENT_UNIT)
    assert not uix._UNIT_RE.match(DROPIN_UNIT)


def test_dropin_helpers_were_removed():
    for name in ("_DROPIN_RE", "_execute_dropin_install", "render_dropin_values",
                 "_dropin_broker_content_violation", "_DROPIN_BROKER_ALLOWED_KEYS"):
        assert not hasattr(uix, name), f"{name} should have been removed (resolve, don't install)"


def test_unit_install_refuses_a_dropin_on_the_broker_unit():
    out = uix.execute_unit_install(
        "willow", unit=DROPIN_UNIT, source=DROPIN_SRC, project="willow-mcp",
    )
    assert out["ok"] is False
    assert out["installed"] is False
    assert out["error"] == "EINVAL"


def test_unit_install_refuses_a_dropin_on_a_non_broker_unit_too():
    # Not just the broker: no drop-in shape is a grantable unit.install
    # target any more -- the whole feature was removed, not narrowed.
    out = uix.execute_unit_install(
        "willow", unit="nestor-ui.service.d/keyring.conf",
        source="willow-memory/willow-mcp@deploy/nestor-ui.service.d/keyring.conf.template",
        project="willow-mcp",
    )
    assert out["ok"] is False
    assert out["error"] == "EINVAL"


def test_whole_unit_install_of_the_broker_is_still_eperm():
    # Sealed row 17 (197aafa5) stands, unamended: the broker's own unit,
    # named directly (not as a drop-in), is still never a grantable target.
    out = uix.execute_unit_install(
        "willow", unit=PARENT_UNIT,
        source="willow-memory/willow-mcp@deploy/willow-mcp-serve.service.template",
        project="willow-mcp",
    )
    assert out["ok"] is False
    assert out["error"] == "EPERM"


# -- build item 5: syscall_amendments must never read `ok` unverifiable -----

def test_diag_syscall_amendments_ok_when_keyring_ok(monkeypatch):
    from willow_mcp import constitutional
    monkeypatch.setattr(constitutional, "diff_changed_rows",
                         lambda: {"ok": True, "rows": [{"row": 18}]})
    out = server._diag_syscall_amendments({"status": "ok"})
    assert out["status"] == "ok"


def test_diag_syscall_amendments_problem_when_rows_and_keyring_not_ok(monkeypatch):
    from willow_mcp import constitutional
    monkeypatch.setattr(constitutional, "diff_changed_rows",
                         lambda: {"ok": True, "rows": [{"row": 18}]})
    out = server._diag_syscall_amendments({"status": "not_enabled"})
    assert out["status"] == "problem"
    assert out.get("fix")


def test_diag_syscall_amendments_problem_when_rows_and_no_keyring_arg(monkeypatch):
    from willow_mcp import constitutional
    monkeypatch.setattr(constitutional, "diff_changed_rows",
                         lambda: {"ok": True, "rows": [{"row": 18}]})
    out = server._diag_syscall_amendments(None)
    assert out["status"] == "problem"


def test_diag_syscall_amendments_ok_when_no_rows_even_without_keyring(monkeypatch):
    from willow_mcp import constitutional
    monkeypatch.setattr(constitutional, "diff_changed_rows", lambda: {"ok": True, "rows": []})
    out = server._diag_syscall_amendments(None)
    assert out["status"] == "ok"


def test_verdict_registries_wire_the_new_checks():
    assert server._VERDICT_SEVERITY_SUBCHECKS["syscall_amendments"] == {"problem": "error"}
    assert server._VERDICT_SEVERITY_SUBCHECKS["keyring_drift"] == {"drift": "warn"}
    assert "syscall_amendments" not in server._VERDICT_INFORMATIONAL_SUBCHECKS
    server._assert_verdict_considers({"syscall_amendments": {}, "keyring_drift": {}})


# -- amendment 785E55E3: keyring_drift ---------------------------------------

def _entry(name, key_hex=PUBKEY_HEX, kind="ed25519", revoked_at="", compromised=False):
    return {"name": name, "key": key_hex, "kind": kind, "revoked_at": revoked_at,
            "compromised": compromised, "reason": "", "created_at": "2026-01-01T00:00:00Z"}


def _write_source_ring(path, verifiers, legacy_key_hex=None):
    doc = {"version": 1, "verifiers": verifiers}
    if legacy_key_hex:
        doc["legacy_key"] = legacy_key_hex
    path.write_text(json.dumps(doc))
    if legacy_key_hex or any(v.get("kind") != "ed25519" for v in verifiers):
        os.chmod(path, 0o600)


def _write_public_ring(path, verifiers):
    path.write_text(json.dumps({"version": 1, "verifiers": verifiers, "public_only": True}))


def test_diag_keyring_drift_unreachable_without_source(monkeypatch):
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    out = server._diag_keyring_drift()
    assert out["status"] == "unreachable"


def test_diag_keyring_drift_equivalent(monkeypatch, tmp_path):
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(src, [_entry("alice")])
    _write_public_ring(pub, [_entry("alice")])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "equivalent"
    assert out["drift_names"] == []


def test_diag_keyring_drift_fingerprint_mismatch(monkeypatch, tmp_path):
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(src, [_entry("alice", key_hex=PUBKEY_HEX)])
    _write_public_ring(pub, [_entry("alice", key_hex=PUBKEY_HEX_2)])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "drift"
    assert out["drift_names"] == ["alice"]
    assert out.get("fix")


def test_diag_keyring_drift_revoked_only_in_source_is_drift(monkeypatch, tmp_path):
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(src, [_entry("alice", revoked_at="2026-01-01T00:00:00Z")])
    _write_public_ring(pub, [_entry("alice", revoked_at="")])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "drift"
    assert "alice" in out["drift_names"]


def test_diag_keyring_drift_compromised_only_change_is_drift(monkeypatch, tmp_path):
    # L7 (Loki 5003520D): drift ignoring `compromised` survived mutation --
    # this pins it down as its own case, distinct from fingerprint/revoked.
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(src, [_entry("alice", compromised=True)])
    _write_public_ring(pub, [_entry("alice", compromised=False)])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "drift"
    assert "alice" in out["drift_names"]


def test_diag_keyring_drift_name_missing_from_public_is_drift(monkeypatch, tmp_path):
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(src, [_entry("alice"), _entry("newkey", key_hex=PUBKEY_HEX_2)])
    _write_public_ring(pub, [_entry("alice")])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "drift"
    assert "newkey" in out["drift_names"]


def test_diag_keyring_drift_public_only_name_is_drift(monkeypatch, tmp_path):
    # L8 (Loki 5003520D): drift ignoring a public-only name survived --
    # this is the reverse of the case above (extra name in PUBLIC, absent
    # from source), which no prior test exercised.
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(src, [_entry("alice")])
    _write_public_ring(pub, [_entry("alice"), _entry("ghost", key_hex=PUBKEY_HEX_2)])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "drift"
    assert "ghost" in out["drift_names"]


def test_diag_keyring_drift_hmac_and_legacy_do_not_count_as_drift(monkeypatch, tmp_path):
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(
        src,
        [_entry("alice"), {"name": "bob-hmac", "key": "aa" * 32, "kind": "hmac",
                            "revoked_at": "", "compromised": False, "reason": "",
                            "created_at": ""}],
        legacy_key_hex="bb" * 16,
    )
    _write_public_ring(pub, [_entry("alice")])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "equivalent"
    assert set(out["hmac_or_legacy_in_source"]) == {"bob-hmac", "legacy_key"}


def test_diag_keyring_drift_unreachable_when_public_missing(monkeypatch, tmp_path):
    src = tmp_path / "source.json"
    _write_source_ring(src, [_entry("alice")])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    missing_pub = tmp_path / "no-such-public.json"
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (missing_pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "unreachable"


def test_diag_keyring_drift_samefile_is_its_own_state(monkeypatch, tmp_path):
    # F5 (Loki 5003520D): once serve's own WILLOW_KEYRING IS the public
    # ring, comparing it to itself must never read "equivalent" -- it
    # proves nothing about drift.
    ring = tmp_path / "verifiers.public.json"
    _write_public_ring(ring, [_entry("alice")])
    monkeypatch.setenv("WILLOW_KEYRING", str(ring))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (ring, "net-signer-unit"))
    out = server._diag_keyring_drift()
    assert out["status"] == "same_file"
    assert out["status"] != "equivalent"


def test_diag_keyring_drift_samefile_via_symlink_is_still_its_own_state(monkeypatch, tmp_path):
    real = tmp_path / "real.json"
    _write_public_ring(real, [_entry("alice")])
    link = tmp_path / "link.json"
    link.symlink_to(real)
    monkeypatch.setenv("WILLOW_KEYRING", str(real))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (link, "net-signer-unit"))
    out = server._diag_keyring_drift()
    assert out["status"] == "same_file"


@pytest.mark.parametrize("case", ["equivalent", "drift", "unreachable", "same_file"])
def test_diag_keyring_drift_never_leaks_key_material(monkeypatch, tmp_path, case):
    # L11 (Loki 5003520D): an HMAC key hex leaking into drift output
    # survived mutation because the old test covered only the equivalent
    # state with one ed25519 pubkey. Cover all four states, with an
    # ed25519, an HMAC and a legacy fixture in the source ring each time.
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    hmac_hex = "cc" * 32
    legacy_hex = "dd" * 16
    verifiers = [
        _entry("alice", key_hex=PUBKEY_HEX),
        {"name": "bob-hmac", "key": hmac_hex, "kind": "hmac", "revoked_at": "",
         "compromised": False, "reason": "", "created_at": ""},
    ]
    _write_source_ring(src, verifiers, legacy_key_hex=legacy_hex)
    monkeypatch.setenv("WILLOW_KEYRING", str(src))

    if case == "equivalent":
        _write_public_ring(pub, [_entry("alice", key_hex=PUBKEY_HEX)])
        monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    elif case == "drift":
        _write_public_ring(pub, [_entry("alice", key_hex=PUBKEY_HEX_2)])
        monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    elif case == "unreachable":
        missing = tmp_path / "no-such-public.json"
        monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (missing, "test"))
    else:  # same_file
        monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (src, "net-signer-unit"))

    out = server._diag_keyring_drift()
    blob = json.dumps(out)
    assert PUBKEY_HEX not in blob
    assert PUBKEY_HEX_2 not in blob
    assert hmac_hex not in blob
    assert legacy_hex not in blob
