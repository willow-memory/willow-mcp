"""Tests for the serve keyring drop-in (assignment 16BAEFD8) and the ring
drift check (amendment 785E55E3).

Build item 1: a tracked drop-in template rendering @WILLOW_KEYRING@ via the
SAME resolver the reloader uses. Build item 3: unit_install_executor grows
narrow `.d/` drop-in support, judged as [parent, dropin] under the existing
unit.install verb -- no enable/start, daemon-reload only. Build item 5 (on
server.py's diagnostic_summary): a pending syscall-table amendment that
cannot be verified reads `problem`, never `ok`. The amendment: a
`keyring_drift` check comparing the source ring to the public ring.
"""
import json
import os
import subprocess

import pytest

from willow_mcp import net_signer
from willow_mcp import reloader
from willow_mcp import server
from willow_mcp import unit_install_executor as uix

from tests.test_unit_install import _FakeGovernancePg, _Fake, _charter, _ledger

PARENT_UNIT = "willow-mcp-serve.service"
DROPIN_UNIT = "willow-mcp-serve.service.d/keyring.conf"
DROPIN_SRC = "willow-memory/willow-mcp@deploy/willow-mcp-serve.service.d/keyring.conf.template"
DROPIN_TEMPLATE = (
    "# unit: willow-mcp-serve.service.d/keyring.conf\n"
    "[Service]\n"
    'Environment="WILLOW_KEYRING=@WILLOW_KEYRING@"\n'
)

PUBKEY_HEX = "11" * 32
PUBKEY_HEX_2 = "22" * 32


def _gh_root(tmp_path, content):
    clone = tmp_path / "gh" / "willow-memory" / "willow-mcp"
    (clone / ".git").mkdir(parents=True)
    target = clone / "deploy" / "willow-mcp-serve.service.d" / "keyring.conf.template"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return tmp_path / "gh"


def _dropin_runner(fake):
    def runner(argv, **kw):
        if argv[:2] == ["systemctl", "show"]:
            # Simulate the net-signer unit being unreachable so
            # reloader._resolve_keyring_path falls through to
            # net_signer.default_ring_path(), which tests monkeypatch.
            return subprocess.CompletedProcess(argv, 1, "", "could not be found")
        return fake(argv, **kw)
    return runner


def _install_dropin(monkeypatch, pg, fake, github_root, dest, ring_path, **kw):
    monkeypatch.setattr(net_signer, "default_ring_path", lambda: ring_path)
    args = dict(app_id="willow", unit=DROPIN_UNIT, source=DROPIN_SRC, project="willow-mcp",
                ledger=_ledger(pg), runner=_dropin_runner(fake), github_root=github_root,
                destination=dest)
    args.update(kw)
    return uix.execute_unit_install(args.pop("app_id"), **args)


# ── build item 2: one shared resolver, not a copy ───────────────────────────

def test_resolve_keyring_path_is_the_same_function_object():
    assert reloader.resolve_keyring_path is reloader._resolve_keyring_path


def test_render_dropin_values_refuses_when_ring_not_a_file(monkeypatch, tmp_path):
    missing = tmp_path / "no-such-ring.json"
    monkeypatch.setattr(net_signer, "default_ring_path", lambda: missing)

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "could not be found")

    with pytest.raises(ValueError, match="is not a file"):
        uix.render_dropin_values(PARENT_UNIT, "keyring.conf", runner=runner)


def test_render_dropin_values_fills_from_the_resolved_ring(monkeypatch, tmp_path):
    ring = tmp_path / "verifiers.public.json"
    ring.write_text("{}")
    monkeypatch.setattr(net_signer, "default_ring_path", lambda: ring)

    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, "", "could not be found")

    vals = uix.render_dropin_values(PARENT_UNIT, "keyring.conf", runner=runner)
    assert vals["WILLOW_KEYRING"] == str(ring)


def test_render_dropin_values_other_names_fall_back_unchanged(monkeypatch, tmp_path):
    called = []
    monkeypatch.setattr(net_signer, "default_ring_path",
                         lambda: called.append(1) or tmp_path / "unused")
    vals = uix.render_dropin_values(PARENT_UNIT, "override.conf", runner=lambda a, **k: None)
    assert not called
    assert "WILLOW_KEYRING" not in vals or vals is not None


# ── build item 3: the `.d/` shape and its narrow admission ─────────────────

def test_dropin_re_matches_the_documented_shape():
    m = uix._DROPIN_RE.match(DROPIN_UNIT)
    assert m is not None
    assert m.group(1) == PARENT_UNIT
    assert m.group(3) == "keyring.conf"


def test_dropin_re_rejects_a_whole_unit():
    assert uix._UNIT_RE.match(PARENT_UNIT)
    assert not uix._DROPIN_RE.match(PARENT_UNIT)


def test_dropin_install_happy_path_writes_and_reloads_only(tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, units=(PARENT_UNIT, DROPIN_UNIT), sources=(DROPIN_SRC,))
    gh = _gh_root(tmp_path, DROPIN_TEMPLATE)
    dest = tmp_path / "systemd-user"
    dest.mkdir()
    ring = tmp_path / "verifiers.public.json"
    ring.write_text("{}")
    pg = _FakeGovernancePg()
    fake = _Fake()

    out = _install_dropin(monkeypatch, pg, fake, gh, dest, ring)

    assert out["ok"] is True, out
    assert out["installed"] is True
    written = dest / f"{PARENT_UNIT}.d" / "keyring.conf"
    assert written.is_file()
    assert f"WILLOW_KEYRING={ring}" in written.read_text()
    assert out["judged_units"] == [PARENT_UNIT, DROPIN_UNIT]
    assert not any(c[0] == "systemctl" and "enable" in c for c in fake.calls)
    assert any(c == ["systemctl", "--user", "daemon-reload"] for c in fake.calls)


def test_dropin_against_broker_unit_with_environment_only_is_admitted(tmp_path, monkeypatch):
    # The assignment's whole point: a drop-in AGAINST the broker's own unit
    # (willow-mcp-serve.service) is admitted -- the whole-unit EPERM guard
    # does not apply to a `.d/` drop-in, only the narrower content guard.
    _charter(tmp_path, monkeypatch, units=(PARENT_UNIT, DROPIN_UNIT), sources=(DROPIN_SRC,))
    gh = _gh_root(tmp_path, DROPIN_TEMPLATE)
    dest = tmp_path / "systemd-user"
    dest.mkdir()
    ring = tmp_path / "verifiers.public.json"
    ring.write_text("{}")
    pg = _FakeGovernancePg()
    fake = _Fake()

    out = _install_dropin(monkeypatch, pg, fake, gh, dest, ring)
    assert out["ok"] is True, out


def test_dropin_against_broker_unit_refuses_execstart_override(tmp_path, monkeypatch):
    # A drop-in against the broker's own unit that tries to change WHAT it
    # runs (ExecStart=) is exactly the hole the whole-unit EPERM closed --
    # the content-level guard must refuse it too, even though the whole-unit
    # check no longer applies to `.d/` targets.
    malicious = (
        "# unit: willow-mcp-serve.service.d/keyring.conf\n"
        "[Service]\n"
        "Environment=\"WILLOW_KEYRING=@WILLOW_KEYRING@\"\n"
        "ExecStart=/bin/sh -c 'evil'\n"
    )
    _charter(tmp_path, monkeypatch, units=(PARENT_UNIT, DROPIN_UNIT), sources=(DROPIN_SRC,))
    gh = _gh_root(tmp_path, malicious)
    dest = tmp_path / "systemd-user"
    dest.mkdir()
    ring = tmp_path / "verifiers.public.json"
    ring.write_text("{}")
    pg = _FakeGovernancePg()
    fake = _Fake()

    out = _install_dropin(monkeypatch, pg, fake, gh, dest, ring)
    assert out["error"] == "EPERM"
    assert not (dest / f"{PARENT_UNIT}.d" / "keyring.conf").exists()


def test_dropin_against_broker_unit_refuses_a_unit_section(tmp_path, monkeypatch):
    malicious = (
        "# unit: willow-mcp-serve.service.d/keyring.conf\n"
        "[Unit]\n"
        "Description=sneaky\n"
        "[Service]\n"
        "Environment=\"WILLOW_KEYRING=@WILLOW_KEYRING@\"\n"
    )
    _charter(tmp_path, monkeypatch, units=(PARENT_UNIT, DROPIN_UNIT), sources=(DROPIN_SRC,))
    gh = _gh_root(tmp_path, malicious)
    dest = tmp_path / "systemd-user"
    dest.mkdir()
    ring = tmp_path / "verifiers.public.json"
    ring.write_text("{}")
    pg = _FakeGovernancePg()
    fake = _Fake()

    out = _install_dropin(monkeypatch, pg, fake, gh, dest, ring)
    assert out["error"] == "EPERM"


def test_dropin_against_a_non_broker_unit_is_unaffected_by_the_content_guard(tmp_path, monkeypatch):
    # The content guard is scoped to a broker-unit PARENT only -- a drop-in
    # for any other already-installed unit is judged solely by the existing
    # envelope bounds and broker_units_named(), exactly as before.
    other_unit = "nestor-ui.service"
    other_dropin = f"{other_unit}.d/keyring.conf"
    other_src = "willow-memory/willow-mcp@deploy/nestor-ui.service.d/keyring.conf.template"
    content = (
        f"# unit: {other_dropin}\n"
        "[Service]\n"
        "Environment=\"WILLOW_KEYRING=@WILLOW_KEYRING@\"\n"
        "ExecStartPost=/bin/true\n"
    )
    _charter(tmp_path, monkeypatch, units=(other_unit, other_dropin), sources=(other_src,))
    clone = tmp_path / "gh" / "willow-memory" / "willow-mcp"
    (clone / ".git").mkdir(parents=True)
    target = clone / "deploy" / "nestor-ui.service.d" / "keyring.conf.template"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    gh = tmp_path / "gh"
    dest = tmp_path / "systemd-user"
    dest.mkdir()
    ring = tmp_path / "verifiers.public.json"
    ring.write_text("{}")
    pg = _FakeGovernancePg()
    fake = _Fake()

    monkeypatch.setattr(net_signer, "default_ring_path", lambda: ring)
    out = uix.execute_unit_install(
        "willow", unit=other_dropin, source=other_src, project="willow-mcp",
        ledger=_ledger(pg), runner=_dropin_runner(fake), github_root=gh, destination=dest,
    )
    assert out["ok"] is True, out


def test_dropin_install_name_mismatch_is_ENAME(tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, units=(PARENT_UNIT, DROPIN_UNIT), sources=(DROPIN_SRC,))
    bad_template = DROPIN_TEMPLATE.replace(
        "# unit: willow-mcp-serve.service.d/keyring.conf",
        "# unit: some-other.service.d/keyring.conf",
    )
    gh = _gh_root(tmp_path, bad_template)
    dest = tmp_path / "systemd-user"
    dest.mkdir()
    ring = tmp_path / "verifiers.public.json"
    ring.write_text("{}")
    pg = _FakeGovernancePg()
    fake = _Fake()

    out = _install_dropin(monkeypatch, pg, fake, gh, dest, ring)
    assert out["error"] == "ENAME"


def test_dropin_install_refuses_when_ring_missing(tmp_path, monkeypatch):
    _charter(tmp_path, monkeypatch, units=(PARENT_UNIT, DROPIN_UNIT), sources=(DROPIN_SRC,))
    gh = _gh_root(tmp_path, DROPIN_TEMPLATE)
    dest = tmp_path / "systemd-user"
    dest.mkdir()
    missing_ring = tmp_path / "no-such-ring.json"
    pg = _FakeGovernancePg()
    fake = _Fake()

    out = _install_dropin(monkeypatch, pg, fake, gh, dest, missing_ring)
    assert out["error"] == "ETEMPLATE"
    assert not (dest / f"{PARENT_UNIT}.d" / "keyring.conf").exists()


# ── build item 5: syscall_amendments must never read `ok` unverifiable ──────

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


# ── amendment 785E55E3: keyring_drift ────────────────────────────────────────

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


def test_diag_keyring_drift_name_missing_from_public_is_drift(monkeypatch, tmp_path):
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(src, [_entry("alice"), _entry("newkey", key_hex=PUBKEY_HEX_2)])
    _write_public_ring(pub, [_entry("alice")])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    assert out["status"] == "drift"
    assert "newkey" in out["drift_names"]


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


def test_diag_keyring_drift_never_leaks_key_material(monkeypatch, tmp_path):
    src, pub = tmp_path / "source.json", tmp_path / "public.json"
    _write_source_ring(src, [_entry("alice", key_hex=PUBKEY_HEX)])
    _write_public_ring(pub, [_entry("alice", key_hex=PUBKEY_HEX)])
    monkeypatch.setenv("WILLOW_KEYRING", str(src))
    monkeypatch.setattr(reloader, "resolve_keyring_path", lambda: (pub, "test"))
    out = server._diag_keyring_drift()
    blob = json.dumps(out)
    assert PUBKEY_HEX not in blob
