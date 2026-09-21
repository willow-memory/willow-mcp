"""The brokered manifest grant (verb 18 `manifest.grant`, sealed `d5504878`) —
a human-sealed Nestor pair names seats + groups; this process, and only this
process, appends those groups to each seat's manifest.json, signs it, and
verifies the result — never a hand-edit, never `manifest_admin.set_permission`
called from a tool (that function's own docstring forbids it). Sibling of
`test_unit_install.py`: a fake FRANK ledger + a real envelope registry in
tmp_path, the sealed pair lives in a per-test SOIL `Store`.
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone

import pytest

from willow_mcp import keyring as keyring_mod
from willow_mcp import manifest_grant_executor as mgx
from willow_mcp import seal_handler
from willow_mcp.db import Store


# ── fake FRANK ledger, same shape as test_unit_install.py ───────────────────

class _FakeGovernancePg:
    def __init__(self):
        self.rows = []

    def cursor(self):
        return _FakeGovernanceCursor(self)

    def commit(self):
        pass


class _FakeGovernanceCursor:
    def __init__(self, pg):
        self.pg = pg
        self._result = []

    def execute(self, sql, params=None):
        params = params or ()
        s = sql.strip()
        if "pg_advisory" in s:
            return
        if s.startswith("SELECT COUNT(*)"):
            envelope_id = params[0]
            self._result = [(sum(
                1 for r in self.pg.rows
                if r["event_type"] == "envelope_citation"
                and r["content"].get("envelope_id") == envelope_id
                and r["content"].get("outcome") == "granted"
            ),)]
            return
        if s.startswith("SELECT hash FROM"):
            self._result = [(self.pg.rows[-1]["hash"],)] if self.pg.rows else []
            return
        if s.startswith("SELECT id, content, created_at FROM"):
            event_type = params[0]
            matches = [r for r in self.pg.rows if r["event_type"] == event_type]
            self._result = [(r["id"], r["content"], r.get("created_at")) for r in matches]
            return
        if s.startswith("INSERT INTO"):
            record_id, project, event_type, content, prev_hash, digest = params
            self.pg.rows.append({
                "id": record_id, "project": project, "event_type": event_type,
                "content": getattr(content, "adapted", content),
                "prev_hash": prev_hash, "hash": digest,
                "created_at": datetime.now(timezone.utc),
            })
            return
        raise AssertionError(f"unexpected SQL: {sql!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result

    def close(self):
        pass


def _ledger(pg):
    from willow_mcp.governance_ledger import GovernanceLedger
    return GovernanceLedger(pg)


def _receipts(pg):
    return [r for r in pg.rows if r["event_type"] == mgx.EVENT]


# ── registry with one manifest.grant grant ───────────────────────────────────

def _charter(tmp_path, monkeypatch, *, grantee="willow", apps=("kart",),
             groups=("store_read",), extra=None, expires="2027-01-01"):
    active = [{
        "id": "env-manifest.grant-test",
        "verb_id": 18,
        "verb": "manifest.grant",
        "grantee": grantee,
        "bounds": {"apps": list(apps), "groups": list(groups)},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": expires,
        "max_count": None,
        "use_count_source": "frank",
        "status": "active",
    }] + list(extra or [])
    table = {"verbs": [{"id": 18, "verb": "manifest.grant",
                        "bounds": {"apps": "l", "groups": "l"}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))


# ── the sealed pair (SOIL governance record + keyring verifier) ─────────────

def _seal(store, *, pair_id="pair-mg-1", verifier="sean", status="sealed",
          seats=("kart",), groups=("store_read",), **overrides):
    record = {
        "id": "grove-perms-test",
        "title": "test grant",
        "status": status,
        "nestor_pair_id": pair_id,
        "nestor_verifier": verifier,
        "seats": list(seats) if seats is not None else seats,
        "groups": list(groups) if groups is not None else groups,
    }
    record.update(overrides)
    rid, _ = store.put(seal_handler.GOVERNANCE_COLLECTION, record)
    return rid


@pytest.fixture
def store(tmp_path):
    return Store(store_root=str(tmp_path / "store"))


@pytest.fixture
def ring_with_sean(tmp_path):
    """A keyring with 'sean' active — the operator's canonical verifier for
    these tests."""
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("sean")
        k.save()
        keyring_mod.set_keyring(k)
        try:
            yield k
        finally:
            keyring_mod.set_keyring(None)


def _manifest(home, app_id, permissions=None):
    d = home / "mcp_apps" / app_id
    d.mkdir(parents=True, exist_ok=True)
    path = d / "manifest.json"
    path.write_text(json.dumps({"app_id": app_id, "permissions": permissions or []}))
    return path


# ── refusals that never touch the envelope or the seat ───────────────────────

def test_non_orchestrator_caller_is_eperm(home, tmp_path, store, ring_with_sean):
    out = mgx.execute_manifest_grant(
        "hanuman", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EPERM"
    assert not out["granted"]


def test_inside_kart_is_eunreach(home, tmp_path, monkeypatch, store):
    monkeypatch.setenv("WILLOW_IN_KART", "1")
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EUNREACH"


def test_no_governance_record_is_enoent(home, tmp_path, store):
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="no-such-pair",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "ENOENT"


def test_unsealed_pair_is_eacces(home, tmp_path, store):
    _seal(store, status="proposed")
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EACCES"
    assert "sealed" in out["reason"]


def test_unknown_verifier_is_eacces(home, tmp_path, store):
    """The keyring has no verifier registered at all — 'sean' is unknown."""
    _seal(store, verifier="sean")
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EACCES"
    assert "keyring" in out["reason"]


def test_compromised_verifier_is_eacces(home, tmp_path, store):
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("sean")
        k.revoke("sean", reason="test", compromised=True)
        k.save()
        keyring_mod.set_keyring(k)
        try:
            _seal(store, verifier="sean")
            out = mgx.execute_manifest_grant(
                "willow", envelope_id="", pair_id="pair-mg-1",
                ledger=_ledger(_FakeGovernancePg()), store=store,
            )
        finally:
            keyring_mod.set_keyring(None)
    assert out["error"] == "EACCES"


def test_malformed_seats_is_einval(home, tmp_path, store, ring_with_sean):
    _seal(store, seats=[])
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EINVAL"


def test_malformed_groups_is_einval(home, tmp_path, store, ring_with_sean):
    _seal(store, groups=None)
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EINVAL"


def test_escalation_group_refused_even_when_sealed(home, tmp_path, monkeypatch, store, ring_with_sean):
    """Sealed, known verifier, envelope bounds would even cover it — refused
    anyway because store_write is on the escalation list."""
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_write",))
    _manifest(home, "kart")
    _seal(store, seats=("kart",), groups=("store_write",))
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["error"] == "EPERM"
    assert "store_write" in out["escalating"]


def test_no_active_envelope_is_enoent(home, tmp_path, monkeypatch, store, ring_with_sean):
    """A registry exists (so the read succeeds) but grants nothing to
    'willow' for this verb — zero matches is ENOENT, not a read failure."""
    _charter(tmp_path, monkeypatch, grantee="someone-else", apps=("kart",), groups=("store_read",))
    _seal(store)
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "ENOENT"


def test_group_outside_bounds_is_eambig(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(store, seats=("kart",), groups=("knowledge_read",))
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["error"] == "EAMBIG"


def test_app_outside_bounds_is_eambig(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "hanuman")
    _seal(store, seats=("hanuman",), groups=("store_read",))
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["error"] == "EAMBIG"


def test_seat_with_no_manifest_is_refused_not_created(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, apps=("ghost",), groups=("store_read",))
    _seal(store, seats=("ghost",), groups=("store_read",))
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["ok"] is False
    assert out["refused"][0]["error"] == "enomanifest"
    assert not (home / "mcp_apps" / "ghost" / "manifest.json").exists()


# ── the happy path (unsigned — no WILLOW_PGP_FINGERPRINT) ────────────────────

def test_happy_path_two_seats_two_groups_unsigned(home, tmp_path, monkeypatch, store, ring_with_sean):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _charter(tmp_path, monkeypatch, apps=("kart", "hanuman"),
             groups=("store_read", "knowledge_read"))
    _manifest(home, "kart", permissions=["store_read"])
    _manifest(home, "hanuman")
    _seal(store, seats=("kart", "hanuman"), groups=("store_read", "knowledge_read"))

    pg = _FakeGovernancePg()
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )

    assert out["ok"] is True, out
    assert not out["refused"]
    assert {g["app_id"] for g in out["granted"]} == {"kart", "hanuman"}
    kart_manifest = json.loads((home / "mcp_apps" / "kart" / "manifest.json").read_text())
    assert set(kart_manifest["permissions"]) == {"store_read", "knowledge_read"}
    hanuman_manifest = json.loads((home / "mcp_apps" / "hanuman" / "manifest.json").read_text())
    assert set(hanuman_manifest["permissions"]) == {"store_read", "knowledge_read"}
    assert len(_receipts(pg)) == 2
    for rec in _receipts(pg):
        assert rec["content"]["pair_id"] == "pair-mg-1"
        assert set(rec["content"]["groups_added"]) <= {"store_read", "knowledge_read"}


def test_idempotent_regrant_adds_nothing_new(home, tmp_path, monkeypatch, store, ring_with_sean):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart", permissions=["store_read"])
    _seal(store, seats=("kart",), groups=("store_read",))

    pg = _FakeGovernancePg()
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )
    assert out["ok"] is True
    assert out["granted"][0]["groups"] == []


# ── signed happy path + rollback (real gpg key, same fixture shape as
#    test_pgp_manifest_signing.py) ───────────────────────────────────────────

def _gen_key(gnupghome, name, email):
    batch = gnupghome / f"{name}.batch"
    batch.write_text(
        "%no-protection\n"
        "Key-Type: EDDSA\n"
        "Key-Curve: ed25519\n"
        f"Name-Real: {name}\n"
        f"Name-Email: {email}\n"
        "Expire-Date: 0\n"
        "%commit\n"
    )
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    subprocess.run(
        ["gpg", "--batch", "--gen-key", str(batch)],
        env=env, check=True, capture_output=True, timeout=30,
    )


@pytest.fixture(scope="module")
def gpg_keypair(tmp_path_factory):
    gnupghome = tmp_path_factory.mktemp("mg_gnupghome")
    _gen_key(gnupghome, "Willow Test Operator", "test@willow.invalid")
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    out = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        env=env, check=True, capture_output=True, text=True, timeout=10,
    )
    fpr = next(line.split(":")[9] for line in out.stdout.splitlines() if line.startswith("fpr"))
    return {"gnupghome": str(gnupghome), "fingerprint": fpr}


@pytest.fixture
def pgp_env(gpg_keypair, monkeypatch):
    monkeypatch.setenv("GNUPGHOME", gpg_keypair["gnupghome"])
    monkeypatch.setenv("WILLOW_PGP_FINGERPRINT", gpg_keypair["fingerprint"])


def test_happy_path_signs_and_gate_then_authorizes(home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env):
    from willow_mcp import gate, pgp

    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    path = _manifest(home, "kart")
    pgp.sign_detached(path)  # start signed, like a real onboarded seat
    _seal(store, seats=("kart",), groups=("store_read",))

    pg = _FakeGovernancePg()
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )

    assert out["ok"] is True, out
    assert gate.authorized("kart") is True
    assert gate.permitted("kart", "store_get") is True
    assert out["granted"][0]["sig_sha256"]


def test_sign_failure_rolls_back_manifest_and_sig(home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env):
    from willow_mcp import pgp

    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    path = _manifest(home, "kart", permissions=["store_write"])
    ok, _ = pgp.sign_detached(path)
    assert ok
    before_bytes = path.read_bytes()
    before_sig = (path.parent / "manifest.json.sig").read_bytes()
    _seal(store, seats=("kart",), groups=("store_read",))

    monkeypatch.setattr(pgp, "sign_detached", lambda p: (False, "forced failure"))

    pg = _FakeGovernancePg()
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )

    assert out["ok"] is False
    assert out["refused"][0]["error"] == "esign"
    assert path.read_bytes() == before_bytes
    assert (path.parent / "manifest.json.sig").read_bytes() == before_sig
    assert not _receipts(pg)


def test_atomic_rollback_undoes_earlier_seats_in_the_same_call(
    home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env,
):
    """Two seats, second one fails to sign — atomic=True (the default) rolls
    the FIRST seat's grant back too, so a partial grant never survives a
    refused call."""
    from willow_mcp import pgp

    _charter(tmp_path, monkeypatch, apps=("kart", "hanuman"), groups=("store_read",))
    kart_path = _manifest(home, "kart")
    hanuman_path = _manifest(home, "hanuman")
    pgp.sign_detached(kart_path)
    pgp.sign_detached(hanuman_path)
    kart_before = kart_path.read_bytes()
    _seal(store, seats=("kart", "hanuman"), groups=("store_read",))

    real_sign = pgp.sign_detached

    def _flaky(path):
        if "hanuman" in str(path):
            return False, "forced failure on second seat"
        return real_sign(path)

    monkeypatch.setattr(pgp, "sign_detached", _flaky)

    pg = _FakeGovernancePg()
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )

    assert out["ok"] is False
    assert "kart" in out["rolled_back"]
    assert kart_path.read_bytes() == kart_before
    assert not _receipts(pg)


def test_frank_event_carries_before_after_digests(home, tmp_path, monkeypatch, store, ring_with_sean):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(store, seats=("kart",), groups=("store_read",))

    pg = _FakeGovernancePg()
    mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )
    receipts = _receipts(pg)
    assert len(receipts) == 1
    content = receipts[0]["content"]
    assert content["app_id"] == "kart"
    assert content["manifest_sha256_before"] != content["manifest_sha256_after"]
    assert content["groups_added"] == ["store_read"]
