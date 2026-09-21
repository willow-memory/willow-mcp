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
#
# Rework (Loki audit 04472e32, finding 4): a grant must be bound to what was
# actually SEALED, not to the mutable SOIL record alone. `_seal()` now also
# writes a matching row into `home/nestor.db` (the default nestor.db path
# `seal_handler._nestor_db_path()` resolves to under the `home` fixture's
# WILLOW_HOME) whose `target_text` is the strict grammar
# `mgx.ruling_text()` produces — the artifact `execute_manifest_grant` binds
# the grant to. Tests that want a MISMATCH between what was sealed and what
# the record now says pass `seal_seats=`/`seal_groups=` explicitly.


def _write_nestor_pair(home, pair_id, target_text, *, verifier="sean",
                        status="sealed", seal_sig="stub-seal-sig"):
    """A minimal `tm_pairs` row — the same shape `tests/test_net_authority.py`
    and `tests/test_reloader.py` use — under `home/nestor.db`."""
    import sqlite3

    db = home / "nestor.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tm_pairs (
            id TEXT PRIMARY KEY, source_text TEXT NOT NULL, source_norm TEXT NOT NULL,
            source_lang TEXT NOT NULL, target_text TEXT NOT NULL, target_lang TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft', verifier TEXT NOT NULL DEFAULT '',
            weight REAL NOT NULL DEFAULT 1.0, origin TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, seal_sig TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '', superseded_by TEXT NOT NULL DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'internal'
        );
    """)
    conn.execute(
        "INSERT OR REPLACE INTO tm_pairs (id, source_text, source_norm, source_lang, "
        "target_text, target_lang, status, verifier, created_at, seal_sig) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (pair_id, "test grant", "test grant", "decision", target_text, "decision",
         status, verifier, "2026-09-21T00:00:00Z", seal_sig),
    )
    conn.commit()
    conn.close()


def _seal(home, store, *, pair_id="pair-mg-1", verifier="sean", status="sealed",
          seats=("kart",), groups=("store_read",),
          seal_seats=None, seal_groups=None, write_nestor_pair=True,
          nestor_status="sealed", nestor_seal_sig="stub-seal-sig", **overrides):
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
    if write_nestor_pair and status == "sealed" and seats is not None and groups is not None:
        sealed_seats = list(seal_seats) if seal_seats is not None else list(seats)
        sealed_groups = list(seal_groups) if seal_groups is not None else list(groups)
        target_text = mgx.ruling_text(sealed_seats, sealed_groups)
        _write_nestor_pair(home, pair_id, target_text, verifier=verifier,
                            status=nestor_status, seal_sig=nestor_seal_sig)
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
    _seal(home, store, status="proposed")
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EACCES"
    assert "sealed" in out["reason"]


def test_unknown_verifier_is_eacces(home, tmp_path, store):
    """The keyring has no verifier registered at all — 'sean' is unknown."""
    _seal(home, store, verifier="sean")
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
            _seal(home, store, verifier="sean")
            out = mgx.execute_manifest_grant(
                "willow", envelope_id="", pair_id="pair-mg-1",
                ledger=_ledger(_FakeGovernancePg()), store=store,
            )
        finally:
            keyring_mod.set_keyring(None)
    assert out["error"] == "EACCES"


def test_malformed_seats_is_einval(home, tmp_path, store, ring_with_sean):
    _seal(home, store, seats=[])
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EINVAL"


def test_malformed_groups_is_einval(home, tmp_path, store, ring_with_sean):
    _seal(home, store, groups=None)
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "EINVAL"


def test_escalation_group_refused_even_when_sealed(home, tmp_path, monkeypatch, store, ring_with_sean):
    """Sealed, known verifier, envelope bounds would even cover it — refused
    anyway because full_access is on the escalation list.

    Loki audit 04472e32 (finding 2): the escalation set is EXACTLY the
    packet's list (task_net, integration_net, web_net, mcp_federation,
    grove_relay, orchestrator, context, binding, full_access, envelope_apply,
    envelope_write, frank_write, governance_propose, governance_sync) — not
    the much broader gate-derived list a prior draft used, which refused
    this verb's own first live pair (10ed2707, naming grove_write).
    store_write is grantable through this verb now; full_access still is not."""
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("full_access",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("full_access",))
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["error"] == "EPERM"
    assert "full_access" in out["escalating"]


def test_escalation_groups_is_exactly_the_packet_list():
    assert mgx.ESCALATION_GROUPS == {
        "task_net", "integration_net", "web_net", "mcp_federation", "grove_relay",
        "orchestrator", "context", "binding", "full_access",
        "envelope_apply", "envelope_write", "frank_write",
        "governance_propose", "governance_sync",
    }
    assert "grove_write" not in mgx.ESCALATION_GROUPS
    assert "store_write" not in mgx.ESCALATION_GROUPS


def test_grove_write_pair_shaped_grant_is_granted(home, tmp_path, monkeypatch, store, ring_with_sean):
    """The live pair 10ed2707 shape: two seats, grove_read + grove_write.
    Neither group is on the trimmed escalation list, so a sealed pair naming
    them is granted, not refused."""
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _charter(tmp_path, monkeypatch, apps=("hanuman", "loki"),
             groups=("grove_read", "grove_write"))
    _manifest(home, "hanuman")
    _manifest(home, "loki")
    _seal(home, store, seats=("hanuman", "loki"), groups=("grove_read", "grove_write"))

    pg = _FakeGovernancePg()
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )

    assert out["ok"] is True, out
    assert {g["app_id"] for g in out["granted"]} == {"hanuman", "loki"}
    for seat in ("hanuman", "loki"):
        manifest = json.loads((home / "mcp_apps" / seat / "manifest.json").read_text())
        assert set(manifest["permissions"]) == {"grove_read", "grove_write"}


def test_no_active_envelope_is_enoent(home, tmp_path, monkeypatch, store, ring_with_sean):
    """A registry exists (so the read succeeds) but grants nothing to
    'willow' for this verb — zero matches is ENOENT, not a read failure."""
    _charter(tmp_path, monkeypatch, grantee="someone-else", apps=("kart",), groups=("store_read",))
    _seal(home, store)
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store,
    )
    assert out["error"] == "ENOENT"


def test_group_outside_bounds_is_eambig(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("knowledge_read",))
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["error"] == "EAMBIG"


def test_app_outside_bounds_is_eambig(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "hanuman")
    _seal(home, store, seats=("hanuman",), groups=("store_read",))
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["error"] == "EAMBIG"


def test_seat_with_no_manifest_is_refused_not_created(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, apps=("ghost",), groups=("store_read",))
    _seal(home, store, seats=("ghost",), groups=("store_read",))
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
    _seal(home, store, seats=("kart", "hanuman"), groups=("store_read", "knowledge_read"))

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
    _seal(home, store, seats=("kart",), groups=("store_read",))

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
    _seal(home, store, seats=("kart",), groups=("store_read",))

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
    _seal(home, store, seats=("kart",), groups=("store_read",))

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
    _seal(home, store, seats=("kart", "hanuman"), groups=("store_read",))

    # The write path now signs a STAGED candidate in an anonymous tempdir
    # (`manifest_admin._signed_candidate`), so the path no longer names
    # which seat is being signed — key the forced failure off call order
    # instead: kart (seat 1) signs fine, hanuman (seat 2) does not.
    real_sign = pgp.sign_detached
    calls = {"n": 0}

    def _flaky(path):
        calls["n"] += 1
        if calls["n"] >= 2:
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
    _seal(home, store, seats=("kart",), groups=("store_read",))

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


# ── pre-state signature verification (Loki finding 3) ────────────────────────

def test_tampered_manifest_is_refused_esig_prestate_bytes_untouched(
    home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env,
):
    """A manifest whose current `.sig` does not verify (hand-edited after
    signing) must never be laundered into a freshly valid signature by a
    grant that only cares about the new content — it stays denied, and
    nothing on disk moves."""
    from willow_mcp import pgp

    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    path = _manifest(home, "kart", permissions=["store_write"])
    ok, _ = pgp.sign_detached(path)
    assert ok
    # Hand-edit AFTER signing: the .sig on disk no longer matches the content.
    path.write_text(json.dumps({"app_id": "kart", "permissions": ["store_write", "full_access"]}))
    before_bytes = path.read_bytes()
    before_sig = (path.parent / "manifest.json.sig").read_bytes()
    _seal(home, store, seats=("kart",), groups=("store_read",))

    pg = _FakeGovernancePg()
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )

    assert out["ok"] is False
    assert out["refused"][0]["error"] == "esig_prestate"
    assert path.read_bytes() == before_bytes
    assert (path.parent / "manifest.json.sig").read_bytes() == before_sig
    assert not _receipts(pg)


def test_signed_manifest_with_no_fingerprint_is_refused_efingerprint_absent(
    home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env,
):
    """A manifest that already carries a detached signature must never be
    overwritten unsigned just because WILLOW_PGP_FINGERPRINT dropped out of
    the environment (Loki finding 5 / probe P2)."""
    from willow_mcp import pgp

    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    path = _manifest(home, "kart")
    ok, _ = pgp.sign_detached(path)
    assert ok
    before_bytes = path.read_bytes()
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _seal(home, store, seats=("kart",), groups=("store_read",))

    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )

    assert out["ok"] is False
    assert out["refused"][0]["error"] == "efingerprint_absent"
    assert path.read_bytes() == before_bytes


# ── bind to the seal, not the mutable record (Loki finding 4) ────────────────

def test_record_edited_after_seal_is_refused_eseal_mismatch(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """The SOIL governance record is mutable after the seal lands
    (`seal_handler.on_seal` keeps upgrading it in place); the sealed text in
    nestor.db is not. Editing `groups` on the record post-seal must be
    refused, not silently executed."""
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read", "knowledge_read"))
    _manifest(home, "kart")
    # Sealed text says store_read only; the record now (falsely) also claims
    # knowledge_read was granted — as if someone edited it after the seal.
    _seal(home, store, seats=("kart",), groups=("store_read", "knowledge_read"),
          seal_groups=("store_read",))

    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )

    assert out["error"] == "eseal_mismatch"
    kart_manifest = json.loads((home / "mcp_apps" / "kart" / "manifest.json").read_text())
    assert kart_manifest["permissions"] == []


def test_unsealed_nestor_pair_is_refused_eacces_even_if_soil_record_says_sealed(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """The SOIL record alone saying status=sealed is not enough — the pair
    itself must be sealed in nestor.db."""
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), nestor_status="draft")

    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["error"] == "EACCES"


def test_unparseable_sealed_text_is_refused_einval(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), write_nestor_pair=False)
    _write_nestor_pair(home, "pair-mg-1", "grant kart store_read please, thanks")

    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()), store=store, apps_root=home / "mcp_apps",
    )
    assert out["error"] == "EINVAL"


def test_ruling_text_round_trips():
    text = mgx.ruling_text(["kart", "hanuman"], ["store_read", "knowledge_read"])
    parsed = mgx._parse_ruling_text(text)
    assert parsed == {"apps": ["kart", "hanuman"], "groups": ["store_read", "knowledge_read"]}


# ── OSError during the write path is `eperm`, never an escaped exception
#    (Loki finding 1) ────────────────────────────────────────────────────────

def test_permission_error_during_write_is_refused_eperm_and_rolled_back(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """A trust root this uid cannot write (Loki probe P5: mcp_apps owned by
    a different uid on the live box) must come back as a structured `eperm`
    refusal naming the path — never an escaped PermissionError, and never a
    grant left half-applied across seats."""
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _charter(tmp_path, monkeypatch, apps=("kart", "hanuman"), groups=("store_read",))
    kart_manifest = _manifest(home, "kart")
    _manifest(home, "hanuman")
    kart_before = kart_manifest.read_bytes()
    _seal(home, store, seats=("kart", "hanuman"), groups=("store_read",))

    from willow_mcp import manifest_admin

    real_set_permission = manifest_admin.set_permission

    def _flaky(app_id, perm, granted, **kwargs):
        if app_id == "hanuman":
            raise PermissionError(f"[Errno 13] Permission denied: 'mcp_apps/{app_id}/manifest.json'")
        return real_set_permission(app_id, perm, granted, **kwargs)

    monkeypatch.setattr(manifest_admin, "set_permission", _flaky)

    pg = _FakeGovernancePg()
    out = mgx.execute_manifest_grant(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps",
    )

    assert out["ok"] is False
    assert out["error"] == "eperm"
    assert out["refused"][0]["app_id"] == "hanuman"
    assert out["refused"][0]["path"].endswith("hanuman/manifest.json")
    assert kart_manifest.read_bytes() == kart_before
    assert not _receipts(pg)
