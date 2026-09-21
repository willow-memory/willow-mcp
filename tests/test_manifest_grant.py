"""The brokered manifest grant (verb 18 `manifest.grant`, sealed `d5504878`,
write path split under pair `b74019ac`) — the broker never publishes.
`manifest_grant_request` verifies everything (orchestrator caller, envelope
bounds, the sealed pair's real ed25519 `seal_sig` against the keyring, the
strict grammar, no escalation group, per-seat pre-state) and writes ONE
request under `$WILLOW_HOME/manifest_grants/pending/<pair_id>.json`, citing
the envelope only after the file is durable. `manifest_grant_apply` — the
trust-owner unit, never the broker, never Kart — re-verifies fresh and does
the actual sign+publish through `manifest_admin.set_permission`, no
`privileged_publisher` (it already owns the trust root). Sibling of
`test_unit_install.py`: a fake FRANK ledger + a real envelope registry in
tmp_path, the sealed pair lives in a per-test SOIL `Store` plus a genuinely
ed25519-signed row in `home/nestor.db`.
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from willow_mcp import keyring as keyring_mod
from willow_mcp import manifest_grant_executor as mgx
from willow_mcp import net_signer as ns
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


# ── the sealed pair: a real ed25519 signature over the grammar, in
#    home/nestor.db, plus the mutable SOIL governance record ────────────────

def _write_nestor_pair(home, pair_id, target_text, *, verifier="sean",
                        status="sealed", seal_sig="stub-seal-sig",
                        created_at=None):
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
         status, verifier, created_at or datetime.now(timezone.utc).isoformat(), seal_sig),
    )
    conn.commit()
    conn.close()


def _sign_seal(kr, name, source_norm, target_text) -> str:
    entry = kr.get(name)
    priv = Ed25519PrivateKey.from_private_bytes(entry.private)
    return priv.sign(ns.seal_message(source_norm, target_text, name)).hex()


def _seal(home, store, *, pair_id="pair-mg-1", verifier="sean", status="sealed",
          seats=("kart",), groups=("store_read",),
          seal_seats=None, seal_groups=None, write_nestor_pair=True,
          nestor_status="sealed", nestor_seal_sig=None, nestor_verifier=None,
          kr=None, **overrides):
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
        sealed_verifier = nestor_verifier if nestor_verifier is not None else verifier
        if nestor_seal_sig is not None:
            sig = nestor_seal_sig
        elif kr is not None and sealed_verifier in kr.names():
            sig = _sign_seal(kr, sealed_verifier, "test grant", target_text)
        else:
            sig = "stub-seal-sig"
        _write_nestor_pair(home, pair_id, target_text, verifier=sealed_verifier,
                            status=nestor_status, seal_sig=sig)
    return rid


@pytest.fixture
def store(tmp_path):
    return Store(store_root=str(tmp_path / "store"))


@pytest.fixture
def ring_with_sean(tmp_path):
    """A keyring with a REAL ed25519 'sean' entry active — the operator's
    canonical verifier for these tests. Yields the `Keyring` so tests can
    sign with `sean`'s private half via `_sign_seal`."""
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("sean", kind="ed25519")
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


def _request(app_id="willow", *, pair_id="pair-mg-1", envelope_id="", ledger=None,
             store=None, apps_root=None, grants_root=None):
    return mgx.manifest_grant_request(
        app_id, envelope_id=envelope_id, pair_id=pair_id,
        ledger=ledger or _ledger(_FakeGovernancePg()), store=store, apps_root=apps_root,
        grants_root=grants_root,
    )


def _pending_files(grants_root):
    d = grants_root / "pending"
    return list(d.glob("*.json")) if d.is_dir() else []


# ── refusals at the REQUEST stage — never touch the envelope or a seat ──────

def test_non_orchestrator_caller_is_eperm(home, tmp_path, store, ring_with_sean):
    out = _request("hanuman", store=store)
    assert out["error"] == "EPERM"


def test_no_governance_record_is_enoent(home, tmp_path, store):
    out = _request(pair_id="no-such-pair", store=store)
    assert out["error"] == "ENOENT"


def test_unsealed_pair_is_eacces(home, tmp_path, store):
    _seal(home, store, status="proposed")
    out = _request(store=store)
    assert out["error"] == "EACCES"
    assert "sealed" in out["reason"]


def test_unknown_verifier_is_eacces(home, tmp_path, store):
    """No keyring configured at all — 'sean' cannot be checked against
    anything, so the seal is refused rather than trusted on the record's say-so."""
    _seal(home, store, verifier="sean")
    out = _request(store=store)
    assert out["error"] == "EACCES"
    assert "keyring" in out["reason"]


def test_compromised_verifier_is_eacces(home, tmp_path, store):
    with keyring_mod.isolated():
        k = keyring_mod.Keyring(path=str(tmp_path / "keys.json"))
        k.add("sean", kind="ed25519")
        k.revoke("sean", reason="test", compromised=True)
        k.save()
        keyring_mod.set_keyring(k)
        try:
            _seal(home, store, verifier="sean")
            out = _request(store=store)
        finally:
            keyring_mod.set_keyring(None)
    assert out["error"] == "EACCES"


def test_garbage_seal_sig_is_refused(home, tmp_path, store, ring_with_sean):
    """A structurally-valid-hex but wrong signature over the sealed bytes:
    the keyring KNOWS 'sean' and 'sean' is active, but the bytes do not
    verify. Loki finding: the seal binding used to compare TEXT only and
    never called net_signer.verify_seal at all — a garbage seal_sig on an
    otherwise well-formed row was granted with a receipt."""
    _seal(home, store, verifier="sean", nestor_seal_sig="ab" * 64)
    out = _request(store=store)
    assert out["error"] == "EACCES"
    assert "does not verify" in out["reason"]


def test_sealed_verifier_mismatch_is_refused(home, tmp_path, store, ring_with_sean):
    """The SOIL record's `nestor_verifier` says 'sean' (active, known-good) —
    but the SEALED ROW in nestor.db actually names 'mallory'. The seal
    signature covers (source_norm, target_text, VERIFIER), so a caller
    cannot launder an unknown verifier through a record that names someone
    else. This must be refused using the SEALED row's verifier, never the
    record's."""
    _seal(home, store, verifier="sean", nestor_verifier="mallory")
    out = _request(store=store)
    assert out["error"] == "EACCES"
    assert "mallory" in out["reason"] or "not in the ring" in out["reason"]


def test_malformed_seats_is_einval(home, tmp_path, store, ring_with_sean):
    _seal(home, store, seats=[])
    out = _request(store=store)
    assert out["error"] == "EINVAL"


def test_malformed_groups_is_einval(home, tmp_path, store, ring_with_sean):
    _seal(home, store, groups=None)
    out = _request(store=store)
    assert out["error"] == "EINVAL"


def test_escalation_group_refused_even_when_sealed(home, tmp_path, monkeypatch, store, ring_with_sean):
    """Sealed with a REAL verifiable signature, envelope bounds would even
    cover it — refused anyway because full_access is on the escalation list.
    store_write/grove_write are grantable through this verb; full_access is not."""
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("full_access",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("full_access",), kr=ring_with_sean)
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EPERM"
    assert "full_access" in out["escalating"]
    assert not _pending_files(home / "manifest_grants")


def test_escalation_groups_is_exactly_the_packet_list():
    assert mgx.ESCALATION_GROUPS == {
        "task_net", "integration_net", "web_net", "mcp_federation", "grove_relay",
        "orchestrator", "context", "binding", "full_access",
        "envelope_apply", "envelope_write", "frank_write",
        "governance_propose", "governance_sync",
    }
    assert "grove_write" not in mgx.ESCALATION_GROUPS
    assert "store_write" not in mgx.ESCALATION_GROUPS


def test_no_active_envelope_is_enoent(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, grantee="someone-else", apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, kr=ring_with_sean)
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "ENOENT"
    assert not _pending_files(home / "manifest_grants")


def test_group_outside_bounds_is_eambig(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("knowledge_read",), kr=ring_with_sean)
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EAMBIG"
    assert not _pending_files(home / "manifest_grants")


def test_seat_with_no_manifest_is_refused_enomanifest(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, apps=("ghost",), groups=("store_read",))
    _seal(home, store, seats=("ghost",), groups=("store_read",), kr=ring_with_sean)
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "enomanifest"
    assert not (home / "mcp_apps" / "ghost" / "manifest.json").exists()
    assert not _pending_files(home / "manifest_grants")


def test_record_edited_after_seal_is_refused_eseal_mismatch(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """The SOIL governance record is mutable after the seal lands
    (`seal_handler.on_seal` keeps upgrading it in place); the sealed text in
    nestor.db is not. Editing `groups` on the record post-seal must be
    refused, not silently executed."""
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read", "knowledge_read"))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read", "knowledge_read"),
          seal_groups=("store_read",), kr=ring_with_sean)
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "eseal_mismatch"
    kart_manifest = json.loads((home / "mcp_apps" / "kart" / "manifest.json").read_text())
    assert kart_manifest["permissions"] == []
    assert not _pending_files(home / "manifest_grants")


def test_unsealed_nestor_pair_is_refused_eacces_even_if_soil_record_says_sealed(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), nestor_status="draft",
          kr=ring_with_sean)
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EACCES"


def test_unparseable_sealed_text_is_refused_einval(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), write_nestor_pair=False)
    sig = _sign_seal(ring_with_sean, "sean", "test grant", "grant kart store_read please, thanks")
    _write_nestor_pair(home, "pair-mg-1", "grant kart store_read please, thanks",
                       verifier="sean", seal_sig=sig)
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EINVAL"
    assert "grammar" in out["reason"]


def test_ruling_text_round_trips():
    text = mgx.ruling_text(["kart", "hanuman"], ["store_read", "knowledge_read"])
    parsed = mgx._parse_ruling_text(text)
    assert parsed == {"apps": ["kart", "hanuman"], "groups": ["store_read", "knowledge_read"]}


# ── grammar: the two live sealed pairs (Loki audit 7518bb57) ────────────────

def test_d23a3726_exact_text_parses_to_seven_seats_two_groups():
    """Pair d23a3726, grammar form — the live grant naming all seven
    receive_dispatch specialists two groups."""
    text = (
        "willow-manifest-grant-v1 seats=hanuman,loki,jeles,ada,skirnir,heimdallr,binder "
        "groups=grove_read,grove_write\n"
        "Every specialist with receive_dispatch: true carries grove_read and "
        "grove_write. Measured 2026-09-21."
    )
    parsed = mgx._parse_ruling_text(text)
    assert parsed == {
        "apps": ["hanuman", "loki", "jeles", "ada", "skirnir", "heimdallr", "binder"],
        "groups": ["grove_read", "grove_write"],
    }


def test_10ed2707_prose_is_refused_naming_the_grammar(home, tmp_path, monkeypatch, store, ring_with_sean):
    """Pair 10ed2707's actual sealed text — prose, no grammar line — must be
    refused with a message naming the grammar this verb requires, not
    guessed at by scraping seat names out of English."""
    prose = (
        "Yes — every specialist with receive_dispatch: true in specialists.json "
        "carries grove_read and grove_write in $WILLOW_HOME/mcp_apps/<app_id>/"
        "manifest.json. Measured 2026-09-21: seven change — hanuman, loki, jeles, "
        "ada, skirnir, heimdallr, binder."
    )
    assert mgx._parse_ruling_text(prose) is None

    _charter(tmp_path, monkeypatch, apps=("hanuman", "loki", "jeles", "ada", "skirnir",
                                          "heimdallr", "binder"),
             groups=("grove_read", "grove_write"))
    for seat in ("hanuman", "loki"):
        _manifest(home, seat)
    _seal(home, store, seats=("hanuman", "loki", "jeles", "ada", "skirnir", "heimdallr", "binder"),
          groups=("grove_read", "grove_write"), write_nestor_pair=False)
    sig = _sign_seal(ring_with_sean, "sean", "test grant", prose)
    _write_nestor_pair(home, "pair-mg-1", prose, verifier="sean", seal_sig=sig)
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EINVAL"
    assert mgx.RULING_FORMAT in out["reason"]


# ── request written only after verification ─────────────────────────────────

def test_pending_file_does_not_exist_until_every_precondition_holds(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    # A refusal (bad envelope grantee) must leave no trace in pending/.
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(tmp_path / "does-not-govern-kart.json"))
    (tmp_path / "does-not-govern-kart.json").write_text(json.dumps({"active": [{
        "id": "e", "verb_id": 18, "verb": "manifest.grant", "grantee": "somebody-else",
        "bounds": {"apps": ["kart"], "groups": ["store_read"]}, "issued_by": "root",
        "issued_at": "2026-01-01", "expires_at": "2027-01-01", "max_count": None,
        "use_count_source": "frank", "status": "active",
    }]}))
    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out["error"] == "ENOENT"
    assert not _pending_files(grants_root)


def test_successful_request_writes_pending_and_cites_the_envelope(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)

    pg = _FakeGovernancePg()
    out = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(pg), store=store, apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert out["ok"] is True, out
    assert out["state"] == "requested"
    assert out["citation_id"]
    pending = _pending_files(grants_root)
    assert len(pending) == 1
    record = json.loads(pending[0].read_text())
    assert record["apps"] == ["kart"] and record["groups"] == ["store_read"]
    assert record["citation_id"] == out["citation_id"]
    assert record["pre_state"]["kart"]["manifest_sha256"]
    # a citation was actually inked — an envelope_citation row exists
    assert any(r["event_type"] == "envelope_citation" for r in pg.rows)


def test_duplicate_request_for_same_pair_is_ealready(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)
    out1 = _request(store=store, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out1["ok"] is True
    out2 = _request(store=store, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out2["error"] == "EALREADY"


# ── apply: signed happy path, rollback, status ──────────────────────────────

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


def _request_and_apply(home, store, ledger, *, apps_root, grants_root, pair_id="pair-mg-1"):
    req = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id=pair_id,
        ledger=ledger, store=store, apps_root=apps_root, grants_root=grants_root,
    )
    assert req["ok"] is True, req
    applied = mgx.manifest_grant_apply(ledger=ledger, apps_root=apps_root, grants_root=grants_root)
    return req, applied


def test_apply_happy_path_signs_and_gate_then_authorizes(
    home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env,
):
    from willow_mcp import gate, pgp

    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    path = _manifest(home, "kart")
    pgp.sign_detached(path)  # start signed, like a real onboarded seat
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req, applied = _request_and_apply(home, store, ledger, apps_root=home / "mcp_apps",
                                      grants_root=grants_root)

    assert applied["ok"] is True, applied
    result = applied["processed"][0]
    assert result["ok"] is True
    assert gate.authorized("kart") is True
    assert gate.permitted("kart", "store_get") is True
    assert result["granted"][0]["sig_sha256"]
    assert len(_receipts(pg)) == 1

    status = mgx.manifest_grant_status("pair-mg-1", grants_root=grants_root)
    assert status["state"] == "done"
    assert not _pending_files(grants_root)


def test_apply_unsigned_happy_path_two_seats(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart", "hanuman"),
             groups=("store_read", "knowledge_read"))
    _manifest(home, "kart", permissions=["store_read"])
    _manifest(home, "hanuman")
    _seal(home, store, seats=("kart", "hanuman"), groups=("store_read", "knowledge_read"),
          kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req, applied = _request_and_apply(home, store, ledger, apps_root=home / "mcp_apps",
                                      grants_root=grants_root)

    assert applied["ok"] is True, applied
    result = applied["processed"][0]
    assert result["ok"] is True
    assert {g["app_id"] for g in result["granted"]} == {"kart", "hanuman"}
    kart_manifest = json.loads((home / "mcp_apps" / "kart" / "manifest.json").read_text())
    assert set(kart_manifest["permissions"]) == {"store_read", "knowledge_read"}
    assert len(_receipts(pg)) == 2


def test_apply_failure_on_group_2_of_seat_1_rolls_back_group_1_and_withholds_receipts(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """Two groups, one seat; the second group's `set_permission` fails. The
    first group must be rolled back through the SAME staged path (never a
    byte restore), no FRANK receipt is inked, and the request lands in
    failed/, not done/."""
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read", "knowledge_read"))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read", "knowledge_read"), kr=ring_with_sean)

    from willow_mcp import manifest_admin

    real_set_permission = manifest_admin.set_permission
    calls = {"n": 0}

    def _flaky(app_id, perm, granted, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("forced failure on second group")
        return real_set_permission(app_id, perm, granted, **kwargs)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=ledger, store=store, apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert req["ok"] is True, req

    monkeypatch.setattr(manifest_admin, "set_permission", _flaky)
    applied = mgx.manifest_grant_apply(ledger=ledger, apps_root=home / "mcp_apps",
                                       grants_root=grants_root)

    assert applied["ok"] is False
    result = applied["processed"][0]
    assert result["ok"] is False
    kart_manifest = json.loads((home / "mcp_apps" / "kart" / "manifest.json").read_text())
    assert kart_manifest["permissions"] == []
    assert not _receipts(pg)

    status = mgx.manifest_grant_status("pair-mg-1", grants_root=grants_root)
    assert status["state"] == "failed"


def test_apply_rolls_back_seat_1_when_seat_2_fails(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart", "hanuman"), groups=("store_read",))
    kart_path = _manifest(home, "kart")
    _manifest(home, "hanuman")
    _seal(home, store, seats=("kart", "hanuman"), groups=("store_read",), kr=ring_with_sean)

    from willow_mcp import manifest_admin

    real_set_permission = manifest_admin.set_permission

    def _flaky(app_id, perm, granted, **kwargs):
        if app_id == "hanuman" and granted:
            raise RuntimeError("forced failure on second seat")
        return real_set_permission(app_id, perm, granted, **kwargs)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=ledger, store=store, apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert req["ok"] is True, req

    monkeypatch.setattr(manifest_admin, "set_permission", _flaky)
    applied = mgx.manifest_grant_apply(ledger=ledger, apps_root=home / "mcp_apps",
                                       grants_root=grants_root)

    assert applied["ok"] is False
    kart_manifest = json.loads(kart_path.read_text())
    assert kart_manifest["permissions"] == []
    assert not _receipts(pg)


def test_request_refuses_tampered_manifest_esig_prestate(
    home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env,
):
    """A manifest whose current `.sig` does not verify (hand-edited after
    signing) must never be laundered into a freshly valid signature by a
    grant that only cares about the new content — refused at REQUEST time,
    before anything is written to pending/."""
    from willow_mcp import pgp

    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    path = _manifest(home, "kart", permissions=["store_write"])
    ok, _ = pgp.sign_detached(path)
    assert ok
    path.write_text(json.dumps({"app_id": "kart", "permissions": ["store_write", "full_access"]}))
    before_bytes = path.read_bytes()
    before_sig = (path.parent / "manifest.json.sig").read_bytes()
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)

    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out["error"] == "esig_prestate"
    assert path.read_bytes() == before_bytes
    assert (path.parent / "manifest.json.sig").read_bytes() == before_sig
    assert not _pending_files(grants_root)


def test_request_refuses_absent_fingerprint_with_existing_sig(
    home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env,
):
    """A manifest that already carries a detached signature must never be
    overwritten unsigned just because WILLOW_PGP_FINGERPRINT dropped out of
    the environment."""
    from willow_mcp import pgp

    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    path = _manifest(home, "kart")
    ok, _ = pgp.sign_detached(path)
    assert ok
    before_bytes = path.read_bytes()
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)

    out = _request(store=store, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out["error"] == "efingerprint_absent"
    assert path.read_bytes() == before_bytes
    assert not _pending_files(grants_root)


def test_apply_sign_failure_rolls_back_manifest_and_sig(
    home, tmp_path, monkeypatch, store, ring_with_sean, pgp_env,
):
    from willow_mcp import pgp

    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    path = _manifest(home, "kart", permissions=["store_write"])
    ok, _ = pgp.sign_detached(path)
    assert ok
    before_bytes = path.read_bytes()
    before_sig = (path.parent / "manifest.json.sig").read_bytes()
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=ledger, store=store, apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert req["ok"] is True, req

    monkeypatch.setattr(pgp, "sign_detached", lambda p: (False, "forced failure"))
    applied = mgx.manifest_grant_apply(ledger=ledger, apps_root=home / "mcp_apps",
                                       grants_root=grants_root)

    assert applied["ok"] is False
    result = applied["processed"][0]
    assert result["error"] == "esign"
    assert path.read_bytes() == before_bytes
    assert (path.parent / "manifest.json.sig").read_bytes() == before_sig
    assert not _receipts(pg)
    status = mgx.manifest_grant_status("pair-mg-1", grants_root=grants_root)
    assert status["state"] == "failed"


def test_apply_inside_kart_is_refused(home, tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_IN_KART", "1")
    out = mgx.manifest_grant_apply(grants_root=home / "manifest_grants")
    assert out["error"] == "EUNREACH"


def test_apply_of_empty_pending_is_a_clean_noop(home, tmp_path):
    out = mgx.manifest_grant_apply(grants_root=home / "manifest_grants")
    assert out["ok"] is True
    assert out["state"] == "empty"


# ── status transitions ───────────────────────────────────────────────────────

# ── audit 3 (Loki, session_handoff-2026-09-21-373bc1a0): seal age is not a
#    lease; forgeable pending/; unit cannot run; rollback honesty; cross-uid
#    move loop ──────────────────────────────────────────────────────────────

def test_verify_seal_max_age_none_accepts_a_30_day_old_seal():
    """net_signer.verify_seal(max_age_s=None) — the direct unit-level claim
    behind finding 1: a governance grant is not a one-day net request."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    seal = {
        "source_norm": "x", "target_text": "y", "verifier": "sean",
        "seal_sig": priv.sign(ns.seal_message("x", "y", "sean")).hex(),
        "created_at": old,
    }
    ring = {"sean": {"key": pub, "kind": "ed25519", "revoked_at": "", "compromised": False}}
    # Default bound still refuses (net_authority.SEAL_MAX_AGE_S = 24h).
    ok, reason, field = ns.verify_seal(seal, ring)
    assert ok is False and field == "created_at"
    # max_age_s=None: no calendar age at all.
    ok2, reason2, field2 = ns.verify_seal(seal, ring, max_age_s=None)
    assert ok2 is True, (reason2, field2)


def test_d23a3726_sealed_30_days_ago_is_accepted_at_request_and_apply(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """The exact live d23a3726 line-1 text, sealed 30 days ago — this is the
    end-to-end shape Loki's Next-bite item (1) names: the live pair must
    survive past its own 24h net-authority-style age bound."""
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    grants_root = home / "manifest_grants"
    seats = ("hanuman", "loki", "jeles", "ada", "skirnir", "heimdallr", "binder")
    groups = ("grove_read", "grove_write")
    _charter(tmp_path, monkeypatch, apps=seats, groups=groups)
    for seat in seats:
        _manifest(home, seat)
    text = mgx.ruling_text(list(seats), list(groups)) + "\nMeasured 2026-09-21."
    old_created_at = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    sig = _sign_seal(ring_with_sean, "sean", "test grant", text)
    _write_nestor_pair(home, "pair-mg-1", text, verifier="sean", seal_sig=sig,
                        created_at=old_created_at)
    store.put(seal_handler.GOVERNANCE_COLLECTION, {
        "id": "grove-perms-test", "title": "test grant", "status": "sealed",
        "nestor_pair_id": "pair-mg-1", "nestor_verifier": "sean",
        "seats": list(seats), "groups": list(groups),
    })

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=ledger, store=store, apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert req["ok"] is True, req
    applied = mgx.manifest_grant_apply(ledger=ledger, apps_root=home / "mcp_apps",
                                       grants_root=grants_root)
    assert applied["ok"] is True, applied
    assert {g["app_id"] for g in applied["processed"][0]["granted"]} == set(seats)


def test_forged_pending_file_with_no_signature_is_eforged_and_grants_nothing(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """Loki's FORGE-1: a hand-written pending/<pair>.json naming full_access
    with citation_id 'forged', dropped straight into pending/ without ever
    calling manifest_grant_request. Must be refused eforged with no grant —
    never reach the seal, the escalation set, or set_permission at all."""
    grants_root = home / "manifest_grants"
    kart_path = _manifest(home, "kart")
    (grants_root / "pending").mkdir(parents=True, exist_ok=True)
    forged = {
        "pair_id": "forged-pair", "envelope_id": "e", "citation_id": "forged",
        "actor": "willow", "apps": ["kart"], "groups": ["full_access"],
        "project": "willow-mcp", "session": "", "requested_at": _now_iso_helper(),
        "pre_state": {"kart": {"manifest_sha256": "0" * 64, "sig_sha256": None}},
    }
    (grants_root / "pending" / "forged-pair.json").write_text(json.dumps(forged))

    applied = mgx.manifest_grant_apply(apps_root=home / "mcp_apps", grants_root=grants_root)
    assert applied["ok"] is False
    result = applied["processed"][0]
    assert result["error"] == "eforged"
    kart_manifest = json.loads(kart_path.read_text())
    assert kart_manifest["permissions"] == []
    assert mgx.manifest_grant_status("forged-pair", grants_root=grants_root)["state"] == "failed"


def test_forged_pending_file_with_bad_signature_is_eforged(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """FORGE-2 shape: a file that DOES carry a broker_sig field, but not one
    that verifies against the broker's real key (e.g. copied from a
    different pending file, or hand-crafted)."""
    grants_root = home / "manifest_grants"
    kart_path = _manifest(home, "kart")
    (grants_root / "pending").mkdir(parents=True, exist_ok=True)
    forged = {
        "pair_id": "forged-pair-2", "envelope_id": "e", "citation_id": "forged",
        "actor": None, "apps": ["kart"], "groups": ["store_read"],
        "project": "willow-mcp", "session": "", "requested_at": _now_iso_helper(),
        "pre_state": {}, "broker_sig": "ab" * 64,
    }
    (grants_root / "pending" / "forged-pair-2.json").write_text(json.dumps(forged))

    applied = mgx.manifest_grant_apply(apps_root=home / "mcp_apps", grants_root=grants_root)
    result = applied["processed"][0]
    assert result["error"] == "eforged"
    kart_manifest = json.loads(kart_path.read_text())
    assert kart_manifest["permissions"] == []


def test_apply_reverifies_escalation_group_even_with_valid_signature_and_seal(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """A request signed and sealed for full_access — simulating an
    escalation-list check that was somehow bypassed or widened between
    request and apply. Apply's OWN escalation re-check must still refuse."""
    grants_root = home / "manifest_grants"
    _manifest(home, "kart")
    text = mgx.ruling_text(["kart"], ["full_access"])
    sig = _sign_seal(ring_with_sean, "sean", "test grant", text)
    _write_nestor_pair(home, "pair-esc", text, verifier="sean", seal_sig=sig)

    record = {
        "pair_id": "pair-esc", "envelope_id": "e-1", "citation_id": "c-1",
        "actor": "willow", "apps": ["kart"], "groups": ["full_access"],
        "project": "willow-mcp", "session": "", "requested_at": _now_iso_helper(),
        "pre_state": {"kart": mgx._seat_pre_state("kart", home / "mcp_apps")},
    }
    record["broker_sig"] = mgx._sign_request(record, grants_root)
    (grants_root / "pending").mkdir(parents=True, exist_ok=True)
    (grants_root / "pending" / "pair-esc.json").write_text(json.dumps(record, default=str))

    applied = mgx.manifest_grant_apply(apps_root=home / "mcp_apps", grants_root=grants_root)
    result = applied["processed"][0]
    assert result["error"] == "EPERM"
    assert result["escalating"] == ["full_access"]
    kart_manifest = json.loads((home / "mcp_apps" / "kart" / "manifest.json").read_text())
    assert kart_manifest["permissions"] == []


def test_apply_refuses_when_citation_does_not_exist_in_frank(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """A properly signed, properly sealed request whose citation_id was
    never actually inked (or does not match FRANK's granted row for this
    envelope) — must be refused eforged with no grant, not applied on the
    file's own say-so."""
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)

    req = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=_ledger(_FakeGovernancePg()),  # a DIFFERENT, empty ledger — nothing was really cited
        store=store, apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert req["ok"] is True, req

    # Apply against an empty ledger: FRANK carries no granted citation at all.
    applied = mgx.manifest_grant_apply(ledger=_ledger(_FakeGovernancePg()),
                                       apps_root=home / "mcp_apps", grants_root=grants_root)
    result = applied["processed"][0]
    assert result["error"] == "eforged"
    kart_manifest = json.loads((home / "mcp_apps" / "kart" / "manifest.json").read_text())
    assert kart_manifest["permissions"] == []


def test_apply_refuses_when_pre_state_is_absent(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """pre_state absent must refuse eforged, never be treated as 'nothing to
    compare' and skip drift checking (the old bug: `if recorded.get(...)`
    silently passed when pre_state was empty)."""
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    text = mgx.ruling_text(["kart"], ["store_read"])
    sig = _sign_seal(ring_with_sean, "sean", "test grant", text)
    _write_nestor_pair(home, "pair-mg-1", text, verifier="sean", seal_sig=sig)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    record = {
        "pair_id": "pair-mg-1", "envelope_id": "env-manifest.grant-test", "citation_id": "",
        "actor": "willow", "apps": ["kart"], "groups": ["store_read"],
        "project": "willow-mcp", "session": "", "requested_at": _now_iso_helper(),
        "pre_state": {},
    }
    rec = ledger.append_citation("willow-mcp", {
        "envelope_id": "env-manifest.grant-test", "verb": mgx.VERB,
        "call_args": {"apps": ["kart"], "groups": ["store_read"]},
        "outcome": "granted", "session": "", "actor": "willow",
    }, max_count=None)
    record["citation_id"] = rec[0]
    record["broker_sig"] = mgx._sign_request(record, grants_root)
    (grants_root / "pending").mkdir(parents=True, exist_ok=True)
    (grants_root / "pending" / "pair-mg-1.json").write_text(json.dumps(record, default=str))

    applied = mgx.manifest_grant_apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    result = applied["processed"][0]
    assert result["error"] == "eforged"
    assert "pre_state" in result["reason"]


def test_rollback_failure_is_reported_truthfully_not_as_success(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """Loki's RBFAIL shape: seat 1 (kart) is granted, seat 2 (hanuman) then
    fails, AND the compensating rollback of seat 1 ALSO fails. The result
    must carry `rollback_failed` naming kart as still holding the group —
    never report `rolled_back: ['kart']` as if the undo succeeded."""
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart", "hanuman"), groups=("store_read",))
    kart_path = _manifest(home, "kart")
    _manifest(home, "hanuman")
    _seal(home, store, seats=("kart", "hanuman"), groups=("store_read",), kr=ring_with_sean)

    from willow_mcp import manifest_admin

    real_set_permission = manifest_admin.set_permission

    def _flaky(app_id, perm, granted, **kwargs):
        if app_id == "hanuman" and granted:
            raise RuntimeError("forced failure on second seat")
        if app_id == "kart" and not granted:
            raise RuntimeError("forced rollback failure — seat 1's dir is unwritable")
        return real_set_permission(app_id, perm, granted, **kwargs)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=ledger, store=store, apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert req["ok"] is True, req

    monkeypatch.setattr(manifest_admin, "set_permission", _flaky)
    applied = mgx.manifest_grant_apply(ledger=ledger, apps_root=home / "mcp_apps",
                                       grants_root=grants_root)

    assert applied["ok"] is False
    result = applied["processed"][0]
    assert "rollback_failed" in result
    still_held = {r["app_id"]: r["still_held"] for r in result["rollback_failed"]}
    assert still_held.get("kart") == ["store_read"]
    assert "kart" not in result.get("rolled_back", [])
    assert "ROLLBACK FAILED" in result["reason"]
    # And the manifest itself actually still holds it — the report is truthful.
    kart_manifest = json.loads(kart_path.read_text())
    assert kart_manifest["permissions"] == ["store_read"]
    assert not _receipts(pg)


def test_apply_refuses_eperm_pending_when_grants_dirs_are_not_writable(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """Loki's MOVE shape: the apply uid cannot reliably move the request out
    of pending/. Checked BEFORE granting anything — no seat is ever
    touched, unlike the old bug where the grant landed and then every tick
    repeated `eunexpected` forever with the grant already live."""
    grants_root = home / "manifest_grants"
    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    kart_path = _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-1",
        ledger=ledger, store=store, apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert req["ok"] is True, req

    monkeypatch.setattr(mgx, "_dirs_writable", lambda root: (False, "simulated: uid mismatch on pending/"))
    applied = mgx.manifest_grant_apply(ledger=ledger, apps_root=home / "mcp_apps",
                                       grants_root=grants_root)
    result = applied["processed"][0]
    assert result["error"] == "eperm_pending"
    kart_manifest = json.loads(kart_path.read_text())
    assert kart_manifest["permissions"] == []


def test_apply_refuses_ewronguser_when_it_does_not_own_apps_root(
    home, tmp_path, monkeypatch,
):
    """Loki finding 3: the unit must run AS the trust owner. Simulated here
    by stat-mocking a mismatched owning uid rather than actually chowning
    (no root in the test sandbox) — the check itself is what is exercised."""
    grants_root = home / "manifest_grants"
    apps_root = home / "mcp_apps"
    apps_root.mkdir(parents=True, exist_ok=True)

    real_stat = Path.stat

    class _FakeStat:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        @property
        def st_uid(self):
            return self._real.st_uid + 1  # never matches os.geteuid()

    def _fake_stat(self, *a, **kw):
        if self == apps_root:
            return _FakeStat(real_stat(self, *a, **kw))
        return real_stat(self, *a, **kw)

    monkeypatch.setattr(Path, "stat", _fake_stat)
    out = mgx.manifest_grant_apply(apps_root=apps_root, grants_root=grants_root)
    assert out["error"] == "ewronguser"


def test_render_manifest_grant_service_template_fills_trust_owner_and_pgp_env(tmp_path, monkeypatch):
    """Fix 3: the service template must render with User=, WILLOW_KEYRING=
    and WILLOW_PGP_FINGERPRINT= filled, plus the ExecStartPre that
    provisions manifest_grants/{pending,done,failed}."""
    from willow_mcp import unit_install_executor as uix

    apps_root = tmp_path / "mcp_apps"
    apps_root.mkdir()
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    monkeypatch.setenv("WILLOW_KEYRING", str(tmp_path / "verifiers.json"))
    monkeypatch.setenv("WILLOW_PGP_FINGERPRINT", "ABCD1234")
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "home"))

    values = uix.render_values("willow-mcp-manifest-grant.service")
    assert values.get("TRUST_OWNER")
    assert values.get("WILLOW_KEYRING") == str(tmp_path / "verifiers.json")
    assert values.get("WILLOW_PGP_FINGERPRINT") == "ABCD1234"

    template_path = (Path(__file__).resolve().parent.parent / "src" / "willow_mcp" / "bundle"
                     / "deploy" / "willow-mcp-manifest-grant.service.template")
    rendered = uix.render_template(template_path.read_text(encoding="utf-8"),
                                   "willow-mcp-manifest-grant.service", values=values)
    assert f"User={values['TRUST_OWNER']}" in rendered
    assert "Environment=\"WILLOW_KEYRING=" in rendered
    assert "Environment=\"WILLOW_PGP_FINGERPRINT=ABCD1234\"" in rendered
    assert "ExecStartPre=" in rendered
    assert "manifest_grants/pending" in rendered
    assert "manifest_grants/done" in rendered
    assert "manifest_grants/failed" in rendered


def _now_iso_helper():
    return datetime.now(timezone.utc).isoformat()


def test_status_not_found_then_pending_then_done(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    grants_root = home / "manifest_grants"
    assert mgx.manifest_grant_status("pair-mg-1", grants_root=grants_root)["state"] == "not_found"

    _charter(tmp_path, monkeypatch, apps=("kart",), groups=("store_read",))
    _manifest(home, "kart")
    _seal(home, store, seats=("kart",), groups=("store_read",), kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    req, applied = _request_and_apply(home, store, ledger, apps_root=home / "mcp_apps",
                                      grants_root=grants_root)
    assert applied["ok"] is True
    status = mgx.manifest_grant_status("pair-mg-1", grants_root=grants_root)
    assert status["state"] == "done"
    assert status["result"]["granted"][0]["app_id"] == "kart"
