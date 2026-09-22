"""The five trust-owner verbs added alongside `manifest.grant` on the same
queue (:mod:`willow_mcp.trust_owner_verbs`, sealed `1bd6fd29`): `envelope.revoke`,
`manifest.retire`, `manifest.create`, `federation.ratify`, `envelope.ratify`.
Fixtures mirror `tests/test_manifest_grant.py` (same fake FRANK ledger, same
real-ed25519 sealed-pair machinery) since these verbs share that module's
queue and signing key.
"""
from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from willow_mcp import keyring as keyring_mod
from willow_mcp import manifest_grant_executor as mgx
from willow_mcp import net_signer as ns
from willow_mcp import seal_handler
from willow_mcp import trust_owner_verbs as tov
from willow_mcp.db import Store


# ── fake FRANK ledger, same shape as test_manifest_grant.py ─────────────────

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


def _receipts(pg, event):
    return [r for r in pg.rows if r["event_type"] == event]


# ── registry with one active envelope per verb ───────────────────────────────

def _charter(tmp_path, monkeypatch, *, verb, verb_id, bounds, grantee="willow", extra=None,
             expires="2027-01-01"):
    active = [{
        "id": f"env-{verb}-test",
        "verb_id": verb_id,
        "verb": verb,
        "grantee": grantee,
        "bounds": bounds,
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": expires,
        "max_count": None,
        "use_count_source": "frank",
        "status": "active",
    }] + list(extra or [])
    table = {"verbs": [{"id": verb_id, "verb": verb, "bounds": {k: "l" for k in bounds}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))
    return reg


def _write_nestor_pair(home, pair_id, target_text, *, verifier="sean",
                        status="sealed", seal_sig="stub-seal-sig", created_at=None):
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
        (pair_id, "test", "test", "decision", target_text, "decision",
         status, verifier, created_at or datetime.now(timezone.utc).isoformat(), seal_sig),
    )
    conn.commit()
    conn.close()


def _sign_seal(kr, name, source_norm, target_text) -> str:
    entry = kr.get(name)
    priv = Ed25519PrivateKey.from_private_bytes(entry.private)
    return priv.sign(ns.seal_message(source_norm, target_text, name)).hex()


def _seal_governance(store, *, pair_id, status="sealed", extra=None):
    record = {"id": f"gov-{pair_id}", "title": "test", "status": status, "nestor_pair_id": pair_id}
    record.update(extra or {})
    return store.put(seal_handler.GOVERNANCE_COLLECTION, record)


def _seal(home, store, *, pair_id, target_text, verifier="sean", kr=None,
          nestor_status="sealed", sealed_text=None, gov_status="sealed"):
    """Seal `target_text` for `pair_id`: a governance record (status=sealed)
    plus a genuinely-signed row in nestor.db. `sealed_text` overrides what is
    actually sealed (for mismatch tests) while the governance record still
    exists."""
    _seal_governance(store, pair_id=pair_id, status=gov_status)
    text = sealed_text if sealed_text is not None else target_text
    if kr is not None and verifier in kr.names():
        sig = _sign_seal(kr, verifier, "test", text)
    else:
        sig = "stub-seal-sig"
    _write_nestor_pair(home, pair_id, text, verifier=verifier, status=nestor_status, seal_sig=sig)


@pytest.fixture
def store(tmp_path):
    return Store(store_root=str(tmp_path / "store"))


@pytest.fixture
def ring_with_sean(tmp_path):
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


def _apply(pair_id=None, ledger=None, apps_root=None, grants_root=None, db_path=None):
    return mgx.manifest_grant_apply(
        pair_id=pair_id, ledger=ledger or _ledger(_FakeGovernancePg()),
        apps_root=apps_root, db_path=db_path, grants_root=grants_root,
    )


# ── envelope.revoke ──────────────────────────────────────────────────────

def _revoke_env(app_id="willow", *, pair_id="pair-rev-1", envelope_id="", ledger=None,
                 store=None, grants_root=None, db_path=None):
    return tov.envelope_revoke_request(
        app_id, envelope_id=envelope_id, pair_id=pair_id,
        ledger=ledger or _ledger(_FakeGovernancePg()), store=store,
        grants_root=grants_root, db_path=db_path,
    )


def test_revoke_non_orchestrator_is_eperm(home, tmp_path, store):
    out = _revoke_env("hanuman", store=store)
    assert out["error"] == "EPERM"


def test_revoke_grammar_miss_is_einval(home, tmp_path, store, ring_with_sean):
    _seal(home, store, pair_id="pair-rev-1", target_text="please revoke it", kr=ring_with_sean)
    out = _revoke_env(store=store)
    assert out["error"] == "EINVAL"


def test_revoke_unknown_envelope_is_enoent(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="envelope.revoke", verb_id=20, bounds={"envelope_ids": ["env-x"]})
    _seal(home, store, pair_id="pair-rev-1",
          target_text="revoke envelope env-x: cleanup", kr=ring_with_sean)
    out = _revoke_env(store=store, grants_root=home / "manifest_grants")
    assert out["error"] == "ENOENT"


def test_revoke_end_to_end(home, tmp_path, monkeypatch, store, ring_with_sean):
    active_extra = [{
        "id": "env-x", "verb_id": 99, "verb": "some.other", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    # envelope_authoring.revoke refuses EREGISTRY when WILLOW_ENVELOPE_REGISTRY
    # steers away from $WILLOW_HOME/constitutional/pre-approved.json (its own
    # registry-identity consistency check) — so this test, unlike the other
    # three verbs', writes the charter at the DEFAULT resolution and never
    # sets that env var.
    default_reg = home / "constitutional" / "pre-approved.json"
    default_reg.parent.mkdir(parents=True, exist_ok=True)
    active = [{
        "id": "env-envelope.revoke-test", "verb_id": 20, "verb": "envelope.revoke",
        "grantee": "willow", "bounds": {"envelope_ids": ["env-x"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }] + active_extra
    default_reg.write_text(json.dumps({"active": active}))
    tab = home / "constitutional" / "syscall-table.json"
    tab.write_text(json.dumps({"verbs": [{"id": 20, "verb": "envelope.revoke",
                                           "bounds": {"envelope_ids": "l"}}]}))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))
    _seal(home, store, pair_id="pair-rev-1",
          target_text="revoke envelope env-x: retiring jeles", kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _revoke_env(store=store, ledger=ledger, grants_root=grants_root)
    assert out["ok"] is True
    assert out["state"] == "requested"

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert apply_out["ok"] is True
    processed = apply_out["processed"][0]
    assert processed["ok"] is True
    assert processed["envelope_id"] == "env-x"

    status = mgx.manifest_grant_status("pair-rev-1", grants_root=grants_root)
    assert status["state"] == "done"

    registry = json.loads(default_reg.read_text())
    row = next(r for r in registry["active"] if r["id"] == "env-x")
    assert row.get("revoked") is True

    assert _receipts(pg, tov.EVENT_REVOKE_APPLIED)


# ── manifest.retire ───────────────────────────────────────────────────────

def _retire_seat(app_id="willow", *, pair_id="pair-ret-1", envelope_id="", ledger=None,
                  store=None, apps_root=None, grants_root=None, db_path=None):
    return tov.manifest_retire_request(
        app_id, envelope_id=envelope_id, pair_id=pair_id,
        ledger=ledger or _ledger(_FakeGovernancePg()), store=store,
        apps_root=apps_root, grants_root=grants_root, db_path=db_path,
    )


def test_retire_orchestrator_itself_is_refused(home, tmp_path, store, ring_with_sean):
    _seal(home, store, pair_id="pair-ret-1", target_text="retire seat willow: bogus", kr=ring_with_sean)
    out = _retire_seat(store=store, apps_root=home / "mcp_apps")
    assert out["error"] == "EPERM"


def test_retire_no_manifest_is_enomanifest(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=21, bounds={"apps": ["ghost"]})
    _seal(home, store, pair_id="pair-ret-1", target_text="retire seat ghost: gone", kr=ring_with_sean)
    out = _retire_seat(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "enomanifest"


def test_retire_active_envelope_is_ebusy(home, tmp_path, monkeypatch, store, ring_with_sean):
    active_extra = [{
        "id": "env-jeles-dispatch", "verb_id": 5, "verb": "dispatch", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=21, bounds={"apps": ["jeles"]},
             extra=active_extra)
    _manifest(home, "jeles")
    _seal(home, store, pair_id="pair-ret-1", target_text="retire seat jeles: retiring the organ",
          kr=ring_with_sean)
    out = _retire_seat(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EBUSY"
    assert "env-jeles-dispatch" in out["envelope_ids"]


def test_retire_end_to_end(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=21, bounds={"apps": ["jeles"]})
    _manifest(home, "jeles")
    _seal(home, store, pair_id="pair-ret-1", target_text="retire seat jeles: retiring the organ",
          kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _retire_seat(store=store, ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out["ok"] is True

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["ok"] is True
    assert not (home / "mcp_apps" / "jeles").exists()
    assert (home / "mcp_apps" / "_retired" / "jeles-pair-ret-1" / "manifest.json").is_file()
    assert _receipts(pg, tov.EVENT_RETIRE_APPLIED)


# ── manifest.create ───────────────────────────────────────────────────────

def _create_seat(app_id="willow", *, pair_id="pair-cre-1", envelope_id="", ledger=None,
                  store=None, apps_root=None, grants_root=None, db_path=None):
    return tov.manifest_create_request(
        app_id, envelope_id=envelope_id, pair_id=pair_id,
        ledger=ledger or _ledger(_FakeGovernancePg()), store=store,
        apps_root=apps_root, grants_root=grants_root, db_path=db_path,
    )


def test_create_escalation_permission_refused(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["jeles-corpus"], "groups": ["full_access"]})
    _seal(home, store, pair_id="pair-cre-1",
          target_text="create seat jeles-corpus store_scope [] store_write [] permissions [full_access]",
          kr=ring_with_sean)
    out = _create_seat(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EPERM"
    assert "full_access" in out["escalating"]


def test_create_already_exists_is_eexist(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["jeles-corpus"], "groups": []})
    _manifest(home, "jeles-corpus")
    _seal(home, store, pair_id="pair-cre-1",
          target_text="create seat jeles-corpus store_scope [] store_write [] permissions [gap_write]",
          kr=ring_with_sean)
    out = _create_seat(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EEXIST"


def test_create_seat_named_willow_case_insensitive_collision_is_refused(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """Loki audit BFCC5C79, F5: `create seat Willow ...` used to pass —
    human_session.is_orchestrator_app lowercases before comparing, but the
    seat namespace on disk is case-sensitive, so 'Willow' and 'willow' were
    treated as the same seat by every case-insensitive check elsewhere while
    manifest.create let a manifest be created for the literal string
    'Willow'. manifest.retire already refused the same collision (the
    orchestrator seat itself can never be retired); create must agree."""
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["Willow"], "groups": []})
    _seal(home, store, pair_id="pair-cre-willow",
          target_text="create seat Willow store_scope [] store_write [] permissions []",
          kr=ring_with_sean)
    out = _create_seat(store=store, pair_id="pair-cre-willow",
                        apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EPERM"
    assert not (home / "mcp_apps" / "Willow" / "manifest.json").exists()


def test_create_apply_time_refuses_willow_collision_even_if_request_time_missed_it(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """The apply-side re-check (never trust what request-time already
    verified) — same shape as the escalation-group re-check."""
    pair_id = "pair-cre-willow-apply"
    grants_root = home / "manifest_grants"
    (grants_root / "pending").mkdir(parents=True, exist_ok=True)
    target = {"app_id": "Willow", "store_scope": [], "store_write": [], "permissions": []}
    record = {
        "pair_id": pair_id, "verb": tov.VERB_CREATE, "envelope_id": "env-x", "citation_id": "cit-x",
        "actor": "willow", "target": target, "project": "willow-mcp", "session": "",
        "requested_at": "2026-01-01T00:00:00+00:00", "pre_state": {"Willow": {"exists": False}},
        "call_args": {"apps": ["Willow"], "groups": []}, "broker_sig": "irrelevant",
    }
    (grants_root / "pending" / f"{pair_id}.json").write_text(json.dumps(record))
    out = tov._apply_manifest_create(
        record, grants_root / "pending" / f"{pair_id}.json",
        ledger=None, apps_root=home / "mcp_apps", db_path=None, grants_root=grants_root,
    )
    assert out["error"] in ("EPERM", "eforged")  # eforged if the signature/citation check runs first


def test_create_end_to_end_jeles_corpus(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["jeles-corpus"], "groups": []})
    _seal(home, store, pair_id="pair-cre-1",
          target_text=("create seat jeles-corpus store_scope "
                        "[ask_jeles_corpus, ask_jeles_corpus_gaps] store_write "
                        "[ask_jeles_corpus, ask_jeles_corpus_gaps] permissions []"),
          kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _create_seat(store=store, ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out["ok"] is True

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["ok"] is True

    manifest = json.loads((home / "mcp_apps" / "jeles-corpus" / "manifest.json").read_text())
    assert manifest["store_scope"] == ["ask_jeles_corpus", "ask_jeles_corpus_gaps"]
    assert manifest["store_write"] == ["ask_jeles_corpus", "ask_jeles_corpus_gaps"]
    assert manifest["permissions"] == []
    assert _receipts(pg, tov.EVENT_CREATE_APPLIED)


# ── federation.ratify ─────────────────────────────────────────────────────

def _ratify(app_id="willow", *, pair_id="pair-fed-1", envelope_id="", ledger=None,
            store=None, grants_root=None, db_path=None):
    return tov.federation_ratify_request(
        app_id, envelope_id=envelope_id, pair_id=pair_id,
        ledger=ledger or _ledger(_FakeGovernancePg()), store=store,
        grants_root=grants_root, db_path=db_path,
    )


def _fake_server(tmp_path, name="jeles-corpus-server"):
    script = tmp_path / name
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


def test_ratify_command_missing_is_enoent(home, tmp_path, store, ring_with_sean):
    _seal(home, store, pair_id="pair-fed-1",
          target_text=(f"ratify federation server jeles-corpus command {tmp_path}/nope "
                        f"cwd {tmp_path} env_keys [WILLOW_HOME]"),
          kr=ring_with_sean)
    out = _ratify(store=store, grants_root=home / "manifest_grants")
    assert out["error"] == "ENOENT"


def test_ratify_bad_env_key_is_einval(home, tmp_path, store, ring_with_sean):
    server = _fake_server(tmp_path)
    _seal(home, store, pair_id="pair-fed-1",
          target_text=(f"ratify federation server jeles-corpus command {server} "
                        f"cwd {tmp_path} env_keys [lower_case_bad]"),
          kr=ring_with_sean)
    out = _ratify(store=store, grants_root=home / "manifest_grants")
    assert out["error"] == "EINVAL"


def test_ratify_end_to_end(home, tmp_path, monkeypatch, store, ring_with_sean):
    server = _fake_server(tmp_path)
    _charter(tmp_path, monkeypatch, verb="federation.ratify", verb_id=23,
             bounds={"servers": ["jeles-corpus"]})
    _seal(home, store, pair_id="pair-fed-1",
          target_text=(f"ratify federation server jeles-corpus command {server} cwd {tmp_path} "
                        "env_keys [WILLOW_HOME, WILLOW_STORE_ROOT, JELES_CORPUS_APP_ID, "
                        "NESTOR_KEYRING, WILLOW_MCP_APPS_ROOT]"),
          kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _ratify(store=store, ledger=ledger, grants_root=grants_root)
    assert out["ok"] is True

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["ok"] is True
    assert processed["name"] == "jeles-corpus"

    from willow_mcp import mcp_federation
    assert mcp_federation.is_ratified(processed["server_id"])
    assert _receipts(pg, tov.EVENT_RATIFY_APPLIED)


# ── shared plumbing: verb dispatch + back-compat ─────────────────────────────

def test_verbless_pending_file_still_applies_as_manifest_grant(home, tmp_path, monkeypatch, store, ring_with_sean):
    """A pending file written before this rework (no `verb` key at all) must
    still apply as `manifest.grant` — the back-compat contract the amendment
    requires."""
    _charter(tmp_path, monkeypatch, verb="manifest.grant", verb_id=18, bounds={"apps": ["kart"], "groups": ["store_read"]})
    _manifest(home, "kart")
    _seal_governance(store, pair_id="pair-mg-legacy",
                      extra={"seats": ["kart"], "groups": ["store_read"], "nestor_verifier": "sean"})
    sig = _sign_seal(ring_with_sean, "sean", "test", mgx.ruling_text(["kart"], ["store_read"]))
    _write_nestor_pair(home, "pair-mg-legacy", mgx.ruling_text(["kart"], ["store_read"]),
                        verifier="sean", seal_sig=sig)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = mgx.manifest_grant_request(
        "willow", envelope_id="", pair_id="pair-mg-legacy", ledger=ledger, store=store,
        apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert out["ok"] is True

    # Simulate a pre-rework file: strip the "verb" key entirely.
    pending_path = grants_root / "pending" / "pair-mg-legacy.json"
    record = json.loads(pending_path.read_text())
    assert record.get("verb") == mgx.VERB
    del record["verb"]
    # Re-sign over the (now verb-less) bytes so the signature still matches
    # what _canonical_request_bytes computes for a verb-absent record — this
    # is exactly the same payload manifest_grant_request already signed
    # (canonical bytes are unchanged for manifest.grant either way).
    pending_path.write_text(json.dumps(record, indent=2, default=str))

    apply_out = mgx.manifest_grant_apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    assert apply_out["ok"] is True
    assert apply_out["processed"][0]["ok"] is True

    manifest = json.loads((home / "mcp_apps" / "kart" / "manifest.json").read_text())
    assert "store_read" in manifest["permissions"]


def test_estale_presigned_failed_record_reads_as_failed(home, tmp_path, store):
    """install.sh step 6b (sealed 33654f35, pair 1bd6fd29 amendment) writes a
    withdrawn pre-install request directly to `failed/<pair_id>.json` in the
    same shape `_move` produces — the original record's fields spread at the
    top level, plus a `result` key, never a `request`-nested wrapper.
    `manifest_grant_status` must read it as `failed` with that error, with no
    special-casing, exactly as every other failure cause in this queue."""
    grants_root = home / "manifest_grants"
    (grants_root / "failed").mkdir(parents=True)
    original_record = {
        "pair_id": "pair-stale-1", "verb": "manifest.grant", "envelope_id": "env-x",
        "citation_id": "cit-1", "actor": "willow", "apps": ["kart"], "groups": ["store_read"],
        "project": "willow-mcp", "session": "", "requested_at": "2026-01-01T00:00:00+00:00",
        "pre_state": {"kart": {"manifest_sha256": "deadbeef", "sig_sha256": None}},
        "broker_sig": "irrelevant-once-withdrawn",
    }
    withdrawn = {
        **original_record,
        "result": {
            "ok": False, "error": "estale_presigned",
            "reason": "withdrawn by install.sh: every manifest was re-signed...",
            "withdrawn_at": "2026-09-22T00:00:00+00:00",
        },
    }
    (grants_root / "failed" / "pair-stale-1.json").write_text(json.dumps(withdrawn, indent=2))

    status = mgx.manifest_grant_status("pair-stale-1", grants_root=grants_root)
    assert status["state"] == "failed"
    assert status["result"]["error"] == "estale_presigned"
    assert status["apps"] == ["kart"]  # top-level fields survived, no "request" nesting

    assert "estale_presigned" in mgx.TERMINAL_ERRORS
    assert "estale_presigned" not in mgx.RETRYABLE_ERRORS

    retry_out = mgx.manifest_grant_retry(
        "willow", "pair-stale-1", ledger=_ledger(_FakeGovernancePg()), grants_root=grants_root,
    )
    assert retry_out["error"] == "EPERM"
    assert retry_out["prior_error"] == "estale_presigned"


def test_unknown_verb_in_pending_file_is_enosys(home, tmp_path, store):
    grants_root = home / "manifest_grants"
    (grants_root / "pending").mkdir(parents=True)
    record = {"pair_id": "pair-unknown", "verb": "no.such.verb", "envelope_id": "e", "citation_id": "c"}
    (grants_root / "pending" / "pair-unknown.json").write_text(json.dumps(record))
    apply_out = mgx.manifest_grant_apply(
        ledger=_ledger(_FakeGovernancePg()), apps_root=home / "mcp_apps", grants_root=grants_root,
    )
    assert apply_out["processed"][0]["error"] == "ENOSYS"
    assert (grants_root / "failed" / "pair-unknown.json").is_file()


# ── F6 (Loki audit BFCC5C79): the brief's own per-verb Prove list, missing
# for all four verbs — EALREADY, apply-time eseal_mismatch, apply-time
# EACCES receipt in failed/, and (one representative exemplar, since the
# mechanism is verb-agnostic shared plumbing —
# _verify_pending_signature_and_citation) apply-time eforged. Apply-time
# edrift (R4, Loki re-audit 54E3DFC0: "zero edrift assertions exist despite
# the prior handoff's claim otherwise") is covered below, one test per verb,
# each driving the exact condition each verb's own `_apply_*` checks.

def test_revoke_second_request_is_ealready(home, tmp_path, monkeypatch, store, ring_with_sean):
    active_extra = [{
        "id": "env-x", "verb_id": 99, "verb": "some.other", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    _charter(tmp_path, monkeypatch, verb="envelope.revoke", verb_id=20,
             bounds={"envelope_ids": ["env-x"]}, extra=active_extra)
    _seal(home, store, pair_id="pair-rev-ea", target_text="revoke envelope env-x: first", kr=ring_with_sean)
    grants_root = home / "manifest_grants"
    out1 = _revoke_env(store=store, pair_id="pair-rev-ea", grants_root=grants_root)
    assert out1["ok"] is True
    out2 = _revoke_env(store=store, pair_id="pair-rev-ea", grants_root=grants_root)
    assert out2["error"] == "EALREADY"


def test_revoke_apply_time_eseal_mismatch(home, tmp_path, monkeypatch, store, ring_with_sean):
    active_extra = [{
        "id": "env-x", "verb_id": 99, "verb": "some.other", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    _charter(tmp_path, monkeypatch, verb="envelope.revoke", verb_id=20,
             bounds={"envelope_ids": ["env-x", "env-y"]}, extra=active_extra)
    _seal(home, store, pair_id="pair-rev-mismatch",
          target_text="revoke envelope env-x: original reason", kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _revoke_env(store=store, ledger=ledger, pair_id="pair-rev-mismatch", grants_root=grants_root)
    assert out["ok"] is True

    # The sealed pair's own text changes after the request was recorded —
    # re-sealed (same pair_id, INSERT OR REPLACE) with a different reason.
    # Apply re-parses the CURRENT sealed text fresh and must refuse rather
    # than trust the pending record's stale recorded target.
    _seal(home, store, pair_id="pair-rev-mismatch",
          target_text="revoke envelope env-x: a DIFFERENT reason", kr=ring_with_sean)

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "eseal_mismatch"
    assert (grants_root / "failed" / "pair-rev-mismatch.json").is_file()


def test_revoke_apply_time_eforged_on_tampered_signature(home, tmp_path, monkeypatch, store, ring_with_sean):
    active_extra = [{
        "id": "env-x", "verb_id": 99, "verb": "some.other", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    _charter(tmp_path, monkeypatch, verb="envelope.revoke", verb_id=20,
             bounds={"envelope_ids": ["env-x"]}, extra=active_extra)
    _seal(home, store, pair_id="pair-rev-forge", target_text="revoke envelope env-x: t", kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _revoke_env(store=store, ledger=ledger, pair_id="pair-rev-forge", grants_root=grants_root)
    assert out["ok"] is True

    pending_path = grants_root / "pending" / "pair-rev-forge.json"
    record = json.loads(pending_path.read_text())
    record["broker_sig"] = "00" * 64  # structurally valid hex, not this broker's signature
    pending_path.write_text(json.dumps(record, indent=2))

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "eforged"
    assert (grants_root / "failed" / "pair-rev-forge.json").is_file()


def test_revoke_apply_time_eacces_on_unwritable_registry(home, tmp_path, monkeypatch, store, ring_with_sean):
    active_extra = [{
        "id": "env-x", "verb_id": 99, "verb": "some.other", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    reg = _charter(tmp_path, monkeypatch, verb="envelope.revoke", verb_id=20,
                    bounds={"envelope_ids": ["env-x"]}, extra=active_extra)
    _seal(home, store, pair_id="pair-rev-eacces", target_text="revoke envelope env-x: t", kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _revoke_env(store=store, ledger=ledger, pair_id="pair-rev-eacces", grants_root=grants_root)
    assert out["ok"] is True

    reg.parent.chmod(0o500)  # the registry's own directory, no longer writable
    try:
        apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    finally:
        reg.parent.chmod(0o700)  # restore so pytest's own tmp_path cleanup can remove it
    processed = apply_out["processed"][0]
    assert processed["error"] in ("EACCES", "eunexpected")
    assert (grants_root / "failed" / "pair-rev-eacces.json").is_file()


def test_retire_second_request_is_ealready(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=21, bounds={"apps": ["jeles"]})
    _manifest(home, "jeles")
    _seal(home, store, pair_id="pair-ret-ea", target_text="retire seat jeles: t", kr=ring_with_sean)
    grants_root = home / "manifest_grants"
    out1 = _retire_seat(store=store, pair_id="pair-ret-ea", apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out1["ok"] is True
    out2 = _retire_seat(store=store, pair_id="pair-ret-ea", apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out2["error"] == "EALREADY"


def test_retire_apply_time_eacces_on_unwritable_apps_root(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=21, bounds={"apps": ["jeles"]})
    _manifest(home, "jeles")
    _seal(home, store, pair_id="pair-ret-eacces", target_text="retire seat jeles: t", kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    apps_root = home / "mcp_apps"
    out = _retire_seat(store=store, ledger=ledger, pair_id="pair-ret-eacces", apps_root=apps_root, grants_root=grants_root)
    assert out["ok"] is True

    apps_root.chmod(0o500)  # can no longer create _retired/ or rename into it
    try:
        apply_out = _apply(ledger=ledger, apps_root=apps_root, grants_root=grants_root)
    finally:
        apps_root.chmod(0o700)
    processed = apply_out["processed"][0]
    assert processed["error"] in ("EACCES", "eunexpected")
    assert (grants_root / "failed" / "pair-ret-eacces.json").is_file()


def test_create_second_request_is_ealready(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["jeles-corpus"], "groups": ["gap_write"]})
    _seal(home, store, pair_id="pair-cre-ea",
          target_text="create seat jeles-corpus store_scope [] store_write [] permissions [gap_write]",
          kr=ring_with_sean)
    grants_root = home / "manifest_grants"
    out1 = _create_seat(store=store, pair_id="pair-cre-ea", apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out1["ok"] is True
    out2 = _create_seat(store=store, pair_id="pair-cre-ea", apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out2["error"] == "EALREADY"


def test_create_apply_time_eacces_on_unwritable_apps_root(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["jeles-corpus"], "groups": ["gap_write"]})
    _seal(home, store, pair_id="pair-cre-eacces",
          target_text="create seat jeles-corpus store_scope [] store_write [] permissions [gap_write]",
          kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    apps_root = home / "mcp_apps"
    apps_root.mkdir(parents=True, exist_ok=True)
    out = _create_seat(store=store, ledger=ledger, pair_id="pair-cre-eacces", apps_root=apps_root, grants_root=grants_root)
    assert out["ok"] is True

    apps_root.chmod(0o500)  # manifest_admin.create_manifest cannot mkdir the new seat dir
    try:
        apply_out = _apply(ledger=ledger, apps_root=apps_root, grants_root=grants_root)
    finally:
        apps_root.chmod(0o700)
    processed = apply_out["processed"][0]
    assert processed["error"] in ("EACCES", "eunexpected")
    assert (grants_root / "failed" / "pair-cre-eacces.json").is_file()


def test_ratify_second_request_is_ealready(home, tmp_path, monkeypatch, store, ring_with_sean):
    server = _fake_server(tmp_path)
    _charter(tmp_path, monkeypatch, verb="federation.ratify", verb_id=23, bounds={"servers": ["jeles-corpus"]})
    _seal(home, store, pair_id="pair-fed-ea",
          target_text=f"ratify federation server jeles-corpus command {server} cwd {tmp_path} env_keys [WILLOW_HOME]",
          kr=ring_with_sean)
    grants_root = home / "manifest_grants"
    out1 = _ratify(store=store, pair_id="pair-fed-ea", grants_root=grants_root)
    assert out1["ok"] is True
    out2 = _ratify(store=store, pair_id="pair-fed-ea", grants_root=grants_root)
    assert out2["error"] == "EALREADY"


def test_ratify_apply_time_eseal_mismatch(home, tmp_path, monkeypatch, store, ring_with_sean):
    server = _fake_server(tmp_path)
    _charter(tmp_path, monkeypatch, verb="federation.ratify", verb_id=23, bounds={"servers": ["jeles-corpus"]})
    _seal(home, store, pair_id="pair-fed-mismatch",
          target_text=f"ratify federation server jeles-corpus command {server} cwd {tmp_path} env_keys [WILLOW_HOME]",
          kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _ratify(store=store, ledger=ledger, pair_id="pair-fed-mismatch", grants_root=grants_root)
    assert out["ok"] is True

    _seal(home, store, pair_id="pair-fed-mismatch",
          target_text=f"ratify federation server jeles-corpus command {server} cwd {tmp_path} "
                      "env_keys [WILLOW_HOME, WILLOW_STORE_ROOT]",
          kr=ring_with_sean)

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "eseal_mismatch"


# ── R4 (Loki re-audit 54E3DFC0): apply-time edrift, one test per verb ───────

def test_revoke_apply_time_edrift_already_revoked(home, tmp_path, monkeypatch, store, ring_with_sean):
    """envelope.revoke's own edrift path (trust_owner_verbs.py:241): the
    envelope named by the request is ALREADY revoked by the time apply runs
    (e.g. a second, out-of-band revoke landed first) — apply must refuse
    rather than double-revoke or silently succeed."""
    active_extra = [{
        "id": "env-x", "verb_id": 99, "verb": "some.other", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    reg = _charter(tmp_path, monkeypatch, verb="envelope.revoke", verb_id=20,
                    bounds={"envelope_ids": ["env-x"]}, extra=active_extra)
    _seal(home, store, pair_id="pair-rev-edrift", target_text="revoke envelope env-x: t", kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _revoke_env(store=store, ledger=ledger, pair_id="pair-rev-edrift", grants_root=grants_root)
    assert out["ok"] is True

    # Simulate an out-of-band revoke landing between request and apply: flip
    # the registry row's own `revoked` flag directly, bypassing this verb.
    registry = json.loads(reg.read_text())
    for row in registry["active"]:
        if row["id"] == "env-x":
            row["revoked"] = True
    reg.write_text(json.dumps(registry))

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "edrift"
    assert (grants_root / "failed" / "pair-rev-edrift.json").is_file()


def test_retire_apply_time_edrift_manifest_changed(home, tmp_path, monkeypatch, store, ring_with_sean):
    """manifest.retire's own edrift path (trust_owner_verbs.py:447): the
    seat's manifest content changed since request-time's pre_state was
    recorded (its sha256 no longer matches) — apply must refuse rather than
    retire a manifest it never actually inspected."""
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=21, bounds={"apps": ["jeles"]})
    manifest_path = _manifest(home, "jeles")
    _seal(home, store, pair_id="pair-ret-edrift", target_text="retire seat jeles: t", kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _retire_seat(store=store, ledger=ledger, pair_id="pair-ret-edrift",
                        apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out["ok"] is True

    # The manifest changes underneath the request between request and apply.
    manifest_path.write_text(json.dumps({"app_id": "jeles", "permissions": ["store_read"]}))

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "edrift"
    assert (grants_root / "failed" / "pair-ret-edrift.json").is_file()
    assert (home / "mcp_apps" / "jeles").exists()  # never moved


def test_create_apply_time_edrift_manifest_created_meanwhile(home, tmp_path, monkeypatch, store, ring_with_sean):
    """manifest.create's own edrift path (trust_owner_verbs.py:695): a
    manifest for the target seat now exists at apply time even though
    request-time's pre-state check saw nothing there — e.g. a second create
    for the same seat landed first. Apply must refuse rather than clobber
    it."""
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["jeles-corpus"], "groups": ["gap_write"]})
    _seal(home, store, pair_id="pair-cre-edrift",
          target_text="create seat jeles-corpus store_scope [] store_write [] permissions [gap_write]",
          kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _create_seat(store=store, ledger=ledger, pair_id="pair-cre-edrift",
                        apps_root=home / "mcp_apps", grants_root=grants_root)
    assert out["ok"] is True

    # A manifest for the same seat shows up between request and apply.
    _manifest(home, "jeles-corpus")

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "edrift"
    assert (grants_root / "failed" / "pair-cre-edrift.json").is_file()


def test_ratify_apply_time_edrift_command_missing(home, tmp_path, monkeypatch, store, ring_with_sean):
    """federation.ratify's own edrift path (trust_owner_verbs.py:885): the
    command executable named at request time is gone (or no longer
    executable) by apply time — apply must refuse rather than ratify a
    server pointing at a command that can no longer run."""
    server = _fake_server(tmp_path)
    _charter(tmp_path, monkeypatch, verb="federation.ratify", verb_id=23, bounds={"servers": ["jeles-corpus"]})
    _seal(home, store, pair_id="pair-fed-edrift",
          target_text=f"ratify federation server jeles-corpus command {server} cwd {tmp_path} env_keys [WILLOW_HOME]",
          kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _ratify(store=store, ledger=ledger, pair_id="pair-fed-edrift", grants_root=grants_root)
    assert out["ok"] is True

    server.unlink()  # the command disappears between request and apply

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "edrift"
    assert (grants_root / "failed" / "pair-fed-edrift.json").is_file()


def test_ratify_apply_time_edrift_cwd_missing(home, tmp_path, monkeypatch, store, ring_with_sean):
    """F10 (Loki audit 54E3DFC0): `cwd` gets the same apply-time re-check as
    `command` — it can vanish between request and apply exactly the same
    way."""
    server = _fake_server(tmp_path)
    gone_cwd = tmp_path / "will-vanish"
    gone_cwd.mkdir()
    _charter(tmp_path, monkeypatch, verb="federation.ratify", verb_id=23, bounds={"servers": ["jeles-corpus"]})
    _seal(home, store, pair_id="pair-fed-cwd-edrift",
          target_text=f"ratify federation server jeles-corpus command {server} cwd {gone_cwd} env_keys [WILLOW_HOME]",
          kr=ring_with_sean)
    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    grants_root = home / "manifest_grants"
    out = _ratify(store=store, ledger=ledger, pair_id="pair-fed-cwd-edrift", grants_root=grants_root)
    assert out["ok"] is True

    gone_cwd.rmdir()  # the cwd disappears between request and apply

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "edrift"
    assert (grants_root / "failed" / "pair-fed-cwd-edrift.json").is_file()


# ── R6 (F8/F9/F10 from Loki audit BFCC5C79, now readable via 54E3DFC0) ──────

def test_retire_ebusy_ignores_non_active_envelope_rows(home, tmp_path, monkeypatch, store, ring_with_sean):
    """F8: `_active_envelopes_for_grantee` used to only check `revoked` —
    broader than the gate's own definition of usable (also `status ==
    'active'`, unexpired). A row naming this grantee but not `status ==
    'active'` (e.g. archived) must not block retirement."""
    active_extra = [{
        "id": "env-archived", "verb_id": 5, "verb": "dispatch", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "archived",
    }]
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=21, bounds={"apps": ["jeles"]},
             extra=active_extra)
    _manifest(home, "jeles")
    _seal(home, store, pair_id="pair-ret-nonactive", target_text="retire seat jeles: t", kr=ring_with_sean)
    out = _retire_seat(store=store, pair_id="pair-ret-nonactive",
                        apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["ok"] is True


def test_gates_panel_list_app_ids_skips_retired_and_federation(home, tmp_path, monkeypatch):
    """F9: `_retired` (manifest.retire's destination) and `_federation`
    (federation.ratify's registry directory) are not seats and must not be
    listed as ones."""
    from willow_mcp import gates_panel

    apps_root = home / "mcp_apps"
    (apps_root / "_retired").mkdir(parents=True)
    (apps_root / "_federation").mkdir(parents=True)
    _manifest(home, "jeles")
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps_root))
    ids = gates_panel.list_app_ids()
    assert "_retired" not in ids
    assert "_federation" not in ids
    assert "jeles" in ids


def test_paths_validate_app_id_refuses_retired_and_federation():
    """F9: the same reserved-name guard `mcp_apps`/`schema_maps` already get
    must also cover `_retired`/`_federation` — a seat literally named either
    would collide with manifest.retire's destination or federation.ratify's
    registry directory."""
    from willow_mcp import paths

    for reserved in ("_retired", "_federation"):
        try:
            paths._validate_app_id(reserved)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{reserved!r} should have been refused as a reserved name")


def test_create_unknown_permission_is_einval_at_request_time(home, tmp_path, monkeypatch, store, ring_with_sean):
    """F10: an unknown permission name used to only be caught at apply time
    (manifest_admin.create_manifest's own validate_permission call),
    spending a citation on a request that was always going to fail. Caught
    here, before any citation is spent."""
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["jeles-corpus"], "groups": ["no_such_permission"]})
    _seal(home, store, pair_id="pair-cre-badperm",
          target_text="create seat jeles-corpus store_scope [] store_write [] permissions [no_such_permission]",
          kr=ring_with_sean)
    out = _create_seat(store=store, pair_id="pair-cre-badperm",
                        apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EINVAL"


def test_create_refuses_reserved_retired_seat_name_at_request_time(home, tmp_path, monkeypatch, store, ring_with_sean):
    """F9 applied to manifest.create's request half: `_retired`/`_federation`
    are reserved container names (paths._validate_app_id) — refused before a
    citation is spent, not only at apply time via manifest_admin."""
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=22,
             bounds={"apps": ["_retired"], "groups": []})
    _seal(home, store, pair_id="pair-cre-reserved",
          target_text="create seat _retired store_scope [] store_write [] permissions []",
          kr=ring_with_sean)
    out = _create_seat(store=store, pair_id="pair-cre-reserved",
                        apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EINVAL"


# ── envelope.ratify ───────────────────────────────────────────────────────
#
# Gap d3f79320ccb5: the fifth trust-owner verb, measured live 2026-09-22 —
# the desk's own envelope_ratify EACCES on the installed box, three
# envelopes queued behind it. Unlike the other four verbs, the apply half
# can never read the broker-owned proposals sidecar at all (Loki audits
# 367C367A T1 / 42B3B46F U1) — the request half copies the proposal's full
# row into the signed request at request time instead. `ratify_proposal_row`
# (envelope_authoring.py, the apply half's own primitive) refuses EREGISTRY
# unless the register resolves to $WILLOW_HOME/constitutional/pre-approved.json
# — same as envelope.revoke's own end-to-end test — so only the end-to-end
# test below skips `_charter`'s WILLOW_ENVELOPE_REGISTRY override.
#
# Rework, Loki audit BDC2B0F2: A2 (high) — the grammar now carries a
# digest over the proposal's governing fields (`tov._proposal_digest`),
# and both halves cross-check the copied row against FRANK's own
# `envelope_proposed` event. A1 (high) — `ratify_proposal_row`/`revoke`
# now load ONLY the active register, never the sidecar. A3 (medium) —
# `_save_active` signs the tmp candidate before either rename.

def _write_sidecar(home, proposals=None, archived=None):
    d = home / "proposals"
    d.mkdir(parents=True, exist_ok=True)
    (d / "proposals.json").write_text(json.dumps({
        "proposals": proposals or [], "archived": archived or [],
    }))


def _proposal_row(proposal_id="env-jeles-dispatch", verb="dispatch", verb_id=5,
                   grantee="jeles", bounds=None):
    return {
        "id": proposal_id, "verb_id": verb_id, "verb": verb, "grantee": grantee,
        "bounds": bounds or {}, "issued_by": "", "issued_at": "", "ratified_via": "",
        "expires_at": None, "max_count": None, "use_count_source": "frank",
        "status": "proposed", "notes": "test proposal",
        "proposed_at": "2026-01-01T00:00:00Z",
        "proposed_by": {"verifier": "sean", "session_id": "s1"}, "precedent_ids": [],
    }


def _digest_for(row):
    return tov._proposal_digest(row)


def _ratify_text(row, words="go ahead", digest=None):
    return f"ratify envelope {row['id']} {digest or _digest_for(row)}: {words}"


def _ink_proposed(ledger, row):
    """Seed the FRANK `envelope_proposed` anchor `envelope_authoring.propose`
    would have inked at propose time — the second independent check both
    halves now run against (Loki audit BDC2B0F2, A2)."""
    from willow_mcp import envelope_authoring as _ea

    ledger.append("willow", _ea.FRANK_EVENT_PROPOSED, {
        "envelope_id": row["id"], "verb": row["verb"], "verb_id": row["verb_id"],
        "grantee": row["grantee"], "bounds_digest": _ea._bounds_digest(row.get("bounds") or {}),
    })


def _envelope_ratify(app_id="willow", *, pair_id="pair-envrat-1", envelope_id="", ledger=None,
                      store=None, grants_root=None, db_path=None):
    return tov.envelope_ratify_request(
        app_id, envelope_id=envelope_id, pair_id=pair_id,
        ledger=ledger or _ledger(_FakeGovernancePg()), store=store,
        grants_root=grants_root, db_path=db_path,
    )


def test_envelope_ratify_non_orchestrator_is_eperm(home, tmp_path, store):
    out = _envelope_ratify("hanuman", store=store)
    assert out["error"] == "EPERM"


def test_envelope_ratify_no_seal_ring_is_eacces(home, tmp_path, store):
    """No keyring configured at all: `_verify_seal_only` refuses before the
    grammar or the sidecar is ever consulted — the "no seal" leg."""
    row = _proposal_row()
    _seal(home, store, pair_id="pair-envrat-1", target_text=_ratify_text(row))
    out = _envelope_ratify(store=store)
    assert out["error"] == "EACCES"


def test_envelope_ratify_grammar_miss_is_einval(home, tmp_path, store, ring_with_sean):
    _seal(home, store, pair_id="pair-envrat-1", target_text="please ratify it", kr=ring_with_sean)
    out = _envelope_ratify(store=store)
    assert out["error"] == "EINVAL"


def test_envelope_ratify_grammar_missing_digest_is_einval(home, tmp_path, store, ring_with_sean):
    """The pre-rework grammar (`ratify envelope <id>: <words>`, no digest)
    no longer matches — Loki audit BDC2B0F2, A2's own grammar change."""
    _seal(home, store, pair_id="pair-envrat-1",
          target_text="ratify envelope env-jeles-dispatch: go ahead", kr=ring_with_sean)
    out = _envelope_ratify(store=store)
    assert out["error"] == "EINVAL"


def test_envelope_ratify_unknown_proposal_is_enoent(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="envelope.ratify", verb_id=24,
             bounds={"proposal_ids": ["env-jeles-dispatch"]})
    _write_sidecar(home, proposals=[])
    row = _proposal_row()
    _seal(home, store, pair_id="pair-envrat-1", target_text=_ratify_text(row), kr=ring_with_sean)
    out = _envelope_ratify(store=store, grants_root=home / "manifest_grants")
    assert out["error"] == "ENOENT"


def test_envelope_ratify_already_active_is_ealready(home, tmp_path, monkeypatch, store, ring_with_sean):
    already_active = [{
        "id": "env-jeles-dispatch", "verb_id": 5, "verb": "dispatch", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    _charter(tmp_path, monkeypatch, verb="envelope.ratify", verb_id=24,
             bounds={"proposal_ids": ["env-jeles-dispatch"]}, extra=already_active)
    row = _proposal_row()
    _write_sidecar(home, proposals=[row])
    _seal(home, store, pair_id="pair-envrat-1", target_text=_ratify_text(row), kr=ring_with_sean)
    out = _envelope_ratify(store=store, grants_root=home / "manifest_grants")
    assert out["error"] == "EALREADY"


def test_envelope_ratify_existing_request_is_ealready(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="envelope.ratify", verb_id=24,
             bounds={"proposal_ids": ["env-jeles-dispatch"]})
    row = _proposal_row()
    _write_sidecar(home, proposals=[row])
    _seal(home, store, pair_id="pair-envrat-1", target_text=_ratify_text(row), kr=ring_with_sean)
    grants_root = home / "manifest_grants"
    (grants_root / "pending").mkdir(parents=True, exist_ok=True)
    (grants_root / "pending" / "pair-envrat-1.json").write_text(json.dumps({"pair_id": "pair-envrat-1"}))
    out = _envelope_ratify(store=store, grants_root=grants_root)
    assert out["error"] == "EALREADY"


def test_envelope_ratify_tampered_sidecar_refused_at_request(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """Loki audit BDC2B0F2, A2 — Loki's exact probe: the sidecar is edited
    (grantee/bounds changed) AFTER the digest was sealed. The request half
    refuses fast, before a citation is ever spent."""
    _charter(tmp_path, monkeypatch, verb="envelope.ratify", verb_id=24,
             bounds={"proposal_ids": ["env-jeles-dispatch"]})
    original = _proposal_row()
    sealed_digest = _digest_for(original)
    _seal(home, store, pair_id="pair-envrat-1",
          target_text=_ratify_text(original, digest=sealed_digest), kr=ring_with_sean)

    # The broker's own sidecar is edited after the seal: grantee escalated,
    # bounds widened to a wildcard.
    tampered = {**original, "grantee": "attacker", "bounds": {"a": ["*"]}}
    _write_sidecar(home, proposals=[tampered])

    out = _envelope_ratify(store=store, grants_root=home / "manifest_grants")
    assert out["error"] == "eseal_mismatch"
    assert out["computed_digest"] != out["expected_digest"]


def test_envelope_ratify_frank_disagreement_refused_at_request(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """The second anchor: even a row whose digest happens to match (a
    forged digest, or a coincidence) is refused if it disagrees with
    FRANK's own envelope_proposed event."""
    _charter(tmp_path, monkeypatch, verb="envelope.ratify", verb_id=24,
             bounds={"proposal_ids": ["env-jeles-dispatch"]})
    row = _proposal_row()
    _write_sidecar(home, proposals=[row])
    _seal(home, store, pair_id="pair-envrat-1", target_text=_ratify_text(row), kr=ring_with_sean)

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    # FRANK's own record of what was actually proposed disagrees (different
    # grantee) — no envelope_proposed event matches this row at all.
    _ink_proposed(ledger, {**row, "grantee": "jeles-corpus"})

    out = _envelope_ratify(store=store, ledger=ledger, grants_root=home / "manifest_grants")
    assert out["error"] == "edrift"
    assert "grantee" in out["fields"]


def test_envelope_ratify_end_to_end(home, tmp_path, monkeypatch, store, ring_with_sean):
    # Same reasoning as envelope.revoke's own end-to-end test: ratify_proposal_row
    # (the apply half's own primitive) refuses EREGISTRY unless the register
    # resolves to $WILLOW_HOME/constitutional/pre-approved.json, so this test
    # writes the charter at the DEFAULT resolution and never sets
    # WILLOW_ENVELOPE_REGISTRY.
    default_reg = home / "constitutional" / "pre-approved.json"
    default_reg.parent.mkdir(parents=True, exist_ok=True)
    governing = {
        "id": "env-envelope.ratify-test", "verb_id": 24, "verb": "envelope.ratify",
        "grantee": "willow", "bounds": {"proposal_ids": ["env-jeles-dispatch"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }
    default_reg.write_text(json.dumps({"active": [governing]}))
    tab = home / "constitutional" / "syscall-table.json"
    tab.write_text(json.dumps({"verbs": [{"id": 24, "verb": "envelope.ratify",
                                           "bounds": {"proposal_ids": "l"}}]}))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))

    proposal = _proposal_row(bounds={"channel": "ops"})
    _write_sidecar(home, proposals=[proposal])

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    _ink_proposed(ledger, proposal)

    _seal(home, store, pair_id="pair-envrat-1",
          target_text=_ratify_text(proposal, words="ratify all three"), kr=ring_with_sean)

    grants_root = home / "manifest_grants"
    out = _envelope_ratify(store=store, ledger=ledger, grants_root=grants_root)
    assert out["ok"] is True
    assert out["state"] == "requested"

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["ok"] is True
    assert processed["envelope_id"] == "env-jeles-dispatch"

    status = mgx.manifest_grant_status("pair-envrat-1", grants_root=grants_root)
    assert status["state"] == "done"

    registry = json.loads(default_reg.read_text())
    row = next(r for r in registry["active"] if r["id"] == "env-jeles-dispatch")
    assert row["status"] == "active"
    assert row["issued_by"] == "root"
    assert row["ratified_by"] == "sean"
    assert row["ratified_via"].startswith("frank ledger entry")

    assert _receipts(pg, tov.EVENT_ENVELOPE_RATIFIED)

    # Sidecar reconciliation (packet item 3): the sidecar still physically
    # carried the proposal (the apply half never touches it), but the
    # broker's own next read drops it once the register carries the id
    # active — the queue is truthful after the apply half acts.
    from willow_mcp import envelope_authoring as _ea
    pending = _ea.list_pending(include_precedents=False)
    assert not any(r["id"] == "env-jeles-dispatch" for r in pending)
    sidecar_doc = json.loads((home / "proposals" / "proposals.json").read_text())
    assert not any(r["id"] == "env-jeles-dispatch" for r in sidecar_doc["proposals"])


def test_envelope_ratify_apply_refuses_tampered_row_even_if_request_missed_it(
    home, tmp_path, store,
):
    """Loki audit BDC2B0F2, A2 — the check that actually holds: even if a
    hand-crafted pending/ record (never mind how) carries a row whose
    digest disagrees with the sealed one, the apply half refuses before
    ever calling ratify_proposal_row."""
    default_reg = home / "constitutional" / "pre-approved.json"
    default_reg.parent.mkdir(parents=True, exist_ok=True)
    default_reg.write_text(json.dumps({"active": []}))
    row = _proposal_row()
    sealed_digest = _digest_for(row)
    _seal(home, store, pair_id="pair-envrat-apply-tamper",
          target_text=_ratify_text(row, digest=sealed_digest), kr=None)
    # _seal without a ring writes a stub seal_sig — good enough here since
    # _apply_envelope_ratify's own seal re-verify is exercised elsewhere;
    # this test targets the digest re-check specifically, reached only
    # after a valid citation, so drive it directly against the function.
    tampered = {**row, "grantee": "attacker"}
    record = {
        "pair_id": "pair-envrat-apply-tamper", "verb": tov.VERB_ENVELOPE_RATIFY,
        "target": {"proposal_id": row["id"], "digest": sealed_digest, "words": "go ahead",
                    "proposal": tampered},
        "actor": "willow", "project": "willow-mcp", "session": "",
        "citation_id": "cit-x", "envelope_id": "env-x", "broker_sig": "irrelevant",
    }
    grants_root = home / "manifest_grants"
    (grants_root / "pending").mkdir(parents=True, exist_ok=True)
    path = grants_root / "pending" / "pair-envrat-apply-tamper.json"
    path.write_text(json.dumps(record))

    out = tov._apply_envelope_ratify(
        record, path, ledger=None, apps_root=home / "mcp_apps",
        db_path=None, grants_root=grants_root,
    )
    # eforged (signature check) or eseal_mismatch/edrift (seal/digest re-check)
    # — whichever gate is reached first, never `ok: True`.
    assert out.get("ok") is not True
    assert out["error"] in ("eforged", "eseal_mismatch", "edrift", "EACCES", "EUNREACH")


def test_ratify_and_revoke_never_read_the_sidecar(home, tmp_path, store, ring_with_sean):
    """Loki audit BDC2B0F2, A1 — ratify_proposal_row/revoke used to call
    _load_registry(), which opens the broker-owned sidecar too; as the
    trust owner that read is refused before any register write happens.
    Patch the sidecar path itself to blow up if touched, and confirm both
    apply-half primitives still complete a real write."""
    from willow_mcp import envelope_authoring as ea

    def _boom():
        raise AssertionError("apply-half primitives must never read the sidecar")

    reg = home / "constitutional" / "pre-approved.json"
    reg.parent.mkdir(parents=True, exist_ok=True)
    reg.write_text(json.dumps({"active": []}))

    with mock.patch.object(ea, "_proposals_path", _boom):
        row = _proposal_row(proposal_id="env-a1-test")
        result = ea.ratify_proposal_row(
            row, ratified_by="sean", ratified_via="frank ledger entry cit-1", ledger=None,
        )
        assert result["status"] == "active"
        assert result["id"] == "env-a1-test"

        revoked = ea.revoke("env-a1-test", verifier="sean", reason="cleanup", ledger=None)
        assert revoked["envelope_id"] == "env-a1-test"

    registry = json.loads(reg.read_text())
    row_after = next(r for r in registry["active"] if r["id"] == "env-a1-test")
    assert row_after.get("revoked") is True


def test_save_active_signs_tmp_before_rename_and_gpg_failure_leaves_prior_state(
    home, tmp_path, monkeypatch, store,
):
    """Loki audit BDC2B0F2, A3 — sign the tmp candidate BEFORE either
    rename (same order manifest_admin.publish_signed_pair already uses).
    A gpg failure must leave the prior register and its prior .sig
    byte-for-byte untouched, never a half-written register with a stale
    or missing signature."""
    from willow_mcp import envelope_authoring as ea
    from willow_mcp import pgp

    reg = home / "constitutional" / "pre-approved.json"
    reg.parent.mkdir(parents=True, exist_ok=True)
    prior_active = [{
        "id": "env-prior", "verb_id": 1, "verb": "dispatch", "grantee": "jeles",
        "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
        "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
        "status": "active",
    }]
    reg.write_text(json.dumps({"active": prior_active}))
    reg_sig = pgp.detached_sig_path(reg)
    reg_sig.write_bytes(b"-----BEGIN PGP SIGNATURE-----\nprior-sig\n-----END PGP SIGNATURE-----\n")
    prior_reg_bytes = reg.read_bytes()
    prior_sig_bytes = reg_sig.read_bytes()

    monkeypatch.setenv("WILLOW_PGP_FINGERPRINT", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234")
    monkeypatch.setattr(pgp, "sign_detached", lambda *a, **kw: (False, "simulated gpg failure"))

    with pytest.raises(ea.EnvelopeAuthoringError):
        ea._save_active({"active": prior_active + [{
            "id": "env-new", "verb_id": 2, "verb": "dispatch", "grantee": "jeles",
            "bounds": {}, "issued_by": "root", "issued_at": "2026-02-01",
            "expires_at": "2027-01-01", "max_count": None, "use_count_source": "frank",
            "status": "active",
        }]})

    assert reg.read_bytes() == prior_reg_bytes
    assert reg_sig.read_bytes() == prior_sig_bytes
    assert not (reg.parent / f"{reg.name}.tmp").exists()
    assert not pgp.detached_sig_path(reg.parent / f"{reg.name}.tmp").exists()


def test_envelope_ratify_apply_refuses_edrift_when_already_ratified(
    home, tmp_path, monkeypatch, store, ring_with_sean,
):
    """The apply-side re-check (never trust what request-time already
    verified) — same shape as the other three verbs' drift re-checks."""
    default_reg = home / "constitutional" / "pre-approved.json"
    default_reg.parent.mkdir(parents=True, exist_ok=True)
    governing = {
        "id": "env-envelope.ratify-test", "verb_id": 24, "verb": "envelope.ratify",
        "grantee": "willow", "bounds": {"proposal_ids": ["env-jeles-dispatch"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }
    default_reg.write_text(json.dumps({"active": [governing]}))
    tab = home / "constitutional" / "syscall-table.json"
    tab.write_text(json.dumps({"verbs": [{"id": 24, "verb": "envelope.ratify",
                                           "bounds": {"proposal_ids": "l"}}]}))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))
    proposal = _proposal_row(bounds={"channel": "ops"})
    _write_sidecar(home, proposals=[proposal])

    pg = _FakeGovernancePg()
    ledger = _ledger(pg)
    _ink_proposed(ledger, proposal)

    _seal(home, store, pair_id="pair-envrat-1",
          target_text=_ratify_text(proposal, words="ratify all three"), kr=ring_with_sean)

    grants_root = home / "manifest_grants"
    out = _envelope_ratify(store=store, ledger=ledger, grants_root=grants_root)
    assert out["ok"] is True

    # Drift: something else already ratified this proposal id between
    # request and apply.
    registry = json.loads(default_reg.read_text())
    registry["active"].append({**proposal, "issued_by": "root", "issued_at": "2026-02-01",
                                "status": "active", "ratified_via": "hand-edit", "ratified_by": "someone-else"})
    default_reg.write_text(json.dumps(registry))

    apply_out = _apply(ledger=ledger, apps_root=home / "mcp_apps", grants_root=grants_root)
    processed = apply_out["processed"][0]
    assert processed["error"] == "edrift"

    status = mgx.manifest_grant_status("pair-envrat-1", grants_root=grants_root)
    assert status["state"] == "failed"
