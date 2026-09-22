"""The four trust-owner verbs added alongside `manifest.grant` on the same
queue (:mod:`willow_mcp.trust_owner_verbs`, sealed `1bd6fd29`): `envelope.revoke`,
`manifest.retire`, `manifest.create`, `federation.ratify`. Fixtures mirror
`tests/test_manifest_grant.py` (same fake FRANK ledger, same real-ed25519
sealed-pair machinery) since these verbs share that module's queue and
signing key.
"""
from __future__ import annotations

import json
import stat
from datetime import datetime, timezone

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
    _charter(tmp_path, monkeypatch, verb="envelope.revoke", verb_id=19, bounds={"envelope_ids": ["env-x"]})
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
        "id": "env-envelope.revoke-test", "verb_id": 19, "verb": "envelope.revoke",
        "grantee": "willow", "bounds": {"envelope_ids": ["env-x"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }] + active_extra
    default_reg.write_text(json.dumps({"active": active}))
    tab = home / "constitutional" / "syscall-table.json"
    tab.write_text(json.dumps({"verbs": [{"id": 19, "verb": "envelope.revoke",
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
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=20, bounds={"apps": ["ghost"]})
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
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=20, bounds={"apps": ["jeles"]},
             extra=active_extra)
    _manifest(home, "jeles")
    _seal(home, store, pair_id="pair-ret-1", target_text="retire seat jeles: retiring the organ",
          kr=ring_with_sean)
    out = _retire_seat(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EBUSY"
    assert "env-jeles-dispatch" in out["envelope_ids"]


def test_retire_end_to_end(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.retire", verb_id=20, bounds={"apps": ["jeles"]})
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
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=21,
             bounds={"apps": ["jeles-corpus"], "groups": ["full_access"]})
    _seal(home, store, pair_id="pair-cre-1",
          target_text="create seat jeles-corpus store_scope [] store_write [] permissions [full_access]",
          kr=ring_with_sean)
    out = _create_seat(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EPERM"
    assert "full_access" in out["escalating"]


def test_create_already_exists_is_eexist(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=21,
             bounds={"apps": ["jeles-corpus"], "groups": []})
    _manifest(home, "jeles-corpus")
    _seal(home, store, pair_id="pair-cre-1",
          target_text="create seat jeles-corpus store_scope [] store_write [] permissions []",
          kr=ring_with_sean)
    out = _create_seat(store=store, apps_root=home / "mcp_apps", grants_root=home / "manifest_grants")
    assert out["error"] == "EEXIST"


def test_create_end_to_end_jeles_corpus(home, tmp_path, monkeypatch, store, ring_with_sean):
    _charter(tmp_path, monkeypatch, verb="manifest.create", verb_id=21,
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
    _charter(tmp_path, monkeypatch, verb="federation.ratify", verb_id=22,
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
