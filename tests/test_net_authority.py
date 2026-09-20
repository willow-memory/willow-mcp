"""Egress authority is seal-driven (decision c8572a92): the seat holds a
row and proposes a pair; the operator seals; a signer running as the key's
owner verifies the seal against a public-only ring and mints the envelope.
Every refusal names its field; the task text never crosses the socket.
Real ed25519 keys, a real sqlite `tm_pairs`, a real Unix socket — only the
Postgres queue and the SOIL store are fakes.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
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


@pytest.fixture
def verifier(tmp_path):
    """The operator's browser key: private half stays here (the 'browser'),
    public half goes into the ring."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    full = tmp_path / "verifiers.json"
    full.write_text(json.dumps({"version": 1, "verifiers": [{
        "name": "sean campbell", "key": pub.hex(), "kind": "ed25519",
        "private": priv.private_bytes(serialization.Encoding.Raw,
                                      serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption()).hex(),
        "revoked_at": None, "compromised": False, "reason": "", "created_at": "2026-09-14",
    }]}))
    full.chmod(0o600)
    return {"name": "sean campbell", "priv": priv, "pub": pub, "full_ring": full}


def _seal(verifier, source_norm: str, target_text: str) -> dict:
    sig = verifier["priv"].sign(ns.seal_message(source_norm, target_text, verifier["name"])).hex()
    return {"source_norm": source_norm, "target_text": target_text,
            "verifier": verifier["name"], "seal_sig": sig}


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
              seal_sig="", superseded_by=""):
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO tm_pairs (id, source_text, source_norm, source_lang, target_text, target_lang,"
        " status, verifier, created_at, seal_sig, superseded_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (pair_id, source_norm, source_norm, "decision", target_text, "decision", status, verifier,
         "2026-09-20T22:00:00Z", seal_sig, superseded_by))
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
    """Just enough of a cursor for hold/drain: an INSERT records values,
    a SELECT of held rows answers, an UPDATE releases."""

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
                elif s.startswith("UPDATE tasks"):
                    envelope, new_status, task_id, held = params
                    row = pg.tasks.get(task_id)
                    if row and row.get("status") == held:
                        row["network_authorization"] = envelope
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


# ── the sealed line ───────────────────────────────────────────────────────────

def test_bound_line_round_trips_and_rejects_drift():
    bound = {"task_id": "ABCD2345", "agent": "kart", "submitted_by": "willow",
             "task_hash": "a" * 64, "scope": "network", "ttl": "600",
             "nonce": "n" * 32}
    line = na.bound_line(bound)
    assert line.startswith("willow-net-auth-v2 task_id=ABCD2345 ")
    assert na.parse_bound_line(line) == bound
    assert na.parse_bound_line(line + " extra=1") is None
    assert na.parse_bound_line(line.replace("scope=network", "scope=root")) is None
    assert na.parse_bound_line("willow-net-auth-v1 " + line.split(" ", 1)[1]) is None
    assert na.parse_bound_line(line + "\nsecond line") is None


def test_bound_line_refuses_a_separator_in_a_value():
    with pytest.raises(ValueError):
        na.bound_line({"task_id": "ABCD2345", "agent": "ka rt", "submitted_by": "w",
                       "task_hash": "a" * 64, "scope": "network", "ttl": "1", "nonce": "n" * 32})


# ── the public-only ring ──────────────────────────────────────────────────────

def test_export_ring_drops_private_halves_and_load_refuses_one_that_kept_them(verifier, tmp_path):
    out = tmp_path / "pub.json"
    exported = ns.export_public_ring(verifier["full_ring"], out)
    data = json.loads(out.read_text())
    assert exported["verifiers"] == ["sean campbell"]
    assert all("private" not in v for v in data["verifiers"])
    assert data["public_only"] is True
    ring = ns.load_public_ring(out)
    assert ring["sean campbell"]["key"] == verifier["pub"]
    with pytest.raises(ValueError, match="private half"):
        ns.load_public_ring(verifier["full_ring"])


# ── the signer ────────────────────────────────────────────────────────────────

def _bound_for(task, task_id="ABCD2345", agent="kart", submitted_by="willow", ttl="600",
               nonce=None, scope="network"):
    return {"task_id": task_id, "agent": agent, "submitted_by": submitted_by,
            "task_hash": ea.normalized_task_hash(task), "scope": scope, "ttl": ttl,
            "nonce": nonce or ("q" * 32)}


def test_signer_mints_only_what_the_operator_sealed(egress_keys, verifier, tmp_path):
    key, pub = egress_keys
    signer = ns.Signer(private_key_path=key, ring=_ring(verifier, tmp_path))
    task = "curl https://example.invalid\n# allow_net"
    bound = _bound_for(task)
    line = na.bound_line(bound)
    seal = _seal(verifier, "authorize network for kart task abcd2345", line)

    reply = signer.handle({"op": "sign_task", "seal": seal, "bound": bound, "pair_id": "p1"})
    assert reply["state"] == "minted", reply
    ok, reason, payload = ea.verify_envelope(
        public_key_path=pub, submitted_by="willow", task_id="ABCD2345", agent="kart",
        task=task, envelope=reply["envelope"])
    assert ok, reason
    assert payload["seal_pair_id"] == "p1"
    assert ea.seal_pair_id_of(reply["envelope"]) == "p1"
    # The same envelope is worth nothing for any other row.
    ok2, reason2, _ = ea.verify_envelope(
        public_key_path=pub, submitted_by="willow", task_id="ZZZZ9999", agent="kart",
        task=task, envelope=reply["envelope"])
    assert not ok2 and reason2 == "task_id mismatch"
    ok3, reason3, _ = ea.verify_envelope(
        public_key_path=pub, submitted_by="willow", task_id="ABCD2345", agent="kart",
        task=task + "\nrm -rf /", envelope=reply["envelope"])
    assert not ok3 and reason3 == "task hash mismatch"


def test_signer_refuses_each_way_a_uid_1000_process_could_try(egress_keys, verifier, tmp_path):
    key, _ = egress_keys
    signer = ns.Signer(private_key_path=key, ring=_ring(verifier, tmp_path))
    task = "echo hi\n# allow_net"
    bound = _bound_for(task)
    line = na.bound_line(bound)
    good = _seal(verifier, "q", line)

    # unsealed: no signature at all
    r = signer.handle({"op": "sign_task", "seal": {**good, "seal_sig": ""}, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "seal_sig"
    # a signature by a key that is not in the ring
    stranger = Ed25519PrivateKey.generate()
    forged = {**good, "seal_sig": stranger.sign(ns.seal_message("q", line, "sean campbell")).hex()}
    r = signer.handle({"op": "sign_task", "seal": forged, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "seal_sig"
    # a verifier the ring never knew
    r = signer.handle({"op": "sign_task", "seal": {**good, "verifier": "mallory"}, "bound": bound})
    assert r["state"] == "refused" and r["field"] == "verifier"
    # a sealed line that is not a bound line
    r = signer.handle({"op": "sign_task", "seal": _seal(verifier, "q", "yes, do it"), "bound": bound})
    assert r["state"] == "refused" and r["field"] == "target_text"
    # the row drifted from what was sealed — every field is named
    for field, value in (("task_hash", "b" * 64), ("agent", "loki"), ("nonce", "z" * 32),
                         ("submitted_by", "hanuman"), ("ttl", "601"), ("task_id", "ZZZZ9999")):
        r = signer.handle({"op": "sign_task", "seal": good, "bound": {**bound, field: value}})
        assert r["state"] == "refused" and r["field"] == field, (field, r)
    # the task text never reaches the signer
    r = signer.handle({"op": "sign_task", "seal": good, "bound": bound, "task": task})
    assert r["state"] == "refused" and r["field"] == "task"


def test_signer_refuses_a_compromised_key(egress_keys, verifier, tmp_path):
    key, _ = egress_keys
    ring = _ring(verifier, tmp_path)
    ring["sean campbell"]["compromised"] = True
    signer = ns.Signer(private_key_path=key, ring=ring)
    bound = _bound_for("x\n# allow_net")
    r = signer.handle({"op": "sign_task", "seal": _seal(verifier, "q", na.bound_line(bound)),
                       "bound": bound})
    assert r["state"] == "refused" and r["field"] == "verifier"


def test_signer_mints_a_lease_in_lease_py_shape(egress_keys, verifier, tmp_path, monkeypatch):
    from willow_mcp import lease as lease_mod

    key, _ = egress_keys
    apps = tmp_path / "apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps))
    signer = ns.Signer(private_key_path=key, ring=_ring(verifier, tmp_path), lease_root=apps)
    reason = "Friday morning fun"
    bound = {"app_id": "willow", "ttl": "1800",
             "reason_sha": hashlib.sha256(reason.encode()).hexdigest()[:16], "scope": "lease"}
    line = na.lease_bound_line(bound)
    r = signer.handle({"op": "sign_lease", "seal": _seal(verifier, "grant", line), "bound": bound,
                       "reason": reason, "pair_id": "pl"})
    assert r["state"] == "minted", r
    state = lease_mod.read_lease("willow")
    assert state["status"] == "active" and state["issuer"] == "seal:sean campbell"
    assert state["reason"] == reason
    # a different reason text than the sealed sha is refused
    r = signer.handle({"op": "sign_lease", "seal": _seal(verifier, "grant", line), "bound": bound,
                       "reason": "something else"})
    assert r["state"] == "refused" and r["field"] == "reason"


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
    bound = _bound_for(task)
    seal = _seal(verifier, "q", na.bound_line(bound))
    reply = na.signer_call({"op": "sign_task", "seal": seal, "bound": bound, "pair_id": "p"},
                           path=sock)
    assert reply["state"] == "minted"
    assert ea.verify_envelope(public_key_path=pub, submitted_by="willow", task_id="ABCD2345",
                              agent="kart", task=task, envelope=reply["envelope"])[0]
    # refused travels with its field
    reply = na.signer_call({"op": "sign_task", "seal": seal, "bound": {**bound, "agent": "loki"}},
                           path=sock)
    assert reply["state"] == "refused" and reply["field"] == "agent"
    # the client refuses to send the task text before it touches the socket
    reply = na.signer_call({"op": "sign_task", "seal": seal, "bound": bound, "task": task}, path=sock)
    assert reply["state"] == "refused"
    # no signer -> unreachable, never an exception
    reply = na.signer_call({"op": "sign_task"}, path=tmp_path / "absent")
    assert reply["state"] == "unreachable" and "socket" in reply


# ── request: hold and propose ─────────────────────────────────────────────────

def test_hold_inserts_an_unclaimable_row_and_proposes_one_sealable_line():
    pg, store = _FakePg(), _FakeStore()
    out = _held(pg, store)
    assert out["status"] == na.HELD_STATUS and out["pair_id"].startswith("pair-net-auth-")
    row = pg.tasks[out["task_id"]]
    assert row["status"] == na.HELD_STATUS and row["submitted_by"] == "willow"
    bound = na.parse_bound_line(out["seal_this"])
    assert bound["task_id"] == out["task_id"]
    assert bound["task_hash"] == ea.normalized_task_hash(row["task"])
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, na.record_id_for_task(out["task_id"]))
    assert gov["ruling"] == out["seal_this"] and gov["rationale"] == row["task"]
    assert gov["kind"] == "net-authorization-request"


def test_hold_does_not_insert_when_the_propose_fails():
    pg, store = _FakePg(), _FakeStore()
    out = _held(pg, store, propose=lambda *a, **k: {"error": "nestor_unavailable"})
    assert out["error"].startswith("net_hold_denied: nestor_unavailable")
    assert pg.tasks == {}


# ── act: the tick ─────────────────────────────────────────────────────────────

def _stamp(store, record_id, pair_id):
    gov = store.get(seal_handler.GOVERNANCE_COLLECTION, record_id)
    gov["nestor_pair_id"] = pair_id
    store.update(seal_handler.GOVERNANCE_COLLECTION, record_id, gov)


class _Ledger:
    def __init__(self):
        self.rows = []

    def append(self, project, event, content):
        self.rows.append((project, event, content))
        return f"frank-{len(self.rows)}"


def test_tick_waits_on_a_draft_mints_on_a_seal_and_is_quiet_after(egress_keys, verifier, tmp_path,
                                                                     monkeypatch):
    key, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    ledger = _Ledger()
    signer = ns.Signer(private_key_path=key, ring=_ring(verifier, tmp_path))
    call = signer.handle

    out = _held(pg, store)
    tid, rid = out["task_id"], out["record_id"]
    _stamp(store, rid, "pair-1")
    _put_pair(db, "pair-1", "q", out["seal_this"])  # draft, unsealed

    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=call)
    assert r["state"] == "populated" and r["rows"][0]["state"] == "waiting"
    assert r["rows"][0]["why"] == "status=draft"
    assert pg.tasks[tid]["status"] == na.HELD_STATUS and ledger.rows == []

    # the operator seals it
    sealed = _seal(verifier, "q", out["seal_this"])
    conn = sqlite3.connect(db)
    conn.execute("UPDATE tm_pairs SET status='sealed', verifier=?, seal_sig=? WHERE id='pair-1'",
                 (verifier["name"], sealed["seal_sig"]))
    conn.commit()
    conn.close()

    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=call)
    row = r["rows"][0]
    assert row["state"] == "minted" and row["released_to"] == "pending", row
    assert pg.tasks[tid]["status"] == "pending"
    ok, reason, payload = ea.verify_envelope(
        public_key_path=pub, submitted_by="willow", task_id=tid, agent="kart",
        task=pg.tasks[tid]["task"], envelope=pg.tasks[tid]["network_authorization"])
    assert ok and payload["seal_pair_id"] == "pair-1"
    assert ledger.rows[-1][1] == na.EVENT_MINTED
    assert ledger.rows[-1][2]["pair_id"] == "pair-1" and ledger.rows[-1][2]["verifier"] == "sean campbell"

    # next tick: nothing held
    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=call)
    assert r["state"] == "empty"


def test_tick_refuses_a_row_that_drifted_from_its_seal_and_inks_it(egress_keys, verifier, tmp_path,
                                                                     monkeypatch):
    key, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    ledger = _Ledger()
    signer = ns.Signer(private_key_path=key, ring=_ring(verifier, tmp_path))
    out = _held(pg, store)
    tid, rid = out["task_id"], out["record_id"]
    _stamp(store, rid, "pair-2")
    sealed = _seal(verifier, "q", out["seal_this"])
    _put_pair(db, "pair-2", "q", out["seal_this"], status="sealed", verifier=verifier["name"],
              seal_sig=sealed["seal_sig"])
    # the row's text changes under the seal (an agent edited the queue)
    pg.tasks[tid]["task"] = "curl https://evil\n# allow_net"
    r = na.drain(pg=pg, cols=_COLS, ledger=ledger, store=store, db_path=db, call=signer.handle)
    row = r["rows"][0]
    assert row["state"] == "refused" and row["field"] == "task_hash"
    assert pg.tasks[tid]["status"] == na.HELD_STATUS
    assert ledger.rows[-1][1] == na.EVENT_REFUSED and ledger.rows[-1][2]["field"] == "task_hash"


def test_tick_three_state_on_the_signer_and_the_seal_store(egress_keys, verifier, tmp_path,
                                                             monkeypatch):
    key, pub = egress_keys
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    pg, store, db = _FakePg(), _FakeStore(), _nestor_db(tmp_path)
    out = _held(pg, store)
    _stamp(store, out["record_id"], "pair-3")
    sealed = _seal(verifier, "q", out["seal_this"])
    _put_pair(db, "pair-3", "q", out["seal_this"], status="sealed", verifier=verifier["name"],
              seal_sig=sealed["seal_sig"])
    # signer down
    r = na.drain(pg=pg, cols=_COLS, store=store, db_path=db,
                 call=lambda req: {"state": "unreachable", "cause": "ECONNREFUSED", "socket": "/x"})
    assert r["rows"][0]["state"] == "unreachable" and r["counts"]["unreachable"] == 1
    assert pg.tasks[out["task_id"]]["status"] == na.HELD_STATUS
    # nestor.db gone
    r = na.drain(pg=pg, cols=_COLS, store=store, db_path=tmp_path / "nope.db",
                 call=lambda req: pytest.fail("signer must not be called"))
    assert r["rows"][0]["state"] == "unreachable"
    # a signer that returns an envelope for a DIFFERENT row is a refusal, not a release
    def wrong_signer(req):
        return {"state": "minted", "envelope": ea.sign_envelope(
            private_key_path=key, submitted_by="willow", task_id="ZZZZ9999", agent="kart",
            task_hash="a" * 64, ttl_seconds=60, nonce="n" * 32)}
    r = na.drain(pg=pg, cols=_COLS, store=store, db_path=db, call=wrong_signer)
    assert r["rows"][0]["state"] == "refused" and r["rows"][0]["field"] == "envelope"
    assert pg.tasks[out["task_id"]]["status"] == na.HELD_STATUS
    # no receipt path when there is no ledger: said, not hidden
    assert r["inked"] is False


def test_superseded_or_unsigned_pair_is_waiting_not_minted(tmp_path, verifier):
    db = _nestor_db(tmp_path)
    _put_pair(db, "a", "q", "t", status="sealed", verifier="v", seal_sig="ab", superseded_by="b")
    _put_pair(db, "b", "q", "t", status="sealed", verifier="v", seal_sig="")
    assert na.read_sealed_pair("a", db)["why"] == "superseded"
    assert na.read_sealed_pair("b", db)["why"] == "unsigned"
    assert na.read_sealed_pair("c", db)["why"] == "pair_absent"
    assert na.read_sealed_pair("a", tmp_path / "missing.db")["state"] == "unreachable"


# ── the executor: a seal stands in for the lease, only after verifying ────────

def test_executor_accepts_a_seal_minted_envelope_without_a_standing_lease(egress_keys, monkeypatch):
    from willow_mcp import consent, gate, lease

    key, pub = egress_keys
    monkeypatch.setattr(gate, "permitted", lambda app, perm: True)
    monkeypatch.setattr(consent, "internet_permitted", lambda: True)
    monkeypatch.setattr(lease, "active", lambda app: False)
    monkeypatch.setattr(lease, "strict_trust_root", lambda: True)  # the executor requires it
    monkeypatch.setattr(lease, "self_writable_trust_paths", lambda app: [])
    monkeypatch.setattr(lease, "path_is_self_writable_or_replaceable", lambda p: False)
    monkeypatch.setattr(ea, "public_key_path", lambda: pub)
    monkeypatch.setattr(ea, "_row_blocks_net_authorization", lambda tid: None)
    monkeypatch.setattr(ea, "_consume_row_net_authorization", lambda tid: True)

    class Row:
        submitted_by, task_id, agent, task = "willow", "ABCD2345", "kart", "x\n# allow_net"

    sealed = ea.sign_envelope(private_key_path=key, submitted_by="willow", task_id="ABCD2345",
                              agent="kart", task_hash=ea.normalized_task_hash(Row.task),
                              ttl_seconds=60, nonce="n" * 32, seal_pair_id="pair-9")
    terminal = ea.sign_envelope(private_key_path=key, submitted_by="willow", task_id="ABCD2345",
                                agent="kart", task=Row.task, ttl_seconds=60, nonce="m" * 32)
    auth = ea.ExecutorNetworkAuthorizer()
    assert auth(Row(), sealed) is True
    assert auth(Row(), terminal) is False and auth.last_error == "egress lease denied"
    # an unsigned claim of a seal is worth nothing: tamper the payload
    parsed = json.loads(terminal)
    parsed["payload"]["seal_pair_id"] = "pair-9"
    assert auth(Row(), json.dumps(parsed)) is False and auth.last_error == "invalid signature"


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
    line = ns.install_lines(rendered_path=tmp_path / ns.UNIT, ring_source=tmp_path / "r.json",
                            ring_dest=Path("/k/verifiers.public.json"))
    assert line.count("sudo") == 4 and "systemctl enable --now" in line


def test_hold_ttl_is_inside_the_lease_ceiling():
    from willow_mcp import lease, server

    assert 0 < server._HELD_NET_TTL_SECONDS <= lease.MAX_TTL_SECONDS


def test_now_is_utc():
    assert na._now().tzinfo == timezone.utc and isinstance(datetime.now(timezone.utc), datetime)
