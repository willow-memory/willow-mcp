"""The brokered model pull (verb 26 `model.pull`, bounds `{models}`).

A real HTTP server on an ephemeral loopback port plays the Ollama daemon —
no network, no real model, never the operator's daemon. The governance
ledger is an in-memory fake with the same SQL surface as
test_package_upgrade.py's.

What this file pins:

* the two keys: no live lease -> ENOLEASE, a model or tag outside the
  envelope's bounds -> EAMBIG, and in both the daemon never sees a pull;
* an unreachable daemon is EUNREACH and a non-loopback address EPERM, each
  distinct from the others;
* a failed pull (EPULL / EVERIFY / EUNREACH) writes no `envelope_citation`,
  so a `max_count=1` grant is still spendable on the retry;
* the happy path reports digest and bytes from the daemon and receipts
  model, tag, digest, bytes and lease id.
"""
from __future__ import annotations

import json
import socket
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from willow_mcp import lease
from willow_mcp import model_pull_executor as mpx

APP = "hanuman"
DIGEST = "a" * 64

# ── a fake frank ledger (same SQL surface as test_package_upgrade.py) ────────


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
        if s.startswith("INSERT INTO"):
            record_id, project, event_type, content, prev_hash, digest = params
            self.pg.rows.append({
                "id": record_id, "project": project, "event_type": event_type,
                "content": getattr(content, "adapted", content),
                "prev_hash": prev_hash, "hash": digest,
                "created_at": datetime.now(UTC),
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
    return [r["content"] for r in pg.rows if r["event_type"] == event]


def _granted_citations(pg, envelope_id="env-model.pull-test"):
    return [
        r for r in pg.rows
        if r["event_type"] == "envelope_citation"
        and r["content"].get("envelope_id") == envelope_id
        and r["content"].get("outcome") == "granted"
    ]


# ── registry with one model.pull grant ───────────────────────────────────────

MODELS = ["gemma4:e2b", "phi4-mini", "qwen3.5"]


def _charter(tmp_path, monkeypatch, *, models=MODELS, max_count=None, grantee=APP):
    active = [{
        "id": "env-model.pull-test",
        "verb_id": 26,
        "verb": "model.pull",
        "grantee": grantee,
        "bounds": {"models": list(models)},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": "2099-01-01",
        "max_count": max_count,
        "use_count_source": "frank",
        "status": "active",
    }]
    table = {"verbs": [{"id": 26, "verb": "model.pull", "bounds": {"models": "l"}}]}
    reg = tmp_path / "pre-approved.json"
    tab = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    reg.write_text(json.dumps({"active": active}))
    tab.write_text(json.dumps(table))
    reg.chmod(0o600)
    tab.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(reg))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(tab))


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(h))
    monkeypatch.delenv("WILLOW_MCP_APPS_ROOT", raising=False)
    return h


@pytest.fixture
def live_lease(home):
    lease.grant(APP, 600, "test-operator", "model pull test")


@pytest.fixture
def asks(monkeypatch):
    """Capture the human-required asks instead of touching a real store."""
    from willow_mcp import gate_request
    seen: list[dict] = []

    def _open(app_id, gate_id, **kw):
        seen.append({"app_id": app_id, "gate_id": gate_id, **kw})
        return {"queued": True, "id": "ask-1"}

    monkeypatch.setattr(gate_request, "open_request", _open)
    return seen


# ── a fake Ollama daemon on loopback ─────────────────────────────────────────


class _Daemon:
    def __init__(self):
        self.pulls: list[str] = []
        self.mode = "ok"            # ok | error_line | no_success | http_500
        self.tag_digest = DIGEST
        self.list_model = True      # False: /api/tags omits the pulled model
        self.size = 2_000_000_000
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _json(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/api/version":
                    return self._json(200, {"version": "0.0-fake"})
                if self.path == "/api/tags":
                    models = []
                    if outer.list_model and outer.pulls:
                        name = outer.pulls[-1]
                        if ":" not in name:
                            name += ":latest"
                        models.append({"name": name, "digest": outer.tag_digest,
                                       "size": outer.size})
                    return self._json(200, {"models": models})
                self._json(404, {})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(n) or b"{}")
                if self.path != "/api/pull":
                    return self._json(404, {})
                outer.pulls.append(req["model"])
                if outer.mode == "http_500":
                    return self._json(500, {"error": "boom"})
                lines = [
                    {"status": "pulling manifest"},
                    {"status": "pulling layer1", "digest": "sha256:l1", "total": 1500, "completed": 100},
                    {"status": "pulling layer1", "digest": "sha256:l1", "total": 1500, "completed": 1500},
                    {"status": "pulling layer2", "digest": "sha256:l2", "total": 500, "completed": 500},
                ]
                if outer.mode == "error_line":
                    lines.append({"error": "pull model manifest: file does not exist"})
                elif outer.mode != "no_success":
                    lines += [{"status": "verifying sha256 digest"},
                              {"status": "writing manifest"}, {"status": "success"}]
                body = "".join(json.dumps(x) + "\n" for x in lines).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._t = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._t.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def daemon():
    d = _Daemon()
    yield d
    d.close()


def _pull(pg, daemon_or_url, model="phi4-mini", **kw):
    url = daemon_or_url if isinstance(daemon_or_url, str) else daemon_or_url.url
    return mpx.execute_model_pull(
        APP, model=model, project="willow", session="sess-1",
        ledger=_ledger(pg), base_url=url, **kw,
    )


# ── happy path ───────────────────────────────────────────────────────────────


def test_granted_pull_reports_digest_bytes_and_receipts_everything(
        tmp_path, monkeypatch, live_lease, daemon, asks):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _pull(pg, daemon)
    assert out["ok"] is True and out["pulled"] is True, out
    assert (out["model"], out["tag"]) == ("phi4-mini", "latest")
    assert out["digest"] == DIGEST
    assert out["bytes"] == 2_000_000_000
    assert out["lease_id"].startswith(f"{APP}@")
    assert daemon.pulls == ["phi4-mini"]
    assert len(_granted_citations(pg)) == 1
    assert out["citation_id"] and out["receipt_id"]
    [rcpt] = _receipts(pg, mpx.EVENT)
    assert rcpt["model"] == "phi4-mini" and rcpt["tag"] == "latest"
    assert rcpt["digest"] == DIGEST and rcpt["bytes"] == 2_000_000_000
    assert rcpt["lease_id"] == out["lease_id"] and rcpt["actor"] == APP
    assert asks == []


def test_explicit_tag_is_passed_to_the_daemon_as_given(
        tmp_path, monkeypatch, live_lease, daemon, asks):
    _charter(tmp_path, monkeypatch)
    out = _pull(_FakeGovernancePg(), daemon, model="gemma4:e2b")
    assert out["ok"] is True, out
    assert daemon.pulls == ["gemma4:e2b"] and out["tag"] == "e2b"


# ── the lease key ────────────────────────────────────────────────────────────


def test_no_lease_refuses_enolease_and_the_daemon_never_sees_a_pull(
        tmp_path, monkeypatch, home, daemon, asks):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _pull(pg, daemon)
    assert out["ok"] is False and out["error"] == "ENOLEASE", out
    assert out["lease_status"] == "none"
    assert daemon.pulls == []
    assert _granted_citations(pg) == []
    assert [a["gate_id"] for a in asks] == ["model.phi4-mini"]


def test_an_expired_lease_is_not_a_lease(tmp_path, monkeypatch, home, daemon, asks):
    _charter(tmp_path, monkeypatch)
    out = _pull(_FakeGovernancePg(), daemon,
                lease_reader=lambda app: {"status": "expired"})
    assert out["error"] == "ENOLEASE" and out["lease_status"] == "expired"
    assert daemon.pulls == []


def test_another_apps_lease_does_not_authorize_the_caller(
        tmp_path, monkeypatch, home, daemon, asks):
    lease.grant("someone-else", 600, "test-operator", "x")
    _charter(tmp_path, monkeypatch)
    out = _pull(_FakeGovernancePg(), daemon)
    assert out["error"] == "ENOLEASE", out
    assert daemon.pulls == []


# ── the envelope key ─────────────────────────────────────────────────────────


def test_a_model_outside_the_bounds_is_eambig_and_never_pulled(
        tmp_path, monkeypatch, live_lease, daemon, asks):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _pull(pg, daemon, model="llama3")
    assert out["ok"] is False and out["error"] == "EAMBIG", out
    assert out["fields"] == ["models"]
    assert out["envelope_id"] == "env-model.pull-test"
    assert daemon.pulls == []
    assert _granted_citations(pg) == []
    assert asks and asks[0]["gate_id"] == "model.llama3"


def test_a_tag_outside_the_bounds_is_eambig_and_never_pulled(
        tmp_path, monkeypatch, live_lease, daemon, asks):
    _charter(tmp_path, monkeypatch)
    out = _pull(_FakeGovernancePg(), daemon, model="gemma4:e4b")
    assert out["error"] == "EAMBIG" and out["fields"] == ["models"], out
    assert daemon.pulls == []


def test_no_envelope_for_the_caller_is_enoent(
        tmp_path, monkeypatch, live_lease, daemon, asks):
    _charter(tmp_path, monkeypatch, grantee="someone-else")
    out = _pull(_FakeGovernancePg(), daemon)
    assert out["error"] == "ENOENT", out
    assert daemon.pulls == []


@pytest.mark.parametrize("bad", [
    "", "  ", "http://x/y", "registry.example.com/team/model:1", "a b", "../x",
])
def test_a_malformed_reference_is_einval(tmp_path, monkeypatch, live_lease, daemon, bad):
    _charter(tmp_path, monkeypatch)
    out = _pull(_FakeGovernancePg(), daemon, model=bad)
    assert out["error"] == "EINVAL", out
    assert daemon.pulls == []


# ── the daemon ───────────────────────────────────────────────────────────────


def _closed_port_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def test_an_unreachable_daemon_is_eunreach_and_spends_nothing(
        tmp_path, monkeypatch, live_lease, asks):
    _charter(tmp_path, monkeypatch)
    pg = _FakeGovernancePg()
    out = _pull(pg, _closed_port_url())
    assert out["ok"] is False and out["error"] == "EUNREACH", out
    assert out["cause"] == "connection_failed"
    assert _granted_citations(pg) == []
    [failed] = _receipts(pg, mpx.FAILED_EVENT)
    assert failed["errno"] == "EUNREACH"


def test_a_non_loopback_daemon_address_is_eperm(tmp_path, monkeypatch, live_lease, asks):
    _charter(tmp_path, monkeypatch)
    for url in ("http://10.0.0.5:11434", "http://example.com:11434", "https://127.0.0.1:11434"):
        out = _pull(_FakeGovernancePg(), url)
        assert out["error"] == "EPERM", (url, out)


def test_distinct_errnos_for_the_three_refusals(
        tmp_path, monkeypatch, home, daemon, asks):
    """No lease / out of bounds / daemon down each say a different thing."""
    _charter(tmp_path, monkeypatch)
    no_lease = _pull(_FakeGovernancePg(), daemon)["error"]
    lease.grant(APP, 600, "test-operator", "x")
    out_of_bounds = _pull(_FakeGovernancePg(), daemon, model="llama3")["error"]
    daemon_down = _pull(_FakeGovernancePg(), _closed_port_url())["error"]
    assert len({no_lease, out_of_bounds, daemon_down}) == 3
    assert (no_lease, out_of_bounds, daemon_down) == ("ENOLEASE", "EAMBIG", "EUNREACH")


# ── a failed pull does not spend the envelope ────────────────────────────────


@pytest.mark.parametrize("mode,errno", [
    ("error_line", "EPULL"), ("no_success", "EPULL"), ("http_500", "EPULL"),
])
def test_a_failed_pull_spends_nothing_and_the_single_use_grant_survives(
        tmp_path, monkeypatch, live_lease, daemon, asks, mode, errno):
    _charter(tmp_path, monkeypatch, max_count=1)
    pg = _FakeGovernancePg()
    daemon.mode = mode
    failed = _pull(pg, daemon)
    assert failed["ok"] is False and failed["error"] == errno, failed
    assert _granted_citations(pg) == []
    [rcpt] = _receipts(pg, mpx.FAILED_EVENT)
    assert rcpt["errno"] == errno and rcpt["lease_id"] == failed["lease_id"]
    assert _receipts(pg, mpx.EVENT) == []

    daemon.mode = "ok"
    retry = _pull(pg, daemon)
    assert retry["ok"] is True, retry          # max_count=1 was not burned
    assert len(_granted_citations(pg)) == 1
    again = _pull(pg, daemon)
    assert again["ok"] is False and again["error"] == "EDQUOT", again


@pytest.mark.parametrize("digest,listed", [
    (None, True), ("not-a-digest", True), (DIGEST, False),
])
def test_an_unverifiable_digest_is_everify_and_spends_nothing(
        tmp_path, monkeypatch, live_lease, daemon, asks, digest, listed):
    _charter(tmp_path, monkeypatch, max_count=1)
    pg = _FakeGovernancePg()
    daemon.tag_digest, daemon.list_model = digest, listed
    out = _pull(pg, daemon)
    assert out["ok"] is False and out["error"] == "EVERIFY", out
    assert _granted_citations(pg) == []
    assert _receipts(pg, mpx.EVENT) == []


# ── the tool surface ─────────────────────────────────────────────────────────


def test_the_tool_is_gated_as_envelope_apply_and_not_in_desk_core():
    from willow_mcp import advertise, server
    assert server._gate_tool_catalogue()["model_pull_execute"] == "envelope_apply"
    assert "model_pull_execute" not in advertise.DESK_CORE


def test_row_26_is_model_pull_with_bounds_models_only():
    from pathlib import Path

    from willow_mcp import envelope_authoring as ea
    bundle = (Path(__file__).resolve().parents[1] / "src" / "willow_mcp" / "bundle"
              / "constitutional" / "syscall-table.json")
    rows = {int(r["id"]): r for r in json.loads(bundle.read_text("utf-8"))["verbs"]}
    row = rows[26]
    assert row["verb"] == "model.pull" and set(row["bounds"]) == {"models"}
    assert ea._validate_bounds_signature("model.pull", {"models": ["phi4-mini"]}, rows) == 26
    with pytest.raises(ea.InvalidBoundsSignatureError, match="bounds signature mismatch"):
        ea._validate_bounds_signature("model.pull", {"models": ["x"], "extra": 1}, rows)


def test_a_model_ask_is_an_unpressable_envelope_request():
    from willow_mcp import gate_request, gates_panel
    assert gate_request.check_requestable("model.phi4-mini") is None
    assert not gates_panel.is_pressable("model.phi4-mini")
