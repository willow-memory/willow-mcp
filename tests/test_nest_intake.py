"""Tests for the Nest live drop-folder router (willow_mcp.nest.intake + rules).

Covers the scan → queue → confirm/override/skip flow, the correction→flag
feedback loop (the classifier proposes a rule delta, a human ratifies), the
generic PII-free seed, and the gated MCP tools end-to-end.
"""
import json

import pytest

from willow_mcp import gate, server
from willow_mcp.db import Store
from willow_mcp.nest import intake, rules
from willow_mcp.receipts import ReceiptLog


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolate HOME + $WILLOW_HOME + the rules store into tmp so track_to_dest
    moves files into a throwaway tree and rules materialize from the seed."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "wh"))
    monkeypatch.setenv("WILLOW_NEST_RULES", str(tmp_path / "nest_rules.json"))
    rules._reset_cache()
    drop = tmp_path / "Desktop" / "Nest"
    drop.mkdir(parents=True)
    return tmp_path, drop


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "store"))


# ── the generic seed + classifier ────────────────────────────────────────────

def test_seed_is_pii_free_and_generic():
    """The shipped seed must not carry the operator's private keywords (case
    numbers, medical/legal matters, personal names) that the willow-2.0 seed had."""
    text = rules.SEED_PATH.read_text().lower()
    for leaked in ("bankruptcy", "physical therapy", "workers", "debtor",
                   "regarding jane", "isd 408", "cse 600", "huntsville", "3dkxz"):
        assert leaked not in text, f"seed leaked private keyword: {leaked!r}"


def test_classify_deterministic_and_expected(env):
    assert rules.classify("2024-05-01.md") == "journal"      # date pattern
    assert rules.classify("invoice_march.pdf") == "financial"  # keyword
    assert rules.classify("mystery.bin") is None              # unknown
    assert rules.classify(".hidden") is None                  # ignored (dotfile)
    assert rules.classify("screenshot 2026.png") == "screenshots"
    assert rules.classify("willow-bot.pem") == "secrets"
    assert rules.classify("github-app-private-key.pem") == "secrets"
    assert rules.classify("willow-bot.env") == "secrets"


def test_confirm_secrets_track_chmod_600(env, store):
    from pathlib import Path
    _tmp, drop = env
    f = drop / "willow-bot.pem"
    f.write_text("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")
    intake.scan(store, folders=[drop])
    item = next(i for i in intake.get_queue(store) if i["filename"] == "willow-bot.pem")
    assert item["track"] == "secrets"
    res = intake.confirm(store, item["id"], app_id="tester")
    dest = Path(res["moved_to"])
    assert dest.exists() and dest.parent.name == "secrets"
    assert (dest.stat().st_mode & 0o777) == 0o600


# ── scan / queue ─────────────────────────────────────────────────────────────

def test_scan_stages_and_is_idempotent(env, store):
    _tmp, drop = env
    (drop / "2024-05-01.md").write_text("j")
    (drop / "invoice_x.pdf").write_text("i")
    first = intake.scan(store, folders=[drop])
    assert {i["track"] for i in first} == {"journal", "financial"}
    # re-scan stages nothing new
    assert intake.scan(store, folders=[drop]) == []
    assert len(intake.get_queue(store)) == 2


# ── confirm / override / skip ────────────────────────────────────────────────

def test_confirm_moves_file_to_predicted_dest(env, store):
    _tmp, drop = env
    f = drop / "2024-05-01.md"
    f.write_text("j")
    intake.scan(store, folders=[drop])
    item = intake.get_queue(store)[0]
    res = intake.confirm(store, item["id"], app_id="tester")
    assert res["status"] == "confirmed" and res["event"] == "confirm"
    assert res["track"] == "journal"
    assert not f.exists()                       # moved out of the drop
    assert Path(res["moved_to"]).exists()       # moved into the track dir


def test_skip_removes_from_queue(env, store):
    _tmp, drop = env
    (drop / "mystery.bin").write_text("x")
    intake.scan(store, folders=[drop])
    item = intake.get_queue(store)[0]
    intake.skip(store, item["id"], app_id="tester")
    assert intake.get_queue(store) == []


def test_override_records_correction_and_flag_at_threshold(env, store):
    _tmp, drop = env
    legal_dir = env[0] / "personal" / "legal"
    # three unknown .pdf files, each filed to legal → same (unknown→legal,.pdf) key
    for k in range(3):
        (drop / f"doc_{k}.pdf").write_text("x")
    intake.scan(store, folders=[drop])
    events = []
    for it in list(intake.get_queue(store)):
        r = intake.confirm(store, it["id"],
                           override_dest=str(legal_dir / it["filename"]),
                           app_id="tester")
        events.append(r["event"])
    assert events == ["override", "override", "override"]
    flags = intake.open_flags(store)
    assert len(flags) == 1
    assert "unknown → legal" in flags[0]["title"]
    assert flags[0]["hit_count"] == 3


# ── gate ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def apps_root(tmp_path, monkeypatch):
    root = tmp_path / "mcp_apps"
    root.mkdir()
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(root))
    return root


def _manifest(apps_root, app_id, perms):
    d = apps_root / app_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps({"permissions": perms}))
    return app_id


def test_gate_router_read_vs_write(apps_root):
    _manifest(apps_root, "r", ["nest_read"])
    _manifest(apps_root, "w", ["nest_write"])
    assert gate.permitted("r", "nest_intake_queue") is True
    assert gate.permitted("r", "nest_intake_flags") is True
    assert gate.permitted("r", "nest_intake_scan") is False
    assert gate.permitted("r", "nest_intake_file") is False
    assert gate.permitted("w", "nest_intake_scan") is True
    assert gate.permitted("w", "nest_intake_file") is True
    assert gate.permitted("w", "nest_intake_skip") is True
    assert gate.permitted("w", "nest_intake_queue") is False


# ── tools end-to-end through _guarded ────────────────────────────────────────

@pytest.fixture
def mk_app(tmp_path, monkeypatch):
    apps = tmp_path / "apps"
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps))
    monkeypatch.setattr(server, "_store", Store(str(tmp_path / "tstore")))
    monkeypatch.setattr(server, "_receipt_log", ReceiptLog(str(tmp_path / "r.db")))
    monkeypatch.setattr(server, "_buckets", {})

    def _mk(app_id, perms):
        d = apps / app_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text(json.dumps({"permissions": perms}))
        return app_id

    return _mk


def _fn(tool):
    return getattr(tool, "fn", tool)


def test_tools_scan_queue_file_end_to_end(env, mk_app):
    _tmp, drop = env
    f = drop / "invoice_x.pdf"
    f.write_text("i")
    mk_app("router", ["nest_write", "nest_read"])
    scan = _fn(server.nest_intake_scan)("router", folder=str(drop))
    assert scan["status"] == "ok" and scan["newly_staged"] == 1
    q = _fn(server.nest_intake_queue)("router")
    assert len(q["pending"]) == 1
    item = q["pending"][0]
    assert item["track"] == "financial"
    out = _fn(server.nest_intake_file)("router", item_id=item["id"])
    assert out["status"] == "confirmed"
    assert not f.exists() and Path(out["moved_to"]).exists()


def test_tool_denied_without_permission(env, mk_app):
    _tmp, drop = env
    mk_app("noperm", ["store_read"])
    out = _fn(server.nest_intake_scan)("noperm", folder=str(drop))
    assert "error" in out


# Path imported late so the fixtures above read cleanly.
from pathlib import Path  # noqa: E402
