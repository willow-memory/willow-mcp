"""tests/test_meter.py — the meter never raises, never fails open, and rides
inside the receipt hash chain."""
import json

from willow_mcp import meter
from willow_mcp.receipts import ReceiptLog


def test_meter_never_raises_and_names_the_unseen(monkeypatch, tmp_path):
    # No RAPL, no nvidia-smi: every field must say so, none may be zero.
    monkeypatch.setattr(meter, "_RAPL_ROOT", tmp_path / "nope")
    monkeypatch.setattr(meter.shutil, "which", lambda _: None)
    with meter.Meter() as m:
        pass
    assert m.row["cpu_j"] == "unmetered"
    assert m.row["gpu_j"] == "unmetered"
    assert m.row["tokens"] == "unseen"
    assert m.row["elapsed_s"] >= 0


def test_meter_does_not_swallow_the_call(monkeypatch, tmp_path):
    monkeypatch.setattr(meter, "_RAPL_ROOT", tmp_path / "nope")
    monkeypatch.setattr(meter.shutil, "which", lambda _: None)
    try:
        with meter.Meter():
            raise ValueError("the call's own error")
    except ValueError as e:
        assert "own error" in str(e)
    else:
        raise AssertionError("meter swallowed the exception")


def test_rapl_counter_and_wrap(monkeypatch, tmp_path):
    zone = tmp_path / "intel-rapl:0"
    zone.mkdir()
    (zone / "name").write_text("package-0\n")
    (zone / "max_energy_range_uj").write_text("1000\n")
    (zone / "energy_uj").write_text("900\n")
    monkeypatch.setattr(meter, "_RAPL_ROOT", tmp_path)
    monkeypatch.setattr(meter.shutil, "which", lambda _: None)
    with meter.Meter() as m:
        (zone / "energy_uj").write_text("100\n")  # wrapped: 100 past the max
    assert m.row["cpu_j"] == round((1000 - 900 + 100) / 1e6, 3)


def test_meter_row_is_inside_the_chain(tmp_path):
    log = ReceiptLog(db_path=str(tmp_path / "r.db"))
    detail = json.dumps({"meter": {"cpu_j": 1.5, "elapsed_s": 0.2}}, separators=(",", ":"))
    log.record("willow", "nest_scan", "ok", detail)
    assert log.verify()["ok"]
    # Edit the joule count out of band: the chain must name the row.
    log._conn.execute("UPDATE receipts SET detail = ? WHERE id = 1",
                      (detail.replace("1.5", "0.1"),))
    v = log.verify()
    assert v["ok"] is False and v["broken_at"] == 1
