"""unit_ops.main exit codes: an idle tick is a success, a failed request is not.

Regression: with nothing pending, results == [] and the old fallback
`or [True]` called True.get("ok"), so every idle timer tick crashed with
AttributeError and the unit sat in `failed` (operator box, since Oct 1).
"""

import pytest

from willow_mcp import db, governance_ledger, unit_ops


@pytest.fixture
def stub_backends(monkeypatch):
    monkeypatch.setattr(db, "get_pg", lambda: object())
    monkeypatch.setattr(governance_ledger, "GovernanceLedger", lambda pg: object())


def _tick_returning(monkeypatch, results):
    monkeypatch.setattr(
        unit_ops,
        "tick",
        lambda *, ledger=None: {"ok": True, "processed": len(results), "remaining": 0, "results": results},
    )


def test_idle_tick_exits_zero(stub_backends, monkeypatch, capsys):
    _tick_returning(monkeypatch, [])
    assert unit_ops.main(["tick"]) == 0
    assert '"processed": 0' in capsys.readouterr().out


def test_all_requests_ok_exits_zero(stub_backends, monkeypatch):
    _tick_returning(monkeypatch, [{"ok": True}, {"ok": True}])
    assert unit_ops.main(["tick"]) == 0


def test_a_failed_request_exits_one(stub_backends, monkeypatch):
    _tick_returning(monkeypatch, [{"ok": True}, {"ok": False, "error": "enable failed"}])
    assert unit_ops.main(["tick"]) == 1


def test_postgres_unavailable_exits_one(monkeypatch, capsys):
    monkeypatch.setattr(db, "get_pg", lambda: None)
    assert unit_ops.main(["tick"]) == 1
    assert "postgres unavailable" in capsys.readouterr().err
