"""The tool funnel refuses an unredactable credential rather than emitting it.

`_guarded` is the single place the README guarantee — "No tool ever returns a
credential" — is enforced. It scanned str/dict/list/tuple and passed anything
else through untouched, which was invisible while every tool returned a dict.

SEP-2322 changed that: a tool that pauses returns an `InputRequiredResult`.
These tests pin the branch that keeps such a result inside the guarantee, and
in particular that a hit **refuses** — a credential that cannot be redacted in
place must not be returned at all.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import server

FAKE_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    app_dir = tmp_path / "mcp_apps" / "opaqueapp"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": ["full_access"]}))
    return "opaqueapp"


class _Model:
    """A structured, non-dict result — what a pydantic result model looks like
    to the scanner."""

    def __init__(self, text: str):
        self.text = text

    def __str__(self) -> str:
        return f"_Model({self.text})"


def test_a_clean_opaque_result_passes_through(app):
    @server._guarded("store_list")
    def _tool(app_id: str = ""):
        return _Model("nothing secret here")

    out = _tool(app_id=app)
    assert isinstance(out, _Model)
    assert out.text == "nothing secret here"


def test_an_opaque_result_carrying_a_credential_is_refused(app):
    """The whole point. Before the branch existed this returned the model —
    and the token in it — with the funnel reporting nothing redacted."""
    @server._guarded("store_list")
    def _tool(app_id: str = ""):
        return _Model(FAKE_TOKEN)

    out = _tool(app_id=app)

    assert isinstance(out, dict)
    assert out == {"error": "egress_scan_refused"}
    assert FAKE_TOKEN not in json.dumps(out)


def test_a_dict_result_still_redacts_rather_than_refusing(app):
    """The existing behaviour for the shapes the scanner CAN rebuild is
    unchanged: redact in place and return, not refuse."""
    @server._guarded("store_list")
    def _tool(app_id: str = ""):
        return {"body": f"token={FAKE_TOKEN}"}

    out = _tool(app_id=app)

    assert isinstance(out, dict)
    assert FAKE_TOKEN not in json.dumps(out)
    assert "REDACTED" in json.dumps(out)


def test_an_unserializable_result_is_refused_not_returned(app):
    """Fail-closed on a result the scanner cannot even read."""
    class _Hostile:
        def __str__(self): raise RuntimeError("no")
        def __repr__(self): raise RuntimeError("no")

    @server._guarded("store_list")
    def _tool(app_id: str = ""):
        return _Hostile()

    out = _tool(app_id=app)
    assert out == {"error": "egress_scan_refused"}
