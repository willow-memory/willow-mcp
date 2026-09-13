"""Desktop pinentry presence challenge — Assuan GETPIN, PIN discarded."""
from __future__ import annotations

from unittest import mock

from willow_mcp.presence import (
    PresenceResult,
    _assuan_escape,
    challenge_presence,
    presence_challenge_enabled,
)


def test_assuan_escape_percent_and_control():
    assert _assuan_escape("a%b\nc") == "a%25b%0Ac"


def test_challenge_disabled_returns_ok(monkeypatch):
    monkeypatch.setenv("WILLOW_PRESENCE_CHALLENGE", "off")
    assert presence_challenge_enabled() is False
    result = challenge_presence()
    assert result == PresenceResult("ok", "WILLOW_PRESENCE_CHALLENGE disabled")


def test_challenge_unavailable_without_pinentry(monkeypatch):
    monkeypatch.setenv("WILLOW_PRESENCE_CHALLENGE", "1")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("PINENTRY_PROGRAM", raising=False)
    with mock.patch("willow_mcp.presence.shutil.which", return_value=None):
        result = challenge_presence()
    assert result.status == "unavailable"
    assert "no pinentry" in result.detail


def test_challenge_unavailable_without_display_bus(monkeypatch):
    monkeypatch.setenv("WILLOW_PRESENCE_CHALLENGE", "1")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    with mock.patch(
        "willow_mcp.presence.shutil.which", return_value="/usr/bin/pinentry"
    ):
        result = challenge_presence()
    assert result.status == "unavailable"
    assert "DISPLAY" in result.detail


def test_challenge_ok_on_assuan_success(monkeypatch):
    monkeypatch.setenv("WILLOW_PRESENCE_CHALLENGE", "1")
    monkeypatch.setenv("DISPLAY", ":0")
    stdout = (
        "OK Pleased to meet you\n"
        "OK\n"
        "OK\n"
        "OK\n"
        "D secret-never-logged\n"
        "OK\n"
        "OK closing connection\n"
    )
    completed = mock.Mock(returncode=0, stdout=stdout, stderr="")
    with mock.patch(
        "willow_mcp.presence.shutil.which", return_value="/usr/bin/pinentry-gnome3"
    ), mock.patch("willow_mcp.presence.subprocess.run", return_value=completed) as run:
        result = challenge_presence(description="Attest session abc")
    assert result.ok
    assert "pinentry-gnome3" in result.detail
    script = run.call_args.kwargs["input"]
    assert "SETDESC Attest session abc" in script
    assert "GETPIN" in script
    assert "secret" not in result.detail


def test_challenge_cancelled_on_err(monkeypatch):
    monkeypatch.setenv("WILLOW_PRESENCE_CHALLENGE", "1")
    monkeypatch.setenv("DISPLAY", ":0")
    stdout = "OK Pleased to meet you\nOK\nERR 83886179 canceled\n"
    completed = mock.Mock(returncode=0, stdout=stdout, stderr="")
    with mock.patch(
        "willow_mcp.presence.shutil.which", return_value="/usr/bin/pinentry"
    ), mock.patch("willow_mcp.presence.subprocess.run", return_value=completed):
        result = challenge_presence()
    assert result.status == "cancelled"
    assert "canceled" in result.detail
