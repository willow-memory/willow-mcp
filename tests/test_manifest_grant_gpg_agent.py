"""The manifest-grant apply unit finds, or starts, the gpg-agent it signs with.

A ``--user`` oneshot unit has no login session, so the agent socket gpgconf
names does not exist until something launches the agent. These tests drive
``_ensure_gpg_agent`` with a scripted ``gpgconf`` and a real unix socket.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

import pytest

from willow_mcp import manifest_grant_executor as mge


@pytest.fixture
def sockdir():
    d = Path(tempfile.mkdtemp(prefix="wga-"))  # short: AF_UNIX path limit
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _fake_gpgconf(monkeypatch, sock: Path, *, launch_creates: bool, launch_rc: int = 0,
                  launch_stderr: str = ""):
    calls: list[list[str]] = []
    holder: list[socket.socket] = []

    def run(cmd, **kw):
        calls.append(list(cmd))
        if cmd[:2] == ["gpgconf", "--list-dirs"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{sock}\n", stderr="")
        if cmd[:2] == ["gpgconf", "--launch"]:
            if launch_creates:
                s = socket.socket(socket.AF_UNIX)
                s.bind(str(sock))
                holder.append(s)
            return subprocess.CompletedProcess(cmd, launch_rc, stdout="", stderr=launch_stderr)
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(mge.subprocess, "run", run)
    return calls, holder


def test_running_agent_socket_is_found_without_launching(monkeypatch, sockdir):
    sock = sockdir / "S.gpg-agent"
    live = socket.socket(socket.AF_UNIX)
    live.bind(str(sock))
    try:
        calls, _ = _fake_gpgconf(monkeypatch, sock, launch_creates=False)
        assert mge._ensure_gpg_agent() == (True, "")
        assert not any(c[:2] == ["gpgconf", "--launch"] for c in calls)
    finally:
        live.close()


def test_absent_agent_is_started_then_found(monkeypatch, sockdir):
    sock = sockdir / "S.gpg-agent"
    calls, holder = _fake_gpgconf(monkeypatch, sock, launch_creates=True)
    try:
        assert mge._ensure_gpg_agent() == (True, "")
        assert ["gpgconf", "--launch", "gpg-agent"] in calls
    finally:
        for s in holder:
            s.close()


def test_agent_that_cannot_start_is_eunreach_with_a_clear_reason(monkeypatch, sockdir):
    sock = sockdir / "S.gpg-agent"
    _fake_gpgconf(monkeypatch, sock, launch_creates=False, launch_rc=2,
                  launch_stderr="gpg-agent: no homedir")
    ok, why = mge._ensure_gpg_agent()
    assert ok is False
    assert str(sock) in why
    assert "exited 2" in why and "no homedir" in why
    assert "GNUPGHOME=" in why and "XDG_RUNTIME_DIR=" in why


def test_gpgconf_missing_is_named(monkeypatch):
    def run(cmd, **kw):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(mge.subprocess, "run", run)
    assert mge._ensure_gpg_agent() == (False, "gpgconf not found on PATH")
    assert mge._gpg_agent_reachable() is False
