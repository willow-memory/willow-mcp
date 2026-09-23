"""server._boot_manifest_verify_sweep_or_exit — Loki audit A38D41C2, F2.

Before this fix, a conflicting or unreadable trust-config file raised out
of the boot-time manifest verify sweep as an uncaught exception: the whole
process (serve broker, or a stdio-attached desk seat) died with a raw
Python traceback nobody at a desk can read. Refusing to start at boot is
right; crashing unreadably is not. This targets the extracted function
directly (`_main()` itself is a large CLI dispatcher, not something a
unit test should have to drive end-to-end for a 6-line behavior)."""
from __future__ import annotations

import pytest

from willow_mcp import pgp, server


def test_returns_problems_on_the_happy_path(monkeypatch):
    monkeypatch.setattr(server, "log_manifest_verify_sweep", lambda: [])
    assert server._boot_manifest_verify_sweep_or_exit() == []


def test_returns_the_sweeps_own_problem_list_unchanged(monkeypatch):
    problems = [{"app_id": "x", "reason": "MANIFEST_UNSIGNED", "detail": "d"}]
    monkeypatch.setattr(server, "log_manifest_verify_sweep", lambda: problems)
    assert server._boot_manifest_verify_sweep_or_exit() is problems


def test_pgp_fingerprint_conflict_becomes_a_clean_system_exit_not_a_crash(monkeypatch, capsys):
    def _raise():
        raise pgp.PgpFingerprintConflict("process env says AAAA but trust.env says BBBB")

    monkeypatch.setattr(server, "log_manifest_verify_sweep", _raise)
    with pytest.raises(SystemExit) as excinfo:
        server._boot_manifest_verify_sweep_or_exit()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "refusing to start" in err
    assert "AAAA" in err and "BBBB" in err


def test_pgp_source_unreadable_becomes_a_clean_system_exit_not_a_crash(monkeypatch, capsys):
    def _raise():
        raise pgp.PgpSourceUnreadable("trust.env exists but is unreadable")

    monkeypatch.setattr(server, "log_manifest_verify_sweep", _raise)
    with pytest.raises(SystemExit) as excinfo:
        server._boot_manifest_verify_sweep_or_exit()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "refusing to start" in err
    assert "unreadable" in err


def test_an_unrelated_exception_still_propagates_uncaught(monkeypatch):
    """This function narrows its catch to exactly the two pgp exceptions
    that used to crash boot unreadably — it must not become a blanket
    except that hides an unrelated bug behind a misleading "refusing to
    start" message."""
    def _raise():
        raise RuntimeError("something else entirely")

    monkeypatch.setattr(server, "log_manifest_verify_sweep", _raise)
    with pytest.raises(RuntimeError, match="something else entirely"):
        server._boot_manifest_verify_sweep_or_exit()
