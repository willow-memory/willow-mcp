"""Two reports that used to assert from the wrong vantage.

Gap 5fd840cb5000: `harden-trust-root --dry-run` inside Kart said forgeable was
the two consent files only — os.access(W_OK) is false on a read-only bind, so
the lease root the host names went missing from the very list meant to fix it.
Gap 8aaf7b59bb13: the diagnostic said nothing about whether the credential
prefixes the sandbox will pass through are populated on this box, so a task
could pay all three egress keys and fail at the API for a key nobody loaded.
"""
from __future__ import annotations

import os

import pytest

from willow_mcp import env_fingerprint
from willow_mcp import home_init as hi
from willow_mcp import server
from willow_mcp import trust_root_setup as trs


def test_audit_inside_kart_marks_writability_unmeasurable(home, monkeypatch):
    hi.ensure_home_layout()
    monkeypatch.setenv("WILLOW_IN_KART", "1")
    audit = trs.audit_trust_root("hanuman")
    assert audit["measured_in_sandbox"] is True
    assert "forgeable" in audit["unmeasurable_in_sandbox"]
    assert "hardened" in audit["unmeasurable_in_sandbox"]
    assert "re-run from the host" in audit["vantage_note"]


def test_audit_on_the_host_measures_and_says_so(home, monkeypatch):
    hi.ensure_home_layout()
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    audit = trs.audit_trust_root("hanuman")
    assert audit["measured_in_sandbox"] is False
    assert audit["unmeasurable_in_sandbox"] == []
    assert audit["vantage_note"] == ""


def test_credential_prefixes_populated_names_prefixes_not_values(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "hf_secret_value_that_must_not_appear")
    for k in [k for k in os.environ if k.startswith("GROQ_")]:
        monkeypatch.delenv(k)
    report = server._credential_prefixes_populated()
    if "_error" in report:  # kartikeya config unreadable here — the degrade is itself the contract
        assert report["_error"].startswith("unreadable")
        return
    assert report.get("HF_") is True
    assert report.get("GROQ_") is False
    assert "hf_secret_value_that_must_not_appear" not in repr(report)


def test_diag_net_lease_carries_the_populated_map(home, monkeypatch):
    hi.ensure_home_layout()
    monkeypatch.setattr(env_fingerprint.subprocess, "run", _no_systemctl)
    out = server._diag_net_lease("")
    assert "credential_prefixes_populated" in out
    assert isinstance(out["credential_prefixes_populated"], dict)
    assert "credential_prefixes_this_process" in out
    assert isinstance(out["credential_prefixes_source"], list)


# ── the vantage is the Kart worker, not this process (2026-09-29) ──────────────
#
# The desk's stdio process inherits the shell that launched the client. That
# shell held only GROQ_, so every session read "only Groq", whatever the
# worker units (which are what a task inherits) actually load.

_PREFIXES = ("GROQ_", "HF_", "GEMINI_", "ANTHROPIC_")


def _no_systemctl(*_a, **_k):
    raise OSError("no systemctl in this test")


class _Proc:
    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout, self.returncode = stdout, returncode


def _runner(by_unit: dict):
    def run(cmd, **_k):
        return _Proc(by_unit.get(cmd[3], ""))
    return run


def _pin_prefixes(monkeypatch):
    sandbox = pytest.importorskip("kartikeya.sandbox")
    monkeypatch.setattr(sandbox, "load_sandbox_config", lambda _p: {"credential_env_prefixes": list(_PREFIXES)})


def _env_file(tmp_path, name: str, lines: list[str]):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_worker_env_decides_populated_not_this_process(tmp_path, monkeypatch):
    _pin_prefixes(monkeypatch)
    for k in [k for k in os.environ if k.startswith(_PREFIXES)]:
        monkeypatch.delenv(k)
    monkeypatch.setenv("GROQ_API_KEY", "gsk_shell_only_value")
    env = _env_file(tmp_path, "env", ["GROQ_API_KEY=gsk_box_value", "HF_API_KEY=hf_box_value_must_not_appear"])
    show = f"EnvironmentFiles={env} (ignore_errors=no)\nEnvironment=\n"
    out = server._diag_credential_prefixes(runner=_runner(dict.fromkeys(env_fingerprint.WORKER_UNITS, show)))
    assert out["credential_prefixes_populated"]["HF_"] is True
    assert out["credential_prefixes_populated"]["GEMINI_"] is False
    assert out["credential_prefixes_this_process"]["HF_"] is False
    assert out["credential_prefixes_this_process"]["GROQ_"] is True
    assert "hf_box_value_must_not_appear" not in repr(out)
    assert "gsk_" not in repr(out)


def test_environment_lines_and_files_are_unioned(tmp_path, monkeypatch):
    _pin_prefixes(monkeypatch)
    env = _env_file(tmp_path, "env", ["GROQ_API_KEY=x"])
    show = f"EnvironmentFiles=-{env} (ignore_errors=yes)\nEnvironment=GEMINI_API_KEY=y WILLOW_HOME=/h\n"
    out = server._diag_credential_prefixes(runner=_runner(dict.fromkeys(env_fingerprint.WORKER_UNITS, show)))
    assert out["credential_prefixes_populated"]["GROQ_"] is True
    assert out["credential_prefixes_populated"]["GEMINI_"] is True


def test_a_prefix_one_lane_lacks_is_not_populated(tmp_path, monkeypatch):
    _pin_prefixes(monkeypatch)
    fast = _env_file(tmp_path, "fast.env", ["GROQ_API_KEY=x", "GEMINI_API_KEY=y"])
    batch = _env_file(tmp_path, "batch.env", ["GROQ_API_KEY=x"])
    fast_unit, batch_unit = env_fingerprint.WORKER_UNITS
    out = server._diag_credential_prefixes(runner=_runner({
        fast_unit: f"EnvironmentFiles={fast} (ignore_errors=no)\n",
        batch_unit: f"EnvironmentFiles={batch} (ignore_errors=no)\n",
    }))
    assert out["credential_prefixes_populated"]["GROQ_"] is True
    assert out["credential_prefixes_populated"]["GEMINI_"] is False


def test_unreadable_worker_env_is_an_error_never_this_process(tmp_path, monkeypatch):
    _pin_prefixes(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "gsk_shell_only_value")
    show = f"EnvironmentFiles={tmp_path / 'missing.env'} (ignore_errors=no)\n"
    out = server._diag_credential_prefixes(runner=_runner(dict.fromkeys(env_fingerprint.WORKER_UNITS, show)))
    assert set(out["credential_prefixes_populated"]) == {"_error"}
    assert all(s["state"] == "unreachable" for s in out["credential_prefixes_source"])


def test_no_systemctl_falls_back_to_box_env_and_says_so(home, monkeypatch):
    hi.ensure_home_layout()
    names = env_fingerprint.env_names_for_unit(env_fingerprint.WORKER_UNITS[0], runner=_no_systemctl)
    assert names["source"] == "fallback"
    assert names["files"] == [str(env_fingerprint.default_env_path())]
