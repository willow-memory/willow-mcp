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
    out = server._diag_net_lease("")
    assert "credential_prefixes_populated" in out
    assert isinstance(out["credential_prefixes_populated"], dict)
