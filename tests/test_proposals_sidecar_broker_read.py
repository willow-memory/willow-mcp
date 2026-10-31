"""The proposals sidecar is the broker's own file, on a trust-provisioned host too.

Sealed pair 31f5d3af (audit 54E3DFC0) split the envelope registry in two:
the ACTIVE register, a governance input (trust-owner owned and signed on a
provisioned host, Loki D06A0EF3), and the PROPOSALS sidecar, broker-owned
end to end and never signed. ``_load_registry`` read both as governance, so
on a provisioned host the broker was refused its own sidecar and no envelope
could be proposed there:

    untrusted ownership or permissions on source path: .../proposals
    (uid 1000; this host is trust-provisioned, so a governance input must be
    owned by the trust owner (994) or root ...)

The register keeps its governance read. The sidecar is read with
``governance=False``: still refused when symlinked or group/other-writable.
A proposal's content is held by its digest and FRANK's envelope_proposed row
at the ratify click and at apply (tests/test_trust_owner_verbs.py), not by
who owns the sidecar.
"""
from __future__ import annotations

import json
import os

import pytest

from willow_mcp import envelope_authoring as ea
from willow_mcp import envelopes, paths, trust_marker

EUID = os.geteuid()


@pytest.fixture
def provisioned(tmp_path, monkeypatch):
    """A WILLOW_HOME bound by a valid trust-provisioned marker whose trust
    owner is NOT this process: what the operator's box looks like."""
    home = tmp_path / "home"
    home.mkdir()
    os.chmod(home, 0o755)
    etc = tmp_path / "etc" / "willow-mcp"
    etc.mkdir(parents=True)
    os.chmod(etc, 0o755)
    os.chmod(etc.parent, 0o755)
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setattr(trust_marker, "_MARKER_PATH", etc / "trust-provisioned")
    monkeypatch.setattr(trust_marker, "_ROOT_UID", EUID)
    monkeypatch.setattr(trust_marker, "_GOVERNANCE_ROOT_UID", EUID + 9)
    monkeypatch.setattr(paths, "_trust_owner_uid", lambda: EUID + 7)  # someone else
    trust_marker._logged_levers.clear()
    marker = trust_marker.marker_path()
    marker.write_text(f"willow_home={os.path.realpath(home)}\ntrust_owner_uid={EUID + 7}\n")
    os.chmod(marker, 0o644)
    assert trust_marker.active_marker() is not None, "the marker binds this home"
    sidecar_dir = home / "proposals"
    sidecar_dir.mkdir()
    os.chmod(sidecar_dir, 0o700)
    sidecar = sidecar_dir / "proposals.json"
    sidecar.write_text(json.dumps({"proposals": [{"id": "env-x"}], "archived": []}))
    os.chmod(sidecar, 0o600)
    return sidecar


def test_the_brokers_own_sidecar_is_read_on_a_provisioned_host(provisioned):
    assert envelopes._load(provisioned, governance=False)["proposals"] == [{"id": "env-x"}]


def test_read_as_governance_it_is_refused_which_was_the_bug(provisioned):
    with pytest.raises(PermissionError, match="trust-provisioned"):
        envelopes._load(provisioned)


@pytest.mark.parametrize("mode", [0o620, 0o602])
def test_a_group_or_other_writable_sidecar_is_still_refused(provisioned, mode):
    os.chmod(provisioned, mode)
    with pytest.raises(PermissionError):
        envelopes._load(provisioned, governance=False)


def test_a_symlinked_sidecar_is_still_refused(provisioned, tmp_path):
    real = tmp_path / "elsewhere.json"
    real.write_text(provisioned.read_text())
    os.chmod(real, 0o600)
    provisioned.unlink()
    provisioned.symlink_to(real)
    with pytest.raises(PermissionError, match="symlinked"):
        envelopes._load(provisioned, governance=False)


def test_the_register_is_read_as_governance_and_the_sidecar_as_the_brokers(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    (tmp_path / "constitutional").mkdir()
    register = tmp_path / "constitutional" / "pre-approved.json"
    register.write_text(json.dumps({"active": [{"id": "a"}]}))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(register))
    sidecar = ea._proposals_path()
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(json.dumps({"proposals": [{"id": "p"}], "archived": []}))
    seen: list[tuple[str, bool]] = []
    monkeypatch.setattr(envelopes, "trusted_read",
                        lambda path, governance=True: seen.append((path.name, governance)))
    registry = ea._load_registry()
    assert registry["active"] == [{"id": "a"}] and registry["proposals"] == [{"id": "p"}]
    assert seen == [("pre-approved.json", True), ("proposals.json", False)]
