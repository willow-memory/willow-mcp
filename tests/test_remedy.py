"""A remedy is a command, and a command that does not run is not a remedy.

The bug these cover cost three attempts at the start of one session: every
attestation error named `willow-mcp sign-session ...` with no environment, and
`WILLOW_HOME` / `WILLOW_KEYRING` live only in the `env` block of the stdio child
in `.mcp.json`. The operator's shell has neither, so the printed line failed —
and failed by reporting a *different* missing thing than the real one.
"""
from __future__ import annotations

import pytest

from willow_mcp import remedy


@pytest.fixture
def box(tmp_path, monkeypatch):
    home = tmp_path / "operator-box"
    home.mkdir()
    monkeypatch.setenv("WILLOW_HOME", str(home))
    monkeypatch.setenv("WILLOW_KEYRING", str(home / "config" / "verifiers.json"))
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    return home


def test_sign_session_carries_both_vars(box):
    line = remedy.sign_session("session_abc")
    assert line.startswith(f"WILLOW_HOME={box} ")
    assert f"WILLOW_KEYRING={box / 'config' / 'verifiers.json'}" in line
    assert "willow-mcp sign-session session_abc --verifier NAME" in line


def test_a_verifier_with_a_space_is_quoted(box):
    """`willow-mcp keys add sean campbell` is two argparse arguments. The box
    this runs on has a verifier named with a space in the other keyring, so
    this is the live case, not a hypothetical."""
    line = remedy.sign_session("session_abc", "sean campbell")
    assert "--verifier 'sean campbell'" in line

    add = remedy.keys_add("sean campbell")
    assert add.endswith("willow-mcp keys add 'sean campbell'")


def test_the_placeholder_stays_bare(box):
    """NAME is a placeholder and must still read as one."""
    assert remedy.sign_session("s").endswith("--verifier NAME")


def test_an_unset_var_is_omitted_not_emptied(box, monkeypatch):
    """Printing `WILLOW_KEYRING=` would be a new lie in place of the old one."""
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    line = remedy.sign_session("s")
    assert "WILLOW_KEYRING" not in line
    assert f"WILLOW_HOME={box}" in line


def test_attest_session_carries_the_pgp_var_not_the_keyring(box, monkeypatch):
    monkeypatch.setenv("WILLOW_PGP_FINGERPRINT", "DEADBEEF")
    line = remedy.attest_session("session_abc")
    assert "WILLOW_PGP_FINGERPRINT=DEADBEEF" in line
    assert "WILLOW_KEYRING" not in line
    assert "willow-mcp attest-session session_abc" in line


def test_attestation_command_picks_the_configured_path(box):
    assert "sign-session" in remedy.attestation_command("s", keyring_on=True)
    assert "attest-session" in remedy.attestation_command("s", keyring_on=False)


def test_keyring_on_survives_a_configured_but_missing_keyring(box):
    """`keyring.enabled()` raises KeyringError when WILLOW_KEYRING names a file
    that is not there — the exact Kart condition, where the var crosses the
    sandbox boundary and the file does not (gap 4e1825878677). A reporter must
    get an answer, and the answer is "yes, this box is on the keyring path and
    its keyring is broken" — not "fall back to PGP"."""
    from willow_mcp import keyring as keyring_mod

    with pytest.raises(keyring_mod.KeyringError):
        keyring_mod.enabled()
    assert remedy.keyring_on() is True
    assert "sign-session" in remedy.attestation_command(
        "s", keyring_on=remedy.keyring_on())


def test_keyring_on_is_false_with_no_var(box, monkeypatch):
    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    from willow_mcp import keyring as keyring_mod

    keyring_mod.set_keyring(None)
    assert remedy.keyring_on() is False


def test_it_never_raises_when_home_cannot_resolve(monkeypatch):
    """Every caller is already inside an error path. A second exception there
    replaces a wrong answer with no answer."""
    def boom():
        raise RuntimeError("retired home")

    monkeypatch.setattr("willow_mcp.paths.willow_home", boom)
    line = remedy.sign_session("s")
    assert "willow-mcp sign-session s" in line
    assert "WILLOW_HOME" not in line
