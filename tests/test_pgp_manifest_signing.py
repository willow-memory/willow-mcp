"""#183 — PGP-enforced manifest signatures: a real end-to-end round trip.

pgp.py's gpg-subprocess calls have never been proven correct against a real
signature anywhere in this suite before this file — every existing caller
(seed_sign, seed_loader, seed_mirror) mocks sign_detached/verify_detached at
the call site. This generates a real, disposable Ed25519 GPG key, signs a
real manifest with it, and proves gate.py denies exactly the cases #183's
own repro names: unsigned, tampered, forged identity, signature reused
against a different manifest, and a valid signature from the wrong key.
"""
import json
import os
import subprocess

import pytest

from willow_mcp import gate, pgp


def _gen_key(gnupghome, name, email):
    batch = gnupghome / f"{name}.batch"
    batch.write_text(
        "%no-protection\n"
        "Key-Type: EDDSA\n"
        "Key-Curve: ed25519\n"
        f"Name-Real: {name}\n"
        f"Name-Email: {email}\n"
        "Expire-Date: 0\n"
        "%commit\n"
    )
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    subprocess.run(
        ["gpg", "--batch", "--gen-key", str(batch)],
        env=env, check=True, capture_output=True, timeout=30,
    )


@pytest.fixture(scope="module")
def gpg_keypair(tmp_path_factory):
    """A real, disposable Ed25519 GPG key — generated once per module. Key
    generation is the slow part; signing/verifying against it is fast."""
    gnupghome = tmp_path_factory.mktemp("gnupghome")
    _gen_key(gnupghome, "Willow Test Operator", "test@willow.invalid")
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    out = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        env=env, check=True, capture_output=True, text=True, timeout=10,
    )
    fpr = next(line.split(":")[9] for line in out.stdout.splitlines() if line.startswith("fpr"))
    return {"gnupghome": str(gnupghome), "fingerprint": fpr}


@pytest.fixture
def pgp_env(gpg_keypair, monkeypatch):
    monkeypatch.setenv("GNUPGHOME", gpg_keypair["gnupghome"])
    monkeypatch.setenv("WILLOW_PGP_FINGERPRINT", gpg_keypair["fingerprint"])


def _write_manifest(home, app_id, **overrides):
    d = home / "mcp_apps" / app_id
    d.mkdir(parents=True, exist_ok=True)
    data = {"app_id": app_id, "permissions": ["store_read"]}
    data.update(overrides)
    path = d / "manifest.json"
    path.write_text(json.dumps(data))
    return path


def test_signed_manifest_verifies_and_is_trusted(home, pgp_env):
    path = _write_manifest(home, "kart")
    ok, detail = pgp.sign_detached(path)
    assert ok, detail
    assert gate.authorized("kart") is True
    assert gate.permitted("kart", "store_get") is True


def test_exported_public_key_verifies_without_signers_gpg_home(
    home, pgp_env, gpg_keypair, monkeypatch
):
    """The trust-owner sudo process has a different HOME/keyring.  A staged
    public key is sufficient for isolated verification and carries no signing
    authority."""
    path = _write_manifest(home, "kart")
    ok, detail = pgp.sign_detached(path)
    assert ok, detail
    public_key, detail = pgp.export_public_key(gpg_keypair["fingerprint"])
    assert public_key, detail

    monkeypatch.delenv("GNUPGHOME", raising=False)
    ok, detail = pgp.verify_detached(
        path,
        fingerprint=gpg_keypair["fingerprint"],
        public_key=public_key,
    )
    assert ok, detail


def test_unsigned_manifest_is_denied_once_pgp_enabled(home, pgp_env):
    _write_manifest(home, "kart")
    assert gate.authorized("kart") is False
    assert gate.permitted("kart", "store_get") is False


def test_tampered_manifest_after_signing_is_denied(home, pgp_env):
    """The self-grant leg of #183/#181: sign, then widen permissions in place."""
    path = _write_manifest(home, "kart")
    ok, _ = pgp.sign_detached(path)
    assert ok
    path.write_text(json.dumps({"app_id": "kart", "permissions": ["full_access"]}))
    assert gate.authorized("kart") is False
    assert gate.permitted("kart", "store_get") is False


def test_forged_identity_manifest_is_denied(home, pgp_env):
    """The #183 repro verbatim: write mcp_apps/steve/manifest.json and try to
    become steve. Unsigned has no standing, same as any other unsigned file."""
    _write_manifest(home, "steve", permissions=["full_access"], store_scope=["*"])
    assert gate.authorized("steve") is False


def test_manifest_signature_reused_against_a_different_manifest_is_denied(home, pgp_env):
    """A signature is bound to file bytes, not a filename — copying a validly
    signed manifest's .sig next to a DIFFERENT manifest.json must not verify,
    because the bytes it was computed over changed."""
    path_a = _write_manifest(home, "alice")
    ok, _ = pgp.sign_detached(path_a)
    assert ok
    sig_bytes = (path_a.parent / "manifest.json.sig").read_bytes()
    path_b = _write_manifest(home, "bob", permissions=["full_access"])
    (path_b.parent / "manifest.json.sig").write_bytes(sig_bytes)
    assert gate.authorized("bob") is False


def test_valid_signature_from_the_wrong_key_is_denied(home, gpg_keypair, monkeypatch):
    """A real, valid signature — just not from the pinned fingerprint. The
    pin is the whole point: without it, any key an agent can generate itself
    would satisfy 'signed'."""
    monkeypatch.setenv("GNUPGHOME", gpg_keypair["gnupghome"])
    monkeypatch.setenv("WILLOW_PGP_FINGERPRINT", "F" * 40)  # syntactically valid, not this key
    path = _write_manifest(home, "kart")
    ok, _ = pgp.sign_detached(path)  # signs with the only real key in this keyring
    assert ok
    assert gate.authorized("kart") is False


def test_sign_manifest_cli_requires_operator_terminal(home, pgp_env, monkeypatch):
    from willow_mcp import server

    class _Args:
        app_id = "kart"

    _write_manifest(home, "kart")
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit):
        server._cmd_sign_manifest(_Args())


def test_sign_manifest_cli_signs_and_gate_then_trusts_it(home, pgp_env, monkeypatch):
    from willow_mcp import server

    class _Args:
        app_id = "kart"

    _write_manifest(home, "kart")
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    server._cmd_sign_manifest(_Args())
    assert gate.authorized("kart") is True


def test_compile_manifests_signs_with_a_real_key_and_gate_trusts_it(home, pgp_env):
    """The #312 repro end to end, against a real GPG signature: compile a
    manifest under enforcement and the gate must trust the result exactly as
    it trusts a manually `sign-manifest`-ed one."""
    from willow_mcp import registry as reg

    registry_doc = {
        "format": reg.REGISTRY_FORMAT,
        "specialists": [{"agent_id": "kart", "role": "x", "permissions": ["store_read"]}],
    }
    result = reg.compile_manifests(registry_doc)
    assert result["signed"] == ["mcp_apps/kart/manifest.json"]
    assert gate.authorized("kart") is True
    assert gate.permitted("kart", "store_get") is True


def test_compile_manifests_recompile_keeps_the_manifest_signed(home, pgp_env):
    """This IS issue #312: a second compile pass over an already-signed
    manifest (`--force` / a registry edit) must re-sign the rewritten bytes,
    not leave the stale `.sig` from the first pass sitting next to new
    content it no longer matches — which used to deny every gated call for
    this app_id with nothing in the output saying why."""
    from willow_mcp import registry as reg

    registry_doc = {
        "format": reg.REGISTRY_FORMAT,
        "specialists": [{"agent_id": "kart", "role": "x", "permissions": ["store_read"]}],
    }
    reg.compile_manifests(registry_doc)
    assert gate.authorized("kart") is True

    registry_doc["specialists"][0]["permissions"] = ["store_read", "knowledge_read"]
    reg.compile_manifests(registry_doc, only_missing=False)

    assert gate.authorized("kart") is True
    assert gate.permitted("kart", "knowledge_search") is True  # granted via the knowledge_read group


def test_sign_manifest_cli_refuses_when_pgp_not_enabled(home, monkeypatch):
    from willow_mcp import server

    class _Args:
        app_id = "kart"

    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    _write_manifest(home, "kart")
    with pytest.raises(SystemExit):
        server._cmd_sign_manifest(_Args())
