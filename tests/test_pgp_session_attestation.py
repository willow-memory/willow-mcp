"""#186 P2 — orchestrator write gate checks session attestation.

Real end-to-end round trip against a disposable GPG key, same pattern as
test_pgp_manifest_signing.py: attest-session signs a dedicated
`<session>.attest.json` sidecar (paths.session_attestation_path) holding only
the stable {app_id, session_id} identity, and orchestrator_write_denial then
requires that signature to still verify before dispatch_send/verify_handoff/
agent_clear/frank_append/envelope_apply run as app_id=willow.

#313: the sidecar is deliberately NOT the live `sessions/willow-{id}.json`
record dispatch.session_bind rewrites on every state change (session_enter,
dispatch_accept, session_handoff_write, agent_clear, ...) -- signing that
mutable record self-invalidated on the very next ordinary write, including
the closeout write meant to end the session. See
test_attestation_survives_session_bind_state_changes and
test_attestation_survives_session_handoff_write below.
"""
import os
import subprocess

import pytest

from willow_mcp import dispatch as ds
from willow_mcp import handoff as hf
from willow_mcp import human_session as hs
from willow_mcp import paths, pgp


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


def _attest(session_id):
    """Sign the identity sidecar the same way `willow-mcp attest-session` does,
    without going through the CLI's tty/Kart guard (exercised separately)."""
    import json as jsonlib
    from datetime import datetime, timezone

    attest_path = paths.session_attestation_path("willow", session_id)
    attest_path.parent.mkdir(parents=True, exist_ok=True)
    attest_path.write_text(
        jsonlib.dumps(
            {
                "format": "orchestrator_session_attestation_v1",
                "app_id": "willow",
                "session_id": session_id,
                "attested_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2, sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    ok, detail = pgp.sign_detached(attest_path)
    assert ok, detail
    return attest_path


def test_env_only_still_works_when_pgp_disabled(home, monkeypatch):
    """No WILLOW_PGP_FINGERPRINT set → interim env-only behavior, unchanged."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    assert hs.orchestrator_write_denial("willow", "dispatch_send", serve_mode=False) is None


def test_pgp_enabled_denies_without_any_session_id(home, pgp_env, monkeypatch):
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    reason = hs.orchestrator_write_denial("willow", "dispatch_send", serve_mode=False)
    assert reason is not None
    assert "orchestrator_session_attestation_missing" in reason


def test_pgp_enabled_denies_unattested_session(home, pgp_env, monkeypatch):
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    ds.session_enter("willow", "sess-1")  # writes sessions/willow-sess-1.json, unsigned
    reason = hs.orchestrator_write_denial(
        "willow", "dispatch_send", serve_mode=False, session_id="sess-1"
    )
    assert reason is not None
    assert "orchestrator_session_attestation_missing" in reason


def test_pgp_enabled_allows_attested_session(home, pgp_env, monkeypatch):
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    ds.session_enter("willow", "sess-2")
    _attest("sess-2")
    assert hs.orchestrator_write_denial(
        "willow", "dispatch_send", serve_mode=False, session_id="sess-2"
    ) is None


def test_attested_session_denied_when_live_session_file_removed(home, pgp_env, monkeypatch):
    """Sidecar alone is not enough — deleting the live session record must
    disarm orchestrator writes (proof session_enter's binding is still on disk)."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    ds.session_enter("willow", "sess-live")
    _attest("sess-live")
    paths.session_path("willow", "sess-live").unlink()
    reason = hs.orchestrator_write_denial(
        "willow", "dispatch_send", serve_mode=False, session_id="sess-live"
    )
    assert reason is not None
    assert "orchestrator_session_attestation_missing" in reason
    assert "no live session file" in reason


def test_tampered_attestation_sidecar_is_denied(home, pgp_env, monkeypatch):
    """Signature is bound to the sidecar's bytes -- editing the sidecar in place
    (same shape #183's tampered-manifest test used) must invalidate it, and the
    denial reason must say BAD signature, not 'never attested'."""
    import json

    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    ds.session_enter("willow", "sess-3")
    attest_path = _attest("sess-3")
    data = json.loads(attest_path.read_text())
    data["session_id"] = "sess-TAMPERED"
    attest_path.write_text(json.dumps(data))
    reason = hs.orchestrator_write_denial(
        "willow", "dispatch_send", serve_mode=False, session_id="sess-3"
    )
    assert reason is not None
    assert "orchestrator_session_attestation_invalid" in reason
    assert "orchestrator_session_attestation_missing" not in reason


def test_attestation_survives_session_bind_state_changes(home, pgp_env, monkeypatch):
    """#313 core regression: session_bind (via session_enter/dispatch_accept/
    agent_clear/...) rewrites sessions/willow-{id}.json -- including a fresh
    updated_at -- on every ordinary state change. That must no longer touch,
    let alone invalidate, the attestation."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    ds.session_enter("willow", "sess-4")
    _attest("sess-4")
    assert hs.orchestrator_write_denial(
        "willow", "dispatch_send", serve_mode=False, session_id="sess-4"
    ) is None

    # Rewrite the live session record directly, the way session_bind does on
    # every state transition (session_enter, dispatch_accept, agent_clear).
    ds.session_bind("willow", "sess-4", "", "idle")
    ds.session_bind("willow", "sess-4", "", "idle")

    assert hs.orchestrator_write_denial(
        "willow", "dispatch_send", serve_mode=False, session_id="sess-4"
    ) is None


def test_attestation_survives_session_handoff_write(home, pgp_env, monkeypatch):
    """#313 confirmed sequence: session_handoff_write is the closeout tool and
    itself calls session_bind at the end (dispatch.py), rewriting the session
    file's updated_at. Under the old design that self-invalidated the very
    attestation the closeout's own frank_append needed. It must not anymore."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    ds.session_enter("willow", "sess-5")
    _attest("sess-5")

    result = ds.session_handoff_write(
        "willow", "sess-5", narrative="closing out", summary="done"
    )
    assert "error" not in result

    reason = hs.orchestrator_write_denial(
        "willow", "frank_append", serve_mode=False, session_id="sess-5"
    )
    assert reason is None, reason


def test_attestation_survives_handoff_write_v4(home, pgp_env, monkeypatch):
    """#334: confirm the #313 fix also covers the *dispatch* closeout path.

    session_handoff_write (human closeout, tested above) explicitly calls
    session_bind at the end, rewriting sessions/willow-{id}.json. The dispatch
    closeout path (handoff_write_v4) is reached differently: dispatch_accept
    calls session_bind when a packet is accepted (already covered by
    test_attestation_survives_session_bind_state_changes), but
    handoff.handoff_write_v4 itself only writes into the dispatch packet
    (handoff.json/closeout.md/status.json) -- it never touches
    sessions/willow-{id}.json or the attestation sidecar. Either way, the
    attestation must survive a full accept -> closeout round trip on a packet
    addressed to app_id=willow, the same way it survives the human path."""
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    ds.session_enter("willow", "sess-v4")
    _attest("sess-v4")

    sent = ds.dispatch_send("hanuman", "willow", "# do the thing\n")
    assert "error" not in sent
    dispatch_id = sent["dispatch_id"]

    accepted = ds.dispatch_accept(dispatch_id, "willow", "sess-v4")
    assert "error" not in accepted, accepted

    # dispatch_accept's session_bind must not have invalidated the attestation.
    assert hs.orchestrator_write_denial(
        "willow", "frank_append", serve_mode=False, session_id="sess-v4"
    ) is None

    result = hf.handoff_write_v4(
        "willow", dispatch_id, narrative="closing out the dispatch: 1 passed",
        no_findings_reason="test fixture: attestation test",
    )
    assert "error" not in result, result
    assert result["status"] == "complete"

    reason = hs.orchestrator_write_denial(
        "willow", "frank_append", serve_mode=False, session_id="sess-v4"
    )
    assert reason is None, reason


def test_serve_mode_bypasses_attestation_check(home, pgp_env, monkeypatch):
    """Serve mode trusts the confirmed OAuth binding alone -- unchanged by #186."""
    assert hs.orchestrator_write_denial(
        "willow", "dispatch_send", serve_mode=True, session_id=""
    ) is None


def test_specialist_write_never_attestation_gated(home, pgp_env, monkeypatch):
    assert hs.orchestrator_write_denial(
        "hanuman", "dispatch_send", serve_mode=False, session_id=""
    ) is None


# ── attest-session CLI ───────────────────────────────────────────────────────

def test_attest_session_cli_requires_operator_terminal(home, pgp_env, monkeypatch):
    from willow_mcp import server

    class _Args:
        session_id = "sess-cli-1"

    ds.session_enter("willow", "sess-cli-1")
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit):
        server._cmd_attest_session(_Args())


def test_attest_session_cli_refuses_when_pgp_not_enabled(home, monkeypatch):
    from willow_mcp import server

    class _Args:
        session_id = "sess-cli-2"

    monkeypatch.delenv("WILLOW_PGP_FINGERPRINT", raising=False)
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    ds.session_enter("willow", "sess-cli-2")
    with pytest.raises(SystemExit):
        server._cmd_attest_session(_Args())


def test_attest_session_cli_refuses_when_session_never_entered(home, pgp_env, monkeypatch):
    from willow_mcp import server

    class _Args:
        session_id = "sess-never-entered"

    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    with pytest.raises(SystemExit):
        server._cmd_attest_session(_Args())


def test_attest_session_cli_signs_and_gate_then_trusts_it(home, pgp_env, monkeypatch):
    from willow_mcp import server

    class _Args:
        session_id = "sess-cli-3"

    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    ds.session_enter("willow", "sess-cli-3")
    server._cmd_attest_session(_Args())
    assert hs.orchestrator_write_denial(
        "willow", "dispatch_send", serve_mode=False, session_id="sess-cli-3"
    ) is None


def test_attest_session_cli_writes_sidecar_not_live_session_file(home, pgp_env, monkeypatch):
    """#313: the CLI must not sign the live session record in place -- that's
    exactly the file dispatch.session_bind rewrites on every state change."""
    from willow_mcp import server

    class _Args:
        session_id = "sess-cli-4"

    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    ds.session_enter("willow", "sess-cli-4")

    session_file = paths.session_path("willow", "sess-cli-4")
    session_sig = session_file.parent / f"{session_file.name}.sig"
    server._cmd_attest_session(_Args())

    assert not session_sig.exists(), (
        "attest-session must not detach-sign the live session record"
    )
    attest_sidecar = paths.session_attestation_path("willow", "sess-cli-4")
    assert attest_sidecar.is_file()
    assert (attest_sidecar.parent / f"{attest_sidecar.name}.sig").is_file()


def test_attest_session_cli_rolls_back_sidecar_on_sign_failure(home, pgp_env, monkeypatch):
    """A failed re-attest must not leave a fresh unsigned sidecar (or clobber
    a previously good sidecar+sig) on disk."""
    from willow_mcp import server

    class _Args:
        session_id = "sess-cli-rollback"

    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    ds.session_enter("willow", "sess-cli-rollback")
    server._cmd_attest_session(_Args())

    attest_sidecar = paths.session_attestation_path("willow", "sess-cli-rollback")
    attest_sig = attest_sidecar.parent / f"{attest_sidecar.name}.sig"
    before_bytes = attest_sidecar.read_text(encoding="utf-8")
    before_sig = attest_sig.read_bytes()

    monkeypatch.setattr(pgp, "sign_detached", lambda p: (False, "gpg-agent unreachable"))
    with pytest.raises(SystemExit) as excinfo:
        server._cmd_attest_session(_Args())
    assert excinfo.value.code == 1
    assert attest_sidecar.read_text(encoding="utf-8") == before_bytes
    assert attest_sig.read_bytes() == before_sig


def test_attest_session_cli_removes_fresh_sidecar_when_first_sign_fails(
    home, pgp_env, monkeypatch,
):
    from willow_mcp import server

    class _Args:
        session_id = "sess-cli-fresh-fail"

    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    monkeypatch.setattr(server.sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    ds.session_enter("willow", "sess-cli-fresh-fail")
    monkeypatch.setattr(pgp, "sign_detached", lambda p: (False, "gpg not found on PATH"))

    with pytest.raises(SystemExit) as excinfo:
        server._cmd_attest_session(_Args())
    assert excinfo.value.code == 1
    attest_sidecar = paths.session_attestation_path("willow", "sess-cli-fresh-fail")
    assert not attest_sidecar.exists()
    assert not (attest_sidecar.parent / f"{attest_sidecar.name}.sig").exists()


def test_dispatch_closeout_gate_e2e_ordinary_error_not_attestation(home, pgp_env, monkeypatch):
    """#334 end-to-end: through the real guarded MCP tools (not the bare
    dispatch/handoff modules), accept and close out a packet addressed to
    app_id=willow, then confirm the next attestation-gated call fails for its
    own ordinary domain reason (no Postgres configured here) rather than
    orchestrator_session_attestation_missing -- proving handoff_write_v4's
    write did not clobber the attestation the way #313 describes."""
    import json

    from willow_mcp import server

    apps = home / "mcp_apps" / "willow"
    apps.mkdir(parents=True)
    manifest_path = apps / "manifest.json"
    manifest_path.write_text(json.dumps({"permissions": ["orchestrator"]}))
    ok, detail = pgp.sign_detached(manifest_path)
    assert ok, detail

    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    server._set_orchestrator_session("")  # isolate from any earlier test in this process
    server.session_enter("willow", "sess-v4-e2e")
    _attest("sess-v4-e2e")

    sent = ds.dispatch_send("hanuman", "willow", "# do the thing\n")
    assert "error" not in sent
    dispatch_id = sent["dispatch_id"]

    accepted = server.dispatch_accept("willow", dispatch_id, "sess-v4-e2e")
    assert "error" not in accepted, accepted

    closed = server.handoff_write_v4(
        "willow", dispatch_id, narrative="closing out via the guarded tool: 1 passed",
        no_findings_reason="test fixture: attestation e2e test",
    )
    assert "error" not in closed, closed
    assert closed["status"] == "complete"

    # The attestation-gated call after closeout must fail (if at all) for its
    # own domain reason -- here, no Postgres configured in this test env --
    # never orchestrator_session_attestation_missing/_invalid.
    result = server.frank_append("willow", "proj", "note", {"x": 1})
    assert "attestation" not in str(result.get("error", ""))


# ── server._gate threading: session_enter records the current session ───────

def test_gate_reads_back_session_recorded_by_session_enter(home, pgp_env, monkeypatch):
    """End-to-end through the MCP tool wrapper, not the bare dispatch module:
    session_enter(app_id=willow) records session_id in server-process state,
    and _gate reads it back for the next orchestrator-write call in the same
    process -- callers of dispatch_send etc. never pass session_id themselves."""
    import json

    from willow_mcp import server

    apps = home / "mcp_apps" / "willow"
    apps.mkdir(parents=True)
    manifest_path = apps / "manifest.json"
    manifest_path.write_text(json.dumps({"permissions": ["orchestrator"]}))
    ok, detail = pgp.sign_detached(manifest_path)
    assert ok, detail

    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    server._set_orchestrator_session("")  # isolate from any earlier test in this process
    server.session_enter("willow", "sess-gate-1")
    assert server._current_orchestrator_session() == "sess-gate-1"

    _attest("sess-gate-1")

    result = server.dispatch_send("willow", "hanuman", "# do the thing\n")
    assert "error" not in result or "attestation" not in result.get("error", "")
