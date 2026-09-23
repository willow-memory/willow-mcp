import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kartikeya import TaskRow

from willow_mcp import egress_authorization as auth


@pytest.fixture(autouse=True)
def _outside_kart_for_signing_tests(monkeypatch):
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)


@pytest.fixture
def keys(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "operator-private.pem"
    public_path = tmp_path / "operator-public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def _signed(
    keys,
    *,
    task="curl https://example.com\n# allow_net",
    task_id="NETTASK1",
    agent="kart",
    now=None,
):
    return auth.sign_envelope(
        private_key_path=keys[0],
        submitted_by="caller",
        task_id=task_id,
        agent=agent,
        task=task,
        ttl_seconds=300,
        nonce="abcdefghijklmnopqrstuvwxyz012345",
        now=now,
    )


def test_valid_envelope_binds_submitter_task_scope_expiry_and_nonce(keys):
    task = auth.canonical_network_task("curl https://example.com")
    envelope = _signed(keys, task=task)
    ok, reason, payload = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="caller",
        task_id="NETTASK1",
        agent="kart",
        task=task,
        envelope=envelope,
    )
    assert (ok, reason) == (True, "verified")
    assert payload["submitted_by"] == "caller"
    assert payload["task_id"] == "NETTASK1"
    assert payload["agent"] == "kart"
    assert payload["task_hash"] == auth.normalized_task_hash(task)
    assert payload["scope"] == auth.NETWORK_SCOPE
    assert payload["nonce"] == "abcdefghijklmnopqrstuvwxyz012345"


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (lambda envelope: "{bad json", "malformed envelope"),
        (lambda envelope: envelope[:-4] + "xxxx", "malformed envelope"),
    ],
)
def test_malformed_envelope_denied(keys, mutator, reason):
    envelope = mutator(_signed(keys))
    ok, detail, _ = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="caller",
        task_id="NETTASK1",
        agent="kart",
        task="curl https://example.com\n# allow_net",
        envelope=envelope,
    )
    assert ok is False
    assert detail == reason


def test_task_mutation_and_identity_forgery_are_denied(keys):
    envelope = _signed(keys)
    mutated = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="caller",
        task_id="NETTASK1",
        agent="kart",
        task="curl https://attacker.example\n# allow_net",
        envelope=envelope,
    )
    forged = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="someone-else",
        task_id="NETTASK1",
        agent="kart",
        task="curl https://example.com\n# allow_net",
        envelope=envelope,
    )
    assert mutated[:2] == (False, "task hash mismatch")
    assert forged[:2] == (False, "submitted_by mismatch")


def test_task_id_and_agent_rebinding_are_denied(keys):
    envelope = _signed(keys)
    wrong_task = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="caller",
        task_id="OTHERTSK",
        agent="kart",
        task="curl https://example.com\n# allow_net",
        envelope=envelope,
    )
    wrong_agent = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="caller",
        task_id="NETTASK1",
        agent="other",
        task="curl https://example.com\n# allow_net",
        envelope=envelope,
    )
    assert wrong_task[:2] == (False, "task_id mismatch")
    assert wrong_agent[:2] == (False, "agent mismatch")


def test_malformed_base64_signature_denied_without_raising(keys):
    envelope = json.loads(_signed(keys))
    envelope["signature"] = "not-base64!"
    ok, reason, _ = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="caller",
        task_id="NETTASK1",
        agent="kart",
        task="curl https://example.com\n# allow_net",
        envelope=json.dumps(envelope),
    )
    assert (ok, reason) == (False, "invalid signature")


def test_expired_envelope_denied(keys):
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    envelope = _signed(keys, now=old)
    ok, reason, _ = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="caller",
        task_id="NETTASK1",
        agent="kart",
        task="curl https://example.com\n# allow_net",
        envelope=envelope,
    )
    assert (ok, reason) == (False, "authorization expired")


def _permit_execution_policy(monkeypatch, keys, tmp_path):
    monkeypatch.setattr(auth.gate, "permitted", lambda *_: True)
    monkeypatch.setattr(auth.consent, "internet_permitted", lambda: True)
    monkeypatch.setattr(auth.lease, "active", lambda *_: True)
    monkeypatch.setattr(auth.lease, "strict_trust_root", lambda: True)
    monkeypatch.setattr(auth.lease, "self_writable_trust_paths", lambda *_: [])
    monkeypatch.setattr(
        auth.lease, "path_is_self_writable_or_replaceable", lambda *_: False
    )
    monkeypatch.setenv("WILLOW_MCP_EGRESS_PUBLIC_KEY", str(keys[1]))
    monkeypatch.setattr(auth, "_row_blocks_net_authorization", lambda *_: None)
    monkeypatch.setattr(auth, "_consume_row_net_authorization", lambda *_: True)
    real_access = os.access
    monkeypatch.setattr(
        auth.os,
        "access",
        lambda path, mode: False if str(path) == str(keys[1]) else real_access(path, mode),
    )


def test_execution_authorizer_allows_envelope_for_its_bound_row(
    keys, tmp_path, monkeypatch
):
    _permit_execution_policy(monkeypatch, keys, tmp_path)
    row = TaskRow(
        task_id="NETTASK1",
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys),
    )
    authorizer = auth.ExecutorNetworkAuthorizer()
    assert authorizer(row, row.network_authorization) is True


@pytest.mark.parametrize(
    ("gate_name", "expected"),
    [
        ("capability", "task_net capability denied"),
        ("consent", "internet consent denied"),
        ("lease", "egress lease denied"),
        ("strict", "strict trust root is required"),
        ("writable", "authorization trust root is self-writable"),
    ],
)
def test_execution_rechecks_every_host_gate(
    keys, tmp_path, monkeypatch, gate_name, expected
):
    _permit_execution_policy(monkeypatch, keys, tmp_path)
    if gate_name == "capability":
        monkeypatch.setattr(auth.gate, "permitted", lambda *_: False)
    elif gate_name == "consent":
        monkeypatch.setattr(auth.consent, "internet_permitted", lambda: False)
    elif gate_name == "lease":
        monkeypatch.setattr(auth.lease, "active", lambda *_: False)
    elif gate_name == "strict":
        monkeypatch.setattr(auth.lease, "strict_trust_root", lambda: False)
    else:
        monkeypatch.setattr(
            auth.lease, "self_writable_trust_paths", lambda *_: [{"key": "manifest"}]
        )
    row = TaskRow(
        task_id="NETTASK1",
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys),
    )
    authorizer = auth.ExecutorNetworkAuthorizer()
    assert authorizer(row, row.network_authorization) is False
    assert authorizer.last_error == expected


@pytest.mark.parametrize(
    ("replaceable_name", "expected"),
    [
        ("operator-public.pem", "verification key is absent, self-writable, or replaceable"),
    ],
)
def test_execution_denies_replaceable_authorization_roots(
    keys, tmp_path, monkeypatch, replaceable_name, expected
):
    _permit_execution_policy(monkeypatch, keys, tmp_path)
    monkeypatch.setattr(
        auth.lease,
        "path_is_self_writable_or_replaceable",
        lambda path: replaceable_name in str(path),
    )
    row = TaskRow(
        task_id="NETTASK1",
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys),
    )
    authorizer = auth.ExecutorNetworkAuthorizer()
    assert authorizer(row, row.network_authorization) is False
    assert authorizer.last_error == expected


def test_signing_is_blocked_inside_kart(keys, monkeypatch):
    monkeypatch.setenv("WILLOW_IN_KART", "1")
    with pytest.raises(PermissionError, match="cannot be signed inside Kart"):
        _signed(keys)


def test_sign_net_cli_requires_interactive_operator_terminal(
    keys, monkeypatch, capsys
):
    from willow_mcp import server

    monkeypatch.setattr(
        server.sys, "stdin", SimpleNamespace(isatty=lambda: False)
    )
    args = SimpleNamespace(
        key=str(keys[0]),
        task="echo hi",
        task_file="",
        app_id="caller",
        agent="kart",
        localhost=False,
        ttl="5m",
    )
    with pytest.raises(SystemExit):
        server._cmd_sign_net_task(args)
    assert "interactive operator terminal" in capsys.readouterr().err


def test_sign_net_cli_emits_verifiable_envelope(
    keys, tmp_path, monkeypatch, capsys
):
    from willow_mcp import server

    monkeypatch.setattr(
        server.sys, "stdin", SimpleNamespace(isatty=lambda: True)
    )
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / "worker-home"))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "worker-store"))
    args = SimpleNamespace(
        key=str(keys[0]),
        task="curl https://example.com",
        task_file="",
        app_id="caller",
        agent="kart",
        localhost=False,
        ttl="5m",
    )
    server._cmd_sign_net_task(args)
    envelope = capsys.readouterr().out.strip()
    ok, reason, _ = auth.verify_envelope(
        public_key_path=keys[1],
        submitted_by="caller",
        task_id=auth.claimed_task_id(envelope),
        agent="kart",
        task=auth.canonical_network_task(args.task),
        envelope=envelope,
    )
    assert (ok, reason) == (True, "verified")


def test_forged_direct_row_is_denied_before_shell_launch(monkeypatch):
    from kartikeya import execute as kexec

    launched = []
    monkeypatch.setattr(auth.gate, "permitted", lambda *_: False)
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: launched.append(True) or ("completed", {}),
    )
    row = TaskRow(
        task_id="FORGED",
        task="curl https://example.com\n# allow_net",
        submitted_by="forged-app",
        network_authorization='{"forged":true}',
    )
    status, result = kexec.execute_task_row(
        row, network_authorizer=auth.ExecutorNetworkAuthorizer()
    )
    assert status == "failed"
    assert "verifier refused" in result["error"]
    assert launched == []


def test_reclaimed_terminal_row_is_denied_before_shell_launch(
    keys, tmp_path, monkeypatch
):
    from kartikeya import execute as kexec

    _permit_execution_policy(monkeypatch, keys, tmp_path)
    monkeypatch.setattr(
        auth,
        "_row_blocks_net_authorization",
        lambda _task_id: "task row is terminal",
    )
    launched = []
    monkeypatch.setattr(
        kexec,
        "run_shell_task",
        lambda *_a, **_k: launched.append(True) or ("completed", {}),
    )
    row = TaskRow(
        task_id="RECLAIM1",
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys, task_id="RECLAIM1"),
    )
    status, result = kexec.execute_task_row(
        row, network_authorizer=auth.ExecutorNetworkAuthorizer()
    )
    assert status == "failed"
    assert "verifier refused" in result["error"]
    assert launched == []


def test_reclaimed_terminal_row_authorizer_sets_last_error(keys, tmp_path, monkeypatch):
    _permit_execution_policy(monkeypatch, keys, tmp_path)
    monkeypatch.setattr(
        auth,
        "_row_blocks_net_authorization",
        lambda _task_id: "task row is terminal",
    )
    row = TaskRow(
        task_id="RECLAIM1",
        task="curl https://example.com\n# allow_net",
        submitted_by="caller",
        network_authorization=_signed(keys, task_id="RECLAIM1"),
    )
    authorizer = auth.ExecutorNetworkAuthorizer()
    assert authorizer(row, row.network_authorization) is False
    assert authorizer.last_error == "task row is terminal"


def test_no_mcp_tool_exports_signing_authority():
    from willow_mcp import server

    names = {tool.name for tool in server.mcp._tool_manager.list_tools()}
    assert "sign_net_task" not in names
    assert "sign-net-task" not in names
