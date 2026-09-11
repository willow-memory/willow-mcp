import json
import os

from willow_mcp import seed_loader as sl


def test_seed_corpus_corrections_idempotent(tmp_path, monkeypatch):
    memory = tmp_path / "memory"
    memory.mkdir()
    (memory / "feedback_no_bash.md").write_text(
        "---\ntitle: x\n---\nDo not use Bash for fleet work.\n"
    )
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "claude_memory_dir", lambda: memory)
    first = sl.seed_corpus_corrections()
    second = sl.seed_corpus_corrections()
    assert first == 1
    assert second == 0
    lanes = sl.load_corpus_lanes()
    assert any("Bash" in c for c in lanes["corrections"])


def test_session_start_includes_boot_context(tmp_path, monkeypatch):
    from willow_mcp import session_start_hook as ssh
    from willow_mcp import server

    monkeypatch.setenv("WILLOW_APP_ID", "hanuman")
    monkeypatch.setattr(
        server,
        "session_enter",
        lambda **kwargs: {
            "entry_mode": "human",
            "orientation": {},
        },
    )
    monkeypatch.setattr(sl, "seed_corpus_corrections", lambda: 0)
    out = ssh.handle({"session_id": "s1", "source": "startup"})
    payload = json.loads(out["additional_context"])
    assert "boot_context" in payload
    assert "[CLOCK]" in payload["boot_context"]


# ── trust-root boot fault: fail closed, not mid-task denial ──────────────────
# (hook spec #3, gap 37d44bfa1f4c, reference_unsigned-manifest-blocks-boot)
#
# diagnostic_summary already breaks its verdict on a broken keyring / bad
# manifest / self-writable grant under strict enforcement (this session's
# merge + server._diag_trust_root_boot_problems above it). These tests pin the
# boot bridge: the SAME probes must produce a LOUD, unmissable boot line
# naming the fault and the fix, and must stay silent on a healthy trust root.


def _write_manifest(tmp_path, monkeypatch, app_id="hanuman", permissions=("fleet_read",)):
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path))
    app_dir = tmp_path / app_id
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "manifest.json").write_text(json.dumps({"permissions": list(permissions)}))


def _clear_keyring(monkeypatch):
    from willow_mcp import keyring as _keyring

    monkeypatch.delenv("WILLOW_KEYRING", raising=False)
    monkeypatch.setattr(_keyring, "_injected", None, raising=False)
    monkeypatch.setattr(_keyring, "_from_env", None, raising=False)
    monkeypatch.setattr(_keyring, "_loaded_from", None, raising=False)


def test_healthy_trust_root_produces_no_boot_fault(tmp_path, monkeypatch):
    from willow_mcp import boot_context as bc

    _write_manifest(tmp_path, monkeypatch)
    _clear_keyring(monkeypatch)
    assert bc._trust_root_fault_lines("hanuman") == []


def test_broken_keyring_blocks_boot_with_fault_and_fix(tmp_path, monkeypatch):
    # A secret-bearing keyring at a group/world-readable mode is exactly the
    # gap-37d44bfa1f4c outage: the loader refuses it, and that must not read
    # as a quiet boot.
    from willow_mcp import boot_context as bc
    from willow_mcp import keyring as _keyring

    _write_manifest(tmp_path, monkeypatch)
    kr = tmp_path / "verifiers.json"
    kr.write_text(json.dumps({"legacy_key": "ab" * 16}))
    os.chmod(kr, 0o644)
    monkeypatch.setenv("WILLOW_KEYRING", str(kr))
    monkeypatch.setattr(_keyring, "_injected", None, raising=False)
    monkeypatch.setattr(_keyring, "_from_env", None, raising=False)
    monkeypatch.setattr(_keyring, "_loaded_from", None, raising=False)

    lines = bc._trust_root_fault_lines("hanuman")
    joined = "\n".join(lines)
    assert "[BOOT FAULT]" in joined
    assert "keyring" in joined
    assert "chmod 600" in joined  # the fix, named


def test_unsigned_or_invalid_manifest_blocks_boot(tmp_path, monkeypatch):
    from willow_mcp import boot_context as bc

    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path))
    app_dir = tmp_path / "hanuman"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "manifest.json").write_text("{ not valid json at all")
    _clear_keyring(monkeypatch)

    lines = bc._trust_root_fault_lines("hanuman")
    joined = "\n".join(lines)
    assert "[BOOT FAULT]" in joined
    assert "manifest" in joined


def test_build_boot_lines_carries_trust_root_fault_loudly(tmp_path, monkeypatch):
    # End to end through the real boot bridge: the fault must survive into the
    # actual SessionStart lines, not just the helper.
    from willow_mcp import boot_context as bc

    _write_manifest(tmp_path, monkeypatch)
    kr = tmp_path / "verifiers.json"
    kr.write_text(json.dumps({"legacy_key": "ef" * 16}))
    os.chmod(kr, 0o644)
    monkeypatch.setenv("WILLOW_KEYRING", str(kr))
    from willow_mcp import keyring as _keyring
    monkeypatch.setattr(_keyring, "_injected", None, raising=False)
    monkeypatch.setattr(_keyring, "_from_env", None, raising=False)
    monkeypatch.setattr(_keyring, "_loaded_from", None, raising=False)

    lines = bc.build_boot_lines("hanuman", "sess-trust-root-fault", "startup", {"orientation": {}})
    joined = "\n".join(lines)
    assert "[BOOT FAULT]" in joined
    assert "keyring" in joined


def test_build_boot_lines_stays_quiet_on_healthy_trust_root(tmp_path, monkeypatch):
    from willow_mcp import boot_context as bc

    _write_manifest(tmp_path, monkeypatch)
    _clear_keyring(monkeypatch)

    lines = bc.build_boot_lines("hanuman", "sess-trust-root-healthy", "startup", {"orientation": {}})
    joined = "\n".join(lines)
    assert "[BOOT FAULT]" not in joined
