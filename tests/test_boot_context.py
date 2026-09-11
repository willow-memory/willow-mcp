import json

from willow_mcp import boot_context as bc
from willow_mcp import gaps as gaps_mod
from willow_mcp import seed_loader as sl


def _quiet_boot(monkeypatch):
    """Strip every other boot section so tests assert on blockers/gaps alone."""
    monkeypatch.setattr(bc, "load_corpus_lanes", lambda: {})
    monkeypatch.setattr(bc, "read_stack_snapshot", lambda app_id: None)
    monkeypatch.setattr(bc, "degraded_boot_line", lambda app_id: None)


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


def test_boot_lines_include_blockers_section_when_present(monkeypatch):
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "_gap_lines", lambda *a, **k: [])
    enter_result = {
        "orientation": {
            "blockers": {
                "count": 1,
                "items": [
                    {
                        "id": "no_egress_lease",
                        "summary": "no active egress lease for 'hanuman' — no lease on disk",
                        "fix": "willow-mcp grant-net hanuman --ttl 30m",
                    }
                ],
            }
        }
    }
    lines = bc.build_boot_lines("hanuman", "sess-blockers-present", "startup", enter_result)
    joined = "\n".join(lines)
    assert "[BLOCKERS]" in joined
    assert "no active egress lease" in joined
    assert "grant-net" in joined


def test_boot_lines_omit_blockers_section_when_absent(monkeypatch):
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "_gap_lines", lambda *a, **k: [])
    for orientation in ({"blockers": {"count": 0, "items": []}}, {}):
        lines = bc.build_boot_lines(
            "hanuman", "sess-blockers-absent", "startup", {"orientation": orientation}
        )
        assert "[BLOCKERS]" not in "\n".join(lines)


def test_boot_lines_surface_collection_denied_as_blocker(monkeypatch):
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "_gap_lines", lambda *a, **k: [])
    enter_result = {
        "orientation": {
            "blockers": {"count": 0, "items": []},
            "records": {
                "stack": {
                    "error": "collection_denied: 'projects_willow_stack' is outside "
                    "this app's store_scope"
                }
            },
        }
    }
    lines = bc.build_boot_lines("hanuman", "sess-blockers-denied", "startup", enter_result)
    joined = "\n".join(lines)
    assert "[BLOCKERS]" in joined
    assert "collection_denied" in joined


def test_boot_lines_include_top_gaps_by_asked_count(monkeypatch):
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "_blocker_lines", lambda *a, **k: [])

    def fake_list_gaps(status=None, limit=50):
        assert status == "open"
        return {
            "items": [
                {"topic": "hanuman", "question": "what color is the accent?", "asked_count": 5},
                {"topic": "hanuman", "question": "what is the border radius?", "asked_count": 2},
            ]
        }

    monkeypatch.setattr(gaps_mod, "list_gaps", fake_list_gaps)
    lines = bc.build_boot_lines("hanuman", "sess-gaps-present", "startup", {"orientation": {}})
    joined = "\n".join(lines)
    assert "[GAPS]" in joined
    assert "accent" in joined
    assert "asked 5" in joined


def test_boot_lines_gaps_degrade_cleanly_when_backlog_empty(monkeypatch):
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "_blocker_lines", lambda *a, **k: [])
    monkeypatch.setattr(gaps_mod, "list_gaps", lambda status=None, limit=50: {"items": []})
    lines = bc.build_boot_lines("hanuman", "sess-gaps-empty", "startup", {"orientation": {}})
    assert "[GAPS]" not in "\n".join(lines)


def test_boot_lines_gaps_degrade_cleanly_when_backlog_denied(monkeypatch):
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "_blocker_lines", lambda *a, **k: [])

    def raises(status=None, limit=50):
        raise RuntimeError("gap_read denied")

    monkeypatch.setattr(gaps_mod, "list_gaps", raises)
    lines = bc.build_boot_lines("hanuman", "sess-gaps-denied", "startup", {"orientation": {}})
    assert "[GAPS]" not in "\n".join(lines)


def test_boot_lines_gaps_degrade_cleanly_on_malformed_row(monkeypatch):
    """Regression for audit AC5F367C MEDIUM: a malformed gap row (None
    instead of a dict) must degrade to no gap section, never raise past
    _gap_lines/build_boot_lines."""
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "_blocker_lines", lambda *a, **k: [])
    monkeypatch.setattr(gaps_mod, "list_gaps", lambda status=None, limit=50: {"items": [None]})
    lines = bc.build_boot_lines("hanuman", "sess-gaps-malformed", "startup", {"orientation": {}})
    assert "[GAPS]" not in "\n".join(lines)


def test_boot_lines_blockers_degrade_cleanly_on_non_dict_records(monkeypatch):
    """Regression for audit AC5F367C LOW: orientation["records"] being a
    truthy non-dict (e.g. a string) must degrade _blocker_lines cleanly
    rather than raising on .items()."""
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(bc, "_gap_lines", lambda *a, **k: [])
    enter_result = {
        "orientation": {
            "blockers": {"count": 0, "items": []},
            "records": "not-a-dict",
        }
    }
    lines = bc.build_boot_lines("hanuman", "sess-blockers-bad-records", "startup", enter_result)
    assert "[BLOCKERS]" not in "\n".join(lines)


def test_session_start_handle_survives_boot_context_fault(monkeypatch):
    """Belt-and-suspenders regression: a fault anywhere in build_boot_lines
    must degrade the boot_context section, not blow up handle() and get
    caught by main()'s top-level except (which would falsely report
    "session_enter FAILED" even though session_enter succeeded)."""
    from willow_mcp import session_start_hook as ssh
    from willow_mcp import server

    monkeypatch.setenv("WILLOW_APP_ID", "hanuman")
    monkeypatch.setattr(
        server,
        "session_enter",
        lambda **kwargs: {"entry_mode": "human", "orientation": {}},
    )
    monkeypatch.setattr(sl, "seed_corpus_corrections", lambda: 0)

    def boom(*a, **k):
        raise AttributeError("simulated boot_context fault")

    monkeypatch.setattr(ssh, "build_boot_lines", boom)
    out = ssh.handle({"session_id": "s1", "source": "startup"})
    payload = json.loads(out["additional_context"])
    assert "boot_context" in payload
    assert "degraded" in payload["boot_context"]


def test_boot_lines_healthy_seat_no_false_alarms(monkeypatch):
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(gaps_mod, "list_gaps", lambda status=None, limit=50: {"items": []})
    enter_result = {"orientation": {"blockers": {"count": 0, "items": []}, "records": {}}}
    lines = bc.build_boot_lines("hanuman", "sess-healthy", "startup", enter_result)
    joined = "\n".join(lines)
    assert "[BLOCKERS]" not in joined
    assert "[GAPS]" not in joined
    assert "BOOT DEGRADED" not in joined
