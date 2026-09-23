import json
import os

from willow_mcp import boot_context as bc
from willow_mcp import gaps as gaps_mod
from willow_mcp import seed_loader as sl


def _quiet_boot(monkeypatch):
    """Strip every other boot section so tests assert on blockers/gaps alone."""
    monkeypatch.setattr(bc, "load_corpus_lanes", lambda: {})
    monkeypatch.setattr(bc, "read_stack_snapshot", lambda app_id: None)
    monkeypatch.setattr(bc, "degraded_boot_line", lambda app_id: None)


def _frontmatter(name, mtype, description, *, scope=None, modified="2026-09-01T00:00:00.000Z"):
    scope_line = f"  scope: {scope}\n" if scope else ""
    return (
        "---\n"
        f"name: {name}\n"
        f'description: "{description}"\n'
        "metadata: \n"
        "  node_type: memory\n"
        f"  type: {mtype}\n"
        "  originSessionId: abc\n"
        f"  modified: {modified}\n"
        f"{scope_line}"
        "---\n\n"
        "Body text here.\n"
    )


def test_seed_corpus_corrections_idempotent(tmp_path, monkeypatch):
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    (memory / "feedback_no_bash.md").write_text(
        "---\ntitle: x\n---\nDo not use Bash for fleet work.\n"
    )
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])
    first = sl.seed_corpus_corrections()
    second = sl.seed_corpus_corrections()
    assert first == 1
    assert second == 0
    lanes = sl.load_corpus_lanes(own_project_dir=memory.parent.name)
    assert any("Bash" in c for c in lanes["memory_notes"])


def test_seed_corpus_corrections_type_scoping(tmp_path, monkeypatch):
    """feedback seeds; project/user/reference and MEMORY.md do not (ruling 2)."""
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    (memory / "no-terminal-incantations.md").write_text(
        _frontmatter("no-terminal-incantations", "feedback", "Never hand over a terminal one-liner.")
    )
    (memory / "canonical-verifier-name.md").write_text(
        _frontmatter("canonical-verifier-name", "project", "Verifier name is sean campbell.")
    )
    (memory / "some-user-pref.md").write_text(
        _frontmatter("some-user-pref", "user", "Prefers terse replies.")
    )
    (memory / "some-reference.md").write_text(
        _frontmatter("some-reference", "reference", "Background doc link.")
    )
    (memory / "MEMORY.md").write_text("- index only, never a record\n")
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])

    seeded = sl.seed_corpus_corrections()
    assert seeded == 1  # feedback only

    lanes = sl.load_corpus_lanes(own_project_dir=memory.parent.name)
    joined = " ".join(lanes["memory_notes"])
    assert "terminal one-liner" in joined
    assert "sean campbell" not in joined
    assert "terse replies" not in joined
    assert "Background doc link" not in joined


def test_seed_corpus_corrections_edit_updates_record(tmp_path, monkeypatch):
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    fpath = memory / "canonical-verifier-name.md"
    fpath.write_text(_frontmatter("canonical-verifier-name", "feedback", "Old text."))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])

    sl.seed_corpus_corrections()
    store = sl._corpus_store()
    record_id = f"{memory.parent.name}::canonical-verifier-name"
    first_created = store.get("corpus_corrections", record_id)["_created"]

    fpath.write_text(_frontmatter("canonical-verifier-name", "feedback", "New corrected text."))
    seeded_again = sl.seed_corpus_corrections()
    assert seeded_again == 1

    updated = store.get("corpus_corrections", record_id)
    assert updated["content"] == "New corrected text."
    assert updated["_created"] == first_created  # created_at preserved across an edit


def test_seed_corpus_corrections_delete_retires_then_restore_revives(tmp_path, monkeypatch):
    """F1: retirement is a status flip (never Store.delete), and a file that
    comes back under the same name is visible again — not lost forever."""
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    fpath = memory / "canonical-verifier-name.md"
    fpath.write_text(_frontmatter("canonical-verifier-name", "feedback", "Some text."))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])

    sl.seed_corpus_corrections()
    store = sl._corpus_store()
    record_id = f"{memory.parent.name}::canonical-verifier-name"
    assert store.get("corpus_corrections", record_id)["status"] == "active"

    fpath.unlink()
    sl.seed_corpus_corrections()
    retired = store.get("corpus_corrections", record_id)
    # Still readable (never Store.delete'd) but flipped to retired, and
    # excluded from what boot shows.
    assert retired is not None
    assert retired["status"] == "retired"
    lanes = sl.load_corpus_lanes(own_project_dir=memory.parent.name)
    assert not any("canonical-verifier-name" in n or "Some text" in n for n in lanes["memory_notes"])

    fpath.write_text(_frontmatter("canonical-verifier-name", "feedback", "Some text."))
    seeded_again = sl.seed_corpus_corrections()
    assert seeded_again == 1
    restored = store.get("corpus_corrections", record_id)
    assert restored["status"] == "active"
    lanes = sl.load_corpus_lanes(own_project_dir=memory.parent.name)
    assert any("Some text" in n for n in lanes["memory_notes"])


def test_seed_corpus_corrections_zero_dirs_is_unreachable_not_empty(tmp_path, monkeypatch):
    """F1: a HOME lacking ~/.claude/projects must never retire the corpus."""
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    fpath = memory / "canonical-verifier-name.md"
    fpath.write_text(_frontmatter("canonical-verifier-name", "feedback", "Some text."))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])
    sl.seed_corpus_corrections()

    monkeypatch.setattr(sl, "memory_dirs", lambda: [])
    seeded = sl.seed_corpus_corrections()
    assert seeded == 0

    store = sl._corpus_store()
    record_id = f"{memory.parent.name}::canonical-verifier-name"
    assert store.get("corpus_corrections", record_id)["status"] == "active"


def test_seed_corpus_corrections_parse_error_leaves_record_untouched(tmp_path, monkeypatch):
    """F1: a transient frontmatter parse failure retires nothing — the file
    is still present, just unreadable this pass."""
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    fpath = memory / "canonical-verifier-name.md"
    fpath.write_text(_frontmatter("canonical-verifier-name", "feedback", "Good text."))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])
    sl.seed_corpus_corrections()

    fpath.write_text("---\nname broken no-colon\n---\nSome body.\n")
    sl.seed_corpus_corrections()

    store = sl._corpus_store()
    record_id = f"{memory.parent.name}::canonical-verifier-name"
    record = store.get("corpus_corrections", record_id)
    assert record["status"] == "active"
    assert record["content"] == "Good text."


def test_seed_corpus_corrections_malformed_frontmatter_reported_not_seeded(tmp_path, monkeypatch, caplog):
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    (memory / "broken-one.md").write_text(
        "---\nname broken-one no-colon-here\n---\nSome body.\n"
    )
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])

    with caplog.at_level("INFO", logger="willow_mcp.seed_loader"):
        seeded = sl.seed_corpus_corrections()
    assert seeded == 0
    store = sl._corpus_store()
    assert store.get("corpus_corrections", f"{memory.parent.name}::broken-one") is None
    assert any("broken-one.md" in rec.message for rec in caplog.records)


def test_seed_corpus_corrections_folded_description_and_toplevel_type(tmp_path, monkeypatch):
    """F7: a YAML folded '>' description parses, and a stray top-level
    `type:` (not nested under metadata:) is honored rather than dropped."""
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    (memory / "folded-one.md").write_text(
        "---\n"
        "name: folded-one\n"
        "description: >\n"
        "  This description\n"
        "  is folded across\n"
        "  several lines.\n"
        "metadata: \n"
        "  type: feedback\n"
        "---\n\nBody.\n"
    )
    (memory / "toplevel-type.md").write_text(
        "---\n"
        "name: toplevel-type\n"
        'description: "Top-level type key, not nested."\n'
        "type: feedback\n"
        "---\n\nBody.\n"
    )
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])

    seeded = sl.seed_corpus_corrections()
    assert seeded == 2

    store = sl._corpus_store()
    folded = store.get("corpus_corrections", f"{memory.parent.name}::folded-one")
    assert folded["content"] == "This description is folded across several lines."
    toplevel = store.get("corpus_corrections", f"{memory.parent.name}::toplevel-type")
    assert toplevel["content"] == "Top-level type key, not nested."


def test_seed_corpus_corrections_same_name_two_projects_is_two_records(tmp_path, monkeypatch):
    """F3/F4: identity is (project_dir, name) — a same-named memory file in
    two projects never overwrites the other."""
    mem_a = tmp_path / "proj-a" / "memory"
    mem_a.mkdir(parents=True)
    (mem_a / "shared-name.md").write_text(_frontmatter("shared-name", "feedback", "A says X."))
    mem_b = tmp_path / "proj-b" / "memory"
    mem_b.mkdir(parents=True)
    (mem_b / "shared-name.md").write_text(_frontmatter("shared-name", "feedback", "B says Y."))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [mem_a, mem_b])

    seeded = sl.seed_corpus_corrections()
    assert seeded == 2

    store = sl._corpus_store()
    a = store.get("corpus_corrections", f"{mem_a.parent.name}::shared-name")
    b = store.get("corpus_corrections", f"{mem_b.parent.name}::shared-name")
    assert a["content"] == "A says X."
    assert b["content"] == "B says Y."

    # Re-seeding is stable (no churn/overwrite loop across the two ids).
    assert sl.seed_corpus_corrections() == 0


def test_load_corpus_lanes_scopes_to_own_project_plus_fleet(tmp_path, monkeypatch):
    own = tmp_path / "own" / "memory"
    own.mkdir(parents=True)
    (own / "own-note.md").write_text(_frontmatter("own-note", "feedback", "Own project note."))
    other = tmp_path / "other" / "memory"
    other.mkdir(parents=True)
    (other / "other-plain.md").write_text(_frontmatter("other-plain", "feedback", "Other project, own-scope only."))
    (other / "other-fleet.md").write_text(
        _frontmatter("other-fleet", "feedback", "Other project, fleet-wide.", scope="fleet")
    )
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [own, other])
    sl.seed_corpus_corrections()

    lanes = sl.load_corpus_lanes(own_project_dir=own.parent.name)
    joined = " ".join(lanes["memory_notes"])
    assert "Own project note" in joined
    assert "fleet-wide" in joined
    assert "own-scope only" not in joined


def test_load_corpus_lanes_ranks_own_first_then_most_recently_modified(tmp_path, monkeypatch):
    own = tmp_path / "own" / "memory"
    own.mkdir(parents=True)
    (own / "old-own.md").write_text(
        _frontmatter("old-own", "feedback", "Old own note.", modified="2026-01-01T00:00:00.000Z")
    )
    other = tmp_path / "other" / "memory"
    other.mkdir(parents=True)
    (other / "fleet-new.md").write_text(
        _frontmatter("fleet-new", "feedback", "New fleet note.", scope="fleet",
                     modified="2026-09-01T00:00:00.000Z")
    )
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [own, other])
    sl.seed_corpus_corrections()

    lanes = sl.load_corpus_lanes(own_project_dir=own.parent.name)
    # Own-project note ranks ahead of a more-recently-modified fleet note —
    # relevance (own project) beats recency (ruling 3).
    assert lanes["memory_notes"][0].startswith("[unverified:") and "Old own note" in lanes["memory_notes"][0]

    # An edit's newer `modified` promotes it within its own group.
    (own / "old-own.md").write_text(
        _frontmatter("old-own", "feedback", "Old own note.", modified="2026-01-01T00:00:00.000Z")
    )
    (own / "new-own.md").write_text(
        _frontmatter("new-own", "feedback", "New own note.", modified="2026-09-01T00:00:00.000Z")
    )
    sl.seed_corpus_corrections()
    lanes = sl.load_corpus_lanes(own_project_dir=own.parent.name)
    assert "New own note" in lanes["memory_notes"][0]


def test_load_corpus_lanes_caps_and_reports_total(tmp_path, monkeypatch):
    memory = tmp_path / "proj-memory"
    memory.mkdir()
    for i in range(6):
        (memory / f"note-{i}.md").write_text(
            _frontmatter(f"note-{i}", "feedback", f"Note {i}.", modified=f"2026-01-0{i + 1}T00:00:00.000Z")
        )
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setattr(sl, "memory_dirs", lambda: [memory])
    sl.seed_corpus_corrections()

    lanes = sl.load_corpus_lanes(own_project_dir=memory.parent.name)
    assert len(lanes["memory_notes"]) == 4  # MAX_CORRECTIONS
    assert lanes["memory_note_total"] == 6


def test_load_sealed_corrections_three_states(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    store = sl._corpus_store()

    # empty: reachable, nothing sealed+tagged yet.
    result = sl.load_sealed_corrections(store)
    assert result["state"] == "empty"
    assert result["items"] == []

    # populated: a sealed governance record tagged boot_correction=true.
    from willow_mcp.seal_handler import GOVERNANCE_COLLECTION
    store.put(GOVERNANCE_COLLECTION, {
        "title": "Push directly to master is never allowed",
        "ruling": "Push directly to master is never allowed.",
        "status": "sealed",
        "boot_correction": True,
        "nestor_verifier": "sean campbell",
        "sealed_at": "2026-09-23T00:00:00Z",
    }, record_id="rule-1")
    result = sl.load_sealed_corrections(store)
    assert result["state"] == "populated"
    assert result["total"] == 1
    assert "master" in result["items"][0]["content"]

    # A sealed-but-untagged record, or a draft, still doesn't count.
    store.put(GOVERNANCE_COLLECTION, {
        "title": "Unrelated policy",
        "ruling": "Some other ruling.",
        "status": "sealed",
    }, record_id="rule-2")
    store.put(GOVERNANCE_COLLECTION, {
        "title": "Still a draft",
        "ruling": "Not sealed yet.",
        "status": "draft",
        "boot_correction": True,
    }, record_id="rule-3")
    result = sl.load_sealed_corrections(store)
    assert result["total"] == 1

    # unreachable: the store read itself fails.
    class _BrokenStore:
        def all(self, collection):
            raise RuntimeError("store unreachable")

    result = sl.load_sealed_corrections(_BrokenStore())
    assert result["state"] == "unreachable"
    assert result["items"] == []


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


def test_boot_lines_surface_frank_from_orientation(monkeypatch):
    """H4 / gap 344388bc31fc: FRANK presence is part of the boot-state contract."""
    _quiet_boot(monkeypatch)
    monkeypatch.setattr(gaps_mod, "list_gaps", lambda status=None, limit=50: {"items": []})
    enter_result = {
        "orientation": {
            "blockers": {"count": 0, "items": []},
            "records": {},
            "frank": {"status": "present", "path": "/tmp/FRANK"},
        },
        "verifier": "sean",
    }
    lines = bc.build_boot_lines("hanuman", "sess-frank", "startup", enter_result)
    joined = "\n".join(lines)
    assert "frank: present (/tmp/FRANK)" in joined
    assert "attestation: verified by sean" in joined
