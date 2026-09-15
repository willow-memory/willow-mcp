import json
from datetime import datetime, timezone

from willow_mcp import consent, consent_admin, envelopes, fleet_roster
from willow_mcp.governance_ledger import entry_hash, entry_hash_v2


class _Ledger:
    def __init__(self, used=0, final_outcome=None):
        self.used = used
        self.final_outcome = final_outcome
        self.events = []

    def citation_count(self, envelope_id):
        return self.used

    def append_citation(self, project, content, *, max_count):
        self.events.append((project, "envelope_citation", content))
        return "citation-1", self.final_outcome or content["outcome"]


def _charter(tmp_path, *, maximum=2):
    registry = {
        "active": [{
            "id": "env-dispatch",
            "verb_id": 11,
            "verb": "dispatch",
            "grantee": "willow",
            "bounds": {"to_agents": ["hanuman"], "task_class": ["build"]},
            "issued_by": "root",
            "issued_at": "2026-01-01",
            "expires_at": "2027-01-01",
            "max_count": maximum,
            "use_count_source": "frank",
            "status": "active",
        }]
    }
    table = {
        "verbs": [{
            "id": 11,
            "verb": "dispatch",
            "bounds": {"to_agents": "list", "task_class": "string"},
        }]
    }
    registry_path = tmp_path / "pre-approved.json"
    syscall_path = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    registry_path.write_text(json.dumps(registry))
    syscall_path.write_text(json.dumps(table))
    # §4.6: governance inputs must be operator-owned, non-writable to trust them.
    registry_path.chmod(0o600)
    syscall_path.chmod(0o600)
    return registry_path, syscall_path


def test_envelope_cites_grant_before_return(monkeypatch, tmp_path):
    registry, syscalls = _charter(tmp_path)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    ledger = _Ledger()

    result = envelopes.EnvelopeAuthority(ledger).authorize_and_cite(
        "env-dispatch",
        actor="willow",
        verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
        project="willow",
        session="s1",
    )

    assert result["ok"] is True
    assert result["cited_before_act"] is True
    assert ledger.events[0][2]["outcome"] == "granted"


def test_envelope_exhaustion_and_bounds_mismatch_are_cited(monkeypatch, tmp_path):
    registry, syscalls = _charter(tmp_path, maximum=1)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    ledger = _Ledger(used=1)
    authority = envelopes.EnvelopeAuthority(ledger)

    exhausted = authority.authorize_and_cite(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
        project="willow", session="s1",
    )
    mismatch = authority.authorize_and_cite(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args={"to_agents": "opus", "task_class": "build"},
        project="willow", session="s1",
    )

    assert exhausted["errno"] == "EDQUOT"
    assert mismatch["errno"] == "EAMBIG"
    assert [event[2]["outcome"] for event in ledger.events] == ["EDQUOT", "EAMBIG"]


def test_expiry_boundary_is_fail_closed(monkeypatch, tmp_path):
    registry, syscalls = _charter(tmp_path)
    data = json.loads(registry.read_text())
    data["active"][0]["expires_at"] = "2026-07-16T20:00:00+00:00"
    registry.write_text(json.dumps(data))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))

    result = envelopes.EnvelopeAuthority(_Ledger()).check(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
        now=datetime(2026, 7, 16, 20, 0, tzinfo=timezone.utc),
    )
    assert result["errno"] == "EEXPIRED"


def test_atomic_meter_can_refuse_racing_final_use(monkeypatch, tmp_path):
    registry, syscalls = _charter(tmp_path)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    result = envelopes.EnvelopeAuthority(_Ledger(final_outcome="EDQUOT")).authorize_and_cite(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
        project="willow", session="s1",
    )
    assert result["ok"] is False
    assert result["errno"] == "EDQUOT"


# ── EnvelopeAuthority.check() — per-guard coverage ───────────────────────────
# Found by tools/envelope_mutation_check.py: every case below reported GAP
# (the guard's own mutation survived) until the test naming it was added. The
# harness is not part of pytest -- it is slow because it reruns this file
# once per guard -- so these are the tests it found missing, not the harness
# itself.

def _check_with(tmp_path, monkeypatch, overrides=None, *, call_args=None,
                 actor="willow", verb="dispatch"):
    registry, syscalls = _charter(tmp_path)
    data = json.loads(registry.read_text())
    if overrides:
        data["active"][0].update(overrides)
    registry.write_text(json.dumps(data))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    return envelopes.EnvelopeAuthority(_Ledger()).check(
        "env-dispatch", actor=actor, verb=verb,
        call_args=call_args if call_args is not None
        else {"to_agents": "hanuman", "task_class": "build"},
    )


def test_check_refuses_empty_registry_loudly(monkeypatch, tmp_path):
    """#332 runtime guard: a registry that loads but holds zero active grants —
    the empty starter seeded at a relocated $WILLOW_HOME while the ratified
    registry is left behind — must be refused as a distinct, loud ENOGRANTS that
    names the resolved file, not the generic per-envelope ENOENT ("envelope not
    active") that read as one grant expiring and hid the outage for ~60 hours."""
    registry, syscalls = _charter(tmp_path)
    data = json.loads(registry.read_text())
    data["active"] = []  # the seeded empty-starter shape
    registry.write_text(json.dumps(data))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    result = envelopes.EnvelopeAuthority(_Ledger()).check(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
    )
    assert result["ok"] is False
    assert result["errno"] == "ENOGRANTS"
    # The reason must name the resolved registry so the diagnosis is one line.
    assert str(registry) in result["reason"]


def test_empty_registry_errno_is_registered_in_the_syscall_table(monkeypatch, tmp_path):
    """ENOGRANTS is a governed errno: the enforcer returns it, so the errno
    registry in the shipped syscall table must define it (route + meaning), the
    same contract every other errno check() emits already honors."""
    from willow_mcp import paths

    table = json.loads((paths.bundle_dir() / "constitutional" / "syscall-table.json").read_text())
    assert "ENOGRANTS" in table["errno"], "check() emits ENOGRANTS; the table must define it"
    assert table["errno"]["ENOGRANTS"]["route"] == "trap_to_console"


def test_registry_of_all_malformed_active_rows_is_ENOGRANTS_not_a_generic_miss(monkeypatch, tmp_path):
    """The guard keys on usable grants, not container truthiness: an `active`
    list that is non-empty but all-malformed (non-dicts, or dicts with no id — a
    truncated write or bad merge) holds zero usable grants and must be refused as
    the loud, systemic ENOGRANTS, not the generic per-envelope ENOENT."""
    registry, syscalls = _charter(tmp_path)
    data = json.loads(registry.read_text())
    data["active"] = ["not-a-dict", 42, {"no": "id"}]  # non-empty, zero usable
    registry.write_text(json.dumps(data))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    result = envelopes.EnvelopeAuthority(_Ledger()).check(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
    )
    assert result["errno"] == "ENOGRANTS"


def test_a_populated_registry_missing_this_id_is_ENOENT_not_ENOGRANTS(monkeypatch, tmp_path):
    """The other side of the boundary: a registry that DOES hold a usable grant,
    just not this envelope_id, is a per-envelope miss (ENOENT), not the systemic
    ENOGRANTS. ENOGRANTS must not swallow ordinary 'no envelope covers this'."""
    registry, syscalls = _charter(tmp_path)  # one usable grant, id 'env-dispatch'
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    result = envelopes.EnvelopeAuthority(_Ledger()).check(
        "env-does-not-exist", actor="willow", verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
    )
    assert result["errno"] == "ENOENT"


def test_every_errno_check_emits_is_registered_in_the_table():
    """Structural contract, not convention: every errno string EnvelopeAuthority
    .check() and its helpers can return must be defined in the shipped syscall
    table's errno registry. Add an errno to the enforcer without registering it
    and this fails — the mechanism that keeps 'the table documents every failure
    mode' honest (the #332 lesson: a governed declaration must track the code)."""
    import re
    from pathlib import Path
    from willow_mcp import paths

    src = Path(envelopes.__file__).read_text()
    emitted = set(re.findall(r'"errno":\s*"([A-Z]+)"', src))
    assert "ENOGRANTS" in emitted, "sanity: the guard's errno should appear in the source"
    table = json.loads((paths.bundle_dir() / "constitutional" / "syscall-table.json").read_text())
    registered = set(table["errno"])
    missing = emitted - registered
    assert not missing, f"errno(s) check() emits but the table does not register: {sorted(missing)}"


def test_check_refuses_duplicate_envelope_id(monkeypatch, tmp_path):
    """Two active rows sharing one id must not silently resolve to the
    first -- that is exactly as forgeable as a missing envelope."""
    registry, syscalls = _charter(tmp_path)
    data = json.loads(registry.read_text())
    data["active"].append(dict(data["active"][0]))
    registry.write_text(json.dumps(data))
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    result = envelopes.EnvelopeAuthority(_Ledger()).check(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
    )
    assert result["ok"] is False
    assert result["errno"] == "ENOENT"


def test_check_refuses_issuer_not_root(monkeypatch, tmp_path):
    result = _check_with(tmp_path, monkeypatch, {"issued_by": "agent"})
    assert result == {"ok": False, "errno": "EACCES", "reason": "issuer mismatch"}


def test_check_refuses_revoked_envelope(monkeypatch, tmp_path):
    result = _check_with(tmp_path, monkeypatch, {"revoked": True})
    assert result == {"ok": False, "errno": "EACCES", "reason": "envelope revoked"}


def test_check_refuses_inactive_status(monkeypatch, tmp_path):
    result = _check_with(tmp_path, monkeypatch, {"status": "pending"})
    assert result == {"ok": False, "errno": "ENOENT", "reason": "envelope inactive"}


def test_check_refuses_actor_outside_grantee(monkeypatch, tmp_path):
    result = _check_with(tmp_path, monkeypatch, actor="mallory")
    assert result == {"ok": False, "errno": "EACCES", "reason": "grantee mismatch"}


def test_check_refuses_verb_not_matching_envelope(monkeypatch, tmp_path):
    result = _check_with(tmp_path, monkeypatch, verb="not_dispatch")
    assert result["ok"] is False
    assert result["errno"] == "EAMBIG"
    assert result["reason"] == "verb mismatch"


def test_check_refuses_non_dict_bounds(monkeypatch, tmp_path):
    result = _check_with(tmp_path, monkeypatch, {"bounds": ["not", "a", "dict"]})
    assert result == {"ok": False, "errno": "EAMBIG", "reason": "malformed bounds"}


def test_check_refuses_bounds_signature_mismatch(monkeypatch, tmp_path):
    # drops task_class from the granted bounds -- no longer matches the
    # syscall table's declared {to_agents, task_class} signature.
    result = _check_with(tmp_path, monkeypatch, {"bounds": {"to_agents": ["hanuman"]}})
    assert result["ok"] is False
    assert result["errno"] == "EAMBIG"
    assert result["reason"] == "bounds signature mismatch"


def test_check_refuses_malformed_max_count(monkeypatch, tmp_path):
    for bad in (-1, True, "3"):
        result = _check_with(tmp_path, monkeypatch, {"max_count": bad})
        assert result == {"ok": False, "errno": "EAMBIG", "reason": "invalid max_count"}, bad


def test_check_refuses_untrusted_meter_source(monkeypatch, tmp_path):
    result = _check_with(tmp_path, monkeypatch, {"use_count_source": "self_reported"})
    assert result == {"ok": False, "errno": "EAMBIG", "reason": "untrusted meter"}


def test_bound_matches_requires_every_item_in_a_list_call_arg(monkeypatch, tmp_path):
    # Grant covers hanuman and opus; a call naming a third, ungranted agent
    # alongside a granted one must still fail closed -- one matching item is
    # not enough when the call itself names more than one recipient.
    result = _check_with(
        tmp_path, monkeypatch,
        {"bounds": {"to_agents": ["hanuman", "opus"], "task_class": ["build"]}},
        call_args={"to_agents": ["hanuman", "mallory"], "task_class": "build"},
    )
    assert result["ok"] is False
    assert result["errno"] == "EAMBIG"
    assert "to_agents" in result.get("fields", [])


def test_bound_matches_scalar_grant_requires_exact_equality(monkeypatch, tmp_path):
    scalar_bounds = {"bounds": {"to_agents": ["hanuman"], "task_class": "build"}}
    granted = _check_with(
        tmp_path, monkeypatch, scalar_bounds,
        call_args={"to_agents": "hanuman", "task_class": "build"},
    )
    assert granted["ok"] is True

    denied = _check_with(
        tmp_path, monkeypatch, scalar_bounds,
        call_args={"to_agents": "hanuman", "task_class": "refactor"},
    )
    assert denied["ok"] is False
    assert denied["errno"] == "EAMBIG"
    assert "task_class" in denied.get("fields", [])


def test_deadline_refuses_non_string_expires_at_instead_of_crashing(monkeypatch, tmp_path):
    result = _check_with(tmp_path, monkeypatch, {"expires_at": 20270101})
    assert result["ok"] is False
    assert result["errno"] == "EAMBIG"


def test_consent_admin_atomically_reconciles_and_audits(monkeypatch, tmp_path):
    monkeypatch.setattr(consent_admin, "_require_operator_terminal", lambda: None)
    tmp_path.chmod(0o700)
    canonical = tmp_path / "settings.global.json"
    mirror = tmp_path / "consent.json"
    canonical.write_text(json.dumps({"other": 1, "consent": {
        "internet": False, "cloud_llm": False, "lan": False,
    }}))
    canonical.chmod(0o600)
    mirror.write_text(json.dumps({
        "internet": True, "cloud_llm": False, "lan": False,
    }))
    mirror.chmod(0o600)
    monkeypatch.setattr(consent, "settings_path", lambda: canonical)
    monkeypatch.setattr(consent, "legacy_path", lambda: mirror)

    result = consent_admin.set_key("internet", True)

    assert json.loads(canonical.read_text())["other"] == 1
    assert json.loads(mirror.read_text())["internet"] is True
    assert result["reconciled"] is True
    assert "before_hash" in json.loads(
        (tmp_path / "audit" / "consent.jsonl").read_text().splitlines()[0]
    )


def test_roster_loader_rejects_prose_rows(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    roster = tmp_path / "fleet.json"
    roster.write_text(json.dumps({"agents": {"hanuman": "engineer"}}))
    roster.chmod(0o600)
    monkeypatch.setenv("WILLOW_FLEET_ROSTER", str(roster))
    try:
        fleet_roster.load_roster()
    except ValueError as exc:
        assert "malformed" in str(exc)
    else:
        raise AssertionError("malformed roster was accepted")


def test_consent_admin_refuses_malformed_or_untrusted_policy(monkeypatch, tmp_path):
    monkeypatch.setattr(consent_admin, "_require_operator_terminal", lambda: None)
    tmp_path.chmod(0o700)
    canonical = tmp_path / "settings.global.json"
    mirror = tmp_path / "consent.json"
    canonical.write_text("{")
    canonical.chmod(0o600)
    monkeypatch.setattr(consent, "settings_path", lambda: canonical)
    monkeypatch.setattr(consent, "legacy_path", lambda: mirror)
    try:
        consent_admin.set_key("internet", True)
    except ValueError as exc:
        assert "malformed" in str(exc)
    else:
        raise AssertionError("malformed policy was overwritten")

    canonical.write_text(json.dumps({"consent": {
        "internet": False, "cloud_llm": False, "lan": False,
    }}))
    canonical.chmod(0o666)
    try:
        consent_admin.set_key("internet", True)
    except PermissionError as exc:
        assert "untrusted" in str(exc)
    else:
        raise AssertionError("world-writable policy was accepted")


def test_hash_matches_existing_frank_algorithm():
    assert entry_hash(None, "decision", {"b": 2, "a": 1}) == entry_hash(
        None, "decision", {"a": 1, "b": 2}
    )


# ── §4.6 input authentication (trust root) ───────────────────────────────────

def test_envelope_registry_refused_when_world_writable(monkeypatch, tmp_path):
    registry, syscalls = _charter(tmp_path)
    registry.chmod(0o666)  # anyone can rewrite the grant table → forged envelopes
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    result = envelopes.EnvelopeAuthority(_Ledger()).check(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args={"to_agents": "hanuman", "task_class": "build"},
    )
    assert result["ok"] is False
    assert result["errno"] == "EAMBIG"  # untrusted source → fail-closed


def test_roster_refused_when_world_writable(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    roster = tmp_path / "fleet.json"
    roster.write_text(json.dumps({"agents": {"hanuman": {"role": "b", "trust": "t"}}}))
    roster.chmod(0o666)
    monkeypatch.setenv("WILLOW_FLEET_ROSTER", str(roster))
    try:
        fleet_roster.load_roster()
    except PermissionError as exc:
        assert "untrusted" in str(exc)
    else:
        raise AssertionError("world-writable roster was trusted")


# ── §4.3 non-forgeable operator boundary ─────────────────────────────────────

def test_operator_terminal_refused_inside_kart(monkeypatch):
    from willow_mcp import human_session
    monkeypatch.setenv("WILLOW_IN_KART", "1")
    try:
        human_session.require_operator_terminal()
    except PermissionError as exc:
        assert "Kart" in str(exc)
    else:
        raise AssertionError("mutation allowed inside the sandbox")


def test_operator_terminal_refused_without_tty(monkeypatch):
    from willow_mcp import human_session
    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    monkeypatch.setattr(human_session.os, "getuid", lambda: 1000)
    import sys as _sys
    monkeypatch.setattr(_sys.stdin, "isatty", lambda: False)
    try:
        human_session.require_operator_terminal()
    except PermissionError as exc:
        assert "terminal" in str(exc)
    else:
        raise AssertionError("mutation allowed without an operator terminal")


def _fake_tty_stat(monkeypatch, human_session, tty_owner_uid: int):
    import os as _os
    import sys as _sys

    tty = "/dev/pts/7"
    real_stat = human_session.os.stat

    def _stat(path, *args, **kwargs):
        if path == tty:
            return _os.stat_result(
                (0o620, 0, 0, 0, tty_owner_uid, 0, 0, 0, 0, 0)
            )
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(human_session.os, "ttyname", lambda _fd: tty)
    monkeypatch.setattr(human_session.os, "stat", _stat)
    monkeypatch.setattr(_sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(_sys.stdin, "fileno", lambda: 0)


def test_trust_owner_publication_accepts_human_tty_under_sudo(monkeypatch):
    """After sudo -u trust-owner, getuid() is not the tty owner; SUDO_UID is."""
    from willow_mcp import human_session

    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(human_session.os, "geteuid", lambda: 994)
    monkeypatch.setattr(human_session.os, "getuid", lambda: 994)
    _fake_tty_stat(monkeypatch, human_session, 1000)
    human_session.require_trust_owner_publication_terminal()


def test_trust_owner_publication_refuses_tty_owner_mismatch(monkeypatch):
    from willow_mcp import human_session

    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(human_session.os, "geteuid", lambda: 994)
    _fake_tty_stat(monkeypatch, human_session, 1001)
    try:
        human_session.require_trust_owner_publication_terminal()
    except PermissionError as exc:
        assert "invoked sudo" in str(exc)
    else:
        raise AssertionError("publication allowed with wrong tty owner")


def test_operator_terminal_refuses_trust_owner_uid_with_human_tty(monkeypatch):
    """Regression for Loki publish-sudo-tty-ownership: the old check blocked sudo."""
    from willow_mcp import human_session

    monkeypatch.delenv("WILLOW_IN_KART", raising=False)
    monkeypatch.setattr(human_session.os, "getuid", lambda: 994)
    _fake_tty_stat(monkeypatch, human_session, 1000)
    try:
        human_session.require_operator_terminal()
    except PermissionError as exc:
        assert "invoking operator" in str(exc)
    else:
        raise AssertionError("trust-owner uid passed the human-only gate")


def test_operator_terminal_script_wrapper_satisfies_gate():
    """`.github/workflows/tests.yml` runs operator CLIs through this wrapper."""
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    script = repo / "scripts" / "operator_terminal.sh"
    assert script.is_file(), "CI smoke depends on scripts/operator_terminal.sh"
    py_cmd = (
        "import os; from willow_mcp import human_session; "
        "os.environ.pop('WILLOW_IN_KART', None); "
        "human_session.require_operator_terminal(); print('ok')"
    )
    proc = subprocess.run(
        ["bash", str(script), sys.executable, "-c", py_cmd],
        capture_output=True,
        text=True,
        cwd=repo,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "ok" in proc.stdout


def test_operator_terminal_script_propagates_child_exit_code():
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    script = repo / "scripts" / "operator_terminal.sh"
    proc = subprocess.run(
        ["bash", str(script), sys.executable, "-c", "raise SystemExit(17)"],
        capture_output=True,
        text=True,
        cwd=repo,
        check=False,
    )
    assert proc.returncode == 17


# ── §4.2 frank_append / envelope_apply behind the human-orchestrator boundary ─

def test_governance_tools_require_human_orchestrator_for_willow(monkeypatch):
    from willow_mcp import human_session
    monkeypatch.delenv("WILLOW_HUMAN_ORCHESTRATOR", raising=False)
    for tool in ("frank_append", "envelope_apply"):
        # willow seat, unattested → denied
        denial = human_session.orchestrator_write_denial("willow", tool, serve_mode=False)
        assert denial and "human" in denial.lower()
        # a specialist app is not blocked by the willow boundary (its own
        # capability still gates it) — caller cannot bypass by NOT being willow.
        assert human_session.orchestrator_write_denial("hanuman", tool, serve_mode=False) is None
    # attested host clears it
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    assert human_session.orchestrator_write_denial("willow", "frank_append", serve_mode=False) is None


# ── §4.7 roster sync aborts on a source that changed mid-sync ─────────────────

def test_roster_sync_aborts_if_source_changes(monkeypatch, tmp_path):
    from willow_mcp import human_session
    tmp_path.chmod(0o700)
    roster = tmp_path / "fleet.json"
    roster.write_text(json.dumps({"agents": {"hanuman": {"role": "b", "trust": "t"}}}))
    roster.chmod(0o600)
    monkeypatch.setenv("WILLOW_FLEET_ROSTER", str(roster))
    monkeypatch.setattr(human_session, "require_operator_terminal", lambda: None)

    class _Cur:
        def execute(self, *a, **k): pass
        def fetchall(self): return []
        def close(self): pass
    class _Pg:
        def cursor(self): return _Cur()
        def commit(self): pass

    digests = iter(["digest-A", "digest-B"])  # changes between pin and recheck
    monkeypatch.setattr(fleet_roster, "_roster_digest", lambda: next(digests))
    try:
        fleet_roster.sync(_Pg())
    except RuntimeError as exc:
        assert "changed during sync" in str(exc)
    else:
        raise AssertionError("sync wrote despite the source changing underfoot")


# ── §4.1 chain append retries a lost prev_hash race instead of forking ───────

def test_chain_insert_retries_on_prev_hash_conflict():
    import psycopg2
    from willow_mcp.governance_ledger import GovernanceLedger

    class _Cur:
        def __init__(self, pg): self.pg = pg
        def execute(self, sql, params=None):
            if sql.strip().upper().startswith("INSERT"):
                self.pg.inserts += 1
                if self.pg.inserts == 1:
                    raise psycopg2.IntegrityError("frank_ledger_no_fork")
        def fetchone(self): return ("head-hash",)
        def close(self): pass
    class _Pg:
        def __init__(self): self.inserts = 0; self.commits = 0; self.rollbacks = 0
        def cursor(self): return _Cur(self)
        def commit(self): self.commits += 1
        def rollback(self): self.rollbacks += 1

    pg = _Pg()
    digest = GovernanceLedger(pg)._chain_insert(
        _Cur(pg), "rec-1", "willow", "decision", {"a": 1}
    )
    assert pg.inserts == 2          # first lost the race, second won
    assert pg.rollbacks == 1
    assert pg.commits == 1
    # A7: new appends use the v2 digest, which covers id + project.
    assert digest == entry_hash_v2("head-hash", "rec-1", "willow", "decision", {"a": 1})


# ── §4.5 one citation authorizes exactly one bounded act ─────────────────────

def test_one_citation_per_act_and_second_act_needs_second_citation(monkeypatch, tmp_path):
    registry, syscalls = _charter(tmp_path, maximum=1)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    args = {"to_agents": "hanuman", "task_class": "build"}

    ledger = _Ledger(used=0)
    authority = envelopes.EnvelopeAuthority(ledger)
    first = authority.authorize_and_cite(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args=args, project="willow", session="s1",
    )
    assert first["ok"] is True
    assert len(ledger.events) == 1                    # exactly one citation for one act

    # the grant is now exhausted (max_count=1); a second act cites and is refused
    ledger.used = 1
    ledger.final_outcome = "EDQUOT"
    second = authority.authorize_and_cite(
        "env-dispatch", actor="willow", verb="dispatch",
        call_args=args, project="willow", session="s1",
    )
    assert second["ok"] is False and second["errno"] == "EDQUOT"
    assert len(ledger.events) == 2                    # a distinct citation, not a replay
