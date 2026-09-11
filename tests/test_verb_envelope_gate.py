"""Verb-level citation-before-act enforcement (#333).

Background: envelope use counts are DERIVED by counting `envelope_citation`
entries in FRANK, never a stored counter. Before this fix the only writer of
that citation was the opt-in `envelope_apply` tool -- an enveloped verb
reachable through its own MCP tool (observed: `dispatch_send`) could skip
`envelope_apply` entirely and neither be charged nor denied. These tests
cover the fix: `dispatch_send` (verb "dispatch", the only verb currently
wired into `server.VERB_LEVEL_ENFORCED_VERBS`) now resolves its own
governing envelope and cites it, atomically with the act, from inside its
own handler.
"""
import json

import pytest

from willow_mcp import server


@pytest.fixture(autouse=True)
def _fresh_rate_buckets():
    server._buckets.clear()
    yield
    server._buckets.clear()


def _write_manifest(home, app_id, **overrides):
    d = home / "mcp_apps" / app_id
    d.mkdir(parents=True, exist_ok=True)
    data = {"app_id": app_id, "permissions": ["dispatch_write", "dispatch_read"]}
    data.update(overrides)
    (d / "manifest.json").write_text(json.dumps(data))


def _charter(tmp_path, *, grantee="loki", maximum=None, extra_active=None):
    """A registry + syscall table naming one active "dispatch" grant, same
    shape as test_governance_continuity.py's _charter (verb 11, bounds
    {to_agents, task_class}) -- kept independent here since this file
    exercises the grant through the real MCP tool path, not EnvelopeAuthority
    directly."""
    active = [{
        "id": "env-dispatch-1",
        "verb_id": 11,
        "verb": "dispatch",
        "grantee": grantee,
        # task_class mirrors dispatch_send's own role-resolution fallback
        # (`role or to_app`, lowercased) -- these tests call dispatch_send
        # with to_app="hanuman" and no explicit role, so the gate's resolved
        # task_class is "hanuman".
        "bounds": {"to_agents": ["hanuman"], "task_class": ["hanuman"]},
        "issued_by": "root",
        "issued_at": "2026-01-01",
        "expires_at": "2027-01-01",
        "max_count": maximum,
        "use_count_source": "frank",
        "status": "active",
    }]
    if extra_active:
        active.extend(extra_active)
    registry = {"active": active}
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
    registry_path.chmod(0o600)
    syscall_path.chmod(0o600)
    return registry_path, syscall_path


def _set_charter(monkeypatch, tmp_path, **kwargs):
    registry, syscalls = _charter(tmp_path, **kwargs)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscalls))
    return registry, syscalls


# ── a fake frank_ledger backing GovernanceLedger.append_citation / .citation_count ──

class _FakeGovernancePg:
    def __init__(self):
        self.rows = []  # each: {id, project, event_type, content, prev_hash, hash}
        self.commits = 0

    def cursor(self):
        return _FakeGovernanceCursor(self)

    def commit(self):
        self.commits += 1


class _FakeGovernanceCursor:
    def __init__(self, pg):
        self.pg = pg
        self._result = []

    def execute(self, sql, params=None):
        params = params or ()
        s = sql.strip()
        if "pg_advisory" in s:
            return
        if s.startswith("SELECT COUNT(*)"):
            envelope_id = params[0]
            count = sum(
                1 for r in self.pg.rows
                if r["event_type"] == "envelope_citation"
                and r["content"].get("envelope_id") == envelope_id
                and r["content"].get("outcome") == "granted"
            )
            self._result = [(count,)]
            return
        if s.startswith("SELECT hash FROM"):
            self._result = [(self.pg.rows[-1]["hash"],)] if self.pg.rows else []
            return
        if s.startswith("INSERT INTO"):
            record_id, project, event_type, content, prev_hash, digest = params
            content_val = getattr(content, "adapted", content)
            self.pg.rows.append({
                "id": record_id, "project": project, "event_type": event_type,
                "content": content_val, "prev_hash": prev_hash, "hash": digest,
            })
            return
        raise AssertionError(f"unexpected SQL in fake governance pg: {sql!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def close(self):
        pass


def _citations(pg, envelope_id=None):
    rows = [r for r in pg.rows if r["event_type"] == "envelope_citation"]
    if envelope_id:
        rows = [r for r in rows if r["content"].get("envelope_id") == envelope_id]
    return rows


# ── (a) enveloped verb, no prior citation: writes exactly one, meter increases ──

def test_dispatch_send_writes_one_citation_and_meter_increases(home, monkeypatch, tmp_path):
    _write_manifest(home, "loki")
    _set_charter(monkeypatch, tmp_path, maximum=5)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    from willow_mcp.governance_ledger import GovernanceLedger
    assert GovernanceLedger(pg).citation_count("env-dispatch-1") == 0

    sent = server.dispatch_send(
        "loki", "hanuman", "# Assignment\n\nDo the thing.\n",
    )

    assert "error" not in sent
    assert "dispatch_id" in sent
    cites = _citations(pg, "env-dispatch-1")
    assert len(cites) == 1
    assert cites[0]["content"]["outcome"] == "granted"
    assert cites[0]["content"]["verb"] == "dispatch"
    assert GovernanceLedger(pg).citation_count("env-dispatch-1") == 1


def test_dispatch_send_second_call_writes_a_second_distinct_citation(home, monkeypatch, tmp_path):
    _write_manifest(home, "loki")
    _set_charter(monkeypatch, tmp_path, maximum=5)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    server.dispatch_send("loki", "hanuman", "# One\n")
    server.dispatch_send("loki", "hanuman", "# Two\n")

    assert len(_citations(pg, "env-dispatch-1")) == 2


# ── (b) exhausted envelope: refused with the quota domain error, act does not run ──

def test_dispatch_send_refuses_with_edquot_when_envelope_exhausted(home, monkeypatch, tmp_path):
    _write_manifest(home, "loki")
    _set_charter(monkeypatch, tmp_path, maximum=1)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    first = server.dispatch_send("loki", "hanuman", "# One\n")
    assert "error" not in first

    before = server.dispatch_list("loki", from_app="loki")
    result = server.dispatch_send("loki", "hanuman", "# Two\n")

    assert result.get("error") == "EDQUOT"
    assert "dispatch_id" not in result
    after = server.dispatch_list("loki", from_app="loki")
    # The act did not execute: no new packet was written for the refused call.
    assert after["total"] == before["total"]
    assert len(_citations(pg, "env-dispatch-1")) == 2  # the refusal was cited too
    assert [c["content"]["outcome"] for c in _citations(pg, "env-dispatch-1")] == [
        "granted", "EDQUOT",
    ]


def test_dispatch_send_refuses_when_postgres_unavailable_but_envelope_governs(home, monkeypatch, tmp_path):
    """A governing envelope was found but the ledger it must cite to is
    unreachable -- fails closed (mirrors envelope_apply's own
    _postgres_unavailable()), rather than silently letting the act through
    uncited."""
    _write_manifest(home, "loki")
    _set_charter(monkeypatch, tmp_path, maximum=5)
    monkeypatch.setattr(server, "get_pg", lambda: None)

    result = server.dispatch_send("loki", "hanuman", "# One\n")

    assert result.get("error") == "postgres_unavailable"


def test_dispatch_send_refuses_ambiguously_governed_verb(home, monkeypatch, tmp_path):
    """Two active grants covering the same verb+actor: the gate cannot say
    which would be charged, so it refuses rather than guessing -- and does
    not cite either one."""
    _write_manifest(home, "loki")
    extra = [{
        "id": "env-dispatch-2", "verb_id": 11, "verb": "dispatch", "grantee": "loki",
        "bounds": {"to_agents": ["hanuman"], "task_class": ["hanuman"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }]
    _set_charter(monkeypatch, tmp_path, maximum=None, extra_active=extra)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    result = server.dispatch_send("loki", "hanuman", "# One\n")

    assert result.get("error") == "EAMBIG"
    assert pg.rows == []


def test_envelope_id_disambiguates_two_governing_grants(home, monkeypatch, tmp_path):
    """Two legitimate grants is a normal registry state. Naming one lets the
    call proceed and charges THAT envelope -- the caller says which, the gate
    does not guess."""
    _write_manifest(home, "loki")
    extra = [{
        "id": "env-dispatch-2", "verb_id": 11, "verb": "dispatch", "grantee": "loki",
        "bounds": {"to_agents": ["hanuman"], "task_class": ["hanuman"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }]
    _set_charter(monkeypatch, tmp_path, maximum=None, extra_active=extra)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    result = server.dispatch_send("loki", "hanuman", "# One\n",
                                  envelope_id="env-dispatch-2")

    assert "error" not in result, result
    assert len(pg.rows) == 1
    assert "env-dispatch-2" in json.dumps(pg.rows[0])


def test_envelope_id_cannot_name_an_envelope_that_does_not_govern(home, monkeypatch, tmp_path):
    """The parameter disambiguates; it must never widen. An id outside the
    actor's own governing set is refused, and nothing is cited."""
    _write_manifest(home, "loki")
    extra = [{
        "id": "env-dispatch-2", "verb_id": 11, "verb": "dispatch", "grantee": "loki",
        "bounds": {"to_agents": ["hanuman"], "task_class": ["hanuman"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }]
    _set_charter(monkeypatch, tmp_path, maximum=None, extra_active=extra)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    result = server.dispatch_send("loki", "hanuman", "# One\n",
                                  envelope_id="env-somebody-elses")

    assert result.get("error") == "ENOENT"
    assert pg.rows == []


def test_eambig_names_the_parameter_that_resolves_it(home, monkeypatch, tmp_path):
    """An error that says what to do next. The ids to choose from are already
    in the payload; the reason now says how to use them."""
    _write_manifest(home, "loki")
    extra = [{
        "id": "env-dispatch-2", "verb_id": 11, "verb": "dispatch", "grantee": "loki",
        "bounds": {"to_agents": ["hanuman"], "task_class": ["hanuman"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }]
    _set_charter(monkeypatch, tmp_path, maximum=None, extra_active=extra)
    monkeypatch.setattr(server, "get_pg", lambda: _FakeGovernancePg())

    result = server.dispatch_send("loki", "hanuman", "# One\n")

    assert result.get("error") == "EAMBIG"
    assert "envelope_id" in result.get("reason", "")
    assert set(result["envelope_ids"]) >= {"env-dispatch-2"}


def test_eambig_names_the_matched_envelope_ids_and_distinguishing_bounds(
    home, monkeypatch, tmp_path
):
    """dispatch-EAMBIG-blocker: the ambiguous refusal now names not just which
    envelope ids matched but what tells them apart -- their bounds -- pulled
    from the real registry rows the gate itself just resolved, not a canned
    hint."""
    _write_manifest(home, "loki")
    extra = [{
        "id": "env-dispatch-2", "verb_id": 11, "verb": "dispatch", "grantee": "loki",
        "bounds": {"to_agents": ["hanuman"], "task_class": ["builder"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }]
    _set_charter(monkeypatch, tmp_path, maximum=None, extra_active=extra)
    monkeypatch.setattr(server, "get_pg", lambda: _FakeGovernancePg())

    result = server.dispatch_send("loki", "hanuman", "# One\n")

    assert result.get("error") == "EAMBIG"
    detail = {row["envelope_id"]: row["bounds"] for row in result["envelopes"]}
    assert set(detail) == {"env-dispatch-1", "env-dispatch-2"}
    # task_class is the bound that differs between the two real grants
    # (["hanuman"] vs ["builder"]) -- it must show up, distinguishing them.
    assert detail["env-dispatch-1"]["task_class"] == ["hanuman"]
    assert detail["env-dispatch-2"]["task_class"] == ["builder"]


def test_eambig_names_the_exact_retry_shape_for_dispatch_send(home, monkeypatch, tmp_path):
    """The caller should not have to reverse-engineer dispatch_send's own
    signature to retry: the refusal names the tool, the parameter
    (envelope_id), and the exact role value this call resolved -- without
    ever picking one of the real envelope_ids FOR the caller."""
    _write_manifest(home, "loki")
    extra = [{
        "id": "env-dispatch-2", "verb_id": 11, "verb": "dispatch", "grantee": "loki",
        "bounds": {"to_agents": ["hanuman"], "task_class": ["hanuman"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }]
    _set_charter(monkeypatch, tmp_path, maximum=None, extra_active=extra)
    monkeypatch.setattr(server, "get_pg", lambda: _FakeGovernancePg())

    result = server.dispatch_send("loki", "hanuman", "# One\n")

    assert result.get("error") == "EAMBIG"
    retry = result["retry"]
    assert retry["tool"] == "dispatch_send"
    assert retry["role"] == "hanuman"  # resolved_role fallback: role or to_app, lowercased
    # The retry shape documents the parameter to pass -- it never fills in
    # one of the real matched ids itself.
    assert retry["envelope_id"] not in result["envelope_ids"]


def test_eambig_never_auto_selects_an_envelope(home, monkeypatch, tmp_path):
    """However legible the message gets, the gate still refuses rather than
    guessing: no citation is written and no packet is created on an
    ambiguous match."""
    _write_manifest(home, "loki")
    extra = [{
        "id": "env-dispatch-2", "verb_id": 11, "verb": "dispatch", "grantee": "loki",
        "bounds": {"to_agents": ["hanuman"], "task_class": ["hanuman"]},
        "issued_by": "root", "issued_at": "2026-01-01", "expires_at": "2027-01-01",
        "max_count": None, "use_count_source": "frank", "status": "active",
    }]
    _set_charter(monkeypatch, tmp_path, maximum=None, extra_active=extra)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    before = server.dispatch_list("loki", from_app="loki")
    result = server.dispatch_send("loki", "hanuman", "# One\n")
    after = server.dispatch_list("loki", from_app="loki")

    assert result.get("error") == "EAMBIG"
    assert pg.rows == []
    assert after["total"] == before["total"]


# ── (c) non-enveloped verbs / actors are unaffected ─────────────────────────

def test_dispatch_send_unaffected_when_no_envelope_governs_this_actor(home, monkeypatch, tmp_path):
    """The registry holds a real "dispatch" grant, but not for THIS actor --
    unenveloped for "mallory", so the call proceeds exactly as before #333,
    without ever needing Postgres."""
    _write_manifest(home, "mallory")
    _set_charter(monkeypatch, tmp_path, grantee="loki", maximum=1)
    monkeypatch.setattr(server, "get_pg", lambda: (_ for _ in ()).throw(
        AssertionError("get_pg should not be called when no envelope governs this actor")
    ))

    result = server.dispatch_send("mallory", "hanuman", "# One\n")

    assert "error" not in result
    assert "dispatch_id" in result


def test_dispatch_send_unaffected_with_no_registry_configured(home, monkeypatch):
    """No WILLOW_ENVELOPE_REGISTRY at all (the common case -- most installs
    never configure envelope governance): dispatch_send is unaffected,
    exactly like before #333."""
    _write_manifest(home, "loki")
    monkeypatch.delenv("WILLOW_ENVELOPE_REGISTRY", raising=False)
    monkeypatch.delenv("WILLOW_SYSCALL_TABLE", raising=False)

    result = server.dispatch_send("loki", "hanuman", "# One\n")

    assert "error" not in result
    assert "dispatch_id" in result


def test_non_enveloped_verb_dispatch_read_is_unaffected(home, monkeypatch, tmp_path):
    """dispatch_read carries no verb-level gate at all (VERB_LEVEL_ENFORCED_VERBS
    only names "dispatch" -> dispatch_send) -- reading a packet must never
    touch Postgres or the envelope registry, even when the sender's own
    dispatch_send call was governed and needed Postgres to cite."""
    _write_manifest(home, "loki")
    _set_charter(monkeypatch, tmp_path, maximum=1)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)
    sent = server.dispatch_send("loki", "hanuman", "# One\n")
    assert "error" not in sent

    monkeypatch.setattr(server, "get_pg", lambda: (_ for _ in ()).throw(
        AssertionError("get_pg should not be called by dispatch_read")
    ))
    result = server.dispatch_read("loki", sent["dispatch_id"])

    assert result.get("error") is None


# ── envelope_apply becomes advisory-only for verb-level-enforced verbs ──────

def test_envelope_apply_is_advisory_only_for_verb_level_enforced_verb(home, monkeypatch, tmp_path):
    """Calling envelope_apply for verb="dispatch" (now handled by
    dispatch_send's own gate) must NOT write a citation of its own -- doing
    so would double-charge the grant's quota for one real act. It still
    reports whether the grant WOULD be honored (a preflight check), just
    without the side effect."""
    _write_manifest(home, "loki", permissions=["orchestrator"])
    _set_charter(monkeypatch, tmp_path, maximum=1)
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    result = server.envelope_apply(
        "loki", "env-dispatch-1", "dispatch",
        {"to_agents": "hanuman", "task_class": "hanuman"},
        project="willow", session="s1",
    )

    assert result["ok"] is True
    assert result["cited_before_act"] is False
    assert result["citation_id"] is None
    assert pg.rows == []  # no citation written


def test_envelope_apply_still_cites_for_verbs_without_a_handler_side_gate(home, monkeypatch, tmp_path):
    """Sanity: the advisory carve-out is narrow -- any verb NOT in
    VERB_LEVEL_ENFORCED_VERBS keeps envelope_apply's original check+cite
    behavior unchanged."""
    _write_manifest(home, "loki", permissions=["orchestrator"])
    registry = {
        "active": [{
            "id": "env-store-1", "verb_id": 10, "verb": "store.write", "grantee": "loki",
            "bounds": {}, "issued_by": "root", "issued_at": "2026-01-01",
            "expires_at": "2027-01-01", "max_count": None,
            "use_count_source": "frank", "status": "active",
        }]
    }
    table = {"verbs": [{"id": 10, "verb": "store.write", "bounds": {}}]}
    registry_path = tmp_path / "pre-approved.json"
    syscall_path = tmp_path / "syscall-table.json"
    tmp_path.chmod(0o700)
    registry_path.write_text(json.dumps(registry))
    syscall_path.write_text(json.dumps(table))
    registry_path.chmod(0o600)
    syscall_path.chmod(0o600)
    monkeypatch.setenv("WILLOW_ENVELOPE_REGISTRY", str(registry_path))
    monkeypatch.setenv("WILLOW_SYSCALL_TABLE", str(syscall_path))
    pg = _FakeGovernancePg()
    monkeypatch.setattr(server, "get_pg", lambda: pg)

    result = server.envelope_apply(
        "loki", "env-store-1", "store.write", {}, project="willow", session="s1",
    )

    assert result["ok"] is True
    assert result["cited_before_act"] is True
    assert len(_citations(pg, "env-store-1")) == 1
