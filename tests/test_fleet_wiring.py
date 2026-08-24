"""The seams other fleet packages attach to — asserted from this side.

`jeles` is a declared dependency of this package and `nestor` mirrors its
ledger into FRANK, so both reach in through surfaces this repo owns: the gate's
manifest ACL and the governance schema. Each of those was broken in a way that
read as fine from here — the librarian seat had no `gap_write`, and the FRANK
tools queried a table this repo never defined — because nothing on this side
had a reason to notice.

`scripts/fleet_seams.py` checks the same seams live, against real checkouts of
all three. These are the half that can run in CI with neither installed.
"""

import json
import re
from pathlib import Path

from willow_mcp import gate, home_init, paths, registry

REPO = Path(__file__).resolve().parents[1]


def _bundle_registry() -> dict:
    return json.loads(
        (REPO / "src" / "willow_mcp" / "bundle" / "config" / "specialists.json")
        .read_text(encoding="utf-8"))


def _row(agent_id: str) -> dict:
    for row in _bundle_registry()["specialists"]:
        if row["agent_id"] == agent_id:
            return row
    raise AssertionError(f"no {agent_id} row in the seeded registry")


# ── the jeles seat can record what the fleet could not answer ────────────────

def test_librarian_seat_carries_gap_write():
    """`jeles.willow_mcp_client.forward_gap` calls `gap_log` as this seat. It
    is the package's own documented seam into this one, and without gap_write
    the gate denies it."""
    assert "gap_write" in _row("jeles")["permissions"]
    assert "gap_read" in _row("jeles")["permissions"]


def test_librarian_seat_cannot_promote_or_purge_gaps():
    """Filling the backlog is not the same authority as answering out of it.
    gap_promote lands a gap as trusted knowledge and gap_purge_topic clears a
    fleet-shared topic; neither belongs to a retrieval seat."""
    perms = _row("jeles")["permissions"]
    assert "gap_promote" not in perms
    assert "gap_purge" not in perms


def test_role_envelope_and_registry_agree_for_the_librarian():
    """Two files describe the same grant — `_DEFAULT_ENVELOPES` (per role) and
    the seeded registry (per agent). They drifted silently before."""
    envelope = home_init._DEFAULT_ENVELOPES["roles"]["librarian"]["allow_groups"]
    assert set(envelope) == set(_row("jeles")["permissions"])


def test_compiled_jeles_manifest_permits_gap_log(home):
    home_init.ensure_home_layout()
    registry.compile_manifests()
    manifest = json.loads(
        (paths.mcp_app_dir("jeles") / "manifest.json").read_text(encoding="utf-8"))
    assert "gap_write" in manifest["permissions"]
    # Through the gate itself, not just the file: the grant is only real if the
    # thing that enforces it agrees.
    assert gate.permitted("jeles", "gap_log")
    assert not gate.permitted("jeles", "gap_promote")


def test_roles_doc_lists_the_grant():
    """docs/ROLES.md is the user-facing copy of the same table, and a grant
    that is real in code and absent from the docs is how an operator ends up
    debugging a denial that isn't happening."""
    row = [line for line in (REPO / "docs" / "ROLES.md").read_text(encoding="utf-8").splitlines()
           if "| RESEARCH |" in line]
    assert row, "no RESEARCH row in docs/ROLES.md"
    assert "gap_write" in row[0]


# ── FRANK has a table on a fresh install ────────────────────────────────────

FRANK_DDL = REPO / "docs" / "schema" / "frank_ledger.postgres.sql"


def test_frank_ledger_ddl_ships_with_the_repo():
    """`frank_append`/`frank_read`/`frank_verify` and every envelope citation
    query `frank_ledger`. The table used to be defined only in willow-2.0's
    governance schema, so a fresh sandbox-bootstrap produced a server whose
    FRANK tools failed on a missing relation with nothing here to apply."""
    assert FRANK_DDL.is_file()


def test_frank_ledger_ddl_is_picked_up_by_the_bootstrap_glob():
    """sandbox-bootstrap.sh applies docs/schema/*.postgres.sql. A DDL file that
    misses the suffix is a file nothing runs."""
    assert FRANK_DDL.name.endswith(".postgres.sql")
    assert FRANK_DDL in set((REPO / "docs" / "schema").glob("*.postgres.sql"))


def test_frank_ledger_ddl_defines_every_column_the_code_uses():
    """Derived from the queries, not from memory: governance_ledger.py inserts
    these seven and server.py selects them back."""
    ddl = FRANK_DDL.read_text(encoding="utf-8")
    create = re.search(r"CREATE TABLE IF NOT EXISTS frank_ledger\s*\((.*?)\);", ddl, re.S)
    assert create, "no frank_ledger CREATE TABLE in the DDL"
    body = create.group(1)
    for column in ("id", "project", "event_type", "content", "prev_hash", "hash", "created_at"):
        assert re.search(rf"^\s*{column}\s+\w", body, re.M), f"{column} missing from frank_ledger"
    # append_citation meters grants with `content->>'envelope_id'`, which only
    # jsonb can answer.
    assert re.search(r"^\s*content\s+jsonb", body, re.M)


def test_frank_ledger_ddl_is_fork_proof_from_the_first_row():
    """The no-fork index is what makes the chain single-headed. It also ships
    as a standalone migration; both are IF NOT EXISTS, so applying either or
    both converges."""
    ddl = FRANK_DDL.read_text(encoding="utf-8")
    assert "frank_ledger_no_fork" in ddl
    assert "WHERE prev_hash IS NOT NULL" in ddl


# ── the fleet scripts stay runnable ─────────────────────────────────────────

def test_fleet_scripts_are_executable_and_present():
    for name in ("fleet-standup.sh", "fleet_seams.py"):
        script = REPO / "scripts" / name
        assert script.is_file(), f"scripts/{name} is missing"
        assert script.stat().st_mode & 0o111, f"scripts/{name} is not executable"


def test_fleet_standup_does_not_export_a_fleet_wide_app_id():
    """WILLOW_APP_ID is client-scoped. Exporting one value into a shared env
    re-seats every package that falls back to it — it re-seated nestor's FRANK
    mirror as the orchestrator, which this server refuses outright."""
    script = (REPO / "scripts" / "fleet-standup.sh").read_text(encoding="utf-8")
    exported = re.findall(r'^\s*echo "export (\w+)=', script, re.M)
    assert "WILLOW_APP_ID" not in exported
    assert "WILLOW_STORE_ROOT" in exported
    assert "JELES_CORPUS_APP_ID" in exported


# ── the CI job that runs the live seam check ────────────────────────────────

_TESTS_WF = REPO / ".github" / "workflows" / "tests.yml"


def _workflow() -> dict:
    import pytest
    yaml = pytest.importorskip("yaml", reason="PyYAML needed to read the workflows")
    return yaml.safe_load(_TESTS_WF.read_text(encoding="utf-8"))


def test_fleet_seams_job_exists_and_checks_out_both_siblings():
    job = _workflow()["jobs"]["fleet-seams"]
    repos = {s.get("with", {}).get("repository")
             for s in job["steps"] if s.get("uses", "").startswith("actions/checkout")}
    assert "hornbook-knowledge/Jeles" in repos
    assert "Die-Namic-Systems/Nestor" in repos


def test_fleet_seams_checks_out_full_history():
    """hatch-vcs takes the version from the tags, so a shallow checkout builds
    jeles as 0.1.devN — which does not satisfy this package's own
    `jeles>=0.5.1`. The co-install seam then fails with what reads as a bad
    pin. Every checkout in this job must be unshallow."""
    job = _workflow()["jobs"]["fleet-seams"]
    for step in job["steps"]:
        if step.get("uses", "").startswith("actions/checkout"):
            assert step.get("with", {}).get("fetch-depth") == 0, \
                f"shallow checkout in {step.get('name', 'checkout')}"


def test_fleet_seams_provides_postgres():
    """Without it the FRANK seam reports SKIP, and a job of SKIPs is not a
    job that checked anything."""
    assert "postgres" in _workflow()["jobs"]["fleet-seams"]["services"]


def test_fleet_seams_runs_the_script_users_run():
    """Not a re-implementation of the stand-up. A stand-up guarded by a
    different code path than the documented one is a stand-up nobody checked."""
    runs = " ".join(s.get("run", "") for s in _workflow()["jobs"]["fleet-seams"]["steps"])
    assert "scripts/fleet-standup.sh" in runs
    assert "scripts/fleet_seams.py" in runs


def test_fleet_seams_does_not_gate_the_merge():
    """Same posture as vendor-sync, for the same reason: the sibling checkouts
    may be unreachable (private, no token), and a job that soft-skips must
    never block a merge. The soft part is the checkout only."""
    jobs = _workflow()["jobs"]
    assert "fleet-seams" not in jobs["test"]["needs"]
    for step in jobs["fleet-seams"]["steps"]:
        if step.get("with", {}).get("repository", "").endswith(("/Jeles", "/Nestor")):
            assert step.get("continue-on-error") is True, \
                "a sibling checkout must be soft — it is the only soft part"


def test_fleet_seams_fails_when_a_seam_skips_on_a_provisioned_runner():
    """SKIP is right when a half is genuinely absent. On this runner nothing is
    absent, so a SKIP is an environment regression — and `quiet reads as fine`
    is the failure the `test` gate below was written to end."""
    steps = _workflow()["jobs"]["fleet-seams"]["steps"]
    guard = [s for s in steps if "SKIP" in (s.get("name") or "")]
    assert guard, "no step asserts that nothing skipped"
    assert "--json" in guard[0]["run"]
    # It must only speak when both siblings actually landed, or it would fail
    # every run on a fork with no token.
    assert "steps.jeles.outcome" in guard[0]["if"]
    assert "steps.nestor.outcome" in guard[0]["if"]
