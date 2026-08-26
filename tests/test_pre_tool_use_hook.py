"""Tests for hooks/pre_tool_use.py's check_bash() — the pure decision logic
behind the PreToolUse hook. Not part of the willow_mcp package (hooks/ is a
sibling directory, not installed with the package), so it's imported by
path rather than via the normal package import.
"""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "pre_tool_use.py"
_spec = importlib.util.spec_from_file_location("pre_tool_use", _HOOK_PATH)
pre_tool_use = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pre_tool_use)


@pytest.fixture(autouse=True)
def _non_orchestrator_seat(monkeypatch):
    """Default every in-process test to the ordinary (non-orchestrator) seat, so
    routing assertions are deterministic regardless of the ambient environment —
    the dev box both exports WILLOW_APP_ID=willow AND has a .mcp.json that
    declares the willow seat. Clear the env and neutralize the file signal by
    pointing _project_dir at nothing. Orchestrator tests opt back in explicitly."""
    monkeypatch.delenv("WILLOW_APP_ID", raising=False)
    monkeypatch.delenv("WILLOW_HUMAN_ORCHESTRATOR", raising=False)
    monkeypatch.setattr(pre_tool_use, "_project_dir", lambda: None)


# ── check_bash: blocked patterns ────────────────────────────────────────

@pytest.mark.parametrize("command", [
    'psql $WILLOW_PG_DB -c "select * from knowledge"',
    "sqlite3 $WILLOW_STORE_ROOT/col/store.db 'select * from records'",
    'python3 -c "import psycopg2; psycopg2.connect(dbname=\'willow\')" # WILLOW_PG_DB',
    "sqlite3 ~/.willow/mcp_receipt.db 'select * from receipts'",
])
def test_check_bash_blocks_owned_store_access(command):
    reason = pre_tool_use.check_bash(command)
    assert reason is not None
    assert "willow-mcp" in reason


def test_check_bash_names_knowledge_tools_for_knowledge_table():
    reason = pre_tool_use.check_bash('psql $WILLOW_PG_DB -c "select * from knowledge"')
    assert "knowledge_search" in reason


def test_check_bash_names_store_tools_for_records_table():
    reason = pre_tool_use.check_bash("sqlite3 $WILLOW_STORE_ROOT/col/store.db 'select * from records'")
    assert "store_get" in reason


def test_check_bash_blocks_on_willow_store_root_alone():
    """The other WILLOW_STORE_ROOT fixture (above) also contains the literal
    word 'records' — a second, independent _OWNED_MARKER_RE alternative — so
    it stays green even if the WILLOW_STORE_ROOT branch is deleted from the
    regex entirely (caught by tools/hook_mutation_check.py, which found this
    gap). Isolate the marker: no 'knowledge'/'records' word, and a filename
    that doesn't independently match the store.db/vault.db/kart.db/
    mcp_receipt.db alternative either."""
    reason = pre_tool_use.check_bash("sqlite3 $WILLOW_STORE_ROOT/data.db 'select 1'")
    assert reason is not None
    assert "willow-mcp" in reason


# ── check_bash: allowed patterns ────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "",
    "git status",
    "psql some_other_db -c 'select 1'",              # psql, but no willow-mcp marker
    "sqlite3 /tmp/unrelated.db 'select 1'",           # sqlite3, but no willow-mcp marker
    "grep -r knowledge src/",                          # 'knowledge' present, but no db client
    "python3 -m pytest tests/",                        # neither client nor marker
])
def test_check_bash_allows_unrelated_commands(command):
    assert pre_tool_use.check_bash(command) is None


# ── check_bash_remote_fail_closed (#164) ─────────────────────────────────

@pytest.fixture
def remote_gate_down(tmp_path, monkeypatch):
    wh = tmp_path / ".willow"
    enforcement = wh / "enforcement"
    enforcement.mkdir(parents=True)
    (enforcement / "remote_posture.json").write_text(
        json.dumps({"mcp_live": False}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDE_CODE_REMOTE", "true")
    monkeypatch.setenv("WILLOW_HOME", str(wh))
    return wh


def test_remote_fail_closed_blocks_bare_psql(remote_gate_down):
    reason = pre_tool_use.check_bash_remote_fail_closed("psql -c 'select 1'")
    assert reason is not None
    assert "remote enforcement" in reason


def test_remote_fail_closed_blocks_sqlite3_and_curl(remote_gate_down):
    assert pre_tool_use.check_bash_remote_fail_closed("sqlite3 /tmp/x.db '.tables'")
    assert pre_tool_use.check_bash_remote_fail_closed("curl -s https://example.com")


def test_remote_fail_closed_allows_when_gate_live(remote_gate_down):
    path = remote_gate_down / "enforcement" / "remote_posture.json"
    path.write_text(json.dumps({"mcp_live": True}), encoding="utf-8")
    assert pre_tool_use.check_bash_remote_fail_closed("psql -c 'select 1'") is None


def test_remote_fail_closed_inactive_without_ccr_flag(monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_REMOTE", raising=False)
    monkeypatch.setenv("WILLOW_HOME", "/tmp/.willow")
    assert pre_tool_use.check_bash_remote_fail_closed("psql -c 'select 1'") is None


def test_remote_fail_closed_without_marker_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CODE_REMOTE", "true")
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path / ".willow"))
    reason = pre_tool_use.check_bash_remote_fail_closed("curl https://example.com")
    assert reason is not None


# ── check_bash: the script-indirection path, allow side ─────────────────
#
# _script_reaches_owned_store() reads the invoked file and applies the same
# two-key test (raw DB client + owned-store marker) to its contents. The block
# side is what a bad-command suite exercises; these pin the *allow* side, which
# is where a broadened guard would start blocking ordinary scripts. Broadening
# the two-key test to `if True` — every readable invoked script blocks — left
# the suite green before these existed, so nothing checked that a benign
# `python3 x.py` survives.


@pytest.fixture
def script_dir(tmp_path, monkeypatch):
    """Run check_bash with cwd at tmp_path, so a relative script resolves."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.mark.parametrize("body, why", [
    ('print("hello")', "no DB client and no marker"),
    # One key each — the same discriminators test_check_bash_allows_unrelated_commands
    # applies to the command line, applied one file deeper.
    ("import sqlite3\nsqlite3.connect('/tmp/unrelated.db')\n", "DB client, no owned marker"),
    ('open("notes.md").read()  # records\n', "marker word, no DB client"),
])
def test_check_bash_allows_a_benign_invoked_script(script_dir, body, why):
    (script_dir / "helper.py").write_text(body)
    assert pre_tool_use.check_bash("python3 helper.py") is None, why


def test_check_bash_allows_a_benign_script_via_the_cd_form(script_dir):
    """The `cd X && python3 y.py` form the guard reads a cwd out of — a benign
    script reached that way is still ordinary work."""
    (script_dir / "tools").mkdir()
    (script_dir / "tools" / "report.py").write_text('print("report")\n')
    assert pre_tool_use.check_bash("cd tools && python3 report.py") is None


def test_check_bash_blocks_a_malicious_script_via_the_cd_form(script_dir):
    """The allow-side sibling above only ever pinned that a benign script
    survives the cd form — nothing pinned that the cd form's whole point (a
    script that DOES reach an owned store) is still caught through it, so a
    regex change that silently stopped resolving cwd for that form would pass
    every existing test (found by tools/hook_mutation_check.py)."""
    (script_dir / "tools").mkdir()
    (script_dir / "tools" / "drop.py").write_text(
        "import sqlite3, os\n"
        "sqlite3.connect(os.environ['WILLOW_STORE_ROOT'] + '/records/store.db')\n"
    )
    reason = pre_tool_use.check_bash("cd tools && python3 drop.py")
    assert reason is not None
    assert "willow-mcp" in reason


def test_check_bash_fails_open_on_an_unreadable_script(script_dir):
    """Tripwire, not a control: a script it cannot read is not a block. Named so
    a future change that makes the guard fail *closed* is a deliberate choice
    with a red test behind it, not a silent one."""
    assert pre_tool_use.check_bash("python3 does_not_exist.py") is None


# ── check_bash: the repo's own scripts/ tree is exempt ───────────────────
#
# Found live (2026-07-31): scripts/sandbox-bootstrap.sh — the README's
# documented one-command setup — trips this guard when run through Bash,
# because it legitimately creates the Postgres database and applies schema
# before any MCP tool exists to call instead. A scan of scripts/ found 16
# other files in the same position (diagnostics/ratification/reconstruction
# tooling). A script already committed under scripts/ went through the same
# review this hook file did; that is a different trust class from an agent
# writing a new script in the working tree, which is what this guard exists
# to catch.

def test_check_bash_allows_a_reviewed_script_under_scripts_dir(script_dir):
    (script_dir / "scripts").mkdir()
    (script_dir / "scripts" / "bootstrap.sh").write_text(
        "psql -U someone -d $WILLOW_PG_DB -c 'select 1'\n"
    )
    assert pre_tool_use.check_bash("bash scripts/bootstrap.sh") is None


def test_check_bash_allows_a_reviewed_script_in_a_scripts_subdir(script_dir):
    (script_dir / "scripts" / "diagnostics").mkdir(parents=True)
    (script_dir / "scripts" / "diagnostics" / "stats.py").write_text(
        "import sqlite3\nsqlite3.connect('WILLOW_STORE_ROOT')\n"
    )
    assert pre_tool_use.check_bash("python3 scripts/diagnostics/stats.py") is None


def test_check_bash_still_blocks_outside_scripts_dir(script_dir):
    """The exemption is scripts/ specifically, not a blanket loosening — a file
    that merely has 'scripts' as a substring of its own directory name
    ('myscripts/') must not ride the exemption."""
    (script_dir / "myscripts").mkdir()
    (script_dir / "myscripts" / "drop.sh").write_text(
        "psql -U someone -d $WILLOW_PG_DB -c 'select 1'\n"
    )
    reason = pre_tool_use.check_bash("bash myscripts/drop.sh")
    assert reason is not None
    assert "willow-mcp" in reason


def test_check_bash_allows_the_real_sandbox_bootstrap_script():
    """End to end, against the actual file this bug was found on — not a
    fixture standing in for it. Runs from the repo root (pytest's normal
    cwd), the same way a live Claude Code session invoking the README's
    documented setup command would."""
    assert pre_tool_use.check_bash("bash scripts/sandbox-bootstrap.sh") is None


def test_check_bash_allows_a_two_level_script_chain(script_dir):
    """The guard reads one level of indirection, deliberately, not two. A
    script whose own body merely shells out to a *second* script that reaches
    an owned store is not caught — helper.py itself has no DB-use token, only
    worker.py does, and worker.py is never the invoked file on the command
    line. See hooks/pre_tool_use.py's comment above _SCRIPT_INVOKE_RE and
    docs/design/hooks-and-skills.md's 2026-07-31 addendum for why this is the
    intended stopping point, not an oversight."""
    (script_dir / "worker.py").write_text(
        "import sqlite3, os\n"
        "sqlite3.connect(os.environ['WILLOW_STORE_ROOT'] + '/records/store.db')\n"
    )
    (script_dir / "helper.py").write_text(
        "import subprocess\n"
        "subprocess.run(['python3', 'worker.py'])\n"
    )
    assert pre_tool_use.check_bash("python3 helper.py") is None
    # Confirm worker.py would have tripped it, had it been the invoked file —
    # otherwise this test would pass for the wrong reason (a broken fixture).
    assert pre_tool_use.check_bash("python3 worker.py") is not None


# ── main(): stdin/stdout contract ───────────────────────────────────────

_SEAT_ENV_KEYS = ("WILLOW_APP_ID", "WILLOW_HUMAN_ORCHESTRATOR", "CLAUDE_PROJECT_DIR")


def _run_hook(payload: dict, env: dict | None = None) -> tuple[int, str]:
    """Run the hook as a subprocess. Strips the seat-determining vars from the
    inherited env so the default is the ordinary seat regardless of where the
    suite runs (the dev box sets CLAUDE_PROJECT_DIR at a repo whose .mcp.json
    declares the willow seat); orchestrator tests pass `env` to opt in."""
    base = {k: v for k, v in os.environ.items() if k not in _SEAT_ENV_KEYS}
    if env:
        base.update(env)
    proc = subprocess.run(
        [sys.executable, str(_HOOK_PATH)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=base,
    )
    return proc.returncode, proc.stdout.strip()


def test_main_blocks_and_exits_zero():
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": 'psql $WILLOW_PG_DB -c "select * from knowledge"'},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "block"
    assert "willow-mcp" in decision["reason"]


def test_main_silent_and_exits_zero_when_allowed():
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "session_id": "s1",
    })
    assert code == 0
    assert stdout == ""


def test_main_ignores_non_bash_tools():
    code, stdout = _run_hook({
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/hosts"},
        "session_id": "s1",
    })
    assert code == 0
    assert stdout == ""


# ── check_task_submit: warns on embedded net directives ─────────────────

@pytest.mark.parametrize("task", [
    "echo hi\n# allow_net",
    "curl https://x\n  # allow_net  ",          # worker strips().== matches, so must we
    "echo hi\n# allow_localhost",
    "a\n# allow_net\nb\n# allow_localhost",
])
def test_check_task_submit_warns_on_embedded_directive(task):
    reason = pre_tool_use.check_task_submit({"task": task})
    assert reason is not None
    assert "task_net" in reason


@pytest.mark.parametrize("task", [
    "echo hi",
    "curl https://example.com",
    "python3 -c 'print(1)  # allow_net in a comment, not its own line'",  # not a bare directive line
    "",
])
def test_check_task_submit_allows_clean_tasks(task):
    assert pre_tool_use.check_task_submit({"task": task}) is None


def test_check_task_submit_handles_missing_task_key():
    assert pre_tool_use.check_task_submit({}) is None


def test_is_task_submit_matches_bare_and_mcp_qualified():
    assert pre_tool_use._is_task_submit("task_submit")
    assert pre_tool_use._is_task_submit("mcp__willow-mcp__task_submit")
    assert pre_tool_use._is_task_submit("mcp__willow-mcp-serve__task_submit")
    assert not pre_tool_use._is_task_submit("task_status")
    assert not pre_tool_use._is_task_submit("Bash")


def test_main_warns_on_task_submit_with_directive():
    code, stdout = _run_hook({
        "tool_name": "mcp__willow-mcp__task_submit",
        "tool_input": {"app_id": "x", "task": "echo hi\n# allow_net"},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "warn"
    assert "task_net" in decision["reason"]


def test_main_silent_on_clean_task_submit():
    code, stdout = _run_hook({
        "tool_name": "mcp__willow-mcp__task_submit",
        "tool_input": {"app_id": "x", "task": "echo hi"},
        "session_id": "s1",
    })
    assert code == 0
    assert stdout == ""


# ── self-grant guard: an agent may request egress, never confirm it ──────

@pytest.mark.parametrize("command", [
    "willow-mcp grant-net willow --ttl 30m",
    "willow-mcp dev-net willow --ttl 30m",
    ".venv/bin/python -m willow_mcp dev-net willow --ttl 1h --reason local",
    "willow-mcp sign-net-task willow --task 'git push' --key /operator/key.pem",
    ".venv/bin/python -m willow_mcp grant-net willow --ttl 1h --reason push",
    'python -c "from willow_mcp import lease; lease.grant(\'willow\', 60, issuer=\'me\')"',
    "willow-mcp consent set internet true",
    "willow-mcp consent reconcile",
    "willow-mcp roster sync",
    "willow-mcp register-agent evil --max-trust 4",
    "willow-mcp revoke-agent op",
    "willow-mcp rotate-agent op",
    'python -c "from willow_mcp import consent_admin; consent_admin.set_key(\'internet\', True)"',
    'python -c "from willow_mcp.egress_authorization import sign_envelope; sign_envelope()"',
    'python -c "from willow_mcp import agent_registry; agent_registry.register_agent(\'evil\', 4)"',
    "echo '{}' > ~/.willow/mcp_apps/_net_leases/willow.json",
    "tee $WILLOW_HOME/mcp_apps/_net_leases/willow.json <<< '{}'",
    "sed -i 's/store_read/task_net/' ~/.willow/mcp_apps/willow/manifest.json",
    'jq \'.permissions += ["task_net"]\' m.json > ~/.willow/mcp_apps/willow/manifest.json',
])
def test_check_bash_self_grant_blocks_minting_egress_keys(command):
    reason = pre_tool_use.check_bash_self_grant(command)
    assert reason is not None
    assert "REQUEST egress" in reason


@pytest.mark.parametrize("command", [
    "",
    "willow-mcp net-status",              # reading is not minting
    "willow-mcp revoke-net willow",       # giving up a key is never escalation
    "willow-mcp worker --once",
    "cat ~/.willow/mcp_apps/willow/manifest.json",          # reading a manifest is fine
    "cat $WILLOW_HOME/mcp_apps/_net_leases/willow.json",    # so is reading a lease
    "ls ~/.willow/mcp_apps/_net_leases/",
    'echo "store_read" > ~/.willow/mcp_apps/willow/manifest.json',  # not the egress key
])
def test_check_bash_self_grant_allows_everything_else(command):
    assert pre_tool_use.check_bash_self_grant(command) is None


# ── keystore guard: an app may request standing, never write its own secret ──────

@pytest.mark.parametrize("command", [
    "echo deadbeef > $WILLOW_HOME/gate/secrets/evil.key",
    "tee ~/.willow/gate/secrets/op.key <<< 'x'",
    'jq \'.evil = {"max_trust": 4}\' r.json > ~/.willow/gate/registry.json',
])
def test_check_bash_self_grant_blocks_keystore_writes(command):
    reason = pre_tool_use.check_bash_self_grant(command)
    assert reason is not None
    assert "keystore" in reason and "REQUEST standing" in reason


@pytest.mark.parametrize("command", [
    "cat $WILLOW_HOME/gate/registry.json",              # reading the registry is fine
    "cat ~/.willow/gate/secrets/op.key",                # reading a secret is not minting
    "ls ~/.willow/gate/secrets/",
])
def test_check_bash_self_grant_allows_keystore_reads(command):
    assert pre_tool_use.check_bash_self_grant(command) is None


def test_check_trust_root_write_blocks_a_secret_file():
    reason = pre_tool_use.check_trust_root_write(
        {"file_path": "/home/x/.willow/gate/secrets/evil.key", "content": "deadbeef"})
    assert reason is not None and "keystore" in reason


def test_check_trust_root_write_blocks_a_lease_file():
    reason = pre_tool_use.check_trust_root_write(
        {"file_path": "/home/x/.willow/mcp_apps/_net_leases/willow.json",
         "content": '{"app_id": "willow"}'})
    assert reason is not None
    assert "B-32" in reason


def test_check_trust_root_write_blocks_task_net_into_a_manifest():
    reason = pre_tool_use.check_trust_root_write(
        {"file_path": "/home/x/.willow/mcp_apps/willow/manifest.json",
         "content": '{"permissions": ["task_queue", "task_net"]}'})
    assert reason is not None


def test_check_trust_root_write_allows_an_unrelated_manifest_edit():
    """Editing a manifest is ordinary work. Only the permission that carries
    egress is the agent's to ask for rather than take."""
    assert pre_tool_use.check_trust_root_write(
        {"file_path": "/home/x/.willow/mcp_apps/willow/manifest.json",
         "content": '{"permissions": ["store_read", "knowledge_read"]}'}) is None


def test_check_trust_root_write_allows_ordinary_files():
    for path in ("", "/home/x/src/server.py", "/home/x/.willow/store/col/store.db"):
        assert pre_tool_use.check_trust_root_write({"file_path": path}) is None


# ── check_owned_db_file_write (item B, 2026-07-31): the non-Bash path ────────
#
# check_bash's raw-client scan only sees a command/script that *invokes a DB
# client* against an owned marker. A Write/Edit tool that overwrites the
# store file's bytes directly invokes no client at all — same crossing, one
# tool over, previously unguarded (deliberately deferred in
# docs/design/hooks-and-skills.md §4 until a concrete case showed up).

@pytest.mark.parametrize("path", [
    "/home/x/.willow/store/store.db",
    "/home/x/.willow/vault.db",
    "kart.db",
    "/home/x/.willow/mcp_receipt.db",
])
def test_check_owned_db_file_write_blocks_the_exact_store_files(path):
    reason = pre_tool_use.check_owned_db_file_write({"file_path": path})
    assert reason is not None
    assert "non-Bash" in reason


@pytest.mark.parametrize("path", [
    "",
    "/home/x/src/server.py",
    "/home/x/.willow/store/col/restore.db",   # "store.db" substring, not the file
    "/home/x/backups/backup_store.db",         # same substring trap, other side
    "/home/x/.willow/store.db.bak",            # a backup copy, not the live file
    "docs/schema/store.postgres.sql",
])
def test_check_owned_db_file_write_allows_unrelated_paths(path):
    assert pre_tool_use.check_owned_db_file_write({"file_path": path}) is None


def test_main_blocks_a_write_targeting_the_store_db_file():
    code, stdout = _run_hook({
        "tool_name": "Write",
        "tool_input": {"file_path": "/home/x/.willow/store/store.db", "content": "junk"},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "block"
    assert "non-Bash" in decision["reason"]


def test_main_allows_an_edit_to_an_ordinary_file():
    code, stdout = _run_hook({
        "tool_name": "Edit",
        "tool_input": {"file_path": "/home/x/src/server.py", "old_string": "a", "new_string": "b"},
        "session_id": "s1",
    })
    assert code == 0
    assert stdout == ""


def test_check_trust_root_write_reads_edit_shaped_input():
    reason = pre_tool_use.check_trust_root_write(
        {"file_path": "/home/x/.willow/mcp_apps/willow/manifest.json",
         "new_string": '"permissions": ["full_access", "task_net"]'})
    assert reason is not None


def test_main_blocks_a_write_that_mints_a_lease():
    code, stdout = _run_hook({
        "tool_name": "Write",
        "tool_input": {"file_path": "/home/x/.willow/mcp_apps/_net_leases/willow.json",
                       "content": "{}"},
        "session_id": "s1",
    })
    assert code == 0
    assert json.loads(stdout)["decision"] == "block"


def test_main_blocks_a_bash_grant_net():
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": "willow-mcp grant-net willow --ttl 3h"},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "block"
    assert "grant-net" in decision["reason"]


def test_check_task_submit_self_grant_blocks_grant_net_in_task_text():
    """Kart task text is shell. The sandbox stops this today via B-14's bound_ro
    mount, but a guard that only works because of a mount option elsewhere is not
    a guard."""
    reason = pre_tool_use.check_task_submit_self_grant(
        {"task": "willow-mcp grant-net willow --ttl 3h"})
    assert reason is not None


def test_check_task_submit_self_grant_allows_ordinary_tasks():
    for task in ("", "echo hi", "git status", "willow-mcp net-status"):
        assert pre_tool_use.check_task_submit_self_grant({"task": task}) is None


def test_main_blocks_a_task_submit_that_smuggles_grant_net():
    code, stdout = _run_hook({
        "tool_name": "mcp__willow-mcp__task_submit",
        "tool_input": {"app_id": "x", "task": "willow-mcp grant-net x --ttl 1h"},
        "session_id": "s1",
    })
    assert code == 0
    assert json.loads(stdout)["decision"] == "block"


def test_main_still_warns_on_directive_when_not_self_granting():
    """The block must not swallow the softer B-21 warning for ordinary tasks."""
    code, stdout = _run_hook({
        "tool_name": "mcp__willow-mcp__task_submit",
        "tool_input": {"app_id": "x", "task": "curl https://x\n# allow_net"},
        "session_id": "s1",
    })
    assert json.loads(stdout)["decision"] == "warn"


def test_main_silent_on_an_ordinary_write():
    code, stdout = _run_hook({
        "tool_name": "Write",
        "tool_input": {"file_path": "/home/x/src/thing.py", "content": "x = 1"},
        "session_id": "s1",
    })
    assert code == 0
    assert stdout == ""


def test_main_handles_empty_and_malformed_stdin_without_crashing():
    for raw in ("", "not json", "{}"):
        proc = subprocess.run(
            [sys.executable, str(_HOOK_PATH)],
            input=raw,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == ""


# ── check_bash_routing: MCP redirect table ─────────────────────────────

# Only the `gh` case actually pins the inspect exemption. `git status` and
# `git log` are allowed for two independent reasons — the exemption's early
# return, and the fact that no _BASH_ROUTING entry matches a bare git inspect
# verb anyway — so deleting the exemption's git half leaves them green. Verified
# by narrowing _GIT_INSPECT_RE (nothing red) and _GH_INSPECT_RE (red here).
# Keep the gh parameter: it is the one carrying the assertion.
@pytest.mark.parametrize("command", [
    "git status",
    "git log -3 --oneline",
    "gh pr view 120",
])
def test_check_bash_routing_allows_git_gh_inspect(command):
    assert pre_tool_use.check_bash_routing(command) is None


@pytest.mark.parametrize("command, decision", [
    ("ls -la src/", "warn"),
    ("git commit -m 'x'", "block"),
    ("gh pr create --title t", "block"),
    ("psql mydb -c 'select 1'", "block"),
])
def test_check_bash_routing_redirects(command, decision):
    routed = pre_tool_use.check_bash_routing(command)
    assert routed is not None
    assert routed[0] == decision
    assert "willow-mcp" in routed[1]


def test_main_warns_on_ls():
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la"},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "warn"
    assert "store_list" in decision["reason"]


# ── check_bash_routing: Kart redirects (network / background / filesystem) ──

@pytest.mark.parametrize("command, decision", [
    ("curl https://example.com/data.json", "block"),
    ("wget https://example.com/file", "block"),
    ("pip install requests", "block"),
    ("pip3 install requests", "block"),
    ("npm install lodash", "block"),
    ("npm i lodash", "block"),
    ("yarn add lodash", "block"),
    ("poetry add requests", "block"),
    ("uv add requests", "block"),
    ("uv pip install requests", "block"),
    ("ssh user@host 'uptime'", "block"),
    ("scp file.txt user@host:/tmp", "block"),
    ("sleep 300 &", "warn"),
    ("nohup python3 server.py &", "warn"),
    ("setsid ./daemon.sh", "warn"),
    ("some_job; disown", "warn"),
    ("screen -dm ./worker.sh", "warn"),
    ("tmux new-session -d -s work './run.sh'", "warn"),
    ("python3 migrate.py", "warn"),
    ("node build.js", "warn"),
    ("make build", "warn"),
    ("mkdir -p out/reports", "warn"),
    ("rm -rf build/", "warn"),
    ("mv old.txt new.txt", "warn"),
    ("cp a.txt b.txt", "warn"),
    ("chmod +x run.sh", "warn"),
    ("chown user:group file.txt", "warn"),
    ("tar xzf archive.tar.gz", "warn"),
])
def test_check_bash_routing_kart_redirects(command, decision):
    routed = pre_tool_use.check_bash_routing(command)
    assert routed is not None
    assert routed[0] == decision
    assert "willow-mcp" in routed[1]


# Allow-side: a block-only suite for these patterns couldn't tell "this guard
# fires correctly" from "this guard fires on everything" — the exact gap the
# allow-side pass over check_bash's guards closed. Pin known-good commands
# that share a token with a blocked pattern but aren't the crossing.
@pytest.mark.parametrize("command", [
    "",
    "git status",
    "echo 'curl and wget and rm are just words in this string'",
    "npm init",            # 'i' without trailing space — not npm install
    "npm info lodash",
    "npm run build",
    "npm test",
    "rsync -a src/ dst/",             # no remote host — not ssh/scp
    "echo a && echo b",               # '&&' is chaining, not a trailing '&'
    "python3 -m pytest tests/",       # module invocation, no script file arg
    "python3 -c 'print(1)'",          # inline, no script file
    "make.py",                        # not the `make` build tool
])
def test_check_bash_routing_kart_redirects_allow_side(command):
    assert pre_tool_use.check_bash_routing(command) is None


def test_check_bash_routing_git_mutation_wins_over_a_prose_nohup_mention():
    # 'nohup' appears in the -m message, not as an invocation; git mutation
    # is still the correct (and only) match.
    routed = pre_tool_use.check_bash_routing(
        "git commit -m 'background the deploy with nohup later'")
    assert routed is not None and routed[0] == "block"
    assert "git mutation" in routed[1]


# ── orchestrator seat: git/gh routing is lifted, the security guards are not ──

def test_is_orchestrator_seat_reads_env(monkeypatch):
    monkeypatch.setenv("WILLOW_APP_ID", "willow")
    assert pre_tool_use._is_orchestrator_seat()
    monkeypatch.setenv("WILLOW_APP_ID", "WILLOW")   # case-insensitive
    assert pre_tool_use._is_orchestrator_seat()
    monkeypatch.setenv("WILLOW_APP_ID", "ada")      # a specialist seat is not exempt
    assert not pre_tool_use._is_orchestrator_seat()
    monkeypatch.delenv("WILLOW_APP_ID", raising=False)
    assert not pre_tool_use._is_orchestrator_seat()
    monkeypatch.setenv("WILLOW_HUMAN_ORCHESTRATOR", "1")
    assert pre_tool_use._is_orchestrator_seat()


def _write_mcp_json(dir_path: Path, env: dict) -> None:
    (dir_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"willow-mcp": {"command": ".venv/bin/python3",
                                       "args": ["-m", "willow_mcp"], "env": env}}}))


def test_mcp_json_declares_orchestrator_from_file(tmp_path):
    """The production signal: no WILLOW_* env, seat read from .mcp.json."""
    _write_mcp_json(tmp_path, {"WILLOW_APP_ID": "willow", "WILLOW_HUMAN_ORCHESTRATOR": "1"})
    assert pre_tool_use._mcp_json_declares_orchestrator(str(tmp_path))

    _write_mcp_json(tmp_path, {"WILLOW_APP_ID": "ada"})   # a specialist project
    assert not pre_tool_use._mcp_json_declares_orchestrator(str(tmp_path))

    _write_mcp_json(tmp_path, {"WILLOW_HUMAN_ORCHESTRATOR": "1"})  # the flag alone
    assert pre_tool_use._mcp_json_declares_orchestrator(str(tmp_path))


def test_mcp_json_declares_orchestrator_fail_safe(tmp_path):
    """A missing or malformed .mcp.json is not the orchestrator (git stays routed)."""
    assert not pre_tool_use._mcp_json_declares_orchestrator(str(tmp_path))  # no file
    (tmp_path / ".mcp.json").write_text("{ not json")
    assert not pre_tool_use._mcp_json_declares_orchestrator(str(tmp_path))
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": "oops"}))
    assert not pre_tool_use._mcp_json_declares_orchestrator(str(tmp_path))


def test_is_orchestrator_seat_reads_mcp_json_when_env_absent(tmp_path, monkeypatch):
    """With no WILLOW_* env (the real hook environment), the seat comes from the
    project's .mcp.json via CLAUDE_PROJECT_DIR."""
    _write_mcp_json(tmp_path, {"WILLOW_APP_ID": "willow", "WILLOW_HUMAN_ORCHESTRATOR": "1"})
    monkeypatch.setattr(pre_tool_use, "_project_dir", lambda: str(tmp_path))
    assert pre_tool_use._is_orchestrator_seat()
    assert pre_tool_use.check_bash_routing("git commit -m x") is None


@pytest.fixture
def orchestrator_seat(monkeypatch):
    monkeypatch.setenv("WILLOW_APP_ID", "willow")


@pytest.mark.parametrize("command", [
    "git commit -m 'x'",
    "git add -A",
    "git push -u origin my-branch",
    "git pull origin main",
    "gh pr create --title t",
])
def test_orchestrator_git_gh_mutations_allowed(orchestrator_seat, command):
    assert pre_tool_use.check_bash_routing(command) is None


@pytest.mark.parametrize("command, decision", [
    ("ls -la src/", "warn"),
    ("psql mydb -c 'select 1'", "block"),
    ("sqlite3 /tmp/x.db 'select 1'", "block"),
    ("curl https://example.com", "block"),
    ("pip install requests", "block"),
    ("rm -rf build/", "warn"),
])
def test_orchestrator_still_routed_off_non_git_habits(orchestrator_seat, command, decision):
    """The exemption is git/gh only — every other routing nudge still fires,
    including the Kart (network/background/filesystem) redirects added
    alongside it: the orchestrator seat's repo-maintenance carve-out doesn't
    extend to running raw curl or pip against the network."""
    routed = pre_tool_use.check_bash_routing(command)
    assert routed is not None and routed[0] == decision


def test_orchestrator_self_grant_guard_not_lifted(orchestrator_seat):
    """The seat exemption never touches the self-grant guard: an orchestrator
    still may not mint its own egress."""
    assert pre_tool_use.check_bash_self_grant(
        "willow-mcp grant-net willow --ttl 3h") is not None


def test_main_allows_orchestrator_commit():
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m 'ship it' && git push"},
        "session_id": "s1",
    }, env={"WILLOW_APP_ID": "willow"})
    assert code == 0
    assert stdout == ""


def test_main_blocks_orchestrator_grant_net():
    """Even from the orchestrator seat, minting egress is blocked — the self-grant
    guard runs before routing and is never lifted."""
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": "willow-mcp grant-net willow --ttl 3h"},
        "session_id": "s1",
    }, env={"WILLOW_APP_ID": "willow"})
    assert code == 0
    assert json.loads(stdout)["decision"] == "block"


def test_main_blocks_native_web_search():
    code, stdout = _run_hook({
        "tool_name": "WebSearch",
        "tool_input": {"search_term": "latest news"},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "block"
    assert "willow_web_search" in decision["reason"]


def test_check_native_web_blocks_webfetch():
    """WebSearch had test_main_blocks_native_web_search; WebFetch had no
    block-side test at all, so a bug narrowing check_native_web's WebFetch
    branch (e.g. a stray typo in the string comparison) would pass the whole
    suite (found by tools/hook_mutation_check.py)."""
    routed = pre_tool_use.check_native_web("WebFetch")
    assert routed is not None
    assert routed[0] == "block"
    assert "willow_web_fetch" in routed[1]


def test_main_blocks_native_web_fetch():
    code, stdout = _run_hook({
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://example.com"},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "block"
    assert "willow_web_fetch" in decision["reason"]


# ── check_native_web: allow side ────────────────────────────────────────
#
# The guard redirects the IDE-native web tools to willow_web_*. Its allow side
# is the sanctioned alternative itself: if the guard ever broadens to match on
# "web" rather than the two exact tool names, it starts blocking the very path
# it steers toward — and every block-side test still passes. Broadening it to
# also fire on willow_web_* left the suite green before these existed.


@pytest.mark.parametrize("tool_name", [
    "mcp__willow-mcp__willow_web_search",
    "mcp__willow-mcp__willow_web_fetch",
    "willow_web_search",
    "willow_web_fetch",
])
def test_check_native_web_allows_the_sanctioned_alternative(tool_name):
    assert pre_tool_use.check_native_web(tool_name) is None


@pytest.mark.parametrize("tool_name", ["", "Bash", "Read", "task_submit", "WebSocket"])
def test_check_native_web_allows_every_other_tool(tool_name):
    assert pre_tool_use.check_native_web(tool_name) is None


def test_main_stays_silent_for_the_sanctioned_web_tool():
    """End to end: the MCP web tool produces no decision at all, so a fetch
    through the recording seat is not merely permitted but uncommented."""
    code, stdout = _run_hook({
        "tool_name": "mcp__willow-mcp__willow_web_fetch",
        "tool_input": {"url": "https://example.com"},
        "session_id": "s1",
    })
    assert code == 0
    assert stdout == ""


# ── seat guard vs gate.PERMISSION_GROUPS: the drift this class of list invites ─
#
# The hook is stdlib-only by design — it runs inside the agent's harness, where
# willow_mcp may not be importable — so its write-capable group list is a literal
# regex. That is exactly the shape that goes quietly out of date: it named ten of
# the forty-two groups, leaving dispatch_write, human_loop_write, frank_write,
# markdownai_directives, orchestrator and eleven more self-grantable with the
# guardrail silent. The pin has to come from this side, where gate IS importable.
#
# The classification below is total by construction: the first test fails if a
# group exists in gate.PERMISSION_GROUPS and in neither column, so adding a group
# forces the read-or-write call rather than defaulting it to "unmatched".

# Groups containing at least one state-mutating tool. Three are judgment calls
# worth naming: `binding` (session_bind writes the trust-ceiling binding),
# `context` (context_save / context_expire), and `task_queue` (task_submit
# executes sandboxed work). `integration_call` is here because a credentialed
# outbound call has side effects the caller does not own.
_WRITE_CAPABLE_GROUPS = {
    "agent_dispatch", "binding", "code_graph_write", "commitment_write",
    "context", "dispatch_write", "envelope_apply", "envelope_write",
    "federation_call", "fork_write",
    "frank_write",
    "friction_write", "full_access", "gap_promote", "gap_purge", "gap_write",
    "grove_all", "grove_write",
    "human_loop_write", "integration_call", "knowledge_curate", "knowledge_write",
    "lineage_write", "markdownai_directives", "markdownai_write", "nest_write",
    "orchestrator",
    "schema_admin", "store_all", "store_write", "task_queue",
    "tool_oracle_route", "tool_oracle_seal",
}

# Groups that mutate nothing. `web_read` is deliberately here: willow_web_fetch
# and willow_web_search write no willow state, and the egress they front is
# gated separately by the web_net capability (covered below), not by this group.
_READ_ONLY_GROUPS = {
    "audit", "code_graph_read", "commitment_read", "dispatch_read",
    "envelope_read", "envelope_read_discards", "federation_read",
    "fleet_read", "grove_read",
    "fork_read", "friction_read", "gap_read", "human_loop_read",
    "integration_read", "knowledge_read", "lineage_read", "markdownai_read",
    "nest_read", "store_read", "tool_oracle_read", "web_read",
}

# Not permission groups — one-off capability flags a manifest lists on their
# own line (the three-key egress gate's half, plus grove_relay). No group
# implies any of them. All are operator-only. Kept in step with gate.py's
# *_PERMISSION capability constants by test_net_capabilities_cover_every_gate_flag.
_NET_CAPABILITIES = ("task_net", "task_db", "integration_net", "web_net", "mcp_federation", "grove_relay")


def _manifest_write(permission):
    """The real decision, through the real entry point, on a manifest that grants
    exactly this one permission."""
    return pre_tool_use.check_trust_root_write({
        "file_path": "/home/x/.willow/mcp_apps/someapp/manifest.json",
        "content": '{"permissions": ["%s"]}' % permission,
    })


def test_seat_guard_classification_covers_every_permission_group():
    """Drift guard. A new group in gate.PERMISSION_GROUPS must be classified
    read-or-write here; this fails until it is."""
    from willow_mcp import gate
    classified = _WRITE_CAPABLE_GROUPS | _READ_ONLY_GROUPS
    actual = set(gate.PERMISSION_GROUPS)
    assert not (actual - classified), (
        "permission groups classified in neither column: %s" % sorted(actual - classified))
    assert not (classified - actual), (
        "classified names that are not permission groups: %s" % sorted(classified - actual))
    assert not (_WRITE_CAPABLE_GROUPS & _READ_ONLY_GROUPS)


def test_seat_guard_covers_every_write_capable_group():
    for group in sorted(_WRITE_CAPABLE_GROUPS):
        assert _manifest_write(group) is not None, (
            "%s is write-capable but self-granting it is not blocked" % group)


def test_seat_guard_leaves_every_read_only_group_alone():
    """The other half of the guard. Widening the denylist must not turn ordinary
    manifest work into a block — the false-positive class B-18 removed."""
    for group in sorted(_READ_ONLY_GROUPS):
        assert _manifest_write(group) is None, (
            "%s is read-only but self-granting it is blocked" % group)


def test_seat_guard_covers_every_egress_capability():
    for cap in _NET_CAPABILITIES:
        assert _manifest_write(cap) is not None, "%s is not blocked" % cap


def test_net_capabilities_cover_every_gate_flag():
    """Drift guard for capabilities, the counterpart to
    test_seat_guard_classification_covers_every_permission_group for groups.
    Every ``*_PERMISSION`` capability constant in gate.py must appear in
    _NET_CAPABILITIES (and so be exercised by the test above). `mcp_federation`
    was added to gate for the federation lane while its self-grant guard was
    silently absent; this fails until a new capability flag is guarded, instead
    of passing because the hard-coded list never learned about it."""
    from willow_mcp import gate
    gate_flags = {v for k, v in vars(gate).items()
                  if k.endswith("_PERMISSION") and isinstance(v, str)}
    missing = gate_flags - set(_NET_CAPABILITIES)
    assert not missing, (
        "gate capability flags absent from _NET_CAPABILITIES (and so unguarded "
        "against self-grant): %s" % sorted(missing))


def test_server_process_egress_capabilities_route_to_the_egress_reason():
    """integration_net and web_net authorize egress from the server process, the
    more privileged lane (gate.py:332-337). They must read as the egress
    self-grant, not as a generic seat widening."""
    for cap in ("task_net", "integration_net", "web_net"):
        assert "REQUEST egress" in _manifest_write(cap)


def test_ambiguous_group_names_do_not_fire_on_prose():
    """orchestrator / context / binding are ordinary words. They must trip as a
    quoted permission and stay silent in a description field."""
    prose = pre_tool_use.check_trust_root_write({
        "file_path": "/home/x/.willow/mcp_apps/someapp/manifest.json",
        "content": '{"permissions": ["store_read"], '
                   '"description": "reads context for the orchestrator, no binding"}',
    })
    assert prose is None
    assert _manifest_write("orchestrator") is not None


def test_bundled_hook_is_identical_to_the_repo_copy():
    """src/willow_mcp/bundle/hooks/pre_tool_use.py is what ships to an agent's
    harness; hooks/pre_tool_use.py is what these tests exercise. A fix applied to
    one and not the other is a guardrail that passes CI and is absent in
    production."""
    bundled = Path(__file__).resolve().parents[1] / "src/willow_mcp/bundle/hooks/pre_tool_use.py"
    assert bundled.read_text() == _HOOK_PATH.read_text()


# ── framing: this is a guardrail, not a control — never let that erode ──────

_DESIGN_DOC_PATH = (
    Path(__file__).resolve().parents[1] / "docs/design/hooks-and-skills.md"
)


def test_module_docstring_states_guardrail_not_control():
    """The hook lives in the agent's own harness and can be bypassed with no
    OS-level obstacle; the durable control is chown + STRICT_TRUST_ROOT (B-32).
    A future PR could quietly drop or soften this sentence while adding a new
    block-decision guard, making the module read like it enforces more than it
    does. Pin the exact framing, and the control it points to, so that drift
    fails a test instead of just a review."""
    doc = pre_tool_use.__doc__
    assert "guardrail, not a control" in doc
    assert "no OS-level obstacle" in doc
    assert "chown" in doc and "WILLOW_MCP_STRICT_TRUST_ROOT" in doc


def test_design_doc_states_guardrail_not_control():
    """Same framing, same reason, second copy: docs/design/hooks-and-skills.md
    is where a human reads the rationale, and it can drift from the docstring
    independently of it."""
    text = _DESIGN_DOC_PATH.read_text()
    assert "guardrail, not a control" in text
    assert "chown" in text and "WILLOW_MCP_STRICT_TRUST_ROOT" in text


# ── #304: allow-permission is a self-grant path the path-keyed guard missed ──

def test_allow_permission_blocks_every_egress_cap_and_write_group():
    """#304 drift guard. `willow-mcp allow-permission <app> <perm>` edits the
    manifest, so it must refuse the SAME egress capabilities and write-capable
    groups the manifest-file guard does — that guard keyed on the manifest.json
    path this CLI never names, so it slipped through. Derived from the same sets
    the seat/net-cap guards use, so a new cap or write group cannot be added
    without this path learning to block it too."""
    for perm in sorted(set(_WRITE_CAPABLE_GROUPS) | set(_NET_CAPABILITIES)):
        cmd = "willow-mcp allow-permission someapp %s" % perm
        assert pre_tool_use.check_bash_self_grant(cmd) is not None, (
            "allow-permission of %s is not blocked (#304 self-grant path)" % perm)


def test_allow_permission_leaves_read_only_groups_alone():
    """The other half: granting a read-only group is not escalation, exactly as
    the manifest-file seat guard leaves read groups alone — over-blocking would
    turn ordinary operator setup into a refusal."""
    for perm in sorted(_READ_ONLY_GROUPS):
        cmd = "willow-mcp allow-permission someapp %s" % perm
        assert pre_tool_use.check_bash_self_grant(cmd) is None, (
            "allow-permission of read-only %s should not be blocked" % perm)


@pytest.mark.parametrize("command", [
    ".venv/bin/willow-mcp allow-permission willow web_net",   # a real path invocation
    'willow-mcp allow-permission myapp "web_net"',            # quoted permission
    "willow_mcp allow-permission myapp web_net",              # underscore spelling
    "willow-mcp allow-permission myapp orchestrator",         # bare write seat
])
def test_allow_permission_self_grant_forms_blocked(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


@pytest.mark.parametrize("command", [
    "willow-mcp deny-permission myapp web_net",               # de-escalation is fine
    "willow-mcp net-status",
    "echo document the allow-permission web_net gap for #304",  # prose, not the command
])
def test_deny_permission_and_prose_are_not_blocked(command):
    assert pre_tool_use.check_bash_self_grant(command) is None
