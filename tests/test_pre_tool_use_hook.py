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


def test_main_blocks_a_bash_grant_build():
    """grant-build is the same self-grant class as grant-net: the operator
    asks and agrees, the agent never authorizes its own build."""
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": "willow-mcp grant-build workflow --ttl 30m --reason ..."},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "block"


def test_check_task_submit_self_grant_blocks_grant_build_in_task_text():
    reason = pre_tool_use.check_task_submit_self_grant(
        {"task": "willow-mcp grant-build workflow --ttl 30m --reason ..."})
    assert reason is not None


def test_check_task_submit_self_grant_allows_build_status_and_earn_check():
    """Reading gate state is not escalation. build-status and earn-check both
    read only; blocking them would be a false positive."""
    for task in ("willow-mcp build-status", "willow-mcp earn-check --json"):
        assert pre_tool_use.check_task_submit_self_grant({"task": task}) is None


def test_lease_dir_re_covers_build_leases_dir():
    """A write into _build_leases/ is the same mint path a write into
    _net_leases/ is; the direct-write guard must refuse both."""
    assert pre_tool_use._LEASE_DIR_RE.search(
        "cat > $WILLOW_HOME/mcp_apps/_build_leases/workflow.json")
    assert pre_tool_use._LEASE_DIR_RE.search(
        "echo {} > mcp_apps/_net_leases/willow.json")


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
    routed = pre_tool_use.check_bash_routing("git commit -m x")
    assert routed is not None and routed[0] == "block" and "task_submit" in routed[1]


@pytest.fixture
def orchestrator_seat(monkeypatch):
    monkeypatch.setenv("WILLOW_APP_ID", "willow")


# ── the willow seat does not use Shell (2026-09-14, gap 715d89fe3c90) ────────
#
# The five commands the seat actually ran that day, and the hook let through,
# are the plants. Each refusal must name the fleet tool that replaces it —
# a block that only says "no" sends the seat back to guessing.

@pytest.mark.parametrize("command, replacement", [
    ("git diff --stat", "detect_changes"),
    ("cd /x && python -m pytest tests/ -q 2>&1 | tail -5", "task_submit"),
    ("python3 -c \"import json; print(1)\"", "task_submit"),
    ("wc -l a.jsonl; tail -2 a.jsonl", "Read"),
    ("git commit -m 'x'", "task_submit"),
    ("git add -A", "task_submit"),
    ("git pull origin main", "git_pull_execute"),
    ("git fetch --prune", "git_pull_execute"),
    ("gh pr create --title t", "pr_open_execute"),
    ("gh pr merge 5", "operator"),
    ("gh pr view 5", "integration_call"),
    ("git status", "detect_changes"),
    ("git log --oneline -3", "detect_changes"),
    ("cat README.md", "Read"),
    ("grep -rn foo src/", "search_code"),
    ("ls -la", "Read"),
    ("systemctl --user status willow-bot-steward.service", "158600e03598"),
    ("ruff check .", "task_submit"),
    ("echo hello", "task_submit"),
])
def test_the_willow_seat_is_refused_shell_and_told_the_door(orchestrator_seat, command, replacement):
    routed = pre_tool_use.check_bash_routing(command)
    assert routed is not None and routed[0] == "block", (command, routed)
    assert "does not use Shell" in routed[1]
    assert replacement in routed[1], (command, routed[1])


def test_the_seat_refusal_is_not_lifted_by_the_git_inspect_allowance(orchestrator_seat):
    """`git status`/`log`/`diff` are read-only and the routing table lets other
    seats run them; the willow seat still does not — `git diff --stat` was the
    first Shell the operator rejected on 2026-09-14."""
    for c in ("git status", "git diff --stat", "gh pr list"):
        routed = pre_tool_use.check_bash_routing(c)
        assert routed is not None and routed[0] == "block", c


def test_orchestrator_raw_push_is_brokered(orchestrator_seat):
    """Push is never Shell-exempt — operator-ruling brokered push / willow-bot App."""
    routed = pre_tool_use.check_bash_routing("git" + " push -u origin my-branch")
    assert routed is not None and routed[0] == "block"
    assert "git_push_execute" in routed[1]


@pytest.mark.parametrize("command", [
    "psql mydb -c 'select 1'",
    "sqlite3 /tmp/x.db 'select 1'",
    "curl https://example.com",
    "pip install requests",
    "rm -rf build/",
])
def test_orchestrator_is_refused_everything_else_too(orchestrator_seat, command):
    routed = pre_tool_use.check_bash_routing(command)
    assert routed is not None and routed[0] == "block"


def test_specialist_seats_keep_the_routing_table(monkeypatch):
    """The seat rule is the willow seat's. A specialist still gets the
    inspect allowance and the warn/block table it always had."""
    monkeypatch.setenv("WILLOW_APP_ID", "ada")
    monkeypatch.setattr(pre_tool_use, "_project_dir", lambda: None)
    assert pre_tool_use.check_bash_routing("git status") is None
    assert pre_tool_use.check_bash_routing("ls -la src/")[0] == "warn"
    assert pre_tool_use.check_bash_routing("git commit -m x")[0] == "block"
    assert pre_tool_use.check_seat_shell("anything") is None


def test_orchestrator_self_grant_guard_not_lifted(orchestrator_seat):
    """The seat exemption never touches the self-grant guard: an orchestrator
    still may not mint its own egress."""
    assert pre_tool_use.check_bash_self_grant(
        "willow-mcp grant-net willow --ttl 3h") is not None


def test_main_refuses_orchestrator_commit_and_names_kart():
    """End to end through main(): the harness gets a block, and the reason
    names task_submit — the same commit, run in Kart with .git bound."""
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m 'ship it'"},
        "session_id": "s1",
    }, env={"WILLOW_APP_ID": "willow"})
    assert code == 0
    body = json.loads(stdout)
    assert body["decision"] == "block"
    assert "does not use Shell" in body["reason"] and "task_submit" in body["reason"]


def test_main_blocks_orchestrator_push_to_broker():
    code, stdout = _run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m 'ship it' && git" + " push"},
        "session_id": "s1",
    }, env={"WILLOW_APP_ID": "willow"})
    assert code == 0
    body = json.loads(stdout)
    assert body["decision"] == "block"
    assert "git_push_execute" in body["reason"]


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


# ── check_corpus_first: consult the fleet's verified organs before the web ──
#
# gap corpus-first-jeles-nestor / 38a0351f2527. The reminder names the three
# organs to try first (knowledge_search, the jeles-corpus federation, nestor)
# and is a warn, never a block, on either the tool it fires on alone.


@pytest.mark.parametrize("tool_name", [
    "willow_web_search",
    "mcp__willow-mcp__willow_web_search",
])
def test_check_corpus_first_warns_on_the_governed_search_tool(tool_name):
    routed = pre_tool_use.check_corpus_first(tool_name)
    assert routed is not None
    decision, reason = routed
    assert decision == "warn"
    assert "knowledge_search" in reason
    assert "nestor" in reason
    assert "jeles" in reason.lower()


def test_check_corpus_first_warns_on_native_websearch_too():
    routed = pre_tool_use.check_corpus_first("WebSearch")
    assert routed is not None
    assert routed[0] == "warn"


@pytest.mark.parametrize("tool_name", [
    "WebFetch",
    "willow_web_fetch",
    "mcp__willow-mcp__willow_web_fetch",
    "Bash",
    "Read",
    "task_submit",
    "",
])
def test_check_corpus_first_allows_every_non_search_tool(tool_name):
    """WebFetch/willow_web_fetch are deliberately excluded: fetching a URL the
    caller already has is not the "where do I look first" decision this hook
    targets, and check_native_web's channel guard already covers WebFetch."""
    assert pre_tool_use.check_corpus_first(tool_name) is None


def test_main_never_hard_blocks_on_corpus_first_alone():
    """Calling willow_web_search directly (no native-web hard block in play)
    must never come back as a block — the corpus can genuinely miss, so this
    guard only ever reminds."""
    code, stdout = _run_hook({
        "tool_name": "willow_web_search",
        "tool_input": {"query": "what is the current release version"},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "warn"
    assert "knowledge_search" in decision["reason"]
    assert "nestor" in decision["reason"]


# ── grant-aware native-web redirect, without a second reader of grant state ──
#
# An earlier revision probed WILLOW_HOME directly to decide whether to name
# willow_web_* outright or say "ask the operator" instead. Cross-model audit
# found that probe was a split-brain: it read the wrong consent path (not the
# canonical config/settings.global.json the real gate prefers, and not
# WILLOW_SETTINGS_GLOBAL), skipped ttl_seconds validation on the lease, didn't
# deny on a corrupt canonical consent file the way the real gate does, and
# didn't know about strict_trust_root/PGP/deny_tools/WILLOW_MCP_APPS_ROOT —
# every one of those gaps could make the probe say "granted" when
# web_egress.egress_denial() would actually refuse. Per the fleet's standing
# rule to eliminate split-brains rather than keep re-syncing two copies of one
# state, check_native_web no longer probes grant state at all: the message is
# unconditional, naming the willow_web_* verb AND noting that an ungranted
# seat should ask the operator, regardless of ambient environment. These tests
# pin that: (1) the redirect always names the verb; (2) it always includes the
# ask-the-operator note, independent of any WILLOW_HOME/WILLOW_APP_ID state;
# (3) willow_web_* is never redirected onto itself.


def test_check_native_web_names_the_verb_and_asks_the_operator():
    """The redirect names the willow_web_* verb AND tells an ungranted seat to
    ask the operator, in a single unconditional message — no probe, so no
    ambient env can change whether the ask-the-operator note appears."""
    decision, reason = pre_tool_use.check_native_web("WebSearch")
    assert decision == "block"
    assert "willow_web_search" in reason
    assert "ask the operator" in reason.lower()
    decision, reason = pre_tool_use.check_native_web("WebFetch")
    assert decision == "block"
    assert "willow_web_fetch" in reason
    assert "ask the operator" in reason.lower()


@pytest.mark.parametrize("env", [
    {},
    {"WILLOW_HOME": "/tmp/does-not-exist-anywhere", "WILLOW_APP_ID": "ada"},
])
def test_check_native_web_wording_is_independent_of_ambient_env(env, monkeypatch):
    """No grant probe means no ambient WILLOW_HOME/WILLOW_APP_ID state can
    change the message — pinned against the exact split-brain the audit found
    (a probe reading stale/wrong files and claiming 'granted')."""
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    for tool_name, verb in (("WebSearch", "willow_web_search"), ("WebFetch", "willow_web_fetch")):
        decision, reason = pre_tool_use.check_native_web(tool_name)
        assert decision == "block"
        assert verb in reason
        assert "ask the operator" in reason.lower()


def test_main_web_search_block_composes_verb_operator_ask_and_corpus_first():
    """Native WebSearch is still hard-blocked — check_native_web's
    unconditional, probe-free redirect (naming the willow_web_search verb and
    telling an ungranted seat to ask the operator) — with the corpus-first
    reminder (knowledge_search / nestor) appended to that SAME decision
    rather than being silently dropped or emitted as a second, conflicting
    one. Only one decision ever reaches the caller."""
    code, stdout = _run_hook({
        "tool_name": "WebSearch",
        "tool_input": {"search_term": "latest news"},
        "session_id": "s1",
    })
    assert code == 0
    decision = json.loads(stdout)
    assert decision["decision"] == "block"
    assert "willow_web_search" in decision["reason"]
    assert "ask the operator" in decision["reason"].lower()
    assert "knowledge_search" in decision["reason"]
    assert "nestor" in decision["reason"]


def test_check_native_web_never_fires_on_the_governed_verb_itself():
    """The governed call is never redirected onto itself — re-asserted here
    alongside the grant-aware wording tests for locality."""
    assert pre_tool_use.check_native_web("willow_web_search") is None
    assert pre_tool_use.check_native_web("mcp__willow-mcp__willow_web_fetch") is None


def test_main_corpus_first_reminder_absent_for_websearch_would_be_a_regression():
    """Mutation-style pin (same intent as test_check_native_web_blocks_webfetch
    above): if check_corpus_first were ever narrowed to skip "WebSearch" — e.g.
    a stray rename — main() would silently stop composing and this test would
    catch it even though the block-only assertions above still pass."""
    assert pre_tool_use.check_corpus_first("WebSearch") is not None


def test_check_corpus_first_is_fail_safe_on_odd_string_input():
    """No external state — a malformed/odd but still-string tool_name (the
    only shape main() ever passes, via payload.get("tool_name", "")) resolves
    to a plain None or a warn, never a raise and never a block."""
    for odd in ("WebSearch\x00", "🤖", "mcp__x__willow_web_search__extra", ""):
        result = pre_tool_use.check_corpus_first(odd)
        assert result is None or result[0] == "warn"


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
    "governance_propose", "governance_sync",
    "grove_all", "grove_write",
    "human_loop_write", "integration_call", "knowledge_curate", "knowledge_write",
    "lineage_write", "markdownai_directives", "markdownai_write", "nest_write",
    "orchestrator",
    "schema_admin", "store_all", "store_write", "task_queue",
    "tool_oracle_route", "tool_oracle_seal",
    # The steward as its own principal (pair 163b9a70): steward_sweep mutates
    # (seal_drain/net_authority_drain/envelope_retire_sweep/gitsync_sweep/
    # git_pull_execute); steward_enqueue mutates the human-required queue.
    "steward_sweep", "steward_enqueue",
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
    # steward_read: human_required_list only — a pure queue view (pair 163b9a70).
    "steward_read",
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


# ── parse the invocation, not the command text (gaps 3cc11d282b4a, 7ede165e5a29) ─
#
# The self-grant guard used to run its grant-verb regexes against the raw
# command string, so a verb or permission merely NAMED in prose, a quoted
# argument, or a heredoc body was read as the act itself. These four pin the
# precision fix: a named permission/verb is not an invocation, but a real
# invocation at command position still is. The first three fail on the current
# tree (the false positive is present) and pass after the parse-aware fix.


def test_commit_message_naming_an_excluded_permission_is_not_a_self_grant():
    """gap 3cc11d282b4a: a commit body describing an EXCLUDED permission was read
    as granting it. The grant token lives inside the quoted -m argument, not at
    command position, so it is prose — the command is `git commit`.

    Round-5 rework (5701FFBD, blocklist → allowlist): this message contains a
    literal `;`, which is one of the disqualifying characters for the inert-
    content check — regardless of the surrounding quote style. The old named-
    operator blocklist didn't check for `;` at all, so this used to blank
    cleanly and ALLOW; the new allowlist has no special case for "it's inside
    single quotes so the shell won't act on it" — ambiguity denies, on
    purpose, so this now DENIES."""
    cmd = ("git commit -m "
           "'note: task_net stays operator-only; never willow-mcp allow-permission app task_net'")
    assert pre_tool_use.check_bash_self_grant(cmd) is not None


@pytest.mark.parametrize("command", [
    'grep -rn "willow-mcp grant-net" docs/',
    "cat notes.md | grep 'willow-mcp allow-permission app web_net'",
])
def test_read_command_containing_a_guarded_keyword_is_not_a_self_grant(command):
    """gap 7ede165e5a29: a pure-read command (grep/cat) was refused for merely
    containing a guarded keyword in its argument. The keyword is data the reader
    scans, not a command it runs."""
    assert pre_tool_use.check_bash_self_grant(command) is None


@pytest.mark.parametrize("command", [
    "willow-mcp grant-net willow --ttl 3h",
    "sudo willow-mcp grant-net willow --ttl 3h",          # wrapper stripped
    "willow-mcp allow-permission app web_net",
    'python -c "from willow_mcp import lease; lease.grant(\'x\', 60)"',  # executor code
])
def test_guarded_invocation_at_command_position_is_still_refused(command):
    """The precision fix must not relax a real self-grant: a grant verb at the
    command-position word (through env/sudo wrappers, or inside an executor's
    code) is still refused."""
    assert pre_tool_use.check_bash_self_grant(command) is not None


# ── fail-closed carve-out regression lock (audit 2AA60817) ──────────────────
#
# The shape-checking parser above (command-position-only matching) is exactly
# what let a real grant invocation through when it reached the guard by any
# shape OTHER than a bare command-position word — cross-model audit 2AA60817.
# The operator ruled: restore the raw substring scan as the primary denier and
# use parsing ONLY to suppress the two measured false positives above. Every
# case below must DENY — each pins one bypass vector the old parser missed.


@pytest.mark.parametrize("command", [
    "ls\nwillow-mcp grant-net loki",
], ids=["newline_separated"])
def test_newline_separated_grant_is_denied(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


@pytest.mark.parametrize("command", [
    "bash <<'EOF'\nwillow-mcp grant-net loki\nEOF",
    "python <<'EOF'\nfrom willow_mcp import lease\nlease.grant('loki', 60)\nEOF",
    "cat <<EOF | bash\nwillow-mcp grant-net loki\nEOF",
], ids=["bash_heredoc", "python_heredoc", "cat_heredoc_piped_to_bash"])
def test_executed_heredoc_grant_is_denied(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


@pytest.mark.parametrize("command", [
    'echo "$(willow-mcp grant-net loki)"',
    "echo `willow-mcp grant-net loki`",
], ids=["dollar_paren_subst", "backtick_subst"])
def test_command_substitution_grant_is_denied(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


def test_subshell_grant_is_denied():
    assert pre_tool_use.check_bash_self_grant("(willow-mcp grant-net loki)") is not None


def test_group_command_grant_is_denied():
    assert pre_tool_use.check_bash_self_grant("{ willow-mcp grant-net loki; }") is not None


def test_leading_assignment_grant_is_denied():
    assert pre_tool_use.check_bash_self_grant("FOO=bar willow-mcp grant-net loki") is not None


@pytest.mark.parametrize("command", [
    "echo 'willow-mcp grant-net loki' | bash",
    "printf 'willow-mcp grant-net loki' | sh",
], ids=["echo_pipe_bash", "printf_pipe_sh"])
def test_pipe_into_executor_grant_is_denied(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


@pytest.mark.parametrize("command", [
    "timeout 10 willow-mcp grant-net loki",
    "xargs willow-mcp grant-net loki </dev/null",
    "nohup willow-mcp grant-net loki &",
    "setsid willow-mcp grant-net loki",
    "doas willow-mcp grant-net loki",
    "ssh host willow-mcp grant-net loki",
    "uv run willow-mcp grant-net loki",
    "uvx willow-mcp grant-net loki",
    "poetry run willow-mcp grant-net loki",
    "npx willow-mcp grant-net loki",
], ids=["timeout", "xargs", "nohup", "setsid", "doas", "ssh", "uv_run", "uvx", "poetry_run", "npx"])
def test_unstripped_wrapper_grant_is_denied(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


def test_python_module_invocation_allow_permission_is_denied():
    assert pre_tool_use.check_bash_self_grant(
        "python -m willow_mcp allow-permission loki task_net"
    ) is not None


def test_task_submit_text_hiding_a_grant_is_denied():
    """check_bash_self_grant also gates task_submit text (server.py ~:510) — a
    grant smuggled into Kart task text must be refused exactly like Bash."""
    tool_input = {"task": "echo setting up\nwillow-mcp grant-net loki --ttl 30m"}
    assert pre_tool_use.check_task_submit_self_grant(tool_input) is not None


# ── the mask must not swallow a live-execution operator (re-audit F72E96E1) ──
#
# The two carve-outs above blank a region and re-scan; if that region is
# reached at all, the masking is fine. But `$(...)`, backticks, and `<(...)`
# inside a `git commit -m/-F` message or a read-only command's argument are
# NOT inert data — the shell evaluates them before the outer command runs.
# Blanking that region deletes the only text carrying the live grant, so the
# re-scan finds nothing and the guard wrongly ALLOWs a real self-grant. Every
# case below must DENY. These fail on the pre-fix tree (ALLOW) and pass after.


@pytest.mark.parametrize("command", [
    'git commit -m "$(willow-mcp grant-net loki)"',
    "git commit -m \"$(willow-mcp allow-permission loki task_net)\"",
], ids=["dollar_paren_in_commit_message", "allow_permission_dollar_paren_in_commit_message"])
def test_command_substitution_inside_commit_message_is_denied(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


def test_backtick_substitution_inside_commit_message_is_denied():
    command = 'git commit -m "`willow-mcp grant-net loki`"'
    assert pre_tool_use.check_bash_self_grant(command) is not None


@pytest.mark.parametrize("command", [
    "cat $(willow-mcp grant-net loki)",
    "head $(willow-mcp grant-net loki)",
    'grep "$(willow-mcp grant-net loki)" f',
    "cat <(willow-mcp grant-net loki)",
], ids=["cat_dollar_paren", "head_dollar_paren", "grep_dollar_paren_arg", "cat_process_substitution"])
def test_live_execution_operator_inside_read_only_argument_is_denied(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


# ── round-5 rework: blocklist → allowlist (closing Opus re-audit 5701FFBD) ──
#
# Round-4's carve-out named three live-execution operators ($(, backtick,
# <() ) and missed two more real ones: `>(` (output process substitution)
# and `${ cmd; }` (bash 5.3 funsub). Both blank cleanly under the old
# regex — the read-only command's whole argument list is whitespace, the
# raw scan finds nothing left, and a live grant is wrongly suppressed. The
# fix replaces the named-operator blocklist with an inert-content
# allowlist: a region may be blanked only when it contains NONE of
# $ ` ( ) < > { } | ; & \ or a newline. These fail (wrongly ALLOW) on the
# pre-fix tree and DENY after.


@pytest.mark.parametrize("command", [
    "cat >(willow-mcp grant-net loki)",
    "head >(willow-mcp grant-net loki)",
], ids=["cat_output_process_substitution", "head_output_process_substitution"])
def test_output_process_substitution_inside_read_only_argument_is_denied(command):
    assert pre_tool_use.check_bash_self_grant(command) is not None


def test_output_process_substitution_allow_permission_variant_is_denied():
    assert pre_tool_use.check_bash_self_grant(
        "cat >(willow-mcp allow-permission loki task_net)"
    ) is not None


def test_funsub_inside_read_only_argument_is_denied():
    assert pre_tool_use.check_bash_self_grant(
        "cat ${ willow-mcp grant-net loki; }"
    ) is not None


def test_ambiguous_commit_message_with_prose_and_subst_denies():
    """Accepted conservative behavior, not a bug to defeat: a commit message
    that BOTH names the grant verb in prose (so the raw scan fires) AND
    contains an unrelated command substitution ($(date)) is denied. The
    masker cannot tell a "safe" use of the special characters from a "live"
    one, so it refuses to blank the whole region and the raw scan's denial
    stands — ambiguity denies, even though the grant text here is only
    prose."""
    assert pre_tool_use.check_bash_self_grant(
        'git commit -m "note: never run willow-mcp grant-net anyone, timestamp $(date)"'
    ) is not None


# The two measured false positives the carve-outs exist for must still ALLOW
# — the fix must refuse to blank ONLY when a live-execution operator is
# present, not regress the plain prose/argument cases.


def test_commit_message_naming_the_verb_in_plain_prose_still_allowed():
    assert pre_tool_use.check_bash_self_grant(
        'git commit -m "grant-net is a scary phrase"'
    ) is None


def test_read_command_naming_the_verb_in_a_plain_argument_still_allowed():
    assert pre_tool_use.check_bash_self_grant('grep "grant-net" README.md') is None


# ── LOW: `git commit` recognition must survive leading git global options ──
#
# Recognition keyed on tokens[1] == "commit", so `git -C /path commit` and
# `git --no-pager commit` were unrecognised as `git commit` invocations —
# a false-positive DENY when the commit message merely named a guarded verb
# in prose. Recognise `git commit` past global options, conservatively.


def test_git_dash_c_commit_with_plain_message_is_allowed():
    assert pre_tool_use.check_bash_self_grant(
        'git -C /path/to/repo commit -m "plain text"'
    ) is None


def test_git_dash_c_commit_naming_the_verb_in_prose_is_denied_by_the_semicolon():
    """Same round-5 policy change as
    test_commit_message_naming_an_excluded_permission_is_not_a_self_grant: the
    literal `;` in this message is disqualifying under the inert-content
    allowlist regardless of `git -C` recognition, so this now DENIES."""
    cmd = ('git -C /path/to/repo commit -m '
           "'note: task_net stays operator-only; never willow-mcp allow-permission app task_net'")
    assert pre_tool_use.check_bash_self_grant(cmd) is not None


def test_git_no_pager_commit_naming_the_verb_in_prose_is_allowed():
    cmd = ('git --no-pager commit -m '
           "'note: never willow-mcp grant-net anyone'")
    assert pre_tool_use.check_bash_self_grant(cmd) is None


def test_cursor_before_shell_execution_denies_routed_git_push():
    """Cursor beforeShellExecution must not use the Claude Bash schema."""
    payload = {
        "command": "git push origin master",
        "hook_event_name": "beforeShellExecution",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "willow_mcp.pre_tool_hook"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert out["permission"] == "deny"
    msg = out.get("agent_message", "").lower()
    assert "git_push_execute" in msg or "willow-mcp" in msg


def test_cursor_pre_tool_use_shell_denies_git_push():
    """Agent Shell tool uses preToolUse + Shell matcher, not beforeShellExecution."""
    payload = {
        "tool_name": "Shell",
        "tool_input": {"command": "git push origin master"},
        "hook_event_name": "preToolUse",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "willow_mcp.pre_tool_hook"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["permission"] == "deny"


def test_willow_bot_steward_loop_is_routed():
    routed = pre_tool_use.check_bash_routing("willow-bot-steward loop")
    assert routed is not None and routed[0] == "block"
    assert "task_submit" in routed[1]


def test_cursor_before_shell_execution_allows_benign_command():
    payload = {
        "command": "echo hello",
        "hook_event_name": "beforeShellExecution",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "willow_mcp.pre_tool_hook"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["permission"] == "allow"


# ── H1 act-vs-text: python heredoc routing is command-position only ─────────


def test_python_heredoc_mentioned_in_echo_is_not_routed():
    """gap a1416fb1b8b1: naming a python heredoc inside echo/printf must not
    trip the prefer-MCP heredoc steer — only an actual invocation does."""
    assert pre_tool_use.check_bash_routing(
        'echo "example: python3 <<END then code END"'
    ) is None


def test_python_heredoc_at_command_position_is_still_routed():
    decision = pre_tool_use.check_bash_routing("python3 <<'EOF'\nprint(1)\nEOF")
    assert decision is not None
    assert decision[0] == "block"
    assert "heredoc" in decision[1].lower()


def test_python_heredoc_with_bare_stdin_dash_is_routed():
    """gap aad87628554c: `python3 - <<` is the common stdin form; H1's first
    pattern required `-\\S+` and let the bare dash through."""
    decision = pre_tool_use.check_bash_routing(
        "python3 - <<'PY'\nprint(1)\nPY"
    )
    assert decision is not None
    assert decision[0] == "block"
    assert "heredoc" in decision[1].lower()


def test_python_heredoc_with_flag_before_redirect_is_routed():
    decision = pre_tool_use.check_bash_routing(
        "python3 -u <<'EOF'\nprint(1)\nEOF"
    )
    assert decision is not None
    assert decision[0] == "block"


# ── H3: self-grant is tool-level, not only group-level (gap 7c3f45e495b4) ───


def test_allow_permission_literal_write_tool_is_refused():
    assert pre_tool_use.check_bash_self_grant(
        "willow-mcp allow-permission app decision_propose"
    ) is not None
    assert pre_tool_use.check_bash_self_grant(
        "willow-mcp allow-permission app store_put"
    ) is not None


def test_allow_permission_literal_read_tool_is_allowed():
    assert pre_tool_use.check_bash_self_grant(
        "willow-mcp allow-permission app store_get"
    ) is None
    assert pre_tool_use.check_bash_self_grant(
        "willow-mcp allow-permission app knowledge_search"
    ) is None


def test_manifest_write_of_literal_write_tool_is_refused():
    assert _manifest_write("decision_propose") is not None
    assert _manifest_write("store_put") is not None


def test_seat_write_tools_cover_every_exclusive_write_tool():
    """Drift pin: exclusive write tools from gate.PERMISSION_GROUPS must match
    the hook's _SEAT_WRITE_TOOLS literal (stdlib-only hook cannot import gate)."""
    from willow_mcp import gate

    write_tools = set()
    read_tools = set()
    for group in _WRITE_CAPABLE_GROUPS:
        write_tools |= set(gate.PERMISSION_GROUPS[group])
    for group in _READ_ONLY_GROUPS:
        read_tools |= set(gate.PERMISSION_GROUPS[group])
    expected = write_tools - read_tools
    actual = set(pre_tool_use._SEAT_WRITE_TOOLS)
    assert not (expected - actual), (
        "write tools missing from _SEAT_WRITE_TOOLS: %s" % sorted(expected - actual)
    )
    assert not (actual - expected), (
        "_SEAT_WRITE_TOOLS has extras not exclusive-write: %s" % sorted(actual - expected)
    )


# ── check_agent_spawn: the spawn-model guard (sealed rule c9ca1a09) ───────

def _spawn_input(prompt, subagent_type="general-purpose", model=""):
    return {
        "prompt": prompt,
        "subagent_type": subagent_type,
        "model": model,
        "description": "test spawn",
    }


def test_agent_spawn_builder_pinned_sonnet_allowed():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="hanuman", session_id="x")', model="sonnet"))
    assert result is None


def test_agent_spawn_builder_unpinned_refused():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="hanuman", session_id="x")'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "hanuman" in reason and "sonnet" in reason


def test_agent_spawn_builder_pinned_opus_refused():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="hanuman", session_id="x")', model="opus"))
    assert result is not None
    assert result[0] == "block"


def test_agent_spawn_auditor_pinned_opus_allowed():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="loki", session_id="x")', model="opus"))
    assert result is None


def test_agent_spawn_auditor_as_fork_refused():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="loki", session_id="x")',
        subagent_type="fork", model="opus"))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "fork" in reason


def test_agent_spawn_explore_no_seat_prompt_allowed():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "Find every usage of foo() across the repo.", subagent_type="Explore"))
    assert result is None


def test_agent_spawn_willow_seat_refused():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="willow", session_id="x")'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason
    assert "human-orchestrator" in reason


def test_agent_spawn_detects_you_are_display_name_framing():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "You are Loki, the audit seat for this dispatch.", subagent_type="fork"))
    assert result is not None
    assert "fork" in result[1]


def test_agent_spawn_registry_unreadable_fallback_still_refuses_fork(monkeypatch):
    monkeypatch.setattr(
        pre_tool_use, "_bundle_config_candidates",
        lambda filename: ["/nonexistent/does/not/exist/%s" % filename],
    )
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="loki", session_id="x")',
        subagent_type="fork", model="opus"))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "fork" in reason
    assert "fallback" in reason


def test_agent_spawn_table_reads_specialists_json_not_code(tmp_path, monkeypatch):
    """The role->model pin is read from specialists.json's own
    model_hint_session field at call time, not hardcoded — one source, not a
    duplicated spawn_models.json — proven by pointing the loader at a tmp
    copy with a different pin. This is a loader-level fact, not permission
    to self-assign: the PRODUCTION path stays refused regardless (see
    test_check_trust_root_write_blocks_specialists_json below)."""
    custom = tmp_path / "specialists.json"
    custom.write_text(json.dumps({
        "specialists": [
            {"agent_id": "hanuman", "display_name": "Hanuman", "role": "builder",
             "model_hint_session": "haiku", "human_only": False},
        ],
        "orchestrator_seat": {
            "agent_id": "willow", "display_name": "Willow", "role": "orchestrator",
            "human_only": True,
        },
    }))
    real_candidates = pre_tool_use._bundle_config_candidates

    def _patched(filename):
        if filename == "specialists.json":
            return [str(custom)]
        return real_candidates(filename)

    monkeypatch.setattr(pre_tool_use, "_bundle_config_candidates", _patched)

    refused = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="hanuman", session_id="x")', model="sonnet"))
    assert refused is not None, "sonnet must now be refused — the tmp copy pins haiku"

    allowed = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="hanuman", session_id="x")', model="haiku"))
    assert allowed is None, "haiku must now be allowed — it came from the tmp copy"


def test_check_trust_root_write_blocks_specialists_json():
    """The production path stays guarded even though the loader above is
    honest data, not code: a seat cannot Write/Edit its own pin table
    (sealed rule c9ca1a09) — neither the bundle copy nor a top-level
    config/ shadow."""
    reason = pre_tool_use.check_trust_root_write({
        "file_path": "src/willow_mcp/bundle/config/specialists.json",
    })
    assert reason is not None
    assert "c9ca1a09" in reason

    reason2 = pre_tool_use.check_trust_root_write({
        "file_path": "/repo/config/specialists.json",
    })
    assert reason2 is not None


def test_check_trust_root_write_blocks_spawn_models_json_if_reintroduced():
    """The removed split-brain file stays guarded too, in case anything ever
    reintroduces it — the guard matches the filename, not just the field."""
    reason = pre_tool_use.check_trust_root_write({
        "file_path": "src/willow_mcp/bundle/config/spawn_models.json",
    })
    assert reason is not None
    assert "c9ca1a09" in reason


# ── check_agent_spawn: detector rework (Loki audit 2026-09-21) ────────────
# Every bypass input from the audit handoff, turned into a test that now
# blocks; every false-positive input turned into a test that now allows.

def test_agent_spawn_detects_bare_json_app_id():
    result = pre_tool_use.check_agent_spawn(_spawn_input('{"app_id": "hanuman"}'))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_colon_app_id_no_quotes():
    result = pre_tool_use.check_agent_spawn(_spawn_input("app_id: hanuman"))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_app_id_mixed_case_value():
    result = pre_tool_use.check_agent_spawn(_spawn_input('app_id="Hanuman"'))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_uppercase_APP_ID_key():
    result = pre_tool_use.check_agent_spawn(_spawn_input('APP_ID="hanuman"'))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_lowercase_you_are():
    result = pre_tool_use.check_agent_spawn(_spawn_input("you are hanuman, go build it"))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_markdown_bold_you_are():
    result = pre_tool_use.check_agent_spawn(_spawn_input("You are **Hanuman**, the builder."))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_youre_contraction():
    result = pre_tool_use.check_agent_spawn(_spawn_input("You're Hanuman for this one."))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_curly_quoted_app_id():
    curly_prompt = "app_id=“hanuman”"
    result = pre_tool_use.check_agent_spawn(_spawn_input(curly_prompt))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_persona_path_reference():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "Read personas/hanuman.md and adopt it before you start."))
    assert result is not None and result[0] == "block"


def test_agent_spawn_detects_comma_start_framing():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "Hanuman, build the thing. Enter as the builder seat first."))
    assert result is not None and result[0] == "block"


def test_agent_spawn_fork_detects_seat_in_description_only():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "continue the build", subagent_type="fork") | {"description": "hanuman builds"})
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "fork" in reason


def test_agent_spawn_fork_detects_enter_as_in_prompt():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "Enter as hanuman and continue.", subagent_type="fork"))
    assert result is not None
    assert "fork" in result[1]


def test_agent_spawn_fork_subagent_type_case_insensitive():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="loki", session_id="x")',
        subagent_type="Fork", model="opus"))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "fork" in reason


def test_agent_spawn_allows_app_id_inside_handoff_read_lookup():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'Look at handoff_read(app_id="hanuman") for background before searching.',
        subagent_type="Explore"))
    assert result is None


def test_agent_spawn_allows_willow_app_id_inside_session_read_lookup():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'Check session_read(app_id="willow") for the current session state.',
        subagent_type="Explore"))
    assert result is None


def test_agent_spawn_allows_you_are_question_negation():
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "You are Loki? no — ask claude-code-guide instead."))
    assert result is None


def test_agent_spawn_prefers_session_enter_seat_over_earlier_mention():
    """Order-bug fix: a correctly pinned auditor spawn that cites the
    builder's packet by app_id ahead of its own session_enter must not be
    pinned to the wrong seat's model."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'dispatch_read(app_id="hanuman", limit=1) then '
        'session_enter(app_id="loki", session_id="x")',
        model="opus"))
    assert result is None


def test_agent_spawn_allows_bare_willow_mention_with_no_framing():
    """A bare app_id=willow mention with no session_enter/"You are" framing
    at all is not an attempt to become the orchestrator seat."""
    result = pre_tool_use.check_agent_spawn(_spawn_input('{"app_id": "willow"}'))
    assert result is None


def test_fallback_specialists_track_the_registry():
    """Drift guard: the hook's literal _FALLBACK_SPECIALISTS must stay in
    step with the shipped config/specialists.json, or an unreadable-registry
    fallback silently protects fewer (or differently-roled) seats than the
    real one does."""
    registry_path = (
        Path(__file__).resolve().parent.parent
        / "src" / "willow_mcp" / "bundle" / "config" / "specialists.json"
    )
    data = json.loads(registry_path.read_text())
    real_roles = {row["agent_id"]: row.get("role") for row in data.get("specialists", [])}
    orch = data["orchestrator_seat"]
    real_roles[orch["agent_id"]] = orch.get("role")
    real_human_only = {row["agent_id"]: bool(row.get("human_only")) for row in data.get("specialists", [])}
    real_human_only[orch["agent_id"]] = bool(orch.get("human_only"))

    fallback_roles = {row["agent_id"]: row.get("role") for row in pre_tool_use._FALLBACK_SPECIALISTS}
    fallback_human_only = {
        row["agent_id"]: bool(row.get("human_only")) for row in pre_tool_use._FALLBACK_SPECIALISTS
    }
    assert real_roles == fallback_roles
    assert real_human_only == fallback_human_only


# ── check_agent_spawn: round-3 rework, four regex-boundary defects ────────
# (Loki re-audit 2026-09-21, handoff session_handoff-2026-09-21-99388882).

def test_agent_spawn_session_enter_seat_survives_nested_paren_before_app_id():
    """(1) A nested paren in the canonical `session_id=str(uuid4())` shape,
    ahead of app_id in the same session_enter(...) call, used to truncate
    the `[^)]*` capture before app_id was reached — falling through to the
    bare tier and letting the willow refusal be bypassed entirely."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(session_id=str(uuid4()), app_id="willow")'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason
    assert "human-orchestrator" in reason


def test_agent_spawn_session_enter_seat_survives_nested_paren_multiline():
    """(1) Multi-line form of the same shape."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(\n'
        '    session_id=str(uuid4()),\n'
        '    app_id="willow",\n'
        ')'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason


def test_agent_spawn_session_enter_seat_nested_paren_still_pins_hanuman():
    """(1) The non-willow variant of the same shape must still resolve to
    the session_enter tier and pin the builder's model, not merely avoid
    crashing."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(session_id=str(uuid4()), app_id="hanuman")'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "hanuman" in reason and "sonnet" in reason

    allowed = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(session_id=str(uuid4()), app_id="hanuman")', model="sonnet"))
    assert allowed is None


def test_agent_spawn_you_are_seat_prefers_earliest_text_match():
    """(2) The row-order bug: iterating rows and returning the first ROW
    that matches anywhere (rather than the earliest TEXT match) pinned a
    correctly-framed Loki spawn to Hanuman's model because the fleet table
    happened to list hanuman before loki. Loki's own "You are Loki" framing
    comes first in the text and must win."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'You are Loki. Audit the packet whose prompt said "You are Hanuman".',
        model="opus"))
    assert result is None


def test_agent_spawn_you_are_allows_willows_possessive():
    """(3) "Willow's" is not "Willow" — no trailing boundary let the human
    -orchestrator refusal fire on a mere possessive."""
    result = pre_tool_use.check_agent_spawn(_spawn_input("You are Willow's auditor."))
    assert result is None


def test_agent_spawn_you_are_allows_willows_grove_reference():
    """(3) "Willow's Grove" is the sibling repo's name, not the seat."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "You are Willow's Grove resident watcher for this shift."))
    assert result is None


def test_agent_spawn_you_are_allows_willowbrook():
    """(3) "Willowbrook" merely starts with "Willow" — a compound word, not
    the seat name."""
    result = pre_tool_use.check_agent_spawn(_spawn_input("You are Willowbrook support."))
    assert result is None


def test_agent_spawn_comma_start_allows_hyphenated_compound():
    """(5, cheap fix) "Hanuman-style" is a compound word describing a style
    of notes, not the comma-start address form entering the seat."""
    result = pre_tool_use.check_agent_spawn(_spawn_input("Hanuman-style build notes"))
    assert result is None


def test_agent_spawn_allows_paren_less_prose_lookup():
    """(5, cheap fix) A read-only lookup call named in prose without
    parentheses ("Run ... with app_id=hanuman") is a lookup argument, not an
    entry — the masking that already covers the parenthesised form is
    extended to this shape too."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "Run mcp__willow-mcp__handoff_read with app_id=hanuman for background.",
        subagent_type="Explore"))
    assert result is None


# ── check_agent_spawn: round-4 rework, three regex-boundary defects ───────
# (Loki third audit 2026-09-21, handoff session_handoff-2026-09-21-498edf37).

def test_agent_spawn_you_are_seat_blocks_single_quoted_hanuman_no_model():
    """(1) REGRESSION: `(?![\\w'?])` treated a closing single quote as a
    boundary, so a single-quoted "You are Hanuman" no longer matched at
    all and the builder's sonnet pin was never enforced."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "'You are Hanuman'. Build the thing."))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "hanuman" in reason and "sonnet" in reason


def test_agent_spawn_you_are_seat_blocks_quoted_enter_as_fork():
    """(1) REGRESSION: the same closing-quote boundary let a quoted "Enter
    as 'Hanuman'" framing dodge the fork refusal."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "Enter as 'Hanuman' now", subagent_type="fork"))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "fork" in reason


def test_agent_spawn_you_are_seat_blocks_willow_trailing_quote():
    """(1) REGRESSION: "You are Willow'" bypassed the orchestrator refusal."""
    result = pre_tool_use.check_agent_spawn(_spawn_input("You are Willow'"))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason and "human-orchestrator" in reason


def test_agent_spawn_you_are_seat_blocks_quoted_enter_as_willow():
    """(1) REGRESSION: "Enter as 'Willow'" bypassed the orchestrator
    refusal the same way."""
    result = pre_tool_use.check_agent_spawn(_spawn_input("Enter as 'Willow'"))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason and "human-orchestrator" in reason


def test_agent_spawn_you_are_seat_still_allows_willows_possessive_apostrophe():
    """(1) The fix must not regress the ORIGINAL apostrophe case: "You are
    Willow's auditor" still is not "Willow"."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "You are Willow's auditor"))
    assert result is None


def test_agent_spawn_session_enter_unclosed_note_paren_blocks_willow():
    """(2) An unclosed session_enter( call — a nested paren inside an
    argument value — used to `continue` past the call entirely, falling to
    the bare tier where the willow refusal never fires."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="willow", note="a ( b")'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason and "human-orchestrator" in reason


def test_agent_spawn_session_enter_unclosed_project_paren_blocks_willow():
    """(2) Same shape via an unbalanced paren in a `project=` value."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="willow", project="Grove (WIP")'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason


def test_agent_spawn_session_enter_truncated_call_blocks_willow():
    """(2) A truncated session_enter( call with no closing paren at all
    still names willow and must still refuse."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="willow"'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason


def test_agent_spawn_session_enter_multiline_unclosed_blocks_willow():
    """(2) Multi-line unclosed form of the same defect."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(\n'
        '    app_id="willow",\n'
        '    note="see (a"\n'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason


def test_agent_spawn_session_enter_unclosed_note_paren_pins_hanuman():
    """(2) The hanuman equivalent of the unclosed-paren shape must still
    resolve to the session_enter tier and pin the builder's model."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="hanuman", note="a ( b")'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "hanuman" in reason and "sonnet" in reason

    allowed = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id="hanuman", note="a ( b")', model="sonnet"))
    assert allowed is None


def test_agent_spawn_allows_mcp_qualified_handoff_read_lookup():
    """(3) FALSE POSITIVE: the paren-pass names_pattern lacked the
    `(?:(?<=__)|\\b)` prefix the prose pass already carries, so the
    MCP-qualified spelling of a lookup call was never masked and tripped
    the bare-app_id tier."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'mcp__willow-mcp__handoff_read(app_id="hanuman", handoff_id="x")',
        subagent_type="Explore"))
    assert result is None


def test_agent_spawn_allows_mcp_qualified_serve_variant_lookup():
    """(3) Same defect on the `-serve` suffixed server-qualified spelling."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'mcp__willow-mcp-serve__store_get(app_id="hanuman", key="k")',
        subagent_type="Explore"))
    assert result is None


def test_agent_spawn_allows_mcp_qualified_whoami_lookup():
    """(3) Same defect on `whoami`, called out separately in the audit."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'mcp__willow-mcp__whoami(app_id="hanuman")', subagent_type="Explore"))
    assert result is None


def test_check_trust_root_write_blocks_doubled_slash_specialists_path():
    """(4) `config//specialists.json` must not slip the guard just because
    the anchored `$` pattern never saw the doubled separator."""
    reason = pre_tool_use.check_trust_root_write({
        "file_path": "src/willow_mcp/bundle/config//specialists.json",
    })
    assert reason is not None
    assert "c9ca1a09" in reason


def test_check_trust_root_write_blocks_dot_segment_specialists_path():
    """(4) `config/./specialists.json` is the same guarded file with an
    inert `.` path segment."""
    reason = pre_tool_use.check_trust_root_write({
        "file_path": "src/willow_mcp/bundle/config/./specialists.json",
    })
    assert reason is not None
    assert "c9ca1a09" in reason


def test_check_trust_root_write_blocks_doubled_slash_manifest_path():
    """(4) Same normalisation defect, same class, for _MANIFEST_RE."""
    reason = pre_tool_use.check_trust_root_write({
        "file_path": "/home/x/.willow/mcp_apps//willow/manifest.json",
        "content": '{"permissions": ["task_net"]}',
    })
    assert reason is not None


def test_check_trust_root_write_blocks_dot_segment_manifest_path():
    """(4) Same normalisation defect, same class, for _MANIFEST_RE."""
    reason = pre_tool_use.check_trust_root_write({
        "file_path": "/home/x/.willow/mcp_apps/./willow/manifest.json",
        "content": '{"permissions": ["task_net"]}',
    })
    assert reason is not None


# ── check_agent_spawn: round-4 rework, six items from Loki's fourth audit ──
# (handoff session_handoff-2026-09-21-78b89408, dispatch 84973DD7).

def test_agent_spawn_comma_start_single_quoted_opening_blocks_fork():
    """(1) MANDATORY: the comma-start tier's docstring claimed a quoted
    opening ("'Hanuman', go") was detected, but `^\\**%s` had no leading
    -quote option and only the trailing-quote form actually matched. An
    optional leading quote is now consumed right at the `^` anchor."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "'Hanuman', go build it", subagent_type="fork"))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "fork" in reason


def test_agent_spawn_comma_start_double_quoted_opening_blocks_fork():
    """(1) Same fix, double-quoted form."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        '"Hanuman", go build', subagent_type="fork"))
    assert result is not None
    assert "fork" in result[1]


def test_agent_spawn_comma_start_curly_quoted_opening_blocks_fork():
    """(1) Same fix, curly-quoted form."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "‘Hanuman’, go build", subagent_type="fork"))
    assert result is not None
    assert "fork" in result[1]


def test_agent_spawn_session_enter_stray_close_paren_before_app_id_blocks_willow():
    """(2) A `)` inside a string argument BEFORE app_id used to close the
    paren-depth walk early, falling to the bare tier where the willow
    refusal never fires."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(note="a ) b", app_id="willow")'))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason and "human-orchestrator" in reason


def test_agent_spawn_app_id_f_string_prefix_pins_hanuman():
    """(3) `app_id=f"hanuman"` used to let _APP_ID_RE capture the `f` prefix
    itself as the id, naming no seat at any tier — a specialist spawn with
    no pin at all. The prefix is now consumed and discarded."""
    blocked = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id=f"hanuman", session_id="x")'))
    assert blocked is not None
    decision, reason = blocked
    assert decision == "block"
    assert "hanuman" in reason and "sonnet" in reason

    allowed = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id=f"hanuman", session_id="x")', model="sonnet"))
    assert allowed is None


def test_agent_spawn_app_id_r_string_prefix_pins_hanuman():
    """(3) Same fix, raw-string prefix."""
    allowed = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id=r"hanuman", session_id="x")', model="sonnet"))
    assert allowed is None
    blocked = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id=r"hanuman", session_id="x")'))
    assert blocked is not None and blocked[0] == "block"


def test_agent_spawn_app_id_b_string_prefix_pins_hanuman():
    """(3) Same fix, bytes-string prefix."""
    blocked = pre_tool_use.check_agent_spawn(_spawn_input(
        'session_enter(app_id=b"hanuman", session_id="x")'))
    assert blocked is not None and blocked[0] == "block"


def test_agent_spawn_underscore_bold_you_are_willow_refused():
    """(4) `__Willow__` (underscore emphasis) used to pass through
    undetected — only asterisk-only bolding was matched."""
    result = pre_tool_use.check_agent_spawn(_spawn_input("You are __Willow__"))
    assert result is not None
    decision, reason = result
    assert decision == "block"
    assert "willow" in reason and "human-orchestrator" in reason


def test_agent_spawn_bold_quoted_you_are_willow_refused():
    """(4) `**'Willow'**` — bold wrapped around a quoted name — used to pass
    through undetected."""
    result = pre_tool_use.check_agent_spawn(_spawn_input("You are **'Willow'**"))
    assert result is not None
    assert result[0] == "block" and "willow" in result[1]


def test_agent_spawn_underscore_you_are_hanuman_pins_sonnet():
    """(4) Same underscore-emphasis fix, non-orchestrator variant, proving
    the builder pin is still enforced (not just a hard refusal)."""
    blocked = pre_tool_use.check_agent_spawn(_spawn_input("You are _Hanuman_"))
    assert blocked is not None
    decision, reason = blocked
    assert decision == "block"
    assert "hanuman" in reason and "sonnet" in reason

    allowed = pre_tool_use.check_agent_spawn(_spawn_input(
        "You are _Hanuman_", model="sonnet"))
    assert allowed is None


def test_agent_spawn_allows_curly_possessive_willows_auditor():
    """(5) `You are Willow's auditor` (U+2019 curly apostrophe) hard
    -refused as the orchestrator seat — the trailing-apostrophe exclusion
    was ASCII `'` only while the leading-quote class on the same line
    already listed the curly forms."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "You are Willow’s auditor"))
    assert result is None


def test_agent_spawn_allows_mixed_case_handoff_read_lookup():
    """(6) `Handoff_Read(...)` on Explore used to pin sonnet because
    `names_pattern` lacked `re.IGNORECASE` — a capitalised lookup call was
    never masked out before the bare-app_id tier ran."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        'Handoff_Read(app_id="hanuman", handoff_id="x")',
        subagent_type="Explore"))
    assert result is None


def test_agent_spawn_allows_willow_adjacent_hyphen_compound():
    """(6) `You are Willow-adjacent support` hard-refused — the "You are"
    tier's trailing-boundary exclusion did not exclude a hyphen, unlike the
    comma-start tier's equivalent exclusion."""
    result = pre_tool_use.check_agent_spawn(_spawn_input(
        "You are Willow-adjacent support"))
    assert result is None
