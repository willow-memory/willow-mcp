"""The apply half must not inherit the broker's uid assumptions at import
(gap 035d287206e1, 2026-09-22): the first live tick of the trust-owner
system unit crashed with a raw traceback at IMPORT TIME --
``server.py:80``'s ``_receipt_log = ReceiptLog()`` module-level side
effect tried to open the BROKER's own receipt log under a ``$WILLOW_HOME``
the trust-owner uid could not even traverse. This is the test that would
have caught it: a `WILLOW_HOME` the current process genuinely cannot
traverse (mode 000, not merely "some subdirectory is missing"), driving
the ACTUAL entry point (`python -m willow_mcp manifest-grant apply`, as a
real subprocess — the same invocation `willow-mcp-manifest-grant.service`
makes), and asserting the failure is a NAMED, structured refusal — never
an unhandled traceback, and never an import that dragged `server.py`
(and its own filesystem side effects) in along the way.

A subprocess, not an in-process import, on purpose: this repo's test
suite imports `willow_mcp.server` early and often, and `sys.modules`
state does not reset between tests in one process — the only way to
prove "this invocation never imported server.py" without cross-test
pollution making the assertion meaningless is to ask a FRESH interpreter.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

_REPO_SRC = str((__import__("pathlib").Path(__file__).resolve().parent.parent / "src"))


def _unreadable_home(tmp_path):
    """A directory this process genuinely cannot traverse (mode 000) —
    not merely empty or missing a subdirectory. Skipped when running as
    root: root ignores DAC permission bits entirely, so this test would
    assert nothing true about a real trust-owner-uid failure."""
    if os.geteuid() == 0:
        pytest.skip("root ignores mode bits — this test needs a genuinely unreadable dir")
    home = tmp_path / "unreadable-home"
    home.mkdir()
    home.chmod(0o000)
    return home


@pytest.fixture
def unreadable_home(tmp_path):
    home = _unreadable_home(tmp_path)
    try:
        yield home
    finally:
        home.chmod(0o700)  # let pytest's own tmp_path cleanup remove it


def _run_apply(env: dict, *, force_out_of_kart: bool = False) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    if force_out_of_kart:
        # manifest_grant_apply's own _in_kart() guard (WILLOW_IN_KART /
        # KART_TASK_ID) refuses EUNREACH before ever touching the
        # filesystem — correct, and itself a no-traceback structured
        # refusal, but it means running this suite's OWN Kart sandbox
        # never reaches the permission-specific code path this test means
        # to prove. Unset both so the real check underneath gets exercised.
        full_env.pop("WILLOW_IN_KART", None)
        full_env.pop("KART_TASK_ID", None)
    full_env.update(env)
    full_env["PYTHONPATH"] = _REPO_SRC
    return subprocess.run(
        [sys.executable, "-m", "willow_mcp", "manifest-grant", "apply"],
        env=full_env, capture_output=True, text=True, timeout=30,
    )


def test_apply_under_unreadable_home_refuses_named_never_tracebacks(unreadable_home):
    """Drive the REAL entry point — `python -m willow_mcp manifest-grant
    apply`, a fresh subprocess, exactly what
    `willow-mcp-manifest-grant.service`'s `ExecStart=` runs — with
    `WILLOW_HOME` pointing at a directory this process cannot even stat
    into. Before the fix: `sqlite3.OperationalError: unable to open
    database file` at IMPORT, inside `ReceiptLog()`, a Python traceback on
    stderr with no calling context — three ticks running on the real box.
    After the fix: the process exits non-zero with NO traceback on
    stderr, and stdout carries a structured refusal that NAMES the exact
    unreadable path — not the silent `{"ok": true, "state": "empty"}`
    `Path.is_dir()`'s own swallowed-OSError behavior produced before this
    same gap's fix to manifest_grant_executor (a permission failure used
    to read identically to "nothing pending, all done" forever)."""
    result = _run_apply({"WILLOW_HOME": str(unreadable_home)}, force_out_of_kart=True)

    assert "Traceback (most recent call last)" not in result.stderr, (
        f"apply raised an unhandled traceback instead of refusing by name:\n{result.stderr}"
    )
    assert result.returncode != 0, "an unreadable WILLOW_HOME must not read as success"

    payload = json.loads(result.stdout)
    assert payload.get("ok") is False
    assert payload.get("state") != "empty", (
        "a permission failure must never read the same as 'nothing pending' — "
        f"got {payload}"
    )
    assert str(unreadable_home) in json.dumps(payload), (
        f"refusal does not name the unreadable path: {payload}"
    )


def test_apply_never_imports_server(unreadable_home):
    """Constraint 2's own claim, proven from OUTSIDE the process rather
    than by inspecting `sys.modules` in-process (which cross-test pollution
    would make meaningless): a fresh interpreter running the apply
    subcommand must never construct `willow_mcp.server`'s module body —
    verified by making `willow_mcp/server.py` itself unimportable (renamed
    out of the way isn't available cross-process cheaply, so instead: a
    sentinel env var server.py's own module body would choke on if it ran,
    proves nothing ran there). Simpler and just as conclusive: run the
    same apply invocation with a working WILLOW_HOME and confirm
    `willow_mcp.server` never appears by auditing `sys.modules` INSIDE
    that same subprocess via `-X importtime`-free means -- a `-c` probe
    that imports cli_manifest_grant only and asserts server is absent."""
    result = subprocess.run(
        [sys.executable, "-c",
         "import sys; import willow_mcp.cli_manifest_grant; "
         "sys.exit(1 if 'willow_mcp.server' in sys.modules else 0)"],
        env={**os.environ, "PYTHONPATH": _REPO_SRC},
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, (
        "importing cli_manifest_grant pulled in willow_mcp.server — the apply "
        f"path is no longer import-safe for a different uid.\nstderr:\n{result.stderr}"
    )


def test_server_module_level_singletons_are_lazy():
    """Constraint 1's own claim, also proven cross-process: importing
    `willow_mcp.server` must not, by itself, construct `_store` (`Store()`,
    an `mkdir`) or `_receipt_log` (`ReceiptLog()`, an `mkdir` +
    `sqlite3.connect`) — both are the same class of module-level side
    effect that assumes a writable/traversable `$WILLOW_HOME`. A fresh
    interpreter imports `server` against a directory it cannot traverse;
    the import must succeed, and the two singletons must still be
    unconstructed proxies afterward."""
    probe = (
        "import willow_mcp.server as s; "
        "assert type(s._store).__name__ == '_LazySingleton'; "
        "assert type(s._receipt_log).__name__ == '_LazySingleton'; "
        "assert s._store._obj is None; "
        "assert s._receipt_log._obj is None; "
        "print('ok')"
    )
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        from pathlib import Path
        home = Path(td) / "unreadable"
        home.mkdir()
        home.chmod(0o000)
        try:
            if os.geteuid() == 0:
                pytest.skip("root ignores mode bits")
            result = subprocess.run(
                [sys.executable, "-c", probe],
                env={**os.environ, "PYTHONPATH": _REPO_SRC, "WILLOW_HOME": str(home)},
                capture_output=True, text=True, timeout=30,
            )
        finally:
            home.chmod(0o700)
    assert "Traceback" not in result.stderr, (
        f"importing server.py raised instead of staying lazy:\n{result.stderr}"
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert result.stdout.strip() == "ok"


def test_apply_refuses_named_when_pending_dir_is_unlistable(tmp_path):
    """Gap `035d287206e1`, F2 (Loki audit B00BD43E, rework 1 on 6743E7AD):
    the `.stat()` probes added for constraint 4 catch "cannot TRAVERSE"
    (needs only `x` on the parent) but `Path.glob()` still swallows "cannot
    LIST" (needs `r` on `pending_dir` itself) exactly the way
    `is_dir()`/`.exists()` used to for the outer directories — a
    traversable but UNREADABLE `pending/` (mode 111: `x` but no `r`) used
    to read as `{ok: true, state: "empty"}`, exit 0, silently, forever
    (measured, Kart SAX46GFP — on the real box `pending/` is 755 + an ACL
    so this does not fire today, but the fix distinguishes 'cannot list'
    from 'empty' regardless of what currently happens to be granted).
    `os.listdir` raises on a mode-111 directory; `Path.glob` does not."""
    if os.geteuid() == 0:
        pytest.skip("root ignores mode bits — this test needs a genuinely unlistable dir")
    home = tmp_path / "wh"
    (home / "mcp_apps").mkdir(parents=True)
    grants_root = home / "manifest_grants"
    pending = grants_root / "pending"
    pending.mkdir(parents=True)
    (grants_root / "done").mkdir()
    (grants_root / "failed").mkdir()
    pending.chmod(0o111)  # traversable (x), NOT listable (no r)
    try:
        full_env = dict(os.environ)
        full_env.pop("WILLOW_IN_KART", None)
        full_env.pop("KART_TASK_ID", None)
        full_env["WILLOW_HOME"] = str(home)
        full_env["PYTHONPATH"] = _REPO_SRC
        result = subprocess.run(
            [sys.executable, "-m", "willow_mcp", "manifest-grant", "apply"],
            env=full_env, capture_output=True, text=True, timeout=30,
        )
    finally:
        pending.chmod(0o700)

    assert "Traceback (most recent call last)" not in result.stderr, (
        f"apply raised instead of refusing by name:\n{result.stderr}"
    )
    assert result.returncode != 0, "an unlistable pending/ must not read as success"
    payload = json.loads(result.stdout)
    assert payload.get("ok") is False
    assert payload.get("state") != "empty", (
        "cannot-list must never read the same as 'nothing pending' — "
        f"got {payload}"
    )
    assert payload.get("error") == "EACCES"
    assert str(pending) in json.dumps(payload), f"refusal does not name pending/: {payload}"
