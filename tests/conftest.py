"""Session-wide test isolation.

willow_mcp.server creates a module-level Store() and ReceiptLog() at import
time, and gate.py resolves its manifest root from WILLOW_MCP_APPS_ROOT/
WILLOW_HOME at call time. Point all of these at a throwaway tmp directory
before any test module can import willow_mcp.server, so the test suite never
touches a real $WILLOW_HOME on the machine running it.
"""
import os
import tempfile

import pytest

# Force these to the throwaway tmp home — do NOT setdefault. A caller may have
# WILLOW_HOME/WILLOW_STORE_ROOT exported (e.g. willow-mcp's own SessionStart
# hook sets them for every web session); setdefault would silently defer to
# those and run the suite against a real store — polluting it and failing the
# gaps/knowledge tests on accumulated rows. Isolation must not be overridable
# by the ambient environment.
_tmp = tempfile.mkdtemp(prefix="willow_mcp_test_home_")
os.environ["WILLOW_HOME"] = _tmp
os.environ["WILLOW_STORE_ROOT"] = os.path.join(_tmp, "store")
os.environ["WILLOW_MCP_RECEIPT_DB"] = os.path.join(_tmp, "mcp_receipt.db")
os.environ["WILLOW_MCP_APPS_ROOT"] = os.path.join(_tmp, "mcp_apps")
# The egress config dir lives OUTSIDE $WILLOW_HOME by design (keys must not sit
# in a sandbox mount), so the isolation above does not cover it. Without this
# line, `home_init.ensure_home_layout` -> `egress_setup.ensure_keypair` ->
# `save_manifest` writes the operator's REAL ~/.config/willow-mcp/egress/
# manifest.json from inside the suite. On a box where harden-trust-root has
# put that file under a separate uid, 52 tests fail with PermissionError; on a
# box where it has not, the suite silently rewrites the operator's manifest.
os.environ["WILLOW_MCP_EGRESS_CONFIG_DIR"] = os.path.join(_tmp, "egress")
# `paths.trusted_read` refuses a governance input that is group- or
# other-writable. pytest's tmp files take the runner's umask, so under a 002
# umask (a Kart sandbox, some CI images) every fixture pre-approved.json and
# FRANK anchor is born 664 and 37 tests fail with "untrusted ownership or
# permissions" — a property of the shell, not the code. Pin the umask the
# trust check assumes; a test that means to exercise the refusal chmods on
# purpose and is unaffected.
os.umask(0o022)

# The same principle applied to the variables that decide GATE OUTCOMES rather
# than paths. The list above pinned where the suite reads and writes; these
# decide what it is allowed to do, and inheriting them makes a test's result a
# property of the machine it ran on.
#
#   WILLOW_MCP_STRICT_TRUST_ROOT — with it set, every gate that consults
#     lease.self_writable_trust_paths() denies, because a pytest tmp_path is
#     always writable by the test uid. That is not a finding, it is the
#     definition of a tmp directory. Six tests across test_server.py failed this
#     way on any install running strict mode, each reporting `trust_root_denied`
#     while claiming to be about network envelope authorization.
#   WILLOW_IN_KART — require_operator_terminal checks this BEFORE isatty, so a
#     suite run inside the Kart sandbox refuses mutations for a different reason
#     than the one the tests name, in different words.
#   WILLOW_PGP_FINGERPRINT — with it set, gate._read_manifest requires a detached
#     signature, and no manifest a test writes has one. 23 tests across
#     test_gate.py and test_manifest_admin.py failed on an install with
#     enforcement on, every one of them reporting an unrelated assertion about
#     permissions or store scope. The tests that mean to exercise enforcement
#     monkeypatch gate.pgp directly and are unaffected by this.
#
# A test that needs any of these ON sets it itself with monkeypatch.setenv, which
# overrides these — deliberate setters keep working, ambient ones stop deciding.
os.environ.pop("WILLOW_MCP_STRICT_TRUST_ROOT", None)
os.environ.pop("WILLOW_IN_KART", None)
os.environ.pop("WILLOW_PGP_FINGERPRINT", None)
os.environ.pop("NESTOR_KEYRING", None)
os.environ.pop("NESTOR_DB", None)
os.environ.pop("NESTOR_REQUIRE_SEAL_KEY", None)


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Per-test isolated $WILLOW_HOME + aligned mcp_apps/store roots."""
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    monkeypatch.setenv("WILLOW_MCP_EGRESS_CONFIG_DIR", str(tmp_path / "egress"))
    monkeypatch.delenv("WILLOW_HUMAN_ORCHESTRATOR", raising=False)
    return tmp_path


@pytest.fixture(autouse=True)
def _stub_egress_public_key_for_diagnostics(request, monkeypatch, tmp_path):
    """CI has no ~/.config/willow-mcp/egress keys; most tests call _derive_problems.

    Also stubs `resolve_private_key_path` to None (#182): the dev box running
    this suite may have a REAL ~/.config/willow-mcp/egress/private.pem from
    earlier manual testing, and `egress_key_readable_by_self()` reading it for
    real (correctly!) makes trust-root/diagnostic tests fail based on an
    accident of the host running them, not the code under test — the same
    hermeticity problem the public-key stub above already exists to prevent,
    now that private-key readability is also part of what gets checked.
    """
    mod = getattr(request.module, "__name__", "")
    if "test_egress" in mod:
        return
    try:
        import willow_mcp.egress_setup as egress_setup
    except ModuleNotFoundError:
        # e.g. pytest without `pip install -e .` / pythonpath — skills-only tests
        # should still run; the rest of the suite needs the package on the path.
        return
    pub = tmp_path / "egress-stub.pub"
    pub.write_text("stub", encoding="utf-8")
    monkeypatch.setattr(egress_setup, "resolve_public_key_path", lambda: pub)
    monkeypatch.setattr(egress_setup, "resolve_private_key_path", lambda: None)
