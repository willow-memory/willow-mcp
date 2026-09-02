"""Integration adapters — the ledger is honest and the egress gate is real.

Properties under test:
  * a declared stub is listable, refuses with its reason, and NEVER opens a
    socket — the anti-pattern this module replaces is the silent empty file;
  * egress needs all three keys (integration_net + consent.internet + lease),
    checked fail-closed in that order, and integration_net is its own line —
    task_net and full_access never imply it;
  * credentials resolve env-before-vault and never appear in any output;
  * transport retries are bounded and honor Retry-After.
"""
import io
import json
import urllib.error
import urllib.request

import pytest

from willow_mcp import integrations, lease
from willow_mcp import server


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    monkeypatch.delenv("WILLOW_SETTINGS_GLOBAL", raising=False)
    monkeypatch.delenv("WILLOW_MCP_STRICT_TRUST_ROOT", raising=False)
    return tmp_path


def _manifest(home, app_id="testapp", permissions=None):
    app_dir = home / "mcp_apps" / app_id
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "manifest.json").write_text(
        json.dumps({"permissions": permissions or ["full_access"]}))
    return app_id


def _consent_yes(home):
    (home / "settings.global.json").write_text(
        json.dumps({"version": 1, "consent": {"internet": True}}))


def _no_network(monkeypatch):
    """Any socket attempt fails the test loudly."""
    def _boom(*a, **k):
        raise AssertionError("network call attempted")
    monkeypatch.setattr(integrations.urllib.request, "urlopen", _boom)


# ── the ledger ────────────────────────────────────────────────────────────────

def test_registry_lists_live_and_stub_adapters():
    rows = integrations.list_integrations()
    by_status = {}
    for r in rows:
        by_status.setdefault(r["status"], []).append(r["name"])
    assert "github" in by_status["live"]
    assert "huggingface" in by_status["live"]
    assert "jeles" in by_status["live"]
    assert "utety" in by_status["live"]
    assert "pangolin" in by_status["live"]
    assert len(by_status["live"]) == 5
    assert len(by_status["stub"]) == 6


def test_jeles_adapter_wired_live_with_secret_header():
    """ask-jeles is a live adapter using shared-secret auth in the
    X-Jeles-Secret header (not Bearer), credential required, fixed HTTPS host."""
    a = integrations.get("jeles")
    assert a is not None and a.status == "live"
    assert a.credential_required is True
    assert a.auth_header == "X-Jeles-Secret"
    assert a.auth_prefix == ""
    assert a.base_url.startswith("https://")
    # the secret rides raw in its own header — no "Bearer " prefix, and never the
    # Authorization header (jeles-remote hmac-compares X-Jeles-Secret directly).
    headers = a._headers("s3cr3t")
    assert headers["X-Jeles-Secret"] == "s3cr3t"
    assert "Authorization" not in headers


def test_every_stub_declares_needs_and_earned_by():
    """A stub without a reason and an earn condition is just an empty file
    wearing a registry entry."""
    for row in integrations.list_integrations():
        if row["status"] == "stub":
            assert row["needs"], f"{row['name']} declares no 'needs'"
            assert row["earned_by"], f"{row['name']} declares no 'earned_by'"


def test_stub_refuses_and_never_touches_network(monkeypatch):
    _no_network(monkeypatch)
    out = integrations.get("slack").request("POST", "/chat.postMessage",
                                            body={"text": "hi"})
    assert out["error"] == "not_implemented"
    assert out["status"] == "stub"
    assert out["needs"]


def test_unknown_integration_is_named():
    assert integrations.get("salesforce") is None


# ── the three-key egress gate ─────────────────────────────────────────────────

def test_egress_denied_without_capability(home):
    """full_access alone must not open the lane (own-line rule)."""
    app = _manifest(home, permissions=["full_access"])
    _consent_yes(home)
    lease.grant(app, 600, issuer="test")
    denial = integrations.egress_denial(app)
    assert denial and denial["error"].startswith("net_denied")


def test_task_net_does_not_imply_integration_net(home):
    """Sandbox egress and server-process egress are different lanes."""
    app = _manifest(home, permissions=["integration_call", "task_net"])
    _consent_yes(home)
    lease.grant(app, 600, issuer="test")
    denial = integrations.egress_denial(app)
    assert denial and denial["error"].startswith("net_denied")


def test_egress_denied_without_consent(home):
    app = _manifest(home, permissions=["integration_net"])
    lease.grant(app, 600, issuer="test")
    denial = integrations.egress_denial(app)
    assert denial and denial["error"].startswith("consent_denied")


def test_egress_denied_without_lease(home):
    app = _manifest(home, permissions=["integration_net"])
    _consent_yes(home)
    denial = integrations.egress_denial(app)
    assert denial and denial["error"].startswith("lease_denied")


def test_egress_passes_with_all_three_keys(home):
    app = _manifest(home, permissions=["integration_net"])
    _consent_yes(home)
    lease.grant(app, 600, issuer="test")
    assert integrations.egress_denial(app) is None


def test_strict_trust_root_denies_forgeable_keys(home, monkeypatch):
    app = _manifest(home, permissions=["integration_net"])
    _consent_yes(home)
    lease.grant(app, 600, issuer="test")
    monkeypatch.setenv("WILLOW_MCP_STRICT_TRUST_ROOT", "1")
    denial = integrations.egress_denial(app)
    assert denial and denial["error"].startswith("trust_root_denied")


# ── credentials ───────────────────────────────────────────────────────────────

def test_credential_env_beats_vault_and_reports_source(home, monkeypatch):
    monkeypatch.setenv("WILLOW_GITHUB_TOKEN", "env-tok")
    gh = integrations.get("github")
    assert gh.credential() == "env-tok"
    assert gh.credential_source() == "env:WILLOW_GITHUB_TOKEN"


def test_credential_absent_reports_none(home, monkeypatch):
    for var in ("WILLOW_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    gh = integrations.get("github")
    assert gh.credential_source() is None


def test_ledger_never_carries_the_credential(home, monkeypatch):
    secret = "ghp_supersecret12345"
    monkeypatch.setenv("WILLOW_GITHUB_TOKEN", secret)
    dumped = json.dumps(integrations.list_integrations())
    assert secret not in dumped
    dumped = json.dumps(integrations.status("anyapp", "github"))
    assert secret not in dumped


def test_error_detail_is_scrubbed_of_credential(home, monkeypatch):
    secret = "tok-leakme"
    monkeypatch.setenv("WILLOW_GITHUB_TOKEN", secret)

    def _fail(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 401, "Unauthorized", {},
            io.BytesIO(f"bad token {secret}".encode()))
    monkeypatch.setattr(integrations.urllib.request, "urlopen", _fail)
    out = integrations.get("github").request("GET", "/user")
    assert out["error"] == "http_401"
    assert secret not in json.dumps(out)


# ── transport ─────────────────────────────────────────────────────────────────

class _FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json"}

    def read(self, n=-1):
        return b'{"ok": true}'

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_retry_honors_retry_after_and_is_bounded(home, monkeypatch):
    calls, sleeps = [], []

    def _urlopen(req, timeout=None):
        calls.append(req.full_url)
        if len(calls) < 3:
            raise urllib.error.HTTPError(
                req.full_url, 429, "rate limited",
                {"Retry-After": "7"}, io.BytesIO(b""))
        return _FakeResponse()

    monkeypatch.setattr(integrations.urllib.request, "urlopen", _urlopen)
    monkeypatch.setattr(integrations.time, "sleep", sleeps.append)
    out = integrations.get("github").request("GET", "/rate_limit")
    assert out == {"status": 200, "body": {"ok": True}}
    assert len(calls) == 3          # bounded at _MAX_ATTEMPTS
    assert sleeps == [7.0, 7.0]     # Retry-After honored


def test_retries_exhaust_to_an_error_not_an_exception(home, monkeypatch):
    def _urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 503, "down", {}, io.BytesIO(b""))
    monkeypatch.setattr(integrations.urllib.request, "urlopen", _urlopen)
    monkeypatch.setattr(integrations.time, "sleep", lambda s: None)
    out = integrations.get("github").request("GET", "/user")
    assert out["error"] == "http_503"


def test_path_validation_rejects_repointing(home, monkeypatch):
    _no_network(monkeypatch)
    gh = integrations.get("github")
    for bad in ("user", "//evil.example/x", "/a b", "/x\n", "/a/../b", ""):
        out = gh.request("GET", bad)
        assert "bad_path" in out["error"], f"{bad!r} was accepted"


def test_bad_method_rejected(home, monkeypatch):
    _no_network(monkeypatch)
    out = integrations.get("github").request("TRACE", "/user")
    assert "bad_method" in out["error"]


def test_oversized_body_rejected_before_network(home, monkeypatch):
    _no_network(monkeypatch)
    out = integrations.get("github").request(
        "POST", "/x", body={"blob": "x" * (600 * 1024)})
    assert "body_too_large" in out["error"]


# ── MCP tool surface ──────────────────────────────────────────────────────────

def test_integration_list_tool_is_gated(home):
    out = server.integration_list(app_id="ghost")
    assert "gate denied" in out["error"]


def test_full_access_grants_ledger_but_not_call(home):
    app = _manifest(home, permissions=["full_access"])
    out = server.integration_list(app_id=app)
    assert len(out["integrations"]) == 11
    out = server.integration_call(app_id=app, name="github", method="GET", path="/user")
    assert "gate denied" in out["error"]


def test_integration_call_happy_path(home, monkeypatch):
    app = _manifest(home, permissions=["integration_call", "integration_net"])
    _consent_yes(home)
    lease.grant(app, 600, issuer="test")
    monkeypatch.setattr(integrations.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResponse())
    out = server.integration_call(app_id=app, name="github",
                                  method="GET", path="/user")
    assert out == {"status": 200, "body": {"ok": True}}


def test_integration_call_unknown_adapter_names_the_known(home):
    app = _manifest(home, permissions=["integration_call", "integration_net"])
    out = server.integration_call(app_id=app, name="salesforce",
                                  method="GET", path="/x")
    assert "unknown_integration" in out["error"]
    assert "github" in out["known"]


def test_integration_status_reads_gate_without_network(home, monkeypatch):
    _no_network(monkeypatch)
    app = _manifest(home, permissions=["integration_read"])
    out = server.integration_status(app_id=app, name="gmail")
    assert out["status"] == "stub"
    assert out["egress"] == "denied"
    assert out["egress_denial"] == "net_denied"


# ── pangolin: the adapter that controls what this box exposes ─────────────────

def test_pangolin_is_registered_live_and_host_pinned():
    a = integrations.get("pangolin")
    assert a is not None and a.status == "live"
    # base_url owns scheme + host, and _PATH_RE forbids a path re-pointing
    # either. That property is load-bearing here in a way it is not for a
    # read-only adapter: this one creates and deletes PUBLIC resources, so a
    # re-pointable host would be an attacker choosing which control plane the
    # fleet's credential is presented to.
    assert a.base_url == "https://api.pangolin.net/v1"
    assert a.base_url.startswith("https://")


def test_pangolin_requires_a_credential_before_egress(monkeypatch):
    # There are no anonymous reads on this API. Failing at the adapter rather
    # than at the far end means a keyless call never opens a socket at all.
    a = integrations.get("pangolin")
    for var in a.env_vars:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(type(a), "credential", lambda self: None)

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("opened a socket without a credential")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    out = a.request("GET", "/org/willow/public-resources")
    assert "error" in out
    assert "credential" in out["error"].lower()


def test_pangolin_credential_env_vars_are_declared():
    a = integrations.get("pangolin")
    assert "WILLOW_PANGOLIN_TOKEN" in a.env_vars
    # env beats vault (BaseAdapter.credential), so the operator's export always
    # wins over stored state — same rule as every other adapter.
    assert a.env_vars[0] == "WILLOW_PANGOLIN_TOKEN"


def test_pangolin_egress_needs_integration_net_like_any_other(home):
    # No exemption for the tunnel's own control plane: task_net and full_access
    # never imply integration_net (B-19, egress is granted on its own line).
    _manifest(home, "tunneler", permissions=["full_access", "task_net"])
    denial = integrations.egress_denial("tunneler")
    assert denial is not None
    assert "integration_net" in json.dumps(denial)
