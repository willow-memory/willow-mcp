"""Outbound integration adapters — external HTTP APIs, behind the egress gate.

Provenance: mined from an over-scoped monorepo sketch (fifty adapters, seven
apps, three message buses — none of it built). What survived the mining is the
one idea worth keeping: a shared adapter base (auth, retry, bounded transport)
plus per-service adapters. What did NOT survive is the scaffolding philosophy.
Surface here is **earned**: an adapter is implemented when work in this fleet
actually needs it, and until then it exists only as a *declared stub* — listed,
counted, fail-closed, and naming what would earn its implementation. A declared
stub is the opposite of an empty file: it can be asked, it answers honestly,
and `integration_list` shows the ledger instead of a directory tree implying
work that never happened.

**Egress.** These adapters make network calls from the SERVER process — the
host lane, not the Kart sandbox. That is a fourth consumer of the three-key
egress gate (`task_submit` was the first), and it gets its OWN capability line:

    integration_net    manifest capability      "this app may ever call out"
    consent.internet   operator switch          "egress is permitted right now"
    lease              time-boxed grant         "this app, until T"

`integration_net` is deliberately NOT `task_net` (B-19: egress is granted on
its own line, never inherited). `task_net` authorizes egress from inside a
network-namespaced sandbox; this module egresses as the server's own uid, with
the server's own filesystem view — a strictly more privileged lane, so holding
one must never imply the other. All three keys are checked by `egress_denial()`
before any adapter touches a socket; a stub never touches one at all.

**Credentials.** Resolved per adapter: environment variable first (operator
export beats stored state), then the vault under `integration/<name>/token`.
Secrets are used in request headers and never returned by any tool, list, or
error — `credential_source()` reports *where* a credential came from, not what
it is, and error details are scrubbed of the credential before they leave.

**Transport.** Stdlib urllib only — no new dependency for the sake of two live
adapters. HTTPS only, fixed per-adapter host (a path cannot re-point the URL),
30s timeout, ≤3 attempts with backoff honoring Retry-After on 429/5xx, response
bodies capped at 2MB.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

logger = logging.getLogger("willow_mcp.integrations")

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_BODY_BYTES = 512 * 1024
_MAX_ATTEMPTS = 3
_MAX_BACKOFF_SECONDS = 30
_TIMEOUT_SECONDS = 30
_RETRYABLE = {429, 500, 502, 503, 504}
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})

# A request path: leading single slash (no protocol-relative "//host"), no
# whitespace or control characters, no dot-dot segments. The adapter's base_url
# owns scheme and host; the path must not be able to re-point either.
# fullmatch, not `$`: `$` matches before a trailing newline, which would let
# "/x\n" through.
_PATH_RE = re.compile(r"/(?!/)[^\s\x00-\x1f]*")


def vault_key(name: str) -> str:
    return f"integration/{name}/token"


class BaseAdapter:
    """One external service. Subclasses set the class attributes; live adapters
    inherit `request()`, stubs override it to refuse."""

    name: str = ""
    base_url: str = ""          # scheme + host (+ root path), no trailing slash
    status: str = "live"        # "live" | "stub"
    doc: str = ""               # one line: what this adapter is for
    env_vars: tuple = ()        # credential env vars, in precedence order
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    credential_required: bool = False
    extra_headers: Optional[dict] = None

    # ── credentials ──────────────────────────────────────────────────────────

    def credential(self) -> Optional[str]:
        for var in self.env_vars:
            val = os.environ.get(var, "").strip()
            if val:
                return val
        try:
            from .vault import default_vault
            return default_vault().read(vault_key(self.name))
        except Exception as e:
            # An unreadable vault is "no stored credential", not a crash — env
            # vars still work, and status() reports source None.
            logger.warning("integrations: vault unavailable for %s: %s", self.name, e)
            return None

    def credential_source(self) -> Optional[str]:
        """Where a credential would come from — never the credential itself."""
        for var in self.env_vars:
            if os.environ.get(var, "").strip():
                return f"env:{var}"
        try:
            from .vault import default_vault
            if default_vault().has(vault_key(self.name)):
                return "vault"
        except Exception:
            logger.debug("vault check failed for %s", self.name, exc_info=True)
        return None

    # ── transport ────────────────────────────────────────────────────────────

    def _headers(self, cred: Optional[str]) -> dict:
        headers = {
            "Accept": "application/json",
            "User-Agent": "willow-mcp-integrations",
            **(self.extra_headers or {}),
        }
        if cred:
            headers[self.auth_header] = f"{self.auth_prefix}{cred}"
        return headers

    def _scrub(self, text: str, cred: Optional[str]) -> str:
        """No error detail leaves this module carrying the credential."""
        if cred and cred in text:
            text = text.replace(cred, "***")
        return text

    def request(self, method: str, path: str,
                params: Optional[dict] = None,
                body: Optional[dict] = None) -> dict:
        """One bounded HTTPS call. Returns {"status", "body"} or {"error", ...}.

        Callers (the `integration_call` tool, the CLI `check`) are responsible
        for the egress gate — this method assumes the three keys were checked.
        """
        method = str(method or "").upper()
        if method not in _METHODS:
            return {"error": f"bad_method: {method!r} — one of {sorted(_METHODS)}"}
        if not isinstance(path, str) or len(path) > 2048 or not _PATH_RE.fullmatch(path):
            return {"error": "bad_path: must start with a single '/', no whitespace "
                             "or control characters, max 2048 chars"}
        if ".." in path:
            return {"error": "bad_path: dot-dot segments are not allowed"}

        # base_url is a per-adapter class attribute, but 2 live adapters
        # (jeles, utety) let an operator override it via env var (see class
        # docstrings below) — so scheme is a config value, not a hardcoded
        # constant, and gets a real check rather than a blanket nosec.
        if urllib.parse.urlparse(self.base_url).scheme != "https":
            return {"error": f"bad_base_url: adapter '{self.name}' base_url "
                             f"must be https, got {self.base_url!r}"}

        url = self.base_url + path
        if params:
            if not isinstance(params, dict):
                return {"error": "bad_params: expected an object"}
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(
                {str(k): str(v) for k, v in params.items()})

        data = None
        if body is not None:
            encoded = json.dumps(body).encode("utf-8")
            if len(encoded) > _MAX_BODY_BYTES:
                return {"error": f"body_too_large: {len(encoded)} bytes (cap {_MAX_BODY_BYTES})"}
            data = encoded

        cred = self.credential()
        if self.credential_required and not cred:
            return {"error": (
                f"no_credential: '{self.name}' requires a token — export "
                f"{' or '.join(self.env_vars)} or run "
                f"`willow-mcp-integrations set-token {self.name}`")}

        headers = self._headers(cred)
        if data is not None:
            headers["Content-Type"] = "application/json"

        last_err = "exhausted retries"
        for attempt in range(_MAX_ATTEMPTS):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:  # nosec B310 - scheme is enforced to https just above; path is regex-validated (_PATH_RE, no "//" or ".." ) and cannot repoint host
                    raw = resp.read(_MAX_RESPONSE_BYTES + 1)
                    if len(raw) > _MAX_RESPONSE_BYTES:
                        return {"error": f"response_too_large: over {_MAX_RESPONSE_BYTES} bytes"}
                    return {"status": resp.status, "body": _parse_body(raw, resp.headers)}
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read(500).decode("utf-8", errors="ignore")
                except Exception:
                    logger.debug("error body read failed", exc_info=True)
                if e.code in _RETRYABLE and attempt + 1 < _MAX_ATTEMPTS:
                    time.sleep(_retry_delay(e.headers.get("Retry-After"), attempt))
                    continue
                return {"error": f"http_{e.code}", "detail": self._scrub(detail, cred)}
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_err = self._scrub(str(e), cred)
                if attempt + 1 < _MAX_ATTEMPTS:
                    time.sleep(_retry_delay(None, attempt))
                    continue
        return {"error": "network", "detail": last_err}


def _retry_delay(retry_after: Optional[str], attempt: int) -> float:
    if retry_after:
        try:
            return min(float(retry_after), _MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(2.0 ** attempt, _MAX_BACKOFF_SECONDS)


def _parse_body(raw: bytes, headers) -> object:
    text = raw.decode("utf-8", errors="replace")
    if "json" in (headers.get("Content-Type") or ""):
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


# ── Live adapters — implemented because this fleet actually uses them ─────────

class GitHubAdapter(BaseAdapter):
    """This repo lives on GitHub; the fleet's PRs, issues, and CI do too."""
    name = "github"
    base_url = "https://api.github.com"
    doc = "GitHub REST v3 — repos, PRs, issues, checks"
    env_vars = ("WILLOW_GITHUB_TOKEN", "GITHUB_TOKEN")
    extra_headers = {"Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": os.environ.get("WILLOW_GITHUB_API_VERSION", "2022-11-28")}


class PangolinAdapter(BaseAdapter):
    """The tunnel's control plane, and therefore a control plane over what this
    box exposes to the public internet.

    Pangolin fronts `willow-mcp --serve` for the remote seat (KB 5B7F11AF /
    2026B306). Its Integration API creates, targets, protects and deletes those
    resources — so the thing being automated here is *what becomes publicly
    reachable*, which is exactly the class of action that must leave receipts
    rather than happen in a shell.

    Concretely, from `/v1/openapi.json`:
      GET    /org/{orgId}/public-resources          audit what is exposed
      GET    /org/{orgId}/sites                     connector state
      PUT    /org/{orgId}/public-resource           create
      PUT    /public-resource/{id}/target           point it at a local port
      POST   /public-resource/{id}/password|pincode|header-auth|whitelist
      PUT    /public-resource-policy/{id}/access-control
      DELETE /public-resource/{id}                  retire

    A key is always required: there are no anonymous reads, so
    `credential_required` is True and a call without one fails before egress
    rather than at the far end with a 401. Mint it at Organization -> API Keys
    with only the permissions the task needs; the key is shown once.

    The API's own docs warn that "REST API routes and behavior may include
    breaking changes between updates", so treat a shape change as expected and
    pin what this fleet depends on rather than trusting the surface.
    """
    name = "pangolin"
    base_url = "https://api.pangolin.net/v1"
    doc = "Pangolin Integration API — sites, public/private resources, targets, resource auth"
    env_vars = ("WILLOW_PANGOLIN_TOKEN", "PANGOLIN_API_KEY")
    credential_required = True


class HuggingFaceAdapter(BaseAdapter):
    """Model/dataset metadata for the fleet's local-model work. Public reads
    work without a token; a token raises rate limits and opens private repos."""
    name = "huggingface"
    base_url = "https://huggingface.co"
    doc = "Hugging Face Hub API — models, datasets, files"
    env_vars = ("WILLOW_HUGGINGFACE_TOKEN", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN")


class JelesAdapter(BaseAdapter):
    """Jeles the Librarian, remote lane. The stateless network-search half of
    legacy fleet monolith's Jeles (`core/jeles_sources.py`), hosted as `jeles-remote` on
    Fly.io: `POST /search` fans out to ~65 institutional/academic sources
    (arXiv, PubMed, Crossref, OpenAlex, Library of Congress, ...) and returns
    citable results. Corroboration across independent sources is the whole
    point — the same external-verification instinct as the lease and the
    consent gate, pointed at facts instead of egress.

    Earned by an operator request to wire ask-jeles into the MCP (the module's
    'surface is earned' rule — this adapter exists because the fleet now calls
    it, not on spec). Auth is a shared secret in the `X-Jeles-Secret` header
    (not a Bearer token), resolved from JELES_REMOTE_SECRET (env) or the vault
    under integration/jeles/token. Host is fixed per the adapter contract; set
    WILLOW_JELES_BASE_URL to point at a self-hosted deployment instead."""
    name = "jeles"
    base_url = os.environ.get(
        "WILLOW_JELES_BASE_URL", "https://jeles-remote.fly.dev").rstrip("/")
    doc = "Jeles remote — academic/institutional source search (~65 citable sources)"
    env_vars = ("JELES_REMOTE_SECRET",)
    auth_header = "X-Jeles-Secret"
    auth_prefix = ""            # raw shared secret — jeles-remote hmac-compares it, no "Bearer "
    credential_required = True


class UtetyAdapter(BaseAdapter):
    """UTETY — the classroom-grade learning product — speaking through its OWN
    mouth, never jeles's.

    Founding rule (build-plan §0.5): UTETY's product identity and egress ride a
    `UtetyAdapter` with its own `app_id` (`utety`), backend URL, and secret — so a
    student-facing call is attributable to `utety`, gated by `utety`'s manifest +
    consent + lease, and never borrows the librarian's credentials. This is the
    seam from build-plan §5.2 made concrete: *UTETY owns the pedagogy, Jeles owns
    the knowledge.* When a claim needs backing, UTETY asks Jeles a de-identified
    question through the jeles lane; but UTETY's own transport is this adapter.

    Earned by the founding decision, not spec — this is the fleet building UTETY.
    The backend (UTETY's pedagogy/knowledge service) is deployed in Phase 1;
    until then `credential_required` stays False so the identity + transport exist
    without a live endpoint to hard-fail against. Point it at the real service by
    setting WILLOW_UTETY_BASE_URL; flip `credential_required` True when the backend
    enforces auth. Host is fixed per the adapter contract (a path cannot re-point
    it), exactly like every other live adapter here."""
    name = "utety"
    base_url = os.environ.get(
        "WILLOW_UTETY_BASE_URL", "https://utety.pages.dev").rstrip("/")
    doc = "UTETY — classroom learning product; its own egress identity (backend wired in Phase 1)"
    env_vars = ("WILLOW_UTETY_SECRET",)
    auth_header = "X-Utety-Secret"
    auth_prefix = ""            # raw shared secret, mirroring the jeles lane
    credential_required = False


# ── Declared stubs — common integration points, deliberately unimplemented ────

class StubAdapter(BaseAdapter):
    """A stub that answers honestly. It is registered, listable, and refuses
    with the reason it is a stub and what earns the implementation — the
    anti-pattern it replaces is a directory of empty index.ts files."""
    status = "stub"
    needs: str = ""      # what is missing (usually an auth flow or a consumer)
    earned_by: str = ""  # the concrete fleet event that justifies building it

    def request(self, method: str, path: str,
                params: Optional[dict] = None,
                body: Optional[dict] = None) -> dict:
        return {"error": "not_implemented",
                "integration": self.name,
                "status": "stub",
                "needs": self.needs,
                "earned_by": self.earned_by}


class GmailStub(StubAdapter):
    name = "gmail"
    base_url = "https://gmail.googleapis.com"
    doc = "Gmail API — read/label/draft"
    needs = "Google OAuth2 flow (refresh-token storage in vault); scopes decision"
    earned_by = "a fleet task that must read or send mail twice"


class SlackStub(StubAdapter):
    name = "slack"
    base_url = "https://slack.com/api"
    doc = "Slack Web API — post, read channels"
    needs = "bot token provisioning + channel-scope decision"
    earned_by = "a dispatch consumer that reports into Slack twice"


class NotionStub(StubAdapter):
    name = "notion"
    base_url = "https://api.notion.com"
    doc = "Notion API — pages, databases"
    needs = "integration token + page-share model; API version header"
    earned_by = "a knowledge-sync task targeting Notion twice"


class GoogleDriveStub(StubAdapter):
    name = "google-drive"
    base_url = "https://www.googleapis.com/drive/v3"
    doc = "Google Drive API — files, metadata"
    needs = "shares Gmail's OAuth2 work; file-scope consent decision"
    earned_by = "a fleet task that must fetch or store Drive files twice"


class DatadogStub(StubAdapter):
    name = "datadog"
    base_url = "https://api.datadoghq.com"
    doc = "Datadog API — metrics, monitors"
    needs = "API+app key pair in vault; decision on what fleet_health exports"
    earned_by = "fleet_health having an external consumer twice"


class JiraStub(StubAdapter):
    name = "jira"
    base_url = os.environ.get("WILLOW_JIRA_URL", "https://example.atlassian.net")  # per-site host — set when earned
    doc = "Jira Cloud API — issues, transitions"
    needs = "per-site base URL config + API token; mapping to task_queue states"
    earned_by = "a task-queue sync request against a real Jira site twice"


_ADAPTERS: tuple = (
    GitHubAdapter(), HuggingFaceAdapter(), JelesAdapter(), UtetyAdapter(),
    PangolinAdapter(),
    GmailStub(), SlackStub(), NotionStub(),
    GoogleDriveStub(), DatadogStub(), JiraStub(),
)

REGISTRY: dict = {a.name: a for a in _ADAPTERS}


def get(name: str) -> Optional[BaseAdapter]:
    return REGISTRY.get(str(name or "").strip().lower())


def list_integrations() -> list:
    """The ledger. Names, statuses, credential *sources* — never credentials."""
    out = []
    for a in _ADAPTERS:
        row = {"name": a.name, "status": a.status, "doc": a.doc,
               "base_url": a.base_url, "credential_source": a.credential_source()}
        if isinstance(a, StubAdapter):
            row["needs"] = a.needs
            row["earned_by"] = a.earned_by
        out.append(row)
    return out


# ── The egress gate, fourth consumer ──────────────────────────────────────────

def egress_denial(app_id: str) -> Optional[dict]:
    """The three-key check, mirrored from task_submit's allow_net gate but keyed
    on `integration_net`. Returns a denial dict, or None when all keys hold."""
    from . import consent, gate, lease

    if not gate.permitted(app_id, gate.INTEGRATION_NET_PERMISSION):
        return {"error": (
            f"net_denied: integration calls require the '{gate.INTEGRATION_NET_PERMISSION}' "
            f"permission in this app's manifest ($WILLOW_HOME/mcp_apps/"
            f"{app_id or '<app_id>'}/manifest.json). It is not granted by "
            f"'{gate.NET_PERMISSION}', integration_call, or full_access — egress is "
            "granted on its own line, per lane.")}

    if not consent.internet_permitted():
        return {"error": (
            "consent_denied: integration calls also require the operator's standing "
            f"'consent.internet' in {consent.settings_path()}. This app holds "
            f"'{gate.INTEGRATION_NET_PERMISSION}', but egress is switched off (or the "
            "consent policy could not be read, which denies).")}

    lease_state = lease.read_lease(app_id)
    if lease_state["status"] != "active":
        return {"error": (
            f"lease_denied: integration calls require an unexpired egress lease for "
            f"'{app_id}' (status: {lease_state['status']}"
            + (f" — {lease_state['error']}" if lease_state.get("error") else "")
            + "). Leases are issued only by the operator via `willow-mcp grant-net "
            f"{app_id or '<app_id>'} --ttl 30m --reason ...` and they expire. "
            "No MCP tool can mint one.")}

    if lease.strict_trust_root():
        forgeable = lease.self_writable_trust_paths(app_id)
        if forgeable:
            return {"error": (
                "trust_root_denied: WILLOW_MCP_STRICT_TRUST_ROOT is set, but this "
                "process can write the very keys that authorize it: "
                + ", ".join(f"{f['key']} ({f['path']})" for f in forgeable)
                + ". Chown these to a uid the agent does not run as.")}
    return None


def status(app_id: str, name: str) -> dict:
    """Offline readiness readout for one adapter: is it live, is a credential
    present (source only), and would the egress gate pass right now? Makes no
    network call — this is the question you ask BEFORE asking for a lease."""
    adapter = get(name)
    if adapter is None:
        return {"error": f"unknown_integration: {name!r}", "known": sorted(REGISTRY)}
    denial = egress_denial(app_id)
    row: dict = {
        "name": adapter.name,
        "status": adapter.status,
        "doc": adapter.doc,
        "base_url": adapter.base_url,
        "credential_source": adapter.credential_source(),
        "egress": "would_pass" if denial is None else "denied",
    }
    if denial is not None:
        row["egress_denial"] = denial["error"].split(":", 1)[0]
    if isinstance(adapter, StubAdapter):
        row["needs"] = adapter.needs
        row["earned_by"] = adapter.earned_by
    return row


# ── Operator CLI — the integration script (`willow-mcp-integrations`) ─────────

def _cli_list() -> int:
    rows = list_integrations()
    width = max(len(r["name"]) for r in rows)
    for r in rows:
        cred = r["credential_source"] or "-"
        line = f"{r['name']:<{width}}  {r['status']:<5}  cred={cred:<24}  {r['doc']}"
        print(line)
        if r["status"] == "stub":
            print(f"{'':<{width}}  needs: {r['needs']}")
    live = sum(1 for r in rows if r["status"] == "live")
    print(f"\n{live} live, {len(rows) - live} declared stubs. "
          "Stubs are fail-closed; see docs/design/integrations.md for the earn rule.")
    return 0


def _cli_check(name: str, app_id: str) -> int:
    out = status(app_id, name)
    print(json.dumps(out, indent=2))
    return 0 if "error" not in out else 1


def _cli_set_token(name: str) -> int:
    adapter = get(name)
    if adapter is None:
        print(f"unknown integration {name!r} — one of {', '.join(sorted(REGISTRY))}")
        return 1
    import getpass
    # getpass, never argv: a token on the command line lands in shell history
    # and the process table.
    token = getpass.getpass(f"token for {name} (input hidden): ").strip()
    if not token:
        print("empty token — nothing stored")
        return 1
    from .vault import default_vault
    default_vault().write(vault_key(name), token)
    print(f"stored in vault as {vault_key(name)}")
    return 0


def main(argv: Optional[list] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="willow-mcp-integrations",
        description="Operator-side integration ledger: list adapters, check "
                    "readiness, store tokens. Live calls go through the "
                    "integration_call MCP tool and the three-key egress gate.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="ledger: every adapter, live or declared stub")
    p_check = sub.add_parser("check", help="offline readiness readout for one adapter")
    p_check.add_argument("name")
    p_check.add_argument("--app-id", default=os.environ.get("WILLOW_APP_ID", ""),
                         help="app identity to evaluate the egress gate for")
    p_token = sub.add_parser("set-token", help="store a credential in the vault (prompted, hidden)")
    p_token.add_argument("name")
    args = parser.parse_args(argv)

    if args.cmd == "list":
        return _cli_list()
    if args.cmd == "check":
        return _cli_check(args.name, args.app_id)
    if args.cmd == "set-token":
        return _cli_set_token(args.name)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
