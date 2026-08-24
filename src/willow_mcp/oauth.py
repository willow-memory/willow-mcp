# willow_mcp/oauth.py — WillowOAuthProvider: GroveOAuthProvider + Google/Apple upstream IdP.
#
# Google flow:
#   /mcp-approve?pending=X  →  user clicks "Sign in with Google"
#   → /oauth/google/start?pending=X  →  redirect to accounts.google.com
#   → /oauth/google/callback?code=Y&state=X
#   → exchange code, verify id_token via tokeninfo endpoint
#   → issue_code(client, params)  →  MCP client completes PKCE
#
# Apple flow:
#   /mcp-approve?pending=X  →  user clicks "Sign in with Apple"
#   → /oauth/apple/start?pending=X  →  redirect to appleid.apple.com
#   → /oauth/apple/callback (POST form_post) with code + id_token + state
#   → verify id_token via Apple JWKS, exchange code for confirmation
#   → issue_code(client, params)
#
# Vault keys (write once via `willow-mcp setup` or directly):
#   google.client_id, google.client_secret
#   apple.team_id, apple.client_id, apple.key_id, apple.p8_key
#
# Note: Apple Sign In requires HTTPS and a registered domain. For local
# (http://127.0.0.1), Google is the practical choice. Set WILLOW_MCP_URL
# to your public HTTPS URL to enable Apple in production.
import asyncio
import base64
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .identity_binding import propose_binding
from .vault import Vault

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

_ACCESS_TTL  = 30 * 86400
_CODE_TTL    = 300
_REFRESH_TTL = 30 * 86400


def _tok() -> str:
    return secrets.token_urlsafe(32)


def _idp_of(data: dict) -> str | None:
    """The upstream IdP name from a token record, old or new.

    Records written before the rename key it `issuer`; new ones use `idp`. Read
    both so an upgrade does not silently invalidate every live token — the
    failure would look like "everyone signed out" and give no reason.
    """
    return data.get("idp") or data.get("issuer")


class GroveOAuthProvider:
    """
    Minimal single-user OAuth 2.0 PKCE provider (lifted from grove/mcp_auth.py).
    Clients register dynamically. Authorization requires a browser approval step.
    """

    def __init__(self, token_path: Path, base_url: str) -> None:
        self._token_path = Path(token_path)
        self._base_url   = base_url.rstrip("/")
        self._pending: dict[str, tuple[OAuthClientInformationFull, AuthorizationParams]] = {}
        self._codes:   dict[str, AuthorizationCode] = {}
        # code -> {"idp": ..., "subject": ...} — the verified upstream IdP identity.
        # NOT an RFC 9207 issuer: this is "google"/"apple", the NAME of the
        # provider that authenticated the human, not a URL identifying this
        # authorization server. See docs/design/idp-vs-issuer.md.
        # for this authorization code, consumed (and persisted onto the
        # issued access/refresh token) in exchange_authorization_code. Not
        # part of self._state: it only needs to survive the short _CODE_TTL
        # window between issue_code() and the client's token exchange.
        self._code_identity: dict[str, dict] = {}
        self._state: dict = self._load_state()

    def _load_state(self) -> dict:
        if self._token_path.exists():
            try:
                return json.loads(self._token_path.read_text())
            except Exception:
                import logging
                logging.getLogger("willow_mcp.oauth").debug(
                    "corrupt token store at %s, resetting", self._token_path, exc_info=True)
        return {"clients": {}, "access_tokens": {}, "refresh_tokens": {}}

    def _save_state(self) -> None:
        self._prune_expired()
        self._token_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write (temp file + rename): a crash mid-write must never
        # leave a half-written token store — the next load would either
        # silently fall back to an empty store (data loss) or, worse, load
        # truncated-but-parseable JSON.
        tmp = self._token_path.with_suffix(self._token_path.suffix + f".tmp-{os.getpid()}")
        tmp.write_text(json.dumps(self._state, indent=2))
        os.replace(tmp, self._token_path)

    def _prune_expired(self) -> None:
        """Drop expired codes/tokens so a long-running serve-mode process
        doesn't accumulate dead entries forever — previously these were only
        ever removed lazily, if that exact code/token happened to be looked
        up again after expiring."""
        now = time.time()
        for code, record in list(self._codes.items()):
            if record.expires_at < now:
                del self._codes[code]
                self._code_identity.pop(code, None)
        for bucket in ("access_tokens", "refresh_tokens"):
            for token, data in list(self._state[bucket].items()):
                exp = data.get("expires_at")
                if exp and exp < now:
                    del self._state[bucket][token]

    def pop_pending(self, key: str):
        return self._pending.pop(key, None)

    def issue_code(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
        identity: Optional[dict] = None,
    ) -> str:
        self._prune_expired()
        code_str = _tok()
        self._codes[code_str] = AuthorizationCode(
            code=code_str,
            scopes=params.scopes or ["willow"],
            expires_at=time.time() + _CODE_TTL,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
        )
        if identity is not None:
            self._code_identity[code_str] = identity
        return code_str

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self._state["clients"].get(client_id)
        return OAuthClientInformationFull(**data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._state["clients"][client_info.client_id] = client_info.model_dump(mode="json")
        self._save_state()

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        key = secrets.token_urlsafe(16)
        self._pending[key] = (client, params)
        return f"{self._base_url}/mcp-approve?pending={key}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str,
    ) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code is None:
            return None
        if code.client_id != client.client_id:
            return None
        if code.expires_at < time.time():
            del self._codes[authorization_code]
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        identity = self._code_identity.pop(authorization_code.code, None) or {}
        access_tok  = _tok()
        refresh_tok = _tok()
        now = int(time.time())
        self._state["access_tokens"][access_tok] = {
            "token": access_tok, "client_id": client.client_id,
            "scopes": authorization_code.scopes, "expires_at": now + _ACCESS_TTL,
            "idp": identity.get("idp"), "subject": identity.get("subject"),
        }
        self._state["refresh_tokens"][refresh_tok] = {
            "token": refresh_tok, "client_id": client.client_id,
            "scopes": authorization_code.scopes, "expires_at": now + _REFRESH_TTL,
            "idp": identity.get("idp"), "subject": identity.get("subject"),
        }
        self._save_state()
        return OAuthToken(
            access_token=access_tok, token_type="bearer",
            expires_in=_ACCESS_TTL, refresh_token=refresh_tok,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str,
    ) -> RefreshToken | None:
        data = self._state["refresh_tokens"].get(refresh_token)
        if data is None:
            return None
        if data["client_id"] != client.client_id:
            return None
        if (exp := data.get("expires_at")) and exp < time.time():
            del self._state["refresh_tokens"][refresh_token]
            self._save_state()
            return None
        return RefreshToken(**data)

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull,
        refresh_token: RefreshToken, scopes: list[str],
    ) -> OAuthToken:
        old_data = self._state["refresh_tokens"].pop(refresh_token.token, None) or {}
        effective_scopes = scopes or refresh_token.scopes
        access_tok  = _tok()
        new_refresh = _tok()
        now = int(time.time())
        self._state["access_tokens"][access_tok] = {
            "token": access_tok, "client_id": client.client_id,
            "scopes": effective_scopes, "expires_at": now + _ACCESS_TTL,
            "idp": _idp_of(old_data), "subject": old_data.get("subject"),
        }
        self._state["refresh_tokens"][new_refresh] = {
            "token": new_refresh, "client_id": client.client_id,
            "scopes": effective_scopes, "expires_at": now + _REFRESH_TTL,
            "idp": _idp_of(old_data), "subject": old_data.get("subject"),
        }
        self._save_state()
        return OAuthToken(
            access_token=access_tok, token_type="bearer",
            expires_in=_ACCESS_TTL, refresh_token=new_refresh,
            scope=" ".join(effective_scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        data = self._state["access_tokens"].get(token)
        if data is None:
            return None
        if (exp := data.get("expires_at")) and exp < time.time():
            del self._state["access_tokens"][token]
            self._save_state()
            return None
        return AccessToken(
            token=data["token"],
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data.get("expires_at"),
            subject=data.get("subject"),
            # `idp`, never `iss`. RFC 9207 / SEP-2468 give `iss` a specific
            # meaning — THIS authorization server's issuer URL — and clients
            # MUST validate a present `iss` against the recorded issuer. Putting
            # "google" there made the two collide.
            claims={"idp": _idp_of(data)} if _idp_of(data) else None,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self._state["access_tokens"].pop(token.token, None)
        else:
            self._state["refresh_tokens"].pop(token.token, None)
        self._save_state()

_APPLE_JWKS_CACHE: tuple[float, dict] | None = None
_APPLE_JWKS_TTL = 3600


# ── Google helpers ─────────────────────────────────────────────────────────────

def _google_auth_url(client_id: str, redirect_uri: str, state: str) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


def _google_exchange_code(code: str, client_id: str, client_secret: str, redirect_uri: str) -> dict:
    data = urllib.parse.urlencode({
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - "https://oauth2.googleapis.com/token" is a hardcoded string literal above; no request input ever reaches scheme or host
        return json.loads(resp.read())


def _google_verify_id_token(id_token: str, client_id: str) -> tuple[str, str]:
    """Verify a Google id_token via the tokeninfo endpoint. Returns (email, sub)."""
    url = "https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode({"id_token": id_token})
    with urllib.request.urlopen(url, timeout=10) as resp:  # nosec B310 - base is the hardcoded "https://oauth2.googleapis.com/tokeninfo" literal above; id_token is only ever urlencoded into the query string, never able to change scheme or host
        claims = json.loads(resp.read())
    if claims.get("aud") != client_id:
        raise ValueError(f"id_token audience mismatch: {claims.get('aud')!r}")
    if claims.get("email_verified") != "true":
        raise ValueError("Google account email not verified")
    return claims["email"], claims["sub"]


# ── Apple helpers ──────────────────────────────────────────────────────────────

def _apple_fetch_jwks() -> dict:
    global _APPLE_JWKS_CACHE
    now = time.time()
    if _APPLE_JWKS_CACHE and now - _APPLE_JWKS_CACHE[0] < _APPLE_JWKS_TTL:
        return _APPLE_JWKS_CACHE[1]
    with urllib.request.urlopen("https://appleid.apple.com/auth/keys", timeout=10) as resp:  # nosec B310 - hardcoded https string literal (Apple's JWKS endpoint); no request input reaches this call
        raw = json.loads(resp.read())
    keys = {}
    for jwk in raw.get("keys", []):
        if jwk.get("kty") == "RSA":
            keys[jwk["kid"]] = _jwk_to_rsa_pub(jwk["n"], jwk["e"])
    _APPLE_JWKS_CACHE = (now, keys)
    return keys


def _b64url_to_int(s: str) -> int:
    s += "=" * (-len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s), "big")


def _jwk_to_rsa_pub(n_b64: str, e_b64: str):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend
    return RSAPublicNumbers(_b64url_to_int(e_b64), _b64url_to_int(n_b64)).public_key(default_backend())


def _apple_verify_id_token(id_token: str, client_id: str) -> tuple[Optional[str], str]:
    """Verify Apple id_token (RS256). Returns (email, sub) — email is None
    on a repeat sign-in with no cached email (§6.1: Apple only includes it
    on the *first* authorization). Callers must not substitute `sub` for a
    missing email — that conflates two different kinds of identifier and
    defeats compute_email_basis's 'unavailable' signal (§6.2)."""
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives.hashes import SHA256

    parts = id_token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT")
    header_raw, payload_raw, sig_raw = parts

    def b64d(s: str) -> bytes:
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    header = json.loads(b64d(header_raw))
    kid = header.get("kid", "")
    keys = _apple_fetch_jwks()
    pub = keys.get(kid)
    if pub is None:
        raise ValueError(f"Unknown Apple key kid={kid!r}")

    signing_input = f"{header_raw}.{payload_raw}".encode()
    pub.verify(b64d(sig_raw), signing_input, PKCS1v15(), SHA256())

    payload = json.loads(b64d(payload_raw))
    if payload.get("iss") != "https://appleid.apple.com":
        raise ValueError(f"Wrong issuer: {payload.get('iss')!r}")
    if payload.get("aud") != client_id:
        raise ValueError(f"Wrong audience: {payload.get('aud')!r}")
    if payload.get("exp", 0) < time.time():
        raise ValueError("Apple id_token expired")

    sub = payload["sub"]
    email = payload.get("email")
    return email, sub


def _apple_client_secret(team_id: str, client_id: str, key_id: str, p8_key: str) -> str:
    """Generate an Apple client_secret JWT (ES256 signed with the P8 key)."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    now = int(time.time())
    header  = {"alg": "ES256", "kid": key_id}
    payload = {"iss": team_id, "iat": now, "exp": now + 15777000,
               "aud": "https://appleid.apple.com", "sub": client_id}

    def _b64(data) -> str:
        if isinstance(data, dict):
            data = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    msg = f"{_b64(header)}.{_b64(payload)}".encode()
    key = load_pem_private_key(
        p8_key.encode() if isinstance(p8_key, str) else p8_key,
        password=None,
    )
    der_sig = key.sign(msg, ECDSA(SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{msg.decode()}.{_b64(raw_sig)}"


def _apple_exchange_code(code: str, client_id: str, team_id: str, key_id: str,
                         p8_key: str, redirect_uri: str) -> dict:
    client_secret = _apple_client_secret(team_id, client_id, key_id, p8_key)
    data = urllib.parse.urlencode({
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode()
    req = urllib.request.Request(
        "https://appleid.apple.com/auth/token",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - "https://appleid.apple.com/auth/token" is a hardcoded string literal above; no request input ever reaches scheme or host
        return json.loads(resp.read())


# ── Approval page ──────────────────────────────────────────────────────────────

_APPROVE_HTML = """\
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Willow MCP — Authorize</title>
<style>
:root{{--bg:#f8fafc;--surface:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--accent-t:#dbeafe}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#60a5fa;--accent-t:#1e3a5f}}}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:36px;max-width:400px;width:100%}}
h1{{font-size:18px;font-weight:700;margin-bottom:6px}}
.client{{font-family:ui-monospace,monospace;font-size:13px;color:var(--accent);background:var(--accent-t);padding:3px 8px;border-radius:4px;display:inline-block;margin-bottom:20px}}
.btn{{display:flex;align-items:center;gap:12px;width:100%;padding:11px 16px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);font-size:15px;font-weight:500;cursor:pointer;text-decoration:none;margin-bottom:10px;transition:border-color .15s,box-shadow .15s}}
.btn:hover{{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-t)}}
.unconfigured{{font-size:13px;color:var(--muted);padding:10px 14px;border:1px dashed var(--border);border-radius:6px;margin-bottom:10px;line-height:1.5}}
code{{font-family:ui-monospace,monospace;font-size:12px;background:var(--bg);padding:1px 4px;border-radius:3px}}
.deny{{display:block;text-align:center;margin-top:20px;font-size:13px;color:var(--muted);text-decoration:none}}
.deny:hover{{text-decoration:underline}}
</style></head><body>
<div class="card">
  <h1>Authorize willow-mcp</h1>
  <div class="client">{client_id}</div>
  {provider_buttons}
  <a href="/mcp-approve?pending={pending_key}&action=deny" class="deny">Deny access</a>
</div></body></html>"""

_GOOGLE_BTN = """\
<a class="btn" href="/oauth/google/start?pending={pending_key}">
  <svg width="18" height="18" viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615Z"/><path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18Z"/><path fill="#FBBC05" d="M3.964 10.706A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.706V4.962H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.038l3.007-2.332Z"/><path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.962L3.964 7.294C4.672 5.163 6.656 3.58 9 3.58Z"/></svg>
  Sign in with Google
</a>"""

_APPLE_BTN = """\
<a class="btn" href="/oauth/apple/start?pending={pending_key}">
  <svg width="18" height="18" viewBox="0 0 814 1000"><path fill="currentColor" d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76 0-103.7 40.8-165.9 40.8s-105.7-59.5-155.8-126.5C46.5 762.1 0 681.3 0 604.5c0-147.2 96.1-224.9 190.5-224.9 50.1 0 91.7 33.7 123.1 33.7 29.9 0 77.2-35.5 133.5-35.5 41.5 0 153.4 5.8 211.1 112.1zm-172.2-87.6c26.6-31.6 45.5-76.1 45.5-120.7 0-6.1-.5-12.3-1.7-17.3-42.8 1.7-93.3 28.5-124.3 64.3-24.2 27.5-47.3 70.9-47.3 116.1 0 6.8 1.1 13.5 1.7 15.6 2.7.5 7.2 1.1 11.6 1.1 38.4 0 86-25.8 114.5-59.1z"/></svg>
  Sign in with Apple
</a>"""

_UNCONFIGURED_MSG = """\
<div class="unconfigured">
  No identity providers configured. Add credentials to the vault:<br><br>
  <code>willow-mcp setup --google-client-id ID --google-client-secret SECRET</code>
</div>"""


# ── Provider ───────────────────────────────────────────────────────────────────

class WillowOAuthProvider(GroveOAuthProvider):
    """GroveOAuthProvider extended with Google and Apple upstream IdP."""

    def __init__(self, token_path: Path, base_url: str, vault: Vault) -> None:
        super().__init__(token_path=token_path, base_url=base_url)
        self._vault = vault

    # helpers
    def _has_google(self) -> bool:
        return bool(self._vault.read("google.client_id"))

    def _has_apple(self) -> bool:
        return bool(self._vault.read("apple.team_id"))

    def _google_redirect_uri(self) -> str:
        return f"{self._base_url}/oauth/google/callback"

    def _apple_redirect_uri(self) -> str:
        return f"{self._base_url}/oauth/apple/callback"

    def _approval_page(self, pending_key: str, client_id: str) -> str:
        buttons = ""
        if self._has_google():
            buttons += _GOOGLE_BTN.format(pending_key=pending_key)
        if self._has_apple():
            buttons += _APPLE_BTN.format(pending_key=pending_key)
        if not buttons:
            buttons = _UNCONFIGURED_MSG
        return _APPROVE_HTML.format(
            pending_key=pending_key,
            client_id=client_id,
            provider_buttons=buttons,
        )

    async def authorize(self, client, params) -> str:
        key = secrets.token_urlsafe(16)
        self._pending[key] = (client, params)
        return f"{self._base_url}/mcp-approve?pending={key}"

    def register_routes(self, mcp: "MCPServer") -> None:
        """Register OAuth routes onto a FastMCP instance."""
        from starlette.requests import Request
        from starlette.responses import HTMLResponse, RedirectResponse

        provider = self  # close over self

        @mcp.custom_route("/mcp-approve", methods=["GET"])
        async def mcp_approve(request: Request) -> HTMLResponse:
            pending_key = request.query_params.get("pending", "")
            action = request.query_params.get("action", "")

            if action == "deny":
                provider._pending.pop(pending_key, None)
                return HTMLResponse("<h2>Access denied.</h2>", status_code=200)

            entry = provider._pending.get(pending_key)
            if not entry:
                return HTMLResponse(
                    "<h2>Invalid or expired approval link.</h2>",
                    status_code=400,
                )
            client, _ = entry
            return HTMLResponse(provider._approval_page(pending_key, client.client_id))

        # ── Google ──────────────────────────────────────────────────────────

        @mcp.custom_route("/oauth/google/start", methods=["GET"])
        async def google_start(request: Request) -> RedirectResponse:
            pending_key = request.query_params.get("pending", "")
            if pending_key not in provider._pending:
                return HTMLResponse("<h2>Invalid approval link.</h2>", status_code=400)

            client_id = provider._vault.read("google.client_id")
            if not client_id:
                return HTMLResponse(
                    "<p>Google Sign In not configured. Add <code>google.client_id</code> to the vault.</p>",
                    status_code=503,
                )
            url = _google_auth_url(
                client_id=client_id,
                redirect_uri=provider._google_redirect_uri(),
                state=pending_key,
            )
            return RedirectResponse(url, status_code=302)

        @mcp.custom_route("/oauth/google/callback", methods=["GET"])
        async def google_callback(request: Request) -> HTMLResponse | RedirectResponse:
            code = request.query_params.get("code", "")
            pending_key = request.query_params.get("state", "")
            entry = provider._pending.pop(pending_key, None)
            if not entry or not code:
                return HTMLResponse("<h2>Authorization failed — invalid state.</h2>", status_code=400)

            client_id     = provider._vault.read("google.client_id")
            client_secret = provider._vault.read("google.client_secret")
            if not client_id or not client_secret:
                return HTMLResponse("<p>Google credentials missing from vault.</p>", status_code=503)

            try:
                tokens = await asyncio.to_thread(
                    _google_exchange_code,
                    code, client_id, client_secret, provider._google_redirect_uri(),
                )
                email, sub = await asyncio.to_thread(
                    _google_verify_id_token, tokens["id_token"], client_id,
                )
            except Exception as exc:
                return HTMLResponse(f"<h2>Google sign-in failed.</h2><p>{exc}</p>", status_code=400)

            propose_binding("google", sub, email)
            client, params = entry
            auth_code = provider.issue_code(client, params, identity={"idp": "google", "subject": sub})
            redirect = str(params.redirect_uri)
            sep = "&" if "?" in redirect else "?"
            url = f"{redirect}{sep}code={auth_code}"
            if params.state:
                url += f"&state={params.state}"
            return RedirectResponse(url, status_code=302)

        # ── Apple ───────────────────────────────────────────────────────────

        @mcp.custom_route("/oauth/apple/start", methods=["GET"])
        async def apple_start(request: Request) -> RedirectResponse | HTMLResponse:
            pending_key = request.query_params.get("pending", "")
            if pending_key not in provider._pending:
                return HTMLResponse("<h2>Invalid approval link.</h2>", status_code=400)

            apple_client_id = provider._vault.read("apple.client_id")
            if not apple_client_id:
                return HTMLResponse(
                    "<p>Apple Sign In not configured. Add <code>apple.client_id</code> to the vault.</p>",
                    status_code=503,
                )
            params = urllib.parse.urlencode({
                "client_id": apple_client_id,
                "redirect_uri": provider._apple_redirect_uri(),
                "response_type": "code id_token",
                "scope": "name email",
                "response_mode": "form_post",
                "state": pending_key,
            })
            return RedirectResponse(
                f"https://appleid.apple.com/auth/authorize?{params}",
                status_code=302,
            )

        @mcp.custom_route("/oauth/apple/callback", methods=["POST"])
        async def apple_callback(request: Request) -> HTMLResponse | RedirectResponse:
            form = await request.form()
            id_token    = form.get("id_token", "")
            pending_key = form.get("state", "")
            entry = provider._pending.pop(pending_key, None)
            if not entry or not id_token:
                return HTMLResponse("<h2>Authorization failed — invalid state.</h2>", status_code=400)

            apple_client_id = provider._vault.read("apple.client_id")
            if not apple_client_id:
                return HTMLResponse("<p>Apple credentials missing from vault.</p>", status_code=503)

            try:
                email, sub = await asyncio.to_thread(
                    _apple_verify_id_token, id_token, apple_client_id,
                )
            except Exception as exc:
                return HTMLResponse(f"<h2>Apple sign-in failed.</h2><p>{exc}</p>", status_code=400)

            propose_binding("apple", sub, email)
            client, params = entry
            auth_code = provider.issue_code(client, params, identity={"idp": "apple", "subject": sub})
            redirect = str(params.redirect_uri)
            sep = "&" if "?" in redirect else "?"
            url = f"{redirect}{sep}code={auth_code}"
            if params.state:
                url += f"&state={params.state}"
            return RedirectResponse(url, status_code=302)
