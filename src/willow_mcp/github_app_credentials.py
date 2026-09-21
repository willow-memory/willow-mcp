"""willow_mcp/github_app_credentials.py — mint willows-bot installation tokens.

Broker-side only (gap 5ecb87cfdf56 slice 3 / docs/design/brokered-push.md).
The PEM and App ID live under ``$WILLOW_VAULT_BOX/secrets/`` — the same files
willow-bot's ``credentials.py`` reads. Tokens are minted in this process for
one push (or one API act) and must never be written into a Kart sandbox.

Returns structured results; never logs the token value.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


_USER_AGENT = "willow-mcp-broker"
_API = "https://api.github.com"
_API_VERSION = "2022-11-28"


def vault_box() -> Path:
    raw = (os.environ.get("WILLOW_VAULT_BOX") or os.environ.get("WILLOW_HOME") or "").strip()
    if raw:
        return Path(raw).expanduser()
    user = os.environ.get("USER") or Path.home().name
    return Path.home() / f"{user}-data-vault" / "willow-operator-box"


def _parse_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key, _, val = s.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        if key:
            out[key] = val
    return out


def load_app_credentials() -> dict[str, Any]:
    """Load App ID + PEM from the vault. Never raises for missing files —
    returns ``{ok: False, reason: ...}``."""
    box = vault_box()
    env = _parse_env_file(box / "secrets" / "willow-bot.env")
    app_id = (os.environ.get("GITHUB_APP_ID") or env.get("GITHUB_APP_ID") or "").strip()
    pem_path_raw = (
        os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH")
        or env.get("GITHUB_APP_PRIVATE_KEY_PATH")
        or ""
    ).strip()
    pem_path = Path(pem_path_raw).expanduser() if pem_path_raw else (box / "secrets" / "willow-bot.pem")
    if not app_id:
        return {"ok": False, "reason": "GITHUB_APP_ID unset in vault secrets/willow-bot.env"}
    if not pem_path.is_file():
        return {"ok": False, "reason": f"App PEM missing at {pem_path}"}
    try:
        pem = pem_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return {"ok": False, "reason": f"App PEM unreadable: {exc}"}
    if "PRIVATE KEY" not in pem:
        return {"ok": False, "reason": f"App PEM at {pem_path} is not a private-key PEM"}
    return {"ok": True, "app_id": app_id, "pem": pem, "pem_path": str(pem_path)}


def _make_jwt(app_id: str, pem: str) -> str:
    import jwt  # PyJWT — already a willow-mcp / willow-bot dependency

    now = int(time.time())
    token = jwt.encode(
        {"iat": now - 60, "exp": now + 9 * 60, "iss": str(app_id)},
        pem,
        algorithm="RS256",
    )
    return token.decode() if isinstance(token, bytes) else token


def _api(method: str, url: str, *, bearer: str, body: dict | None = None,
         timeout: int = 20) -> dict[str, Any]:
    """`timeout` defaults to 20s (unchanged) but is overridable per call —
    envelope_retire_sweep clips it to whatever remains of its own wall-clock
    budget so a single slow row cannot overrun by a full 20s call it has no
    time left for (rework of Loki's MEDIUM finding on BAA43543/9494D3AF/
    D81165E5: "the real worst case per row is ~80s of urlopen timeouts")."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/vnd.github+json",
            "User-Agent": _USER_AGENT,
            "X-GitHub-Api-Version": _API_VERSION,
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return {"ok": True, "status": resp.status, "body": json.loads(raw) if raw else {}}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        return {"ok": False, "status": exc.code, "reason": detail or exc.reason}
    except Exception as exc:  # noqa: BLE001 — surface as structured miss
        return {"ok": False, "status": 0, "reason": f"{type(exc).__name__}: {exc}"}


def mint_installation_token(repo: str, timeout: int = 20) -> dict[str, Any]:
    """Mint a short-lived installation token for ``org/name``.

    On success: ``{ok, token, expires_at, permissions, installation_id, mode: "app"}``.
    On miss (no App coverage / no creds): ``{ok: False, reason, mode}``.
    The caller decides fall-back vs refuse — this module does not push.

    ``timeout`` (default 20s, unchanged for every existing caller) is
    passed to BOTH of this function's own HTTP calls — envelope_retire_sweep
    clips it to whatever remains of its own wall-clock budget so a token
    mint cannot itself overrun a nearly-exhausted tick (rework of Loki's
    LOW finding on D81165E5/FAAD3E4A: mints used to always spend up to two
    full 20s calls regardless of budget left)."""
    repo = (repo or "").strip().strip("/")
    if repo.count("/") != 1:
        return {"ok": False, "mode": "unavailable", "reason": "repo must be org/name"}

    creds = load_app_credentials()
    if not creds.get("ok"):
        return {"ok": False, "mode": "host", "reason": creds.get("reason", "App credentials missing")}

    jwt_token = _make_jwt(creds["app_id"], creds["pem"])
    inst = _api("GET", f"{_API}/repos/{repo}/installation", bearer=jwt_token, timeout=timeout)
    if not inst.get("ok"):
        status = int(inst.get("status") or 0)
        if status == 404:
            return {
                "ok": False,
                "mode": "host",
                "reason": f"willows-bot is not installed on {repo}",
            }
        return {
            "ok": False,
            "mode": "unavailable",
            "reason": f"installation lookup failed HTTP {status}: {inst.get('reason')}",
        }

    installation_id = inst["body"].get("id")
    if not installation_id:
        return {"ok": False, "mode": "unavailable", "reason": "installation response missing id"}

    # Restrict the token to this one repository name (not the org slug).
    repo_name = repo.split("/", 1)[1]
    minted = _api(
        "POST",
        f"{_API}/app/installations/{installation_id}/access_tokens",
        bearer=jwt_token,
        body={"repositories": [repo_name]},
        timeout=timeout,
    )
    if not minted.get("ok"):
        return {
            "ok": False,
            "mode": "unavailable",
            "reason": f"token mint failed HTTP {minted.get('status')}: {minted.get('reason')}",
        }

    body = minted["body"]
    token = (body.get("token") or "").strip()
    if not token:
        return {"ok": False, "mode": "unavailable", "reason": "token mint returned empty token"}

    perms = body.get("permissions") or inst["body"].get("permissions") or {}
    return {
        "ok": True,
        "mode": "app",
        "token": token,
        "expires_at": body.get("expires_at"),
        "permissions": perms,
        "installation_id": installation_id,
        "app_id": creds["app_id"],
        "app_slug": inst["body"].get("app_slug"),
        "repo": repo,
    }


def bot_login(auth: dict | None) -> str:
    """The willows-bot App's own PR-author identity: ``<app_slug>[bot]`` —
    the login GitHub attributes a bot-authored PR to, the same shape every
    ``user.login`` on a bot-opened PR carries. Empty when the mint response
    (a fake in tests, or a real one predating this field) carries no
    ``app_slug`` — callers treat that as "cannot verify", never as a match.
    """
    slug = ((auth or {}).get("app_slug") or "").strip()
    return f"{slug}[bot]" if slug else ""


def contents_perm_allows_push(permissions: dict | None) -> bool:
    level = (permissions or {}).get("contents") or ""
    return level in ("write", "admin")


def workflows_perm_allows_write(permissions: dict | None) -> bool:
    """The App's ``workflows`` permission gates changes under
    ``.github/workflows/**``: even with ``contents: write``, a push whose
    commit range modifies a workflow file is rejected by GitHub when the
    App does not carry ``workflows: write``. Gap ``3f24d2d4a243`` — the
    broker preflights this so the envelope is not consumed on a request
    GitHub will refuse."""
    level = (permissions or {}).get("workflows") or ""
    return level in ("write", "admin")
