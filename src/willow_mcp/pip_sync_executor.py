"""willow_mcp/pip_sync_executor.py — host-side editable install into a vault venv.

Idea A.2 (willow-bot/docs/ideas.md): Kart binds product ``.venv`` and
``$WILLOW_HOME/venvs/*`` read-only, so ``# allow_net`` pip always hits
Errno 30. This verb runs in the broker process — parallel to
:mod:`pull_executor`, not Kart and not ``integration_call``.

Receipt-only (no syscall envelope in slice 0): allowlisted checkout +
fixed extras tokens + bare vault venv name. Tagged offline installs stay
row 25 ``package.upgrade``. Crossing ink is a FRANK ``pip_sync`` receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Callable, Optional

from . import paths

EVENT = "pip_sync"
FAILED_EVENT = "pip_sync_failed"

_PIP_TIMEOUT_S = 600
_GIT_TIMEOUT_S = 30
_VENV_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_EXTRA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SCRUBBED_ENV_KEEP = ("PATH", "HOME", "USER", "LANG", "LC_ALL", "http_proxy",
                      "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                      "no_proxy")


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "synced": False, "reason": reason, **extra}


def _git(checkout: Path, *args: str, runner: Optional[Callable] = None) -> subprocess.CompletedProcess:
    run = runner or subprocess.run
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return run(
        ["git", "-C", str(checkout), *args],
        capture_output=True, text=True, timeout=_GIT_TIMEOUT_S, env=env, check=False,
    )


def _scrubbed_pip_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _SCRUBBED_ENV_KEEP}
    env["PIP_CONFIG_FILE"] = "/dev/null"
    env.setdefault("LC_ALL", "C")
    # Never carry publish credentials into the install path (ideas A.4).
    for drop in ("TWINE_PASSWORD", "TWINE_USERNAME", "PYPI_TOKEN",
                 "PYPI_PASSWORD", "PIP_INDEX_URL"):
        env.pop(drop, None)
    return env


def _github_root() -> Path:
    for var in ("WILLOW_DEV_SAFE_ROOT", "GITHUB_ROOT"):
        v = (os.environ.get(var) or "").strip()
        if v:
            return Path(v).expanduser()
    return Path.home() / "github"


def _venvs_root() -> Path:
    return paths.willow_home() / "venvs"


def load_allowlist(*, path: Optional[Path] = None) -> dict:
    """Box override first, then the bundled default beside this package."""
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    override = paths.willow_home() / "constitutional" / "pip_sync_allowlist.json"
    if override.is_file():
        return json.loads(override.read_text(encoding="utf-8"))
    bundled = Path(__file__).resolve().parent / "bundle" / "constitutional" / "pip_sync_allowlist.json"
    if bundled.is_file():
        try:
            return json.loads(bundled.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return {"extras": ["connectors", "dev", "mcp", "nestor"], "pairs": {}}


def remote_slug(checkout: Path, *, runner: Optional[Callable] = None) -> Optional[str]:
    """``owner/repo`` from ``origin``, or None."""
    proc = _git(checkout, "remote", "get-url", "origin", runner=runner)
    if proc.returncode != 0:
        return None
    url = (proc.stdout or "").strip()
    if not url:
        return None
    if url.endswith(".git"):
        url = url[:-4]
    parts = [p for p in re.split(r"[:/]", url) if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[-2], parts[-1]
    if not owner or not repo:
        return None
    return f"{owner}/{repo}"


def lookup_pair(slug: str, allowlist: dict) -> Optional[dict]:
    pairs = allowlist.get("pairs") or {}
    if slug in pairs:
        return dict(pairs[slug])
    # Case-insensitive GitHub remotes.
    lowered = {k.lower(): v for k, v in pairs.items()}
    hit = lowered.get(slug.lower())
    return dict(hit) if hit else None


def _resolve_venv(venv: str, *, venvs_root: Path) -> dict:
    name = (venv or "").strip()
    if not name or "/" in name or "\\" in name or not _VENV_NAME_RE.match(name):
        return _refuse("EVENV", f"venv {venv!r} must be a bare name under {venvs_root}")
    path = venvs_root / name
    try:
        resolved = path.resolve()
        inside = resolved.is_relative_to(venvs_root.resolve())
    except OSError as exc:
        return _refuse("EVENV", f"could not resolve {path}: {exc}")
    if not inside:
        return _refuse("EVENV", f"venv {venv!r} resolves outside {venvs_root}")
    if not path.is_dir():
        return _refuse("EVENV", f"venv {venv!r} does not exist under {venvs_root}")
    python = path / "bin" / "python"
    if not python.is_file():
        return _refuse("EVENV", f"venv {venv!r} has no bin/python — not a real venv")
    return {"ok": True, "path": path, "python": python, "name": name}


def _check_writable(venv_path: Path) -> dict | None:
    if os.access(venv_path, os.W_OK):
        return None
    try:
        owner_uid = venv_path.stat().st_uid
    except OSError:
        owner_uid = None
    return _refuse(
        "EPERM",
        f"this process cannot write {venv_path} (owner uid {owner_uid!r}) — "
        f"never escalated",
        owner_uid=owner_uid,
    )


def _checkout_under_roots(checkout: Path, *, github_root: Path) -> bool:
    try:
        resolved = checkout.resolve()
        root = github_root.resolve()
    except OSError:
        return False
    return resolved == root or root in resolved.parents


def _normalize_extras(extras: Optional[list[str]], *, allowed: set[str]) -> dict:
    tokens: list[str] = []
    for raw in extras or ():
        tok = (raw or "").strip()
        if not tok:
            continue
        if not _EXTRA_RE.match(tok):
            return _refuse("ENOALLOW", f"extra {tok!r} is not a valid extras token")
        if tok not in allowed:
            return _refuse("ENOALLOW", f"extra {tok!r} is not on the allowlist")
        if tok not in tokens:
            tokens.append(tok)
    return {"ok": True, "extras": tokens}


def _default_branch(checkout: Path, *, runner: Optional[Callable] = None) -> Optional[str]:
    proc = _git(checkout, "symbolic-ref", "--short", "refs/remotes/origin/HEAD", runner=runner)
    if proc.returncode != 0:
        return None
    v = (proc.stdout or "").strip()
    if v.startswith("origin/"):
        v = v[len("origin/"):]
    return v or None


def _package_name(checkout: Path) -> Optional[str]:
    """Best-effort project name from pyproject.toml (no tomllib required)."""
    pp = checkout / "pyproject.toml"
    if not pp.is_file():
        return None
    try:
        text = pp.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', text)
    return m.group(1) if m else None


def _installed_version(python: Path, package: str, *, runner: Optional[Callable] = None) -> Optional[str]:
    run = runner or subprocess.run
    proc = run(
        [str(python), "-c",
         "import importlib.metadata as m,sys;\n"
         f"print(m.version({package!r}))"],
        capture_output=True, text=True, timeout=_GIT_TIMEOUT_S, check=False,
        env=_scrubbed_pip_env(),
    )
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or None


def _requirement_hash(checkout: Path, extras: list[str]) -> str:
    parts = [str(checkout.resolve()), ",".join(extras)]
    pp = checkout / "pyproject.toml"
    if pp.is_file():
        try:
            parts.append(pp.read_text(encoding="utf-8"))
        except OSError:
            pass
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _append_receipt(ledger, *, project: str, event: str, content: dict) -> Optional[str]:
    if ledger is None:
        return None
    try:
        return ledger.append(project, event, content)
    except Exception:  # noqa: BLE001 — ink must not kill the act's return
        return None


def execute_pip_sync(
    app_id: str,
    *,
    venv: str = "",
    checkout: str | Path,
    extras: Optional[list[str]] = None,
    project: str = "",
    session: str = "",
    ledger=None,
    runner: Optional[Callable] = None,
    allowlist: Optional[dict] = None,
    venvs_root: Optional[Path] = None,
    github_root: Optional[Path] = None,
) -> dict:
    """Install ``checkout`` editable into ``$WILLOW_HOME/venvs/<venv>``.

    ``venv`` may be omitted when the checkout's ``origin`` maps to a pair in
    the allowlist. ``extras`` tokens must be allowlisted; when omitted, the
    pair's default extras (if any) are used.
    """
    path = Path(checkout).expanduser()
    allow = allowlist if allowlist is not None else load_allowlist()
    roots = venvs_root or _venvs_root()
    ghub = github_root or _github_root()
    allowed_extras = set(allow.get("extras") or ())

    if path.is_symlink():
        return _refuse("EINVAL", f"refusing a symlinked checkout: {path}")
    try:
        resolved = path.resolve()
    except OSError as exc:
        return _refuse("EINVAL", f"could not resolve checkout {path}: {exc}")
    if not (resolved / ".git").exists() and not (resolved / ".git").is_file():
        return _refuse("EINVAL", f"checkout is not a git tree: {resolved}")
    if not _checkout_under_roots(resolved, github_root=ghub):
        return _refuse(
            "ENOALLOW",
            f"checkout {resolved} is not under the github root {ghub.resolve()}",
        )

    slug = remote_slug(resolved, runner=runner)
    if not slug:
        return _refuse("ENOALLOW", "checkout has no origin remote slug to allowlist against")
    pair = lookup_pair(slug, allow)
    if pair is None:
        return _refuse("ENOALLOW", f"remote {slug!r} is not on the pip_sync allowlist")

    venv_name = (venv or "").strip() or (pair.get("venv") or "").strip()
    if not venv_name:
        return _refuse("EVENV", f"allowlist pair for {slug!r} has no venv")
    if pair.get("venv") and venv_name != pair["venv"]:
        return _refuse(
            "ENOALLOW",
            f"remote {slug!r} is bound to venv {pair['venv']!r}, not {venv_name!r}",
        )

    requested = list(extras) if extras is not None else list(pair.get("extras") or ())
    extra_ok = _normalize_extras(requested, allowed=allowed_extras)
    if not extra_ok.get("ok"):
        return extra_ok
    extra_tokens: list[str] = extra_ok["extras"]

    # Default branch + clean tracked tree (same hygiene as install_receipt).
    status = _git(resolved, "status", "--porcelain", "--untracked-files=no", runner=runner)
    if status.returncode != 0:
        return _refuse("EDIRTY", "could not read worktree status")
    if (status.stdout or "").strip():
        return _refuse("EDIRTY", "tracked worktree is dirty; pip_sync refused")

    branch_proc = _git(resolved, "rev-parse", "--abbrev-ref", "HEAD", runner=runner)
    branch = (branch_proc.stdout or "").strip() if branch_proc.returncode == 0 else ""
    default = _default_branch(resolved, runner=runner)
    if default and branch and branch != default:
        return _refuse(
            "EBRANCH",
            f"HEAD is on {branch!r}, not default {default!r}; pip_sync refused",
            branch=branch, default_branch=default,
        )

    venv_info = _resolve_venv(venv_name, venvs_root=roots)
    if not venv_info.get("ok"):
        return venv_info
    venv_path: Path = venv_info["path"]
    python: Path = venv_info["python"]
    writ = _check_writable(venv_path)
    if writ is not None:
        return writ

    pkg = _package_name(resolved)
    before = _installed_version(python, pkg, runner=runner) if pkg else None
    req_hash = _requirement_hash(resolved, extra_tokens)
    target = str(resolved)
    if extra_tokens:
        target = f"{resolved}[{','.join(extra_tokens)}]"

    run = runner or subprocess.run
    argv = [str(python), "-m", "pip", "install", "--upgrade", "-e", target]
    try:
        proc = run(
            argv,
            capture_output=True, text=True, timeout=_PIP_TIMEOUT_S,
            check=False, env=_scrubbed_pip_env(),
        )
    except subprocess.TimeoutExpired:
        content = {
            "app_id": app_id, "session": session, "venv": venv_name,
            "checkout": str(resolved), "repo": slug, "extras": extra_tokens,
            "requirement_hash": req_hash, "before": before, "errno": "EINSTALL",
            "reason": f"pip timed out after {_PIP_TIMEOUT_S}s",
        }
        rid = _append_receipt(ledger, project=project or slug, event=FAILED_EVENT, content=content)
        return _refuse("EINSTALL", content["reason"], receipt_id=rid, **content)

    if proc.returncode != 0:
        tail = "\n".join((proc.stderr or proc.stdout or "").strip().splitlines()[-12:])
        content = {
            "app_id": app_id, "session": session, "venv": venv_name,
            "checkout": str(resolved), "repo": slug, "extras": extra_tokens,
            "requirement_hash": req_hash, "before": before, "errno": "EINSTALL",
            "reason": tail or f"pip exited {proc.returncode}",
            "pip_rc": proc.returncode,
        }
        rid = _append_receipt(ledger, project=project or slug, event=FAILED_EVENT, content=content)
        return _refuse("EINSTALL", content["reason"], receipt_id=rid,
                       venv=venv_name, checkout=str(resolved), repo=slug,
                       extras=extra_tokens, pip_rc=proc.returncode)

    after = _installed_version(python, pkg, runner=runner) if pkg else None
    content = {
        "app_id": app_id, "session": session, "venv": venv_name,
        "checkout": str(resolved), "repo": slug, "extras": extra_tokens,
        "package": pkg, "before": before, "after": after,
        "requirement_hash": req_hash, "branch": branch,
    }
    rid = _append_receipt(ledger, project=project or slug, event=EVENT, content=content)
    return {
        "ok": True, "synced": True, "venv": venv_name, "checkout": str(resolved),
        "repo": slug, "extras": extra_tokens, "package": pkg,
        "before": before, "after": after, "requirement_hash": req_hash,
        "receipt_id": rid, "branch": branch,
    }
