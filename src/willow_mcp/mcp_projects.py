"""Fleet MCP project registry: render + sync per-repo IDE configs (agent-agnostic).

Registry lives at ``$WILLOW_HOME/mcp/projects.json`` (seed:
``src/willow_mcp/deploy/mcp_projects.seed.json``).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import egress_setup
from .paths import store_root, willow_home
from .project_wiring import (
    expand_home,
    normalize_wiring,
    render_cursor_hooks,
    render_project_claude_settings,
    resolve_willow_mcp_python,
)

#: MCP servers this renderer can materialize besides willow-mcp itself. A name
#: outside this table raises in `_static_server_block` rather than rendering a
#: block nobody can launch.
#:
#: These are launched by the IDE directly and are NOT manifest-gated: they get
#: no WILLOW_APP_ID, so willow-mcp's permission groups, store_scope and PGP
#: signature check do not apply. That is the existing shape — codebase-memory-mcp
#: has no manifest in mcp_apps/ — and it is worth knowing before adding a server
#: that reaches the network or holds a key.
_STATIC_SERVERS: dict[str, dict[str, Any]] = {
    "codebase-memory-mcp": {
        "type": "stdio",
        "command": "${HOME}/.local/bin/codebase-memory-mcp",
        "args": [],
    },
    # Nestor's verified corpus over stdio: the model may ask and propose, and
    # cannot seal. Sealing is a human at `nestor.ui`. --read-only is belt to
    # that braces.
    #
    # NESTOR_DB is load-bearing here, not decoration. `nestor` resolves its
    # store from $NESTOR_DB, then $NESTOR_HOME/keep, then a CWD-RELATIVE
    # default — so unpinned, every project would serve a different and usually
    # empty corpus resolved from wherever the IDE started the process, and each
    # one would look healthy. The per-project `server_env` supplies the pin;
    # nestor raises PinRefused on a bad one rather than falling back, so a typo
    # fails loudly instead of forking the corpus.
    "nestor": {
        "type": "stdio",
        "command": "${HOME}/github/Die-Namic-Systems/nestor/.venv/bin/nestor",
        "args": ["serve", "--read-only"],
    },
}


def deploy_dir() -> Path:
    return Path(__file__).resolve().parent / "deploy"


def seed_path() -> Path:
    return deploy_dir() / "mcp_projects.seed.json"


def registry_path() -> Path:
    return willow_home() / "mcp" / "projects.json"


def expand_home_in_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return expand_home(obj)
    if isinstance(obj, list):
        return [expand_home_in_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: expand_home_in_obj(v) for k, v in obj.items()}
    return obj


def _write_json(path: Path, data: dict, *, dry_run: bool) -> None:
    if dry_run:
        print(f"[mcp_projects] Would write {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    print(f"[mcp_projects] Wrote {path}")


def load_seed() -> dict:
    return json.loads(seed_path().read_text(encoding="utf-8"))


def ensure_registry(*, dry_run: bool = False) -> Path:
    """Copy seed → fleet home if projects.json missing."""
    dest = registry_path()
    if dest.is_file():
        return dest
    seed = load_seed()
    _write_json(dest, seed, dry_run=dry_run)
    return dest


def load_registry(*, bootstrap: bool = True) -> dict:
    path = registry_path()
    if not path.is_file():
        if bootstrap:
            ensure_registry(dry_run=False)
        else:
            raise FileNotFoundError(f"MCP registry missing: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("projects"), dict):
        raise ValueError(f"Invalid registry (missing projects): {path}")
    # No seed overlay here. The seed's job is bootstrapping a registry that does
    # not exist yet (ensure_registry above); it is not a source of truth for one
    # that does. Overlaying it on every load meant the seed's entries — shipped
    # identically to every install — silently replaced whatever the operator had
    # under those project ids, and persist=True wrote the loss to disk, so a
    # local correction reverted on the next load with nothing reporting it.
    return data


def list_projects() -> list[dict[str, Any]]:
    reg = load_registry()
    rows: list[dict[str, Any]] = []
    for pid, entry in sorted(reg.get("projects", {}).items()):
        if not isinstance(entry, dict):
            continue
        rows.append(
            {
                "id": pid,
                "path": entry.get("path", ""),
                "agent": entry.get("agent", ""),
                "servers": list(entry.get("servers") or []),
                "ides": list(entry.get("ides") or []),
                "note": entry.get("note", ""),
                "wiring": normalize_wiring(entry),
            }
        )
    return rows


def _egress_public_key_env() -> dict[str, str]:
    pub = egress_setup.resolve_public_key_path()
    if pub is not None and pub.is_file():
        return {"WILLOW_MCP_EGRESS_PUBLIC_KEY": str(pub.resolve())}
    return {}


def _skip_store_override(
    key: str, val: str, entry: dict[str, Any], *, project_id: str
) -> bool:
    if key != "WILLOW_STORE_ROOT" or project_id != "willow":
        return False
    expanded = expand_home(val)
    # Names the legacy fleet SOIL path in order to skip the override, never to use it.
    if "github/willow/.willow/store" in expanded:  # path-guard: allow
        return True
    raw_path = str(entry.get("path") or "").strip()
    if raw_path:
        project_root = Path(expand_home(raw_path)).resolve()
        try:
            if Path(expanded).resolve() == (project_root / ".willow" / "store").resolve():
                return True
        except OSError:
            pass
    return False


def _willow_mcp_server_block(
    *,
    project_id: str,
    agent: str,
    entry: dict[str, Any],
    extra_env: dict[str, Any] | None = None,
    human_orchestrator: bool = False,
) -> dict[str, Any]:
    env: dict[str, str] = {
        "WILLOW_APP_ID": agent,
        "WILLOW_PG_DB": "willow_20",
        "WILLOW_HOME": str(willow_home().resolve()),
        "WILLOW_STORE_ROOT": str(store_root().resolve()),
    }
    if human_orchestrator or agent.strip().lower() == "willow":
        env["WILLOW_HUMAN_ORCHESTRATOR"] = "1"
    env.update(_egress_public_key_env())
    for key, val in (extra_env or {}).items():
        if isinstance(val, str):
            if _skip_store_override(key, val, entry, project_id=project_id):
                continue
            env[key] = expand_home(val)
    return {
        "type": "stdio",
        "command": resolve_willow_mcp_python(),
        "args": ["-m", "willow_mcp"],
        "env": env,
    }


def _static_server_block(
    name: str,
    extra_env: dict[str, Any] | None = None,
    args_override: list[str] | None = None,
) -> dict[str, Any]:
    if name not in _STATIC_SERVERS:
        raise ValueError(f"unknown static server {name!r}")
    block = json.loads(json.dumps(_STATIC_SERVERS[name]))
    if args_override is not None:
        block["args"] = list(args_override)
    if extra_env:
        env = block.setdefault("env", {})
        if isinstance(env, dict):
            for key, val in extra_env.items():
                if isinstance(val, str):
                    env[key] = expand_home(val)
    return block


def _validated_server_args(
    project_id: str,
    entry: dict[str, Any],
    servers: list[Any],
) -> dict[str, list[str]]:
    raw = entry.get("server_args")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise TypeError(f"project {project_id!r}: server_args must be an object")
    selected = {name for name in servers if isinstance(name, str)}
    validated: dict[str, list[str]] = {}
    for name, args in raw.items():
        if not isinstance(name, str) or name not in _STATIC_SERVERS:
            raise ValueError(
                f"project {project_id!r}: server_args only supports static servers; "
                f"got {name!r}"
            )
        if (
            not isinstance(args, list)
            or not args
            or any(not isinstance(arg, str) or not arg.strip() for arg in args)
        ):
            raise TypeError(
                f"project {project_id!r}: server_args[{name!r}] "
                "must be a non-empty list of non-empty strings"
            )
        if name not in selected:
            raise ValueError(
                f"project {project_id!r}: server_args configured for unselected "
                f"server {name!r}"
            )
        validated[name] = list(args)
    return validated


def render_project_mcp(
    project_id: str,
    entry: dict[str, Any],
) -> dict[str, Any]:
    agent = str(entry.get("agent") or "willow").strip()
    servers = entry.get("servers") or []
    if not isinstance(servers, list) or not servers:
        raise ValueError(f"project {project_id!r}: servers[] required")

    willow_env = dict(entry.get("env") if isinstance(entry.get("env"), dict) else {})
    raw_path = str(entry.get("path") or "").strip()
    if raw_path:
        willow_env.setdefault("WILLOW_PROJECT_ROOT", raw_path)
    willow_env.setdefault("WILLOW_HANDOFF_PROJECT", project_id)
    server_env = entry.get("server_env") if isinstance(entry.get("server_env"), dict) else {}
    server_args = _validated_server_args(project_id, entry, servers)

    mcp_servers: dict[str, Any] = {}
    for name in servers:
        if not isinstance(name, str):
            continue
        if name == "willow-mcp":
            mcp_servers["willow-mcp"] = _willow_mcp_server_block(
                project_id=project_id,
                agent=agent,
                entry=entry,
                extra_env=willow_env,
                human_orchestrator=agent.strip().lower() == "willow",
            )
        elif name in _STATIC_SERVERS:
            overrides = server_env.get(name) if isinstance(server_env.get(name), dict) else {}
            mcp_servers[name] = _static_server_block(
                name,
                overrides,
                server_args.get(name),
            )
        else:
            raise ValueError(f"project {project_id!r}: unknown server {name!r}")

    return {"mcpServers": mcp_servers}


def render_charter_codex_config(
    project_id: str,
    entry: dict[str, Any],
) -> str:
    """Codex MCP fragment for the charter Jarvis seat."""
    if project_id != "willow":
        raise ValueError(f"charter codex template only applies to project 'willow', not {project_id!r}")
    template = (deploy_dir() / "charter-codex-mcp.toml.template").read_text(encoding="utf-8")
    agent = str(entry.get("agent") or "willow").strip()
    env_overrides = entry.get("env") if isinstance(entry.get("env"), dict) else {}
    store = str(env_overrides.get("WILLOW_STORE_ROOT") or str(store_root().resolve()))
    project_root = str(env_overrides.get("WILLOW_PROJECT_ROOT") or "{{HOME}}/github/willow")
    handoff = str(env_overrides.get("WILLOW_HANDOFF_PROJECT") or project_id)
    values = {
        "AGENT_NAME": agent,
        "WILLOW_HOME": str(willow_home().resolve()),
        "WILLOW_MCP_PYTHON": resolve_willow_mcp_python(),
        "WILLOW_STORE_ROOT": expand_home(store),
        "WILLOW_PROJECT_ROOT": expand_home(project_root),
        "WILLOW_HANDOFF_PROJECT": handoff,
    }
    out = template
    for key, val in values.items():
        out = out.replace(f"{{{{{key}}}}}", val)
    return out.rstrip() + "\n"


def project_paths(project_id: str, entry: dict[str, Any]) -> dict[str, Path]:
    raw = str(entry.get("path") or "").strip()
    if not raw:
        raise ValueError(f"project {project_id!r}: path required")
    root = Path(expand_home(raw)).resolve()
    home_mcp = willow_home() / "mcp" / f"{project_id}.mcp.json"
    return {
        "root": root,
        "canonical": home_mcp,
        "cursor": root / ".cursor" / "mcp.json",
        "claude_mcp": root / ".mcp.json",
        "claude_settings": root / ".claude" / "settings.local.json",
        "codex_config": root / ".codex" / "config.toml",
    }


def _normalize_mcp_json(data: dict) -> str:
    canonical = expand_home_in_obj(data)
    return json.dumps(canonical, sort_keys=True, indent=2) + "\n"


def audit_project(
    project_id: str,
    entry: dict[str, Any],
) -> list[str]:
    """Return drift messages (empty = in sync)."""
    from .project_wiring import audit_project_wiring

    issues: list[str] = []
    expected = render_project_mcp(project_id, entry)
    paths = project_paths(project_id, entry)
    expected_text = _normalize_mcp_json(expected)

    for label, path in (
        ("canonical", paths["canonical"]),
        ("cursor", paths["cursor"]),
        ("claude_mcp", paths["claude_mcp"]),
    ):
        if not path.is_file():
            issues.append(f"{project_id}: missing {label} → {path}")
            continue
        try:
            on_disk = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            issues.append(f"{project_id}: unreadable {label} ({path}): {e}")
            continue
        if _normalize_mcp_json(on_disk) != expected_text:
            issues.append(f"{project_id}: drift {label} → {path}")

    ides = entry.get("ides") or []
    wiring = normalize_wiring(entry)
    if "claude" in ides and wiring.get("claude_settings") == "project":
        settings = paths["claude_settings"]
        try:
            expected_settings = render_project_claude_settings(
                entry, project_id=project_id
            )
        except (TypeError, ValueError):
            # audit_project_wiring reports the precise manifest/client error
            # below. An audit is a report, not an exception path.
            expected_settings = None
        if expected_settings is not None:
            if not settings.is_file():
                issues.append(f"{project_id}: missing claude settings → {settings}")
            else:
                try:
                    on_disk = json.loads(settings.read_text(encoding="utf-8"))
                except Exception as e:
                    issues.append(f"{project_id}: unreadable claude settings: {e}")
                else:
                    keys = (
                        "permissions",
                        "enableAllProjectMcpServers",
                        "enabledMcpjsonServers",
                        "hooks",
                        "env",
                    )
                    for key in keys:
                        if on_disk.get(key) != expected_settings.get(key):
                            issues.append(
                                f"{project_id}: claude settings drift ({key}) "
                                f"→ {settings}"
                            )
                            break

    issues.extend(audit_project_wiring(project_id, entry))

    proj_path = paths["root"]
    if not proj_path.is_dir():
        issues.append(f"{project_id}: path does not exist → {proj_path}")

    return issues


def sync_project(
    project_id: str,
    entry: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Path]:
    from .project_wiring import sync_project_wiring

    payload = render_project_mcp(project_id, entry)
    paths = project_paths(project_id, entry)
    ides = entry.get("ides") or []
    wiring = normalize_wiring(entry)

    # Validate all project-owned hook inputs before any MCP or hook config is
    # replaced. In particular, an unsupported client mapping must not produce
    # a half-updated project.
    if "cursor" in ides and wiring.get("hooks"):
        render_cursor_hooks(entry, project_id=project_id)
    claude_settings = (
        render_project_claude_settings(entry, project_id=project_id)
        if "claude" in ides and wiring.get("claude_settings") == "project"
        else None
    )

    for label, path in (
        ("canonical", paths["canonical"]),
        ("cursor", paths["cursor"] if "cursor" in ides else None),
        ("claude_mcp", paths["claude_mcp"] if "claude" in ides else None),
    ):
        if path is None:
            continue
        _write_json(path, payload, dry_run=dry_run)

    if "claude" in ides and wiring.get("claude_settings") == "project":
        assert claude_settings is not None
        _write_json(
            paths["claude_settings"],
            claude_settings,
            dry_run=dry_run,
        )

    if "codex" in ides and project_id == "willow":
        codex_path = paths.get("codex_config")
        if codex_path is not None:
            text = render_charter_codex_config(project_id, entry)
            if dry_run:
                print(f"[mcp_projects] Would write {codex_path}")
            else:
                codex_path.parent.mkdir(parents=True, exist_ok=True)
                codex_path.write_text(text, encoding="utf-8")
                print(f"[mcp_projects] Wrote {codex_path}")

    sync_project_wiring(project_id, entry, dry_run=dry_run)

    return paths


def sync_all(
    *,
    project_ids: list[str] | None = None,
    dry_run: bool = False,
) -> list[str]:
    reg = load_registry()
    projects: dict[str, Any] = reg.get("projects", {})
    selected = project_ids or sorted(projects.keys())
    written: list[str] = []
    for pid in selected:
        entry = projects.get(pid)
        if not isinstance(entry, dict):
            raise KeyError(f"Unknown project {pid!r}")
        sync_project(pid, entry, dry_run=dry_run)
        written.append(pid)
    return written


def audit_all(
    *,
    project_ids: list[str] | None = None,
) -> list[str]:
    reg = load_registry()
    projects: dict[str, Any] = reg.get("projects", {})
    selected = project_ids or sorted(projects.keys())
    issues: list[str] = []
    seen_roots: dict[Path, str] = {}
    for pid in selected:
        entry = projects.get(pid)
        if not isinstance(entry, dict):
            issues.append(f"Unknown project {pid!r}")
            continue
        raw = str(entry.get("path") or "").strip()
        if raw:
            resolved = Path(expand_home(raw)).resolve()
            prior = seen_roots.get(resolved)
            if prior is not None:
                continue
            seen_roots[resolved] = pid
        issues.extend(audit_project(pid, entry))
    return issues
