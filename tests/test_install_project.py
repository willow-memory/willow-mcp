"""Tests for willow_mcp.install_project — atomic merge with third-party preservation.

The critical property: a user's hand-added third-party hook in
`.claude/settings.json` must SURVIVE a reinstall. Fylgja's `_merge_event_hooks`
is exactly this — the fleet does not own the whole file, only its own
entries. The alternative (full-file overwrite, which the current fleet
does via `sync_desk_client_hooks.py`) silently eats a user's config.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from willow_mcp import install_project as ip


# ── _is_managed_entry ──────────────────────────────────────────────────────


def test_managed_entry_true_for_hook_runner_command():
    entry = {
        "hooks": [
            {"type": "command", "command": "python3 -m willow_mcp.hook_runner --format claude pre_tool"},
        ]
    }
    assert ip._is_managed_entry(entry) is True


def test_managed_entry_true_for_pre_tool_hook_command():
    entry = {
        "hooks": [
            {"type": "command", "command": "python3 -m willow_mcp.pre_tool_hook"},
        ]
    }
    assert ip._is_managed_entry(entry) is True


def test_managed_entry_true_for_bundle_hook_path():
    entry = {
        "hooks": [
            {"type": "command", "command": "python3 ${CLAUDE_PLUGIN_ROOT}/hooks/pre_tool_use.py"},
        ]
    }
    assert ip._is_managed_entry(entry) is True


def test_managed_entry_true_for_grove_hook_command():
    """PR 2c: grove-hook and nestor-hook wrappers are fleet-managed when
    a sibling repo delegates its write through apply_hooks. Without this,
    Grove's own hook rows would be misclassified as third-party by its
    own installer and never replaced on re-sync."""
    entry = {
        "hooks": [
            {"type": "command", "command": '"$CLAUDE_PROJECT_DIR/hooks/grove-hook" claude before_web'},
        ]
    }
    assert ip._is_managed_entry(entry) is True


def test_managed_entry_true_for_nestor_hook_command():
    entry = {
        "hooks": [
            {"type": "command", "command": '"$CLAUDE_PROJECT_DIR/hooks/nestor-hook" claude before_bash'},
        ]
    }
    assert ip._is_managed_entry(entry) is True


def test_managed_entry_false_for_third_party_command():
    """A user's hand-added tool must NOT match any managed signature."""
    entry = {
        "hooks": [
            {"type": "command", "command": "python3 ~/scripts/my-custom-guard.py"},
        ]
    }
    assert ip._is_managed_entry(entry) is False


def test_managed_entry_false_for_empty_hooks_list():
    """An entry with no hooks is not considered managed — a real installer
    should refuse to overwrite it either way."""
    assert ip._is_managed_entry({"hooks": []}) is False
    assert ip._is_managed_entry({}) is False


def test_managed_entry_false_for_mixed_managed_and_third_party():
    """A hooks entry mixing a managed hook with a third-party hook is NOT
    wholly managed — conservatively preserve it. Losing the third-party half
    to a reinstall would be the same bug as full-file overwrite."""
    entry = {
        "hooks": [
            {"type": "command", "command": "python3 -m willow_mcp.pre_tool_hook"},
            {"type": "command", "command": "python3 ~/scripts/other-guard.py"},
        ]
    }
    assert ip._is_managed_entry(entry) is False


# ── _merge_event_hooks ─────────────────────────────────────────────────────


def test_merge_replaces_managed_and_preserves_third_party():
    """The core invariant: after merge, managed entries come from `managed`,
    every non-managed entry from `existing` survives."""
    existing = [
        {
            "matcher": "Bash",
            "hooks": [
                {"type": "command", "command": "python3 -m willow_mcp.pre_tool_hook"},
            ],
        },
        {
            "matcher": "Bash",
            "hooks": [
                {"type": "command", "command": "python3 ~/scripts/my-guard.py"},
            ],
        },
    ]
    managed = [
        {
            "matcher": "Bash",
            "hooks": [
                {"type": "command", "command": "python3 -m willow_mcp.hook_runner --format claude pre_tool"},
            ],
        },
    ]
    merged = ip._merge_event_hooks(existing, managed)
    assert len(merged) == 2
    assert merged[0] == managed[0]  # managed first
    assert merged[1]["hooks"][0]["command"].endswith("my-guard.py")  # third-party survives


def test_merge_empty_existing_returns_managed_only():
    """A fresh clone has no existing settings.json — the merge yields
    exactly the managed set."""
    managed = [
        {
            "matcher": "Bash",
            "hooks": [
                {"type": "command", "command": "python3 -m willow_mcp.hook_runner --format claude pre_tool"},
            ],
        }
    ]
    assert ip._merge_event_hooks([], managed) == managed
    assert ip._merge_event_hooks(None, managed) == managed


def test_merge_empty_managed_preserves_all_existing():
    """A managed block with no entries (say, an event willow-mcp does not
    wire) must not blindly drop the user's entries for that event."""
    existing = [
        {
            "matcher": "Bash",
            "hooks": [
                {"type": "command", "command": "python3 ~/scripts/my-guard.py"},
            ],
        },
    ]
    assert ip._merge_event_hooks(existing, []) == existing


# ── apply_hooks / atomic write ─────────────────────────────────────────────


def _write_template(pkg: Path, hooks: dict) -> None:
    """Write a minimal deploy/claude-settings.json under `pkg`."""
    deploy = pkg / "deploy"
    deploy.mkdir(parents=True, exist_ok=True)
    (deploy / "claude-settings.json").write_text(json.dumps({"hooks": hooks}), encoding="utf-8")


def test_apply_hooks_writes_settings_when_none_exists(tmp_path):
    pkg = tmp_path / "willow_mcp"
    _write_template(
        pkg,
        {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "{{WILLOW_MCP_PYTHON}} -m willow_mcp.hook_runner --format claude pre_tool",
                        },
                    ],
                },
            ]
        },
    )
    settings = tmp_path / "settings.json"
    ip.apply_hooks(settings, pkg, python_bin="/opt/py/bin/python3")
    landed = json.loads(settings.read_text())
    cmd = landed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd.startswith("/opt/py/bin/python3 -m willow_mcp.hook_runner")


def test_apply_hooks_preserves_third_party_entry(tmp_path):
    """The load-bearing invariant: a user's third-party hook in
    settings.json survives a re-install."""
    pkg = tmp_path / "willow_mcp"
    _write_template(
        pkg,
        {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "{{WILLOW_MCP_PYTHON}} -m willow_mcp.hook_runner --format claude pre_tool",
                        },
                    ],
                },
            ]
        },
    )
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "python3 ~/my-guard.py"},
                            ],
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    ip.apply_hooks(settings, pkg, python_bin="/opt/py/bin/python3")
    landed = json.loads(settings.read_text())
    cmds = [h["command"] for e in landed["hooks"]["PreToolUse"] for h in e["hooks"]]
    assert any("my-guard.py" in c for c in cmds), "third-party hook must survive"
    assert any("willow_mcp.hook_runner" in c for c in cmds)


def test_apply_hooks_replaces_previously_managed_entry(tmp_path):
    """A re-install must REPLACE willow-mcp's own prior entry (say, an
    older shape) with the fresh one — not stack them."""
    pkg = tmp_path / "willow_mcp"
    _write_template(
        pkg,
        {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "{{WILLOW_MCP_PYTHON}} -m willow_mcp.hook_runner --format claude pre_tool",
                        },
                    ],
                },
            ]
        },
    )
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                # Legacy shape from an older install
                                {"type": "command", "command": "python3 -m willow_mcp.pre_tool_hook"},
                            ],
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    ip.apply_hooks(settings, pkg, python_bin="/opt/py/bin/python3")
    landed = json.loads(settings.read_text())
    entries = landed["hooks"]["PreToolUse"]
    assert len(entries) == 1  # replaced, not stacked
    assert "hook_runner" in entries[0]["hooks"][0]["command"]


def test_apply_hooks_refuses_to_overwrite_unparseable_settings(tmp_path):
    """A settings.json the user broke by hand must not be silently discarded."""
    pkg = tmp_path / "willow_mcp"
    _write_template(pkg, {"PreToolUse": []})
    settings = tmp_path / "settings.json"
    settings.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        ip.apply_hooks(settings, pkg, python_bin="/opt/py/bin/python3")
    # The broken content is still on disk.
    assert settings.read_text() == "{not valid json"


def test_apply_hooks_atomic_write_leaves_original_on_failure(tmp_path, monkeypatch):
    """An interrupted write must leave the original settings.json intact —
    the `.tmp` file may exist, but the target keeps its old bytes."""
    pkg = tmp_path / "willow_mcp"
    _write_template(
        pkg,
        {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "{{WILLOW_MCP_PYTHON}} -m willow_mcp.hook_runner --format claude pre_tool",
                        },
                    ],
                },
            ]
        },
    )
    settings = tmp_path / "settings.json"
    original = json.dumps({"hooks": {}, "user_key": "keep_me"})
    settings.write_text(original, encoding="utf-8")

    # Force replace() to fail after .tmp has been written.
    def blow_up(self, target):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(Path, "replace", blow_up)

    with pytest.raises(OSError):
        ip.apply_hooks(settings, pkg, python_bin="/opt/py/bin/python3")
    assert settings.read_text() == original


def test_apply_hooks_dry_run_writes_nothing(tmp_path):
    pkg = tmp_path / "willow_mcp"
    _write_template(
        pkg,
        {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "{{WILLOW_MCP_PYTHON}} -m willow_mcp.hook_runner --format claude pre_tool",
                        },
                    ],
                },
            ]
        },
    )
    settings = tmp_path / "settings.json"
    settings.write_text('{"hooks": {}}', encoding="utf-8")
    merged = ip.apply_hooks(settings, pkg, dry_run=True, python_bin="/opt/py/bin/python3")
    # dict returned with the merge applied…
    cmds = [h["command"] for e in merged["hooks"]["PreToolUse"] for h in e["hooks"]]
    assert any("willow_mcp.hook_runner" in c for c in cmds)
    # …but the file was NOT touched.
    assert json.loads(settings.read_text()) == {"hooks": {}}


# ── _resolve_python_bin ────────────────────────────────────────────────────


def test_resolve_python_bin_prefers_explicit_arg(monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_PYTHON", "/env/bin/python3")
    assert ip._resolve_python_bin("/explicit/py3") == "/explicit/py3"


def test_resolve_python_bin_uses_env_when_no_arg(monkeypatch):
    monkeypatch.setenv("WILLOW_MCP_PYTHON", "/env/bin/python3")
    assert ip._resolve_python_bin(None) == "/env/bin/python3"


def test_resolve_python_bin_falls_back_to_sys_executable(monkeypatch):
    import sys as _sys

    monkeypatch.delenv("WILLOW_MCP_PYTHON", raising=False)
    assert ip._resolve_python_bin(None) == _sys.executable


def test_resolve_python_bin_treats_blank_env_as_unset(monkeypatch):
    """An empty env var must NOT resolve to `""` — that would produce a
    settings command starting with a space, silently unparseable."""
    import sys as _sys

    monkeypatch.setenv("WILLOW_MCP_PYTHON", "   ")
    assert ip._resolve_python_bin(None) == _sys.executable


# ── apply_hooks(managed_hooks=…) — the pre-rendered path (PR 2c) ──────────

_GROVE_HOOKS = {
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": '"$CLAUDE_PROJECT_DIR/hooks/grove-hook" claude before_bash',
                    },
                ],
            },
        ],
    }
}


def test_apply_hooks_accepts_pre_rendered_managed_block(tmp_path):
    """A sibling repo (e.g. willows-grove/scripts/sync_desk_client_hooks.py)
    compiles its own managed block from its neutral manifest and passes it
    through `apply_hooks(managed_hooks=...)`. The willow-mcp template is
    NOT read in this shape — the caller owns the block."""
    settings = tmp_path / "settings.json"
    ip.apply_hooks(settings, managed_hooks=_GROVE_HOOKS)
    landed = json.loads(settings.read_text())
    cmd = landed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "grove-hook" in cmd
    # And the willow-mcp template was NOT read (no pre_tool_hook / hook_runner
    # invocation snuck in from a phantom render).
    assert "willow_mcp." not in cmd


def test_apply_hooks_pre_rendered_preserves_third_party(tmp_path):
    """The core preservation invariant applies to the pre-rendered path too:
    a user's hand-added third-party hook in the project-local settings.json
    survives a delegated write from a sibling repo's installer."""
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "python3 ~/my-guard.py"},
                            ],
                        },
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    ip.apply_hooks(settings, managed_hooks=_GROVE_HOOKS)
    landed = json.loads(settings.read_text())
    cmds = [h["command"] for e in landed["hooks"]["PreToolUse"] for h in e["hooks"]]
    assert any("my-guard.py" in c for c in cmds), "third-party hook must survive"
    assert any("grove-hook" in c for c in cmds), "grove-hook must land"


def test_apply_hooks_pre_rendered_replaces_previously_managed_grove_entry(tmp_path):
    """The same "replace, don't stack" rule applies to grove-hook rows: a
    prior grove-hook entry from a previous sync is REPLACED by the fresh
    one, not doubled up. This is why `_MANAGED_SIGNATURES` gained the
    grove-hook / nestor-hook substrings in this PR."""
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": '"$CLAUDE_PROJECT_DIR/hooks/grove-hook" claude before_bash_LEGACY',
                                },
                            ],
                        },
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    ip.apply_hooks(settings, managed_hooks=_GROVE_HOOKS)
    landed = json.loads(settings.read_text())
    entries = landed["hooks"]["PreToolUse"]
    assert len(entries) == 1, "prior grove-hook entry must be replaced, not stacked"
    assert "before_bash_LEGACY" not in entries[0]["hooks"][0]["command"]


def test_apply_hooks_pre_rendered_needs_dict_shape(tmp_path):
    """`managed_hooks=` must be a dict; passing a list or a string is a
    caller bug and must raise with a clear message rather than silently
    doing nothing."""
    settings = tmp_path / "settings.json"
    with pytest.raises(TypeError, match="managed_hooks"):
        ip.apply_hooks(settings, managed_hooks=["not-a-dict"])  # type: ignore[arg-type]


def test_apply_hooks_needs_either_package_root_or_managed_hooks(tmp_path):
    """Called with neither `package_root` nor `managed_hooks`, apply_hooks
    cannot know what to write. Raise with a message naming both options."""
    settings = tmp_path / "settings.json"
    with pytest.raises(ValueError, match="package_root.*managed_hooks|managed_hooks.*package_root"):
        ip.apply_hooks(settings)


def test_apply_hooks_pre_rendered_forwards_top_level_keys(tmp_path):
    """A pre-rendered block that carries top-level keys beyond `hooks`
    (Grove ships an ambient `env` block, for example) must land in the
    written settings.json. Only the `hooks` key gets per-event merge; every
    other top-level key the caller sets overwrites `existing` verbatim."""
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"model": "opus", "env": {"OLD_KEY": "keep"}}),
        encoding="utf-8",
    )
    block = {
        "hooks": _GROVE_HOOKS["hooks"],
        "env": {
            "WILLOW_APP_ID": "willow",
            "WILLOW_KEYRING": "${WILLOW_HOME}/config/verifiers.json",
        },
    }
    ip.apply_hooks(settings, managed_hooks=block)
    landed = json.loads(settings.read_text())
    # Fresh env block landed in full — this is the whole point of the
    # forwarding: sibling installers get one call, not two writes.
    assert landed["env"] == block["env"]
    # A top-level key `existing` had that `fresh` didn't touch stays put.
    assert landed["model"] == "opus"
    # And the hooks side still merged, not overwritten.
    assert "grove-hook" in landed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]


def test_apply_hooks_template_path_does_not_forward_unknown_top_level(tmp_path):
    """The template path (no `managed_hooks=`) keeps its historical seed-only
    behavior — only the shipped `enableAllProjectMcpServers` flag is forwarded,
    and only if `existing` doesn't already declare it. A user's other
    top-level settings (statusLine, model, permissions, whatever) survive.
    """
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"model": "opus"}), encoding="utf-8")

    pkg = tmp_path / "pkg"
    deploy = pkg / "deploy"
    deploy.mkdir(parents=True)
    (deploy / "claude-settings.json").write_text(
        json.dumps(
            {
                "hooks": {},
                "enableAllProjectMcpServers": True,
                # A key the shipped template happens to carry but the seed
                # rule doesn't name; must NOT be forwarded blindly.
                "someUnrelatedFlag": "should-not-land",
            }
        ),
        encoding="utf-8",
    )
    ip.apply_hooks(settings, package_root=pkg, python_bin="/usr/bin/python3")
    landed = json.loads(settings.read_text())
    assert landed["model"] == "opus"
    assert landed.get("enableAllProjectMcpServers") is True
    assert "someUnrelatedFlag" not in landed


def test_apply_hooks_pre_rendered_ignores_package_root(tmp_path):
    """When `managed_hooks=` is supplied, `package_root` is ignored — the
    caller's block wins, and no template file is read (even if the path
    doesn't exist). This is what lets Grove's sync script skip the willow-mcp
    template entirely."""
    settings = tmp_path / "settings.json"
    fake_pkg = tmp_path / "not-real"
    # No `not-real/deploy/claude-settings.json` on disk, yet the call must succeed.
    ip.apply_hooks(settings, package_root=fake_pkg, managed_hooks=_GROVE_HOOKS)
    landed = json.loads(settings.read_text())
    assert "grove-hook" in landed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
