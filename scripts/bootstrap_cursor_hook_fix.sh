#!/usr/bin/env bash
# Install cursor_hook_io into operator venv and refresh .cursor/hooks.json.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${WILLOW_MCP_VENV:-$HOME/sean-data-vault/willow-operator-box/venvs/willow-mcp}"
export WILLOW_HOME="${WILLOW_HOME:-$HOME/sean-data-vault/willow-operator-box}"

cp "$ROOT/src/willow_mcp/bundle/hooks/pre_tool_use.py" "$ROOT/hooks/pre_tool_use.py"
"$VENV/bin/pip" install -q -e "$ROOT"
"$VENV/bin/willow-mcp" project sync willow-mcp

PY="$VENV/bin/python"
echo -n "preToolUse allow smoke: "
echo '{"tool_name":"Shell","tool_input":{"command":"echo ok"},"hook_event_name":"preToolUse"}' \
  | "$PY" -m willow_mcp.pre_tool_hook
