#!/usr/bin/env bash
# Refresh the repo-level hooks/ mirror from its source, the packaged
# src/willow_mcp/bundle/hooks/ (the tree the wheel ships). Byte copy only;
# tests/test_hook_mirror_parity.py fails when the two differ.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src/willow_mcp/bundle/hooks"
for f in "$SRC"/*.py; do
  cp "$f" "$ROOT/hooks/$(basename "$f")"
done
