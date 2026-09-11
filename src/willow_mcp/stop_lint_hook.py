"""Cursor/Claude Stop hook entry — delegates to the bundle green-claim gate."""
from __future__ import annotations

import importlib.util
from pathlib import Path


def main() -> None:
    hook_path = Path(__file__).resolve().parent / "bundle" / "hooks" / "stop_lint_gate.py"
    spec = importlib.util.spec_from_file_location("willow_mcp_bundle_stop_lint_gate", hook_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load stop_lint hook from {hook_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()


if __name__ == "__main__":
    main()
