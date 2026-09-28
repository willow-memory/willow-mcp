"""Standalone worker for Loki 6FC22847's N4 (separate-interpreters) probe.
Invoked as a fresh `python` subprocess per session -- shares no in-process
state with the pytest process or with its siblings (same shape as
_bite1_subprocess_worker.py's N4 predecessor). Waits on a file-based barrier
so every sibling races the SAME packet's session_enter in the same narrow
window."""
import json
import os
import sys
import time


def _wait_go(go_path: str) -> None:
    while not os.path.exists(go_path):
        time.sleep(0.005)


def main() -> None:
    dispatch_id, idx, go_path, out_path = sys.argv[1:5]
    from willow_mcp import dispatch as ds

    _wait_go(go_path)
    result = ds.session_enter("loki", f"sess-n4-{idx}", dispatch_id=dispatch_id)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f)


if __name__ == "__main__":
    main()
