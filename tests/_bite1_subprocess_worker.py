"""Standalone worker for bite-1 (dispatch 9BA76253) real-process concurrency
tests. Invoked as a fresh `python` subprocess (never forked) so it shares
no in-process state -- threads, locks, mock patches -- with the pytest
process or with each other. Waits on a file-based barrier so every
sibling worker races the SAME packet in the same narrow window.
"""
import json
import os
import sys
import time


def _wait_go(go_path: str) -> None:
    while not os.path.exists(go_path):
        time.sleep(0.005)


def main() -> None:
    mode, dispatch_id, idx, go_path, out_path = sys.argv[1:6]
    from willow_mcp import dispatch as ds
    from willow_mcp import handoff as ho

    _wait_go(go_path)
    if mode == "accept":
        result = ds.dispatch_accept(dispatch_id, "loki", f"s-{idx}")
    else:
        result = ho.handoff_write_v4(
            "loki",
            dispatch_id,
            findings=[{"text": f"writer {idx}", "evidence": ["e"]}],
            narrative=f"writer {idx}: 1 passed.",
            checklist_resolved=True,
        )
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f)


if __name__ == "__main__":
    main()
