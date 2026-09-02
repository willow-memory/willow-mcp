"""The serve port must not depend on how the server was started.

`scripts/willow-serve` defaulted to 8766 while `src/willow_mcp/server.py`
defaults to 8765, so the listening port depended on whether you ran the module
or the wrapper — and the unit installed on a live box had taken 8766.

8766 is willows-grove's desk page, sealed loopback-only (D4). KB 2026B306 is
explicit that remote Pangolin terminates "at :8765 only, never :8766". A remote
seat pointed at "the serve port" was therefore one race away from publishing the
desk page instead of the MCP endpoint.

The fleet map (willows-grove docs/runbooks/grove.md carries the same table):

    8765  willow-mcp --serve      tunnelled — the ratified remote seat
    8766  grove_serve.py desk     NEVER tunnelled — loopback only
    8767  grove/mcp_local.py      tunnelled as its own resource

Read from source rather than by importing and inspecting runtime state: the
question is what a fresh install gets, and other suites mutate the environment.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SERVE_PORT = 8765
GROVE_DESK_PORT = 8766


def _module_default() -> int:
    src = (ROOT / "src" / "willow_mcp" / "server.py").read_text()
    m = re.search(r'os\.getenv\(\s*"WILLOW_MCP_PORT",\s*"(\d+)"\s*\)', src)
    assert m, "WILLOW_MCP_PORT default not found in server.py"
    return int(m.group(1))


def _wrapper_default() -> int:
    src = (ROOT / "scripts" / "willow-serve").read_text()
    m = re.search(r'PORT="\$\{WILLOW_MCP_PORT:-(\d+)\}"', src)
    assert m, "PORT default not found in scripts/willow-serve"
    return int(m.group(1))


def test_wrapper_and_module_agree():
    assert _wrapper_default() == _module_default(), (
        "scripts/willow-serve and server.py disagree on the port; the listening "
        "port then depends on how the server was started"
    )


def test_serve_port_is_the_ratified_one():
    assert _module_default() == SERVE_PORT


def test_serve_never_binds_the_loopback_only_desk_port():
    assert _module_default() != GROVE_DESK_PORT
    assert _wrapper_default() != GROVE_DESK_PORT
