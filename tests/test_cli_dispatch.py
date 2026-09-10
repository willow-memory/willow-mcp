"""`_main`'s dispatch table and its parser must agree, in both directions.

The bug this file exists to prevent is #458's, generalized. `_main` used to
dispatch ~45 subcommands as a flat `if args.command == "...":` ladder in which
every branch was responsible for terminating itself. Nothing enforced that a
branch did. `sign-net-task` did not: it signed, printed the envelope, then fell
through every remaining comparison and off the end of the ladder into the stdio
server boot. Since `sign-net-task` refuses to run outside an operator terminal,
the operator saw a hang, Ctrl-C'd, read a `KeyboardInterrupt` out of `asyncio`,
and never noticed the envelope a few lines above it.

#458 fixed that one branch and tested that one branch. This tests the shape:
a subcommand registered with the parser but missing from `_COMMANDS` would
silently boot a server, and an entry in `_COMMANDS` naming a subcommand the
parser does not register is dead weight that reads as wiring. Both are caught
here, at test time, rather than by an operator at a terminal.
"""
from __future__ import annotations

import argparse

from willow_mcp import server


def _parser_commands() -> set[str]:
    """Every subcommand name the real parser registers.

    Read off the parser rather than hardcoded: the point is to catch a
    subcommand someone adds, and a list maintained here by hand would need
    the same discipline the ladder needed.
    """
    parser = server._build_parser()
    names: set[str] = set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            names.update(action.choices)
    return names


def test_parser_registers_subcommands():
    """Guard the guard: if this ever comes back empty the two tests below
    would pass vacuously, having compared nothing to nothing."""
    assert len(_parser_commands()) > 20


def test_every_subcommand_has_a_handler():
    """A subcommand the parser knows and the table does not falls through to
    the server boot — #458 exactly."""
    missing = _parser_commands() - set(server._COMMANDS)
    assert not missing, (
        f"subcommand(s) {sorted(missing)} are registered with the parser but "
        f"absent from server._COMMANDS — running one would fall through the "
        f"dispatch and boot the MCP server instead"
    )


def test_every_handler_has_a_subcommand():
    """The other direction: an entry naming a subcommand the parser does not
    register can never be reached, and reads as wiring that exists."""
    unreachable = set(server._COMMANDS) - _parser_commands()
    assert not unreachable, (
        f"server._COMMANDS names {sorted(unreachable)}, which the parser does "
        f"not register — unreachable dispatch entries"
    )


def test_every_handler_name_resolves():
    """The table holds handler names so dispatch stays late-bound (the ladder
    resolved `_cmd_*` through the module namespace at call time, and #458's
    regression test monkeypatches exactly that). The cost of names over
    function objects is that a typo is not a NameError at import — so resolve
    every one of them here, which is where that cost is paid back."""
    for command, handler_name in server._COMMANDS.items():
        handler = getattr(server, handler_name, None)
        assert handler is not None, (
            f"{command!r} maps to {handler_name!r}, which does not exist on "
            f"the server module"
        )
        assert callable(handler), f"handler for {command!r} is not callable"


def test_unknown_command_does_not_dispatch():
    """`_COMMANDS` is consulted with `.get`, so an unrecognized command must
    fall to the server boot deliberately rather than raise KeyError — bare
    `willow-mcp` with no subcommand is the ordinary stdio-server invocation."""
    assert server._COMMANDS.get("no-such-command") is None
    assert server._COMMANDS.get(None) is None
