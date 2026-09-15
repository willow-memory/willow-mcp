#!/usr/bin/env bash
# Run a command with an operator-owned controlling TTY.
#
# Local mutation CLIs (`allow-permission`, `grant-net`, …) call
# require_operator_terminal(), which refuses non-tty stdin and requires the
# controlling terminal's uid to match the invoking user. GitHub Actions `run:`
# steps have no tty; `script(1)` allocates a pseudo-TTY owned by the runner
# user — the same topology the gate verifies, not an env bypass.
set -euo pipefail
if [[ $# -lt 1 ]]; then
  echo "usage: operator_terminal.sh COMMAND [ARG...]" >&2
  exit 2
fi
cmd=$(printf '%q ' "$@")
exec script -qefc "${cmd}" /dev/null
