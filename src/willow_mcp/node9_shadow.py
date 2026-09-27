"""node9 shadow mode (sealed ``a6d054b3``, amended by
``node9-shadow-shape-only-ledger-2026-09-27``, an operator ruling that
REPLACES the earlier ``node9-shadow-hybrid-ledger-2026-09-27`` amendment).

node9 judges the same commands the willow guard judges, on two surfaces
(Kart task text via `task_submit`, and Bash tool calls via the PreToolUse
hook). It NEVER blocks, prompts, or changes a verdict — every judgement is
appended to a ledger, and `willow-mcp shadow-report node9` later shows where
the two disagree, by class.

This is the second rework. Loki's first audit (``53741054``) failed the
original build on weak redaction and free-text fields, allow-on-doubt, a
spoofable parser, a Kart-writable execution path, a lock-free pruner, a
synchronous critical path, a fabricated version, no off switch, an unguarded
import, and a writable install tree (F1-F11) — the first rework fixed all of
those. Loki's RE-audit (``A68E86E9``) then found the rework's own detached-
recorder mechanism introduced a NEW high-severity hole (R1: `python -m` puts
the caller's cwd first on `sys.path`, so a planted `willow_mcp/` package ran
on the host) and that the "hybrid" ledger (store the full command only when
nothing fires) was still reachable for secrets no detector recognised (R2).
The operator's response was not "patch the detector list again" — it was to
retire the hybrid model outright: `node9-shadow-shape-only-ledger-2026-09-27`
rules that the ledger never stores command text again, full stop.

Loki's THIRD audit (``1CCE0D9B``) found the shape-only ledger's own rule
still leaked: keeping "the first low-entropy lowercase word" of a segment let
a password sitting alone on its own line — a heredoc body, a bare secret
between two ``;``/``|``/newline separators — pass as a "command" whenever it
happened to look lowercase and short enough (S1). It also found the R4
process-group kill still never fired in practice: `os.getpgid(proc.pid)`
raises `ProcessLookupError` once `communicate()` has already reaped the
child, so the kill was always a no-op, and the live test that claimed to
prove otherwise never actually exercised the kill (S2). This rework:

* Replaces the shape heuristic with a fixed, committed ALLOWLIST of known
  command names (:data:`_COMMAND_ALLOWLIST`, ~150 entries) — a word is kept
  as a shape word only when its basename is exactly one of those names;
  everything else, including a bare password, a heredoc body line, or a
  ``$(...)``/backtick/``<(...)`` construct (whose own punctuation never
  matches a bare name), becomes ``?`` (S1). Heredoc bodies (``<<WORD``,
  ``<<-WORD``, ``<<'WORD'``) are stripped before segmentation
  (:func:`_strip_heredocs`); an unterminated heredoc drops everything after
  it, with ``truncated: true``.
* Kills node9's process group by ``os.killpg(proc.pid, SIGKILL)`` directly —
  never ``getpgid`` after the child may already be reaped — in a ``finally``
  that runs on every path (S2).
* Caps what crosses the recorder's stdin pipe at ``MAX_STDIN_BYTES`` (60 KB,
  under the 64 KiB pipe buffer): above that, the CALLER computes
  ``cmd_hmac``/``len`` itself (cheap, no ledger lock) and sends only those,
  never the oversize command, so the caller never blocks on a full pipe
  (S3).
* Creates ``$WILLOW_HOME/shadow/`` mode ``0700`` and tightens it if it
  already existed looser (S4).
* Adds :func:`run_selftest` (``willow-mcp shadow-report node9 --selftest``):
  runs the recorder once, for real, on a fixed benign command, and reports
  whether a row actually appeared — telling "no traffic" apart from "the
  recorder is silently broken" (e.g. the ``-I`` interpreter resolving a
  stale or absent ``willow_mcp`` before this branch is merged and pulled).

The pieces, as of this rework:

* The ledger is SHAPE-ONLY (:func:`_shape_of`, :func:`_detect_flags`,
  :func:`_cmd_hmac`) — no branch ever stores the raw command, regardless of
  what any detector does or does not recognise (this is what closes R2, not
  a better detector list). Every row carries `cmd_hmac` (HMAC-SHA256 keyed
  by a random, 0600, ``$WILLOW_HOME/shadow/.hmac_key``) and `shape` (the
  first identifier-shaped, low-entropy word of each pipeline segment, `?`
  otherwise); an optional `flags` field names fixed detector CATEGORIES,
  never values. :func:`_size_check` runs BEFORE any regex (R3): oversize
  input is capped to `MAX_SHAPE_BYTES` for shape/flag purposes only, with
  `truncated: true` on the row — the real command still goes to node9 in
  full; only the ledger's own computation is bounded and linear-time.
* The shim (``bundle/node9/shadow-eval.mjs``) is a hardened, mechanical
  parser only: JSON-args in, `{verdict, node9_rule_raw}` out, verdict is a
  strict ``allow|block|review|unknown`` enum with no default-to-allow path.
  `node9_rule_raw` is still free text; :func:`_safe_rule` whitelists it
  before anything is written.
* :func:`spawn_shadow` is the call sites' entry point: fire-and-forget,
  detached via `subprocess.Popen`. The recorder is started `-I` (isolated:
  no cwd/user-site on `sys.path`, no `PYTHON*` env) with `cwd` pinned to
  this shadow's own install directory (R1), and the payload reaches it
  ONLY over its stdin pipe — never a tempfile (R6).
  :func:`_do_record` is the synchronous worker the detached child (or a
  test) actually runs; it kills node9's WHOLE process group unconditionally
  after every call, not only on a timeout (R4), using the SAME timeout
  value the shim's own inner spawnSync uses.
* :func:`install_shim` vendors a pinned ``node`` binary and the ``node9-ai``
  package into ``$WILLOW_HOME/venvs/node9/`` so every execution is by
  absolute path inside that tree — never PATH, never the operator's real
  node/node9 install.
* :func:`build_report` / :func:`render_report` — the read-only report
  (``willow-mcp shadow-report node9``), showing shape and flags only.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import paths

#: How long a ledger row survives a prune sweep. Pruning never runs on the
#: hot path (F6) — only from `build_report` / `shadow-report --prune` / this
#: module's own `--prune` CLI action, each of which takes the ledger lock.
RETENTION_DAYS = 30

#: The shim's own subprocess budget, and the recorder's own outer bound —
#: ONE value, owned by the recorder (Loki A68E86E9 R4: two independently-
#: chosen timeouts meant the shim's own inner SIGTERM usually fired first
#: and Python's process-group kill never ran at all). Passed to the shim as
#: NODE9_SHADOW_TIMEOUT_MS; Python's own Popen.communicate timeout is set
#: slightly above it as a backstop, but the group is killed unconditionally
#: after communicate() returns either way — never only on the timeout path.
TIMEOUT_SECONDS = 2.0

#: Above this many bytes, `shape`/`flags` are computed over the first
#: MAX_SHAPE_BYTES only, with `truncated: true` on the row (R3) — never a
#: reason to skip sending the full command to node9 itself, which still
#: judges the real thing; only the LEDGER's own shape/flags computation is
#: bounded, so a 200 KB command's regex work stays sub-millisecond instead
#: of the ~25 s the unbounded, pre-size-check version took.
MAX_SHAPE_BYTES = 16 * 1024

#: The most this caller will ever write to the recorder's stdin pipe (Loki
#: 1CCE0D9B S3). A pipe's kernel buffer is commonly 64 KiB; writing more
#: than that synchronously blocks the writer until a reader drains it, and
#: the "reader" here is a freshly-exec'd `python -I` process that has not
#: even imported this module yet. Above this cap the caller sends no
#: command text at all — only a caller-computed `cmd_hmac` + `len` — so a
#: write to the recorder's stdin never blocks regardless of input size.
MAX_STDIN_BYTES = 60 * 1024

_BUNDLE_NODE9_DIR = Path(__file__).parent / "bundle" / "node9"
_SHIM_NAME = "shadow-eval.mjs"

#: The off switch (F9): unset (default) or "1" means shadow mode is active;
#: "0" means spawn_shadow() returns immediately, no row, no child, nothing.
_ENV_ENABLE = "WILLOW_MCP_NODE9_SHADOW"

#: A single, concrete "we are under pytest" signal (never set in production
#: code paths — task_submit and the hook never set it) that gates the
#: test-only absolute-path overrides below. Anything False under this key
#: means the override envvars are never even read.
_ENV_UNDER_TEST = "PYTEST_CURRENT_TEST"
_ENV_NODE_OVERRIDE = "WILLOW_MCP_NODE9_SHADOW_NODE_OVERRIDE"
_ENV_SCRIPT_OVERRIDE = "WILLOW_MCP_NODE9_SHADOW_SCRIPT_OVERRIDE"

#: Passed to the shim so its own inner spawnSync timeout and the recorder's
#: outer Popen timeout are the SAME value (R4) rather than two independently
#: chosen numbers.
_ENV_TIMEOUT_MS = "NODE9_SHADOW_TIMEOUT_MS"


def _shadow_root() -> Path:
    return paths.willow_home() / "venvs" / "node9"


def shim_path() -> Path:
    return _shadow_root() / _SHIM_NAME


def shadow_home_path() -> Path:
    return _shadow_root() / "shadow-home"


def shadow_cwd_path() -> Path:
    """Empty, pinned working directory `explain` is always run from —
    `getConfig()` reads `./node9.config.json` from cwd (node9-proxy
    config/index.ts), so an attacker-writable cwd could inject config the
    shadow was never meant to see. This directory holds nothing, ever."""
    return _shadow_root() / "cwd"


def _node_bin_path() -> Path:
    return _shadow_root() / "bin" / "node"


def _node9_script_path() -> Path:
    return _shadow_root() / "lib" / "node_modules" / "node9-ai" / "bin" / "node9.js"


def _version_file_path() -> Path:
    return _shadow_root() / "VERSION"


def ledger_path() -> Path:
    """``$WILLOW_HOME/shadow/node9.jsonl`` — outside every Kart write bind.
    The kartikeya-vendored default template only ever binds named
    repositories and named secret files, never ``shadow/`` or
    ``venvs/node9`` by name; see
    ``tests/test_node9_shadow.py::test_ledger_path_is_never_named_in_the_vendored_kart_sandbox_template``
    for the caveat this still carries on a box left at the implicit
    ``~/.willow`` default.
    """
    return paths.willow_home() / "shadow" / "node9.jsonl"


def _lock_path() -> Path:
    return ledger_path().with_suffix(".lock")


def _shadow_dir_path() -> Path:
    return paths.willow_home() / "shadow"


def _ensure_shadow_dir() -> Path:
    """``$WILLOW_HOME/shadow/`` mode ``0700`` (Loki 1CCE0D9B S4: the process
    umask left it at 0775 observed, so the ledger and lock inherited a
    group-writable directory even though the HMAC key file itself was
    already 0600). `mode=` on `mkdir` is ANDed with the umask, but 0700 sets
    no group/other bits for a umask to clear, so this is umask-proof by
    construction; the explicit `chmod` afterward additionally tightens a
    directory that already existed looser from an earlier version."""
    d = _shadow_dir_path()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def _hmac_key_path() -> Path:
    """``$WILLOW_HOME/shadow/.hmac_key`` — 32 random bytes, mode 0600,
    created on first use. Outside every Kart write bind for the same reason
    the ledger itself is (see :func:`ledger_path`); keying the ledger's
    command digest with a secret this small and this cheaply protected
    means a stolen/leaked ledger cannot be dictionary-attacked against a
    guessed command the way an unkeyed sha256 could be."""
    return paths.willow_home() / "shadow" / ".hmac_key"


def _get_or_create_hmac_key() -> bytes:
    path = _hmac_key_path()
    try:
        data = path.read_bytes()
        if len(data) == 32:
            return data
    except OSError:
        pass
    _ensure_shadow_dir()
    key = os.urandom(32)
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key
    except FileExistsError:
        # Lost a create race to another process — read what it wrote rather
        # than each process keying rows with its own key.
        try:
            data = path.read_bytes()
            if len(data) == 32:
                return data
        except OSError:
            pass
        return key


def _cmd_hmac(command: str) -> str:
    key = _get_or_create_hmac_key()
    return hmac.new(
        key, command.encode("utf-8", errors="surrogateescape"), hashlib.sha256
    ).hexdigest()


# ── installer (F5, F8, F11) ──────────────────────────────────────────────

def install_shim(
    force: bool = False,
    source_node: str | None = None,
    source_node9_ai: str | None = None,
) -> dict[str, Any]:
    """Vendor a pinned ``node`` binary and the ``node9-ai`` package into
    ``$WILLOW_HOME/venvs/node9/``, and copy the shim + pinned shadow-home +
    empty pinned cwd alongside them — all read-only, including the root
    directory itself (F11: the original installer left ``venvs/node9/``
    writable, so the shim could be replaced by rename even with its own
    file chmodded 0555).

    ``source_node`` / ``source_node9_ai`` name the HOST binary/package to
    vendor (e.g. an fnm-managed node + its global node9-ai install). This
    is a one-time operator/host act — Kart's own sandbox policy never binds
    ``venvs/`` in the first place, so it cannot reach this function, and
    unlike the runtime execution path this function is explicitly allowed
    to resolve its sources however the operator names them.

    Every execution afterward (:func:`_do_record`) runs the VENDORED copies
    by absolute path only, never the sources named here again.
    """
    source_node = source_node or os.environ.get("WILLOW_MCP_NODE9_SHADOW_SOURCE_NODE", "").strip()
    source_node9_ai = source_node9_ai or os.environ.get(
        "WILLOW_MCP_NODE9_SHADOW_SOURCE_NODE9_AI", ""
    ).strip()
    if not source_node or not source_node9_ai:
        raise ValueError(
            "install_shim needs source_node (a real node binary) and "
            "source_node9_ai (a node9-ai package directory containing bin/node9.js) "
            "— pass them explicitly or set WILLOW_MCP_NODE9_SHADOW_SOURCE_NODE / "
            "WILLOW_MCP_NODE9_SHADOW_SOURCE_NODE9_AI. install_shim never guesses a "
            "PATH-resolved node (F5) — the whole point is that nothing this shadow "
            "executes is Kart-writable."
        )
    src_node_p = Path(source_node)
    src_node9_ai_p = Path(source_node9_ai)
    if not src_node_p.is_file():
        raise OSError(f"source_node is not a file: {src_node_p}")
    if not (src_node9_ai_p / "bin" / "node9.js").is_file():
        raise OSError(f"source_node9_ai has no bin/node9.js: {src_node9_ai_p}")

    dest_root = _shadow_root()
    dest_shim = dest_root / _SHIM_NAME
    dest_home = dest_root / "shadow-home"
    dest_cwd = shadow_cwd_path()
    dest_bin = _node_bin_path()
    dest_node9_dir = _node9_script_path().parent.parent  # .../lib/node_modules/node9-ai

    if dest_shim.exists() and not force:
        raise ValueError(
            f"{dest_shim} already exists — pass force=True (--force) to overwrite"
        )

    if dest_root.exists():
        _make_tree_writable(dest_root)

    dest_root.mkdir(parents=True, exist_ok=True)
    (dest_root / "bin").mkdir(parents=True, exist_ok=True)
    (dest_root / "lib" / "node_modules").mkdir(parents=True, exist_ok=True)

    src_shim = _BUNDLE_NODE9_DIR / _SHIM_NAME
    src_home = _BUNDLE_NODE9_DIR / "shadow-home"
    if not src_shim.is_file():
        raise OSError(f"bundled shim missing: {src_shim}")
    shutil.copyfile(src_shim, dest_shim)
    dest_shim.chmod(0o555)

    if dest_home.exists():
        shutil.rmtree(dest_home)
    if src_home.is_dir():
        shutil.copytree(src_home, dest_home)
    else:
        dest_home.mkdir(parents=True)

    dest_cwd.mkdir(parents=True, exist_ok=True)

    shutil.copyfile(src_node_p, dest_bin)
    dest_bin.chmod(0o555)

    if dest_node9_dir.exists():
        shutil.rmtree(dest_node9_dir)
    shutil.copytree(src_node9_ai_p, dest_node9_dir, symlinks=False)

    # F8: the version this shadow stamps on every row is read ONCE, here, from
    # the vendored package's own package.json — never from `explain`'s stdout
    # (which echoes the command and can carry an attacker-chosen X.Y.Z).
    version = "unknown"
    try:
        pkg = json.loads((dest_node9_dir / "package.json").read_text(encoding="utf-8"))
        version = str(pkg.get("version") or "unknown")
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    _version_file_path().write_text(version, encoding="utf-8")

    _make_tree_read_only(dest_root)
    # cwd must stay a directory node9 can chdir into but never write under —
    # 0555 on the directory itself already forbids writes inside it.

    return {
        "shim_path": str(dest_shim),
        "shadow_home": str(dest_home),
        "node_bin": str(dest_bin),
        "node9_script": str(_node9_script_path()),
        "version": version,
        "wrote": [str(dest_shim), str(dest_home), str(dest_bin), str(dest_node9_dir)],
    }


def _make_tree_writable(root: Path) -> None:
    try:
        root.chmod(0o755)
    except OSError:
        pass
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            try:
                (Path(dirpath) / name).chmod(0o755)
            except OSError:
                pass
        for name in filenames:
            try:
                (Path(dirpath) / name).chmod(0o644)
            except OSError:
                pass


def _make_tree_read_only(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            try:
                p.chmod(stat.S_IMODE(p.stat().st_mode) & ~0o222)
            except OSError:
                pass
        for name in dirnames:
            p = Path(dirpath) / name
            try:
                p.chmod(0o555)
            except OSError:
                pass
    try:
        root.chmod(0o555)  # F11: the root itself, not just the shim file
    except OSError:
        pass


def is_installed() -> bool:
    return shim_path().is_file()


# ── absolute-path resolution (F5) ────────────────────────────────────────

def _under_test() -> bool:
    return bool(os.environ.get(_ENV_UNDER_TEST, "").strip())


def _resolve_exec_paths() -> tuple[Path, Path] | None:
    """The (node_bin, node9_script) this run will exec, or None if doubt.

    Overrides are read ONLY when `_under_test()` — a concrete pytest-only
    signal task_submit and the hook never set — and even then the resolved
    paths must exist as files; a missing override is doubt, not a silent
    fall-through to the default (which would defeat the point of a test
    asserting the override took effect).
    """
    if _under_test():
        o1 = os.environ.get(_ENV_NODE_OVERRIDE, "").strip()
        o2 = os.environ.get(_ENV_SCRIPT_OVERRIDE, "").strip()
        if o1 or o2:
            node_bin = Path(o1) if o1 else _node_bin_path()
            node9_script = Path(o2) if o2 else _node9_script_path()
            if node_bin.is_file() and node9_script.is_file():
                return node_bin, node9_script
            return None
    node_bin = _node_bin_path()
    node9_script = _node9_script_path()
    # F5's containment guarantee: the default paths are built from
    # _shadow_root() itself, so this is normally trivially true; the
    # explicit check catches a symlink swap under venvs/node9 (still inside
    # the tree, but no longer the file install_shim actually wrote).
    root_real = os.path.realpath(_shadow_root())
    for p in (node_bin, node9_script):
        if not p.is_file():
            return None
        if not os.path.realpath(p).startswith(root_real + os.sep):
            return None
    return node_bin, node9_script


# ── shape-only ledger (operator ruling node9-shadow-shape-only-ledger-
# 2026-09-27, replacing the hybrid ledger from the previous rework) ──────
#
# The ledger NEVER stores command text again — not even when nothing fires.
# Every row carries `cmd_hmac` (keyed, so a stolen ledger cannot be
# dictionary-attacked against a guessed command) and `shape` (the first
# word of each pipeline segment, only when it is itself a safe-looking
# identifier — never an argument, a path, or a value). An optional `flags`
# field names fixed detector CATEGORIES ("aws_key", "password_arg", ...),
# never the matched value. R3 (Loki A68E86E9): the size/decodability check
# runs FIRST, before any regex, and every remaining pattern is bounded
# (no unbounded `*`/`+` ahead of a backtrackable literal) so scanning is
# linear in the input length regardless of content.

_VAR_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")
_SHAPE_SEGMENT_SPLIT = re.compile(r"\r\n|\n|\|\||\||&&|;")
_CONTINUATION_RE = re.compile(r"\\\r?\n[ \t]*")

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=\-]{16,}")

#: A word matching a heredoc opener: `<<WORD`, `<<-WORD` (leading tabs may be
#: stripped from the body and the terminator), `<<'WORD'`/`<<"WORD"` (quoted
#: — no interpolation inside, irrelevant here since the body is dropped
#: either way). Group 2 is the terminator word to search for.
_HEREDOC_OPEN_RE = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")

#: Fixed, committed allowlist of known command names (Loki 1CCE0D9B S1):
#: the ONLY way a `shape` word can be anything but `?` is for its basename
#: to appear here, verbatim, case-sensitively. This replaces the previous
#: regex+entropy heuristic outright — that heuristic kept "the first
#: lowercase, low-entropy word" of a segment, which let a bare password on
#: its own line (a heredoc body, or simply between two `;`/`|`/newline
#: separators) pass as a "command" whenever it happened to look short and
#: lowercase. A password never collides with a real, committed command
#: name, so this cannot leak the same way. Shell builtins/keywords,
#: coreutils, and the common dev tools this fleet's own tasks actually
#: run.
_COMMAND_ALLOWLIST: frozenset[str] = frozenset({
    # shell builtins / keywords
    "cd", "set", "unset", "export", "readonly", "declare", "local", "echo",
    "printf", "if", "then", "else", "elif", "fi", "for", "while", "until",
    "do", "done", "case", "esac", "function", "return", "break", "continue",
    "exit", "eval", "exec", "trap", "shift", "test", "true", "false",
    "source", "alias", "unalias", "wait", "read", "let", "type", "command",
    "builtin", "help", "history", "jobs", "bg", "fg", "ulimit", "umask",
    "times", "getopts", "pwd", "hash", "shopt", "select",
    # coreutils / common unix tools
    "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "touch", "chmod",
    "chown", "chgrp", "ln", "stat", "df", "du", "find", "xargs", "grep",
    "egrep", "fgrep", "sed", "awk", "cut", "sort", "uniq", "wc", "head",
    "tail", "tr", "tee", "diff", "patch", "xxd", "hexdump", "od", "base64",
    "md5sum", "sha1sum", "sha256sum", "sha512sum", "gzip", "gunzip",
    "bzip2", "xz", "zip", "unzip", "tar", "split", "join", "paste", "comm",
    "column", "fold", "expand", "unexpand", "nl", "seq", "yes", "sleep",
    "date", "cal", "env", "printenv", "which", "whereis", "file",
    "basename", "dirname", "realpath", "readlink", "mktemp", "install",
    "rsync", "scp", "sftp", "ssh", "ssh-keygen", "ssh-agent", "ssh-add",
    "sshpass", "nc", "ncat", "netcat", "ping", "traceroute", "dig",
    "nslookup", "host", "curl", "wget", "telnet", "ftp", "expect",
    "ps", "top", "htop", "kill", "killall", "pkill", "pgrep", "nice",
    "renice", "nohup", "disown", "setsid", "systemctl", "journalctl",
    "service", "crontab", "at", "mount", "umount", "lsblk", "fdisk",
    "chroot", "su", "sudo", "passwd", "useradd", "usermod", "groupadd",
    "id", "whoami", "who", "w", "last", "uptime", "uname", "hostname",
    "hostnamectl", "ip", "ifconfig", "route", "iptables", "nft",
    # dev tools / languages
    "git", "gh", "hub", "svn", "hg", "python", "python3", "pip", "pip3",
    "uv", "uvx", "pytest", "ruff", "black", "flake8", "mypy", "tox",
    "poetry", "pipenv", "node", "npm", "npx", "yarn", "pnpm", "deno",
    "bun", "tsc", "eslint", "prettier", "java", "javac", "mvn", "gradle",
    "go", "cargo", "rustc", "rustup", "gcc", "g++", "cc", "make", "cmake",
    "ninja", "meson", "docker", "docker-compose", "podman", "kubectl",
    "helm", "terraform", "ansible", "vagrant", "packer", "aws", "gcloud",
    "az", "heroku", "vercel", "netlify", "psql", "mysql", "sqlite3",
    "redis-cli", "mongo", "mongosh", "jq", "yq", "openssl", "gpg", "gpg2",
    "keytool", "certbot", "twine", "vim", "vi", "nano", "emacs", "less",
    "more", "man", "info", "node9", "willow-mcp", "willow-bot", "kart",
})


def _strip_heredocs(text: str) -> tuple[str, bool]:
    """Drops heredoc BODIES (Loki 1CCE0D9B S1) before any segmentation: a
    body is data, never a command, but the old shape rule split on `\\n`
    like anything else and would happily read a password sitting alone on
    a body line as "the first word of a segment". The opener line itself
    (e.g. `mysql -u root -p <<EOF`) is kept — it still carries a real
    command word — only the lines between it and the terminator are
    dropped. `<<-WORD` strips leading tabs from both body and terminator
    lines before comparing (matching the shell's own `<<-` rule); `<<WORD`
    and `<<'WORD'`/`<<"WORD"` compare the terminator line verbatim.
    Returns (text_with_bodies_dropped, truncated) — truncated is True only
    when a heredoc opener has NO matching terminator line at all, in which
    case everything from that point on is dropped (there is no reliable
    way to know where such a script would have continued)."""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _HEREDOC_OPEN_RE.search(line)
        if not m:
            out.append(line)
            i += 1
            continue
        out.append(line)
        strip_tabs = m.group(1) == "-"
        terminator = m.group(3)
        j = i + 1
        found = False
        while j < n:
            candidate = lines[j].lstrip("\t") if strip_tabs else lines[j]
            if candidate == terminator:
                found = True
                break
            j += 1
        if found:
            i = j + 1
        else:
            return "\n".join(out), True
    return "\n".join(out), False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _join_continuations(command: str) -> str:
    """Backslash-newline line continuations glue a secret split across two
    lines back into one token before anything scans it (Loki 53741054's
    `split` probe: a real key with a `\\\n` in the middle of it)."""
    return _CONTINUATION_RE.sub("", command)


def _size_check(command: str) -> tuple[str, bool]:
    """MUST run before any regex or tokenising (R3). Returns
    (text_to_scan, truncated) — text_to_scan is capped at MAX_SHAPE_BYTES
    UTF-8 bytes' worth of characters; truncated is True when it was cut.
    This bounds every detector below to O(MAX_SHAPE_BYTES), independent of
    how large the real command is — the real command still goes to node9
    itself in full; only the ledger's shape/flags computation is capped."""
    encoded = command.encode("utf-8", errors="surrogateescape")
    if len(encoded) <= MAX_SHAPE_BYTES:
        return command, False
    truncated_bytes = encoded[:MAX_SHAPE_BYTES]
    # Decode back, dropping a possibly-split trailing multibyte sequence
    # rather than raising.
    text = truncated_bytes.decode("utf-8", errors="ignore")
    return text, True


# Fixed, bounded-repetition category detectors. Every pattern here is
# anchored or length-capped ahead of any `://`/`@`/quantifier so none of
# them can backtrack quadratically (R3's `_USERINFO_URL` fix: the old
# unbounded scheme `[a-zA-Z0-9+.\-]*` before `://` is now capped at 31
# chars, same as a real URI scheme ever needs).
_FLAG_CATEGORIES: list[tuple[str, "re.Pattern[str]"]] = [
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,40}\b|\bgithub_pat_[A-Za-z0-9_]{20,60}\b")),
    ("provider_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{16,60}\b|\bxox[baprs]-[A-Za-z0-9\-]{10,60}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{6,60}\.eyJ[A-Za-z0-9_\-]{6,60}\.[A-Za-z0-9_\-]{6,80}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----")),
    # A flag whose OWN name says what it holds, glued or space/eq-separated:
    # -p<v>, -k <v>, --password=<v>, --token <v>, --secret=<v>, --auth <v>,
    # --cred <v>. The value itself is never captured into `flags`.
    ("password_arg", re.compile(
        r"(?i)(?:^|\s)(?:-p\S{1,200}|-k\s+\S{1,200}"
        r"|--[a-z-]{0,20}(?:pass|pwd|secret|token|auth|cred)[a-z-]{0,20}(?:[= ]\S{1,200})?)"
    )),
    ("header_secret", re.compile(
        r"(?i)(?:x-api-key|authorization|x-auth-token)\s*:\s*\S{1,300}"
    )),
    ("query_secret", re.compile(
        r"(?i)[?&][a-z_]{0,20}(?:token|key|secret|pass|auth|sig)[a-z_]{0,20}=[^&\s]{1,300}"
    )),
    ("url_userinfo", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{0,31}://[^\s/:@]{1,200}:[^\s/@]{1,200}@")),
    ("curl_userpass", re.compile(r"(?:^|\s)-u\s*[^\s:]{1,200}:\S{1,200}")),
    ("cred_path", re.compile(
        r"(?:~|/home/[^/\s\"']{1,100}|/Users/[^/\s\"']{1,100})/\.(?:ssh|aws|gnupg|pgp|kube|docker|netrc)(?:/|$|['\"\s])"
    )),
    ("email", re.compile(r"\b[^\s@\"']{1,64}@[^\s@\"']{1,255}\.[A-Za-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IBAN_CANDIDATE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

#: The exact, fixed set of category names `_detect_flags` can ever emit
#: (Loki BAC13B68, L1): every name in `_FLAG_CATEGORIES`, plus the three
#: names appended outside that loop (`card_number`, `iban`, `high_entropy`).
#: `_do_record_inner` filters against this set at WRITE time, never trusting
#: `_detect_flags`'s return value directly — the leak-scan tests exclude
#: `flags` from their substring check on the assumption that it only ever
#: carries these fixed names, never a value; this is the write-time
#: guarantee that assumption rests on, so a future bug in `_detect_flags`
#: (or a new category added without updating this set) cannot put free text
#: into `flags` unseen by that scan.
FLAG_NAMES: frozenset[str] = frozenset(
    {name for name, _ in _FLAG_CATEGORIES} | {"card_number", "iban", "high_entropy"}
)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _iban_ok(code: str) -> bool:
    code = code.upper()
    if len(code) < 15:
        return False
    rearranged = code[4:] + code[:4]
    try:
        digits = "".join(str(int(c, 36)) for c in rearranged)
        return int(digits) % 97 == 1
    except ValueError:
        return False


def _detect_flags(text: str) -> list[str]:
    """Category names only, never values — an optional diagnostic field.
    `text` should already be the size-capped, continuation-joined scan
    text (see `_size_check`/`_join_continuations`), never the raw command."""
    flags: list[str] = []
    for name, rx in _FLAG_CATEGORIES:
        if rx.search(text):
            flags.append(name)
    for m in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            flags.append("card_number")
            break
    for m in _IBAN_CANDIDATE.finditer(text):
        if _iban_ok(m.group(0)):
            flags.append("iban")
            break
    if any(_shannon_entropy(tok) >= 3.5 for tok in _TOKEN_RE.findall(text)):
        flags.append("high_entropy")
    return flags


def _shape_of(text: str) -> str:
    """First word of each pipeline/`;`/`&&`/`||`/newline segment — skipping
    any leading `VAR=value` assignment tokens first — kept ONLY when its
    basename matches an entry in :data:`_COMMAND_ALLOWLIST` exactly and
    case-sensitively (Loki 1CCE0D9B S1, replacing the previous
    regex+entropy heuristic outright: a password never happens to equal a
    committed command name, so this cannot leak the way "lowercase and
    short" could). `/usr/bin/curl` matches on its basename (`curl`); a
    `$(...)`/backtick/`<(...)` construct never matches by construction,
    since its own punctuation is part of the compared string, not stripped
    off. `text` should already be size-capped and heredoc-stripped (see
    `_size_check` / `_strip_heredocs`)."""
    segments = _SHAPE_SEGMENT_SPLIT.split(text)
    shapes = []
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        words = seg.split()
        idx = 0
        while idx < len(words) and _VAR_ASSIGN_RE.match(words[idx]):
            idx += 1
        if idx >= len(words):
            shapes.append("?")
            continue
        first = words[idx]
        basename = first.rsplit("/", 1)[-1]
        shapes.append(basename if basename in _COMMAND_ALLOWLIST else "?")
    return " ".join(shapes) if shapes else "?"


# ── node9_rule / willow_reason: no free text, ever (F1, F2) ─────────────

_RULE_OK = re.compile(r"^[a-z0-9:._-]{1,64}$")


def _safe_rule(raw: str) -> str:
    """Whitelists the shim's raw `Reason:` text into a short machine-safe
    token, or "unparsed" — never the free text itself (F2)."""
    if not raw:
        return ""
    tokens = raw.strip().split()
    if not tokens:
        return ""
    candidate = tokens[-1].strip(":,.;()").lower()
    return candidate if _RULE_OK.match(candidate) else "unparsed"


#: Known willow_reason/error prefixes this codebase actually uses
#: (server.py's `snake_case: detail` error convention). Anything else
#: collapses to "other" — never the free text (F1).
_REASON_CODES = frozenset({
    "net_denied", "consent_denied", "lease_denied", "db_denied",
    "schema_unusable", "allow_localhost_retired", "trust_root_denied",
    "net_authorization_denied", "db_authorization_denied",
    "invalid_lane", "held_net_authorization",
})


def _reason_code(reason: str) -> str:
    reason = (reason or "").strip()
    if not reason:
        return "other"
    m = re.match(r"^([a-z][a-z0-9_]*):", reason)
    if m and m.group(1) in _REASON_CODES:
        return m.group(1)
    lower = reason.lower()
    if any(w in lower for w in ("route", "prefer", "instead")):
        return "routing"
    return "other"


# ── verdict whitelist (F3) ────────────────────────────────────────────────

_VALID_NODE9_VERDICTS = frozenset({"allow", "block", "review"})


def _normalize_willow_verdict(willow_verdict: str) -> str:
    v = (willow_verdict or "").strip().lower()
    if v == "held" or v == "held_net_authorization":
        return "held"
    return "block" if v == "block" else "allow"


# ── ledger I/O, locked (F6) ──────────────────────────────────────────────

def _with_lock(fn):
    lock_path = _lock_path()
    _ensure_shadow_dir()
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            return fn()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _append_ledger_row_locked(row: dict[str, Any]) -> None:
    def _do() -> None:
        path = ledger_path()
        _ensure_shadow_dir()
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    _with_lock(_do)


def prune_ledger() -> int:
    """Drops rows older than RETENTION_DAYS. Takes the SAME lock the
    appender uses, so a row appended mid-prune is never lost (F6) — never
    called from the hot path (evaluate/record), only from `shadow-report`
    or this module's own `--prune` action."""
    def _do() -> int:
        path = ledger_path()
        if not path.is_file():
            return 0
        cutoff = datetime.now(UTC) - timedelta(days=RETENTION_DAYS)
        lines = path.read_text(encoding="utf-8").splitlines()
        kept: list[str] = []
        dropped = 0
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                ts = datetime.fromisoformat(str(row.get("ts", "")))
            except (ValueError, TypeError, json.JSONDecodeError):
                kept.append(line)
                continue
            if ts >= cutoff:
                kept.append(line)
            else:
                dropped += 1
        if dropped:
            tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
            tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            tmp.replace(path)
        return dropped
    return _with_lock(_do)


# ── the synchronous worker (what the detached child actually runs) ──────

def _do_record(payload: dict[str, Any]) -> None:
    """Everything after the willow guard's own decision: detect, exec the
    shim, parse, whitelist, append. Runs in the DETACHED child, never on the
    caller's own critical path (F7). Never raises — a bug here must not
    turn a background record into a visible crash of a detached process
    nobody is watching."""
    try:
        _do_record_inner(payload)
    except Exception:  # noqa: BLE001, S110 — last-resort: this runs
        # unattended in a detached child nobody is watching; there is no
        # caller left to log to, and re-raising here would only print a
        # traceback to /dev/null.
        pass


def _do_record_inner(payload: dict[str, Any]) -> None:
    if not is_installed():
        return  # F9: off switch — no shim, no row, nothing.

    surface = str(payload.get("surface", ""))
    seat = str(payload.get("seat", ""))
    willow_verdict_raw = str(payload.get("willow_verdict", ""))
    willow_reason_raw = str(payload.get("willow_reason", ""))
    start = time.monotonic()

    if payload.get("oversize"):
        # S3 (Loki 1CCE0D9B): the caller already decided this command was
        # too large to send over the pipe at all, and computed cmd_hmac/len
        # itself — there is no `command` in this payload, ever, and nothing
        # here touches node9 or the shape/flag detectors.
        row = {
            "ts": datetime.now(UTC).isoformat(),
            "surface": surface,
            "seat": seat,
            "cmd_hmac": str(payload.get("cmd_hmac", "")),
            "len": int(payload.get("len") or 0),
            "status": "oversize",
            "willow_verdict": _normalize_willow_verdict(willow_verdict_raw),
            "willow_reason": _reason_code(willow_reason_raw),
            "node9_verdict": "unknown",
            "node9_rule": "",
            "node9_version": "",
            "latency_ms": int((time.monotonic() - start) * 1000),
        }
        _append_ledger_row_locked(row)
        return

    command = str(payload.get("command", "") or "")

    # R3: size/decodability FIRST, before any regex or tokenising. Every
    # detector below only ever sees a derivative of `scan_text` (size-
    # capped, continuation-joined), never the raw `command` — the shim
    # still gets the full raw command for a real node9 verdict, further
    # down.
    scan_text, truncated = _size_check(command)
    scan_text = _join_continuations(scan_text)
    # S1 (Loki 1CCE0D9B): `shape` additionally never sees heredoc BODY
    # lines — a body is data, never a command, and the old rule read a
    # password sitting alone on a body line as "the first word of a
    # segment". `flags` deliberately keeps seeing the un-stripped text: it
    # only ever records fixed category NAMES, never values, so there is
    # nothing to leak by still recognising e.g. a PEM key marker inside a
    # heredoc body — narrowing what `_detect_flags` sees would only cost
    # recall on an already-safe field, for no safety gain.
    shape_text, heredoc_truncated = _strip_heredocs(scan_text)
    truncated = truncated or heredoc_truncated

    # Shape-only ledger (operator ruling node9-shadow-shape-only-ledger-
    # 2026-09-27): cmd_hmac + shape (+ optional flags) — never the command,
    # never a "when nothing fires, keep the full text" branch.
    row: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "surface": surface,
        "seat": seat,
        "cmd_hmac": _cmd_hmac(command),
        "shape": _shape_of(shape_text),
        "willow_verdict": _normalize_willow_verdict(willow_verdict_raw),
        "willow_reason": _reason_code(willow_reason_raw),
    }
    if truncated:
        row["truncated"] = True
    # L1 (Loki BAC13B68): never trust _detect_flags's return value directly —
    # keep only names in the fixed FLAG_NAMES set; anything else (a future
    # detector bug, a mis-added category) is dropped and replaced by a
    # single "invalid_flag" marker, never the offending value itself. This
    # is the write-time guarantee the leak scan's own exclusion of `flags`
    # depends on.
    raw_flags = _detect_flags(scan_text)
    flags = [f for f in raw_flags if f in FLAG_NAMES]
    if len(flags) != len(raw_flags):
        flags.append("invalid_flag")
    if flags:
        row["flags"] = flags

    resolved = _resolve_exec_paths()
    if resolved is None:
        row["node9_verdict"] = "unknown"
        row["node9_rule"] = ""
        row["node9_version"] = ""
        row["latency_ms"] = int((time.monotonic() - start) * 1000)
        _append_ledger_row_locked(row)
        return
    node_bin, node9_script = resolved

    version = "unknown"
    try:
        version = _version_file_path().read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        pass

    shadow_cwd_path().mkdir(parents=True, exist_ok=True)
    timeout_ms = int(TIMEOUT_SECONDS * 1000)
    env = {
        "HOME": str(shadow_home_path()),
        "PATH": "/usr/bin:/bin",
        "NODE9_NO_AUTO_DAEMON": "1",
        _ENV_TIMEOUT_MS: str(timeout_ms),
    }
    tool = "bash" if surface in ("bash", "kart") else surface
    # The shim/node9 still gets the FULL raw command — only the LEDGER is
    # shape-only. node9's own real verdict needs the real text.
    shim_payload = json.dumps({"tool": tool, "command": command})

    verdict = "unknown"
    rule_raw = ""
    proc = None
    try:
        # Popen (not subprocess.run) so we always hold the process's own pid
        # to kill the WHOLE process group by (R4) — subprocess.run's
        # TimeoutExpired does not expose that, and killing only the direct
        # child leaves node9's own grandchild orphaned and running.
        proc = subprocess.Popen(
            [str(node_bin), str(shim_path()), str(node9_script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=str(shadow_cwd_path()),
            start_new_session=True,
        )
        try:
            # R4: Python's own outer bound is the SAME value the shim's
            # inner spawnSync uses (passed via _ENV_TIMEOUT_MS above), plus
            # a small buffer so the shim's own clean SIGTERM path usually
            # wins the race — but the group is killed unconditionally below
            # regardless of which timeout (if either) actually fired.
            stdout, _stderr = proc.communicate(
                input=shim_payload, timeout=TIMEOUT_SECONDS + 0.3
            )
        except subprocess.TimeoutExpired:
            stdout = ""
        if proc.returncode == 0 and stdout.strip():
            out = json.loads(stdout)
            candidate = out.get("verdict")
            if candidate in _VALID_NODE9_VERDICTS:
                verdict = candidate
            rule_raw = out.get("node9_rule_raw") or ""
    except Exception:  # noqa: BLE001 — subprocess/parse doubt, never allow.
        verdict = "unknown"
    finally:
        # R4/S2 (Loki A68E86E9, then 1CCE0D9B): ALWAYS kill the process
        # group, not only on the timeout path — the shim's own inner
        # timeout (spawnSync) can fire first, SIGTERM only its direct node9
        # child, print `unknown`, and exit 0, in which case `communicate()`
        # above returns cleanly and a timeout-only `except` branch would
        # never run at all, leaving any grandchild node9 spawned (e.g. a
        # shell pipeline node9 itself launched) still alive.
        #
        # S2: `os.getpgid(proc.pid)` after `communicate()` has already
        # reaped the child raises `ProcessLookupError` — silently swallowed
        # by the old `except (ProcessLookupError, OSError): pass` — so the
        # kill was ALWAYS a no-op regardless of whether anything survived.
        # `start_new_session=True` makes this child a session AND process
        # group leader, so its pgid is its own pid by construction; killing
        # `proc.pid` directly needs no lookup and cannot race a reap.
        if proc is not None and proc.pid is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                # Every process in the group (including the shim itself)
                # already exited on its own — nothing left to kill.
                pass
            try:
                proc.wait(timeout=1)
            except Exception:  # noqa: BLE001 — best-effort reap only.
                pass

    row["node9_verdict"] = verdict
    row["node9_rule"] = _safe_rule(rule_raw)
    row["node9_version"] = version
    row["latency_ms"] = int((time.monotonic() - start) * 1000)
    _append_ledger_row_locked(row)


# ── fire-and-forget entry point (F7) ─────────────────────────────────────

def spawn_shadow(
    surface: str,
    seat: str,
    command: str,
    willow_verdict: str,
    willow_reason: str = "",
) -> None:
    """Hand the payload to a detached child process and return immediately.
    Never blocks on node9, never blocks on the ledger, never raises. This is
    what `task_submit` and the PreToolUse hook call.

    F9 (off switch): if the shim is not installed, or
    `WILLOW_MCP_NODE9_SHADOW=0`, this returns immediately with no row, no
    child process, nothing.
    """
    try:
        if os.environ.get(_ENV_ENABLE, "").strip() == "0":
            return
        if not is_installed():
            return
        command = command or ""
        full_payload = json.dumps({
            "surface": surface, "seat": seat or "", "command": command,
            "willow_verdict": willow_verdict or "", "willow_reason": willow_reason or "",
        })
        if len(full_payload.encode("utf-8", errors="surrogateescape")) > MAX_STDIN_BYTES:
            # S3 (Loki 1CCE0D9B): never write more to the recorder's stdin
            # than the pipe's own buffer can hold without blocking. The
            # HMAC key is 0600 but readable by this same uid, so computing
            # cmd_hmac HERE, in the caller, costs one fast hash pass and no
            # ledger lock — never the oversize command itself crosses the
            # pipe.
            oversize_payload = json.dumps({
                "surface": surface, "seat": seat or "", "oversize": True,
                "cmd_hmac": _cmd_hmac(command),
                "len": len(command.encode("utf-8", errors="surrogateescape")),
                "willow_verdict": willow_verdict or "", "willow_reason": willow_reason or "",
            })
            _spawn_detached(oversize_payload)
            return
        _spawn_detached(full_payload)
    except Exception:  # noqa: BLE001 — the whole point is this never raises.
        return


def _recorder_command() -> list[str]:
    """The argv that launches the detached recorder (R1): isolated mode,
    module invocation, exactly `sys.executable -I -m willow_mcp.node9_shadow
    --record`. Factored into its own function as a deliberate, narrow test
    seam: `-I` ignores `PYTHONPATH`, so a dev checkout that only makes its
    OWN worktree importable via `PYTHONPATH` (rather than a matching
    editable pip install) cannot make the isolated interpreter see that
    worktree's code at all — a pre-existing environment property of how
    worktrees are used here, not a security concern `-I` is meant to
    address. Tests that need the real subprocess to run the code under
    test (rather than whatever the ambient editable install resolves to)
    monkeypatch this one function to inject the worktree's src dir via an
    explicit `-c sys.path.insert(...)` bootstrap; production never touches
    it and always gets the plain, brief-specified command below."""
    return [sys.executable, "-I", "-m", "willow_mcp.node9_shadow", "--record"]


def _spawn_detached(payload_json: str) -> None:
    """Launch the detached recorder via `subprocess.Popen`, never raw
    `os.fork()`. A hand-rolled double-fork does real Python-level work
    (setsid, a second fork, dup2 calls) in the fragile post-fork/pre-exec
    window — CPython's own docs warn that calling anything but `os.exec*`
    between `fork()` and exec in a process that has ever had more than one
    thread can deadlock the child (a held libc allocator or import lock
    forked mid-critical-section is never released in the child, since only
    the forking thread survives the fork). This module is imported into the
    same long-lived, multi-threaded MCP server process that owns
    `task_submit`, and into a pytest session that also uses real threads
    (this file's own concurrency test) — both are exactly the conditions
    that make raw `fork()` unsafe here. `subprocess.Popen` does its
    fork+exec in a narrow, audited C helper (`_posixsubprocess.fork_exec`)
    designed to be safe under exactly these conditions.

    R1 (Loki A68E86E9): `python -m` puts the CURRENT WORKING DIRECTORY
    first on `sys.path`, so a `willow_mcp/node9_shadow.py` planted in the
    caller's cwd (any repo a Kart task or a clone can write to) would run
    INSTEAD of the installed module, unsandboxed, with this process's own
    environment. Two independent closes: `-I` (isolated mode — no cwd/
    script-dir and no user-site on `sys.path`, `PYTHON*` env ignored) AND
    an explicit `cwd=` pinned to this shadow's own install directory,
    which is never the caller's working directory regardless of what
    invoked `spawn_shadow()`.

    R6 (Loki A68E86E9): the raw command reaches the recorder ONLY through
    its stdin pipe — never a tempfile. The old version wrote the full
    payload (including any undetected secret) to `/tmp/node9-shadow-*.json`
    before the child even started; a killed/OOM child left it behind
    indefinitely. Writing to `proc.stdin` and closing it hands the child
    the bytes over a pipe that exists only in kernel memory for the
    lifetime of this call — there is no file to leak or leave behind.

    `start_new_session=True` gives the child its own session (detached from
    our controlling terminal, if any); the parent never calls `.wait()` on
    it, so this truly returns before node9 has necessarily even started. A
    short-lived hook process exits right after this returns, and the OS
    reaps the orphan; inside the long-lived MCP server, `subprocess`'s own
    internal `_active` list opportunistically reaps finished children on
    the next `Popen` call anywhere in the process."""
    try:
        proc = subprocess.Popen(
            _recorder_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(_shadow_root()),
            start_new_session=True,
            close_fds=True,
        )
    except Exception:  # noqa: BLE001 — spawn_shadow() (the only caller) must
        # never raise regardless of why the recorder could not be started.
        return
    try:
        if proc.stdin is not None:
            proc.stdin.write(payload_json.encode("utf-8"))
            proc.stdin.close()
    except Exception:  # noqa: BLE001 — a broken pipe (child exited instantly,
        # e.g. -I somehow failing to resolve the module) must not raise back
        # into the caller; the child either got a partial/no payload and
        # will produce no row, which is the fail-open contract.
        pass


# Backward-compatible synchronous name some earlier tests/call sites may
# still reference — delegates to the same detached path. New code should
# call spawn_shadow() directly.
evaluate = spawn_shadow


# ── report ───────────────────────────────────────────────────────────────

_CLASSES = ("node9_stricter", "willow_stricter", "agree_allow", "agree_block")


def _classify(node9_verdict: str, willow_verdict: str) -> str | None:
    if willow_verdict not in ("allow", "block"):
        return None  # held / anything else — excluded from the 4 classes (F10)
    if node9_verdict not in _VALID_NODE9_VERDICTS:
        return None  # shim_error / unknown — excluded, never counted as agreement
    node9_strict = node9_verdict in ("block", "review")
    willow_block = willow_verdict == "block"
    if node9_strict and not willow_block:
        return "node9_stricter"
    if not node9_strict and willow_block:
        return "willow_stricter"
    if not node9_strict and not willow_block:
        return "agree_allow"
    return "agree_block"


def _read_ledger(since: str | None = None) -> list[dict[str, Any]]:
    path = ledger_path()
    if not path.is_file():
        return []
    cutoff = None
    if since:
        cutoff = datetime.fromisoformat(since)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=UTC)
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if cutoff is not None:
            try:
                ts = datetime.fromisoformat(str(row.get("ts", "")))
            except ValueError:
                continue
            if ts < cutoff:
                continue
        rows.append(row)
    return rows


def _selftest_result_path() -> Path:
    return _shadow_dir_path() / "selftest.json"


def _write_selftest_result(result: dict[str, Any]) -> None:
    _ensure_shadow_dir()
    try:
        _selftest_result_path().write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    except OSError:
        pass


def _read_selftest_result() -> dict[str, Any] | None:
    try:
        return json.loads(_selftest_result_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None


#: Prefix for `run_selftest`'s per-run probe command — never a real shell
#: effect (a no-op even if some future change actually executed it
#: locally, which nothing here does). Loki CC59AF30 T2: a FIXED command
#: (no nonce) meant `run_selftest` matched ANY row ever written with that
#: same cmd_hmac, so one successful run made every LATER selftest report
#: `ok` for the rest of the 30-day retention window regardless of whether
#: the recorder still worked. Each call now embeds a fresh random nonce, so
#: a run can only ever match its OWN row.
_SELFTEST_COMMAND_PREFIX = "true # willow-mcp node9-shadow selftest probe"


def run_selftest(timeout: float = 5.0, poll_interval: float = 0.05) -> dict[str, Any]:
    """``willow-mcp shadow-report node9 --selftest`` (Loki 1CCE0D9B, INFO;
    hardened per Loki CC59AF30 T2): in production the detached recorder
    runs under `python -I`, which resolves whatever `willow_mcp` package
    the interpreter's OWN site-packages sees — until this branch is merged
    and pulled there, that import can fail silently (`_spawn_detached`'s
    own `stderr=DEVNULL` plus `_do_record`'s outer catch-all mean a broken
    recorder produces NO row and NO visible signal at all). This tells "no
    traffic yet" apart from "the recorder cannot run": it fires a real,
    per-run, benign command (a fresh random nonce embedded in the text, so
    the hash below can only ever match THIS run's own row — never an older
    row from a time the recorder happened to still work) through the REAL
    `spawn_shadow()` path — fire-and-forget, exactly like a production
    caller — then polls the ledger for a row matching both this run's
    nonce-derived `cmd_hmac` AND a `ts` at or after this run started (belt
    and braces against the astronomically unlikely HMAC collision) up to
    `timeout` seconds. The result (ok/when/error) is persisted so the plain
    report header can show the last run without re-running it."""
    run_started = datetime.now(UTC)
    nonce = os.urandom(16).hex()
    command = f"{_SELFTEST_COMMAND_PREFIX} {nonce}"
    marker_hmac = _cmd_hmac(command)
    ran_at = run_started.isoformat()
    if not is_installed():
        result = {"ok": False, "ran_at": ran_at, "error": "not_installed"}
        _write_selftest_result(result)
        return result
    spawn_shadow(
        surface="selftest", seat="selftest", command=command,
        willow_verdict="allow",
    )
    deadline = time.monotonic() + timeout
    ok = False
    while time.monotonic() < deadline:
        rows = _read_ledger()
        for r in rows:
            if r.get("cmd_hmac") != marker_hmac:
                continue
            try:
                row_ts = datetime.fromisoformat(str(r.get("ts", "")))
            except ValueError:
                continue
            if row_ts >= run_started:
                ok = True
                break
        if ok:
            break
        time.sleep(poll_interval)
    result = {
        "ok": ok,
        "ran_at": ran_at,
        "error": None if ok else "no_row_appeared_within_timeout",
    }
    _write_selftest_result(result)
    return result


def build_report(since: str | None = None, prune: bool = True) -> dict[str, Any]:
    """Counts by agreement class, per rule and per surface, plus the top
    node9-stricter rows. Reads only, except that this is one of the two
    places pruning is allowed to run (the other is `--prune`); pass
    `prune=False` to skip it (used by tests that want a stable fixture)."""
    if prune:
        prune_ledger()
    # Loki CC59AF30 T2: a selftest row is diagnostic, never real traffic —
    # it must never move an agreement-class count, a surface count, or the
    # total, and it never appears in the top-stricter table. It shows only
    # in the report header via `run_selftest`'s own persisted result.
    rows = [r for r in _read_ledger(since) if r.get("surface") != "selftest"]
    classes = {c: 0 for c in _CLASSES}
    shim_errors = 0
    unknowns = 0
    held = 0
    by_surface: dict[str, dict[str, int]] = {}
    by_rule: dict[str, int] = {}
    node9_stricter_rows: list[dict[str, Any]] = []

    for row in rows:
        node9_verdict = row.get("node9_verdict", "")
        willow_verdict = row.get("willow_verdict", "allow")
        if willow_verdict == "held":
            held += 1
            continue
        if node9_verdict == "unknown":
            unknowns += 1
            continue
        if node9_verdict not in _VALID_NODE9_VERDICTS:
            shim_errors += 1
            continue
        cls = _classify(node9_verdict, willow_verdict)
        if cls is None:
            continue
        classes[cls] += 1
        surface = row.get("surface", "unknown")
        by_surface.setdefault(surface, {c: 0 for c in _CLASSES})
        by_surface[surface][cls] += 1
        rule = row.get("node9_rule") or "(unnamed)"
        if cls == "node9_stricter":
            by_rule[rule] = by_rule.get(rule, 0) + 1
            # A hash-only row has no `command`/`redacted` text field at all —
            # only `shape` — so there is never anything to print here beyond
            # what the ledger itself already carries (never re-derive text).
            node9_stricter_rows.append({
                "ts": row.get("ts"),
                "surface": surface,
                "rule": rule,
                "shape": row.get("shape", ""),
                "flags": row.get("flags", []),
            })

    node9_stricter_rows.sort(key=lambda r: r.get("ts") or "", reverse=True)
    return {
        "total": len(rows),
        "shim_errors": shim_errors,
        "unknown": unknowns,
        "held": held,
        "classes": classes,
        "by_surface": by_surface,
        "node9_stricter_by_rule": by_rule,
        "top_node9_stricter": node9_stricter_rows[:20],
        "since": since,
        "selftest": _read_selftest_result(),
    }


def render_report(report: dict[str, Any]) -> str:
    lines = [
        f"node9 shadow report ({report['total']} evaluations"
        + (f", since {report['since']}" if report.get("since") else "")
        + f", {report['shim_errors']} shim_error, {report['unknown']} unknown, "
        + f"{report['held']} held)",
    ]
    selftest = report.get("selftest")
    if selftest:
        status = "ok" if selftest.get("ok") else f"FAILED ({selftest.get('error')})"
        lines.append(f"last selftest: {status} at {selftest.get('ran_at')}")
    else:
        lines.append("last selftest: never run (see --selftest)")
    lines.append("")
    lines.append("By agreement class:")
    for cls in _CLASSES:
        lines.append(f"  {cls:<16} {report['classes'][cls]}")
    lines.append("")
    lines.append("By surface:")
    for surface, counts in sorted(report["by_surface"].items()):
        lines.append(f"  {surface}: " + ", ".join(f"{c}={n}" for c, n in counts.items()))
    lines.append("")
    lines.append("node9-stricter, by rule:")
    if not report["node9_stricter_by_rule"]:
        lines.append("  (none)")
    for rule, n in sorted(report["node9_stricter_by_rule"].items(), key=lambda kv: -kv[1]):
        lines.append(f"  {rule}: {n}")
    lines.append("")
    lines.append("Top node9-stricter rows (never the raw command — a shape-only row")
    lines.append("has no text field at all, only a shape and flag category names):")
    if not report["top_node9_stricter"]:
        lines.append("  (none)")
    for row in report["top_node9_stricter"][:10]:
        flags = ",".join(row.get("flags") or []) or "-"
        lines.append(f"  [{row['ts']}] {row['surface']} {row['rule']}: {row['shape']} [{flags}]")
    return "\n".join(lines)


# ── CLI: `python -I -m willow_mcp.node9_shadow --record` (stdin) / `--prune` ──

def _main(argv: list[str]) -> int:
    if argv and argv[0] == "--record":
        # R6: the payload comes ONLY from stdin — never a filename argument,
        # never a tempfile. Reading raw bytes (not sys.stdin, which is a
        # TextIOWrapper that would mis-decode a non-UTF-8 command) then
        # decoding with surrogateescape so an undecodable byte never raises
        # here — it becomes part of what _do_record's own size/decode check
        # sees, exactly as a real Bash payload would.
        try:
            raw = sys.stdin.buffer.read()
        except Exception:  # noqa: BLE001 — no payload, nothing to record.
            return 0
        try:
            payload = json.loads(raw.decode("utf-8", errors="surrogateescape"))
        except (ValueError, json.JSONDecodeError):
            return 0
        _do_record(payload)
        return 0
    if argv and argv[0] == "--prune":
        prune_ledger()
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
