"""willow_mcp/onescript_executor.py — the desk runs the one script; nobody types.

``onescript_run_execute`` is the broker door for the host steps of the one
script's first local seat run (willow-bot ``one-script`` + ``ratatosk
--onescript``): key export, check-in, scope, seal, serve, one Rat turn, the
turn that takes the proposals, check-out. Operator, 2026-10-07: *"build the
broker verb."* Standing rule (2026-09-16): an act that cannot run through Kart
or a broker verb, once bundled in the APK, is a gap.

Shape, deliberately narrow:

* **A fixed step table.** The caller names a step and its validated arguments;
  it never supplies argv, a path, an interpreter, or an environment. Every
  argument is checked against a closed shape and unknown keys are refused.
* **Fixed paths.** Interpreters come from ``$WILLOW_HOME/venvs/<venv>/bin``;
  the willow-bot checkout is resolved the way ``git_pull_execute`` resolves a
  clone (verified by its ``origin``, never a symlink); the box, the served
  file and the proposals file sit under that checkout's ``.flow/onescript``;
  the signing keyring and its public export sit under ``$WILLOW_HOME``.
* **A minimal child environment.** ``HOME``, ``PATH``, ``WILLOW_HOME``,
  ``NESTOR_DB``/``WILLOW_NESTOR_DB``, ``ONESCRIPT_GROVE`` and a loopback
  ``OLLAMA_HOST`` — no provider keys, no proxy variables, and in particular no
  ``WILLOW_KEYRING`` (it names the *signing* ring; the one-script reads the
  public export only).
* **Three states, never collapsed.** ``populated`` (ran, exit 0, output),
  ``empty`` (ran, exit 0, nothing to say) and ``unreachable`` (could not run to
  a verdict: a missing prerequisite, a timeout, a non-zero exit). The raw
  ``exit`` and a ``reason`` always ride along.
* **Ink.** A FRANK ``onescript_run`` receipt per executed step: step, an
  arguments digest (never the text itself), exit, duration, state.
* **No envelope, no egress, nothing pushed.** Local steps only, like
  ``git_pull_execute``. ``keys_export`` returns names and counts, never key
  material.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from . import paths

EVENT = "onescript_run"

BOT_REPO = "willow-memory/willow-bot"
BOT_VENV = "willow-bot"
RAT_VENV = "willow-mcp"  # the venv ratatosk is installed into on this box

#: Per-step wall clock, seconds. ``checkin`` runs the tests gate, so it gets
#: more than the 2-minute default the other local steps share.
TIMEOUTS = {
    "keys_export": 120,
    "checkin": 300,
    "scope": 120,
    "seal": 120,
    "serve": 120,
    "rat_turn": 900,
    "turn": 120,
    "checkout": 120,
}

STEPS = tuple(TIMEOUTS)

#: Environment variables a child may inherit. Nothing else.
ENV_ALLOW = (
    "HOME", "PATH", "WILLOW_HOME", "NESTOR_DB", "WILLOW_NESTOR_DB",
    "ONESCRIPT_GROVE", "OLLAMA_HOST",
)

WS = ("who", "what", "when", "where")
MAX_TASK = 2000
MAX_VALUE = 200
MAX_CHARS_CAP = 60000  # ratatosk reads at most 64 KiB of served file
MAX_STDOUT = 200_000
_JSON_RETURN_CAP = 20_000
_TAIL_LINES = 20

_SUBJECT_RE = re.compile(r"^(serve|proposal):[0-9a-f]{16,128}$")
_PAIR_ID_RE = re.compile(r"^[0-9A-Za-z-]{4,64}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{32,}")
_PEM = re.compile(r"-----BEGIN [A-Z ]+-----.*?(?:-----END [A-Z ]+-----|$)", re.S)
_KEYS_LINE = re.compile(
    r"^(exported \d+ public key\(s\) to .+|  kept     \S.*|  dropped  .+|refused: .+)$"
)


class _Refusal(Exception):
    def __init__(self, errno: str, reason: str):
        super().__init__(reason)
        self.errno = errno
        self.reason = reason


def _refuse(step: str, errno: str, reason: str) -> dict:
    return {"ok": False, "ran": False, "step": step, "error": errno, "reason": reason}


# ── argument validation ──────────────────────────────────────────────────────

def _no_args(args: dict) -> list[str]:
    if args:
        raise _Refusal("EINVAL", f"this step takes no arguments (got {sorted(args)})")
    return []


def _only(args: dict, allowed: set[str]) -> None:
    extra = sorted(set(args) - allowed)
    if extra:
        raise _Refusal("EINVAL", f"unknown argument(s) {extra}; allowed: {sorted(allowed)}")


def _text(value, what: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _Refusal("EINVAL", f"{what} must be a non-empty string")
    if len(value) > limit:
        raise _Refusal("EINVAL", f"{what} is over {limit} characters")
    if "\x00" in value:
        raise _Refusal("EINVAL", f"{what} may not contain NUL")
    if value.lstrip().startswith("-"):
        raise _Refusal("EINVAL", f"{what} may not begin with '-'")
    return value


def _int(value, what: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Refusal("EINVAL", f"{what} must be an integer")
    if not lo <= value <= hi:
        raise _Refusal("EINVAL", f"{what} must be between {lo} and {hi}")
    return value


def _spec_flags(args: dict) -> list[str]:
    """``--by`` / ``--match W=value`` / ``--upto`` shared by scope and serve."""
    flags: list[str] = []
    by = args.get("by", ["who"])
    if isinstance(by, str):
        by = [by]
    if not isinstance(by, list) or not by or not all(isinstance(w, str) for w in by):
        raise _Refusal("EINVAL", "by must be a non-empty list of W names")
    bad = [w for w in by if w not in WS]
    if bad:
        raise _Refusal("EINVAL", f"by names {bad}; the W's are {list(WS)}")
    flags += ["--by", ",".join(by)]
    match = args.get("match") or {}
    if not isinstance(match, dict):
        raise _Refusal("EINVAL", "match must be an object of W -> value")
    for key in sorted(match):
        if key not in WS:
            raise _Refusal("EINVAL", f"match key {key!r} is not a W ({list(WS)})")
        value = match[key]
        if not isinstance(value, str) or not value or len(value) > MAX_VALUE or "\x00" in value:
            raise _Refusal("EINVAL", f"match value for {key!r} must be a short non-empty string")
        flags += ["--match", f"{key}={value}"]
    if args.get("upto") is not None:
        flags += ["--upto", str(_int(args["upto"], "upto", 0, 10**9))]
    return flags


def _scope_args(args: dict) -> list[str]:
    _only(args, {"by", "match", "upto"})
    return _spec_flags(args)


def _serve_args(args: dict) -> list[str]:
    _only(args, {"by", "match", "upto", "max_chars"})
    if args.get("upto") is None:
        raise _Refusal("EINVAL", "serve needs upto, the row scope named")
    if args.get("max_chars") is None:
        raise _Refusal("EINVAL", "serve needs max_chars; nothing is served uncapped")
    flags = _spec_flags(args)
    flags += ["--max-chars", str(_int(args["max_chars"], "max_chars", 1, MAX_CHARS_CAP))]
    return flags


def _seal_args(args: dict) -> tuple[list[str], list[str]]:
    _only(args, {"subject", "pair_id"})
    subject = args.get("subject")
    if not isinstance(subject, str) or not _SUBJECT_RE.match(subject):
        raise _Refusal("EINVAL", "subject must be serve:<hash> or proposal:<hash>")
    pair_id = args.get("pair_id")
    if pair_id is not None and (not isinstance(pair_id, str) or not _PAIR_ID_RE.match(pair_id)):
        raise _Refusal("EINVAL", "pair_id must be a Nestor pair id")
    return [subject], []


# ── fixed locations ──────────────────────────────────────────────────────────

class _Ctx:
    """Everything the broker fixes, resolved once per call."""

    def __init__(self, home: Path, bot: Optional[Path]):
        self.home = home
        self.bot = bot

    @property
    def one_script(self) -> Path:
        assert self.bot is not None
        return self.bot / "one-script"

    @property
    def box(self) -> Path:
        assert self.bot is not None
        return self.bot / ".flow" / "onescript"

    @property
    def served(self) -> Path:
        return self.box / "served.json"

    @property
    def proposals(self) -> Path:
        return self.box / "proposals.jsonl"

    @property
    def signing_ring(self) -> Path:
        return self.home / "verifiers.json"

    @property
    def public_ring(self) -> Path:
        return self.home / "config" / "verifiers.public.json"

    @property
    def bot_python(self) -> Path:
        return self.home / "venvs" / BOT_VENV / "bin" / "python"

    @property
    def rat(self) -> Path:
        return self.home / "venvs" / RAT_VENV / "bin" / "ratatosk"


def _unreachable(reason: str, **extra) -> dict:
    return {"state": "unreachable", "reason": reason, "exit": None, **extra}


def _resolve_bot(bot_checkout: Optional[Path], runner: Optional[Callable]) -> Path | dict:
    if bot_checkout is not None:
        clone: Optional[Path] = Path(bot_checkout)
    else:
        from . import pull_executor

        status = pull_executor.resolve_clone_status(BOT_REPO, runner=runner)
        clone = status["clone"]
        if clone is None:
            why = (
                f"{len(status['candidates'])} checkouts match {BOT_REPO}"
                if status["error"] == "EAMBIG"
                else f"no checkout of {BOT_REPO} found under the github root"
            )
            return _unreachable(why, error=status["error"] or "ENOCLONE")
    if clone.is_symlink():
        return _unreachable(f"refusing a symlinked checkout: {clone}", error="EINVAL")
    one = clone / "one-script"
    if one.is_symlink() or not (one / "onescript" / "__main__.py").is_file():
        return _unreachable(f"{one} is not a real one-script directory", error="ENOCLONE")
    return clone


def _require_real_box(ctx: _Ctx) -> Optional[dict]:
    for part in (ctx.bot / ".flow", ctx.box):  # type: ignore[operator]
        if part.is_symlink():
            return _unreachable(f"refusing a symlinked box path: {part}")
    if not ctx.box.is_dir():
        return _unreachable(f"the box {ctx.box} does not exist; run checkin first")
    return None


def _need_python(ctx: _Ctx) -> Optional[dict]:
    if not ctx.bot_python.is_file():
        return _unreachable(f"no interpreter at {ctx.bot_python}; the bot venv is not installed")
    return None


# ── model check (rat_turn) ───────────────────────────────────────────────────

def _ollama_root() -> str:
    raw = (os.environ.get("OLLAMA_HOST") or "").strip() or "127.0.0.1:11434"
    if "://" not in raw:
        raw = "http://" + raw
    return raw.rstrip("/")


def _loopback(root: str) -> bool:
    from urllib.parse import urlparse

    host = (urlparse(root).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1")


def list_local_models(root: Optional[str] = None, timeout: float = 3.0) -> list[str] | None:
    """Installed local Ollama tags (cloud/remote entries left out), or None when
    the daemon will not say. No proxy: nothing here may leave loopback."""
    root = root or _ollama_root()
    if not _loopback(root):
        return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"{root}/api/tags", timeout=timeout) as resp:
            info = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 — "won't say" is an answer, reported as unreachable
        return None
    names: list[str] = []
    for m in info.get("models") or []:
        if not isinstance(m, dict) or m.get("remote_host"):
            continue
        for key in ("name", "model"):
            if isinstance(m.get(key), str):
                names.append(m[key])
    return names


def _check_model(model, lister: Callable[[], list[str] | None]) -> Optional[dict]:
    """None when ``model`` is an installed local tag; a result dict otherwise."""
    if not isinstance(model, str) or not _MODEL_RE.match(model):
        raise _Refusal("EINVAL", "model must be a plain Ollama tag (letters, digits, . _ : / -)")
    if model.lower().endswith(("-cloud", ":cloud")):
        raise _Refusal("EINVAL", f"model {model!r} is a cloud model; rat_turn runs local models only")
    if not _loopback(_ollama_root()):
        return _unreachable("OLLAMA_HOST is not a loopback address; rat_turn runs local models only")
    names = lister()
    if names is None:
        return _unreachable("the local Ollama daemon did not list its models")
    have = set(names)
    if model not in have and (":" in model or f"{model}:latest" not in have):
        raise _Refusal("EMODEL", f"model {model!r} is not an installed local Ollama tag")
    return None


# ── process runner ───────────────────────────────────────────────────────────

def _child_env(home: Path) -> dict[str, str]:
    env = {k: os.environ[k] for k in ENV_ALLOW if os.environ.get(k)}
    env["WILLOW_HOME"] = str(home)
    root = os.environ.get("OLLAMA_HOST")
    if root and not _loopback(_ollama_root()):
        env.pop("OLLAMA_HOST", None)
    return env


def _run_child(argv: list[str], *, env: dict[str, str], cwd: Path, timeout: float) -> dict:
    """Run one fixed argv in its own session so a timeout kills the whole tree."""
    started = time.monotonic()
    try:
        proc = subprocess.Popen(  # noqa: S603 — argv is built from the fixed table
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            errors="replace", start_new_session=True,
        )
    except OSError as exc:
        return {"spawn_error": f"{type(exc).__name__}: {exc}", "duration": 0.0}
    try:
        out, err = proc.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
        out, err = proc.communicate()
        timed_out = True
    return {
        "rc": proc.returncode, "out": (out or "")[:MAX_STDOUT], "err": (err or "")[:MAX_STDOUT],
        "timed_out": timed_out, "duration": round(time.monotonic() - started, 3),
    }


def _redact(text: str) -> str:
    return _HEX_RUN.sub("[hex withheld]", _PEM.sub("[pem withheld]", text))


def _tail(text: str) -> str:
    return "\n".join(text.strip().splitlines()[-_TAIL_LINES:])


def _digest(step: str, args: dict) -> str:
    blob = json.dumps({"step": step, "args": args}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _keys_summary(out: str) -> dict:
    """Names and counts only — never anything but the whitelisted lines."""
    kept, dropped, refused = [], [], []
    for line in out.splitlines():
        if not _KEYS_LINE.match(line):
            continue
        if line.startswith("  kept"):
            kept.append(line.split(None, 1)[1].strip())
        elif line.startswith("  dropped"):
            dropped.append(line.split(None, 2)[1])
        elif line.startswith("refused:"):
            refused.append(_HEX_RUN.sub("[hex withheld]", line))
    return {"exported": kept, "exported_count": len(kept),
            "dropped_hmac": dropped, "dropped_hmac_count": len(dropped), "refused": refused}


# ── the step table ───────────────────────────────────────────────────────────

def _plan(step: str, args: dict, ctx: _Ctx, lister: Callable) -> dict:
    """The fixed argv for ``step`` (or an early result dict under ``result``)."""
    py = str(ctx.bot_python)

    def onescript(*rest: str) -> list[str]:
        return [py, "-m", "onescript", *rest]

    cwd = ctx.one_script
    if step == "keys_export":
        _no_args(args)
        if not ctx.signing_ring.is_file():
            return {"result": _unreachable(f"no signing keyring at {ctx.signing_ring}")}
        return {"argv": onescript("keys", "export", "--from", str(ctx.signing_ring),
                                  "--to", str(ctx.public_ring)), "cwd": cwd}
    if step == "checkin":
        _no_args(args)
        return {"argv": onescript("checkin"), "cwd": cwd}
    if step == "checkout":
        _no_args(args)
        return {"argv": onescript("checkout"), "cwd": cwd}
    if step == "scope":
        return {"argv": onescript("scope", *_scope_args(args)), "cwd": cwd}
    if step == "serve":
        return {"argv": onescript("serve", *_serve_args(args)), "cwd": cwd}
    if step == "seal":
        (subject,), _ = _seal_args(args)
        # The pair is found by subject in Nestor's store (read-only, fixed in
        # the child's env); the CLI takes no pair id. A pair_id, if given, is
        # validated and kept for the receipt only.
        return {"argv": onescript("seal", subject), "cwd": cwd}
    if step == "turn":
        _only(args, {"bite", "proposals"})
        bite = _text(args.get("bite"), "bite", MAX_TASK)
        use = args.get("proposals", True)
        if not isinstance(use, bool):
            raise _Refusal("EINVAL", "proposals must be true or false")
        argv = onescript("turn", bite)
        if use:
            if (bad := _require_real_box(ctx)) is not None:
                return {"result": bad}
            if not ctx.proposals.is_file():
                return {"result": _unreachable(
                    f"no proposals file at {ctx.proposals}; run rat_turn first or pass proposals=false")}
            argv += ["--proposal", str(ctx.proposals)]
        return {"argv": argv, "cwd": cwd}
    if step == "rat_turn":
        _only(args, {"model", "task"})
        task = _text(args.get("task"), "task", MAX_TASK)
        model = args.get("model")
        early = _check_model(model, lister)
        if early is not None:
            return {"result": early}
        if (bad := _require_real_box(ctx)) is not None:
            return {"result": bad}
        if not ctx.rat.is_file():
            return {"result": _unreachable(
                f"ratatosk is not installed at {ctx.rat}; the onescript model seat cannot run")}
        return {"argv": [str(ctx.rat), "--onescript", "--served", str(ctx.served),
                         "--out", str(ctx.proposals), "--model", model, task],
                "cwd": ctx.home}
    raise _Refusal("EINVAL", f"unknown step {step!r}; steps are {list(STEPS)}")


def _shape(step: str, run: dict) -> dict:
    """Turn a finished child into the three-state result."""
    if "spawn_error" in run:
        return _unreachable(f"could not start the step: {run['spawn_error']}", duration_s=0.0)
    rc, out, err = run["rc"], run["out"], run["err"]
    base = {"exit": rc, "duration_s": run["duration"]}
    if run["timed_out"]:
        return {**base, "exit": None, "state": "unreachable", "timed_out": True,
                "reason": f"{step} timed out after {TIMEOUTS[step]}s and was killed",
                "tail": _redact(_tail(out or err))}
    if step == "keys_export":
        summary = _keys_summary(out)
        if rc == 0 and summary["exported_count"]:
            return {**base, "state": "populated", "reason": "", "stdout_json": summary}
        if rc == 0:
            return {**base, "state": "empty", "reason": "no ed25519 entries were exported",
                    "stdout_json": summary}
        why = summary["refused"][0] if summary["refused"] else f"keys export exited {rc}"
        return {**base, "state": "unreachable", "reason": why, "stdout_json": summary}
    if rc != 0:
        why = next((ln for ln in out.splitlines() if ln.startswith(("refused:", "BOX WON'T OPEN"))), "")
        return {**base, "state": "unreachable",
                "reason": _redact(why) or _redact(_tail(err)) or f"{step} exited {rc}",
                "tail": _redact(_tail(out or err))}
    if not out.strip():
        return {**base, "state": "empty", "reason": f"{step} exited 0 and printed nothing",
                "tail": _redact(_tail(err))}
    parsed = None
    if len(out) <= _JSON_RETURN_CAP:
        try:
            parsed = json.loads(out)
        except ValueError:
            parsed = None
    result = {**base, "state": "populated", "reason": ""}
    if parsed is not None:
        result["stdout_json"] = parsed
    else:
        result["tail"] = _redact(_tail(out))
        if len(out) > _JSON_RETURN_CAP:
            result["truncated"] = True
    return result


def execute_step(
    app_id: str,
    step: str,
    args: Optional[dict] = None,
    *,
    project: str = "",
    session: str = "",
    ledger=None,
    bot_checkout: Optional[Path] = None,
    model_lister: Optional[Callable[[], list[str] | None]] = None,
    runner: Optional[Callable] = None,
) -> dict:
    """Run one fixed step of the one script, or refuse it with the reason.

    ``bot_checkout`` replaces the willow-bot clone lookup; ``model_lister``
    replaces the Ollama query; ``runner`` replaces the git runner the clone
    lookup uses. None of these is reachable from the MCP tool."""
    step = (step or "").strip() if isinstance(step, str) else ""
    if step not in STEPS:
        return _refuse(step or "?", "EINVAL", f"unknown step; steps are {list(STEPS)}")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return _refuse(step, "EINVAL", "args must be an object")

    try:
        home = paths.willow_home()
    except paths.RetiredHomeError as exc:
        return {"ok": False, "ran": False, "step": step, "state": "unreachable",
                "exit": None, "reason": f"retired_home: {exc}"}
    ctx = _Ctx(home, None)

    try:
        pair_id = None
        if step == "seal":
            pair_id = _seal_args(args)[0] and args.get("pair_id")
        digest = _digest(step, args)
        resolved = _resolve_bot(bot_checkout, runner)
        if isinstance(resolved, dict):
            return _finish(step, resolved, digest, ledger, project, app_id, session, ran=False)
        ctx.bot = resolved
        if (bad := _need_python(ctx)) is not None and step != "rat_turn":
            return _finish(step, bad, digest, ledger, project, app_id, session, ran=False)
        plan = _plan(step, args, ctx, model_lister or list_local_models)
    except _Refusal as exc:
        return _refuse(step, exc.errno, exc.reason)

    if "result" in plan:
        return _finish(step, plan["result"], digest, ledger, project, app_id, session, ran=False)
    run = _run_child(plan["argv"], env=_child_env(home), cwd=plan["cwd"], timeout=TIMEOUTS[step])
    shaped = _shape(step, run)
    extra = {"pair_id": pair_id} if pair_id else {}
    return _finish(step, shaped, digest, ledger, project, app_id, session, ran=True, extra=extra)


def _finish(step, shaped, digest, ledger, project, app_id, session, *, ran, extra=None) -> dict:
    out = {"ok": ran and shaped.get("exit") == 0,
           "ran": ran, "step": step, "args_digest": digest, **shaped}
    if extra:
        out.update(extra)
    content = {
        "actor": app_id, "session": session, "step": step, "args_digest": digest,
        "exit": shaped.get("exit"), "duration_s": shaped.get("duration_s", 0.0),
        "state": shaped.get("state"), "ran": ran,
        "timed_out": bool(shaped.get("timed_out")), **(extra or {}),
    }
    rid = None
    if ledger is not None:
        try:
            rid = ledger.append(project or "onescript", EVENT, content)
        except Exception as exc:  # noqa: BLE001 — the act happened; the ink failing is reported
            out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    out["receipt_id"] = rid
    return out
