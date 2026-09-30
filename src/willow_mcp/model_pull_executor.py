"""willow_mcp/model_pull_executor.py — pull a named Ollama model through the
local daemon; nobody types.

Verb 26, ``model.pull`` (bounds ``{models}``). Gap ``56d2ff156771``: the
Kaggle step-2b models (gemma4:e2b, phi4-mini, qwen3.5) had no route onto the
box. Kart is network-isolated and ``allow_localhost`` is retired, and the
Ollama daemon does its own registry egress — so the broker, not Kart, calls
the daemon's ``/api/pull`` on loopback. Governance record
``model-pull-is-a-broker-verb-2026-09-30`` (Nestor pair ``87989683``); the
syscall row needs that pair sealed before merge.

Two keys, both required, each a different question:

* the **lease** is the egress key — a live, operator-issued lease for the
  caller (:func:`willow_mcp.lease.read_lease`). Nothing is pulled without
  one, because the daemon's registry traffic is exactly the egress the lease
  exists to meter;
* the **envelope** (``model.pull``) names *what* may be pulled: the model
  string must match a member of its ``models`` bound exactly.

What it refuses, each with its own errno, in this order:

* ``EINVAL`` — a model name that is not a bare ``name[:tag]`` (no registry
  host, no scheme, no whitespace);
* ``ENOLEASE`` — no live lease for ``app_id`` (status reported: none,
  expired, unreadable, ...);
* ``ENOENT`` / ``EAMBIG`` / ``EEXPIRED`` / ``EDQUOT`` / ``ENOGRANTS`` /
  ``EACCES`` — the envelope check. ``EAMBIG`` is also how a model or tag
  outside the bounds refuses, with the failed field named;
* ``EPERM`` — the configured daemon address is not loopback;
* ``EUNREACH`` — the daemon does not answer on loopback.

**A failed pull does not spend the envelope.** The envelope is *checked*
before the act (no citation written) and *cited* only after the daemon
reports success and the pulled manifest digest is read back. A pull that
fails mid-stream (``EPULL``) or whose digest cannot be confirmed
(``EVERIFY``) leaves a ``model_pull_failed`` FRANK receipt and no citation,
so a ``max_count=1`` grant is still there for the retry.

Refusals the operator could remedy (no lease, no envelope, near-miss, spent
or expired) file an ask in the human-required queue, same as
:mod:`unit_reload_executor`.
"""
from __future__ import annotations

import http.client
import json
import os
import re
from typing import Callable, Optional
from urllib.parse import urlparse

VERB = "model.pull"
EVENT = "model_pull"
FAILED_EVENT = "model_pull_failed"

DEFAULT_DAEMON = "http://127.0.0.1:11434"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_PROBE_TIMEOUT_S = 5
#: Per-read socket timeout while streaming a pull. Layers arrive in
#: multi-GB chunks; the daemon reports progress far more often than this.
_STREAM_READ_TIMEOUT_S = 300

#: Errnos for which an ask is worth filing: the verb is real and the actor is
#: the right one; what is missing is a grant or lease the operator could issue.
_ASKABLE = frozenset({"ENOLEASE", "ENOENT", "EAMBIG", "EEXPIRED", "EDQUOT", "ENOGRANTS"})

#: ``name[:tag]`` or ``namespace/name[:tag]``. No scheme, no registry host
#: (a first path segment with a dot is a host, and is refused below).
_MODEL_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?(:[A-Za-z0-9][A-Za-z0-9._-]*)?$"
)
_DIGEST_RE = re.compile(r"^(sha256:)?[0-9a-f]{64}$")


class DaemonUnreachable(Exception):
    """The daemon did not answer; ``cause`` is distinct per failure shape."""

    def __init__(self, cause: str, detail: str = ""):
        super().__init__(f"{cause}: {detail}" if detail else cause)
        self.cause = cause
        self.detail = detail


class PullFailed(Exception):
    """The daemon answered but the pull did not complete."""


def _refuse(errno: str, reason: str, **extra) -> dict:
    return {"ok": False, "error": errno, "reason": reason, "pulled": False, **extra}


def split_model(model: str) -> tuple[str, str]:
    """``(name, tag)`` of a bare ``name[:tag]`` string; the tag is ``latest``
    when absent (the daemon's own default). Raises ``ValueError`` for anything
    else — a registry host, a scheme, whitespace, an empty name."""
    m = (model or "").strip()
    if not m or not _MODEL_RE.match(m):
        raise ValueError(f"{model!r} is not a bare name[:tag] model reference")
    if "/" in m and "." in m.split("/", 1)[0]:
        raise ValueError(f"{model!r} names a registry host — only the daemon's default registry is pullable")
    name, _, tag = m.partition(":")
    return name, tag or "latest"


def resolve_daemon(base_url: str = "") -> tuple[str, int]:
    """``(host, port)`` of the daemon, loopback only. ``base_url`` (tests) or
    ``OLLAMA_HOST`` or the default. Raises ``PermissionError`` for a
    non-loopback host — a broker that follows an env var off the box is an
    egress path the lease does not describe."""
    raw = (base_url or os.environ.get("OLLAMA_HOST") or DEFAULT_DAEMON).strip()
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    if parsed.scheme != "http" or host not in _LOOPBACK_HOSTS:
        raise PermissionError(f"daemon address {raw!r} is not plain-http loopback")
    return host, parsed.port or 11434


def _conn(host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _get_json(host: str, port: int, path: str) -> dict:
    conn = _conn(host, port, _PROBE_TIMEOUT_S)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
    except TimeoutError as exc:
        raise DaemonUnreachable("timeout", str(exc)) from exc
    except OSError as exc:
        raise DaemonUnreachable("connection_failed", f"{type(exc).__name__}: {exc}") from exc
    finally:
        conn.close()
    if resp.status != 200:
        raise DaemonUnreachable("bad_status", f"GET {path} -> {resp.status}")
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DaemonUnreachable("bad_response", f"GET {path} returned non-JSON") from exc
    if not isinstance(data, dict):
        raise DaemonUnreachable("bad_response", f"GET {path} returned a non-object")
    return data


def stream_pull(host: str, port: int, model: str) -> dict:
    """POST ``/api/pull`` and read the NDJSON stream to its end. Returns
    ``{"layers": {digest: total_bytes}, "statuses": n}`` on ``status:
    success``; raises :class:`PullFailed` on an ``error`` line, a non-200, a
    stream that ends without ``success``, or a socket failure mid-stream."""
    conn = _conn(host, port, _STREAM_READ_TIMEOUT_S)
    layers: dict[str, int] = {}
    statuses = 0
    success = False
    try:
        body = json.dumps({"model": model, "stream": True}).encode("utf-8")
        conn.request("POST", "/api/pull", body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        if resp.status != 200:
            tail = resp.read()[:300].decode("utf-8", "replace")
            raise PullFailed(f"daemon answered {resp.status}: {tail}")
        while True:
            line = resp.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise PullFailed("daemon stream carried a non-JSON line") from exc
            if not isinstance(msg, dict):
                continue
            if msg.get("error"):
                raise PullFailed(str(msg["error"])[:300])
            statuses += 1
            digest, total = msg.get("digest"), msg.get("total")
            if isinstance(digest, str) and isinstance(total, int) and not isinstance(total, bool):
                layers[digest] = max(layers.get(digest, 0), total)
            if msg.get("status") == "success":
                success = True
    except PullFailed:
        raise
    except OSError as exc:
        raise PullFailed(f"stream broke: {type(exc).__name__}: {exc}") from exc
    except http.client.HTTPException as exc:
        raise PullFailed(f"stream broke: {type(exc).__name__}: {exc}") from exc
    finally:
        conn.close()
    if not success:
        raise PullFailed("stream ended without status=success")
    return {"layers": layers, "statuses": statuses}


def read_back(host: str, port: int, name: str, tag: str) -> Optional[dict]:
    """The daemon's own record of ``name:tag`` from ``/api/tags`` —
    ``{"digest", "size"}`` — or ``None`` when it is not listed."""
    data = _get_json(host, port, "/api/tags")
    want = f"{name}:{tag}"
    for entry in data.get("models") or []:
        if isinstance(entry, dict) and entry.get("name") == want:
            return {"digest": entry.get("digest"), "size": entry.get("size")}
    return None


def _file_ask(app_id: str, *, model: str, errno: str, reason: str, fields,
              task_id: str, store=None) -> dict:
    """The row lands on the ``gates`` surface (``kind=consent`` under
    ``model.<model>``) — same shape as :func:`unit_reload_executor._file_ask`."""
    from . import gate_request

    detail = f"{errno}: {reason}"
    if fields:
        detail += f" (fields: {', '.join(str(f) for f in fields)})"
    summary = (
        f"{app_id or 'an agent'} asked to pull model {model!r} and was "
        f"refused: {detail}. The pull needs a live egress lease for the "
        f"caller and a model.pull envelope with bounds (models=[{model!r}])."
    )
    return gate_request.open_request(
        app_id or "", f"model.{model}", task_id=task_id, reason=summary, store=store,
    )


def _refuse_with_ask(app_id, model, errno, reason, *, fields=None, task_id="",
                     store=None, **extra) -> dict:
    out = _refuse(errno, reason, **extra)
    if fields:
        out["fields"] = fields
    if errno in _ASKABLE:
        out["ask"] = _file_ask(app_id, model=model, errno=errno, reason=reason,
                               fields=fields, task_id=task_id, store=store)
    return out


def execute_model_pull(
    app_id: str,
    *,
    model: str,
    envelope_id: str = "",
    project: str = "willow",
    session: str = "",
    task_id: str = "",
    ledger=None,
    store=None,
    base_url: str = "",
    lease_reader: Optional[Callable[[str], dict]] = None,
) -> dict:
    """Pull exactly ``model`` through the local daemon under the
    ``model.pull`` envelope that governs ``app_id`` and a live lease — or
    refuse, and say which. ``ledger`` is a :class:`GovernanceLedger`; tests
    pass a fake-backed one. ``base_url`` points tests at a fake daemon on
    loopback. ``lease_reader`` replaces :func:`lease.read_lease`."""
    from . import lease as _lease
    from .envelopes import EnvelopeAuthority, governing_envelope_ids

    model = (model or "").strip()
    try:
        name, tag = split_model(model)
    except ValueError as exc:
        return _refuse("EINVAL", str(exc))

    if ledger is None:
        return _refuse(
            "EAMBIG",
            "no governance ledger: a pull that cannot be cited or receipted "
            "is not performed",
        )

    # Key one: the lease. Fail closed — only a positively `active` lease passes.
    lease_info = (lease_reader or _lease.read_lease)(app_id)
    if lease_info.get("status") != "active":
        return _refuse_with_ask(
            app_id, model, "ENOLEASE",
            f"no live egress lease for {app_id!r} (status "
            f"{lease_info.get('status')!r}) — the daemon's registry traffic "
            f"is egress and only a lease authorizes it",
            task_id=task_id, store=store, lease_status=lease_info.get("status"),
        )
    lease_id = f"{app_id}@{lease_info.get('granted_at')}"

    # Key two: the envelope — checked here, cited only after a real pull.
    call_args = {"models": [model]}
    try:
        matches = governing_envelope_ids(VERB, app_id)
    except (OSError, ValueError) as exc:
        return _refuse("EAMBIG", f"envelope registry unreadable: {exc}")
    if envelope_id:
        if envelope_id not in matches:
            return _refuse_with_ask(
                app_id, model, "ENOENT",
                f"envelope {envelope_id!r} does not govern {VERB} for {app_id!r}",
                task_id=task_id, store=store, envelope_ids=matches,
            )
        matches = [envelope_id]
    if not matches:
        return _refuse_with_ask(
            app_id, model, "ENOENT", f"no active {VERB} envelope governs {app_id!r}",
            task_id=task_id, store=store,
        )
    if len(matches) > 1:
        return _refuse(
            "EAMBIG",
            f"multiple active {VERB} envelopes govern {app_id!r} — pass "
            f"envelope_id to name which one to cite",
            envelope_ids=matches,
        )
    authority = EnvelopeAuthority(ledger)
    verdict = authority.check(matches[0], actor=app_id, verb=VERB, call_args=call_args)
    if not verdict.get("ok"):
        return _refuse_with_ask(
            app_id, model, verdict.get("errno", "EAMBIG"), verdict.get("reason", ""),
            fields=verdict.get("fields"), task_id=task_id, store=store,
            envelope_id=matches[0],
        )

    try:
        host, port = resolve_daemon(base_url)
    except PermissionError as exc:
        return _refuse("EPERM", str(exc), envelope_id=matches[0])

    def _failed(errno: str, reason: str, **extra) -> dict:
        out = _refuse(errno, reason, envelope_id=matches[0], model=name, tag=tag,
                      lease_id=lease_id, **extra)
        try:
            out["receipt_id"] = ledger.append(project, FAILED_EVENT, {
                "actor": app_id, "model": name, "tag": tag, "errno": errno,
                "reason": reason[:300], "lease_id": lease_id, "session": session,
                "envelope_id": matches[0],
            })
        except Exception as exc:  # noqa: BLE001 — the pull failed; the receipt failing is reported, not hidden
            out["receipt_error"] = f"{type(exc).__name__}: {exc}"
        return out

    try:
        _get_json(host, port, "/api/version")
    except DaemonUnreachable as exc:
        return _failed("EUNREACH", f"daemon unreachable: {exc}", cause=exc.cause)

    try:
        streamed = stream_pull(host, port, model)
    except PullFailed as exc:
        return _failed("EPULL", f"pull did not complete: {exc}")

    try:
        pulled = read_back(host, port, name, tag)
    except DaemonUnreachable as exc:
        return _failed("EVERIFY", f"pulled, but the daemon could not be read back: {exc}")
    digest = (pulled or {}).get("digest")
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        return _failed(
            "EVERIFY",
            f"the daemon reports no valid manifest digest for {name}:{tag} "
            f"after a successful pull (got {digest!r})",
        )
    size = (pulled or {}).get("size")
    nbytes = size if isinstance(size, int) and not isinstance(size, bool) else sum(streamed["layers"].values())

    # The pull is real and verified: spend the envelope now.
    cited = authority.authorize_and_cite(
        matches[0], actor=app_id, verb=VERB, call_args=call_args,
        project=project, session=session,
    )
    if not cited.get("ok"):
        return _refuse(
            cited.get("errno", "EAMBIG"), cited.get("reason", ""),
            envelope_id=matches[0], citation_id=cited.get("citation_id"),
            pulled_unrecorded=True, model=name, tag=tag, digest=digest, bytes=nbytes,
            note="the model is on disk but the envelope could not be cited — it is not a granted pull",
        )

    out = {
        "ok": True, "pulled": True, "model": name, "tag": tag, "digest": digest,
        "bytes": nbytes, "lease_id": lease_id,
        "envelope_id": matches[0], "citation_id": cited.get("citation_id"),
    }
    try:
        out["receipt_id"] = ledger.append(project, EVENT, {
            "actor": app_id, "model": name, "tag": tag, "digest": digest,
            "bytes": nbytes, "lease_id": lease_id, "session": session,
            "citation_id": cited.get("citation_id"), "envelope_id": matches[0],
        })
    except Exception as exc:  # noqa: BLE001 — the pull happened; the receipt failing is reported, not hidden
        out["receipt_error"] = f"{type(exc).__name__}: {exc}"
    return out
