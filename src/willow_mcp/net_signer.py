"""willow_mcp/net_signer.py — the hand that holds the egress key.

Decision ``c8572a92``: per-task network authority is seal-driven, and the
thing that turns a seal into a ``willow-net-auth-v2`` envelope runs as the
egress key's owner (uid 994, ``willow-operator``), NOT as the seat. The seat
(uid 1000) cannot read ``private.pem`` — that is the whole point of the uid
split — and this process cannot read the seat's task text, because it is
never sent. What crosses the socket, per request:

    {"op": "sign_task",
     "seal":  {"source_norm", "target_text", "verifier", "seal_sig"},
     "bound": {"task_id", "agent", "submitted_by", "task_hash", "scope", "ttl", "nonce"},
     "pair_id": "..."}

and the reply is one of ``{"state": "minted", "envelope": "..."}``,
``{"state": "refused", "reason": "...", "field": "..."}``. A request that
carries ``task`` or ``task_text`` is refused unread. Newline-delimited JSON,
one request per connection.

What the signer checks, in order, and refuses on with the field named:

1. the verifier is in the public-only ring and not revoked;
2. ``seal_sig`` verifies over Nestor's FROZEN seal bytes
   ``json.dumps([source_norm, target_text, verifier], separators=(",", ":"),
   ensure_ascii=False).encode()`` under that verifier's ed25519 public key
   (``nestor/signing.py::_message`` — a wire contract, reproduced here
   rather than imported so the signer needs no Nestor install);
3. ``target_text`` parses as exactly one ``willow-net-auth-v2`` bound line;
4. every parsed field equals the ``bound`` view the caller sent — the caller
   is the seat's side of the queue, and a row that drifted from what the
   operator sealed is not signed;
5. the ttl is within the lease ceiling.

Only then ``sign_envelope(task_hash=...)`` — the signer binds the hash the
operator sealed, never a text.

The ring it reads is a PUBLIC-ONLY export (``export-ring``) of the
operator's keyring: same JSON shape, ``private`` halves dropped, so it may
live world-readable beside the key and gives this process nothing to sign
Nestor seals with. The ``700`` home (gap ``8ef0e691b6c2``) is never
traversed: the key and the ring sit under ``~/.config/willow-mcp/egress``
(994-owned already) or wherever the unit points, and the socket lives in
``RuntimeDirectory``. Leases are the one place this process WRITES: on a
hardened box the lease root is 994-owned, so the signer writes the lease
file itself; if it cannot reach the root it says ``unreachable`` with the
path, and the tick receipt carries that — it does not pretend.

Install is the one unavoidable root act, printed as one line by
``install --print``; the unit runs as ``User=willow-operator``.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socketserver
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import egress_authorization as ea
from . import net_authority as na

logger = logging.getLogger(__name__)

RING_ENV = "WILLOW_NET_SIGNER_RING"
KEY_ENV = "WILLOW_NET_SIGNER_KEY"
UNIT = "willow-mcp-net-signer.service"
_TEMPLATE = "willow-mcp-net-signer.service.template"
_MAX_REQUEST = 64 * 1024


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── the ring, public halves only ──────────────────────────────────────────────

def export_public_ring(source: Path, dest: Path) -> dict:
    """Write ``dest`` as ``source`` minus every ``private`` half. Refuses a
    source that is not a keyring. The result holds no secret and may be
    world-readable; ``willow_mcp.keyring.load`` accepts it (its mode rule
    follows the material, not the filename)."""
    raw = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("verifiers"), list):
        raise ValueError(f"{source}: not a keyring (no verifiers list)")
    out_verifiers = []
    for v in raw["verifiers"]:
        if not isinstance(v, dict) or not v.get("name") or not v.get("key"):
            continue
        entry = {k: v[k] for k in v if k != "private"}
        out_verifiers.append(entry)
    out = {"version": raw.get("version", 1), "verifiers": out_verifiers,
           "exported_at": _now().isoformat(), "public_only": True}
    # Deliberately no legacy_key: it is an HMAC secret, and a public ring
    # must hold nothing that can sign.
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(out, indent=2), encoding="utf-8")
    os.replace(tmp, dest)
    os.chmod(dest, 0o644)
    return {"path": str(dest), "verifiers": [v["name"] for v in out_verifiers]}


def load_public_ring(path: Path) -> dict[str, dict]:
    """``{name: {key: bytes, kind, revoked_at, compromised}}``. Refuses a ring
    that carries a private half — this process must never hold one."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    ring: dict[str, dict] = {}
    for v in raw.get("verifiers", []):
        if not isinstance(v, dict):
            continue
        if v.get("private"):
            raise ValueError(f"{path}: verifier {v.get('name')!r} carries a private half — "
                             "the signer's ring must be public-only (export-ring)")
        try:
            key = bytes.fromhex(str(v.get("key", "")))
        except ValueError:
            continue
        ring[str(v.get("name"))] = {
            "key": key, "kind": str(v.get("kind", "hmac")),
            "revoked_at": v.get("revoked_at"), "compromised": bool(v.get("compromised")),
        }
    if raw.get("legacy_key"):
        raise ValueError(f"{path}: carries legacy_key (an HMAC secret) — not a public ring")
    return ring


def seal_message(source_norm: str, target_text: str, verifier: str) -> bytes:
    """Nestor's frozen seal bytes (signing.py::_message). Do not change."""
    return json.dumps([source_norm, target_text, verifier],
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_seal(seal: dict, ring: dict[str, dict]) -> tuple[bool, str, str]:
    """(ok, reason, field). Only ed25519 verifiers can confirm — an HMAC
    entry's key is a shared secret this process must not be trusted with,
    and a public ring never carries one that can verify anyway."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    for k in ("source_norm", "target_text", "verifier", "seal_sig"):
        if not isinstance(seal.get(k), str) or not seal.get(k):
            return False, f"seal missing {k}", k
    entry = ring.get(seal["verifier"])
    if entry is None:
        return False, f"verifier {seal['verifier']!r} is not in the ring", "verifier"
    if entry.get("compromised"):
        return False, f"verifier {seal['verifier']!r} key is marked compromised", "verifier"
    if entry.get("kind") != "ed25519":
        return False, f"verifier {seal['verifier']!r} is not an ed25519 verifier", "verifier"
    try:
        Ed25519PublicKey.from_public_bytes(entry["key"]).verify(
            bytes.fromhex(seal["seal_sig"]),
            seal_message(seal["source_norm"], seal["target_text"], seal["verifier"]))
    except (InvalidSignature, ValueError):
        return False, "seal signature does not verify", "seal_sig"
    return True, "verified", ""


# ── the two ops ───────────────────────────────────────────────────────────────

class Signer:
    def __init__(self, *, private_key_path: Path, ring: dict[str, dict],
                 lease_root: Optional[Path] = None):
        self.private_key_path = Path(private_key_path)
        self.ring = ring
        self.lease_root = lease_root

    def handle(self, request: dict) -> dict:
        if not isinstance(request, dict):
            return {"state": "refused", "reason": "request is not an object", "field": "request"}
        if "task" in request or "task_text" in request:
            return {"state": "refused",
                    "reason": "protocol: the task text must never reach the signer", "field": "task"}
        op = request.get("op")
        if op == "sign_task":
            return self.sign_task(request)
        if op == "sign_lease":
            return self.sign_lease(request)
        return {"state": "refused", "reason": f"unknown op {op!r}", "field": "op"}

    def sign_task(self, request: dict) -> dict:
        seal = request.get("seal") or {}
        ok, reason, field = verify_seal(seal, self.ring)
        if not ok:
            return {"state": "refused", "reason": reason, "field": field}
        sealed_bound = na.parse_bound_line(seal["target_text"])
        if sealed_bound is None:
            return {"state": "refused",
                    "reason": "sealed text is not one willow-net-auth-v2 bound line",
                    "field": "target_text"}
        view = request.get("bound") or {}
        for key in na.BOUND_FIELDS:
            if str(view.get(key)) != sealed_bound[key]:
                return {"state": "refused",
                        "reason": f"{key} differs between the sealed line and the row",
                        "field": key}
        ttl = int(sealed_bound["ttl"])
        from . import lease as lease_mod

        if ttl <= 0 or ttl > lease_mod.MAX_TTL_SECONDS:
            return {"state": "refused", "reason": f"ttl {ttl} outside 1..{lease_mod.MAX_TTL_SECONDS}",
                    "field": "ttl"}
        try:
            envelope = ea.sign_envelope(
                private_key_path=self.private_key_path,
                submitted_by=sealed_bound["submitted_by"],
                task_id=sealed_bound["task_id"],
                agent=sealed_bound["agent"],
                task_hash=sealed_bound["task_hash"],
                ttl_seconds=ttl,
                nonce=sealed_bound["nonce"],
                scope=sealed_bound["scope"],
                seal_pair_id=str(request.get("pair_id") or ""),
            )
        except (OSError, ValueError, PermissionError) as exc:
            return {"state": "unreachable", "cause": f"signing failed: {type(exc).__name__}: {exc}"}
        return {"state": "minted", "envelope": envelope, "verifier": seal["verifier"],
                "task_id": sealed_bound["task_id"]}

    def sign_lease(self, request: dict) -> dict:
        import hashlib

        from . import lease as lease_mod

        seal = request.get("seal") or {}
        ok, reason, field = verify_seal(seal, self.ring)
        if not ok:
            return {"state": "refused", "reason": reason, "field": field}
        sealed_bound = na.parse_lease_bound_line(seal["target_text"])
        if sealed_bound is None:
            return {"state": "refused", "reason": "sealed text is not one lease bound line",
                    "field": "target_text"}
        view = request.get("bound") or {}
        for key in na.LEASE_BOUND_FIELDS:
            if str(view.get(key)) != sealed_bound[key]:
                return {"state": "refused",
                        "reason": f"{key} differs between the sealed line and the request",
                        "field": key}
        reason_text = request.get("reason") or ""
        if hashlib.sha256(reason_text.encode("utf-8")).hexdigest()[:16] != sealed_bound["reason_sha"]:
            return {"state": "refused", "reason": "reason text does not match the sealed reason sha",
                    "field": "reason"}
        ttl = int(sealed_bound["ttl"])
        if ttl <= 0 or ttl > lease_mod.MAX_TTL_SECONDS:
            return {"state": "refused", "reason": f"ttl {ttl} outside 1..{lease_mod.MAX_TTL_SECONDS}",
                    "field": "ttl"}
        if self.lease_root is not None:
            os.environ["WILLOW_MCP_APPS_ROOT"] = str(self.lease_root)
        try:
            record = lease_mod.grant(sealed_bound["app_id"], ttl,
                                     issuer=f"seal:{seal['verifier']}",
                                     reason=reason_text)
        except (OSError, ValueError) as exc:
            return {"state": "unreachable",
                    "cause": f"lease root unreachable from the signer: {type(exc).__name__}: {exc}",
                    "path": str(lease_mod._leases_root())}
        return {"state": "minted", "path": str(lease_mod.lease_path(sealed_bound["app_id"])),
                "expires_at": record["expires_at"], "verifier": seal["verifier"]}


# ── the socket ────────────────────────────────────────────────────────────────

def serve(signer: Signer, sock_path: Path, *, mode: int = 0o660,
          ready=None, stop=None) -> None:
    """Serve until ``stop`` (a threading.Event) is set. ``ready`` (an Event)
    is set once the socket is bound — tests wait on it."""
    sock_path = Path(sock_path)
    if sock_path.exists():
        sock_path.unlink()
    sock_path.parent.mkdir(parents=True, exist_ok=True)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline(_MAX_REQUEST)
            try:
                request = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                reply = {"state": "refused", "reason": "malformed request", "field": "request"}
            else:
                try:
                    reply = signer.handle(request)
                except Exception as exc:  # noqa: BLE001 — one bad request must not kill the signer
                    logger.error("net_signer: request failed", exc_info=True)
                    reply = {"state": "unreachable", "cause": f"{type(exc).__name__}: {exc}"}
            self.wfile.write((json.dumps(reply, separators=(",", ":")) + "\n").encode("utf-8"))

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    with Server(str(sock_path), Handler) as server:
        os.chmod(sock_path, mode)
        server.timeout = 0.5
        if ready is not None:
            ready.set()
        while stop is None or not stop.is_set():
            server.handle_request()


def default_ring_path() -> Path:
    from . import egress_setup

    raw = os.environ.get(RING_ENV, "").strip()
    if raw:
        return Path(raw).expanduser()
    return egress_setup.config_dir() / "verifiers.public.json"


def default_key_path() -> Path:
    from . import egress_setup

    raw = os.environ.get(KEY_ENV, "").strip()
    if raw:
        return Path(raw).expanduser()
    resolved = egress_setup.resolve_private_key_path()
    return Path(resolved) if resolved is not None else egress_setup.default_private_key_path()


# ── the unit ──────────────────────────────────────────────────────────────────

def _template() -> Path:
    return Path(__file__).resolve().parent / "bundle" / "deploy" / _TEMPLATE


def render_unit(*, python: Path, key: Path, ring: Path, user: str, group: str,
                willow_home: Path, apps_root: Path) -> str:
    values = {"PYTHON": python, "KEY": key, "RING": ring, "USER": user, "GROUP": group,
              "WILLOW_HOME": willow_home, "APPS_ROOT": apps_root,
              "SOCKET": na.DEFAULT_SOCKET}
    text = _template().read_text(encoding="utf-8")
    for k, v in values.items():
        s = str(v)
        if any(ch in s for ch in ("\n", "\r", '"')):
            raise ValueError(f"{k} contains characters unsafe for a systemd unit")
        text = text.replace(f"@{k}@", s)
    if "@" in text:
        raise ValueError("unit template contains unresolved placeholders")
    return text


def install_lines(*, rendered_path: Path, ring_source: Path, ring_dest: Path) -> str:
    """The ONE operator line. Root is unavoidable exactly here: a system unit
    under /etc and a file placed in the 994-owned key directory."""
    return (
        f"sudo install -m 644 {rendered_path} /etc/systemd/system/{UNIT} && "
        f"sudo install -o willow-operator -g willow-operator -m 644 {ring_source} {ring_dest} && "
        f"sudo systemctl daemon-reload && sudo systemctl enable --now {UNIT}"
    )


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(prog="willow-mcp-net-signer",
                                     description="Turn an operator's seal into a task envelope "
                                                 "(decision c8572a92); runs as the egress key owner.")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--socket", default=None)
    s.add_argument("--key", default=None)
    s.add_argument("--ring", default=None)
    s.add_argument("--lease-root", default=None)
    e = sub.add_parser("export-ring", help="write the public-only ring the signer verifies with")
    e.add_argument("--source", default=os.environ.get("WILLOW_KEYRING", ""))
    e.add_argument("--out", default=None)
    i = sub.add_parser("install", help="render the system unit and print the one root line")
    i.add_argument("--out", default=None, help="where to write the rendered unit (default: cwd)")
    i.add_argument("--group", default=None, help="the operator's group (socket access)")
    args = parser.parse_args(argv)

    if args.command == "export-ring":
        if not args.source:
            print("export-ring: --source or WILLOW_KEYRING is required", file=sys.stderr)
            return 2
        out = Path(args.out) if args.out else default_ring_path()
        print(json.dumps(export_public_ring(Path(args.source), out), indent=2))
        return 0

    if args.command == "install":
        import grp
        import pwd

        from . import egress_setup, paths

        group = args.group
        if not group:
            group = grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name
        ring = default_ring_path()
        key = default_key_path()
        rendered = render_unit(python=Path(sys.executable), key=key, ring=ring,
                               user="willow-operator", group=group,
                               willow_home=paths.willow_home(),
                               apps_root=Path(os.environ.get("WILLOW_MCP_APPS_ROOT",
                                                             paths.willow_home() / "mcp_apps")))
        out = Path(args.out) if args.out else Path.cwd() / UNIT
        out.write_text(rendered, encoding="utf-8")
        ring_source = Path(os.environ.get("WILLOW_KEYRING", "")).expanduser()
        staged = out.with_name("verifiers.public.json")
        if ring_source.is_file():
            export_public_ring(ring_source, staged)
        print(json.dumps({
            "unit": str(out), "ring_staged": str(staged) if staged.exists() else None,
            "key": str(key), "egress_dir": str(egress_setup.config_dir()),
            "run_this_once_as_root": install_lines(rendered_path=out, ring_source=staged,
                                                   ring_dest=ring),
        }, indent=2))
        return 0

    # serve
    import threading

    key = Path(args.key) if args.key else default_key_path()
    ring_path = Path(args.ring) if args.ring else default_ring_path()
    try:
        mode = stat.S_IMODE(key.stat().st_mode)
    except OSError as exc:
        print(f"net_signer: cannot read key metadata at {key}: {exc}", file=sys.stderr)
        return 2
    if mode & 0o077:
        print(f"net_signer: key {key} is group/world accessible — refusing", file=sys.stderr)
        return 2
    ring = load_public_ring(ring_path)
    signer = Signer(private_key_path=key, ring=ring,
                    lease_root=Path(args.lease_root) if args.lease_root else None)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    sock_path = Path(args.socket) if args.socket else na.socket_path()
    print(f"net_signer: serving {sock_path} for verifiers {sorted(ring)}", flush=True)
    serve(signer, sock_path, stop=stop)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
