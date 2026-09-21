"""willow_mcp/net_signer.py — the hand that holds the egress key.

Decision ``c8572a92``: per-task network authority is seal-driven, and the
thing that turns a seal into a ``willow-net-auth-v2`` envelope runs as the
egress key's owner (uid 994, ``willow-operator``), NOT as the seat. The seat
(uid 1000) cannot read ``private.pem`` — that is the whole point of the uid
split. What crosses the socket, per request, and NOTHING else:

    {"op": "sign_task",
     "seal":  {"source_norm", "target_text", "verifier", "seal_sig", "created_at"},
     "bound": {"task_id", "agent", "submitted_by", "scope", "ttl", "nonce"}}

The reply is one of ``{"state": "minted", "envelope": "...", "seal_digest"}``,
``{"state": "refused", "reason": "...", "field": "..."}``,
``{"state": "unreachable", "cause"}``. Any other top-level key — a task
text, a ``task_hash``, a ``pair_id`` — is refused by name, unread. The
task text the signer hashes is the one INSIDE ``target_text``, under the
rule line, because that is the text the operator sealed (Loki 7153DC79;
amending pair 6b305258). Newline-delimited JSON, one request per connection.

What the signer checks, in order, and refuses on with the field named:

1. the verifier is in the public-only ring, not compromised, and not
   revoked at all — a seal carries no signing time, so a revoked-but-honest
   key cannot be told from a revoked-and-stolen one here; both refuse;
2. the seal's ``created_at`` (Nestor's own stamp) is within ``SEAL_MAX_AGE_S``
   and not in the future;
3. ``seal_sig`` verifies over Nestor's FROZEN seal bytes
   ``json.dumps([source_norm, target_text, verifier], separators=(",", ":"),
   ensure_ascii=False).encode()`` under that verifier's ed25519 public key
   (``nestor/signing.py::_message`` — a wire contract, reproduced here
   rather than imported so the signer needs no Nestor install);
4. ``target_text`` splits as one ``willow-net-auth-v2`` bound line, the
   rule ``---``, and a body;
5. every identity field in the line equals the ``bound`` view the caller
   sent — a row that drifted from what the operator sealed is not signed;
6. the ttl is within the lease ceiling.

Only then ``sign_envelope(task_hash=sha256(body))`` — the hash is DERIVED
from the sealed body, never accepted; and ``seal_pair_id`` in the signed
payload is the sha256 of the verified seal bytes + signature, a fact this
process computed, not an id a caller supplied.

The ring it reads is a PUBLIC-ONLY export (``export-ring``) of the
operator's keyring: ed25519 entries only, public halves only. An ``hmac``
entry's ``key`` IS its secret and is never exported; a ring that carries
one is refused on load. The ring file must not be writable or replaceable
by this process (``lease.path_is_self_writable_or_replaceable``), checked
at start. The ``700`` home (gap ``8ef0e691b6c2``) is never
traversed: the key and the ring sit under ``~/.config/willow-mcp/egress``
(994-owned already) or wherever the unit points, and the socket lives in
``RuntimeDirectory``. Leases are the one place this process WRITES: on a
hardened box the lease root is 994-owned, so the signer writes the lease
file itself; if it cannot reach the root it says ``unreachable`` with the
path, and the tick receipt carries that — it does not pretend.

Install is the one unavoidable root act, printed as one line by
``install`` — and only when every file that line names has been staged;
otherwise it names what is missing instead. The unit runs as
``User=willow-operator``.
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
from datetime import datetime, timedelta, timezone
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
    """Write ``dest`` as the ed25519 PUBLIC halves of ``source`` and nothing
    else. Refuses a source that is not a keyring, and refuses to write a
    ring with no ed25519 entry at all.

    Only ``kind == "ed25519"`` entries are exported. For an ``hmac`` entry
    the ``key`` field IS the shared secret (nestor/signing.py:93-97 signs
    with it) — Loki 7153DC79: an export that merely dropped ``private``
    put that secret in a 0644 file. An HMAC verifier cannot be a
    public-ring verifier by construction; it is skipped and named in the
    result so the operator knows who cannot confirm through the signer."""
    raw = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("verifiers"), list):
        raise ValueError(f"{source}: not a keyring (no verifiers list)")
    out_verifiers, skipped = [], []
    for v in raw["verifiers"]:
        if not isinstance(v, dict) or not v.get("name") or not v.get("key"):
            continue
        if str(v.get("kind", "hmac")) != "ed25519":
            skipped.append({"name": v["name"], "kind": str(v.get("kind", "hmac"))})
            continue
        entry = {k: v[k] for k in ("name", "key", "kind", "revoked_at", "compromised",
                                   "reason", "created_at") if k in v}
        out_verifiers.append(entry)
    if not out_verifiers:
        raise ValueError(f"{source}: no ed25519 verifier to export — a public ring needs one")
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
    return {"path": str(dest), "verifiers": [v["name"] for v in out_verifiers],
            "skipped": skipped}


def load_public_ring(path: Path) -> dict[str, dict]:
    """``{name: {key: bytes, kind, revoked_at, compromised}}``. Refuses a ring
    that carries a private half or ANY non-ed25519 entry — an ``hmac``
    ``key`` is a secret, and this process must never hold one."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    ring: dict[str, dict] = {}
    for v in raw.get("verifiers", []):
        if not isinstance(v, dict):
            continue
        if v.get("private"):
            raise ValueError(f"{path}: verifier {v.get('name')!r} carries a private half — "
                             "the signer's ring must be public-only (export-ring)")
        kind = str(v.get("kind", "hmac"))
        if kind != "ed25519":
            raise ValueError(f"{path}: verifier {v.get('name')!r} is kind {kind!r}; its key is a "
                             "shared secret — not a public ring (export-ring skips these)")
        try:
            key = bytes.fromhex(str(v.get("key", "")))
        except ValueError:
            continue
        if len(key) != 32:
            continue
        ring[str(v.get("name"))] = {
            "key": key, "kind": kind,
            "revoked_at": v.get("revoked_at"), "compromised": bool(v.get("compromised")),
        }
    if raw.get("legacy_key"):
        raise ValueError(f"{path}: carries legacy_key (an HMAC secret) — not a public ring")
    return ring


def ring_is_trustworthy(path: Path) -> tuple[bool, str]:
    """The ring file, and the directory it sits in, must not be writable by
    this process — a ring the signer could rewrite is a ring an attacker
    with the signer's uid could add a verifier to. ``lease.py`` already
    owns the ancestor-walk; reuse it rather than restate it."""
    from . import lease as lease_mod

    p = Path(path)
    if not p.is_file():
        return False, f"ring {p} is not a file"
    if lease_mod.path_is_self_writable_or_replaceable(p):
        return False, f"ring {p} is writable or replaceable by uid {os.geteuid()} — refusing"
    return True, "ok"


def seal_message(source_norm: str, target_text: str, verifier: str) -> bytes:
    """Nestor's frozen seal bytes (signing.py::_message). Do not change."""
    return json.dumps([source_norm, target_text, verifier],
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def seal_digest(seal: dict) -> str:
    """The name the signer gives a seal it verified: sha256 over the exact
    bytes it checked the signature on, plus the signature. A fact this
    process derived, not a pair id a caller asserted (Loki 7153DC79)."""
    import hashlib

    return hashlib.sha256(
        seal_message(seal["source_norm"], seal["target_text"], seal["verifier"])
        + b"\n" + seal["seal_sig"].encode("ascii")).hexdigest()


def _parse_iso(value) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def verify_seal(seal: dict, ring: dict[str, dict], *, now: Optional[datetime] = None,
                max_age_s: int = na.SEAL_MAX_AGE_S) -> tuple[bool, str, str]:
    """(ok, reason, field). Only ed25519 verifiers can confirm.

    A revoked key refuses even when revoked-not-compromised (Loki
    7153DC79): Nestor keeps a rotated key honouring its own PAST seals, but
    that needs a signature-time the seal does not carry, so this signer
    cannot tell an old honest seal from one made after the rotation and
    refuses both — stated, not silent. A seal older than ``max_age_s``
    (Nestor's ``created_at``, which the sealer stamps) refuses too: a
    request nobody minted in a day is not minted a week later.
    """
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
    if entry.get("revoked_at"):
        return False, (f"verifier {seal['verifier']!r} key was revoked at {entry['revoked_at']}; "
                       "a seal carries no signing time, so it cannot be shown to predate that"), \
            "verifier"
    if entry.get("kind") != "ed25519":
        return False, f"verifier {seal['verifier']!r} is not an ed25519 verifier", "verifier"
    sealed_at = _parse_iso(seal.get("created_at"))
    if sealed_at is None:
        return False, "seal carries no timezone-aware created_at", "created_at"
    current = (now or _now())
    if (current - sealed_at).total_seconds() > max_age_s:
        return False, f"seal from {seal['created_at']} is older than {max_age_s}s", "created_at"
    if sealed_at > current + timedelta(seconds=300):
        return False, "seal is dated in the future", "created_at"
    try:
        Ed25519PublicKey.from_public_bytes(entry["key"]).verify(
            bytes.fromhex(seal["seal_sig"]),
            seal_message(seal["source_norm"], seal["target_text"], seal["verifier"]))
    except (InvalidSignature, ValueError):
        return False, "seal signature does not verify", "seal_sig"
    return True, "verified", ""


# ── the two ops ───────────────────────────────────────────────────────────────

#: Fields a request may carry. Anything else — a task text, a hash, a pair
#: id — is a caller-supplied fact the signer must not read; refused by name.
_ALLOWED_REQUEST_KEYS = frozenset({"op", "seal", "bound"})
_ALLOWED_SEAL_KEYS = frozenset({"source_norm", "target_text", "verifier", "seal_sig", "created_at"})


class Signer:
    def __init__(self, *, private_key_path: Path, ring: dict[str, dict],
                 lease_root: Optional[Path] = None):
        self.private_key_path = Path(private_key_path)
        self.ring = ring
        self.lease_root = lease_root

    def handle(self, request: dict) -> dict:
        if not isinstance(request, dict):
            return {"state": "refused", "reason": "request is not an object", "field": "request"}
        extra = sorted(set(request) - _ALLOWED_REQUEST_KEYS)
        if extra:
            return {"state": "refused", "field": extra[0],
                    "reason": f"protocol: {extra[0]} is not part of the sealed bytes and is not read"}
        seal = request.get("seal")
        if isinstance(seal, dict):
            extra = sorted(set(seal) - _ALLOWED_SEAL_KEYS)
            if extra:
                return {"state": "refused", "field": extra[0],
                        "reason": f"protocol: seal.{extra[0]} is not a seal field"}
        bound = request.get("bound")
        if isinstance(bound, dict) and any(k in bound for k in ("task_hash", "task", "pair_id")):
            return {"state": "refused", "field": "bound",
                    "reason": "protocol: bound may name identity fields only, never a hash or text"}
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
        split = na.split_sealed_text(seal["target_text"])
        if split is None:
            return {"state": "refused",
                    "reason": "sealed text is not a willow-net-auth-v2 line, a rule, and a body",
                    "field": "target_text"}
        sealed_bound, sealed_body = split
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
        # The ONE place the hash is computed: from the body inside the bytes
        # whose signature just verified. Nothing a caller sent reaches it.
        derived_hash = ea.normalized_task_hash(sealed_body)
        try:
            envelope = ea.sign_envelope(
                private_key_path=self.private_key_path,
                submitted_by=sealed_bound["submitted_by"],
                task_id=sealed_bound["task_id"],
                agent=sealed_bound["agent"],
                task_hash=derived_hash,
                ttl_seconds=ttl,
                nonce=sealed_bound["nonce"],
                scope=sealed_bound["scope"],
                seal_pair_id=seal_digest(seal),
            )
        except (OSError, ValueError, PermissionError) as exc:
            return {"state": "unreachable", "cause": f"signing failed: {type(exc).__name__}: {exc}"}
        return {"state": "minted", "envelope": envelope, "verifier": seal["verifier"],
                "task_id": sealed_bound["task_id"], "seal_digest": seal_digest(seal)}

    def sign_lease(self, request: dict) -> dict:
        from . import lease as lease_mod

        seal = request.get("seal") or {}
        ok, reason, field = verify_seal(seal, self.ring)
        if not ok:
            return {"state": "refused", "reason": reason, "field": field}
        split = na.split_sealed_lease_text(seal["target_text"])
        if split is None:
            return {"state": "refused", "reason": "sealed text is not a lease line, a rule, and a reason",
                    "field": "target_text"}
        sealed_bound, reason_text = split
        view = request.get("bound") or {}
        for key in na.LEASE_BOUND_FIELDS:
            if str(view.get(key)) != sealed_bound[key]:
                return {"state": "refused",
                        "reason": f"{key} differs between the sealed line and the request",
                        "field": key}
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
    under /etc and a file placed in the 994-owned key directory. Every path
    it names must exist before it is printed — :func:`stage_install` refuses
    to print it otherwise (gap 6031199ac4e1: the first live install printed
    a line naming a ring it had not staged, and the operator's ``sudo`` chain
    failed halfway on ``install: No such file or directory``)."""
    for must_exist in (rendered_path, ring_source):
        if not Path(must_exist).is_file():
            raise FileNotFoundError(f"install line would name a file that does not exist: {must_exist}")
    return (
        f"sudo install -m 644 {rendered_path} /etc/systemd/system/{UNIT} && "
        f"sudo install -o willow-operator -g willow-operator -m 644 {ring_source} {ring_dest} && "
        f"sudo systemctl daemon-reload && sudo systemctl enable --now {UNIT}"
    )


def default_stage_dir() -> Path:
    """Where ``install`` renders to: under the willow home, never the
    caller's cwd. The first live install wrote its unit and ring beside
    whatever the operator happened to be standing in — the Grove's tracked
    tree — which is two stray files in the active checkout and a ring that
    ``git status`` shows to every reader."""
    from . import paths

    return paths.willow_home() / "deploy" / "net-signer"


def stage_install(*, stage_dir: Optional[Path] = None, group: Optional[str] = None,
                  keyring: Optional[Path] = None, python: Optional[Path] = None) -> dict:
    """Render the unit and stage the public ring, then say EXACTLY what the
    operator can run. Three states, never a half-truth:

    * ``ready`` — unit and ring both staged; ``run_this_once_as_root`` is the
      one line, and every path in it exists.
    * ``ring_missing`` — no keyring to export from: ``WILLOW_KEYRING`` was
      unset in this shell (or ``keyring`` absent). The unit is still staged,
      but NO root line is printed: ``missing`` names the env var and the
      command to run instead. A line that names a file this call did not
      make is the failure this function replaces.
    * ``error`` — the export itself refused (not a keyring, no ed25519
      entry): ``error`` carries the reason, still no root line.
    """
    import grp
    import pwd

    from . import egress_setup, paths

    if not group:
        group = grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name
    ring = default_ring_path()
    key = default_key_path()
    rendered = render_unit(python=python or Path(sys.executable), key=key, ring=ring,
                           user="willow-operator", group=group,
                           willow_home=paths.willow_home(),
                           apps_root=Path(os.environ.get("WILLOW_MCP_APPS_ROOT",
                                                         paths.willow_home() / "mcp_apps")))
    stage = Path(stage_dir) if stage_dir is not None else default_stage_dir()
    stage.mkdir(parents=True, exist_ok=True)
    unit_path = stage / UNIT
    unit_path.write_text(rendered, encoding="utf-8")
    staged_ring = stage / "verifiers.public.json"
    out: dict = {"unit": str(unit_path), "key": str(key), "ring_dest": str(ring),
                 "egress_dir": str(egress_setup.config_dir()), "stage_dir": str(stage)}

    source = keyring if keyring is not None else Path(os.environ.get("WILLOW_KEYRING", "")).expanduser()
    if not str(source) or not source.is_file():
        out.update(state="ring_missing", ring_staged=None, run_this_once_as_root=None,
                   missing={"env": "WILLOW_KEYRING",
                            "detail": "no keyring to export the public ring from in this shell",
                            "run_instead": (f"WILLOW_KEYRING=<path to config/verifiers.json> "
                                            f"{python or sys.executable} -m willow_mcp.net_signer install")})
        return out
    try:
        export_public_ring(source, staged_ring)
    except (ValueError, OSError) as exc:
        out.update(state="error", ring_staged=None, run_this_once_as_root=None,
                   error=f"{type(exc).__name__}: {exc}")
        return out
    out.update(state="ready", ring_staged=str(staged_ring),
               run_this_once_as_root=install_lines(rendered_path=unit_path, ring_source=staged_ring,
                                                   ring_dest=ring))
    return out


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
    i = sub.add_parser("install", help="render the system unit, stage the public ring, "
                                       "and print the one root line — or say what is missing")
    i.add_argument("--stage-dir", default=None,
                   help="where to stage the unit and ring (default: $WILLOW_HOME/deploy/net-signer)")
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
        out = stage_install(stage_dir=Path(args.stage_dir) if args.stage_dir else None,
                            group=args.group)
        print(json.dumps(out, indent=2))
        # A root line was printed only in the ready state; anything else is
        # the operator's next move, not a success.
        return 0 if out["state"] == "ready" else 2

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
    trusted, why = ring_is_trustworthy(ring_path)
    if not trusted:
        print(f"net_signer: {why}", file=sys.stderr)
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
