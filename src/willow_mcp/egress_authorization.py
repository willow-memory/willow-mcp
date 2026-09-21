"""Operator-signed, per-task network authorization.

The ``# allow_net`` directive is only a request.  Kartikeya calls
``ExecutorNetworkAuthorizer`` immediately before shell execution; this module
then re-checks the host policy, verifies a signed envelope bound to the
submitter, unique queue task id, agent, and exact normalized task text, and
confirms the adopted Postgres row has not already consumed net authority.
Replay markers are deliberately unnecessary: the signed task id is the queue
primary key, so the authority cannot be attached to a second row; single-use
per row is enforced by terminal status, ``completed_at``, and an atomic
result-json marker written only on allow.

Signing is intentionally not an MCP surface.  ``sign_envelope`` is used only by
the local ``willow-mcp sign-net-task`` command and reads a private key path that
the worker neither needs nor receives.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import consent, gate, lease

# Reserved result-json marker: set atomically by the execution authorizer when
# net authority is consumed for a row. Workers may write `result`, but the
# authorizer only flips this key via a conditional UPDATE on `status=running`,
# so a reclaimed row cannot replay the same envelope. Cleared when mark_done
# stores a fresh terminal result (retry path overwrites result).
_NET_AUTHORITY_CONSUMED_KEY = "_net_authority_consumed"
_TERMINAL_STATUSES = frozenset({"completed", "failed"})
_ROW_GATE_FIELDS = ("task_id", "status", "completed_at", "result")

ENVELOPE_FORMAT = "willow-net-auth-v2"
NETWORK_SCOPE = "network"
# The same signed-envelope machinery authorizes local Postgres access (B2). The
# scope is bound into the signed payload and re-checked on verify, so a network
# envelope can never authorize a `# allow_db` task or vice versa — the two are
# cryptographically distinct even though they share a format and a signing key.
DB_SCOPE = "database"
_VALID_SCOPES = frozenset({NETWORK_SCOPE, DB_SCOPE})
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_TASK_ID_RE = re.compile(r"^[A-Z0-9]{8}$")
_AGENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_KART_TASK_DIRECTIVES = {"# allow_net", "# allow_localhost", "# allow_db"}
_NET_DIRECTIVES = {"# allow_net", "# allow_localhost"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_task(task: str) -> str:
    """Normalize transport newlines only; every other byte remains significant."""
    return (task or "").replace("\r\n", "\n").replace("\r", "\n")


def canonical_network_task(task: str, *, localhost: bool = False) -> str:
    """Produce the exact task representation stored by ``task_submit``."""
    clean = "\n".join(
        line
        for line in normalize_task(task).splitlines()
        if line.strip() not in _KART_TASK_DIRECTIVES
    )
    directive = "# allow_localhost" if localhost else "# allow_net"
    return clean.rstrip("\n") + f"\n{directive}"


def canonical_db_task(task: str) -> str:
    """Produce task text with a single gated ``# allow_db`` directive."""
    clean = "\n".join(
        line
        for line in normalize_task(task).splitlines()
        if line.strip() not in _KART_TASK_DIRECTIVES
    )
    return clean.rstrip("\n") + "\n# allow_db"


def normalized_task_hash(task: str) -> str:
    return hashlib.sha256(normalize_task(task).encode("utf-8")).hexdigest()


def _canonical_payload(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def claimed_task_id(envelope: str) -> str:
    """Return the syntactically valid claimed task id; verification is separate."""
    try:
        value = json.loads(envelope).get("payload", {}).get("task_id", "")
    except (AttributeError, TypeError, json.JSONDecodeError):
        return ""
    return value if isinstance(value, str) and _TASK_ID_RE.fullmatch(value) else ""


def seal_pair_id_of(envelope: str) -> str:
    """The ``seal_pair_id`` an envelope CLAIMS was its confirm, or ``""``.

    A claim, not a fact — the field is inside the signed payload, so it is
    only meaningful once ``verify_envelope`` has passed on the same string.
    Callers use it to decide whether to look for a standing lease; they never
    grant on it alone.
    """
    try:
        value = json.loads(envelope).get("payload", {}).get("seal_pair_id", "")
    except (AttributeError, TypeError, json.JSONDecodeError):
        return ""
    return value if isinstance(value, str) else ""


def _parse_deadline(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    raw = Path(path).expanduser().read_bytes()
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("egress signing key must be an Ed25519 private key")
    return key


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    raw = Path(path).expanduser().read_bytes()
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("egress verification key must be an Ed25519 public key")
    return key


def sign_envelope(
    *,
    private_key_path: str | Path,
    submitted_by: str,
    task_id: str,
    agent: str,
    task: str | None = None,
    ttl_seconds: int,
    nonce: str,
    scope: str = NETWORK_SCOPE,
    now: datetime | None = None,
    task_hash: str | None = None,
    seal_pair_id: str = "",
) -> str:
    """Create a signed envelope. This function is never registered as an MCP tool.

    ``task`` is hashed here (the operator's terminal path, ``sign-net-task``).
    ``task_hash`` is the seal-driven path (decision ``c8572a92`` as amended
    by ``6b305258``): the signer that holds the key DERIVES the hash from the
    task text inside the sealed bytes the operator signed — never from a
    hash a caller handed it — and passes what it derived here. Exactly one
    of the two must be given. ``seal_pair_id`` is the signer's digest of the
    verified seal bytes and rides INSIDE the signed payload, so an executor
    can tell a seal-minted envelope from a terminal-minted one without
    trusting anything unsigned.
    """
    if os.environ.get("WILLOW_IN_KART", "").strip():
        raise PermissionError("network authorization cannot be signed inside Kart")
    if not submitted_by.strip():
        raise ValueError("submitted_by is required")
    if (task is None) == (task_hash is None):
        raise ValueError("exactly one of task or task_hash is required")
    if task_hash is not None and not re.fullmatch(r"[0-9a-f]{64}", task_hash):
        raise ValueError("task_hash must be a 64-hex sha256")
    if not _TASK_ID_RE.fullmatch(task_id or ""):
        raise ValueError("task_id must be exactly 8 uppercase letters or digits")
    if not _AGENT_RE.fullmatch(agent or ""):
        raise ValueError("agent must be 1..64 identifier characters")
    if scope not in _VALID_SCOPES:
        raise ValueError(f"unsupported authorization scope {scope!r}")
    if (
        not isinstance(ttl_seconds, int)
        or isinstance(ttl_seconds, bool)
        or ttl_seconds <= 0
        or ttl_seconds > lease.MAX_TTL_SECONDS
    ):
        raise ValueError(
            f"ttl_seconds must be within 1..{lease.MAX_TTL_SECONDS}"
        )
    if not _NONCE_RE.fullmatch(nonce or ""):
        raise ValueError("nonce must be 22..128 URL-safe characters")
    issued = (now or _now()).astimezone(timezone.utc)
    payload = {
        "format": ENVELOPE_FORMAT,
        "submitted_by": submitted_by,
        "task_id": task_id,
        "agent": agent,
        "task_hash": task_hash if task_hash is not None else normalized_task_hash(task or ""),
        "scope": scope,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(seconds=ttl_seconds)).isoformat(),
        "nonce": nonce,
    }
    if seal_pair_id:
        payload["seal_pair_id"] = seal_pair_id
    signature = _load_private_key(private_key_path).sign(
        _canonical_payload(payload)
    )
    return json.dumps(
        {
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def verify_envelope(
    *,
    public_key_path: str | Path,
    submitted_by: str,
    task_id: str,
    agent: str,
    task: str,
    envelope: str,
    expected_scope: str = NETWORK_SCOPE,
    now: datetime | None = None,
) -> tuple[bool, str, dict | None]:
    """Verify signature and all task-bound claims without consuming the nonce.

    ``expected_scope`` binds the check to one authority domain: a caller
    verifying a DB task passes ``DB_SCOPE`` and a network envelope (scope
    ``network``) is refused with "scope mismatch", and vice versa."""
    try:
        parsed = json.loads(envelope)
    except (TypeError, json.JSONDecodeError):
        return False, "malformed envelope", None
    if not isinstance(parsed, dict):
        return False, "malformed envelope", None
    payload, encoded_sig = parsed.get("payload"), parsed.get("signature")
    if not isinstance(payload, dict) or not isinstance(encoded_sig, str):
        return False, "malformed envelope", None
    if payload.get("format") != ENVELOPE_FORMAT:
        return False, "unsupported envelope format", payload
    if payload.get("submitted_by") != submitted_by:
        return False, "submitted_by mismatch", payload
    if payload.get("task_id") != task_id:
        return False, "task_id mismatch", payload
    if payload.get("agent") != agent:
        return False, "agent mismatch", payload
    if payload.get("scope") != expected_scope:
        return False, "scope mismatch", payload
    if payload.get("task_hash") != normalized_task_hash(task):
        return False, "task hash mismatch", payload
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        return False, "malformed nonce", payload
    issued = _parse_deadline(payload.get("issued_at"))
    expires = _parse_deadline(payload.get("expires_at"))
    if issued is None or expires is None:
        return False, "malformed authorization time", payload
    current = (now or _now()).astimezone(timezone.utc)
    if issued > current + timedelta(seconds=30):
        return False, "authorization issued in the future", payload
    if expires <= current:
        return False, "authorization expired", payload
    ttl = (expires - issued).total_seconds()
    if ttl <= 0 or ttl > lease.MAX_TTL_SECONDS:
        return False, "authorization lifetime exceeds policy", payload
    try:
        signature = base64.b64decode(encoded_sig, validate=True)
        public_key = _load_public_key(public_key_path)
        public_key.verify(signature, _canonical_payload(payload))
    except (OSError, TypeError, ValueError, binascii.Error, InvalidSignature):
        return False, "invalid signature", payload
    return True, "verified", payload


def public_key_path() -> Path | None:
    from . import egress_setup

    return egress_setup.resolve_public_key_path()


def _task_table_columns():
    """Resolve adopted `tasks` column names once; None when Postgres is absent."""
    from .db import get_pg
    from . import schema_profile as sp

    pg = get_pg()
    if pg is None:
        return None
    app_id = os.environ.get("WILLOW_APP_ID", "willow").strip() or "willow"
    mapping = sp.resolve(pg, app_id, "tasks", list(_ROW_GATE_FIELDS))
    if "error" in mapping or not mapping.get("confirmed"):
        return None
    fields = mapping["fields"]
    cols = {name: fields[name]["column"] for name in _ROW_GATE_FIELDS}
    if not cols.get("task_id") or not cols.get("status"):
        return None
    return cols


def _result_json_has_net_consumed(result) -> bool:
    if result is None:
        return False
    if isinstance(result, dict):
        return bool(result.get(_NET_AUTHORITY_CONSUMED_KEY))
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except (TypeError, json.JSONDecodeError):
            return False
        return isinstance(parsed, dict) and bool(parsed.get(_NET_AUTHORITY_CONSUMED_KEY))
    return False


def _row_blocks_net_authorization(task_id: str) -> str | None:
    """Return a denial reason when Postgres says this row may not consume net."""
    cols = _task_table_columns()
    if cols is None:
        return "queue state unavailable"
    from .db import get_pg

    pg = get_pg()
    if pg is None:
        return "queue state unavailable"
    present = [name for name in _ROW_GATE_FIELDS if cols.get(name)]
    if "task_id" not in present or "status" not in present:
        return "queue state unavailable"
    select = ", ".join(f'"{cols[name]}"' for name in present)
    cur = pg.cursor()
    cur.execute(
        f'SELECT {select} FROM tasks WHERE "{cols["task_id"]}" = %s',  # nosec B608 - select/cols come from _task_table_columns()'s confirmed schema_profile mapping, not request input; task_id is a bound param
        (task_id,),
    )
    row = cur.fetchone()
    cur.close()
    if row is None:
        return "task row not found"
    values = dict(zip(present, row))
    status = (values.get("status") or "").strip().lower()
    if status in _TERMINAL_STATUSES:
        return "task row is terminal"
    if "completed_at" in values and values.get("completed_at") is not None:
        return "task row already completed"
    if "result" in values and _result_json_has_net_consumed(values.get("result")):
        return "network authorization already consumed for row"
    return None


def _consume_row_net_authorization(task_id: str) -> bool:
    """Atomically mark net authority consumed for a running row."""
    cols = _task_table_columns()
    from .db import get_pg

    pg = get_pg()
    if cols is None or pg is None:
        return False
    result_col = cols.get("result")
    status_col = cols.get("status")
    id_col = cols.get("task_id")
    if not result_col or not status_col or not id_col:
        return False
    completed_guard = ""
    if cols.get("completed_at"):
        completed_guard = f'AND "{cols["completed_at"]}" IS NULL '
    cur = pg.cursor()
    cur.execute(
        f'UPDATE tasks SET "{result_col}" = jsonb_set('  # nosec B608 - result_col/status_col/id_col come from _task_table_columns()'s confirmed schema_profile mapping, not request input; task_id is a bound param
        f"COALESCE(\"{result_col}\", '{{}}'::jsonb), "
        f"'{{{_NET_AUTHORITY_CONSUMED_KEY}}}', 'true'::jsonb, true) "
        f'WHERE "{id_col}" = %s '
        f'AND "{status_col}" = \'running\' '
        f"{completed_guard}"
        f"AND NOT COALESCE(\"{result_col}\", '{{}}'::jsonb) "
        f"? %s "
        f'RETURNING "{id_col}"',
        (task_id, _NET_AUTHORITY_CONSUMED_KEY),
    )
    claimed = cur.fetchone() is not None
    cur.close()
    pg.commit()
    return claimed


class ExecutorNetworkAuthorizer:
    """Concrete execution-time policy passed into Kartikeya's host seam.

    Trust boundary: cryptographic envelope checks prove the operator signed
    this exact row's work, but they do not prove the row has never executed
    before. The queue's adopted Postgres row is authoritative for that:
    terminal status, ``completed_at``, and a conditional result-json marker
    are read and updated via ``get_pg()`` — not from the in-memory
    ``TaskRow``, which the worker could otherwise misrepresent.
    """

    def __init__(self) -> None:
        self.last_error = ""

    def _deny(self, reason: str) -> bool:
        self.last_error = reason
        return False

    def __call__(self, row, envelope: str) -> bool:
        submitted_by = (row.submitted_by or "").strip()
        if not submitted_by:
            return self._deny("submitted_by missing")
        if not gate.permitted(submitted_by, gate.NET_PERMISSION):
            return self._deny("task_net capability denied")
        if not consent.internet_permitted():
            return self._deny("internet consent denied")
        # Decision c8572a92: a sealed per-task pair satisfies the lease FOR
        # THAT TASK. The claim rides inside the signed payload
        # (``seal_pair_id``), so it is only honoured after the signature
        # verifies below — an unsigned claim of a seal is worth nothing. A
        # standing lease still satisfies exactly as before.
        if not lease.active(submitted_by) and not seal_pair_id_of(envelope):
            return self._deny("egress lease denied")
        if not lease.strict_trust_root():
            return self._deny("strict trust root is required")
        if lease.self_writable_trust_paths(submitted_by):
            return self._deny("authorization trust root is self-writable")
        public_key = public_key_path()
        if public_key is None:
            return self._deny("verification key is not configured")
        try:
            if (
                not public_key.is_file()
                or lease.path_is_self_writable_or_replaceable(public_key)
            ):
                return self._deny(
                    "verification key is absent, self-writable, or replaceable"
                )
        except OSError:
            return self._deny("verification key is unreadable")
        ok, reason, payload = verify_envelope(
            public_key_path=public_key,
            submitted_by=submitted_by,
            task_id=row.task_id,
            agent=row.agent,
            task=row.task,
            envelope=envelope,
        )
        if not ok or payload is None:
            return self._deny(reason)
        blocked = _row_blocks_net_authorization(row.task_id)
        if blocked:
            return self._deny(blocked)
        if not _consume_row_net_authorization(row.task_id):
            return self._deny("network authorization already consumed for row")
        self.last_error = ""
        return True
