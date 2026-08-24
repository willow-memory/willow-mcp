"""Canonical bound-receipt schema (#195).

Spec: docs/design/bound-receipt-schema.md
JSON Schema: `willow_mcp/schemas/bound_receipt.v1.schema.json`

This module pins wire shape, ref derivations, canonical signing bytes, and the
#196 writer/verifier. AT-R1 lives in tests/test_bound_receipt_at_r1.py.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

FORMAT_VERSION = "willow-bound-receipt/1"
DEFAULT_TTL_SECONDS = 300

_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_DENIAL_RE = re.compile(r"^denial:[a-z0-9_]{1,64}$")
_EFFECT_RE = re.compile(r"^effect:[a-f0-9]{64}$")
_SIGNER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SIG_ALG = frozenset({"hmac-sha256", "ed25519"})

_SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "bound_receipt.v1.schema.json"


class VerificationReason(str, Enum):
    """Distinguishable failure reasons for the staged verify contract."""

    OK = "ok"
    STRUCTURAL_INVALID = "structural_invalid"
    EXPIRED = "expired"
    SIGNATURE_INVALID = "signature_invalid"

    @staticmethod
    def ref_mismatch(field: str) -> str:
        return f"ref_mismatch:{field}"


_PAYLOAD_REF_FIELDS = (
    "agent_identity_ref",
    "capability_token_ref",
    "policy_or_manifest_digest",
    "tool_call_digest",
    "effect_ref_or_denial_code",
    "ledger_prev",
    "ledger_entry_hash",
)


@dataclass(frozen=True, slots=True)
class ReceiptSources:
    """Live planes captured at tool-call time (#196)."""

    agent_id: str
    trust_level: int
    session_id: str
    manifest: dict
    app_id: str
    tool: str
    call_nonce: str
    ledger_prev: str
    ledger_ts: str
    ledger_app_id: str
    ledger_tool: str
    ledger_outcome: str
    ledger_detail: Optional[str] = None
    denied: bool = False
    denial_code: Optional[str] = None
    effect_outcome: Optional[str] = None
    effect_detail: Optional[str] = None


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    reason: str
    detail: str = "ok"


class BoundReceiptError(Exception):
    """Writer/refusal when binding prerequisites are missing."""


@dataclass(frozen=True, slots=True)
class BoundReceiptPayload:
    agent_identity_ref: str
    capability_token_ref: str
    policy_or_manifest_digest: str
    tool_call_digest: str
    effect_ref_or_denial_code: str
    ledger_prev: str
    ledger_entry_hash: str
    signer_id: str
    issued_at: str
    expires_at: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BoundReceiptSignature:
    alg: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"alg": self.alg, "value": self.value}


@dataclass(frozen=True, slots=True)
class BoundReceiptWire:
    payload: BoundReceiptPayload
    signature: BoundReceiptSignature
    meta: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "format": FORMAT_VERSION,
            "payload": self.payload.to_dict(),
            "signature": self.signature.to_dict(),
        }
        if self.meta is not None:
            out["meta"] = self.meta
        return out


def schema_path() -> Path:
    return _SCHEMA_PATH


def load_json_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


# ── Ref derivations (sources documented in bound-receipt-schema.md) ───────────

def agent_identity_ref(agent_id: str, trust_level: int, session_id: str) -> str:
    """Digest of the bound session_bind identity (capped trust + session id)."""
    msg = json.dumps(
        ["session_bind", agent_id, int(trust_level), session_id],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def manifest_acl_digest(manifest: dict) -> str:
    """Capability plane: sorted manifest permission groups / tool names."""
    app_id = manifest.get("app_id")
    perms = sorted({p for p in (manifest.get("permissions") or []) if isinstance(p, str)})
    msg = json.dumps(["manifest-acl", app_id, perms], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def manifest_policy_digest(manifest: dict) -> str:
    """Policy plane: canonical manifest document bytes (sorted keys at top level)."""
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def tool_call_digest(session_id: str, app_id: str, tool: str, call_nonce: str) -> str:
    """Same message shape as session_binder.call_sig (without the HMAC)."""
    msg = json.dumps(
        ["call", session_id, app_id, tool, call_nonce],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def effect_ref(outcome: str, detail: Optional[str] = None) -> str:
    msg = json.dumps(["effect", outcome, detail], separators=(",", ":"), ensure_ascii=False)
    return f"effect:{hashlib.sha256(msg.encode('utf-8')).hexdigest()}"


def denial_code(code: str) -> str:
    code = re.sub(r"[^a-z0-9_]", "_", code.lower())[:64]
    if not code:
        raise ValueError("denial code must be non-empty")
    return f"denial:{code}"


def ledger_entry_hash(
    prev_hash: str,
    ts: str,
    app_id: str,
    tool: str,
    outcome: str,
    detail: Optional[str],
) -> str:
    """Matches willow_mcp.receipts._entry_hash for cross-linking."""
    payload = json.dumps(
        [prev_hash, ts, app_id, tool, outcome, detail],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── Canonical signing bytes ───────────────────────────────────────────────────

def canonical_signed_bytes(payload: BoundReceiptPayload | dict[str, str]) -> bytes:
    p = payload if isinstance(payload, dict) else payload.to_dict()
    array = [
        FORMAT_VERSION,
        p["agent_identity_ref"],
        p["capability_token_ref"],
        p["policy_or_manifest_digest"],
        p["tool_call_digest"],
        p["effect_ref_or_denial_code"],
        p["ledger_prev"],
        p["ledger_entry_hash"],
        p["signer_id"],
        p["issued_at"],
        p["expires_at"],
    ]
    return json.dumps(array, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── Structural validation (stage 1) ───────────────────────────────────────────

def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST_RE.match(value))


def _valid_effect_or_denial(value: Any) -> bool:
    return isinstance(value, str) and (
        bool(_DENIAL_RE.match(value)) or bool(_EFFECT_RE.match(value))
    )


def _parse_timestamp(value: str) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def validate_structure(wire: dict[str, Any]) -> tuple[bool, Optional[VerificationReason], str]:
    """Stage 1: reject malformed receipts before crypto or ref work."""
    if not isinstance(wire, dict):
        return False, VerificationReason.STRUCTURAL_INVALID, "wire must be an object"
    if wire.get("format") != FORMAT_VERSION:
        return False, VerificationReason.STRUCTURAL_INVALID, "bad or missing format"
    if set(wire.keys()) - {"format", "payload", "signature", "meta"}:
        return False, VerificationReason.STRUCTURAL_INVALID, "unknown top-level keys"
    payload = wire.get("payload")
    if not isinstance(payload, dict):
        return False, VerificationReason.STRUCTURAL_INVALID, "payload must be an object"
    expected = set(BoundReceiptPayload.__dataclass_fields__)
    if set(payload.keys()) != expected:
        return False, VerificationReason.STRUCTURAL_INVALID, "payload keys mismatch"
    for key in (
        "agent_identity_ref",
        "capability_token_ref",
        "policy_or_manifest_digest",
        "tool_call_digest",
        "ledger_prev",
        "ledger_entry_hash",
    ):
        if not _valid_digest(payload.get(key)):
            return False, VerificationReason.STRUCTURAL_INVALID, f"bad digest: {key}"
    if not _valid_effect_or_denial(payload.get("effect_ref_or_denial_code")):
        return False, VerificationReason.STRUCTURAL_INVALID, "bad effect_ref_or_denial_code"
    signer = payload.get("signer_id")
    if not isinstance(signer, str) or not _SIGNER_RE.match(signer):
        return False, VerificationReason.STRUCTURAL_INVALID, "bad signer_id"
    for ts_key in ("issued_at", "expires_at"):
        if _parse_timestamp(payload.get(ts_key, "")) is None:
            return False, VerificationReason.STRUCTURAL_INVALID, f"bad timestamp: {ts_key}"
    sig = wire.get("signature")
    if not isinstance(sig, dict) or set(sig.keys()) != {"alg", "value"}:
        return False, VerificationReason.STRUCTURAL_INVALID, "bad signature object"
    if sig.get("alg") not in _SIG_ALG:
        return False, VerificationReason.STRUCTURAL_INVALID, "bad signature alg"
    val = sig.get("value")
    if not isinstance(val, str) or not re.match(r"^[a-f0-9]+$", val):
        return False, VerificationReason.STRUCTURAL_INVALID, "bad signature value"
    if sig["alg"] == "hmac-sha256" and len(val) != 64:
        return False, VerificationReason.STRUCTURAL_INVALID, "hmac-sha256 value must be 64 hex"
    if sig["alg"] == "ed25519" and len(val) != 128:
        return False, VerificationReason.STRUCTURAL_INVALID, "ed25519 value must be 128 hex"
    meta = wire.get("meta")
    if meta is not None and not isinstance(meta, dict):
        return False, VerificationReason.STRUCTURAL_INVALID, "meta must be an object"
    return True, VerificationReason.OK, "ok"


def check_freshness(
    wire: dict[str, Any],
    *,
    now: Optional[datetime] = None,
) -> tuple[bool, Optional[VerificationReason], str]:
    """Stage 2: expires_at must be in the future (UTC)."""
    ok, reason, detail = validate_structure(wire)
    if not ok:
        return False, reason, detail
    expires = _parse_timestamp(wire["payload"]["expires_at"])
    assert expires is not None
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if now_utc > expires:
        return False, VerificationReason.EXPIRED, "expires_at in the past"
    return True, VerificationReason.OK, "ok"


def payload_from_dict(data: dict[str, str]) -> BoundReceiptPayload:
    return BoundReceiptPayload(**data)


def wire_from_dict(data: dict[str, Any]) -> BoundReceiptWire:
    ok, reason, detail = validate_structure(data)
    if not ok:
        raise ValueError(f"{reason}: {detail}")
    return BoundReceiptWire(
        payload=payload_from_dict(data["payload"]),
        signature=BoundReceiptSignature(**data["signature"]),
        meta=data.get("meta"),
    )


# ── Writer / verifier (#196) ──────────────────────────────────────────────────

def supports_bound_receipt(signing_key: Optional[bytes]) -> bool:
    """All-or-nothing: no key ⇒ do not emit a receipt that looks bound."""
    return bool(signing_key)


def _effect_from_sources(sources: ReceiptSources) -> str:
    if sources.denied:
        if not sources.denial_code:
            raise BoundReceiptError("denied call requires denial_code")
        return denial_code(sources.denial_code)
    outcome = sources.effect_outcome if sources.effect_outcome is not None else sources.ledger_outcome
    return effect_ref(outcome, sources.effect_detail)


def expected_refs(sources: ReceiptSources) -> dict[str, str]:
    manifest = sources.manifest
    return {
        "agent_identity_ref": agent_identity_ref(sources.agent_id, sources.trust_level, sources.session_id),
        "capability_token_ref": manifest_acl_digest(manifest),
        "policy_or_manifest_digest": manifest_policy_digest(manifest),
        "tool_call_digest": tool_call_digest(
            sources.session_id, sources.app_id, sources.tool, sources.call_nonce
        ),
        "effect_ref_or_denial_code": _effect_from_sources(sources),
        "ledger_prev": sources.ledger_prev,
        "ledger_entry_hash": ledger_entry_hash(
            sources.ledger_prev,
            sources.ledger_ts,
            sources.ledger_app_id,
            sources.ledger_tool,
            sources.ledger_outcome,
            sources.ledger_detail,
        ),
    }


def _sign_hmac_sha256(signing_key: bytes, payload: dict[str, str]) -> str:
    return hmac.new(signing_key, canonical_signed_bytes(payload), hashlib.sha256).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def write_receipt(
    *,
    sources: ReceiptSources,
    signing_key: bytes,
    signer_id: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    issued_at: Optional[datetime] = None,
    meta: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Emit one bound receipt for a tool call. Key must be outside agent reach."""
    if not supports_bound_receipt(signing_key):
        raise BoundReceiptError("signing_key required — refusing to emit a pseudo-bound receipt")
    refs = expected_refs(sources)
    now = issued_at or _utc_now()
    expires = now + timedelta(seconds=max(1, int(ttl_seconds)))
    payload = BoundReceiptPayload(
        signer_id=signer_id,
        issued_at=_format_ts(now),
        expires_at=_format_ts(expires),
        **refs,
    )
    sig_hex = _sign_hmac_sha256(signing_key, payload.to_dict())
    wire = BoundReceiptWire(
        payload=payload,
        signature=BoundReceiptSignature(alg="hmac-sha256", value=sig_hex),
        meta=meta,
    )
    return wire.to_dict()


def _check_refs(wire: dict[str, Any], sources: ReceiptSources) -> Optional[VerificationResult]:
    expected = expected_refs(sources)
    payload = wire["payload"]
    for field in _PAYLOAD_REF_FIELDS:
        if payload.get(field) != expected[field]:
            return VerificationResult(
                ok=False,
                reason=VerificationReason.ref_mismatch(field),
                detail=f"expected {expected[field]!r}, got {payload.get(field)!r}",
            )
    return None


def _check_signature(wire: dict[str, Any], signing_key: bytes) -> Optional[VerificationResult]:
    sig = wire["signature"]
    if sig.get("alg") != "hmac-sha256":
        return VerificationResult(
            ok=False,
            reason=VerificationReason.SIGNATURE_INVALID.value,
            detail="only hmac-sha256 verifier implemented",
        )
    expected = _sign_hmac_sha256(signing_key, wire["payload"])
    if not hmac.compare_digest(expected, sig.get("value") or ""):
        return VerificationResult(
            ok=False,
            reason=VerificationReason.SIGNATURE_INVALID.value,
            detail="signature mismatch",
        )
    return None


def verify_receipt(
    wire: dict[str, Any],
    *,
    signing_key: bytes,
    sources: ReceiptSources,
    now: Optional[datetime] = None,
) -> VerificationResult:
    """Staged verify: structural → freshness → refs → signature (#194 / #196)."""
    ok, reason, detail = validate_structure(wire)
    if not ok:
        return VerificationResult(ok=False, reason=reason.value, detail=detail)
    fresh_ok, fresh_reason, fresh_detail = check_freshness(wire, now=now)
    if not fresh_ok:
        return VerificationResult(ok=False, reason=fresh_reason.value, detail=fresh_detail)
    ref_fail = _check_refs(wire, sources)
    if ref_fail is not None:
        return ref_fail
    sig_fail = _check_signature(wire, signing_key)
    if sig_fail is not None:
        return sig_fail
    return VerificationResult(ok=True, reason=VerificationReason.OK.value, detail="ok")
