"""B8 — the vendored mem_ratify Canon-promotion gate and its knowledge_ingest wiring.

Two things are pinned here:

  1. DRIFT-GUARD (theme ① of the 2026-07-24 box audit): mem_ratify is a manual
     copy of the willow repo's mem_ratify package. Nothing else catches it going
     stale, so its body is pinned to a known hash — mirroring
     tests/test_stance_friction.py for friction_floor. The cross-repo companion
     is scripts/check_mem_ratify_sync.py (run in CI's vendor-sync job).

  2. WIRING: knowledge_ingest's core write consults the gate ONLY when the
     off-by-default flag WILLOW_MCP_ENFORCE_MEM_RATIFY is set, and blocks ONLY
     when mem_ratify's own WILLOW_MEM_RATIFY_ENFORCE is also set (both knobs).
     The default path must stay byte-for-byte unchanged.
"""
import hashlib
import pathlib

from willow_mcp import mem_ratify
from willow_mcp import server

MEM_RATIFY_DIR = pathlib.Path(__file__).resolve().parents[1] / "src/willow_mcp/mem_ratify"

# ── drift-guard: the vendored body must not silently diverge from upstream ──────
# Fires on ANY edit to the vendored copy. That is intended: the copy is not a
# place to edit. Change mem_ratify UPSTREAM in the willow repo, then re-sync both
# files here (byte-for-byte from the module docstring onward, header excepted)
# and update the EXPECTED_*_SHA256 values below to what the assertion prints.
EXPECTED_RATIFY_SHA256 = "477f686dd9eb7010133967abb9c9ae2215d28b6e3004a0d0f4a8d495ff322da7"
EXPECTED_INIT_SHA256 = "5dcdb81e8218c9fe38c66e466b060747b2ee1e6c538f566df471ae690acae77c"


def _body_hash(name: str) -> str:
    text = (MEM_RATIFY_DIR / name).read_text()
    body = text[text.index('"""'):]  # docstring onward — the vendored contract
    return hashlib.sha256(body.encode()).hexdigest()


def test_vendored_ratify_body_matches_pinned_hash():
    got = _body_hash("ratify.py")
    assert got == EXPECTED_RATIFY_SHA256, (
        "vendored mem_ratify/ratify.py body drifted from the pinned willow copy.\n"
        f"  got:      {got}\n  expected: {EXPECTED_RATIFY_SHA256}\n"
        "If you re-synced from willow on purpose, update EXPECTED_RATIFY_SHA256.\n"
        "If you edited the vendored copy directly — don't; edit willow and re-sync.")


def test_vendored_init_body_matches_pinned_hash():
    got = _body_hash("__init__.py")
    assert got == EXPECTED_INIT_SHA256, (
        "vendored mem_ratify/__init__.py body drifted from the pinned willow copy.\n"
        f"  got:      {got}\n  expected: {EXPECTED_INIT_SHA256}\n"
        "If you re-synced from willow on purpose, update EXPECTED_INIT_SHA256.")


# ── the gate itself (pure, stdlib — sanity that the vendored copy behaves) ──────
def test_bare_promotion_to_canon_is_refused():
    """A write with no witnesses/quorum is refused, fail-closed (the B8 hole)."""
    req = mem_ratify.RatifyRequest.build(
        claim_id="c", current_tier=mem_ratify.Tier.CONTESTED,
        target_tier=mem_ratify.Tier.CANONICAL, proposer_id="app")
    assert mem_ratify.ratify(req).allowed is False


# ── the enforce flag ────────────────────────────────────────────────────────────
def test_enforce_flag_off_by_default(monkeypatch):
    monkeypatch.delenv("WILLOW_MCP_ENFORCE_MEM_RATIFY", raising=False)
    assert server._enforce_mem_ratify() is False


def test_enforce_flag_reads_env(monkeypatch):
    for val in ("1", "true", "yes", "on", "ON", "True"):
        monkeypatch.setenv("WILLOW_MCP_ENFORCE_MEM_RATIFY", val)
        assert server._enforce_mem_ratify() is True
    for val in ("", "0", "off", "no"):
        monkeypatch.setenv("WILLOW_MCP_ENFORCE_MEM_RATIFY", val)
        assert server._enforce_mem_ratify() is False


# ── the gate helper (no Postgres needed — it runs before the DB touch) ──────────
def test_gate_advisory_when_mcp_flag_off(monkeypatch):
    """Both knobs off → helper is a no-op (never even called on the live path)."""
    monkeypatch.delenv("WILLOW_MEM_RATIFY_ENFORCE", raising=False)
    assert server._mem_ratify_gate("app", "general", "") is None


def test_gate_advisory_when_only_mcp_flag_on(monkeypatch):
    """MCP flag on but mem_ratify's own enforce knob off → advisory, not blocking."""
    monkeypatch.delenv("WILLOW_MEM_RATIFY_ENFORCE", raising=False)
    assert server._mem_ratify_gate("app", "general", "") is None


def test_gate_blocks_when_both_flags_on(monkeypatch):
    """Both knobs on → fail-closed refusal with a structured, auditable reason."""
    monkeypatch.setenv("WILLOW_MEM_RATIFY_ENFORCE", "1")
    denied = server._mem_ratify_gate("app", "general", "")
    assert denied is not None
    assert denied["error"].startswith("mem_ratify_denied:")
    assert denied["mem_ratify"]["allowed"] is False
    assert denied["mem_ratify"]["reasons"]
