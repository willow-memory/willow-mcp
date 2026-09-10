"""The redaction funnel must not have a type-shaped hole in it.

README guarantee: "No tool ever returns a credential." It is enforced at one
funnel — `_guarded`'s call to `secret_scan.redact_egress` — and that funnel
walks str/dict/list/tuple. Everything else `_walk` returns untouched, which is
right for an int and a hole for a structured object.

That hole was theoretical while every tool returned a dict. SEP-2322 made it
real: a tool that pauses returns an `InputRequiredResult`, a pydantic model,
which would have sailed through unscanned — and the guarantee would have
quietly stopped applying to whichever return type was added most recently.
"""
from __future__ import annotations

from willow_mcp import secret_scan

#: Shaped like the scanner's `github_token` pattern, and not a real token.
FAKE_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


class _Model:
    """Stands in for a pydantic result model: structured, not a dict."""

    def __init__(self, text: str):
        self.text = text

    def __str__(self) -> str:
        return f"_Model({self.text})"


# ── the hole, named ──────────────────────────────────────────────────────────

def test_walk_passes_an_opaque_object_through_untouched():
    """Not a bug in `_walk` — its contract — but the reason `is_opaque` exists.
    Stated as a test so that if `_walk` ever grows object support, whoever does
    it sees why the funnel branch was added."""
    model = _Model(FAKE_TOKEN)
    scanned, kinds = secret_scan.redact_egress(model)

    assert scanned is model
    assert kinds == []          # unscanned, not clean


def test_is_opaque_distinguishes_structures_from_scalars():
    assert secret_scan.is_opaque(_Model("x")) is True
    for scalar in ("a string", {"k": "v"}, ["a"], ("a",), 1, 1.5, True, None):
        assert secret_scan.is_opaque(scalar) is False, scalar


# ── the hole, closed ─────────────────────────────────────────────────────────

def test_scan_opaque_finds_a_credential_inside_a_model():
    assert "github_token" in secret_scan.scan_opaque(_Model(FAKE_TOKEN))


def test_scan_opaque_is_quiet_on_a_clean_model():
    assert secret_scan.scan_opaque(_Model("nothing to see")) == []


def test_scan_opaque_reports_rather_than_raises_on_the_unserializable():
    """Fail-closed: an object that cannot be turned into text at all is
    reported as a sentinel kind, so the caller refuses. Returning [] here
    would read as 'clean' and be the same hole again."""
    class _Hostile:
        def __str__(self):
            raise RuntimeError("no")

        def __repr__(self):
            raise RuntimeError("no")

    assert secret_scan.scan_opaque(_Hostile()) == ["unserializable"]


def test_scan_opaque_does_not_rewrite_its_argument():
    """Detection only — the caller refuses rather than redacts, because a model
    this module cannot rebuild must not be half-rebuilt."""
    model = _Model(FAKE_TOKEN)
    secret_scan.scan_opaque(model)
    assert model.text == FAKE_TOKEN


# ── the funnel itself ────────────────────────────────────────────────────────

def test_the_pause_result_is_scanned_and_allowed_through(monkeypatch):
    """An `InputRequiredResult` is opaque, so it takes the new branch — and a
    clean one must still reach the client, or pausing would never work."""
    from willow_mcp import egress_pause, request_context

    class _Session:
        def check_client_capability(self, _c): return True

    class _Ctx:
        session = _Session()
        params: dict = {}

    monkeypatch.setattr(request_context, "current", lambda: _Ctx())
    paused = egress_pause.pause_for_lease("kart", request_id="R1")

    assert secret_scan.is_opaque(paused) is True
    assert secret_scan.scan_opaque(paused) == []
