"""SEP-2322: the call pauses for the operator, and the pause grants nothing.

#463 made a refused call file a durable ask. This is the other half of
`docs/design/egress-request-seam.md` — the call *pauses* instead of being told
to ask and carrying on, which the doc calls the difference between a gate and
"a bulletin board".

The property that matters most here is the one SEP-2322 makes newly possible
to get wrong: the confirmation now travels back over the same wire as the ask,
so a careless implementation would let an agent grant itself egress by
answering its own elicitation. The authorization is the lease on disk and
nothing else.
"""
from __future__ import annotations

import json

import pytest

from willow_mcp import egress_pause


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(tmp_path / "mcp_apps"))
    monkeypatch.setenv("WILLOW_STORE_ROOT", str(tmp_path / "store"))
    return tmp_path


class _Session:
    def __init__(self, supports: bool):
        self._supports = supports

    def check_client_capability(self, _cap) -> bool:
        return self._supports


class _Ctx:
    def __init__(self, supports=False, params=None):
        self.session = _Session(supports)
        self.params = params or {}


# ── asking the client ────────────────────────────────────────────────────────

def test_no_elicitation_capability_means_no_pause(monkeypatch):
    """A client that cannot be asked must get the ordinary denial. Pausing a
    client that will never answer is a hung call, which is the failure #458
    spent two good signatures teaching us to avoid."""
    from willow_mcp import request_context

    monkeypatch.setattr(request_context, "current", lambda: _Ctx(supports=False))
    assert egress_pause.client_can_be_asked() is False
    assert egress_pause.pause_for_lease("kart") is None


def test_no_request_context_means_no_pause(monkeypatch):
    from willow_mcp import request_context

    monkeypatch.setattr(request_context, "current", lambda: None)
    assert egress_pause.client_can_be_asked() is False
    assert egress_pause.pause_for_lease("kart") is None


def test_a_raising_context_means_no_pause(monkeypatch):
    """Fail-safe, not fail-open: an enhancement that breaks must fall back to
    denying, never to allowing and never to raising."""
    from willow_mcp import request_context

    def _boom():
        raise RuntimeError("no context here")

    monkeypatch.setattr(request_context, "current", _boom)
    assert egress_pause.client_can_be_asked() is False
    assert egress_pause.pause_for_lease("kart") is None


def test_a_capable_client_gets_an_input_required_result(monkeypatch):
    from mcp_types import InputRequiredResult

    from willow_mcp import request_context

    monkeypatch.setattr(request_context, "current", lambda: _Ctx(supports=True))
    result = egress_pause.pause_for_lease("kart", task_id="T1", request_id="R1")

    assert isinstance(result, InputRequiredResult)
    assert result.request_state
    assert result.input_requests


def test_the_prompt_names_the_operator_command(monkeypatch):
    from willow_mcp import request_context

    monkeypatch.setattr(request_context, "current", lambda: _Ctx(supports=True))
    result = egress_pause.pause_for_lease("kart", request_id="R1")
    message = json.dumps(result.model_dump(), default=str)

    assert "grant-net kart" in message
    # And it must not promise that confirming is what grants.
    assert "does not grant" in message


# ── the state channel ────────────────────────────────────────────────────────

def test_state_roundtrips(monkeypatch):
    from willow_mcp import request_context

    monkeypatch.setattr(request_context, "current", lambda: _Ctx(supports=True))
    result = egress_pause.pause_for_lease("kart", task_id="T9", request_id="R2")

    state = egress_pause.decode_state(result.request_state)
    assert state == {"app_id": "kart", "task_id": "T9", "request_id": "R2"}


@pytest.mark.parametrize("bad", [
    None, "", "   ", "not-ours", "willow-egress:", "willow-egress:{",
    "willow-egress:[]", 'willow-egress:{"task_id":"T1"}',
])
def test_a_state_we_cannot_read_is_not_acted_on(bad):
    """A resume for some other seam, a malformed blob, or one a caller
    invented — none of them is an egress resume."""
    assert egress_pause.decode_state(bad) is None


def test_resuming_for_matches_only_its_own_app(monkeypatch):
    from willow_mcp import request_context

    monkeypatch.setattr(request_context, "current", lambda: _Ctx(supports=True))
    state = egress_pause.pause_for_lease("kart", task_id="T1").request_state

    monkeypatch.setattr(request_context, "current",
                        lambda: _Ctx(params={"request_state": state}))
    assert egress_pause.resuming_for("kart") is True
    assert egress_pause.resuming_for("some-other-app") is False


def test_no_state_is_not_a_resume(monkeypatch):
    from willow_mcp import request_context

    monkeypatch.setattr(request_context, "current", lambda: _Ctx(params={}))
    assert egress_pause.resuming_for("kart") is False


# ── the property the whole seam rests on ─────────────────────────────────────

def test_the_module_offers_no_way_to_authorize(home):
    """The confirmation travels back over the same wire as the ask, so the one
    thing this module must not have is a function that turns a client's answer
    into authority.

    There is deliberately no `resume_is_authorized`: the caller's own
    `lease.read_lease` is the authorization, on a resume exactly as on a first
    attempt. Two ways to ask one security question is what let the attestation
    blocker and its gate disagree (#457).
    """
    assert not hasattr(egress_pause, "resume_is_authorized")

    # Nothing in the module reads the client's answers at all.
    import inspect

    source = inspect.getsource(egress_pause)
    assert "input_responses" not in source.replace(
        "`input_responses`", "").replace("input_responses`", "")


def test_a_pause_does_not_create_a_lease(home, monkeypatch):
    """Issuing the pause must not, by itself, move the gate one inch."""
    from willow_mcp import lease, request_context

    monkeypatch.setattr(request_context, "current", lambda: _Ctx(supports=True))

    assert lease.read_lease("kart")["status"] != "active"
    egress_pause.pause_for_lease("kart", task_id="T1", request_id="R1")
    assert lease.read_lease("kart")["status"] != "active"


def test_a_resume_without_a_real_lease_is_still_unauthorized(home, monkeypatch):
    """The client comes back saying the human granted it. They did not.

    This is the attack the design has to survive: an agent whose client can
    answer its own elicitation must not thereby hold a lease.
    """
    from willow_mcp import lease, request_context

    monkeypatch.setattr(request_context, "current", lambda: _Ctx(supports=True))
    state = egress_pause.pause_for_lease("kart", task_id="T1").request_state

    # The resume arrives, carrying a confident answer and a valid state.
    monkeypatch.setattr(request_context, "current", lambda: _Ctx(
        params={"request_state": state,
                "input_responses": {"egress_lease": {"action": "accept"}}},
    ))

    assert egress_pause.resuming_for("kart") is True
    # …and the only thing that decides is still the lease on disk.
    assert lease.read_lease("kart")["status"] != "active"
