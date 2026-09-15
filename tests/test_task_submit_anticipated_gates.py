"""``task_submit(anticipated_gates=...)`` — the upfront ask surface.

Gap ``5ecb87cfdf56``, slice 2b PR 3. Denial-site producers (lease, perm, push)
surface an ask only after the task hits the refusal for the first time. On a
task the operator plans to run once, that is the same information they need
before it starts; on a task with a retry loop, it fills the queue with rows
that duplicate the same intent under the dedup key.

`anticipated_gates` lets the submitter declare, at submit time, which gates
the task expects to need. Each is filed with the new task_id as the dedup key.
The row is exactly the same shape a denial-site ask would produce later, so an
operator's press activates the same standing grant whichever surface filed the
ask.

The security half of this file: `task_submit` must not become a laundering
path for asks the caller's own denial site would refuse to file. Two rules
hold that:

* Every gate id passes ``gate_request.check_requestable`` (same allowlist as
  every other seam).
* ``lease.<X>`` and ``perm.<X>.<...>`` must name THIS submitting app.
"""
from __future__ import annotations

import pytest

from willow_mcp import gates_panel, server


# ── unit: _validate_anticipated_gates ─────────────────────────────────────────

def test_none_is_the_zero_list_not_a_type_error():
    """Not passing the param at all is the common case."""
    assert server._validate_anticipated_gates("kart", None) is None
    assert server._validate_anticipated_gates("kart", []) is None


def test_a_non_list_is_refused_by_shape():
    """MCP passes structured params, but a caller assembling JSON by hand can
    still send a string. Refusing here is louder than fanning out a per-char
    iteration."""
    err = server._validate_anticipated_gates("kart", "lease.kart")  # type: ignore[arg-type]
    assert err and "expected a list" in err["error"]


def test_a_non_string_entry_is_refused():
    err = server._validate_anticipated_gates("kart", ["lease.kart", 42])  # type: ignore[list-item]
    assert err and "not a string" in err["error"]


def test_a_gate_outside_the_allowlist_is_refused():
    err = server._validate_anticipated_gates("kart", ["sudo.kart"])
    assert err and "sudo.kart" in err["error"]
    assert "names no requestable gate" in err["error"]


def test_a_never_requestable_perm_is_refused():
    """Same refusal `check_requestable` gives the denial-site producers."""
    err = server._validate_anticipated_gates("kart", ["perm.kart.full_access"])
    assert err and "may never be requested" in err["error"]


def test_a_lease_for_another_app_is_refused():
    """A task may anticipate only its own gates — otherwise `task_submit`
    would be a laundering path for asks the caller's own denial site would
    refuse."""
    err = server._validate_anticipated_gates("kart", ["lease.loki"])
    assert err and "names 'loki'" in err["error"]


def test_a_perm_for_another_app_is_refused():
    err = server._validate_anticipated_gates("kart", ["perm.loki.store_read"])
    assert err and "names 'loki'" in err["error"]


def test_ownership_rule_admits_self_perm_and_lease():
    assert server._validate_anticipated_gates(
        "kart", ["lease.kart", "perm.kart.store_read"]
    ) is None


def test_push_and_attest_are_admitted_without_app_ownership():
    """`push.` and `attest.` gate ids carry no app_id, so ownership is beyond
    what the shape can prove; `check_requestable` still validates format."""
    assert server._validate_anticipated_gates(
        "kart",
        ["push.willow-memory/willow-bot:feat/x", "attest.session_abc"],
    ) is None


def test_malformed_push_is_refused_by_check_requestable():
    err = server._validate_anticipated_gates("kart", ["push.bare:feat/x"])
    assert err and "not a well-formed push" in err["error"]


# ── unit: _file_anticipated_gate_asks ─────────────────────────────────────────

class _FakeGateRequest:
    """Records every open_request call and returns a scripted result."""
    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def open_request(self, app_id, gate_id, *, task_id="", reason="", store=None):
        self.calls.append({
            "app_id": app_id, "gate_id": gate_id, "task_id": task_id,
            "reason": reason,
        })
        return self._results.pop(0)


def test_file_asks_returns_one_row_per_gate(monkeypatch):
    fake = _FakeGateRequest([
        {"queued": True, "id": "req-1", "gate_id": "lease.kart"},
        {"queued": True, "id": "req-2", "gate_id": "perm.kart.store_read"},
    ])
    monkeypatch.setattr(server, "gate_request", fake, raising=False)
    # `_file_anticipated_gate_asks` does `from . import gate_request` at call
    # time, so patch that lookup:
    import willow_mcp
    monkeypatch.setattr(willow_mcp, "gate_request", fake, raising=False)

    filed = server._file_anticipated_gate_asks(
        "kart", "T1", "do a thing",
        ["lease.kart", "perm.kart.store_read"],
    )
    assert filed == [
        {"gate_id": "lease.kart", "queued": True, "id": "req-1"},
        {"gate_id": "perm.kart.store_read", "queued": True, "id": "req-2"},
    ]
    assert len(fake.calls) == 2
    assert fake.calls[0]["task_id"] == "T1"
    assert "do a thing" in fake.calls[0]["reason"]


def test_file_asks_reports_duplicates_without_reraising(monkeypatch):
    fake = _FakeGateRequest([
        {"queued": False, "duplicate_of": "req-1",
         "reason": "an open request for this gate and task is already ..."}
    ])
    import willow_mcp
    monkeypatch.setattr(willow_mcp, "gate_request", fake, raising=False)

    filed = server._file_anticipated_gate_asks(
        "kart", "T1", "task", ["lease.kart"])
    assert filed[0]["queued"] is False
    assert filed[0]["duplicate_of"] == "req-1"
    assert filed[0]["id"] == "req-1"


def test_file_asks_returns_empty_for_no_input():
    assert server._file_anticipated_gate_asks("kart", "T1", "t", None) == []
    assert server._file_anticipated_gate_asks("kart", "T1", "t", []) == []


# ── the whole set through the tool ────────────────────────────────────────────

# End-to-end tests through `server.task_submit()` need a fake pg (see
# test_server.py's `_FakePg`), so they live there. This module holds the pure
# validation and ask-filing units.


def test_check_requestable_admits_every_prefix_the_task_submit_help_names():
    """A live cross-check: the docstring for `task_submit`'s
    `anticipated_gates` param says "the same allowlist as denial-site asks".
    That is `REQUESTABLE_PREFIXES` — pinned here so a future prefix added to
    one and not the other fails at test time."""
    assert gates_panel.REQUESTABLE_PREFIXES == (
        "lease.", "perm.", "attest.", "push.", "pr.",
    )


# ── ownership rule pinned against split_permission_gate's shape ───────────────

def test_a_perm_gate_that_split_cannot_parse_is_refused_upstream():
    """A `perm.` with no third dot is caught by `check_requestable`'s own
    "not a well-formed perm.<app_id>.<group> gate" refusal — the ownership
    check does not need to defend against a shape `check_requestable` already
    refused."""
    err = server._validate_anticipated_gates("kart", ["perm.kart"])
    assert err and "not a well-formed" in err["error"]


@pytest.mark.parametrize("gate_id,expected", [
    ("attest.session_abc", None),
    ("push.willow-memory/willow-bot:feat/x", None),
    ("lease.kart", None),
    ("perm.kart.store_read", None),
])
def test_admits_shape_ok_and_owned(gate_id, expected):
    assert server._validate_anticipated_gates("kart", [gate_id]) is expected
