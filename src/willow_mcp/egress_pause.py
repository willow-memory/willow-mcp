"""willow_mcp/egress_pause.py — hold the call open instead of losing it.

#463 gave the egress denial a durable record: a refused call files an ask the
operator can see. This is the other half of
`docs/design/egress-request-seam.md`'s recommended shape — the agent's call
**pauses** rather than being told to ask and carrying on.

The doc is explicit about why the durable record alone is not enough: an
enqueue "writes a row and returns — the module docstring says the discipline is
*automation pauses for a human* and nothing pauses. The agent gets a queue id
and carries on, which is a bulletin board, not a gate."

SEP-2322 (the 2026-07-28 revision, available since willow-mcp went to SDK 2.0)
is the first protocol-level way to suspend a tool call until a person acts: the
server returns an `InputRequiredResult`, and the client retries the call
echoing `request_state`.

## The rule this module exists to enforce

**The client's answer is not the authorization.**

The elicitation asks a human to go and grant a lease. What comes back is a
human saying they did. That is a *hint that it is worth re-checking*, and
nothing more — the authorization is the lease on disk, written by
`grant-net` at an operator terminal, and it is re-read from scratch on every
resume. `resume_is_authorized()` never looks at `input_responses` at all.

If it did, the whole three-key gate would come undone in one move: an agent
whose client can answer its own elicitation would be an agent that can grant
itself egress by replying "yes". The seam's rule is that *an agent may
REQUEST, never CONFIRM*, and SEP-2322 makes it newly possible to blur those
two, because the confirmation now travels back over the same wire as the ask.

## Fail-safe, not fail-open

Pausing is an enhancement over denying, so every uncertainty resolves to the
old behaviour: if the client does not advertise elicitation, if the capability
cannot be determined, if the request context is missing, or if anything here
raises, the caller gets the ordinary `lease_denied` dict it got before. A
paused call that should have been a denial is a held-open gate; a denial that
could have been a pause is only an inconvenience.
"""
from __future__ import annotations

import json
from typing import Any, Optional

#: Prefix marking a `request_state` as ours, so a state minted by some other
#: seam (or hand-typed) is not read as an egress resume.
_STATE_MARKER = "willow-egress:"

#: The key our single input request is filed under in `input_requests`.
_REQUEST_KEY = "egress_lease"


def client_can_be_asked() -> bool:
    """Whether this client advertised elicitation. Never raises.

    False on any doubt — no request context, no session, an SDK shape we do not
    recognise, or an exception. See the module docstring: uncertainty resolves
    to the plain denial.
    """
    try:
        from mcp_types import ClientCapabilities, ElicitationCapability

        from . import request_context

        ctx = request_context.current()
        session = getattr(ctx, "session", None)
        if session is None:
            return False
        return bool(session.check_client_capability(
            ClientCapabilities(elicitation=ElicitationCapability())
        ))
    except Exception:
        return False


def _encode_state(app_id: str, task_id: str, request_id: str) -> str:
    return _STATE_MARKER + json.dumps(
        {"app_id": app_id, "task_id": task_id, "request_id": request_id},
        sort_keys=True, separators=(",", ":"),
    )


def decode_state(request_state: Optional[str]) -> Optional[dict]:
    """The egress pause encoded in `request_state`, or None. Never raises.

    None for anything that is not ours: a resume for some other seam, a
    malformed blob, a state a caller invented. A state we cannot read is not a
    state we act on.
    """
    raw = (request_state or "").strip()
    if not raw.startswith(_STATE_MARKER):
        return None
    try:
        data = json.loads(raw[len(_STATE_MARKER):])
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) and data.get("app_id") else None


def current_request_state() -> Optional[str]:
    """The `request_state` this call is echoing back, if any. Never raises.

    Read off the `ServerRequestContext` our own middleware publishes rather
    than an injected `Context`: the SDK injects `Context` into tool functions,
    and that injection does not reach a decorator wrapping 120 tools — the same
    reason `request_context` exists at all (see its module docstring).
    """
    try:
        from . import request_context

        ctx = request_context.current()
        if ctx is None:
            return None
        params = getattr(ctx, "params", None)
        if isinstance(params, dict):
            state = params.get("request_state")
            if isinstance(state, str):
                return state
        state = getattr(params, "request_state", None)
        return state if isinstance(state, str) else None
    except Exception:
        return None


def resuming_for(app_id: str) -> bool:
    """Whether this call is the retry of a pause we issued for `app_id`."""
    state = decode_state(current_request_state())
    return bool(state and state.get("app_id") == app_id)


#: There is deliberately NO `resume_is_authorized()` here.
#:
#: The obvious API for this module would be one — "the resume came back, is the
#: lease valid now?" — and it would be a second implementation of a question
#: the caller has already answered. Every site that can pause re-reads the
#: lease at the top of the call; that read IS the authorization, on the resume
#: exactly as on the first attempt, because a retry is an ordinary call that
#: happens to carry a `request_state`.
#:
#: A helper here would make two ways to ask one security question, which is the
#: shape that let the attestation blocker and its gate disagree for months
#: (#457). So this module answers only questions about the *pause* — can this
#: client be asked, is this call a resume — and never about authority.


def pause_for_lease(app_id: str, *, task_id: str = "", request_id: str = "",
                    detail: str = "") -> Optional[Any]:
    """An `InputRequiredResult` that holds the call open, or None to deny.

    None means "fall back to the ordinary denial" — the caller must still
    refuse in that case, exactly as it did before this module existed.
    """
    try:
        if not client_can_be_asked():
            return None

        from mcp_types import (
            ElicitRequest,
            ElicitRequestFormParams,
            InputRequiredResult,
        )

        message = (
            f"'{app_id}' needs an egress lease and does not have one.\n\n"
            "No MCP tool can mint one — this asks you to grant it yourself, at "
            "your own terminal:\n\n"
            f"    willow-mcp grant-net {app_id} --ttl 30m --reason \"...\"\n\n"
            + (f"{detail}\n\n" if detail else "")
            + (f"This ask is queued for you as request {request_id}, and also "
               f"appears in `willow-mcp gates`.\n\n" if request_id else "")
            + "Confirm once the lease is granted and the call will continue. "
              "Confirming does not grant anything: the lease itself is "
              "re-checked on disk before the call proceeds, so answering yes "
              "without running the command simply denies again."
        )
        request = ElicitRequest(
            params=ElicitRequestFormParams(
                message=message,
                requestedSchema={"type": "object", "properties": {}},
            )
        )
        return InputRequiredResult(
            input_requests={_REQUEST_KEY: request},
            request_state=_encode_state(app_id, task_id, request_id),
        )
    except Exception:
        # An enhancement that breaks must not take the denial down with it.
        return None
