"""Consent gate for model inference that leaves this machine.

`nest_scan`'s docstring has always promised *"Nothing leaves the machine; no
cloud inference."* That is true of the **default** and was never true of the
**variable**: the embedding and generative seams post to
``os.environ["OLLAMA_HOST"]`` (default ``http://localhost:11434``), and nothing
checked where that pointed. An operator who exported it at a box across the room
— or across the internet — got exactly the same reassuring sentence, while
`nest/classify.py` sent document **bodies** out of what `nest/__init__.py` calls
"the local PII zone".

Meanwhile `consent.cloud_llm` existed, was persisted, reconciled against the
legacy mirror, and rendered in the gates panel, and **nothing read it**.

TWO HALVES, TWO HOMES
---------------------
The DETECTION half — `model_host` / `_addresses` / `is_local_host`, the
fail-closed "is the model on this machine?" primitive (only all-loopback is
local; an unparseable URL, an unresolvable name, or a loopback/non-loopback mix
all read as OFF the machine) — was written here, vendored byte-for-byte by the
Forge on 2026-08-11 as the thing its declared-not-ambient routing turns on, and
is now imported back from `forge.model_egress` since forge-play 0.1.0 (the
operator's 2026-09-02 decision: Willow depends on the engine). It is
security-relevant and subtle, exactly the kind of thing to hold in one place.

The POLICY half — `denial()` — stays here. It reads THIS repo's consent store
(`consent.cloud_llm`); the Forge gates egress on the build's signed manifest
instead and deliberately did not take it. `tests/test_forge_take.py` pins the
split. The Forge never imports willow-mcp.

WHY THE GATE IS HERE AND NOT AT THE POST
----------------------------------------
The obvious place to check is `nest/embed.py:_post` / `nest/llm.py:_http_json`,
where the request is actually made. Those files are **vendored byte-for-byte**
from ``safe-app-store/libs/nest-pipeline`` (box audit A4) with a hash pin and a
CI ``vendor-sync`` job enforcing it, and the library is deliberately policy-free
so that each consumer keeps its own layers outside the shared core. Editing them
would fork the canonical library to carry one consumer's consent model, and
break the drift-guard on its next run.

So the gate sits at willow-mcp's own boundary — the tool that decides to invoke
the pipeline — which is also where the false promise is written.

LOOPBACK IS NOT EGRESS
----------------------
A loopback host needs no consent key. That is a deliberate carve-out, not an
oversight: `home_init` writes ``cloud_llm: false`` into every install, so
requiring the key for ``localhost:11434`` would deny the default configuration on
every machine and teach operators to switch the key on permanently — which is
how a consent gate becomes a formality.

WHAT THIS DOES NOT DO
---------------------
It does not split non-loopback into private-vs-public. Every host that is not
loopback requires ``cloud_llm``, including one on your own LAN. That is
deliberate for this cut: the promise being enforced is *"nothing leaves the
machine"*, and a box across the room is off the machine. The finer split is what
``consent.lan`` is for, and enforcing that is a breaking change tracked in
docs/design/consent-toggles.md.

Resolution happens here, at gate time, and the connection happens later inside
the pipeline — so a hostname that resolves differently in between is not caught.
That is a real limit, stated rather than papered over; it is strictly better than
the previous behaviour of not looking at all, and closing it properly means a
post-resolution check at the socket, which is the vendored library's business.
"""

from __future__ import annotations

from typing import Optional

# The detection half, from its home. `_addresses` is re-exported too so any
# caller that reached for it by this path keeps working; it is the Forge's.
from forge.model_egress import (  # noqa: F401
    DEFAULT_MODEL_HOST,
    MODEL_HOST_ENV,
    _addresses,
    is_local_host,
    model_host,
)


def denial(tool_name: str = "this tool") -> Optional[dict]:
    """None when model inference is permitted, else an error dict saying why.

    Mirrors `web_egress.egress_denial` in shape: the denial names the key that is
    missing and the file the operator edits, because a gate that only says "no"
    trains people to route around it.
    """
    from . import consent

    host = model_host()
    if is_local_host(host):
        return None

    if not consent.cloud_llm_permitted():
        return {"error": (
            f"cloud_llm_denied: {tool_name} would send content to a model at "
            f"{host}, which is not on this machine. That requires the operator's "
            f"standing 'consent.cloud_llm' in {consent.settings_path()}. "
            f"It is not granted by 'consent.internet' — inference on your "
            f"documents is a separate decision from web access, and is granted "
            f"on its own line. To keep inference local instead, unset "
            f"{MODEL_HOST_ENV} (or point it at localhost) and no consent key is "
            "needed.")}
    return None
