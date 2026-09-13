"""Out-of-band operator presence via desktop pinentry.

SessionStart (and later Kart-brokered acts) need a proof that a human is
present which is *not* ``sys.stdin.isatty()``. An owned tty is forgeable by
any local process that can allocate a pty; a pinentry dialog on the
operator's session bus is not driven by the agent chat.

Honest limit (approval-broker.md §5b): on the ed25519 keyring path the
private half is stored with ``NoEncryption()``, so the passphrase typed
here unlocks nothing. This module's job is presence, not key custody.
The entered PIN is discarded immediately and never written to logs,
sidecars, or env.

Opt-out for automated tests: ``WILLOW_PRESENCE_CHALLENGE=off`` (or
``0``/``false``/``no``) makes :func:`challenge_presence` return
``ok`` without spawning pinentry. Production desk boots leave it unset.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Literal


PresenceStatus = Literal["ok", "cancelled", "unavailable"]


@dataclass(frozen=True)
class PresenceResult:
    status: PresenceStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


_FALSEY = frozenset({"0", "false", "no", "off", ""})


def presence_challenge_enabled() -> bool:
    raw = os.environ.get("WILLOW_PRESENCE_CHALLENGE", "1").strip().lower()
    return raw not in _FALSEY


def _pinentry_binary() -> str | None:
    preferred = os.environ.get("PINENTRY_PROGRAM", "").strip()
    if preferred and shutil.which(preferred):
        return preferred
    for name in (
        "pinentry-gnome3",
        "pinentry-qt",
        "pinentry-gtk-2",
        "pinentry-x11",
        "pinentry",
    ):
        path = shutil.which(name)
        if path:
            return path
    return None


def _assuan_escape(text: str) -> str:
    """Percent-encode Assuan specials so DESC/PROMPT survive the wire."""
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if ch in "%\r\n" or o < 0x20:
            out.append(f"%{o:02X}")
        else:
            out.append(ch)
    return "".join(out)


def challenge_presence(
    *,
    title: str = "Willow session attestation",
    description: str = "Confirm you are present to attest this orchestrator session.",
    prompt: str = "Attestation passphrase:",
    timeout_s: float = 120.0,
) -> PresenceResult:
    """Open a desktop pinentry and wait for OK / cancel / failure.

    Returns ``ok`` when the operator completes GETPIN (any non-empty or
    empty confirmation that pinentry accepts — we do not validate the
    passphrase against a key). ``cancelled`` on user abort. ``unavailable``
    when no pinentry binary, no display/session bus, or the dialog cannot
    start.
    """
    if not presence_challenge_enabled():
        return PresenceResult("ok", "WILLOW_PRESENCE_CHALLENGE disabled")

    binary = _pinentry_binary()
    if binary is None:
        return PresenceResult(
            "unavailable",
            "no pinentry binary on PATH (install pinentry-gnome3 or set PINENTRY_PROGRAM)",
        )

    display = os.environ.get("DISPLAY", "").strip()
    wayland = os.environ.get("WAYLAND_DISPLAY", "").strip()
    dbus = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "").strip()
    if not display and not wayland and not dbus:
        return PresenceResult(
            "unavailable",
            "no DISPLAY/WAYLAND_DISPLAY/DBUS_SESSION_BUS_ADDRESS — cannot open desktop pinentry",
        )

    script = (
        f"SETTITLE {_assuan_escape(title)}\n"
        f"SETDESC {_assuan_escape(description)}\n"
        f"SETPROMPT {_assuan_escape(prompt)}\n"
        "GETPIN\n"
        "BYE\n"
    )
    try:
        proc = subprocess.run(
            [binary],
            input=script,
            text=True,
            capture_output=True,
            timeout=timeout_s,
            env=os.environ.copy(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return PresenceResult("cancelled", f"pinentry timed out after {timeout_s:.0f}s")
    except OSError as exc:
        return PresenceResult("unavailable", f"pinentry spawn failed: {exc}")

    # Assuan replies: "D <pin>" then "OK" on success; "ERR ... " on cancel.
    # Never retain the PIN line — strip D-payloads before any logging surface.
    lines = [
        line
        for line in (proc.stdout or "").splitlines()
        if not line.startswith("D ")
    ]
    joined = "\n".join(lines)
    err_lines = [
        line
        for line in (proc.stderr or "").splitlines()
        if line.strip()
    ]

    if any(line.startswith("ERR ") for line in lines):
        err = next(line for line in lines if line.startswith("ERR "))
        # Common cancel codes from pinentry: 83886179 (canceled)
        return PresenceResult("cancelled", err[4:].strip() or "pinentry cancelled")

    # Success path: GETPIN answered OK (with or without a D-line we discarded).
    # Require at least one OK after SET* commands; a binary that only greets
    # and dies must not count as presence.
    ok_count = sum(1 for line in lines if line == "OK" or line.startswith("OK "))
    if proc.returncode == 0 and ok_count >= 2:
        return PresenceResult("ok", f"pinentry via {os.path.basename(binary)}")

    detail = joined.strip() or (err_lines[0] if err_lines else f"exit {proc.returncode}")
    return PresenceResult("unavailable", f"pinentry did not complete GETPIN: {detail}")
