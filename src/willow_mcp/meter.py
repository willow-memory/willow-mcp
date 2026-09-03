"""willow_mcp/meter.py — joules per tool call, from the machine's own counters.

Move one of the fleet plan (made-by-willow/2026-09-03-fleet-vs-complaints).
Stdlib only. Never raises into the call it measures. Never fails open: when a
counter is absent the row says ``unmetered`` — a class nothing measured is
named *unseen*, never *sound* (Forge, measure_panel).

WHAT IS MEASURED
----------------
* CPU package energy from Intel RAPL — ``/sys/class/powercap/intel-rapl:0/energy_uj``
  (plus ``intel-rapl:0:N`` subzones named ``dram`` when present). This is an
  energy COUNTER, so before/after is exact, not sampled. Wraps at
  ``max_energy_range_uj``; handled.
* GPU energy from ``nvidia-smi --query-gpu=total_energy_consumption`` (mJ), a
  counter on drivers that expose it; otherwise ``power.draw`` (W) sampled at
  start and end, times elapsed — labeled ``approx`` in the row so the two are
  never confused.
* Wall-clock seconds.

WHAT IS NOT
-----------
Tokens. The generative and embedding seams are vendored byte-for-byte from
nest-pipeline (see model_egress.py, "why the gate is here and not at the
post"), so this module does not reach into them. Ollama already returns
``prompt_eval_count`` / ``eval_count`` in its response; surfacing those is a
consumer-side change in nest/classify's caller, tracked as the follow-up. Until
then ``tokens`` is reported as ``unseen``.

PERMISSIONS
-----------
RAPL is root-readable only on many kernels since 5.10 (CVE-2020-8694). Either
``chmod a+r`` the ``energy_uj`` files via a udev rule, or run willow-mcp's
worker under a group that can read them. When unreadable the row says so.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

_RAPL_ROOT = Path("/sys/class/powercap")


def _read_int(p: Path) -> Optional[int]:
    try:
        return int(p.read_text().strip())
    except (OSError, ValueError):
        return None


def _rapl_zones() -> list[tuple[str, Path, int]]:
    """(name, energy_uj path, max_range) for every readable RAPL zone.

    Only top-level packages and ``dram`` subzones — ``core``/``uncore`` are
    subsets of the package and would double-count.
    """
    zones = []
    if not _RAPL_ROOT.exists():
        return zones
    for d in sorted(_RAPL_ROOT.glob("intel-rapl:*")):
        name_f, energy_f, max_f = d / "name", d / "energy_uj", d / "max_energy_range_uj"
        try:
            name = name_f.read_text().strip()
        except OSError:
            continue
        top_level = d.name.count(":") == 1
        if not (top_level or name == "dram"):
            continue
        e = _read_int(energy_f)
        if e is None:
            continue
        zones.append((f"{d.name}:{name}", energy_f, _read_int(max_f) or (1 << 62)))
    return zones


def _rapl_read(zones) -> dict[str, int]:
    out = {}
    for name, path, _ in zones:
        v = _read_int(path)
        if v is not None:
            out[name] = v
    return out


def _nvidia_query(field: str) -> Optional[float]:
    if not shutil.which("nvidia-smi"):
        return None
    try:
        r = subprocess.run(
            ["nvidia-smi", f"--query-gpu={field}", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=2.0,
        )
        if r.returncode != 0:
            return None
        return float(r.stdout.strip().splitlines()[0])
    except (subprocess.SubprocessError, ValueError, IndexError, OSError):
        return None


class Meter:
    """``with Meter() as m: ...; m.row`` → a dict for the receipt's detail."""

    def __init__(self) -> None:
        self.row: dict = {}
        self._zones = _rapl_zones()
        self._t0 = 0.0
        self._cpu0: dict[str, int] = {}
        self._gpu_mj0: Optional[float] = None
        self._gpu_w0: Optional[float] = None

    def __enter__(self) -> "Meter":
        self._t0 = time.monotonic()
        self._cpu0 = _rapl_read(self._zones)
        self._gpu_mj0 = _nvidia_query("total_energy_consumption")
        if self._gpu_mj0 is None:
            self._gpu_w0 = _nvidia_query("power.draw")
        return self

    def __exit__(self, *exc) -> bool:
        try:
            self._finish()
        except Exception:  # a meter must never break the call it measures
            self.row = {"meter": "error"}
        return False  # never swallow the call's own exception

    def _finish(self) -> None:
        elapsed = max(time.monotonic() - self._t0, 0.0)
        row: dict = {"elapsed_s": round(elapsed, 4)}

        # CPU (exact, counter-based)
        cpu_j = 0.0
        seen = False
        now = _rapl_read(self._zones)
        for name, _, max_range in self._zones:
            a, b = self._cpu0.get(name), now.get(name)
            if a is None or b is None:
                continue
            seen = True
            delta = b - a if b >= a else (max_range - a) + b  # counter wrap
            cpu_j += delta / 1e6
        row["cpu_j"] = round(cpu_j, 3) if seen else "unmetered"

        # GPU (counter if the driver has it, else power × time, labeled)
        if self._gpu_mj0 is not None:
            mj1 = _nvidia_query("total_energy_consumption")
            row["gpu_j"] = round((mj1 - self._gpu_mj0) / 1e3, 3) if mj1 is not None else "unmetered"
            row["gpu_method"] = "counter"
        elif self._gpu_w0 is not None:
            w1 = _nvidia_query("power.draw")
            if w1 is not None:
                row["gpu_j"] = round(((self._gpu_w0 + w1) / 2.0) * elapsed, 3)
                row["gpu_method"] = "approx"
            else:
                row["gpu_j"] = "unmetered"
        else:
            row["gpu_j"] = "unmetered"

        # Where the model is, and which one — from configuration, not the call.
        # Detection primitive is the Forge's (model_egress); policy stays in
        # willow-mcp. Tokens are deliberately unseen (see module docstring).
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        try:
            from forge.model_egress import is_local_host  # willow depends on the engine
            row["model_host"] = "local" if is_local_host(host) else "remote"
        except Exception:
            row["model_host"] = "unseen"
        row["model"] = os.environ.get("WILLOW_OLLAMA_MODEL") or "unseen"
        row["tokens"] = "unseen"
        self.row = row
