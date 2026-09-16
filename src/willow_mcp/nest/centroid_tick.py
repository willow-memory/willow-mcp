"""Bounded warm of nest taxonomy centroids (Ollama nomic-embed-text).

``nest_scan`` embeds category exemplars on first use and caches them under
``NEST_CACHE_DIR`` (default ``~/.cache/nest-seed``). A cold cache makes the
first personal scan pay that cost synchronously. ``run_centroid_tick`` moves
the warm onto a deliberate pass — same three-state receipt as Nestor's
``embed-tick``.

* ``ok`` — centroids built and written (or rebuilt with ``force``).
* ``empty`` — current cache already present for this model + exemplar hash.
* ``unreachable`` — Ollama / model not usable; nothing written.
"""
from __future__ import annotations

import json
import time
from typing import Any

from . import embed as _embed
from . import taxonomy


def _write_cache(cache, centroids: dict[str, list[float]]) -> None:
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(centroids))


def run_centroid_tick(
    *,
    model: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Warm nest category centroids in one pass (fixed exemplar set)."""
    started = time.monotonic()
    model = model or _embed.DEFAULT_EMBED_MODEL
    cache = taxonomy._cache_path(model)
    receipt: dict[str, Any] = {
        "status": "unreachable",
        "backend": "ollama",
        "model": model,
        "cache_path": str(cache),
        "categories": 0,
        "force": force,
        "stopped": "unreachable",
        "elapsed_s": 0.0,
        "reason": "",
    }

    if not force and cache.exists():
        try:
            data = json.loads(cache.read_text())
            if isinstance(data, dict) and data:
                receipt.update({
                    "status": "empty",
                    "categories": len(data),
                    "stopped": "done",
                    "elapsed_s": round(time.monotonic() - started, 3),
                })
                return receipt
        except (OSError, ValueError):
            pass

    if not _embed.available(model):
        receipt["reason"] = (
            f"Ollama unreachable or model {model!r} not installed "
            f"(OLLAMA_HOST / NEST_EMBED_MODEL)"
        )
        receipt["elapsed_s"] = round(time.monotonic() - started, 3)
        return receipt

    if force:
        centroids = taxonomy.build_centroids(model=model, use_cache=False)
        if not centroids:
            receipt["reason"] = "forced rebuild failed (embed returned nothing)"
            receipt["elapsed_s"] = round(time.monotonic() - started, 3)
            return receipt
        try:
            _write_cache(cache, centroids)
        except OSError as exc:
            receipt["reason"] = f"could not write cache: {exc}"
            receipt["elapsed_s"] = round(time.monotonic() - started, 3)
            return receipt
    else:
        centroids = taxonomy.build_centroids(model=model, use_cache=True)
        if not centroids:
            receipt["reason"] = "centroid build returned nothing (embed failed mid-pass)"
            receipt["elapsed_s"] = round(time.monotonic() - started, 3)
            return receipt

    receipt.update({
        "status": "ok",
        "categories": len(centroids),
        "stopped": "done",
        "elapsed_s": round(time.monotonic() - started, 3),
        "reason": "",
    })
    return receipt


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="willow-mcp nest-centroid-tick",
        description="Warm nest taxonomy centroids (Ollama) under a three-state receipt",
    )
    p.add_argument("--model", default="", help="embed model (default: NEST_EMBED_MODEL)")
    p.add_argument("--force", action="store_true",
                   help="rebuild even when a current cache file exists")
    p.add_argument("--json", action="store_true", help="machine-readable receipt")
    args = p.parse_args(argv)

    receipt = run_centroid_tick(
        model=args.model or None,
        force=args.force,
    )
    human = (
        f"nest-centroid-tick {receipt['status']}: model={receipt['model']!r} "
        f"categories={receipt['categories']} stopped={receipt['stopped']} "
        f"elapsed_s={receipt['elapsed_s']} cache={receipt['cache_path']}"
    )
    if receipt.get("reason"):
        human += f"\n  reason: {receipt['reason']}"
    if args.json:
        print(json.dumps(receipt, indent=2))
    else:
        print(human)
    return 1 if receipt["status"] == "unreachable" else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
