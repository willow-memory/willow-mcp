"""
nest-seed/ingest.py — walk a folder, OCR/extract, classify, write to Nest DB.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:  # works both as a package (apps.nest_seed) and as a plain script dir
    from . import db as _db
    from . import ocr as _ocr
    from . import classify as _classify
    from . import llm as _llm
    from . import taxonomy as _tax
    from . import selflearn as _learn
except ImportError:
    import db as _db
    import ocr as _ocr
    import classify as _classify
    import llm as _llm
    import taxonomy as _tax
    import selflearn as _learn

_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp"}


def run(folder: Path, db_path: Path, owner: str, dry_run: bool = False,
        verbose: bool = False, use_llm: bool = False, use_embed: bool = True,
        text_model: str | None = None, vision_model: str | None = None,
        embed_model: str | None = None, learn: bool = False,
        discover: int = 0, promote: bool = False) -> dict:
    conn = None if dry_run else _db.open_db(db_path)
    if conn:
        _db.init_meta(conn, owner=owner, description=f"Seeded from {folder}")

    model = embed_model or _tax._embed.DEFAULT_EMBED_MODEL

    # Build category centroids once for the whole run (cached to disk). Adaptive
    # centroids fold in anything previously learned — identical to the static
    # exemplar centroids until the user has confirmed files.
    centroids = None
    if use_embed:
        centroids = _learn.build_adaptive_centroids(model=model)
        if verbose:
            print(f"  [embed] centroids: {'built ('+str(len(centroids))+' categories)' if centroids else 'unavailable — embedding tier off'}",
                  file=sys.stderr)

    # Recorder collects per-doc observations (reusing the embedding the
    # classifier already computes) for self-learning and clustering discovery,
    # and every tier-3 escalation when the LLM tier is on — the escalation log
    # accumulates from normal operation, not only from a --learn run.
    recorder = _learn.Recorder() if (learn or discover or promote or use_llm) else None

    supported = _ocr.supported_suffixes()
    files = [p for p in sorted(folder.rglob("*"))
             if p.is_file() and p.suffix.lower() in supported]

    counts = {"files": 0, "extracted": 0, "failed": 0, "fragments": 0, "skipped": 0}

    for path in files:
        counts["files"] += 1
        if verbose:
            print(f"  [{counts['files']}/{len(files)}] {path.relative_to(folder)}", file=sys.stderr)

        text, method = _ocr.extract(path)
        is_image = path.suffix.lower() in _IMAGE_EXTS

        # When OCR is unavailable for an image but local vision is on, we can
        # still classify it from pixels — don't skip it.
        vision_rescue = use_llm and is_image and method.startswith("missing:")

        if (method.startswith("missing:") or method == "unsupported") and not vision_rescue:
            counts["skipped"] += 1
            if conn:
                sid = _db.add_source(conn, path, mime_hint=path.suffix.lower())
                _db.update_source_status(conn, sid, "skipped", ocr_method=method)
            continue

        if any(method.startswith(p) for p in ("read_error", "ocr_error", "pdf_error", "docx_error")):
            counts["failed"] += 1
            if conn:
                sid = _db.add_source(conn, path, mime_hint=path.suffix.lower())
                _db.update_source_status(conn, sid, "failed", ocr_method=method, error=method)
            continue

        counts["extracted"] += 1
        sink = None
        esc_sink = None
        if recorder is not None:
            key = _db.file_hash(path)
            sink = recorder.sink_for(key=key, snippet=text[:140])
            esc_sink = recorder.escalation_sink_for(key=key)
        frags = _classify.classify(text, filename=path.name, path=path,
                                   use_llm=use_llm, use_embed=use_embed,
                                   centroids=centroids, text_model=text_model,
                                   vision_model=vision_model, embed_model=embed_model,
                                   learn_sink=sink, escalation_sink=esc_sink)
        counts["fragments"] += len(frags)

        if verbose:
            tag = "vision" if vision_rescue else method
            print(f"    OK  {tag} → {len(frags)} fragments", file=sys.stderr)

        if dry_run:
            for f in frags:
                lab = f" «{f.label}»" if f.label else ""
                print(f"  {f.fragment_type:10}{lab:14} [{f.confidence:11}] {f.content[:80]!r}")
            continue

        sid = _db.add_source(conn, path, mime_hint=path.suffix.lower())
        ocr_label = "vision" if vision_rescue else method
        _db.update_source_status(conn, sid, "extracted", ocr_method=ocr_label, char_count=len(text))
        for f in frags:
            _db.add_fragment(conn, source_id=sid, fragment_type=f.fragment_type,
                             content=f.content, label=f.label, confidence=f.confidence,
                             date_ref=f.date_ref)

    if conn:
        counts["db_stats"] = _db.stats(conn)
        conn.close()

    # Escalation log, three-state: off (LLM tier not requested), on with a count
    # (possibly zero — every doc resolved on the embedding tier), or on and the
    # log itself could not be written. Written even on a dry run: the tuple was
    # computed and the teacher was paid for either way.
    if recorder is None or not use_llm:
        counts["escalations"] = {"state": "off", "escalated": 0, "logged": 0}
    else:
        escalated = len(recorder.escalations)
        unanswered = sum(1 for r in recorder.escalations if r.get("verdict") is None)
        flushed = recorder.flush_escalations(text_model or _llm.DEFAULT_TEXT_MODEL)
        counts["escalations"] = {
            "state": "unreachable" if flushed.get("error") else "on",
            "escalated": escalated,
            "unanswered": unanswered,
            "logged": flushed.get("logged", 0),
            "path": flushed.get("path"),
            **({"error": flushed["error"]} if flushed.get("error") else {}),
        }
        if verbose:
            print(f"  [escalations] {counts['escalations']}", file=sys.stderr)

    # Fold this run's confident classifications into the learned centroids, so
    # the next run starts adapted to the user's own documents.
    if recorder is not None and learn:
        counts["learned"] = recorder.flush_learned(model)
        if verbose:
            print(f"  [learn] {counts['learned']}", file=sys.stderr)

    # Surface candidate categories from the uncertain tail (report-only).
    if recorder is not None and discover:
        counts["discovery"] = _learn.discover(recorder.tail, k=discover)
        if verbose:
            print(f"  [discover] {counts['discovery']}", file=sys.stderr)

    # Promote qualifying tail clusters into new persisted categories.
    if recorder is not None and promote:
        counts["promotion"] = _learn.promote_clusters(
            model, recorder.tail, k=(discover or 8))
        if verbose:
            print(f"  [promote] {counts['promotion']}", file=sys.stderr)

    return counts
