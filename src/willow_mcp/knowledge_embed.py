"""Knowledge-base embedding: Ollama vectors on Postgres ``knowledge``.

Optional columns (discovered by introspection — never required for ILIKE):

* ``embedding`` — ``vector(768)`` (nomic-embed-text)
* ``embedding_model`` — text tag that produced the vector
* ``content_sha`` — sha256 of content; tick / ingest skip stale rows

Confirmed schema mappings stay on the five core ``KNOWLEDGE_FIELDS``; embed
columns are additive and only used when present. Search prefers cosine when
a query vector and stored vectors exist, otherwise ILIKE (never collapses
unreachable into empty).
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Optional

from .nest import embed as _embed

EMBED_DIM = 768
DEFAULT_MODEL = _embed.DEFAULT_EMBED_MODEL

# Exact column names we write/read when introspection finds them.
COL_EMBEDDING = "embedding"
COL_MODEL = "embedding_model"
COL_SHA = "content_sha"


def content_sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def vec_literal(vec: list[float]) -> str:
    """pgvector text form accepted by ``%s::vector`` without the pgvector wheel."""
    return "[" + ",".join(repr(float(x)) for x in vec) + "]"


def discover_embed_cols(conn) -> dict[str, Optional[str]]:
    """Return ``{embedding, embedding_model, content_sha}`` → column name or None."""
    from . import schema_profile as sp

    by_name = {c.name: c for c in sp.introspect(conn, "knowledge")}
    out = {
        COL_EMBEDDING: COL_EMBEDDING if COL_EMBEDDING in by_name else None,
        COL_MODEL: COL_MODEL if COL_MODEL in by_name else None,
        COL_SHA: COL_SHA if COL_SHA in by_name else None,
    }
    return out


def try_embed_document(text: str, model: str = DEFAULT_MODEL) -> Optional[list[float]]:
    if not (text or "").strip():
        return None
    if not _embed.available(model):
        return None
    return _embed.embed_document(text, model=model)


def try_embed_query(text: str, model: str = DEFAULT_MODEL) -> Optional[list[float]]:
    if not (text or "").strip():
        return None
    if not _embed.available(model):
        return None
    return _embed.embed_query(text, model=model)


def ingest_embed_values(
    content: str,
    embed_cols: dict[str, Optional[str]],
    *,
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    """Extra column→value pairs for INSERT when embed columns exist.

    Keys are *column names* (not canonical fields). Empty dict when the
    table has no embedding column or Ollama is unreachable — ILIKE path
    stays valid either way.
    """
    emb_col = embed_cols.get(COL_EMBEDDING)
    if not emb_col:
        return {}
    vec = try_embed_document(content, model=model)
    if not vec:
        return {}
    out: dict[str, Any] = {emb_col: vec_literal(vec)}
    if embed_cols.get(COL_MODEL):
        out[embed_cols[COL_MODEL]] = model
    if embed_cols.get(COL_SHA):
        out[embed_cols[COL_SHA]] = content_sha(content)
    return out


def run_embed_tick(
    conn,
    *,
    budget_s: float = 30.0,
    limit: int = 64,
    model: str = DEFAULT_MODEL,
    domain: str = "",
) -> dict[str, Any]:
    """Fill NULL / missing embeddings under a wall-clock budget.

    Receipt: ``ok`` / ``empty`` / ``unreachable`` (plus ``more`` when the
    limit capped the batch).
    """
    started = time.monotonic()
    budget_s = max(0.0, float(budget_s))
    limit = max(0, int(limit))
    cols = discover_embed_cols(conn)
    receipt: dict[str, Any] = {
        "status": "unreachable",
        "backend": "ollama",
        "model": model,
        "embedded": 0,
        "skipped": 0,
        "candidates": 0,
        "remaining": 0,
        "stopped": "unreachable",
        "more": False,
        "budget_s": budget_s,
        "elapsed_s": 0.0,
        "reason": "",
        "columns": {k: v for k, v in cols.items() if v},
    }

    if not cols.get(COL_EMBEDDING):
        receipt["reason"] = (
            "knowledge table has no embedding column — apply "
            "docs/schema/knowledge_embed.migrate.sql (or recreate from "
            "knowledge.postgres.sql)"
        )
        receipt["elapsed_s"] = round(time.monotonic() - started, 3)
        return receipt

    if not _embed.available(model):
        receipt["reason"] = (
            f"Ollama unreachable or model {model!r} not installed "
            f"(OLLAMA_HOST / NEST_EMBED_MODEL)"
        )
        receipt["elapsed_s"] = round(time.monotonic() - started, 3)
        return receipt

    emb_col = cols[COL_EMBEDDING]
    sha_col = cols.get(COL_SHA)
    model_col = cols.get(COL_MODEL)

    # Candidates: NULL embedding, non-blank content. Blank rows can never embed
    # (nest.embed returns None on empty) and must not abort the tick.
    where = (
        f'"{emb_col}" IS NULL'
        f" AND length(trim(coalesce(\"content\"::text, ''))) > 0"
    )
    # Rows we already marked unembeddable stay out until cleared.
    # Literal % must be %% so psycopg2 does not treat it as a bind placeholder.
    if model_col:
        where += (
            f' AND coalesce("{model_col}", \'\') NOT LIKE \'skip:%%\''
        )
    params: list[Any] = []
    if domain:
        where += ' AND "domain" = %s'
        params.append(domain)
    if limit == 0 or budget_s == 0.0:
        count_params: list[Any] = []
        count_sql = f'SELECT count(*) FROM knowledge WHERE {where}'
        if domain:
            count_params.append(domain)
        cur = conn.cursor()
        try:
            cur.execute(count_sql, count_params)  # nosec B608
            n = int(cur.fetchone()[0])
        finally:
            cur.close()
        receipt.update({
            "status": "empty" if n == 0 else "ok",
            "candidates": min(n, 1) if n else 0,
            "remaining": n,
            "stopped": "budget" if n else "done",
            "more": n > 0,
            "elapsed_s": round(time.monotonic() - started, 3),
        })
        return receipt

    sql = (
        f'SELECT "id", "content" FROM knowledge WHERE {where} '  # nosec B608
        f'ORDER BY "id" LIMIT %s'
    )
    params = list(params) + [limit]

    cur = conn.cursor()
    try:
        cur.execute(sql, params)
        rows = cur.fetchall()
    finally:
        cur.close()

    receipt["candidates"] = len(rows)
    if not rows:
        receipt.update({
            "status": "empty",
            "stopped": "done",
            "more": False,
            "elapsed_s": round(time.monotonic() - started, 3),
        })
        return receipt

    deadline = started + budget_s
    embedded = 0
    skipped = 0
    stopped = "done"
    hit_limit = len(rows) >= limit
    up = conn.cursor()
    try:
        for kid, content in rows:
            if time.monotonic() >= deadline:
                stopped = "budget"
                break
            text = content if isinstance(content, str) else (
                json.dumps(content, ensure_ascii=False) if content is not None else ""
            )
            text = (text or "").strip()
            if not text:
                skipped += 1
                continue
            vec = try_embed_document(text, model=model)
            if not vec:
                # One bad surface must not kill the tick. If Ollama is gone,
                # stop; otherwise mark the row skip:failed so it does not
                # monopolize every later pass.
                if not _embed.available(model):
                    receipt["reason"] = (
                        f"Ollama became unreachable after {embedded} embeds "
                        f"(last id={kid!r})"
                    )
                    stopped = "unreachable"
                    break
                skipped += 1
                if model_col:
                    up.execute(
                        f'UPDATE knowledge SET "{model_col}" = %s WHERE "id" = %s',  # nosec B608
                        ("skip:failed", kid),
                    )
                continue
            sets = [f'"{emb_col}" = %s::vector']
            vals: list[Any] = [vec_literal(vec)]
            if model_col:
                sets.append(f'"{model_col}" = %s')
                vals.append(model)
            if sha_col:
                sets.append(f'"{sha_col}" = %s')
                vals.append(content_sha(text))
            vals.append(kid)
            up.execute(
                f'UPDATE knowledge SET {", ".join(sets)} WHERE "id" = %s',  # nosec B608
                vals,
            )
            embedded += 1
        if not getattr(conn, "autocommit", False):
            conn.commit()
    except Exception as exc:  # noqa: BLE001 — receipt must name the failure
        try:
            conn.rollback()
        except Exception:
            pass
        receipt["reason"] = f"update failed: {type(exc).__name__}: {exc}"
        receipt["embedded"] = embedded
        receipt["skipped"] = skipped
        receipt["elapsed_s"] = round(time.monotonic() - started, 3)
        return receipt
    finally:
        up.close()

    remaining = max(0, len(rows) - embedded - skipped)
    if stopped == "done" and (remaining or hit_limit):
        stopped = "limit"
    if stopped == "unreachable":
        receipt.update({
            "status": "unreachable",
            "embedded": embedded,
            "skipped": skipped,
            "remaining": remaining,
            "stopped": stopped,
            "more": True,
            "elapsed_s": round(time.monotonic() - started, 3),
        })
        return receipt

    receipt.update({
        "status": "ok" if embedded or skipped else "empty",
        "embedded": embedded,
        "skipped": skipped,
        "remaining": remaining,
        "stopped": stopped,
        "more": bool(hit_limit or remaining),
        "elapsed_s": round(time.monotonic() - started, 3),
        "reason": (
            f"skipped {skipped} unembeddable row(s) (marked embedding_model=skip:failed)"
            if skipped and not embedded
            else (f"skipped {skipped} unembeddable row(s)" if skipped else "")
        ),
    })
    return receipt

def search_semantic(
    conn,
    *,
    select_clause: str,
    present: list[str],
    unmapped: list[str],
    fields: dict,
    query: str,
    domain: Optional[str],
    limit: int,
    retract_sql: str,
    retract_params: list,
    model: str = DEFAULT_MODEL,
) -> Optional[dict[str, Any]]:
    """Cosine search when embedding column + Ollama exist; else None (caller ILIKE).

    Returns a result dict shaped like ``knowledge_search`` plus ``search_mode``,
    or ``None`` when semantic cannot run (no column / no vector / ollama down).
    """
    cols = discover_embed_cols(conn)
    emb_col = cols.get(COL_EMBEDDING)
    if not emb_col:
        return None

    qvec = try_embed_query(query, model=model)
    if not qvec:
        return {
            "results": [],
            "search_mode": "unreachable",
            "reason": "query embed unavailable (Ollama or model)",
            "_fallback": "ilike",
        }

    # Only project core mapped columns; never SELECT embedding into the atom.
    content_col = fields.get("content", {}).get("column")
    id_col = fields.get("id", {}).get("column")
    if not content_col or not id_col:
        return None

    sql = f'SELECT {select_clause} FROM knowledge WHERE "{emb_col}" IS NOT NULL{retract_sql}'
    params: list[Any] = list(retract_params)
    domain_col = fields.get("domain", {}).get("column")
    if domain and domain_col:
        sql += f' AND "{domain_col}" = %s'
        params.append(domain)
    sql += f' ORDER BY "{emb_col}" <=> %s::vector LIMIT %s'
    params.extend([vec_literal(qvec), limit])

    cur = conn.cursor()
    try:
        cur.execute(sql, params)  # nosec B608
        rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        try:
            conn.rollback()
        except Exception:
            pass
        return {
            "results": [],
            "search_mode": "unreachable",
            "reason": f"semantic query failed: {type(exc).__name__}: {exc}",
            "_fallback": "ilike",
        }
    finally:
        cur.close()

    if not rows:
        return {
            "results": [],
            "search_mode": "empty",
            "_fallback": "ilike",
        }

    from . import kb_curate as kbc
    from ._kb_sql import row_to_dict

    return {
        "results": [kbc.enrich_atom(row_to_dict(r, present, unmapped)) for r in rows],
        "search_mode": "semantic",
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import os

    from . import paths

    p = argparse.ArgumentParser(
        prog="willow-mcp knowledge-embed-tick",
        description="Warm knowledge.embedding under a wall-clock budget",
    )
    p.add_argument("--budget-s", type=float, default=30.0)
    p.add_argument("--limit", type=int, default=64)
    p.add_argument("--model", default="", help="default NEST_EMBED_MODEL / nomic-embed-text")
    p.add_argument("--domain", default="", help="limit to one domain")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--dsn", default="",
        help="Postgres DSN (default: WILLOW_DB_URL, else same as get_pg — "
             "WILLOW_PG_DB / settings.global.json postgres.db)",
    )
    args = p.parse_args(argv)

    try:
        import psycopg2
    except ImportError:
        print("psycopg2 required", flush=True)
        return 2

    dsn = args.dsn or os.environ.get("WILLOW_DB_URL") or os.environ.get("DATABASE_URL") or ""
    try:
        if dsn:
            conn = psycopg2.connect(dsn, connect_timeout=5)
        else:
            # Same resolution as willow_mcp.db.get_pg — never hardcode "willow".
            conn = psycopg2.connect(
                dbname=paths.pg_db(),
                user=os.environ.get("WILLOW_PG_USER", os.environ.get("USER", "")),
                connect_timeout=5,
            )
        conn.autocommit = True
    except Exception as exc:
        dbhint = paths.pg_db() if not dsn else dsn
        print(json.dumps({
            "status": "unreachable",
            "reason": (
                f"postgres: {type(exc).__name__}: {exc} "
                f"(resolved={dbhint!r}; set WILLOW_HOME or WILLOW_PG_DB=willow_20)"
            ),
        }, indent=2) if args.json else (
            f"knowledge-embed-tick unreachable: postgres: {exc} "
            f"(resolved={dbhint!r}; set WILLOW_HOME or WILLOW_PG_DB=willow_20)"
        ))
        return 1

    try:
        receipt = run_embed_tick(
            conn,
            budget_s=args.budget_s,
            limit=args.limit,
            model=args.model or DEFAULT_MODEL,
            domain=args.domain or "",
        )
    finally:
        conn.close()

    human = (
        f"knowledge-embed-tick {receipt['status']}: model={receipt['model']!r} "
        f"embedded={receipt['embedded']}/{receipt['candidates']} "
        f"skipped={receipt.get('skipped', 0)} "
        f"remaining={receipt['remaining']} stopped={receipt['stopped']} "
        f"more={receipt['more']} elapsed_s={receipt['elapsed_s']}"
    )
    if receipt.get("reason"):
        human += f"\n  reason: {receipt['reason']}"
    print(json.dumps(receipt, indent=2) if args.json else human)
    return 1 if receipt["status"] == "unreachable" else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
