"""knowledge_embed: tick receipt + ingest extras without a live Postgres/Ollama."""
from __future__ import annotations

from willow_mcp import knowledge_embed as kemb
from willow_mcp.nest import embed


class _Col:
    def __init__(self, name, data_type="text"):
        self.name = name
        self.data_type = data_type


class _Cur:
    def __init__(self, conn):
        self._conn = conn
        self._rows = []

    def execute(self, sql, params=None):
        self._conn.executed.append((sql, params))
        sql_l = sql.lower()
        if "information_schema.columns" in sql_l:
            self._rows = [(c.name, c.data_type) for c in self._conn.columns]
        elif "count(*)" in sql_l:
            self._rows = [(self._conn.null_embed_count,)]
        elif sql_l.strip().startswith("select"):
            self._rows = list(self._conn.select_rows)
        else:
            self._rows = []
            if "update" in sql_l:
                self._conn.updates += 1

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def close(self):
        pass


class _Conn:
    def __init__(self, columns, select_rows=None, null_embed_count=0):
        self.columns = columns
        self.select_rows = select_rows or []
        self.null_embed_count = null_embed_count
        self.executed = []
        self.updates = 0

    def cursor(self):
        return _Cur(self)

    def commit(self):
        pass

    def rollback(self):
        pass


def test_vec_literal_and_sha():
    assert kemb.vec_literal([1.0, 2.5]) == "[1.0,2.5]"
    assert len(kemb.content_sha("hi")) == 64


def test_ingest_embed_values_empty_without_column(monkeypatch):
    monkeypatch.setattr(embed, "available", lambda model="x": True)
    monkeypatch.setattr(embed, "embed_document", lambda t, model="x": [0.1] * 8)
    assert kemb.ingest_embed_values("hello", {}) == {}


def test_ingest_embed_values_when_ollama_up(monkeypatch):
    monkeypatch.setattr(embed, "available", lambda model="x": True)
    monkeypatch.setattr(embed, "embed_document", lambda t, model="x": [0.25, 0.5])
    cols = {
        "embedding": "embedding",
        "embedding_model": "embedding_model",
        "content_sha": "content_sha",
    }
    out = kemb.ingest_embed_values("hello", cols, model="nomic-embed-text")
    assert out["embedding"] == "[0.25,0.5]"
    assert out["embedding_model"] == "nomic-embed-text"
    assert out["content_sha"] == kemb.content_sha("hello")


def test_tick_unreachable_without_column(monkeypatch):
    from willow_mcp import schema_profile as sp

    monkeypatch.setattr(sp, "introspect", lambda conn, table: [_Col("id"), _Col("content")])
    conn = _Conn([])
    r = kemb.run_embed_tick(conn, budget_s=5, limit=10)
    assert r["status"] == "unreachable"
    assert "embedding column" in r["reason"]


def test_tick_empty_when_no_nulls(monkeypatch):
    from willow_mcp import schema_profile as sp

    cols = [_Col("id"), _Col("content"), _Col("embedding", "USER-DEFINED")]
    monkeypatch.setattr(sp, "introspect", lambda conn, table: cols)
    monkeypatch.setattr(embed, "available", lambda model="x": True)
    conn = _Conn(cols, select_rows=[])
    r = kemb.run_embed_tick(conn, budget_s=5, limit=10)
    assert r["status"] == "empty"
    assert r["embedded"] == 0


def test_tick_ok_embeds_batch(monkeypatch):
    from willow_mcp import schema_profile as sp

    cols = [
        _Col("id"), _Col("content"),
        _Col("embedding", "USER-DEFINED"),
        _Col("embedding_model"), _Col("content_sha"),
    ]
    monkeypatch.setattr(sp, "introspect", lambda conn, table: cols)
    monkeypatch.setattr(embed, "available", lambda model="x": True)
    monkeypatch.setattr(embed, "embed_document", lambda t, model="x": [0.1] * 4)
    conn = _Conn(cols, select_rows=[("A1", "alpha"), ("A2", "beta")])
    r = kemb.run_embed_tick(conn, budget_s=30, limit=64)
    assert r["status"] == "ok"
    assert r["embedded"] == 2
    assert r["more"] is False
    assert conn.updates == 2
    assert any("::vector" in sql for sql, _ in conn.executed if isinstance(sql, str))


def test_tick_skips_failed_embed_and_continues(monkeypatch):
    from willow_mcp import schema_profile as sp

    cols = [
        _Col("id"), _Col("content"),
        _Col("embedding", "USER-DEFINED"),
        _Col("embedding_model"), _Col("content_sha"),
    ]
    monkeypatch.setattr(sp, "introspect", lambda conn, table: cols)
    monkeypatch.setattr(embed, "available", lambda model="x": True)

    def _doc(text, model="x"):
        if "bad" in text:
            return None
        return [0.2] * 4

    monkeypatch.setattr(embed, "embed_document", _doc)
    conn = _Conn(cols, select_rows=[("A1", "good one"), ("A2", "bad row"), ("A3", "also good")])
    r = kemb.run_embed_tick(conn, budget_s=30, limit=64)
    assert r["status"] == "ok"
    assert r["embedded"] == 2
    assert r["skipped"] == 1
    assert r["stopped"] != "unreachable"
    select_sql = next(
        sql for sql, _ in conn.executed
        if isinstance(sql, str) and "LIMIT" in sql.upper() and "IS NULL" in sql.upper()
    )
    assert "skip:%%" in select_sql
