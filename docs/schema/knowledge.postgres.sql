-- willow-mcp — knowledge table (fresh install)
--
-- willow-mcp ADAPTS to an existing `knowledge` table when one is present (see
-- docs/design/schema-adaptation.md); this DDL is for a fresh install that has
-- no such table yet. Columns match the canonical _KNOWLEDGE_FIELDS the server
-- maps (server.py: id, content, domain, source, tags). A host table that names
-- these columns differently is fine — the schema profiler resolves aliases and
-- omits anything it can't map; this file just gives a fresh DB the happy path.
--
-- Optional embedding columns (pgvector) are NOT in this fresh-install DDL —
-- stock Postgres (including CI's postgres:15 service) has no `vector` type, and
-- bootstrap applies this file with ON_ERROR_STOP=1. Apply
-- docs/schema/knowledge_embed.migrate.sql when pgvector is available; ingest /
-- tick / search discover those columns by introspection and fall back to ILIKE
-- when they are absent.
--
-- After creating it, confirm the mapping once (writes stay locked until you do):
--   schema_confirm_mapping(app_id=..., table="knowledge")
-- then knowledge_ingest / kb_* / knowledge_search resolve against it.
--
-- Read path: knowledge_search prefers cosine when embedding is populated;
-- otherwise `content ILIKE %keyword%` (AND across tokens), optionally filtered
-- by `domain`. Write path: knowledge_ingest does INSERT ... ON CONFLICT DO
-- NOTHING; when Ollama is up and embed columns exist it also fills embedding.
-- `tags` is written as JSON.

CREATE TABLE IF NOT EXISTS knowledge (
    id               text PRIMARY KEY,
    content          text  NOT NULL,
    domain           text  NOT NULL DEFAULT 'general',
    source           text  NOT NULL DEFAULT '',
    tags             jsonb NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_knowledge_domain ON knowledge (domain);
