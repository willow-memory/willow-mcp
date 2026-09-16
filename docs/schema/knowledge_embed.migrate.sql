-- Add optional semantic-search columns to an existing knowledge table.
-- Safe to re-run. Requires pgvector (CREATE EXTENSION vector).
--
-- After this, run: willow-mcp knowledge-embed-tick --budget-s 30 --limit 64 --json
-- until status=empty. knowledge_search then ranks by cosine when vectors exist.

CREATE EXTENSION IF NOT EXISTS vector;

ALTER TABLE knowledge ADD COLUMN IF NOT EXISTS embedding vector(768);
ALTER TABLE knowledge ADD COLUMN IF NOT EXISTS embedding_model text;
ALTER TABLE knowledge ADD COLUMN IF NOT EXISTS content_sha text;
