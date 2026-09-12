"""willow_mcp.nest — the Nest content engine, vendored into willow-mcp.

"Dump your life and let the pigeon figure it out." Walk a folder of personal
files, extract text (OCR/PDF/docx/plaintext), classify fragments by *meaning*
(a regex → local-embedding → LLM cascade), and write a canonical SQLite Nest DB.
The engine is exposed to the fleet through the gated MCP tools in
``willow_mcp.server`` (``nest_scan`` / ``nest_status`` / ``nest_digest`` /
``nest_promote``); this package is the machinery behind those tools.

THE WALL (why this lives behind willow-mcp's gate). The Nest DB is the local
PII zone — a person's legal filings, journals, messages. The promotion path to
the shared knowledge base (``nest_promote`` → ``bridge.build_bridge``) pushes
*structure, not content*: counts, curated category names, and redacted secret
*kinds* — never fragment content, person names, or filenames. ``nest_digest``
returns its walled variant over MCP for the same reason. That asymmetry —
relative/structural shape is process (shareable); absolute content is person
(walled) — is the load-bearing decision, the same one corpuslens's Guard makes.

Provenance: home is THIS repo. The content pipeline core (db, embed, ingest,
llm, secrets, selflearn, taxonomy, classify, ocr) was vendored from
rudi193-cmd/safe-app-store ``libs/nest-pipeline`` (MIT; box audit A4) under a
hash pin and a CI ``vendor-sync`` compare. safe-app-store is archived and is
never an origin again (owner decision, 2026-09-12: "the forge is to be
vendored; safe-app-store isn't to be vendored — it's to be archived and turned
into a parts bin"), so since that date these modules are source like the rest
of ``willow_mcp``: edit them here, test them here, no pin. The pipeline is still
deliberately policy-free — consent and egress gates live at the tool boundary
(``model_egress``), not in here. ΔΣ=42
"""
