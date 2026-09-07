"""
willow_mcp/resources.py — MCP Resource handlers for URI-addressable read-only data.

Exposes KB atoms and Store records as MCP Resources (2026-07-28 spec),
the protocol's native way to let clients fetch server-held data into context
on demand via `resources/list` and `resources/read`.

KB atoms are a natural fit: each has a stable identity (`atom_id`), is
read-only from the consumer's perspective, and benefits from URI-addressable
access. Store records follow the same pattern (collection + record_id).

URI schemes (RFC 6570 templates):
  kb://atom/{atom_id}                  — one KB atom by ID
  store://collections                  — list all store collection names
  store://{collection}/records         — list records in one collection
  store://{collection}/records/{record_id} — one store record by collection + ID

Register all resources on an MCPServer instance by calling `register(mcp)`,
the same pattern `willow_mcp.grove_tools` and `willow_mcp.mai.tools` use.

Auth note: MCP resources are server-level data the client pulls on demand —
they have no `app_id` argument (the protocol does not carry one). In stdio
mode this is consistent with the single-operator trust model: the client
already has access to every tool in the listing. In serve mode, the OAuth
session authenticates the client at the transport level. Per-app
store_scope narrowing is tool-level policy and does NOT apply to resources;
the resources expose the full store as the server sees it, same as any
other read-only server-level primitive.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from .db import Store, get_pg
from . import schema_profile as sp
from . import kb_curate as kbc
from ._kb_sql import KNOWLEDGE_FIELDS as _KNOWLEDGE_FIELDS
from ._kb_sql import build_select as _build_select
from ._kb_sql import row_to_dict as _row_to_dict

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer


# ── Helpers ──────────────────────────────────────────────────────────────────

def _postgres_unavailable() -> dict:
    from .db import last_pg_error
    return {
        "error": "postgres_unavailable",
        "detail": (
            "No Postgres connection — set WILLOW_PG_HOST / WILLOW_PG_SOCKET or "
            "ensure the fleet Postgres is reachable."
        ),
        # What the attempt actually said, rather than a guess at it.
        "reason": last_pg_error() or "no reason recorded (no connection attempt this process)",
    }


# ── Registration ─────────────────────────────────────────────────────────────

def register(mcp: "MCPServer", store: Store) -> None:
    """Register all MCP resources on the provided MCPServer instance.

    Parameters
    ----------
    mcp : MCPServer
        The server instance to register resources on.
    store : Store
        The SQLite store instance (same one server.py's tool functions use).
    """

    # ── KB resources ────────────────────────────────────────────────────────

    @mcp.resource(
        "kb://atom/{atom_id}",
        name="kb_atom",
        title="KB Atom",
        description=(
            "A single knowledge-base atom from the fleet Postgres, "
            "fetched by its exact ID. Returns content, domain, source, "
            "and tags — the same data kb_at exposes, as a URI-addressable "
            "MCP resource."
        ),
        mime_type="application/json",
    )
    def kb_atom_resource(atom_id: str) -> str:
        pg = get_pg()
        if not pg:
            return json.dumps(_postgres_unavailable())

        # Use a fresh app_id-less resolve: resources are server-level, not
        # app-scoped. Pass an empty app_id — schema_profile.resolve treats
        # it the same as a default lookup (the mapping is per-table, not
        # per-app).
        mapping = sp.resolve(pg, "", "knowledge", _KNOWLEDGE_FIELDS)
        if "error" in mapping:
            return json.dumps(mapping)
        fields = mapping["fields"]
        id_col = fields["id"]["column"]
        if id_col is None:
            return json.dumps({"error": "schema_unusable: 'knowledge' table has no mappable 'id' column"})

        select_clause, present, unmapped = _build_select(_KNOWLEDGE_FIELDS, fields)
        cur = pg.cursor()
        cur.execute(
            f'SELECT {select_clause} FROM knowledge WHERE "{id_col}" = %s',  # nosec B608 - select_clause/id_col from schema_profile, not request input
            (atom_id,),
        )
        row = cur.fetchone()
        cur.close()
        if not row:
            return json.dumps({"error": "not_found"})

        result = kbc.enrich_atom(_row_to_dict(row, present, unmapped))
        if unmapped:
            result["_unmapped"] = unmapped
        return json.dumps(result, default=str)

    # ── Store resources ─────────────────────────────────────────────────────

    @mcp.resource(
        "store://collections",
        name="store_collections",
        title="Store Collections",
        description=(
            "List every SOIL collection visible to this server instance. "
            "Returns collection names and count — the same data "
            "store_collections exposes, as a static MCP resource."
        ),
        mime_type="application/json",
    )
    def store_collections_resource() -> str:
        names = store.list_collections()
        return json.dumps({"collections": names, "count": len(names)})

    @mcp.resource(
        "store://{collection}/records",
        name="store_collection_list",
        title="Store Collection Records",
        description=(
            "Up to 200 live records in one SOIL collection, oldest first. "
            "Each record includes _id/_created/_updated metadata. "
            "For larger collections, use the store_list tool for full "
            "paginated access."
        ),
        mime_type="application/json",
    )
    def store_collection_list_resource(collection: str) -> str:
        records, next_cursor = store.all_paginated(collection, limit=200)
        result: dict = {"records": records, "count": len(records)}
        if next_cursor:
            result["truncated"] = True
            result["hint"] = "Collection has more records. Use the store_list tool for paginated access."
        return json.dumps(result, default=str)

    @mcp.resource(
        "store://{collection}/records/{record_id}",
        name="store_record",
        title="Store Record",
        description=(
            "A single record from a SOIL collection, fetched by collection "
            "name and record ID. Returns the stored JSON plus _id/_created/"
            "_updated/_deviation/_action metadata. Equivalent to store_get, "
            "as a URI-addressable MCP resource."
        ),
        mime_type="application/json",
    )
    def store_record_resource(collection: str, record_id: str) -> str:
        item = store.get(collection, record_id)
        if item is None:
            return json.dumps({"error": "not_found"})
        return json.dumps(item, default=str)
