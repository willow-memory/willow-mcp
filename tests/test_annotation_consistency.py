"""Structural guard: MCP tool annotations must match actual behavior.

Every tool's readOnlyHint annotation must agree with what the tool does:
  * A tool that writes state (store.put, store.delete, dispatch_set_status,
    file writes, etc.) must NOT have readOnlyHint=True.
  * A tool in a _write permission group must not be annotated ANNO_READ.

Read from source so the heavy runtime (Postgres, filesystem, etc.) is never
imported — same approach as test_authority_surface.py.

Background: session_enter was annotated read-only but wrote dispatch state
(fixed in PR #350). This test catches future recurrences structurally.
"""
import re
from pathlib import Path

from willow_mcp import gate

_ROOT = Path(__file__).resolve().parents[1]
_SERVER = _ROOT / "src" / "willow_mcp" / "server.py"
_GROVE_TOOLS = _ROOT / "src" / "willow_mcp" / "grove_tools.py"
_MAI_TOOLS = _ROOT / "src" / "willow_mcp" / "mai" / "tools.py"

# Annotation constant names that mean readOnlyHint=True.
_READ_ANNO_NAMES = {"_ANNO_READ", "_ANNO_READ_OPEN"}

# Annotation constant names that mean readOnlyHint=False (writes).
_WRITE_ANNO_NAMES = {"_ANNO_WRITE", "_ANNO_WRITE_IDEM", "_ANNO_DESTRUCTIVE", "_ANNO_WRITE_OPEN"}

# Permission groups whose names signal "write" semantics — a tool in one of
# these that is annotated as read-only is suspicious.  We match on suffixes
# and known write-group names.
_WRITE_GROUP_SUFFIXES = ("_write", "_curate", "_purge", "_promote", "_seal")
_WRITE_GROUP_NAMES = frozenset({
    "frank_write", "envelope_apply", "schema_admin",
    "tool_oracle_route", "tool_oracle_seal",
    "integration_call", "federation_call",
    "binding",
})


def _extract_tool_annotations(filepath: Path) -> dict[str, str]:
    """Parse {tool_name: annotation_const_name} from source, without import."""
    if not filepath.exists():
        return {}
    src = filepath.read_text(encoding="utf-8")
    lines = src.splitlines()
    tools: dict[str, str] = {}
    for i, line in enumerate(lines):
        m = re.search(r"@mcp\.tool\(annotations=([\w_]+)\)", line.strip())
        if m:
            anno = m.group(1)
            for j in range(i + 1, min(i + 5, len(lines))):
                dm = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", lines[j])
                if dm:
                    tools[dm.group(1)] = anno
                    break
    return tools


def _all_tool_annotations() -> dict[str, str]:
    """Merged annotation map across all tool-hosting modules."""
    merged: dict[str, str] = {}
    for fp in (_SERVER, _GROVE_TOOLS, _MAI_TOOLS):
        merged.update(_extract_tool_annotations(fp))
    return merged


def _is_write_group(name: str) -> bool:
    if name in _WRITE_GROUP_NAMES:
        return True
    return any(name.endswith(s) for s in _WRITE_GROUP_SUFFIXES)


# ── The tests ──────────────────────────────────────────────────────────────────


def test_sanity_tool_count():
    """We expect a significant number of tools; a zero result means the regex
    broke or the files moved."""
    tools = _all_tool_annotations()
    assert len(tools) >= 80, f"only found {len(tools)} tools — extraction likely broke"


def test_write_group_tools_are_not_annotated_read():
    """A tool that lives in a _write (or _curate/_purge/_promote) permission
    group must not claim readOnlyHint=True — that was the session_enter bug."""
    tools = _all_tool_annotations()
    mismatches: list[str] = []

    for group_name, group_tools in gate.PERMISSION_GROUPS.items():
        if not _is_write_group(group_name):
            continue
        for tool in sorted(group_tools):
            anno = tools.get(tool)
            if anno is None:
                # Tool not registered (e.g. __mai_directives__ pseudo-tool).
                continue
            if anno in _READ_ANNO_NAMES:
                mismatches.append(
                    f"{tool}: annotation={anno} but belongs to write group "
                    f"{group_name!r}"
                )

    assert not mismatches, (
        "Tools in write permission groups must not have readOnlyHint=True "
        "(a read annotation). Mismatches found:\n  " + "\n  ".join(mismatches)
    )


def test_known_write_tools_are_not_annotated_read():
    """Hardcoded list of tools that are known to modify state — they must
    never regress to a read annotation.  Add to this list when a new tool
    is confirmed to write."""
    # These tools modify state; their annotations must reflect that.
    # Each entry: tool_name -> why it writes.
    known_writers = {
        "session_enter": "writes dispatch state via session_enter()",
        "agent_seed_mirror": "calls store.put() to mirror a seed record into SOIL",
        "verify_handoff": "calls dispatch_set_status('verified') on success",
        "context_get": "deletes expired records via store.delete()",
        "context_list": "deletes expired records via store.delete()",
    }
    tools = _all_tool_annotations()

    regressions: list[str] = []
    for tool, reason in sorted(known_writers.items()):
        anno = tools.get(tool)
        if anno is None:
            continue  # tool removed — not a regression
        if anno in _READ_ANNO_NAMES:
            regressions.append(f"{tool}: has {anno} but {reason}")

    assert not regressions, (
        "Known-writer tools must not have readOnlyHint=True. Regressions:\n  "
        + "\n  ".join(regressions)
    )


def test_every_tool_has_a_recognized_annotation():
    """Every @mcp.tool annotation must be one of the known constants —
    catches typos and undeclared custom annotations."""
    all_known = _READ_ANNO_NAMES | _WRITE_ANNO_NAMES
    tools = _all_tool_annotations()
    unknown: list[str] = []
    for tool, anno in sorted(tools.items()):
        if anno not in all_known:
            unknown.append(f"{tool}: {anno}")
    assert not unknown, (
        "Tools with unrecognized annotation constants:\n  " + "\n  ".join(unknown)
    )


def test_read_group_tools_with_write_annotations_are_acknowledged():
    """A tool in a _read permission group that has a write annotation is
    unusual — it means the tool writes state but is accessible to apps that
    only hold read access.  Each such case must be explicitly acknowledged
    in the allowlist below.  If you're adding a new one, confirm the write
    is intentional for read-group holders and add it here."""
    # Acknowledged: these tools live in read groups but correctly have write
    # annotations because they do modify state.  The permission group
    # membership is intentional (e.g. session_enter needs to be callable
    # by dispatch_read holders for session bootstrap).
    acknowledged = {
        "session_enter",      # dispatch_read — writes session state, bootstrap
        "agent_seed_mirror",  # dispatch_read — writes to SOIL store (store.put), also in store_write
        "context_get",        # context — lazy-deletes expired records
        "context_list",       # context — lazy-deletes expired records
    }

    tools = _all_tool_annotations()
    unacknowledged: list[str] = []

    for group_name, group_tools in gate.PERMISSION_GROUPS.items():
        if not group_name.endswith("_read"):
            continue
        for tool in sorted(group_tools):
            anno = tools.get(tool)
            if anno is None:
                continue
            if anno in _WRITE_ANNO_NAMES and tool not in acknowledged:
                unacknowledged.append(
                    f"{tool}: annotation={anno} in read group {group_name!r}"
                )

    assert not unacknowledged, (
        "Tools in _read permission groups with write annotations must be "
        "explicitly acknowledged (add to the allowlist if intentional). "
        "Unacknowledged:\n  " + "\n  ".join(unacknowledged)
    )


def _extract_tool_docstrings(filepath: Path) -> dict[str, str]:
    """Parse {tool_name: docstring} from source, without import."""
    if not filepath.exists():
        return {}
    src = filepath.read_text(encoding="utf-8")
    lines = src.splitlines()
    tools: dict[str, str] = {}
    for i, line in enumerate(lines):
        m = re.search(r"@mcp\.tool\(annotations=([\w_]+)\)", line.strip())
        if m:
            for j in range(i + 1, min(i + 5, len(lines))):
                dm = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", lines[j])
                if dm:
                    name = dm.group(1)
                    doc_lines = []
                    in_doc = False
                    for k in range(j + 1, min(j + 30, len(lines))):
                        stripped = lines[k].strip()
                        if not in_doc:
                            if stripped.startswith('"""') or stripped.startswith("'''"):
                                quote = stripped[:3]
                                if stripped.endswith(quote) and len(stripped) > 6:
                                    doc_lines.append(stripped[3:-3])
                                    break
                                in_doc = True
                                doc_lines.append(stripped[3:])
                            else:
                                break
                        else:
                            if quote in stripped:
                                doc_lines.append(stripped[:stripped.index(quote)])
                                break
                            doc_lines.append(stripped)
                    tools[name] = "\n".join(doc_lines)
                    break
    return tools


def test_write_annotated_tools_do_not_claim_read_only():
    """A tool annotated as WRITE/WRITE_IDEM/DESTRUCTIVE must not have a
    terminal 'Read-only.' claim in its docstring — that contradicts what the
    annotation declares to the client.  'Read-only reconcile:' or similar
    qualified uses are fine; only a standalone sentence-final claim is flagged.

    Catches the verify_handoff class of bug: annotation updated, docstring
    not."""
    stale: list[str] = []
    for fp in (_SERVER, _GROVE_TOOLS, _MAI_TOOLS):
        annos = _extract_tool_annotations(fp)
        docs = _extract_tool_docstrings(fp)
        for tool, anno in annos.items():
            if anno not in _WRITE_ANNO_NAMES:
                continue
            doc = docs.get(tool, "")
            if re.search(r'Read-only\.\s*$', doc, re.MULTILINE):
                stale.append(f"{tool}: annotated {anno} but docstring claims 'Read-only.'")
    assert not stale, (
        "Write-annotated tools must not have a terminal 'Read-only.' claim in "
        "their docstring (update the docstring to reflect what the tool actually "
        "writes). Stale claims:\n  " + "\n  ".join(stale)
    )
