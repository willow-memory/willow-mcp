#!/usr/bin/env python3
"""Check the seams between willow-mcp, jeles and nestor on a live stand-up.

`sandbox-bootstrap.sh` proves willow-mcp works *alone*. This proves the three
packages are wired to **each other**, which is a different claim and the one
that kept being wrong: every seam below was broken at least once while it read
as fine from both sides, because each package's half was correct and nothing
exercised the join.

Run it after `fleet-standup.sh` (which ends by calling it):

    .venv/bin/python scripts/fleet_seams.py            # human output
    .venv/bin/python scripts/fleet_seams.py --json     # machine output

Exit status is 0 only if every seam passes. A seam that cannot be *reached*
(no Postgres, nestor not installed) reports SKIP and does not fail the run —
an absent optional half is a smaller claim than a broken one, and saying
"pass" about it would be a lie.

Each check writes real data through the real path — the gate, the shared
SQLite file, the hash chain — because a seam that is only imported is a seam
that has not been tested. Everything it writes is tagged `fleet-seams` so it
is identifiable afterwards.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from typing import Any, Callable

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"

# Tag on everything this script writes, so a curator can tell probe rows from
# real ones without reading this file.
TAG = "fleet-seams"


class Result:
    def __init__(self, name: str, status: str, detail: str) -> None:
        self.name, self.status, self.detail = name, status, detail

    def as_dict(self) -> dict[str, str]:
        return {"seam": self.name, "status": self.status, "detail": self.detail}


def _require_env() -> None:
    """Both packages key off WILLOW_STORE_ROOT; an unset one silently splits
    the store in two (jeles under ~/.willow, willow-mcp under $WILLOW_HOME)
    and every seam below still "passes" against its own private copy."""
    missing = [k for k in ("WILLOW_HOME", "WILLOW_STORE_ROOT") if not os.environ.get(k)]
    if missing:
        sys.exit(
            f"unset: {', '.join(missing)}. Source the fleet env first:\n"
            f"    . $WILLOW_HOME/fleet.env\n"
            f"(fleet-standup.sh writes it.)"
        )


# ── the organ's manifest (gap 3cdeb177af78, willow-mcp half) ────────────────
#
# CI fleet-seams went red at #617/528ef68 after Jeles#87 (jeles/corpus.py's
# `_manifest_scope`, sealed ae23d366 "Jeles is the organ"): the probe
# co-installs Jeles master, and `_conn`/`_validate_collection` now refuse
# every store-backed call — put_nugget, search_nuggets — unless
# `$WILLOW_MCP_APPS_ROOT/<JELES_CORPUS_APP_ID>/manifest.json` exists, has a
# sibling `manifest.json.sig` that at least LOOKS like an ASCII-armored PGP
# signature (`_looks_like_pgp_signature` — shape only, `_manifest_scope`'s
# own docstring is explicit that this module holds no keyring and verifies
# nothing cryptographic; that is willow-mcp's gate's job, unreachable from
# here for the same "no reverse channel from a spawned stdio child" reason
# named in corpus.py), and declares `store_scope`/`store_write` as lists.
#
# `JELES_CORPUS_APP_ID` is the organ's OWN seat id, never the retired Ask
# Jeles specialist seat `jeles` — an explicit `jeles` is refused outright by
# `_manifest_scope` before any manifest is even looked up (ae23d366). This
# probe's fixture always uses `jeles-corpus` (Jeles' own hardcoded default
# when the env var is unset), named explicitly here rather than left to that
# default, so a future default change cannot silently point this fixture at
# the wrong seat without this file also going red.
_JELES_CORPUS_APP_ID = "jeles-corpus"

#: The exact collections this probe exercises through the corpus store —
#: `seam_shared_store` (put_nugget: write, then a read-back through
#: willow-mcp's own Store) and `seam_nugget_bridge` (search_nuggets: read).
#: Nothing else in this script touches jeles' corpus store directly —
#: `seam_gap_forward` calls willow-mcp's own `gap_log` tool over MCP, never
#: jeles' local `corpus.log_gap`/GAPS_COLLECTION — so the fixture's reach is
#: exactly this one collection, not "everything," matching the organ's own
#: fail-closed, declared-list model.
_JELES_CORPUS_FIXTURE_COLLECTIONS = ["ask_jeles_corpus"]

#: RFC 4880 §6.1 CRC-24 ("Radix-64"), the checksum line every real
#: ASCII-armored PGP block carries after its base64 body. Implemented here
#: (rather than importing a PGP library willow-mcp does not otherwise
#: depend on) purely so the fixture below is a real armor block, not prose
#: wearing the markers (Loki 23CAD2B4 F5: the prior fixture had no base64
#: body and no CRC, which happened to still pass jeles'
#: `_looks_like_pgp_signature` shape check today, but would break the
#: instant that check -- or any real armor parser -- got stricter).
_CRC24_INIT = 0xB704CE
_CRC24_POLY = 0x1864CFB


def _crc24(data: bytes) -> int:
    crc = _CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= _CRC24_POLY
    return crc & 0xFFFFFF


def _fake_armored_pgp_signature(payload: bytes) -> str:
    """A syntactically real ASCII-armored PGP signature block wrapping
    `payload` -- base64 body (64-char lines, per RFC 4880 §6.3) plus its
    CRC-24 checksum line. `payload` is arbitrary filler, never a real
    signature over anything; nothing here signs or verifies -- this is a
    test fixture, and `jeles/corpus.py`'s own `_manifest_scope` docstring
    is explicit that it checks shape only, never validity."""
    import base64

    b64 = base64.b64encode(payload).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    crc = _crc24(payload)
    crc_b64 = base64.b64encode(crc.to_bytes(3, "big")).decode("ascii")
    body = "\n".join(lines)
    return (
        "-----BEGIN PGP SIGNATURE-----\n"
        "\n"
        f"{body}\n"
        f"={crc_b64}\n"
        "-----END PGP SIGNATURE-----\n"
    )


#: The fixture's fake "signed" content -- never a real signature over
#: anything, just filler bytes wrapped in a real armor shape.
_JELES_CORPUS_FIXTURE_SIG = _fake_armored_pgp_signature(
    b"fleet-seams test fixture -- shape only, verifies nothing."
)


def _provision_jeles_corpus_manifest() -> None:
    """Write the organ's fixture manifest + sibling `.sig` under
    `$WILLOW_MCP_APPS_ROOT/jeles-corpus/`, and set `JELES_CORPUS_APP_ID`/
    `WILLOW_MCP_APPS_ROOT` in this process's own env before any seam runs.

    Idempotent (overwrites on every run, same as `fleet-standup.sh` treats
    the rest of the fleet env) and side-effect-free if jeles is not even
    installed here -- `seam_coinstall` reports that as its own FAIL/SKIP;
    this function only ever writes files under `$WILLOW_HOME`, it never
    imports jeles.
    """
    import pathlib

    home = pathlib.Path(os.environ["WILLOW_HOME"]).expanduser()
    apps_root_override = os.environ.get("WILLOW_MCP_APPS_ROOT", "").strip()
    apps_root = pathlib.Path(apps_root_override) if apps_root_override else home / "mcp_apps"
    os.environ["WILLOW_MCP_APPS_ROOT"] = str(apps_root)
    os.environ["JELES_CORPUS_APP_ID"] = _JELES_CORPUS_APP_ID

    app_dir = apps_root / _JELES_CORPUS_APP_ID
    app_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = app_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "store_scope": list(_JELES_CORPUS_FIXTURE_COLLECTIONS),
                "store_write": list(_JELES_CORPUS_FIXTURE_COLLECTIONS),
                # willow-mcp's own gate reads "permissions" from this SAME
                # manifest file (it is not jeles-side scope, a separate
                # concept) -- an absent/empty list denies every tool call,
                # which is what #619's fleet-seams leg measured for real:
                # "gate: empty permissions for 'jeles-corpus' (tool=
                # 'gap_log') — denied". gap_write is the narrowest
                # PERMISSION_GROUPS entry that carries gap_log (gate.py) --
                # not full_access, not a wider gap_* group.
                "permissions": ["gap_write"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    sig_path = manifest_path.with_name(manifest_path.name + ".sig")
    sig_path.write_text(_JELES_CORPUS_FIXTURE_SIG, encoding="utf-8")


# ── seam 1: the three packages co-install and resolve to the checkouts ────────

def seam_coinstall() -> Result:
    import willow_mcp
    mods: dict[str, Any] = {"willow_mcp": willow_mcp}
    try:
        import jeles
        mods["jeles"] = jeles
    except ImportError as exc:
        return Result("co-install", FAIL, f"jeles not importable: {exc}")
    try:
        import nestor
        mods["nestor"] = nestor
    except ImportError:
        return Result("co-install", SKIP, "nestor not installed in this venv")

    from importlib.metadata import version
    parts = []
    for name, mod in mods.items():
        dist = {"willow_mcp": "willow-mcp"}.get(name, name)
        try:
            v = version(dist)
        except Exception:
            v = "?"
        parts.append(f"{dist} {v} ({os.path.dirname(mod.__file__ or '')})")
    return Result("co-install", PASS, "; ".join(parts))


# ── seam 2: jeles' corpus lives in willow-mcp's SOIL store ───────────────────

def seam_shared_store() -> Result:
    """jeles.corpus and willow_mcp's Store must land on the same SQLite file.

    This is the seam with no error message when it breaks: both halves work
    perfectly, on two different databases, and the only symptom is a corpus
    the hub cannot see.
    """
    from jeles import corpus

    want = os.path.realpath(os.environ["WILLOW_STORE_ROOT"])
    got = os.path.realpath(str(corpus._store_root()))
    if want != got:
        return Result("shared SOIL store", FAIL,
                      f"jeles writes to {got}, willow-mcp serves {want}")

    written = corpus.put_nugget(
        question=f"[{TAG}] does the jeles corpus share willow-mcp's store?",
        answer="Yes — both resolve $WILLOW_STORE_ROOT/<collection>/store.db.",
        sources=["scripts/fleet_seams.py"],
        verified_by=TAG,
        tags=[TAG],
        # A stable id so re-running upserts instead of adding a probe row per
        # run, and "asserted" because that is what this write is: nobody
        # checked it. Claiming `human` here would put a lie in the corpus to
        # test that the corpus works.
        nugget_id="fleet-seams-store-probe",
        verification_kind="asserted",
    )
    db = os.path.join(got, corpus.NUGGETS_COLLECTION, "store.db")
    if not os.path.exists(db):
        return Result("shared SOIL store", FAIL,
                      f"put_nugget reported {written.get('action')} but {db} does not exist")

    # Read it back through willow-mcp's own Store, not through jeles again —
    # a round-trip inside one package proves nothing about the other.
    from willow_mcp.db import Store
    rows = Store(got).search(corpus.NUGGETS_COLLECTION, TAG)
    if not rows:
        return Result("shared SOIL store", FAIL,
                      f"willow-mcp's Store cannot see jeles' nugget in {db}")
    return Result("shared SOIL store", PASS,
                  f"{len(rows)} row(s) visible to both at {db}")


# ── seam 3: a jeles gap crosses the gate into willow-mcp's backlog ───────────

def seam_gap_forward() -> Result:
    """The seam that crosses willow-mcp's manifest ACL over stdio MCP.

    Denials here used to be invisible from both sides — jeles logged them at
    DEBUG and dropped them, so this check asserts `forward_status()` as well
    as the backlog row.
    """
    from jeles import willow_mcp_client as client
    from willow_mcp import gaps

    # Unique per run, and deliberately NOT cleaned up afterwards. A gap's id is
    # uuid5(topic + normalized question), and `Store.delete` is a tombstone that
    # `put` does not lift (db.py documents that as the deliberate price of a
    # durable delete) — so purging the probe topic between runs would brick
    # exactly this id forever and every later run would report a false FAIL.
    # Leaving the rows is the honest option; they are tagged and few.
    marker = f"{TAG}-{os.getpid()}-{int(time.time())}"
    question = f"[{marker}] did a jeles gap reach willow-mcp's backlog?"
    topic = f"{TAG}-probe"

    client.forward_gap(question, topic=topic)

    deadline = time.monotonic() + 20
    found = None
    while time.monotonic() < deadline:
        time.sleep(0.5)
        for row in gaps.list_gaps(topic=topic, limit=10).get("items", []):
            if row.get("question") == question:
                found = row
                break
        if found:
            break

    status = client.forward_status()
    if not found:
        why = status.get("last_error") or status.get("session_error") or "no error reported"
        return Result("gap forward (jeles -> willow-mcp)", FAIL,
                      f"as app_id={status.get('app_id')!r}: {why}")
    if status.get("last_error"):
        return Result("gap forward (jeles -> willow-mcp)", FAIL,
                      f"gap landed but a later forward failed: {status['last_error']}")
    return Result("gap forward (jeles -> willow-mcp)", PASS,
                  f"as app_id={status.get('app_id')!r}, gap {found.get('_id')} "
                  f"in topic {topic!r}")


# ── seam 4: willow-mcp's institutional search binds this jeles ───────────────

def seam_institutional() -> Result:
    """`willow_institutional_search` imports jeles in-process. No egress here:
    the check is that the hub binds the *checkout*, not that ~60 collections
    answer — the egress gate is a separate, deliberate grant."""
    try:
        from jeles import institutional, sources
    except ImportError as exc:
        return Result("institutional search (willow-mcp -> jeles)", FAIL, str(exc))

    listed = institutional.list_sources()
    if not listed:
        return Result("institutional search (willow-mcp -> jeles)", FAIL,
                      "jeles.institutional.list_sources() is empty")
    return Result("institutional search (willow-mcp -> jeles)", PASS,
                  f"{len(listed)} collections registered, {len(sources.SOURCES)} source "
                  f"functions, from {os.path.dirname(institutional.__file__)}")


# ── seam 5: nestor mirrors its ledger into FRANK, through the gate ──────────

def seam_frank() -> Result:
    try:
        from nestor import frank
    except ImportError:
        return Result("FRANK mirror (nestor -> willow-mcp)", SKIP, "nestor not installed")

    from willow_mcp.server import get_pg
    pg = get_pg()
    if not pg:
        return Result("FRANK mirror (nestor -> willow-mcp)", SKIP,
                      "Postgres unavailable — FRANK is Postgres-backed")

    forwarder = frank.willow_forwarder()
    marker = f"{TAG}-{os.getpid()}"
    try:
        forwarder("nestor.seam_check", {"marker": marker})
    except frank.FrankUnavailable as exc:
        return Result("FRANK mirror (nestor -> willow-mcp)", FAIL,
                      f"as app_id={forwarder._app_id!r}: {exc}")

    cur = pg.cursor()
    try:
        cur.execute(
            "SELECT id, project, hash FROM frank_ledger "
            "WHERE content->>'marker' = %s", (marker,))
        row = cur.fetchone()
    finally:
        cur.close()
    if not row:
        return Result("FRANK mirror (nestor -> willow-mcp)", FAIL,
                      "frank_append returned but no row landed in frank_ledger")

    # A row is not a chain. Ask the ledger whether it still verifies.
    from willow_mcp.governance_ledger import GovernanceLedger
    verdict = GovernanceLedger(pg).verify()
    if not verdict.get("valid"):
        return Result("FRANK mirror (nestor -> willow-mcp)", FAIL,
                      f"row landed but the chain does not verify: broken at "
                      f"{verdict.get('broken_at')}")
    return Result("FRANK mirror (nestor -> willow-mcp)", PASS,
                  f"as app_id={forwarder._app_id!r}, project={row[1]!r}, "
                  f"chain valid over {verdict.get('count')} entries")


# ── seam 6: a jeles nugget crosses into nestor — as a draft, never sealed ───

def seam_nugget_bridge() -> Result:
    """nestor's whole claim is that an unsigned assertion does not arrive as a
    seal. The check is therefore not "did it import" but "did it refuse to
    call it verified"."""
    try:
        import nestor  # noqa: F401
    except ImportError:
        return Result("nugget bridge (jeles -> nestor)", SKIP, "nestor not installed")

    bridge = _load_jeles_bridge()
    if bridge is None:
        return Result("nugget bridge (jeles -> nestor)", SKIP,
                      "recipes/jeles_bridge.py not on the path "
                      "(set NESTOR_REPO to the nestor checkout)")

    from jeles import corpus
    from nestor import memory, storage
    from nestor.sqlite_store import SqliteStore

    nuggets = corpus.search_nuggets(TAG, limit=5)
    if not nuggets:
        return Result("nugget bridge (jeles -> nestor)", SKIP,
                      "no nuggets in the corpus to bridge (run the store seam first)")

    # A throwaway store: the seam under test is the demotion rule, and it must
    # not be answered by, or write into, an operator's real memory.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store = SqliteStore(os.path.join(tmp, "seams.db"))
        try:
            memory.set_matcher(bridge.MATCHER)
            report = bridge.bridge_nuggets(nuggets, store=store)
            rows = store.all_pairs() if hasattr(store, "all_pairs") else []
        finally:
            memory.set_matcher(None)
            storage.set_store(None)
            store.close()

    if report.get("sealed"):
        return Result("nugget bridge (jeles -> nestor)", FAIL,
                      f"{report['sealed']} nugget(s) arrived SEALED — an unsigned "
                      f"claim must cross as a draft")
    if not (report.get("demoted") or report.get("existing")):
        return Result("nugget bridge (jeles -> nestor)", FAIL,
                      f"nothing crossed: {report}")
    sealed_rows = [r for r in rows if r.get("status") == "sealed"]
    if sealed_rows:
        return Result("nugget bridge (jeles -> nestor)", FAIL,
                      f"{len(sealed_rows)} sealed row(s) in the store after a bridge")
    return Result("nugget bridge (jeles -> nestor)", PASS,
                  f"{report.get('demoted', 0)} nugget(s) crossed as draft, 0 sealed")


def _load_jeles_bridge():
    """`recipes/` is not an installed package — it ships in the nestor repo and
    is imported from a checkout. Find it without requiring one."""
    import importlib.util
    candidates = []
    if os.environ.get("NESTOR_REPO"):
        candidates.append(os.path.join(os.environ["NESTOR_REPO"], "recipes", "jeles_bridge.py"))
    try:
        import nestor
        pkg = os.path.dirname(os.path.dirname(nestor.__file__ or ""))
        candidates.append(os.path.join(pkg, "recipes", "jeles_bridge.py"))
    except ImportError:
        pass
    for path in candidates:
        if not os.path.exists(path):
            continue
        spec = importlib.util.spec_from_file_location("jeles_bridge", path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


SEAMS: list[tuple[str, Callable[[], Result]]] = [
    ("co-install", seam_coinstall),
    ("shared SOIL store", seam_shared_store),
    ("gap forward (jeles -> willow-mcp)", seam_gap_forward),
    ("institutional search (willow-mcp -> jeles)", seam_institutional),
    ("FRANK mirror (nestor -> willow-mcp)", seam_frank),
    ("nugget bridge (jeles -> nestor)", seam_nugget_bridge),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    _require_env()
    _provision_jeles_corpus_manifest()

    results: list[Result] = []
    for name, fn in SEAMS:
        try:
            results.append(fn())
        except Exception:
            results.append(Result(name, FAIL, traceback.format_exc(limit=3).strip()))

    if args.json:
        print(json.dumps({"seams": [r.as_dict() for r in results]}, indent=2))
    else:
        width = max(len(r.name) for r in results)
        for r in results:
            print(f"  {r.status:4}  {r.name:{width}}  {r.detail}")
        failed = [r for r in results if r.status == FAIL]
        skipped = [r for r in results if r.status == SKIP]
        print()
        print(f"{len(results) - len(failed) - len(skipped)} passed, "
              f"{len(failed)} failed, {len(skipped)} skipped")

    return 1 if any(r.status == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
