"""A4 — the vendored Nest pipeline core is pinned to its canonical.

DRIFT-GUARD (theme ① of the 2026-07-24 box audit): the Nest content pipeline
was duplicated between safe-app-store's nest-seed app and willow-mcp's
``nest/``. Step 1 (safe-app-store) made ``libs/nest-pipeline`` the canonical
home; this repo vendors that shared core into ``src/willow_mcp/nest/``. Nothing
else catches the copy going stale, so each shared module's body is pinned to a
known hash — mirroring tests/test_mem_ratify.py / test_subject_consent.py. The
cross-repo companion is scripts/check_nest_pipeline_sync.py (run in CI's
vendor-sync job) which catches canonical advancing while this copy lags.

The copy is NOT a place to edit. Change the pipeline UPSTREAM in
safe-app-store's ``libs/nest-pipeline``, then re-sync the file(s) here
byte-for-byte (module docstring onward, header excepted) and update the
EXPECTED_SHA256 value below to what the assertion prints.
"""
import hashlib
import pathlib

import pytest

NEST_DIR = pathlib.Path(__file__).resolve().parents[1] / "src/willow_mcp/nest"

# Shared-core modules vendored from safe-app-store libs/nest-pipeline, pinned to
# their canonical body. (bridge/digest/intake/rules/__init__ are app-specific
# and deliberately NOT pinned.)
EXPECTED_SHA256 = {
    "db.py": "85f5146cfe0207427252250ef44e2e673d62cecf41338ab96547149ffe254076",
    "embed.py": "e80f61c1a24f9b82a7c4a16c5be8bf89706f1a41b6fe91cd8530775e5157754f",
    "ingest.py": "bb244baf2b7d1500da494b1b98cc86b0591fe823caa7be53618db3d34ecf29fc",
    "llm.py": "628a3f58b11087b07ff9b5c096e3899c1ba468e6bc3849a71fddff03df738bfc",
    "secrets.py": "efd773441f05266c7f63512f6fe038e68ed838edc2b0f860dffa92b295958e12",
    "selflearn.py": "9126c1aa3266c6d1d684b9da6fb34eb481049358f3479f40bfdca7f646725f09",
    "taxonomy.py": "57a6593d122d3422a1938bacd75d7141ecc33206d05a6702ef200fe98c5bf623",
    "classify.py": "7e81f75d98011aea824317e8fc977e16777fae1f6b7730b51bcfb93ab32748ca",
    "ocr.py": "479dc5ed4cf5dad62e6eadcc92e6097fbd8b4e0f2f138c5ce61a37c332200254",
}


def _body_hash(name: str) -> str:
    text = (NEST_DIR / name).read_text()
    body = text[text.index('"""'):]  # docstring onward — the vendored contract
    return hashlib.sha256(body.encode()).hexdigest()


@pytest.mark.parametrize("name", sorted(EXPECTED_SHA256))
def test_vendored_nest_module_body_matches_pinned_hash(name):
    got = _body_hash(name)
    assert got == EXPECTED_SHA256[name], (
        f"vendored nest/{name} body drifted from the pinned canonical copy.\n"
        f"  got:      {got}\n  expected: {EXPECTED_SHA256[name]}\n"
        "If you re-synced from safe-app-store libs/nest-pipeline on purpose, update "
        f"EXPECTED_SHA256[{name!r}].\n"
        "If you edited the vendored copy directly — don't; edit the canonical and re-sync.")
