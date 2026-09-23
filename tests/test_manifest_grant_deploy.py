"""`deploy/manifest-grant/` — the system-unit install (sealed `1fdfbdf3` /
`1bd6fd29`, pair `42DF2EA1` amendment 1). These five files were copied from
the operator's own `~/Desktop/Nest/manifest-grant-system/` staging area
(never modified there — the desk removes that copy when this PR merges) and
`install.sh` was reworked here: the broker-public-key and broker-unit
lookups no longer glob, and step 1 migrates the envelope register and
federation registry to trust-owner ownership (pair 31f5d3af) for the four
new verbs (envelope.revoke, manifest.retire, manifest.create,
federation.ratify — syscall-table rows 20-23, renumbered from an original
19-22 draft per Loki audit BFCC5C79 finding F4) beyond
mcp_apps/manifest_grants.

Divergence note (this PR's own finding, not a bug): `src/willow_mcp/bundle/
deploy/willow-mcp-manifest-grant.service.template` is the OLD `--user`
BROKER-owned unit design this install retires outright (INSTALL.md step 2 —
`systemctl --user disable --now willow-mcp-manifest-grant.timer`); it is a
Python `.format()`-style template the reloader installs under the broker's
own `--user` manager, while `deploy/manifest-grant/willow-mcp-manifest-
grant.service` is a static SYSTEM unit (`User=willow-operator`, installed by
root into `/etc/systemd/system/`) — a different deployment model entirely,
never rendered from that template and not expected to match it. There is no
existing template for the NEW system-unit shape this PR adds — noted here as
the assignment's own "(if there is none, say so in the handoff)" clause.

Every text-scan below is factored into a module-level helper and shown to
fire on a planted violation in `test_plant_every_deploy_scan_helper_
catches_its_violation` (`tests/test_scans_fire.py`'s house rule: a scan
never shown to catch anything is not verified to check anything).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_DEPLOY = Path(__file__).resolve().parents[1] / "deploy" / "manifest-grant"
_BUNDLE_TEMPLATE = (
    Path(__file__).resolve().parents[1] / "src" / "willow_mcp" / "bundle" / "deploy"
    / "willow-mcp-manifest-grant.service.template"
)

_SEALED_PAIRS = ("1fdfbdf3", "1bd6fd29")

# The glob patterns an auditor flagged (amendment 1, packet 42DF2EA1) and the
# concrete names install.sh must use instead.
_FORBIDDEN_GLOBS = ("*.pub", "*public*", "willow-mcp*.service")
_REQUIRED_KNOWN_NAMES = ("broker_public_key.pub", "willow-mcp-serve.service", "willow-mcp.service")


def _script_body(install_sh_text: str) -> str:
    """The script body, past the header comment block — so a COMMENT
    describing the old glob this install.sh replaced (prose, in the header)
    never itself trips the "no glob" guard below."""
    return install_sh_text.split("set -euo pipefail", 1)[-1]


def _missing_pair_citations(text: str) -> list[str]:
    """Which of the two governing sealed pairs a file fails to cite."""
    return [pid for pid in _SEALED_PAIRS if pid not in text]


def _install_sh_glob_offenders(install_sh_text: str) -> list[str]:
    """Forbidden glob patterns present in the SCRIPT BODY (never the header
    prose) of install.sh."""
    body = _script_body(install_sh_text)
    return [pattern for pattern in _FORBIDDEN_GLOBS if pattern in body]


def _install_sh_missing_known_names(install_sh_text: str) -> list[str]:
    """Concrete names (no glob) the script body must reference."""
    body = _script_body(install_sh_text)
    return [name for name in _REQUIRED_KNOWN_NAMES if name not in body]


def _install_sh_estale_presigned_problems(install_sh_text: str) -> list[str]:
    """Step 6b must mint `estale_presigned` in the FLAT shape
    `manifest_grant_executor._move` produces — never a `request`-nested
    wrapper."""
    problems = []
    if "estale_presigned" not in install_sh_text:
        problems.append("no estale_presigned")
    if '"request": rec' in install_sh_text:
        problems.append("nested request wrapper present")
    if '**rec, "result"' not in install_sh_text:
        problems.append("no flat **rec, result spread")
    return problems


_FIXED_TMP_NAMES = ("/tmp/manifest-grant.env", "/tmp/$s.manifest.json.sig")


def _install_sh_fixed_tmp_names(install_sh_text: str) -> list[str]:
    """Loki audit BFCC5C79, F7: a predictable name in world-writable /tmp is
    a symlink race — every staging file must come from mktemp instead."""
    body = _script_body(install_sh_text)
    return [name for name in _FIXED_TMP_NAMES if name in body]


_F7_REQUIRED_MARKERS = ("mktemp", "trust-owner python interpreter", "traversal")


def _install_sh_missing_f7_checks(install_sh_text: str) -> list[str]:
    """Loki audit BFCC5C79, F7: an interpreter check up front, $H traversal
    for the trust owner, and mktemp for every staged file."""
    body = _script_body(install_sh_text)
    return [marker for marker in _F7_REQUIRED_MARKERS if marker not in body]


def _install_sh_6b_before_restart(install_sh_text: str) -> bool:
    """True when step 6b's withdrawal runs BEFORE the broker restart —
    Loki audit BFCC5C79, F7: restarting first lets a freshly-restarted
    broker accept a new request into pending/ before 6b can withdraw the
    stale ones, and the blanket withdrawal cannot tell them apart by
    content alone.

    Dispatch E29CCFC7 (Loki A38D41C2, F5): the restart is now a shared
    ``restart_broker`` function, defined once near the top of the script
    (before step 0) and CALLED at the plain-install flow's own position
    (after 6b) and again from --rotate. A plain substring search for the
    function's own name would find the DEFINITION first, always "before"
    6b regardless of where it's actually invoked — this looks for the bare
    call line (``restart_broker`` with no ``()`` after it, which only the
    call site has) instead."""
    body = _script_body(install_sh_text)
    idx_6b = body.find("6b. withdraw every request")
    idx_restart_call = body.find("\nrestart_broker\n")
    if idx_6b == -1 or idx_restart_call == -1:
        return False
    return idx_6b < idx_restart_call


def _service_unit_missing(text: str) -> list[str]:
    required = ("[Service]", "User=willow-operator", "ReadWritePaths=", "constitutional")
    return [r for r in required if r not in text]


def _timer_missing(text: str) -> list[str]:
    required = ("Unit=willow-mcp-manifest-grant.service",)
    return [r for r in required if r not in text]


# dispatch A9BF01A9 (amending BD5843FD) markers below: the atomic sync+sign
# (gap c1395b307421's real defect), the carried gpg fix (338bbdb), and the
# envelope.ratify bootstrap seed (gap 18affe49e198).

_GPG_PATH_OUTPUT_PATTERN = '-o "$SIG_TMP"'


def _install_sh_gpg_writes_to_a_path_offenders(install_sh_text: str) -> list[str]:
    """338bbdb: gpg must never be handed a path to open for writing (it runs
    as a different uid than the one that created the temp file) — every
    detached-sign call uses `--output -` into a shell redirection instead.
    Returns the offending lines' count as a list so the assert reads like
    the other scan helpers here (empty == clean)."""
    body = _script_body(install_sh_text)
    return [_GPG_PATH_OUTPUT_PATTERN for _ in body.split("\n") if _GPG_PATH_OUTPUT_PATTERN in _]


_ONE_ACT_SYNC_SIGN_MARKERS = (
    "sync_and_sign", "--sign-as", "seed_envelope_ratify.py",
)


def _install_sh_missing_one_act_markers(install_sh_text: str) -> list[str]:
    """Dispatch A9BF01A9: step 1c's sync and sign must be one act
    (sync_constitutional.py's --sign-as/sync_and_sign path), and the
    envelope.ratify bootstrap envelope must be seeded."""
    body = _script_body(install_sh_text)
    return [marker for marker in _ONE_ACT_SYNC_SIGN_MARKERS if marker not in body]


def _install_sh_syscall_table_double_signed(install_sh_text: str) -> bool:
    """True if $SYSCALL_TABLE still appears in step 6's re-sign loop — it
    must not: step 1c signs it atomically, in the same act as the sync;
    step 6 re-signing it again is not just redundant, it reopens the
    two-acts-not-one window this PR exists to close."""
    body = _script_body(install_sh_text)
    return '"$REG" "$SYSCALL_TABLE"' in body


def _old_template_has_a_fixed_user_line(text: str) -> bool:
    """True only for an actual `User=<name>` CONFIG line with no template
    placeholder — never a comment mentioning `User=` in prose."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("User=") and "@" not in stripped:
            return True
    return False


# dispatch B291C0C7 ("one signing key, one source of truth"), amending
# A9BF01A9: --rotate/--check-signatures/--retire, the pgp.conf strip, and
# retire-only-after-verify ordering.

_ROTATE_REQUIRED_MARKERS = (
    "--rotate", "--check-signatures", "--retire", "governed_files",
    "rotate_resign.py", "frank_head_anchor.json",
)


def _install_sh_missing_rotate_markers(install_sh_text: str) -> list[str]:
    body = _script_body(install_sh_text)
    return [marker for marker in _ROTATE_REQUIRED_MARKERS if marker not in body]


def _install_sh_retires_before_verify(install_sh_text: str) -> bool:
    """True (a defect) only if a `--delete-secret-and-public-key` call
    appears BEFORE the post-rotate `--check` verification — the old key
    must survive until every governed file is confirmed to verify under
    the new one."""
    body = _script_body(install_sh_text)
    idx_delete = body.find("delete-secret-and-public-key")
    idx_verify = body.find('rotate_resign.py" --check --fingerprint "$NEW_FPR"')
    if idx_delete == -1 or idx_verify == -1:
        return False
    return idx_delete < idx_verify


_F_B_REQUIRED_MARKERS = (
    "TRUST_ENV_FPR", "STALE_KEY_MARKER", "retire_stale_key_if_marked",
    "list-secret-keys",
)


def _install_sh_missing_f_b_markers(install_sh_text: str) -> list[str]:
    """F-B (dispatch 10F9E837, Loki audit 23DE8AA9): step 1b must prefer
    trust.env's own fingerprint (checked via list-secret-keys) over the
    $KEY_UID substring lookup, and a failed retire must persist as a named
    marker a later run retries -- not merely print a warning."""
    body = _script_body(install_sh_text)
    return [marker for marker in _F_B_REQUIRED_MARKERS if marker not in body]


def _install_sh_step_1b_prefers_trust_env_fpr(install_sh_text: str) -> bool:
    """True (correct) only when the TRUST_ENV_FPR check appears BEFORE the
    $KEY_UID substring lookup in step 1b -- the ordering that actually
    prevents the F-B reversion (checking trust.env first, falling back to
    the substring search only when its key is gone)."""
    body = _script_body(install_sh_text)
    idx_prefer = body.find("TRUST_ENV_FPR=")
    idx_fallback = body.find('gpg --batch --list-keys --with-colons "$KEY_UID"')
    if idx_prefer == -1 or idx_fallback == -1:
        return False
    return idx_prefer < idx_fallback


def _install_sh_missing_pgp_dropin_strip(install_sh_text: str) -> bool:
    body = _script_body(install_sh_text)
    return "willow-mcp-serve.service.d/pgp.conf" not in body


def test_plant_every_deploy_scan_helper_catches_its_violation():
    """Plants one violation per scan helper above and shows each one fires."""
    assert _missing_pair_citations("no citations here") == list(_SEALED_PAIRS)
    assert _missing_pair_citations("1fdfbdf3 and 1bd6fd29 both cited") == []

    assert _install_sh_glob_offenders("set -euo pipefail\nfor f in *.pub; do :; done") == ["*.pub"]
    assert _install_sh_glob_offenders(
        "the header may say *.pub / *public* in prose\nset -euo pipefail\nno globs in the body"
    ) == []

    assert "broker_public_key.pub" in _install_sh_missing_known_names("set -euo pipefail\nnothing here")
    assert _install_sh_missing_known_names(
        "set -euo pipefail\nbroker_public_key.pub willow-mcp-serve.service willow-mcp.service"
    ) == []

    assert _install_sh_estale_presigned_problems("nothing here") == [
        "no estale_presigned", "no flat **rec, result spread",
    ]
    assert _install_sh_estale_presigned_problems(
        'json.dump({**rec, "result": out}, ...)  # estale_presigned'
    ) == []
    assert "nested request wrapper present" in _install_sh_estale_presigned_problems(
        '{"pair_id": ..., "result": out, "request": rec}  # estale_presigned'
    )

    assert _service_unit_missing("") == ["[Service]", "User=willow-operator", "ReadWritePaths=", "constitutional"]
    assert _service_unit_missing(
        "[Service]\nUser=willow-operator\nReadWritePaths=/x\nconstitutional"
    ) == []

    assert _timer_missing("") == ["Unit=willow-mcp-manifest-grant.service"]
    assert _timer_missing("Unit=willow-mcp-manifest-grant.service") == []

    assert _old_template_has_a_fixed_user_line("User=someone\n") is True
    assert _old_template_has_a_fixed_user_line("# a comment mentioning User= in prose\n") is False
    assert _old_template_has_a_fixed_user_line("User=@TRUST_OWNER@\n") is False

    assert _install_sh_fixed_tmp_names(
        "set -euo pipefail\ninstall x /tmp/manifest-grant.env\n"
    ) == ["/tmp/manifest-grant.env"]
    assert _install_sh_fixed_tmp_names("set -euo pipefail\nENV_TMP=$(mktemp)\n") == []

    assert _install_sh_missing_f7_checks("set -euo pipefail\nnothing here") == list(_F7_REQUIRED_MARKERS)
    assert _install_sh_missing_f7_checks(
        "set -euo pipefail\nmktemp trust-owner python interpreter traversal"
    ) == []

    assert _install_sh_6b_before_restart(
        "set -euo pipefail\n...6b. withdraw every request...\nrestart_broker\n"
    ) is True
    assert _install_sh_6b_before_restart(
        "set -euo pipefail\nrestart_broker\n...6b. withdraw every request..."
    ) is False
    assert _install_sh_6b_before_restart("neither marker present") is False

    assert _install_sh_gpg_writes_to_a_path_offenders(
        'set -euo pipefail\nas_to gpg --detach-sign -o "$SIG_TMP" "$f"\n'
    ) == ['-o "$SIG_TMP"']
    assert _install_sh_gpg_writes_to_a_path_offenders(
        'set -euo pipefail\nas_to gpg --detach-sign --output - "$f" > "$SIG_TMP"\n'
    ) == []

    assert _install_sh_missing_one_act_markers("set -euo pipefail\nnothing here") == list(
        _ONE_ACT_SYNC_SIGN_MARKERS
    )
    assert _install_sh_missing_one_act_markers(
        "set -euo pipefail\nsync_and_sign --sign-as x seed_envelope_ratify.py"
    ) == []

    assert _install_sh_syscall_table_double_signed(
        'set -euo pipefail\nfor f in "$REG" "$SYSCALL_TABLE" "$H/mcp_apps/_federation/servers.json"; do :; done'
    ) is True
    assert _install_sh_syscall_table_double_signed(
        'set -euo pipefail\nfor f in "$REG" "$H/mcp_apps/_federation/servers.json"; do :; done'
    ) is False

    assert _install_sh_missing_rotate_markers("set -euo pipefail\nnothing here") == list(
        _ROTATE_REQUIRED_MARKERS
    )
    assert _install_sh_missing_rotate_markers(
        "set -euo pipefail\n" + " ".join(_ROTATE_REQUIRED_MARKERS)
    ) == []

    assert _install_sh_retires_before_verify(
        'set -euo pipefail\ndelete-secret-and-public-key\nrotate_resign.py" --check --fingerprint "$NEW_FPR"\n'
    ) is True
    assert _install_sh_retires_before_verify(
        'set -euo pipefail\nrotate_resign.py" --check --fingerprint "$NEW_FPR"\ndelete-secret-and-public-key\n'
    ) is False
    assert _install_sh_retires_before_verify("neither marker present") is False

    assert _install_sh_missing_pgp_dropin_strip("set -euo pipefail\nnothing here") is True
    assert _install_sh_missing_pgp_dropin_strip(
        "set -euo pipefail\nwillow-mcp-serve.service.d/pgp.conf"
    ) is False

    assert _install_md_missing_required_content("nothing here") == list(_INSTALL_MD_REQUIRED_STRINGS)
    assert _install_md_missing_required_content(" ".join(_INSTALL_MD_REQUIRED_STRINGS)) == []

    assert _install_md_still_claims_home_env_is_the_source(
        "`$H/env` is now the **one** source of truth"
    ) is True
    assert _install_md_still_claims_home_env_is_the_source(
        "`trust.env` is now the one source of truth"
    ) is False

    assert _install_md_missing_reconnect_is_not_enough_caveat("reconnecting just works") is True
    assert _install_md_missing_reconnect_is_not_enough_caveat(
        "reconnecting that session is NOT enough by itself"
    ) is False

    assert _install_md_still_claims_step_4_is_point_of_no_return(
        "Step 4 is the point of no return, everything before it is reversible"
    ) is True
    assert _install_md_still_claims_step_4_is_point_of_no_return(
        "nothing about step numbering at all"
    ) is True
    assert _install_md_still_claims_step_4_is_point_of_no_return(
        "the real point of no return is step 3, not step 4"
    ) is False

    assert _install_md_missing_step_3_outage_window("nothing about an outage here") is True
    assert _install_md_missing_step_3_outage_window(
        "THE FLEET GOES DOWN HERE, FAIL-CLOSED, until step 4 completes"
    ) is False

    assert _install_md_missing_step_2_to_3_reconnect_warning("reconnect whenever you like") is True
    assert _install_md_missing_step_2_to_3_reconnect_warning(
        "Do not reconnect the desk between this step and step 4"
    ) is False

    assert _install_md_missing_m1_explanation("nothing about the deadlock here") is True
    assert _install_md_missing_m1_explanation(
        "why step 1d does not deadlock, dispatch FA4F79AC: sign_as bypasses the check"
    ) is False

    assert _install_md_still_claims_a_stop_anywhere_leaves_the_box_as_it_was(
        "a stop anywhere before the write leaves the box exactly as it was"
    ) is True
    assert _install_md_still_claims_a_stop_anywhere_leaves_the_box_as_it_was(
        "no residual section at all"
    ) is True
    assert _install_md_still_claims_a_stop_anywhere_leaves_the_box_as_it_was(
        "the syscall-table residual: a stop after step 1c leaves the box fail-closed, "
        "not as it was, but recoverable"
    ) is False

    assert _install_md_missing_vault_ruling_and_closure("nothing about a vault here") is True
    assert _install_md_missing_vault_ruling_and_closure(
        "rework #4, Loki audit 23DE8AA9, F-C reverted WILLOW_VAULT_BOX -- a broker-settable "
        "variable is a worse problem; the rename-away hole is UNCHANGED and still open"
    ) is False

    assert _install_md_missing_f_a_explanation("nothing about a fresh install here") is True
    assert _install_md_missing_f_a_explanation(
        "F-A: a truly fresh install, no register at all, dispatch 10F9E837, "
        "_load_active_register treats it as active: []"
    ) is False

    assert _install_md_missing_f_b_explanation("nothing about a failed retire here") is True
    assert _install_md_missing_f_b_explanation(
        "F-B: a failed retire, dispatch 10F9E837, .stale_trust_key, "
        "step 1b prefers trust.env's own fingerprint"
    ) is False

    assert _install_sh_missing_f_b_markers("set -euo pipefail\nnothing here") == list(
        _F_B_REQUIRED_MARKERS
    )
    assert _install_sh_missing_f_b_markers(
        "set -euo pipefail\n" + " ".join(_F_B_REQUIRED_MARKERS)
    ) == []

    assert _install_sh_step_1b_prefers_trust_env_fpr(
        'set -euo pipefail\nTRUST_ENV_FPR=x\ngpg --batch --list-keys --with-colons "$KEY_UID"\n'
    ) is True
    assert _install_sh_step_1b_prefers_trust_env_fpr(
        'set -euo pipefail\ngpg --batch --list-keys --with-colons "$KEY_UID"\nTRUST_ENV_FPR=x\n'
    ) is False
    assert _install_sh_step_1b_prefers_trust_env_fpr("neither marker present") is False


def test_all_five_files_present():
    for name in (
        "INSTALL.md", "install.sh", "willow-mcp-manifest-grant.service",
        "willow-mcp-manifest-grant.timer", "manifest-grant.env",
    ):
        assert (_DEPLOY / name).is_file(), f"missing {name}"


def test_install_md_documents_trust_env_and_the_mcp_json_pin():
    """N3 BLOCKING-per-re-audit: the prior round's closeout claimed this
    file was updated; `git diff --stat` for those commits had no
    INSTALL.md in it at all. This asserts the CONTENT a re-audit actually
    checked for, not merely that some line changed."""
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing_required_content(text) == []


def test_install_md_no_longer_claims_home_env_is_the_source_of_truth():
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_still_claims_home_env_is_the_source(text) is False


def test_install_md_no_longer_claims_reconnect_alone_picks_up_a_new_key():
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing_reconnect_is_not_enough_caveat(text) is False


# ── Loki audit D06A0EF3 (rework #3, dispatch FA4F79AC): M1 install
# deadlock, M2 point-of-no-return mislabelled, N1 syscall-table residual,
# and the vault location's honest closure argument. Each check below is a
# module-level helper, planted in test_plant_every_deploy_scan_helper_
# catches_its_violation like every other scan in this file. ────────────

def _install_md_still_claims_step_4_is_point_of_no_return(text: str) -> bool:
    return "Step 4 is the point of no return" in text or "step 3, not step 4" not in text


def _install_md_missing_step_3_outage_window(text: str) -> bool:
    return not ("fleet goes down here" in text.lower() and "fail-closed" in text.lower())


def _install_md_missing_step_2_to_3_reconnect_warning(text: str) -> bool:
    return "do not reconnect the desk between this step and step" not in text.lower()


def _install_md_missing_m1_explanation(text: str) -> bool:
    return not ("does not deadlock" in text and "sign_as" in text and "FA4F79AC" in text)


def _install_md_still_claims_a_stop_anywhere_leaves_the_box_as_it_was(text: str) -> bool:
    """N1 residual: the false blanket claim this document used to make."""
    return (
        "a stop anywhere before the write leaves the box exactly as it was" in text
        or "syscall-table residual" not in text
    )


def _install_md_missing_vault_ruling_and_closure(text: str) -> bool:
    """F-C (dispatch 10F9E837, Loki audit 23DE8AA9): the document must
    explain that the WILLOW_VAULT_BOX-based location was reverted (not
    silently dropped), name F-C, and still state honestly that the
    rename-away hole is unchanged and open — never claim the reverted
    recipe closed it."""
    lowered = text.lower()
    return not (
        "23de8aa9" in lowered
        and "f-c" in lowered
        and "willow_vault_box" in lowered
        and ("reverted" in lowered or "revert" in lowered)
        and "unchanged" in lowered
        and "still open" in lowered
    )


def _install_md_missing_f_a_explanation(text: str) -> bool:
    lowered = text.lower()
    return not (
        "f-a" in lowered
        and "10f9e837" in lowered
        and "fresh install" in lowered
        and "_load_active_register" in text
    )


def _install_md_missing_f_b_explanation(text: str) -> bool:
    lowered = text.lower()
    return not (
        "f-b" in lowered
        and "10f9e837" in lowered
        and ".stale_trust_key" in lowered
        and "trust.env" in lowered
    )


def test_install_md_no_longer_claims_step_4_is_the_point_of_no_return():
    """M2: the real point of no return is step 3 (the code deploy itself
    puts an already-provisioned box into a fail-closed outage, before
    step 4 ever runs) — the prior draft's "Step 4 is the point of no
    return" is corrected."""
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_still_claims_step_4_is_point_of_no_return(text) is False


def test_install_md_documents_the_step_3_outage_window():
    """M2: the fleet-down window opened by deploying the code before
    trust.env exists must be named explicitly, with what is down and why
    it is safe (fail-closed, not a bug)."""
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing_step_3_outage_window(text) is False


def test_install_md_documents_the_step_2_to_3_enforcement_off_window():
    """M2: a desk reconnect between removing its .mcp.json pin (step 2)
    and deploying the new code (step 3) runs with NO fingerprint at all —
    named explicitly, not left implicit."""
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing_step_2_to_3_reconnect_warning(text) is False


def test_install_md_documents_m1_and_why_step_1d_does_not_deadlock():
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing_m1_explanation(text) is False


def test_install_md_no_longer_claims_a_stop_anywhere_leaves_the_box_exactly_as_it_was():
    """N1 residual: the prior draft's blanket claim ('a stop anywhere
    before the write leaves the box exactly as it was') is false once
    step 1c has already succeeded — corrected to name the real, fail-closed,
    recoverable-by-rerun state instead."""
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_still_claims_a_stop_anywhere_leaves_the_box_as_it_was(text) is False


def test_install_md_documents_the_vault_ruling_and_its_closure_condition():
    """F-C (dispatch 10F9E837): the document explains that the
    WILLOW_VAULT_BOX-based location was reverted, names F-C, and states
    the rename-away hole is unchanged and still open — never claims the
    reverted recipe closed it."""
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing_vault_ruling_and_closure(text) is False


def test_install_md_documents_f_a_the_fresh_install_fix():
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing_f_a_explanation(text) is False


def test_install_md_documents_f_b_the_failed_retire_fix():
    text = (_DEPLOY / "INSTALL.md").read_text(encoding="utf-8")
    assert _install_md_missing_f_b_explanation(text) is False


def test_install_sh_has_the_f_b_markers_and_ordering():
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_missing_f_b_markers(text) == []
    assert _install_sh_step_1b_prefers_trust_env_fpr(text) is True


def test_install_sh_no_longer_resolves_trust_env_through_vault_box():
    """F-C: install.sh's own TRUST_ENV resolution must not READ
    $WILLOW_VAULT_BOX at all (the bare word may still appear in comments
    explaining why it was reverted) -- a fixed $H/constitutional/trust.env,
    matching paths.trust_config_path() exactly."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    body = _script_body(text)
    assert 'TRUST_ENV="$H/constitutional/trust.env"' in body
    assert "$WILLOW_VAULT_BOX" not in body
    assert "${WILLOW_VAULT_BOX" not in body


def test_every_file_cites_both_sealed_pairs():
    for name in (
        "install.sh", "willow-mcp-manifest-grant.service",
        "willow-mcp-manifest-grant.timer", "manifest-grant.env",
    ):
        text = (_DEPLOY / name).read_text(encoding="utf-8")
        assert _missing_pair_citations(text) == [], f"{name} missing a sealed-pair citation"


def test_service_unit_is_a_system_unit_under_the_trust_owner():
    text = (_DEPLOY / "willow-mcp-manifest-grant.service").read_text(encoding="utf-8")
    assert _service_unit_missing(text) == []


def test_timer_unit_matches_the_service_name():
    text = (_DEPLOY / "willow-mcp-manifest-grant.timer").read_text(encoding="utf-8")
    assert _timer_missing(text) == []


def test_install_sh_has_no_fixed_tmp_names():
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_fixed_tmp_names(text) == []


def test_install_sh_has_the_f7_preflight_and_ordering_fixes():
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_missing_f7_checks(text) == []
    assert _install_sh_6b_before_restart(text) is True


# ── Loki re-audit 93D0F057, N3: "claimed but not done" last round — this
# time the diff is in evidence (see the handoff), and this test proves the
# CONTENT, not just that some edit happened. ────────────────────────────

_INSTALL_MD_REQUIRED_STRINGS = (
    "trust.env",              # the one source of truth is named
    ".mcp.json",              # the desk's pin is named
    "point of no return",     # N3: mark it
    "--check-signatures",     # N3: first step is a read-only check
    "report-only",            # N4: that check must work with no trust.env yet
    "WILLOW_VAULT_BOX",       # FA4F79AC: the location ruling, named
    "rename-away",            # FA4F79AC: the closure argument is not silently assumed
)


def _install_md_missing_required_content(text: str) -> list[str]:
    return [s for s in _INSTALL_MD_REQUIRED_STRINGS if s not in text]


def _install_md_still_claims_home_env_is_the_source(text: str) -> bool:
    """The stale claim Loki measured: '$H/env is the one source'. The
    fingerprint's source is trust.env now; $H/env is still named (it
    holds secrets, and the migration step references it), but never as
    THE source of the fingerprint."""
    return "$H/env` is now the **one**" in text or "$H/env` is now the one" in text


def _install_md_missing_reconnect_is_not_enough_caveat(text: str) -> bool:
    """The stale claim Loki measured (F2): reconnecting a stdio desk
    session picks up a new fingerprint. It does not, when that session's
    own .mcp.json still pins one — this must be said explicitly, not
    implied to just work."""
    return "NOT enough" not in text


def test_install_sh_has_no_glob_for_broker_public_key_or_broker_unit():
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_glob_offenders(text) == []
    assert _install_sh_missing_known_names(text) == []


def test_install_sh_writes_estale_presigned_in_the_move_shape():
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_estale_presigned_problems(text) == []


def test_install_sh_is_valid_bash_syntax():
    result = subprocess.run(
        ["bash", "-n", str(_DEPLOY / "install.sh")], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_install_sh_shellcheck_clean_if_available():
    if subprocess.run(["which", "shellcheck"], capture_output=True).returncode != 0:
        pytest.skip("shellcheck not installed in this sandbox — CI leg, not covered here")
    result = subprocess.run(
        ["shellcheck", str(_DEPLOY / "install.sh")], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_install_sh_never_hands_gpg_a_path_to_open_for_writing():
    """338bbdb, carried onto this branch: gpg always runs as a DIFFERENT uid
    than the one that created the temp file — a path handed to `-o` fails
    with EACCES (measured on the box, first real two-uid run). Every sign
    call uses `--output -` instead."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_gpg_writes_to_a_path_offenders(text) == []


def test_install_sh_syncs_and_signs_syscall_table_as_one_act_and_seeds_the_bootstrap_envelope():
    """Dispatch A9BF01A9: the real defect the operator's first live run
    measured was step 1c (sync) and step 6 (sign) being TWO acts, with real
    wall-clock time and several other steps in between — any interruption
    in that window leaves an edited-but-unsigned governance file. Step 1c
    must now sync and sign in one call (sync_and_sign, via --sign-as), and
    step 6 must not re-sign syscall-table.json a second time. Also: the
    envelope.ratify bootstrap envelope (gap 18affe49e198) must be seeded
    somewhere in the script."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_missing_one_act_markers(text) == []
    assert _install_sh_syscall_table_double_signed(text) is False


def test_install_sh_key_setup_runs_before_the_atomic_sync_and_sign_step():
    """$FPR must exist before step 1c calls sync_constitutional.py
    --sign-as — the signing-key step was moved ahead of it for exactly this
    reason (dispatch A9BF01A9)."""
    body = _script_body((_DEPLOY / "install.sh").read_text(encoding="utf-8"))
    idx_key = body.find("signing key owned by")
    idx_sync_sign = body.find("sync + sign constitutional policy files")
    assert idx_key != -1, "signing-key step not found"
    assert idx_sync_sign != -1, "sync+sign step not found"
    assert idx_key < idx_sync_sign


def test_install_sh_writes_trust_env_exactly_once_from_one_shared_function():
    """Loki re-audit 93D0F057, N1: the plain install used to publish
    trust.env at step 1b, separately from --rotate's own write, and could
    drift out of sync with it (F3's pattern recurring in the plain-install
    path). There is now exactly ONE place in the whole script that installs
    a file at $TRUST_ENV — inside sign_and_publish_trust — proving both
    the plain install and --rotate call the same sequence rather than
    maintaining two orderings."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    body = _script_body(text)
    write_marker = 'install -o "$TRUST_OWNER" -g "$TRUST_OWNER" -m 644 "$TRUST_TMP" "$TRUST_ENV"'
    assert body.count(write_marker) == 1, (
        f"expected exactly one $TRUST_ENV write site, found {body.count(write_marker)}"
    )
    # And it must live inside sign_and_publish_trust, not inside step 1b.
    idx_write = body.find(write_marker)
    idx_shared_fn = body.find("sign_and_publish_trust() {")
    idx_step_1c = body.find("1c. sync + sign constitutional")
    assert idx_shared_fn != -1 and idx_step_1c != -1
    assert idx_shared_fn < idx_write < idx_step_1c, (
        "the $TRUST_ENV write must live inside sign_and_publish_trust's own "
        "definition, which install.sh defines before step 1c ever runs"
    )


def test_install_sh_step_6_calls_the_shared_sign_and_publish_function():
    """The plain install's step 6 must call sign_and_publish_trust rather
    than re-sign files with its own independent loop (N1) — this also
    means it now covers frank_head_anchor.json and ratified seeds via
    governed_files(), which the old step 6 loop never did."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    body = _script_body(text)
    idx_step6 = body.find('say "== 6. re-sign everything under $FPR')
    assert idx_step6 != -1
    tail = body[idx_step6:idx_step6 + 400]
    assert 'sign_and_publish_trust "$FPR" "$OLD_TRUST_FPR"' in tail


def _extract_strip_pgp_pin_heredoc(install_sh_text: str) -> str:
    """The Python tokenizer embedded in `strip_pgp_pin()`'s
    `"$PY" - "$dropin" <<'PYEOF' ... PYEOF` heredoc, extracted so it can
    be executed directly against synthetic drop-in files — the only way
    to prove the REAL logic handles a given Environment= shape, rather
    than eyeballing the regex."""
    marker_start = '"$PY" - "$dropin" <<\'PYEOF\'\n'
    start = install_sh_text.index(marker_start) + len(marker_start)
    end = install_sh_text.index("\nPYEOF", start)
    return install_sh_text[start:end]


@pytest.mark.parametrize(
    "dropin_line",
    [
        'Environment="WILLOW_PGP_FINGERPRINT=9B6F87BEB4AE56E2000000000000000000000000"',
        'Environment="FOO=1" "WILLOW_PGP_FINGERPRINT=9B6F87BEB4AE56E2000000000000000000000000"',
        'Environment = "WILLOW_PGP_FINGERPRINT=9B6F87BEB4AE56E2000000000000000000000000"',
        'WILLOW_PGP_FINGERPRINT=9B6F87BEB4AE56E2000000000000000000000000',
    ],
    ids=["quoted-solo", "multi-token", "spaced-equals", "bare-legacy"],
)
def test_strip_pgp_pin_heredoc_actually_strips_every_real_shape(tmp_path, dropin_line):
    """Loki audit A38D41C2 F1 and its re-audit residual (93D0F057): proves
    the REAL extracted tokenizer — not a paraphrase of it — removes the
    fingerprint token from every shape systemd's Environment= directive
    can actually take, including two the first cut's sed missed:
    `Environment="FOO=1" "WILLOW_PGP_FINGERPRINT=..."` (a second
    assignment sharing the line) and `Environment = "..."` (space before
    the `=`)."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    heredoc_src = _extract_strip_pgp_pin_heredoc(text)
    script = tmp_path / "strip.py"
    script.write_text(heredoc_src, encoding="utf-8")
    dropin = tmp_path / "pgp.conf"
    dropin.write_text(f"[Service]\n{dropin_line}\n", encoding="utf-8")
    result = subprocess.run(
        ["python3", str(script), str(dropin)], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    final = dropin.read_text(encoding="utf-8")
    assert "WILLOW_PGP_FINGERPRINT" not in final, (
        f"pin survived the strip for shape {dropin_line!r}: {final!r}"
    )


def test_strip_pgp_pin_heredoc_preserves_an_unrelated_token_on_the_same_line(tmp_path):
    """The multi-token shape must not delete the WHOLE line just because
    it also carries the fingerprint — only that one token."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    heredoc_src = _extract_strip_pgp_pin_heredoc(text)
    script = tmp_path / "strip.py"
    script.write_text(heredoc_src, encoding="utf-8")
    dropin = tmp_path / "pgp.conf"
    dropin.write_text(
        '[Service]\nEnvironment="FOO=1" "WILLOW_PGP_FINGERPRINT=AAAA"\n', encoding="utf-8"
    )
    subprocess.run(["python3", str(script), str(dropin)], check=True, capture_output=True)
    final = dropin.read_text(encoding="utf-8")
    assert "FOO=1" in final
    assert "WILLOW_PGP_FINGERPRINT" not in final


_TRACKED_SHEBANG_SCRIPTS = (
    _DEPLOY / "install.sh",
    _DEPLOY / "sync_constitutional.py",
    _DEPLOY / "seed_envelope_ratify.py",
    _DEPLOY / "rotate_resign.py",
)


def test_tracked_shebang_scripts_are_executable():
    """`sudo <path>` (as opposed to `sudo bash <path>`) fails with
    'Permission denied (os error 13)' on a tracked 0644 script — measured
    on the box. Any tracked file whose first two bytes are `#!` must carry
    at least one executable bit in git's own tree, not just on disk (a
    worktree checkout can pick up the filesystem's umask; this checks the
    mode git actually tracks)."""
    import stat as _stat

    for path in _TRACKED_SHEBANG_SCRIPTS:
        assert path.is_file(), f"missing {path}"
        first_bytes = path.read_bytes()[:2]
        assert first_bytes == b"#!", f"{path} does not start with a shebang"
        mode = path.stat().st_mode
        assert mode & _stat.S_IXUSR, f"{path} is not executable (mode {oct(mode)})"

    result = subprocess.run(
        ["git", "ls-files", "-s", *(str(p) for p in _TRACKED_SHEBANG_SCRIPTS)],
        cwd=_DEPLOY.parents[1], capture_output=True, text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().splitlines():
            git_mode = line.split()[0]
            assert git_mode == "100755", f"git tracks a non-executable mode: {line}"
    else:
        pytest.skip("not inside the git checkout this test expects (git ls-files unavailable)")


def test_install_sh_has_rotate_check_signatures_and_retire():
    """Dispatch B291C0C7: --rotate generates a new key, writes it to
    $H/env and $ETC/manifest-grant.env, re-signs every governed file as
    one atomic batch (rotate_resign.py), and only then retires the old
    key(s); --check-signatures reports which fingerprint each governed
    file verifies under right now."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_missing_rotate_markers(text) == []


def test_install_sh_rotate_retires_old_key_only_after_verifying_the_new_one():
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_retires_before_verify(text) is False


def test_install_sh_strips_the_serve_units_own_pgp_pin():
    """The split brain this dispatch closes: a per-file WILLOW_PGP_FINGERPRINT
    pin in the serve unit's own systemd drop-in, disagreeing with $H/env."""
    text = (_DEPLOY / "install.sh").read_text(encoding="utf-8")
    assert _install_sh_missing_pgp_dropin_strip(text) is False


def test_bundle_manifest_grant_template_is_the_retired_user_unit_design():
    """No existing template covers the NEW system-unit shape this PR adds
    (the assignment's own "if there is none, say so in the handoff" clause);
    the OLD one is the --user design this install RETIRES (INSTALL.md step
    2), and is not expected to match it — a different deployment model."""
    if not _BUNDLE_TEMPLATE.is_file():
        pytest.skip("no bundle template for the --user manifest-grant unit exists at all")
    old_text = _BUNDLE_TEMPLATE.read_text(encoding="utf-8")
    new_text = (_DEPLOY / "willow-mcp-manifest-grant.service").read_text(encoding="utf-8")
    assert _old_template_has_a_fixed_user_line(old_text) is False
    assert _service_unit_missing(new_text) == []
    assert old_text != new_text
