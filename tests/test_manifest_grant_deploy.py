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
    content alone."""
    body = _script_body(install_sh_text)
    idx_6b = body.find("6b. withdraw every request")
    idx_restart = body.find("broker restart (WILLOW_PGP_FINGERPRINT changed")
    if idx_6b == -1 or idx_restart == -1:
        return False
    return idx_6b < idx_restart


def _service_unit_missing(text: str) -> list[str]:
    required = ("[Service]", "User=willow-operator", "ReadWritePaths=", "constitutional")
    return [r for r in required if r not in text]


def _timer_missing(text: str) -> list[str]:
    required = ("Unit=willow-mcp-manifest-grant.service",)
    return [r for r in required if r not in text]


def _old_template_has_a_fixed_user_line(text: str) -> bool:
    """True only for an actual `User=<name>` CONFIG line with no template
    placeholder — never a comment mentioning `User=` in prose."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("User=") and "@" not in stripped:
            return True
    return False


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
        "...6b. withdraw every request...\n...broker restart (WILLOW_PGP_FINGERPRINT changed..."
    ) is True
    assert _install_sh_6b_before_restart(
        "...broker restart (WILLOW_PGP_FINGERPRINT changed...\n...6b. withdraw every request..."
    ) is False
    assert _install_sh_6b_before_restart("neither marker present") is False


def test_all_five_files_present():
    for name in (
        "INSTALL.md", "install.sh", "willow-mcp-manifest-grant.service",
        "willow-mcp-manifest-grant.timer", "manifest-grant.env",
    ):
        assert (_DEPLOY / name).is_file(), f"missing {name}"


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
