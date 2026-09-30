"""`constitutional.apply_evaluated_syscall_sync` signs what it writes (gap 90b43b45d99a).

On 2026-09-30 12:40 the first successful syscall.sync left a stale ``.sig``
beside the new table and every trusted read refused until the operator
re-signed by hand. The apply now signs exactly as
``envelope_authoring._save_active`` does: sign a tmp candidate, rename the
``.sig`` into place BEFORE the content, refuse before any write when signing
fails, and repair a content-current table whose signature does not verify.

Signing is exercised with FAKE sign/verify callables (same approach as
``tests/test_sync_constitutional.py``) -- never real gpg.
"""
from __future__ import annotations

import json

import pytest

from tests.test_constitutional import _FakeLedger, _row, _write_table
from willow_mcp import constitutional, pgp

FP = "AB" * 20


class _FakeSigner:
    """sign_fn/verify_fn pair. The 'signature' is ``SIG:`` + the signed bytes."""

    def __init__(self, live, *, fail_signing=False):
        self.live = live
        self.fail_signing = fail_signing
        self.calls = []

    def sign_fn(self, path, local_user=""):
        live_sig = pgp.detached_sig_path(self.live)
        self.calls.append({
            "path": path.name,
            "local_user": local_user,
            "live_bytes": self.live.read_bytes(),
            "live_sig": live_sig.read_bytes() if live_sig.exists() else None,
        })
        if self.fail_signing:
            return False, "fake gpg: agent down"
        pgp.detached_sig_path(path).write_bytes(b"SIG:" + path.read_bytes())
        return True, "ok"

    def verify_fn(self, path):
        sig = pgp.detached_sig_path(path)
        if not sig.exists():
            return False, "no signature file"
        if sig.read_bytes() != b"SIG:" + path.read_bytes():
            return False, "bad signature"
        return True, "signature verified"


@pytest.fixture
def tables(tmp_path):
    tmp_path.chmod(0o700)
    live = tmp_path / "live" / "syscall-table.json"
    bundle = tmp_path / "bundle" / "syscall-table.json"
    live.parent.mkdir()
    bundle.parent.mkdir()
    return live, bundle


def _sign_in_place(live):
    pgp.detached_sig_path(live).write_bytes(b"SIG:" + live.read_bytes())


def _files(directory):
    return sorted(p.name for p in directory.iterdir())


def test_apply_signs_what_it_writes_and_sig_lands_before_content(tables):
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _sign_in_place(live)
    _write_table(bundle, [_row(1, "git.push"), _row(2, "pr.open")])
    old_bytes = live.read_bytes()
    old_sig = pgp.detached_sig_path(live).read_bytes()
    signer = _FakeSigner(live)

    plan = constitutional.evaluate_syscall_table_sync(
        live_path=live, bundle_path=bundle,
        verify_fn=signer.verify_fn, fingerprint=FP,
    )
    assert plan["needs_apply"] is True and not plan.get("resign_only")
    out = constitutional.apply_evaluated_syscall_sync(
        plan, live_path=live, ledger=_FakeLedger(),
        sign_fn=signer.sign_fn, fingerprint=FP,
    )

    assert out["ok"] is True, out
    # signed under the configured fingerprint, a TMP candidate, while the live
    # table and its .sig were still the old pair
    assert len(signer.calls) == 1
    call = signer.calls[0]
    assert call["path"] == "syscall-table.json.tmp"
    assert call["local_user"] == FP
    assert call["live_bytes"] == old_bytes
    assert call["live_sig"] == old_sig
    # afterwards the live pair verifies, and nothing is left behind
    assert {r["id"] for r in json.loads(live.read_text())["verbs"]} == {1, 2}
    assert signer.verify_fn(live) == (True, "signature verified")
    assert _files(live.parent) == ["syscall-table.json", "syscall-table.json.sig"]


def test_sign_failure_writes_nothing_and_leaves_prior_table_and_sig(tables):
    live, bundle = tables
    _write_table(live, [_row(1, "git.push")])
    _sign_in_place(live)
    _write_table(bundle, [_row(1, "git.push"), _row(2, "pr.open")])
    old_bytes = live.read_bytes()
    old_sig = pgp.detached_sig_path(live).read_bytes()
    signer = _FakeSigner(live, fail_signing=True)

    plan = constitutional.evaluate_syscall_table_sync(
        live_path=live, bundle_path=bundle,
        verify_fn=signer.verify_fn, fingerprint=FP,
    )
    out = constitutional.apply_evaluated_syscall_sync(
        plan, live_path=live, ledger=_FakeLedger(),
        sign_fn=signer.sign_fn, fingerprint=FP,
    )

    assert out["ok"] is False and out["refused"] is True
    assert "agent down" in out["reason"]
    assert live.read_bytes() == old_bytes
    assert pgp.detached_sig_path(live).read_bytes() == old_sig
    assert _files(live.parent) == ["syscall-table.json", "syscall-table.json.sig"]


def test_stale_sig_on_current_content_plans_a_resign_not_a_noop(tables):
    live, bundle = tables
    rows = [_row(1, "git.push"), _row(2, "pr.open")]
    _write_table(live, rows)
    _write_table(bundle, rows)
    pgp.detached_sig_path(live).write_bytes(b"STALE")
    signer = _FakeSigner(live)

    plan = constitutional.evaluate_syscall_table_sync(
        live_path=live, bundle_path=bundle,
        verify_fn=signer.verify_fn, fingerprint=FP,
    )

    assert plan["ok"] is True
    assert plan["needs_apply"] is True
    assert plan["resign_only"] is True
    assert plan["added"] == []


def test_resign_only_apply_resigns_without_rewriting_content(tables):
    live, bundle = tables
    rows = [_row(1, "git.push"), _row(2, "pr.open")]
    _write_table(live, rows)
    _write_table(bundle, rows)
    pgp.detached_sig_path(live).write_bytes(b"STALE")
    before = live.read_bytes()
    inode_before = live.stat().st_ino
    signer = _FakeSigner(live)
    ledger = _FakeLedger()

    plan = constitutional.evaluate_syscall_table_sync(
        live_path=live, bundle_path=bundle,
        verify_fn=signer.verify_fn, fingerprint=FP,
    )
    out = constitutional.apply_evaluated_syscall_sync(
        plan, live_path=live, ledger=ledger,
        sign_fn=signer.sign_fn, fingerprint=FP,
    )

    assert out["ok"] is True and out["resigned"] is True, out
    assert live.read_bytes() == before
    assert live.stat().st_ino == inode_before  # content never replaced
    assert signer.verify_fn(live) == (True, "signature verified")
    assert _files(live.parent) == ["syscall-table.json", "syscall-table.json.sig"]
    assert ledger.rows[0]["content"]["resigned"] is True


def test_resign_failure_leaves_the_stale_sig_alone(tables):
    live, bundle = tables
    rows = [_row(1, "git.push")]
    _write_table(live, rows)
    _write_table(bundle, rows)
    pgp.detached_sig_path(live).write_bytes(b"STALE")
    signer = _FakeSigner(live, fail_signing=True)

    plan = constitutional.evaluate_syscall_table_sync(
        live_path=live, bundle_path=bundle,
        verify_fn=signer.verify_fn, fingerprint=FP,
    )
    out = constitutional.apply_evaluated_syscall_sync(
        plan, live_path=live, sign_fn=signer.sign_fn, fingerprint=FP,
    )

    assert out["ok"] is False
    assert pgp.detached_sig_path(live).read_bytes() == b"STALE"
    assert _files(live.parent) == ["syscall-table.json", "syscall-table.json.sig"]


def test_verifying_sig_on_current_content_is_still_a_noop(tables):
    live, bundle = tables
    rows = [_row(1, "git.push")]
    _write_table(live, rows)
    _write_table(bundle, rows)
    _sign_in_place(live)
    signer = _FakeSigner(live)

    plan = constitutional.evaluate_syscall_table_sync(
        live_path=live, bundle_path=bundle,
        verify_fn=signer.verify_fn, fingerprint=FP,
    )

    assert plan["needs_apply"] is False
    assert signer.calls == []
