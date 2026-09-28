"""unit_status (gap 158600e03598) — the desk can see whether a systemd
--user unit is actually running, not just enabled. `read_unit_status`
never runs a real subprocess here; a fake `runner` stands in for
`subprocess.run`, and `test_unit_status_tool_gate_and_visibility`
exercises the MCP tool through the gate the way a caller actually reaches
it — same shape as `test_bot_status.py`.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest

from willow_mcp import gate
from willow_mcp import server
from willow_mcp import unit_status as us
from willow_mcp.db import Store
from willow_mcp.receipts import ReceiptLog


def _fn(tool):
    return getattr(tool, "fn", tool)


def _cp(argv, stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(argv, rc, stdout, stderr)


def _show_text(*, active="active", sub="running", pid="1234", restarts="0",
                enter="Mon 2026-09-15 10:00:00 UTC", file_state="enabled",
                exit_status="0"):
    return (
        f"ActiveState={active}\n"
        f"SubState={sub}\n"
        f"ActiveEnterTimestamp={enter}\n"
        f"ActiveEnterTimestampMonotonic=123456\n"
        f"MainPID={pid}\n"
        f"ExecMainStartTimestamp={enter}\n"
        f"NRestarts={restarts}\n"
        f"UnitFileState={file_state}\n"
        f"ExecMainStatus={exit_status}\n"
    )


class _Fake:
    """Answers `systemctl --user list-units`, `list-unit-files`, `show`, and
    `journalctl --user` calls. `raise_map` keys: "list_units", "list_files",
    a unit name (for `show`), or `f"journal:{unit}"` (for `journalctl`) — the
    mapped exception is raised instead of returning a completed process."""

    def __init__(self, *, list_units="", list_units_rc=0, list_units_err="",
                 list_files="", list_files_rc=0, list_files_err="",
                 show=None, journal=None, raise_map=None):
        self.list_units = list_units
        self.list_units_rc = list_units_rc
        self.list_units_err = list_units_err
        self.list_files = list_files
        self.list_files_rc = list_files_rc
        self.list_files_err = list_files_err
        self.show = show or {}
        self.journal = journal or {}
        self.raise_map = raise_map or {}
        self.calls: list[list[str]] = []
        self.calls_kw: list[dict] = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        self.calls_kw.append(kw)
        if argv[0] == "systemctl":
            if argv[1:3] == ["--user", "list-units"]:
                if "list_units" in self.raise_map:
                    raise self.raise_map["list_units"]
                return _cp(argv, self.list_units, self.list_units_err, self.list_units_rc)
            if argv[1:3] == ["--user", "list-unit-files"]:
                if "list_files" in self.raise_map:
                    raise self.raise_map["list_files"]
                return _cp(argv, self.list_files, self.list_files_err, self.list_files_rc)
            if argv[1:3] == ["--user", "show"]:
                unit = argv[-1]
                if unit in self.raise_map:
                    raise self.raise_map[unit]
                stdout, rc, err = self.show.get(unit, (_show_text(), 0, ""))
                return _cp(argv, stdout, err, rc)
            raise AssertionError(f"unexpected systemctl call {argv}")
        if argv[0] == "journalctl":
            unit = argv[argv.index("-u") + 1]
            key = f"journal:{unit}"
            if key in self.raise_map:
                raise self.raise_map[key]
            stdout, rc, err = self.journal.get(unit, ("", 0, ""))
            return _cp(argv, stdout, err, rc)
        raise AssertionError(f"unexpected call {argv}")


# ── enumeration: union of loaded units and enabled unit files ────────────────

def test_populated_unions_loaded_and_enabled_not_loaded():
    fake = _Fake(
        list_units=(
            "willow-mcp.service loaded active running Willow\n"
            "other.service loaded active running Other\n"
        ),
        list_files=(
            "willow-mcp.service enabled enabled\n"
            "ratatosk-relay.service enabled enabled\n"
            "other.service enabled enabled\n"
        ),
        journal={
            "willow-mcp.service": ("2026-09-27T10:00:00 hello\n", 0, ""),
            "ratatosk-relay.service": ("", 0, ""),
        },
    )
    out = us.read_unit_status(runner=fake)
    assert out["state"] == "populated"
    names = {u["unit"] for u in out["units"]}
    assert names == {"willow-mcp.service", "ratatosk-relay.service"}
    assert "other.service" not in names
    # ratatosk-relay was enabled but never loaded -- still shows up.
    relay = next(u for u in out["units"] if u["unit"] == "ratatosk-relay.service")
    assert relay["active_state"] == "active"


def test_empty_when_no_matching_units():
    fake = _Fake(
        list_units="other.service loaded active running Other\n",
        list_files="other.service enabled enabled\n",
    )
    out = us.read_unit_status(runner=fake)
    assert out["state"] == "empty"
    assert out["units"] == []


# ── unreachable, each cause distinct (top-level, via the listing call) ──────

def test_systemctl_missing_is_unreachable():
    fake = _Fake(raise_map={"list_units": FileNotFoundError("systemctl")})
    out = us.read_unit_status(runner=fake)
    assert out["state"] == "unreachable" and out["cause"] == "systemctl_missing"


def test_list_units_timeout_is_unreachable():
    fake = _Fake(raise_map={"list_units": subprocess.TimeoutExpired(["systemctl"], 10)})
    out = us.read_unit_status(runner=fake)
    assert out["state"] == "unreachable" and out["cause"] == "timeout"


def test_no_user_bus_is_unreachable():
    fake = _Fake(list_units_rc=1,
                 list_units_err="Failed to connect to bus: No such file or directory")
    out = us.read_unit_status(runner=fake)
    assert out["state"] == "unreachable" and out["cause"] == "no_user_bus"


def test_no_user_bus_is_never_collapsed_into_empty():
    fake = _Fake(list_units_rc=1, list_units_err="Failed to connect to bus")
    out = us.read_unit_status(runner=fake)
    assert out["state"] != "empty"


# ── EINVAL: not a general systemd reader ─────────────────────────────────────

def test_off_prefix_unit_is_refused_einval():
    fake = _Fake()
    out = us.read_unit_status(unit="sshd.service", runner=fake)
    assert out["error"] == "EINVAL"
    assert fake.calls == []  # refusal precedes any subprocess call


# ── F1 (Loki 6ACB1F10): a strict full-match regex, one trick per test ───────

@pytest.mark.parametrize("unit", [
    "willow-../x",                          # ".." path-climb trick
    "willow-x..service",                    # ".." embedded right before the suffix
    "willow-*.service",                     # glob star
    "ratatosk-[a-z]*",                      # glob bracket expression, no valid suffix either
    "willow-[..]evil.service",              # glob bracket wrapping a ".."
    "willow-a b.service",                   # embedded space
    "willow-x.service\nsshd.service",       # embedded newline smuggling a second unit
    "willow-x.service --all",               # trailing flag-shaped argv
    "willow-",                              # bare prefix, nothing after it
    "ratatosk-",                            # bare prefix, other allowed stem
    "willow- x.service",                    # embedded leading space after the prefix
    "WILLOW-x.service",                     # wrong case
    "-willow-x.service",                    # leading dash before the prefix
    "willow-x.socket",                      # not a service/timer suffix at all
])
def test_unit_name_trick_is_refused_einval(unit):
    fake = _Fake()
    out = us.read_unit_status(unit=unit, runner=fake)
    assert out["error"] == "EINVAL", unit
    assert fake.calls == [], unit


@pytest.mark.parametrize("unit", [
    "willow-mcp.service",
    "willow-mcp-serve.timer",
    "willow-bot-steward.service",
    "ratatosk-relay.service",
    "willow-mcp-serve@1.service",
    "willow-a.b_c-d.service",
])
def test_valid_unit_shapes_are_allowed(unit):
    fake = _Fake(show={unit: (_show_text(), 0, "")}, journal={unit: ("", 0, "")})
    out = us.read_unit_status(unit=unit, runner=fake)
    assert out["state"] == "populated", unit


def test_named_unit_unknown_to_systemd_is_empty_not_unreachable():
    fake = _Fake(show={"willow-ghost.service": ("", 1, "Unit willow-ghost.service could not be found.")})
    out = us.read_unit_status(unit="willow-ghost.service", runner=fake)
    assert out["state"] == "empty"


def test_named_unit_unknown_via_real_systemd_rc0_loadstate_not_found_is_empty():
    """F4 (Loki 6ACB1F10): real systemd 259 exits 0 on an unknown unit with
    ActiveState=inactive -- only LoadState=not-found actually says "unknown".
    The old fake's rc=1 shape (above) is the OTHER path systemd can take;
    this is the one that was silently mis-read as populated/inactive."""
    text = (
        "LoadState=not-found\n"
        "ActiveState=inactive\n"
        "SubState=dead\n"
    )
    fake = _Fake(show={"willow-ghost.service": (text, 0, "")})
    out = us.read_unit_status(unit="willow-ghost.service", runner=fake)
    assert out["state"] == "empty"


def test_named_unit_populated():
    fake = _Fake(journal={"willow-mcp.service": ("line one\n", 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    assert out["state"] == "populated"
    assert out["units"][0]["unit"] == "willow-mcp.service"


# ── restarting: "active is not bound", in code ───────────────────────────────

def test_restarting_true_when_recent_restarts():
    fake = _Fake(show={
        "willow-mcp.service": (
            _show_text(restarts="3", enter="Sun 2026-09-27 12:00:00 UTC"), 0, ""),
    })
    now = datetime(2026, 9, 27, 12, 0, 30, tzinfo=timezone.utc)  # 30s later
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake, now=now)
    assert out["units"][0]["restarting"] is True


def test_restarting_false_when_restarts_are_old():
    fake = _Fake(show={
        "willow-mcp.service": (
            _show_text(restarts="3", enter="Sun 2026-09-27 12:00:00 UTC"), 0, ""),
    })
    now = datetime(2026, 9, 27, 12, 5, 0, tzinfo=timezone.utc)  # 5 minutes later
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake, now=now)
    assert out["units"][0]["restarting"] is False


def test_restarting_true_on_auto_restart_substate_regardless_of_timestamp():
    fake = _Fake(show={
        "willow-mcp.service": (
            _show_text(sub="auto-restart", restarts="0",
                       enter="Sun 2020-01-01 00:00:00 UTC"), 0, ""),
    })
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    assert out["units"][0]["restarting"] is True


def test_restarting_false_with_zero_restarts():
    fake = _Fake(show={"willow-mcp.service": (_show_text(restarts="0"), 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    assert out["units"][0]["restarting"] is False


# ── journal tail: own three-state ────────────────────────────────────────────

def test_journal_tail_populated():
    fake = _Fake(journal={"willow-mcp.service": ("2026-09-27T10:00:00 hello\n", 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert journal["state"] == "populated"
    assert journal["lines"] == ["2026-09-27T10:00:00 hello"]


def test_journal_tail_empty():
    fake = _Fake(journal={"willow-mcp.service": ("", 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    assert out["units"][0]["journal"] == {"state": "empty", "lines": []}


def test_journal_tail_unreachable_timeout():
    fake = _Fake(raise_map={"journal:willow-mcp.service": subprocess.TimeoutExpired(["journalctl"], 10)})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert journal["state"] == "unreachable" and journal["cause"] == "timeout"


def test_journal_tail_unreachable_no_user_bus():
    fake = _Fake(journal={"willow-mcp.service": ("", 1, "Failed to connect to bus")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert journal["state"] == "unreachable" and journal["cause"] == "no_user_bus"


def test_journal_no_entries_sentinel_on_real_systemd_is_empty_not_populated():
    """F4 (Loki 6ACB1F10): journalctl prints this literal line on stdout with
    rc=0 for an empty (or unknown-unit) journal -- the OLD code took rc==0 +
    non-empty stdout as `populated` and returned the sentinel AS a log line."""
    fake = _Fake(journal={"willow-mcp.service": ("-- No entries --\n", 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert journal == {"state": "empty", "lines": []}


def test_journal_no_journal_files_on_rc0_is_unreachable_not_populated():
    """F4: journalctl also exits 0 when the journal itself is unreadable (no
    persistent journal, permission denied), with the failure legible only on
    stderr -- rc alone cannot tell this apart from a real empty journal."""
    fake = _Fake(journal={
        "willow-mcp.service": ("", 0, "No journal files were found.\n"),
    })
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert journal["state"] == "unreachable"
    assert journal["cause"] == "journal_unreadable"


# ── redaction ─────────────────────────────────────────────────────────────────

def test_journal_pem_block_spanning_lines_is_redacted_whole():
    """F3 (Loki 6ACB1F10): the OLD code redacted line-by-line, which defeated
    the private_key rule's own multi-line match -- each line, seen alone,
    never matched the whole-block pattern and the key body survived. The
    joined-then-split fix must catch it."""
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    journal_text = f"2026-09-27T10:00:00 leaked key:\n{pem}2026-09-27T10:00:01 after\n"
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert "b3BlbnNz" not in "\n".join(journal["lines"]), "key body line survived the joined redaction"
    assert "PRIVATE KEY" not in "\n".join(journal["lines"])
    assert "private_key" in journal["redacted_kinds"]


@pytest.mark.parametrize("kind,secret_line", [
    ("groq_api_key", "GROQ_API_KEY=gsk_" + "a" * 40),
    ("hf_token", "HF_API_KEY=hf_" + "b" * 30),
    ("cerebras_api_key", "CEREBRAS_API_KEY=csk-" + "c" * 30),
    ("xai_api_key", "XAI_API_KEY=xai-" + "d" * 30),
    ("authorization_header", "Authorization: Bearer sekret.token.value"),
    ("pg_dsn_password", "DSN=postgresql://willow:hunter2@127.0.0.1/willow"),
    ("password_kv", "password=hunter2plusmore"),
    ("labelled_secret_kv", "NESTOR_SEAL_KEY=" + "ab" * 32),
])
def test_journal_new_secret_formats_are_redacted(kind, secret_line):
    """F3: the missing provider prefixes and labelled KEY=/TOKEN=/SECRET=/
    Authorization-header/DSN-password formats, each reproduced through
    unit_status's own journal_tail (not secret_scan directly)."""
    journal_text = f"2026-09-27T10:00:00 {secret_line} tail\n"
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert kind in journal.get("redacted_kinds", []), journal
    for secret_fragment in ("hunter2", "sekret.token.value", "a" * 40, "b" * 30, "c" * 30, "d" * 30):
        if secret_fragment in secret_line:
            assert secret_fragment not in journal["lines"][0]


def test_journalctl_call_never_carries_dash_q():
    """B1 (Loki 0DFFEFA6): on real systemd 259, `journalctl -q` silences
    BOTH signals `journal_tail` reads from the text below — an unreadable
    journal comes back completely empty (rc=0, no stdout, no stderr) and is
    indistinguishable from a genuinely empty one. Pin the argv so `-q` can
    never quietly come back."""
    fake = _Fake(journal={"willow-mcp.service": ("", 0, "")})
    us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journalctl_calls = [c for c in fake.calls if c[0] == "journalctl"]
    assert journalctl_calls
    assert "-q" not in journalctl_calls[0]


def test_journal_no_journal_files_real_systemd_shape_is_unreachable():
    """B1: the REAL (no `-q`) rc=0 shape for an unreadable journal carries
    BOTH the `-- No entries --` sentinel on stdout AND the warning on
    stderr — not the stderr-only fake B1 replaced."""
    fake = _Fake(journal={
        "willow-mcp.service": ("-- No entries --\n", 0, "No journal files were found.\n"),
    })
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert journal["state"] == "unreachable"
    assert journal["cause"] == "journal_unreadable"


# ── B3 (Loki 0DFFEFA6): the journal-scoped redactor must NOT over-redact ────

@pytest.mark.parametrize("secret_line", [
    "Column(Integer, primary_key=True)",
    "order_by(sort_key=lambda r: r.id)",
    "password=None",
    "OPENAI_API_KEY=env:OPENAI_API_KEY",
    'idempotency_key="req-42"',
    "public_key=ssh-ed25519-AAAA",
])
def test_journal_new_patterns_do_not_over_redact(secret_line):
    journal_text = f"2026-09-27T10:00:00 {secret_line} tail\n"
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert journal["state"] == "populated"
    assert journal["lines"] == [f"2026-09-27T10:00:00 {secret_line} tail"], journal
    assert "redacted_kinds" not in journal, journal


def test_journal_pem_block_truncated_by_the_n_window_redacts_to_the_end():
    """F3 residual (a): a PEM block the `-n` window cut off before a closing
    `-----END ... KEY-----` line ever appeared must still redact everything
    it left visible, not leak the rest of the (truncated) body."""
    pem_no_end = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
        "moretruncatedbase64bodyheretail\n"
    )
    journal_text = f"2026-09-27T10:00:00 leaked key:\n{pem_no_end}"
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    joined = "\n".join(journal["lines"])
    assert "b3BlbnNz" not in joined and "moretruncatedbase64" not in joined
    assert "private_key" in journal["redacted_kinds"]


@pytest.mark.parametrize("secret_line", [
    "NESTOR_SEAL_KEY: " + "ab" * 32,
    'DB_PASSWORD=' + "s3cr3t!" * 3,
    "PGPASSWORD=" + "s3cr3t!" * 3,
])
def test_journal_colon_and_password_suffix_forms_are_redacted(secret_line):
    journal_text = f"2026-09-27T10:00:00 {secret_line} tail\n"
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert "labelled_secret_kv" in journal.get("redacted_kinds", []), journal
    value = secret_line.split("=", 1)[-1].split(": ", 1)[-1]
    assert value not in journal["lines"][0]


def test_journal_json_form_labelled_key_is_redacted():
    journal_text = '2026-09-27T10:00:00 {"NESTOR_SEAL_KEY": "' + "ab" * 32 + '"} tail\n'
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert "labelled_secret_kv" in journal.get("redacted_kinds", []), journal
    assert "ab" * 32 not in journal["lines"][0]


def test_journal_dsn_password_containing_at_sign_redacts_to_the_last_at():
    """F3 residual (c): a password containing `@` no longer leaks its tail —
    the match extends to the LAST `@` on the line, which is the real
    scheme/host boundary."""
    journal_text = "2026-09-27T10:00:00 DSN=postgresql://willow:p@ss@127.0.0.1/willow tail\n"
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert "pg_dsn_password" in journal.get("redacted_kinds", []), journal
    assert "p@ss" not in journal["lines"][0]
    # The whole password, not just its prefix up to the FIRST `@`, must be
    # gone — a first-`@`-only match would still leak "ss@127.0.0.1".
    assert "ss@127.0.0.1" not in journal["lines"][0], journal["lines"][0]
    assert journal["lines"][0].endswith("@127.0.0.1/willow tail")


def test_journal_authorization_header_does_not_cross_a_newline():
    """F3 residual (d): `Authorization: Bearer` with no TOKEN before the end
    of its own line must never cross the `\\n` and eat the FOLLOWING journal
    line's timestamp as if it were the credential."""
    journal_text = (
        "2026-09-27T10:00:00 Authorization: Bearer\n"
        "2026-09-27T10:00:01 next line unrelated\n"
    )
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert "authorization_header" not in journal.get("redacted_kinds", [])
    assert journal["lines"] == [
        "2026-09-27T10:00:00 Authorization: Bearer",
        "2026-09-27T10:00:01 next line unrelated",
    ]


@pytest.mark.parametrize("secret_line", [
    "API_KEY=null-9f8e7d6c5b4a",
    "DB_PASSWORD=vaultpass123secret",
])
def test_journal_null_and_vault_prefixed_secrets_are_redacted(secret_line):
    """Loki 58BC828C: the null/None/vault SKIP must match the EXACT token
    only, not a prefix of it — `null-9f8e7d6c5b4a` and `vaultpass123secret`
    are real secret values that merely start with a skip word, and must
    still be redacted, not waved through as a "value names an absent
    credential / a source" case."""
    journal_text = f"2026-09-27T10:00:00 {secret_line} tail\n"
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert "labelled_secret_kv" in journal.get("redacted_kinds", []), journal
    value = secret_line.split("=", 1)[-1]
    assert value not in journal["lines"][0], journal["lines"][0]


def test_journal_quoted_value_with_spaces_redacts_to_the_closing_quote():
    """Loki 58BC828C: a bare `\\S+` capture stopped at the first space and
    left the TAIL of a quoted multi-word value leaking past the placeholder
    (`SECRET_KEY="two words"` -> `...] words"`). The value token must accept
    a quoted string and consume it whole, through its closing quote."""
    journal_text = '2026-09-27T10:00:00 SECRET_KEY="two words" tail\n'
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert "labelled_secret_kv" in journal.get("redacted_kinds", []), journal
    assert "two words" not in journal["lines"][0]
    assert "words" not in journal["lines"][0]
    assert journal["lines"][0].endswith(" tail")


def test_journal_unterminated_quote_does_not_swallow_the_next_line():
    """B1 (Loki 2359F421): the quoted-value class `[^"\\\\]` matched `\\n`, so
    an unterminated quote on one line consumed everything up to the next
    quote in the tail — including the FOLLOWING journal line and its
    timestamp. The class must exclude `\\n` so a stray unclosed quote never
    crosses a line."""
    journal_text = (
        '2026-09-27T10:00:00 h u[1]: SECRET_KEY="abc\n'
        '2026-09-27T10:00:01 h u[1]: next "quoted" line\n'
    )
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert len(journal["lines"]) == 2
    assert journal["lines"][1] == '2026-09-27T10:00:01 h u[1]: next "quoted" line'


def test_journal_key_at_end_of_line_does_not_swallow_the_next_line():
    """Sibling of B1: `\\s*[:=]\\s*` around the key/value separator also
    crossed `\\n` — a label ending a line with no value (`DB_PASSWORD:`) ate
    the FOLLOWING line's timestamp as if it were the value. `[ \\t]*` never
    crosses a line."""
    journal_text = (
        "2026-09-27T10:00:00 h u[1]: DB_PASSWORD:\n"
        "2026-09-27T10:00:01 h u[1]: next line\n"
    )
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert len(journal["lines"]) == 2
    assert journal["lines"][1] == "2026-09-27T10:00:01 h u[1]: next line"


def test_journal_authorization_header_any_scheme_is_redacted():
    """Loki 58BC828C: only `Bearer`/`Basic`/`Token` were recognized schemes —
    `ApiKey` (and any other scheme a service might send) sailed through
    unredacted. The whole value after the scheme, to end of line, must be
    replaced regardless of the scheme name."""
    journal_text = "2026-09-27T10:00:00 Authorization: ApiKey abcdef123 secret\n"
    fake = _Fake(journal={"willow-mcp.service": (journal_text, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert "authorization_header" in journal.get("redacted_kinds", []), journal
    assert "abcdef123" not in journal["lines"][0]
    assert journal["lines"][0] == (
        "2026-09-27T10:00:00 Authorization: ApiKey [REDACTED:authorization_header]"
    )


def test_journal_lines_are_redacted():
    # Built by concatenation, not a static literal: some environments run a
    # DLP-style scrubber over tracked files that rewrites AWS-key-shaped
    # strings in place, which silently neutered a hardcoded literal here
    # before this test ever ran. Assembling it at import/call time keeps the
    # on-disk source free of the matchable pattern while still producing one
    # at runtime for secret_scan.redact_egress to catch.
    fake_key = "AKIA" + "".join(["ABCDEFGHIJKLMNOP"[i] for i in range(16)])
    secret_line = f"2026-09-27T10:00:00 aws creds {fake_key} leaked\n"
    fake = _Fake(journal={"willow-mcp.service": (secret_line, 0, "")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal = out["units"][0]["journal"]
    assert fake_key not in journal["lines"][0], "raw key leaked unredacted"
    assert "[REDACTED:aws_access_key_id]" in journal["lines"][0]
    assert journal["redacted_kinds"] == ["aws_access_key_id"]


# ── journal_lines cap ─────────────────────────────────────────────────────────

def test_journal_lines_is_capped():
    fake = _Fake(journal={"willow-mcp.service": ("", 0, "")})
    us.read_unit_status(unit="willow-mcp.service", journal_lines=99999, runner=fake)
    journalctl_calls = [c for c in fake.calls if c[0] == "journalctl"]
    assert len(journalctl_calls) == 1
    n_index = journalctl_calls[0].index("-n") + 1
    assert journalctl_calls[0][n_index] == "200"


def test_journal_lines_default_and_passthrough():
    fake = _Fake(journal={"willow-mcp.service": ("", 0, "")})
    us.read_unit_status(unit="willow-mcp.service", journal_lines=5, runner=fake)
    journalctl_calls = [c for c in fake.calls if c[0] == "journalctl"]
    n_index = journalctl_calls[0].index("-n") + 1
    assert journalctl_calls[0][n_index] == "5"


# ── L9 (Loki 6ACB1F10 F5): a NAMED unit's own unreachable causes must never
# collapse into "empty" -- only unit_unknown (the bus answered, this one
# name is not known) is "empty"; no_user_bus/timeout stay unreachable ──────

def test_named_unit_no_user_bus_stays_unreachable_not_empty():
    fake = _Fake(show={"willow-mcp.service": ("", 1, "Failed to connect to bus: no")})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    assert out["state"] == "unreachable" and out["cause"] == "no_user_bus"


def test_named_unit_timeout_stays_unreachable_not_empty():
    fake = _Fake(raise_map={"willow-mcp.service": subprocess.TimeoutExpired(["systemctl"], 10)})
    out = us.read_unit_status(unit="willow-mcp.service", runner=fake)
    assert out["state"] == "unreachable" and out["cause"] == "timeout"


# ── L10: a list-unit-files failure must refuse unreachable, never be
# silently treated as "no enabled files" ─────────────────────────────────────

def test_list_unit_files_failure_is_unreachable_not_swallowed():
    fake = _Fake(list_units="willow-mcp.service loaded active running Willow\n",
                 raise_map={"list_files": subprocess.TimeoutExpired(["systemctl"], 10)})
    out = us.read_unit_status(runner=fake)
    assert out["state"] == "unreachable" and out["cause"] == "timeout"


def test_list_unit_files_no_user_bus_is_unreachable():
    fake = _Fake(list_units="willow-mcp.service loaded active running Willow\n",
                 list_files_rc=1, list_files_err="Failed to connect to bus")
    out = us.read_unit_status(runner=fake)
    assert out["state"] == "unreachable" and out["cause"] == "no_user_bus"


# ── L11: the journal_lines floor -- 0 (or negative) must never reach `-n 0` ──

def test_journal_lines_floor_at_zero():
    fake = _Fake(journal={"willow-mcp.service": ("", 0, "")})
    us.read_unit_status(unit="willow-mcp.service", journal_lines=0, runner=fake)
    journalctl_calls = [c for c in fake.calls if c[0] == "journalctl"]
    n_index = journalctl_calls[0].index("-n") + 1
    assert journalctl_calls[0][n_index] == "1"


def test_journal_lines_floor_at_negative():
    fake = _Fake(journal={"willow-mcp.service": ("", 0, "")})
    us.read_unit_status(unit="willow-mcp.service", journal_lines=-5, runner=fake)
    journalctl_calls = [c for c in fake.calls if c[0] == "journalctl"]
    n_index = journalctl_calls[0].index("-n") + 1
    assert journalctl_calls[0][n_index] == "1"


# ── L12/L14/L17: every subprocess call on this path carries a real timeout,
# never an unbounded call that could hang the broker's threadpool worker ────

def test_show_unit_call_carries_a_timeout():
    fake = _Fake(show={"willow-mcp.service": (_show_text(), 0, "")})
    us.read_unit_status(unit="willow-mcp.service", runner=fake)
    show_calls = [(a, kw) for a, kw in zip(fake.calls, fake.calls_kw)
                  if a[0] == "systemctl" and a[1:3] == ["--user", "show"]]
    assert show_calls, "no show call recorded"
    for _, kw in show_calls:
        assert kw.get("timeout"), "show_unit call has no timeout"


def test_journalctl_call_carries_a_timeout():
    fake = _Fake(journal={"willow-mcp.service": ("", 0, "")})
    us.read_unit_status(unit="willow-mcp.service", runner=fake)
    journal_calls = [(a, kw) for a, kw in zip(fake.calls, fake.calls_kw) if a[0] == "journalctl"]
    assert journal_calls, "no journalctl call recorded"
    for _, kw in journal_calls:
        assert kw.get("timeout"), "journal_tail call has no timeout"


def test_list_units_call_carries_a_timeout():
    fake = _Fake()
    us.read_unit_status(runner=fake)
    list_calls = [(a, kw) for a, kw in zip(fake.calls, fake.calls_kw)
                  if a[0] == "systemctl" and a[1:3] == ["--user", "list-units"]]
    assert list_calls, "no list-units call recorded"
    for _, kw in list_calls:
        assert kw.get("timeout"), "list-units call has no timeout"


# ── the tool is gated and grouped like bot_status / pr_checks_read ──────────

@pytest.fixture
def mk_app(tmp_path, monkeypatch):
    apps = tmp_path / "apps"
    monkeypatch.setenv("WILLOW_HOME", str(tmp_path))
    monkeypatch.setenv("WILLOW_MCP_APPS_ROOT", str(apps))
    monkeypatch.setattr(server, "_store", Store(str(tmp_path / "store")))
    monkeypatch.setattr(server, "_receipt_log", ReceiptLog(str(tmp_path / "r.db")))
    monkeypatch.setattr(server, "_buckets", {})

    def _mk(app_id, perms):
        d = apps / app_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text(json.dumps({"permissions": perms}))
        return app_id

    return _mk


def test_unit_status_tool_gate_and_visibility(mk_app, monkeypatch):
    denied = mk_app("hanuman", ["store_read"])
    allowed = mk_app("frigg", ["fleet_read"])

    monkeypatch.setattr(us, "read_unit_status",
                        lambda unit="", journal_lines=20: {"state": "empty", "units": []})

    out = _fn(server.unit_status)(app_id=denied)
    assert "gate denied" in out.get("error", "")

    out = _fn(server.unit_status)(app_id=allowed)
    assert out["state"] == "empty"

    assert gate.permitted(allowed, "unit_status")
    assert not gate.permitted(denied, "unit_status")


def test_unit_status_is_in_fleet_read_and_full_access():
    assert "unit_status" in gate.PERMISSION_GROUPS["fleet_read"]
    assert "unit_status" in gate.PERMISSION_GROUPS["full_access"]


def test_unit_status_is_classed_read_by_the_tier_ceiling():
    from willow_mcp import tier_policy

    assert tier_policy.TOOL_CLASS["unit_status"] == tier_policy.READ


def test_unit_status_is_not_in_desk_core():
    from willow_mcp import advertise

    assert "unit_status" not in advertise.DESK_CORE
