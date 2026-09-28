"""Egress secret redaction — the unit contract for secret_scan.redact_egress.

These are the adversarial fixtures the funnel relies on: a credential of each
supported FORMAT smuggled through the data path is redacted, structure and
non-secret data survive, the reported kinds never carry the value, and
legitimate near-misses (a credential SOURCE, an ordinary id) are left alone.
"""
from willow_mcp import secret_scan


AWS_KEY = "AKIA" + "Q" * 16
PROVIDER_KEY = "sk-ant-" + "a1B2c3D4" * 4
GITHUB_TOKEN = "ghp_" + "b" * 36
SLACK_TOKEN = "xoxb-123456789012-abcdefABCDEF"
GOOGLE_KEY = "AIza" + "C" * 35
STRIPE_KEY = "sk_live_" + "d" * 24
JWT = "eyJhbGciOiJI.eyJzdWIiOiIx.QsWn3kF9aa"
PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
    "-----END OPENSSH PRIVATE KEY-----"
)


def test_aws_access_key_is_redacted():
    out, kinds = secret_scan.redact_egress({"note": f"key is {AWS_KEY} ok"})
    assert AWS_KEY not in out["note"]
    assert "[REDACTED:aws_access_key_id]" in out["note"]
    assert kinds == ["aws_access_key_id"]


def test_provider_api_key_is_redacted():
    out, kinds = secret_scan.redact_egress({"v": PROVIDER_KEY})
    assert PROVIDER_KEY not in out["v"]
    assert kinds == ["provider_api_key"]


def test_private_key_block_is_redacted_whole():
    out, kinds = secret_scan.redact_egress(PRIVATE_KEY)
    assert "PRIVATE KEY" not in out
    assert "b3BlbnNz" not in out          # the base64 body is gone too
    assert kinds == ["private_key"]


def test_github_slack_google_stripe_jwt_each_redacted():
    for secret, kind in [
        (GITHUB_TOKEN, "github_token"),
        (SLACK_TOKEN, "slack_token"),
        (GOOGLE_KEY, "google_api_key"),
        (STRIPE_KEY, "stripe_key"),
        (JWT, "jwt"),
    ]:
        out, kinds = secret_scan.redact_egress({"body": f"x {secret} y"})
        assert secret not in out["body"], kind
        assert kinds == [kind]


def test_redaction_walks_nested_structures():
    payload = {"rows": [{"blob": f"pre {AWS_KEY} post"}, {"ok": "harmless"}],
               "meta": {"deep": {"tok": PROVIDER_KEY}}}
    out, kinds = secret_scan.redact_egress(payload)
    assert AWS_KEY not in str(out)
    assert PROVIDER_KEY not in str(out)
    assert out["rows"][1]["ok"] == "harmless"        # non-secret untouched
    assert set(kinds) == {"aws_access_key_id", "provider_api_key"}


def test_reported_kinds_never_contain_the_value():
    _, kinds = secret_scan.redact_egress({"v": AWS_KEY})
    assert all(AWS_KEY not in k for k in kinds)       # audit trail is payload-free


def test_non_string_scalars_pass_through():
    out, kinds = secret_scan.redact_egress({"n": 42, "b": True, "z": None})
    assert out == {"n": 42, "b": True, "z": None}
    assert kinds == []


def test_credential_source_is_not_a_secret():
    # `credential_source()` returns strings like "env:OPENAI_API_KEY" — a name,
    # not a value. The backstop must not redact the source it points to.
    out, kinds = secret_scan.redact_egress({"source": "env:OPENAI_API_KEY",
                                            "via": "vault"})
    assert out == {"source": "env:OPENAI_API_KEY", "via": "vault"}
    assert kinds == []


def test_ordinary_ids_are_not_false_positives():
    # UUIDs, sha hashes, and record ids must survive — precision over recall.
    payload = {"id": "9f8c2b10-4e3a-4d21-bb0e-2a1c9d6e7f00",
               "sha": "a" * 40, "record_id": "agents:42"}
    out, kinds = secret_scan.redact_egress(payload)
    assert out == payload
    assert kinds == []


def test_clean_result_is_returned_unchanged():
    payload = {"id": "notes:1", "action": "created", "count": 3}
    out, kinds = secret_scan.redact_egress(payload)
    assert out == payload
    assert kinds == []


def test_shared_egress_never_applies_label_or_kv_heuristics():
    """Loki 0DFFEFA6 B3: `*_KEY=`/`*_TOKEN=`/`*_SECRET=`/`password=` label
    heuristics belong ONLY to the journal-scoped redactor
    (`secret_scan.redact_journal_tail`, exercised via
    `unit_status.journal_tail`), never this shared funnel every tool
    response passes through — they over-redact ordinary field names and even
    a credential SOURCE (`env:VAR`), which the README's own guarantee says a
    tool MAY return."""
    payload = {
        "a": "Column(Integer, primary_key=True)",
        "b": "order_by(sort_key=lambda r: r.id)",
        "c": "password=None",
        "d": "OPENAI_API_KEY=env:OPENAI_API_KEY",
        # Loki 58BC828C F1: a journal-only POSITIVE — a value the journal
        # redactor WOULD redact. Every other entry here is one the
        # now-precise journal pattern set also passes through, so a mutant
        # routing `redact_egress` through `_JOURNAL_PATTERNS` (the exact
        # B3-class regression) survived until this one was added: it is a
        # real, high-confidence journal hit, and the shared funnel must
        # still leave it alone.
        "e": "DB_PASSWORD=hunter2",
    }
    out, kinds = secret_scan.redact_egress(payload)
    assert out == payload
    assert kinds == []
    # Prove the journal-only positive actually differs from the shared set —
    # otherwise this test cannot tell the two funnels apart either.
    journal_redacted, journal_kinds = secret_scan.redact_journal_tail(payload["e"])
    assert journal_kinds == ["labelled_secret_kv"]
    assert "hunter2" not in journal_redacted
