"""Unit tests for willow_mcp.nest.secrets.find_secrets — the credential-shape
scanner the autointake hook relies on to hold anything carrying a live key.

Regression coverage for the word-boundary evasion (MEDIUM, re-audit of
feat/hook-nest-autointake): the old `\\b`-anchored patterns required a
transition between a word char and a non-word char immediately around the
credential shape, so a key glued directly to surrounding letters
(`wrapAKIA...wrap`) never matched at all — no boundary, no detection, no
redaction. The fix matches the credential's own fixed structure (prefix +
charset + exact length) instead of relying on a separator existing.
"""
from __future__ import annotations

from willow_mcp.nest import secrets

AWS_KEY = "AKIA" + "Q" * 16  # 20 chars total — the real AWS access key shape


def test_embedded_aws_key_glued_to_letters_is_detected():
    """The exact evasion demonstrated in the audit: a live key with no
    separator on either side must still be found, not silently skipped."""
    text = f"wrap{AWS_KEY}wrap"
    found = secrets.find_secrets(text)
    assert ("aws_access_key", AWS_KEY) in found


def test_embedded_aws_key_is_still_redacted():
    text = f"wrap{AWS_KEY}wrap"
    redacted = secrets.redact_text(text)
    assert AWS_KEY not in redacted
    assert "[REDACTED:aws_access_key]" in redacted


def test_aws_key_with_separators_still_detected():
    """Non-regression: the original, easier case (spaces around the key)
    must still work after removing the \\b anchor."""
    text = f"the key is {AWS_KEY} ok"
    found = secrets.find_secrets(text)
    assert ("aws_access_key", AWS_KEY) in found


def test_github_pat_embedded_in_letters_is_detected():
    token = "ghp_" + "b" * 36
    text = f"prefix{token}suffix"
    found = secrets.find_secrets(text)
    assert ("github_pat", token) in found


def test_google_api_key_embedded_in_letters_is_detected():
    token = "AIza" + "C" * 35
    text = f"leading{token}trailing"
    found = secrets.find_secrets(text)
    assert ("google_api_key", token) in found


def test_longer_uppercase_run_does_not_produce_a_truncated_false_key():
    """The AWS pattern now anchors its END with a negative lookahead so it
    can't slice a 16-char 'key' out of the middle of a longer run of the
    same charset — that run isn't a real key, so it should not match."""
    junk = "AKIA" + "Q" * 30  # not a real 20-char AWS key — too long
    found = secrets.find_secrets(junk)
    assert found == []


def test_ordinary_prose_is_not_a_false_positive():
    """A normal paragraph that happens to use words like 'key', 'secret',
    and 'token' — but carries no actual credential shape — must not trip
    the scanner. Precision over recall."""
    prose = (
        "The secret to a good journal entry is honesty. I left my house key "
        "on the token booth counter again and had to ask the desk clerk for "
        "a spare. Note to self: buy a keyring so this stops happening."
    )
    assert secrets.find_secrets(prose) == []


def test_prose_containing_the_bare_letters_akia_is_not_a_false_positive():
    """The bare substring 'AKIA' (no full 20-char shape after it) must not
    fire — only the complete prefix+charset+length shape should."""
    prose = "Her name badge read AKIA, short for Akiako, and nothing else."
    assert secrets.find_secrets(prose) == []
