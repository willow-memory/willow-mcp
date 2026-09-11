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


def test_longer_uppercase_run_is_held_as_the_whole_run():
    """A trailing negative-lookahead was tried here to reject a longer
    same-charset run as 'not a real 20-char key', but that reopened the
    evasion: a real key glued to more uppercase/digits would fail the
    lookahead and evade entirely. The pattern is greedy with no trailing
    anchor, so a longer run is matched and held in full — over-matching a
    same-charset run is harmless since it is never an ordinary-prose shape."""
    junk = "AKIA" + "Q" * 30
    found = secrets.find_secrets(junk)
    assert ("aws_access_key", junk) in found


def test_aws_key_with_trailing_uppercase_glue_is_detected():
    """Auditor case: a real 20-char AWS key immediately followed by more
    uppercase letters must still be HELD — the whole glued run is matched
    and flagged, not silently dropped."""
    text = "AKIAIOSFODNN7EXAMPLEQRST"
    found = secrets.find_secrets(text)
    assert ("aws_access_key", text) in found


def test_aws_key_with_trailing_digit_glue_is_detected():
    """Auditor case: a real 20-char AWS key immediately followed by a
    trailing digit must still be HELD."""
    text = "AKIAIOSFODNN7EXAMPLE0"
    found = secrets.find_secrets(text)
    assert ("aws_access_key", text) in found


def test_aws_key_in_filename_with_trailing_uppercase_glue_is_detected():
    """Auditor case: the filename shape AKIA...BACKUP.txt must still be
    HELD — the uppercase glue after the key must not cause an evasion."""
    filename = "AKIAIOSFODNN7EXAMPLEBACKUP.txt"
    found = secrets.find_secrets(filename)
    assert any(kind == "aws_access_key" for kind, _ in found)
    assert any(val.startswith("AKIAIOSFODNN7EXAMPLE") for _, val in found)


def test_aws_key_glued_to_base64ish_uppercase_run_is_detected():
    """A key embedded in a base64-ish blob with an uppercase char right
    after it must still be HELD as one glued run, not evaded."""
    blob = "AKIAIOSFODNN7EXAMPLE" + "MMNNPPQQ=="
    text = f"payload: {blob} end"
    found = secrets.find_secrets(text)
    assert any(kind == "aws_access_key" and val.startswith("AKIAIOSFODNN7EXAMPLE") for kind, val in found)


def test_aws_key_with_trailing_lowercase_still_stops_at_twenty():
    """A key followed by a lowercase letter (ordinary prose glue) must
    still stop at the 20-char key shape, not swallow the lowercase glue."""
    text = f"wrap{AWS_KEY}wrap"
    found = secrets.find_secrets(text)
    assert ("aws_access_key", AWS_KEY) in found
    assert not any(val == AWS_KEY + "w" for _, val in found)


def test_realistic_journal_prose_with_uppercase_words_is_not_a_false_positive():
    """A realistic prose passage that happens to contain runs of capital
    letters (an acronym, a shouted word) but no AKIA-prefixed shape must
    not trip the AWS pattern. AKIA is a specific literal prefix, so
    ordinary ALL-CAPS text should never match it."""
    prose = (
        "Dear journal, today the IRS sent a letter in ALL CAPS ABOUT AN "
        "OVERDUE FORM, and I had to call the DMV about my ID renewal. "
        "Nothing about any of that involves a real credential."
    )
    assert secrets.find_secrets(prose) == []


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
