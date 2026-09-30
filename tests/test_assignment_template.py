"""The assignment template carries the merge-commit audit rule (gap 0ba4681a64f0)."""

from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent.parent / "docs" / "templates" / "ASSIGNMENT.template.md"


def test_template_tells_auditors_to_diff_the_first_parent_of_a_merge():
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "git diff <sha>^1 <sha> -- <path>" in text
    assert "Never `git show <sha> -- <path>`" in text
