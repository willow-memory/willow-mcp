"""The assignment template carries the merge-commit audit rule (gap 0ba4681a64f0)."""

from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent.parent / "docs" / "templates" / "ASSIGNMENT.template.md"

#: What the template must tell an auditor about a merge commit: diff its first
#: parent, and never `git show` it (which prints a combined diff, empty for a
#: clean merge).
FIRST_PARENT_INSTRUCTIONS = (
    "git diff <sha>^1 <sha> -- <path>",
    "Never `git show <sha> -- <path>`",
)


def missing_first_parent_instructions(text, required=FIRST_PARENT_INSTRUCTIONS):
    """The first-parent instructions `text` fails to carry, in `required` order."""
    return [phrase for phrase in required if phrase not in text]


def test_template_tells_auditors_to_diff_the_first_parent_of_a_merge():
    text = TEMPLATE.read_text(encoding="utf-8")
    assert missing_first_parent_instructions(text) == []


def test_the_first_parent_check_fires_on_a_template_missing_it():
    """Planted: a template that never mentions the first parent, or that
    carries only half of the rule, must be reported phrase by phrase; a
    template with both must not."""
    assert missing_first_parent_instructions("# Assignment\n\nAudit the diff.\n") == list(
        FIRST_PARENT_INSTRUCTIONS
    )
    assert missing_first_parent_instructions(
        "Run `git diff <sha>^1 <sha> -- <path>` on a merge.\n"
    ) == ["Never `git show <sha> -- <path>`"]
    assert missing_first_parent_instructions("\n".join(FIRST_PARENT_INSTRUCTIONS)) == []
