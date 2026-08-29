"""The release chain is four files that must agree, and every disagreement is silent.

    release-please-config.json  decides the tag name and what cuts a release
    .release-please-manifest.json  is the version it bumps from
    .claude-plugin/plugin.json  carries a version release.yml refuses to
                                publish without
    .github/workflows/release.yml  fires on a tag pattern

Nothing joins them up at runtime. A mismatch does not raise, it just means a
release quietly does not happen — which is how this repo lost releases before,
and how PR #256 was produced: `include-component-in-tag` was omitted, so
release-please would have tagged `willow-mcp-v2.2.0`, `release.yml` listens for
`v*`, and the two would never have met. A comment saying "keep these in step"
is what failed; this is the version that fails the build instead.
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML needed to read the workflows")

_REPO = Path(__file__).resolve().parents[1]
_CONFIG = _REPO / "release-please-config.json"
_MANIFEST = _REPO / ".release-please-manifest.json"
_PLUGIN = _REPO / ".claude-plugin" / "plugin.json"
_RELEASE_WF = _REPO / ".github" / "workflows" / "release.yml"
_RP_WF = _REPO / ".github" / "workflows" / "release-please.yml"


def _json(path: Path) -> dict:
    return json.loads(path.read_text())


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _package_config() -> dict:
    return _json(_CONFIG)["packages"]["."]


def _tag_patterns() -> list[str]:
    # `on: push: tags:` — PyYAML parses the bare key `on` as the boolean True.
    trigger = _yaml(_RELEASE_WF)[True]
    return list(trigger["push"]["tags"])



# A credential whose events actually trigger workflows — the property, not the
# mechanism. GITHUB_TOKEN's events are suppressed; the willow-ci App token and
# the PAT it replaces both are not. Matched against raw values because an App
# token is `steps.app-token.outputs.token`, a step output rather than a secret
# reference, so it never appears in a set of secret NAMES.
NON_SUPPRESSED_CREDENTIALS = (
    "RELEASE_PLEASE_TOKEN",              # fine-grained PAT (being retired)
    "steps.app-token.outputs.token",     # willow-ci App installation token
)


def _names_a_non_suppressed_credential(value: object) -> bool:
    text = str(value)
    return any(c in text for c in NON_SUPPRESSED_CREDENTIALS)


def test_the_tag_release_please_creates_matches_what_release_yml_listens_for():
    """The one that mattered. With `include-component-in-tag` unset it defaults
    to true, and the tag becomes `<package-name>-vX.Y.Z` — which `v*` does not
    match, so the publish workflow never runs and nothing says why."""
    cfg = _package_config()
    version = _json(_MANIFEST)["."]

    if cfg.get("include-component-in-tag", True):
        tag = f"{cfg['package-name']}-v{version}"
    else:
        tag = f"v{version}"

    patterns = _tag_patterns()
    assert any(fnmatch.fnmatch(tag, p) for p in patterns), (
        f"release-please would create the tag {tag!r}, which matches none of "
        f"release.yml's trigger patterns {patterns!r}. Nothing would publish, "
        f"and nothing would report an error."
    )


def test_the_three_version_strings_agree():
    """`plugin.json` is the version nothing derives — release.yml refuses to
    publish when it disagrees with the tag, and it had already drifted to 2.0.0
    while the package was 2.0.1. release-please keeps it in step via
    `extra-files`; this asserts the starting point was right, because a wrong
    manifest bumps from the wrong number."""
    manifest = _json(_MANIFEST)["."]
    plugin = _json(_PLUGIN)["version"]
    assert manifest == plugin, (
        f".release-please-manifest.json says {manifest}, "
        f".claude-plugin/plugin.json says {plugin}"
    )


def test_plugin_json_is_wired_for_the_automatic_bump():
    """Without this `extra-files` entry, plugin.json is never bumped, and every
    release fails at release.yml's assertion instead — after the tag exists."""
    extra = _package_config().get("extra-files") or []
    targets = {e.get("path") for e in extra if isinstance(e, dict)}
    assert ".claude-plugin/plugin.json" in targets, (
        "plugin.json carries a version string nothing derives; release-please "
        "must bump it, or release.yml blocks the publish after tagging"
    )


def test_release_automation_uses_the_pat_everywhere():
    """A bot token silently produces no workflow runs: the release PR merges,
    no tag workflow fires, nothing publishes. jeles lost three releases to this
    exact substitution."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]

    # Match `secrets.X` references only. The workflow's own failure message
    # mentions GITHUB_TOKEN by name to explain the trap, and a plain substring
    # search flags that prose — which is a test failing on its own docstring.
    used = set()
    values: list[str] = []
    for step in steps:
        for value in list((step.get("env") or {}).values()) + \
                     list((step.get("with") or {}).values()):
            values.append(str(value))
            used.update(re.findall(r"secrets\.([A-Z_]+)", str(value)))

    assert any(_names_a_non_suppressed_credential(v) for v in values), used
    assert "GITHUB_TOKEN" not in used, (
        "release-please and the auto-merge arming must both use the PAT — "
        f"events generated with GITHUB_TOKEN start no workflow runs. Found: {used}"
    )


def test_the_changelog_is_rebuilt_before_auto_merge_is_armed():
    """Order is the whole point. The correction has to land on the release PR
    *before* auto-merge can take it, or the release ships with the wrong section
    and gets fixed afterwards — which is the thing being replaced.

    Three releases in a row were wrong this way. 2.1.2 and 2.1.4 listed the same
    fix twice (the merge commit and the commit it merged); 2.1.3 listed the merge
    commit and dropped `0073767` entirely, leaving a shipped fix undocumented.
    This repo merges with merge commits, and GitHub writes the PR title into the
    merge commit body, where release-please reads it.
    """
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    names = [s.get("name") or str(s.get("uses", "")) for s in steps]

    def index_of(needle: str) -> int:
        hits = [i for i, n in enumerate(names) if needle in n]
        assert hits, f"no step matching {needle!r} in {names}"
        return hits[0]

    i_action = index_of("release-please-action")
    i_fix = index_of("Rebuild the changelog")
    i_arm = index_of("Arm auto-merge")
    assert i_action < i_fix < i_arm, (
        f"must run release-please -> rebuild changelog -> arm auto-merge; got {names}"
    )

    # The tool derives entries from `git log <previous tag>..<this release>`, so
    # a shallow clone or missing tags would silently change what it computes.
    checkout = next(s for s in steps
                    if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["fetch-depth"] == 0, "needs full history for the range"
    assert checkout["with"]["fetch-tags"] is True, "needs tags to find the previous release"
    assert index_of("actions/checkout") < i_fix


def test_the_release_body_is_synced_after_the_release_is_created():
    """release-please writes the GitHub Release body from its own parse, not
    from CHANGELOG.md, so fixing the file leaves the release *page* wrong —
    v2.1.4's page kept the duplicate after the changelog was corrected.

    Order matters twice over: after the action (the release must exist) and
    before the auto-merge arming, so a failure here is visible rather than
    hidden behind a merge."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    names = [s.get("name") or str(s.get("uses", "")) for s in steps]

    def index_of(needle: str) -> int:
        hits = [i for i, n in enumerate(names) if needle in n]
        assert hits, f"no step matching {needle!r} in {names}"
        return hits[0]

    assert (index_of("release-please-action") < index_of("Make the GitHub Release body")
            < index_of("Arm auto-merge")), names

    step = steps[index_of("Make the GitHub Release body")]
    run = step["run"]
    assert "--print-section" in run, "must take the body from the corrected changelog"
    assert "gh release edit" in run
    assert _names_a_non_suppressed_credential(step.get("env"))
    assert "GITHUB_TOKEN" not in str(step.get("env"))

    # The step above can leave the tree on the release PR branch; this one must
    # read the pushed commit regardless.
    assert "$GITHUB_SHA" in run, "must not depend on which branch the previous step left"

    # A plain diff calls the missing trailing newline a difference, which would
    # rewrite the release body on every push to master forever.
    assert "rstrip()" in run, "the comparison must ignore trailing whitespace"


def test_the_release_prs_own_description_is_synced_too():
    """The changelog and the GitHub Release page are two of three copies of the
    same section; the release PR's own description is the third, and nothing
    corrected it. #274 shipped with the duplicate entry still sitting in the PR
    body after CHANGELOG.md had already been fixed — the one copy a reviewer
    reads before approving the release.

    This must live in the same step as the changelog rebuild (not a separate
    one), because it needs the PR number that step already looked up, and it
    must run after the corrected CHANGELOG.md is pushed, so `--print-section`
    reads the fixed text rather than release-please's original."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    names = [s.get("name") or str(s.get("uses", "")) for s in steps]

    def index_of(needle: str) -> int:
        hits = [i for i, n in enumerate(names) if needle in n]
        assert hits, f"no step matching {needle!r} in {names}"
        return hits[0]

    step = steps[index_of("Rebuild the changelog")]
    run = step["run"]

    assert "gh pr edit" in run, "must write the corrected description back"
    assert "gh pr view" in run, "must read release-please's own body to splice into"
    assert run.count("--print-section") >= 1, (
        "must reuse the section already computed for the changelog/release-body "
        "sync, not recompute it a third way"
    )
    assert _names_a_non_suppressed_credential(step.get("env"))
    assert "GITHUB_TOKEN" not in str(step.get("env"))

    # The splice must run after CHANGELOG.md is pushed (so the section it reads
    # back out is the corrected one) and, being in this step, necessarily before
    # "Arm auto-merge" runs as the next step.
    assert run.index("git push origin") < run.index("gh pr edit"), (
        "the PR description must be synced from the *pushed* (corrected) "
        "CHANGELOG.md, not from release-please's original"
    )
    assert index_of("Rebuild the changelog") < index_of("Arm auto-merge")


def test_the_changelog_tool_exists_and_the_workflow_calls_it():
    """A workflow step invoking a script nobody ships is a silent no-op — and
    this one runs on the release path, where nobody is watching."""
    assert (_REPO / "tools" / "changelog_dedup.py").exists()
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    runs = " ".join(str(s.get("run", "")) for s in steps)
    assert "tools/changelog_dedup.py" in runs


def test_only_types_that_change_the_installed_package_cut_a_release():
    """Every un-hidden type releases on its own. jeles shipped v0.4.1 to PyPI
    for a `ci:` commit that touched a workflow file, which is survivable when a
    human merges the release PR and fatal-ish when auto-merge does."""
    sections = _package_config()["changelog-sections"]
    visible = {s["type"] for s in sections if not s.get("hidden")}
    assert visible == {"feat", "fix", "security", "perf", "refactor",
                       "build", "deps"}, visible
    for t in ("docs", "test", "ci", "chore"):
        assert next(s for s in sections if s["type"] == t).get("hidden") is True


def test_this_package_is_past_1_0_so_no_pre_major_flags():
    """jeles carries `bump-minor-pre-major` because it is below 1.0. Copying it
    here would cap every breaking change at a minor bump, so 3.0.0 could never
    be reached by the automation."""
    cfg = _package_config()
    for flag in ("bump-minor-pre-major", "bump-patch-for-minor-pre-major"):
        assert flag not in cfg, f"{flag} is for pre-1.0 packages; this is 2.x"
    assert re.match(r"^[2-9]\.", _json(_MANIFEST)["."]), "expected a 2.x+ version"


def test_the_checkout_uses_the_pat_so_its_pushes_are_not_gated():
    """`actions/checkout` persists whatever credential it used, and the changelog
    step's `git push` then uses it. `env: GH_TOKEN` only reaches the `gh` CLI.

    With the default GITHUB_TOKEN the commit is pushed as github-actions[bot],
    and the release PR's CI run comes back `action_required` — created, but held
    awaiting manual approval — so auto-merge waits on a check that never
    reports. Observed on the 2.2.0 release PR, which needed CI started by hand;
    release-please's own commit on the same branch was not gated, because it
    pushes with the PAT.

    This is the fourth way this fleet has been bitten by token attribution, so
    it gets a test rather than a comment."""
    steps = _yaml(_RP_WF)["jobs"]["release-please"]["steps"]
    checkout = next(s for s in steps
                    if str(s.get("uses", "")).startswith("actions/checkout"))
    token = str((checkout.get("with") or {}).get("token", ""))
    assert _names_a_non_suppressed_credential(token), (
        "checkout must carry a credential whose events trigger workflows. "
        f"Got: {token!r}")
    assert "GITHUB_TOKEN" not in token
