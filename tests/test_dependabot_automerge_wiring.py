"""#297: a Dependabot PR auto-merged with GITHUB_TOKEN reaches master with no
CI run and no release-please run on the result.

GitHub does not trigger `on: push` / `on: pull_request` workflows for events
it generated with GITHUB_TOKEN — its recursion guard, and it is documented and
intentional. `gh pr merge --auto` *arms* a merge; GitHub performs the merge
itself later, once required checks pass, and attributes that merge to
whoever armed it (release-please.yml already documents and tests this same
fact for the release PR). #293 was armed with GITHUB_TOKEN, so its eventual
merge push carried github-actions[bot]'s identity, started zero workflow
runs, and silently dropped two CHANGELOG entries because release-please's
changelog-rebuild step never ran.

The fix reuses the PAT release-please.yml already requires
(`RELEASE_PLEASE_TOKEN`) to arm auto-merge here too, so the eventual merge is
an ordinary push and `Tests` / `Release Please` (both `on: push`) run on it
like any other merge to master. These tests pin that everywhere auto-merge is
armed uses the PAT, not GITHUB_TOKEN — and nowhere else, since read-only
metadata fetches never needed it and giving it that scope would be needless.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML needed to read the workflow")

_REPO = Path(__file__).resolve().parents[1]
_WF = _REPO / ".github" / "workflows" / "dependabot-automerge.yml"


def _load() -> dict:
    return yaml.safe_load(_WF.read_text())


def _steps(job: str) -> list[dict]:
    return _load()["jobs"][job]["steps"]


def _secrets_used(value) -> set[str]:
    return set(re.findall(r"secrets\.([A-Z_]+)", str(value)))


# A credential whose events trigger workflows. What matters is that it is NOT
# GITHUB_TOKEN: #297 shipped because arming with GITHUB_TOKEN attributed the
# eventual merge to github-actions[bot], so the push to master started no runs
# at all. The willow-ci App token has the same non-bot property as the PAT it
# replaces, and expires in an hour instead of on a calendar.
#
# Checked against the raw env rather than _secrets_used(), because an App token
# arrives as `steps.app-token.outputs.token` — a step output, not a secret
# reference, so it can never appear in a set of secret NAMES.
NON_SUPPRESSED_CREDENTIALS = (
    "RELEASE_PLEASE_TOKEN",              # fine-grained PAT (being retired)
    "steps.app-token.outputs.token",     # willow-ci App installation token
)


def _arms_with_non_suppressed_credential(value) -> bool:
    text = str(value)
    return any(c in text for c in NON_SUPPRESSED_CREDENTIALS)


def test_automerge_arming_uses_the_pat_not_github_token():
    """The step that actually calls `gh pr merge --auto` on a fresh Dependabot
    PR must run with the PAT — GITHUB_TOKEN here silently reproduces #297."""
    steps = _steps("dependabot-pr")
    arm = next(s for s in steps if s.get("name") == "Enable auto-merge")
    assert "gh pr merge --auto" in arm["run"]

    used = _secrets_used(arm.get("env"))
    assert _arms_with_non_suppressed_credential(arm.get("env")), arm.get("env")
    assert "GITHUB_TOKEN" not in used, (
        "arming auto-merge with GITHUB_TOKEN attributes the eventual merge "
        f"to github-actions[bot], which starts no workflow run. Found: {used}"
    )


def test_refresh_stale_prs_also_uses_the_pat():
    """`refresh-stale-dependabot-prs` re-arms auto-merge after the base moves —
    same `gh pr merge --auto` call, same attribution trap, same fix."""
    steps = _steps("refresh-stale-dependabot-prs")
    rearm = next(
        s for s in steps
        if "Re-arm auto-merge" in (s.get("name") or "")
    )
    assert "gh pr merge --auto" in rearm["run"]

    used = _secrets_used(rearm.get("env"))
    assert _arms_with_non_suppressed_credential(rearm.get("env")), rearm.get("env")
    assert "GITHUB_TOKEN" not in used, used


def test_metadata_fetch_stays_on_github_token():
    """The Dependabot metadata fetch only reads the PR — it merges nothing, so
    handing it the PAT would be scope it never needs. It must stay narrow
    even though the merge steps around it were widened to the PAT."""
    steps = _steps("dependabot-pr")
    fetch = next(s for s in steps if s.get("name") == "Fetch Dependabot metadata")
    used = _secrets_used(fetch.get("with"))
    assert used == {"GITHUB_TOKEN"}, used


def test_both_jobs_mint_the_credential_before_arming():
    """A missing credential must fail loudly, not silently degrade to a
    GITHUB_TOKEN arm that looks fine until the merge lands untested.

    This used to be a shell step that checked whether the secret was set. The
    mint step replaces it and is a stronger guard: it fails if the App is not
    installed, if the key is wrong, or if the org values are missing — states a
    `[ -z "$TOKEN" ]` check could not see. What still has to hold is the
    ordering: the credential must be minted BEFORE anything arms a merge with
    it."""
    for job, arm_name in (
        ("dependabot-pr", "Enable auto-merge"),
        ("refresh-stale-dependabot-prs", "Re-arm auto-merge on open Dependabot PRs after the base moves"),
    ):
        steps = _steps(job)
        names = [s.get("name") for s in steps]

        mint_idx = next(
            i for i, s_ in enumerate(steps)
            if s_.get("id") == "app-token"
        )
        arm_idx = names.index(arm_name)
        assert mint_idx < arm_idx, (job, names)

        mint = steps[mint_idx]
        assert str(mint.get("uses", "")).startswith(
            "actions/create-github-app-token"), (job, mint)
        with_ = mint.get("with") or {}
        assert "WILLOW_CI_APP_ID" in str(with_.get("app-id")), (job, with_)
        assert "WILLOW_CI_PRIVATE_KEY" in str(with_.get("private-key")), (job, with_)


def test_no_gh_pr_merge_call_anywhere_uses_github_token():
    """Belt-and-suspenders over the two targeted tests above: scan every step
    in the workflow and refuse GITHUB_TOKEN next to any `gh pr merge --auto`
    call, so a future step added the same way this bug shipped is caught."""
    data = _load()
    for job_name, job in data["jobs"].items():
        for step in job["steps"]:
            run = str(step.get("run", ""))
            if "gh pr merge --auto" not in run:
                continue
            used = _secrets_used(step.get("env"))
            assert "GITHUB_TOKEN" not in used, (
                f"{job_name}/{step.get('name')} arms auto-merge with "
                f"GITHUB_TOKEN — the merge it eventually performs would start "
                f"no workflow run. Found: {used}"
            )
            assert _arms_with_non_suppressed_credential(step.get("env")), (
                job_name, step.get("name"), step.get("env"))


def test_permissions_are_read_only_now_that_arming_uses_the_pat():
    """GITHUB_TOKEN performs no write in this workflow anymore — only the
    read-only metadata fetch uses it. The `permissions:` block should say so,
    not carry write scope nothing exercises."""
    perms = _load()["permissions"]
    assert perms == {"contents": "read", "pull-requests": "read"}, perms
