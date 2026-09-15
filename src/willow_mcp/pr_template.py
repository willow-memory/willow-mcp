"""willow_mcp/pr_template.py — resolve and enforce a repo's PR template.

Gap ``378c2e57c3d0``. GitHub's web UI shows the repo's
``pull_request_template.md`` in the body field on every new-PR page; the
API path does not, so a bot that opens a PR ships an empty body — the
first thing the operator sees is "please fill this in", and the check
that would have caught it lives in the human's browser, not the wire.

This module puts the same check on the wire. Two readers, one shape:

- :func:`resolve_repo_template` — the repo's own template (root or
  ``.github/`` or ``docs/`` or a single ``PULL_REQUEST_TEMPLATE/*.md``
  under ``.github/``).
- :func:`resolve_org_template` — the fallback under ``<org>/.github``
  when the repo carries none.

Then :func:`validate_body` checks that the H2 / H1 section headings the
template names all appear (as ``## heading`` lines) in the submitted
body. The check is deliberately about SECTION PRESENCE, not content —
a bot filling one section with a placeholder still passes the shape
check, which is what the human review is for. A missing section is
``EBODY`` with the list of what is missing.
"""
from __future__ import annotations

import base64
import re
from typing import Any, Callable


_API = "https://api.github.com"

#: The paths GitHub searches for a repo template, in the order it uses.
#: See docs.github.com — "Creating a pull request template".
_TEMPLATE_PATHS = (
    ".github/pull_request_template.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "pull_request_template.md",
    "PULL_REQUEST_TEMPLATE.md",
    "docs/pull_request_template.md",
    "docs/PULL_REQUEST_TEMPLATE.md",
)

#: Case-insensitive H1 / H2 heading (``# Title`` or ``## Title``).
_HEADING_RE = re.compile(r"^\s*(#{1,2})\s+([^#\n]+?)\s*#*\s*$", re.MULTILINE)


def _get_content(api: Callable, url: str, *, bearer: str) -> dict[str, Any]:
    resp = api("GET", url, bearer=bearer)
    return resp if isinstance(resp, dict) else {"ok": False, "status": 0, "reason": "malformed api response"}


def _decode_content(payload: dict) -> str | None:
    """GitHub's ``/contents`` returns a base64 blob in ``content`` when the
    file is small enough. Empty content or a directory response returns
    None."""
    if not isinstance(payload, dict):
        return None
    if payload.get("type") != "file":
        return None
    encoded = payload.get("content") or ""
    if payload.get("encoding") != "base64":
        return None
    try:
        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return None


def resolve_repo_template(
    api: Callable, *, repo: str, ref: str = "", bearer: str,
    api_base: str = _API,
) -> dict[str, Any]:
    """Try every well-known template path in the repo. Returns the first
    that resolves, or ``{"ok": True, "state": "absent"}`` if none does."""
    ref_qs = f"?ref={ref}" if ref else ""
    for path in _TEMPLATE_PATHS:
        url = f"{api_base}/repos/{repo}/contents/{path}{ref_qs}"
        resp = _get_content(api, url, bearer=bearer)
        if not resp.get("ok"):
            continue
        text = _decode_content(resp.get("body") or {})
        if text is not None:
            return {"ok": True, "state": "present", "source": f"repo:{path}",
                    "template": text}
    return {"ok": True, "state": "absent",
            "reason": "no template at any of the repo's well-known paths"}


def resolve_org_template(
    api: Callable, *, owner: str, bearer: str, api_base: str = _API,
) -> dict[str, Any]:
    """Fall back to ``<owner>/.github``'s ``pull_request_template.md``.
    GitHub uses this repo as the org-level default for a repo without its
    own template."""
    for path in _TEMPLATE_PATHS:
        url = f"{api_base}/repos/{owner}/.github/contents/{path}"
        resp = _get_content(api, url, bearer=bearer)
        if not resp.get("ok"):
            continue
        text = _decode_content(resp.get("body") or {})
        if text is not None:
            return {"ok": True, "state": "present", "source": f"org:{owner}/.github:{path}",
                    "template": text}
    return {"ok": True, "state": "absent",
            "reason": f"no template under {owner}/.github at any well-known path"}


def resolve_template(
    api: Callable, *, repo: str, bearer: str, api_base: str = _API,
) -> dict[str, Any]:
    """Repo template first, then org fallback. Absent from both is
    ``state="absent"`` with no template text."""
    repo_result = resolve_repo_template(api, repo=repo, bearer=bearer, api_base=api_base)
    if repo_result.get("state") == "present":
        return repo_result
    owner = (repo or "").split("/", 1)[0]
    if not owner:
        return repo_result
    return resolve_org_template(api, owner=owner, bearer=bearer, api_base=api_base)


def required_sections(template: str) -> list[str]:
    """Every H2 / H1 heading in the template, in order, lowercased. This is
    the shape the body is checked against: the template's own headings ARE
    the required sections. A template that names four ``## Foo`` headings
    requires four sections; a body missing any of them refuses."""
    seen: list[str] = []
    for match in _HEADING_RE.finditer(template or ""):
        heading = (match.group(2) or "").strip().lower()
        if heading and heading not in seen:
            seen.append(heading)
    return seen


def validate_body(body: str, template: str) -> dict[str, Any]:
    """Check that every H1/H2 section heading in ``template`` appears (as a
    heading of the same shape) in ``body``. Returns
    ``{"ok": True, "sections": [...]}`` when every section is present, or
    ``{"ok": False, "errno": "EBODY", "missing": [...], "sections": [...]}``
    when not."""
    sections = required_sections(template)
    if not sections:
        # A template with no headings is a template that names no shape —
        # the shape check is a no-op. (An operator who wants line-level
        # checking can add the headings.)
        return {"ok": True, "sections": [], "state": "no_headings"}
    body_headings = set(required_sections(body or ""))
    missing = [s for s in sections if s not in body_headings]
    if missing:
        return {
            "ok": False, "errno": "EBODY", "state": "missing_sections",
            "reason": (f"body is missing {len(missing)} required section(s): "
                       + ", ".join(f"'{m}'" for m in missing[:5])
                       + (f" (and {len(missing) - 5} more)" if len(missing) > 5 else "")),
            "sections": sections, "missing": missing,
        }
    return {"ok": True, "state": "complete", "sections": sections}


def preflight(
    api: Callable, *, repo: str, body: str, bearer: str,
    api_base: str = _API,
) -> dict[str, Any]:
    """The one call ``pr_executor`` makes: resolve the template, validate the
    body, return one receipt. Absent template → ``state="no_template"``
    (proceed; there is no shape to enforce). Missing sections → refuse
    ``EBODY`` before envelope citation."""
    resolved = resolve_template(api, repo=repo, bearer=bearer, api_base=api_base)
    if resolved.get("state") != "present":
        return {"ok": True, "state": "no_template",
                "reason": resolved.get("reason", "no repo or org template resolved")}
    validation = validate_body(body or "", resolved["template"])
    validation["template_source"] = resolved["source"]
    return validation
