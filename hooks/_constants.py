"""Shared string constants used by pre_tool_use.py and its bundled twin.

Extracted so the federation server id, the web-order ladder, and the
brokered-push hint live in exactly one place and cannot drift between the
top-level hook file and the bundle mirror. Every reason string that names
Jeles / Nestor / willows-bot imports from here.

`_constants.py` is a plain module import from `hooks/pre_tool_use.py`;
the bundle twin lives at `src/willow_mcp/bundle/hooks/_constants.py` and
must be byte-identical (pinned by tests/test_skills_sync.py's hook-parity
assertion — the same rule that pins the two `pre_tool_use.py` copies).
"""

# The ratified Jeles corpus federation server. Named in
# skills/orchestrator-routing.md, the willows-grove seat scripts, and
# every hook redirect that mentions federation.
JELES_FEDERATION_SERVER = "8cae3d1dcdf4"

# The verified-organs ladder. Every reason string that redirects the seat
# away from the open web ends with this sentence so the caller knows in
# one place where verified knowledge lives.
WEB_ORDER = (
    "nestor_ask/nestor_resolve (sealed) → "
    f"federation_call server {JELES_FEDERATION_SERVER} "
    "(corpus_web_search / corpus_institutional_search / corpus_verify_claim) → "
    "knowledge_search → "
    "willow_web_* only as unverified fallback (three keys: web_net + "
    "consent.internet + live operator lease)"
)

# The brokered-push hint. Every reason string that blocks or warns on
# `git push` / `gh` names this so the caller knows push is a brokered
# verb (`git_push_execute`) and never a Kart-held credential. Ties to
# docs/design/brokered-push.md (slice 1 landed; slice 3 landed; slice 2
# still open under gap 5ecb87cfdf56).
GIT_PUSH_HINT = (
    "git_push_execute(app_id=..., repo='org/name', branch=..., remote='origin') "
    "— brokered push; willows-bot installation token on the broker; "
    "never `git push` in Bash or Kart with a token"
)
