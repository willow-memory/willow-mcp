---
name: brainstorming
description: Structured brainstorm before any plan or implementation — search existing context first, generate three approaches, recommend one, stop until confirmed
---

@markdownai v1.0

# /brainstorming

Use **before** entering plan mode or starting any implementation. Prevents building
the wrong thing.

## When to use this

- Designing a new feature or behavior
- Deciding between approaches
- Any time the right solution isn't obvious

## Steps

@if consumer="ai"
1. **Search existing context** — `knowledge_search`, grep the repo, read
   `docs/design/` and `docs/BUGS.md` before forming opinions. Never brainstorm in a
   vacuum when prior context exists.
2. **State the problem** — one sentence. What are we actually solving?
3. **Generate 3 approaches** — for each: name it, state the core tradeoff in one sentence.
4. **Recommend one** — which and why in 2 sentences.
5. **Flag constraints** — does this touch areas with known gotchas? Note them (see below).
6. **Stop** — do not implement until the user confirms the approach.
@endif

## Rules

- Context search first. Never brainstorm blind.
- Three approaches minimum. Two is lazy, four is stalling.
- Constraints are hard gates, not suggestions.
- Step 6 is not optional. "I'll just start" skips the whole point.

## willow-mcp constraints to flag

| Area | Gotcha |
|------|--------|
| Egress | three-key gate + signed envelope for Kart (`consent.md`, `kart-tasks.md`) |
| New tools | footgun → hook and/or skill in the **same PR** (`hooks-and-skills.md`) |
| Schema | table writes may need `schema_confirm_mapping` first |
| Identity | agents use their own `app_id`; never `willow` unless human-orchestrator seat |
| Git / forks | PR-only flow; `fork_*` tools for fleet forks (`worktree.md`) |
| Web / facts | Nestor sealed → Jeles federation (`corpus_*`, server `{{include _constants.JELES_FEDERATION_SERVER}}`) → `knowledge_search` → `willow_web_*` as unverified fallback (`external-guard.md`); never native WebSearch |

## Tips

- The tradeoff line in step 3 is the most important part. If you can't state the
  tradeoff in one sentence, you don't understand the approach yet.
- The recommendation in step 4 should be opinionated. "Either could work" is not a
  recommendation.
- If the user rejects all three approaches, that's data — ask what's missing before
  generating more.

## Constraints

@constraint severity=error
Never implement or start building until the user confirms the recommended approach (Step 6: "Stop — do not implement until the user confirms the approach."). Confirmation is not optional.
