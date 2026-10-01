---
kind: assignment
title: "{title}"
from: "{orchestrator}"
to: "{agent}"
role: "{role}"
priority: normal
dispatch_id: "{id}"
reply_to: "{reply_to}"
---

@markdownai v1.0

# Assignment: {title}

**From:** {orchestrator}
**To:** {agent}
**Persona / role:** {role}
**Priority:** {high | normal | low}
**Dispatch ID:** {id}
**Reply to:** {reply_to}

## Bite

One sentence — the single outcome.

## Checklist

- [ ] {item}
- [ ] {item}

## Context

- {link or reference}

## Tools

- **Run:** every command (git, tests, lint) goes through Kart — `task_submit`, then `task_status`. No Bash.
- **Read code:** codebase-memory-mcp (`search_graph`, `search_code`, `get_code_snippet`, `trace_path`; project `{project_slug}`), and the Read tool for exact ranges.
- **Rulings:** Nestor (`nestor_ask`, `nestor_check`, `nestor_match`) before asserting a ruling or convention. Prefer a sealed answer and cite its pair id. Draft/pending means this organ cannot prove a seal — not that no human ever checked the claim. Never present unsealed material as sealed. Read-only — never propose or seal.
- **Auditing a commit:** for a merge commit (two parents), diff the first parent — `git diff <sha>^1 <sha> -- <path>`. Never `git show <sha> -- <path>`: for a 2-parent merge it prints nothing, which reads as "no change".
- No Agent tool; no subagents.

## Success criteria

- {what done looks like}

@constraint severity=error
Out of scope:

- {what you must not do}
