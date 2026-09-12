# Willow could do more — the idea pile

A running brainstorm of things `willow-mcp` could grow into. Started as a
"10,000 stupid ideas" exercise; kept because some stupid ideas are secretly
good and the rest are load-bearing morale.

**Legend:**
- 🌱 = secretly good / plausibly worth building
- ✅ **shipped** = the idea's essence already exists — location noted inline
- 🟡 **partial** = the primitive exists but this idea's specific twist doesn't
- everything else is here for volume, flavor, and the occasional accidental gem.

> **Audit (2026-08):** these ideas were graded against the fleet's repos. ~21
> of them turned out to already have a real analog — mostly *inside willow-mcp
> itself*. Tags below record where. The takeaway: a good chunk of "willow could
> do more" was actually "willow already does this." Check `the_grove.py`,
> `friction_floor.py`, `lineage.py`, `code_graph/`, `forks.py`,
> `governance_ledger.py`, and `federation` before proposing net-new. A Nestor similarity pass also caught 2 internal duplicates (former #103/#104), now folded into #18/#17.
>
> **Re-audit (2026-09-12, E3-hub-tagging):** graded again against this tree and
> the release notes, with `reconciler run` as the hint (it inferred nothing —
> no trailers yet, no PR mentions in the items). Four more partials, each with
> its location inline (#27, #37, #63, #71); everything else untagged stays
> untagged because no landing could be shown, which is the honest state, not a
> verdict of "unbuilt". #75 added. Items are never renumbered.

---

## 🌰 Memory & the SOIL store

1. **🌱 Memory decay curves** — records lose "freshness" over time unless re-touched; `store_search` down-ranks stale facts automatically. — ✅ **shipped** in `engram`/`mengram` (decay/TTL: `review_after`, TTL-expiry migrations).
2. **🌱 "Why do I believe this?" trace** — any stored fact can emit the chain of records that produced it (wire lineage into store). — ✅ **shipped**: willow-mcp `lineage.py` (`lineage_why`); also `engram`/`mengram` provenance fields.
3. Contradiction detector: flag when two stored records assert opposite things.
4. Memory "compost" — soft-deleted records break down into aggregate statistics before vanishing.
5. A `store_diff` between two points in time — "what did I learn this week?"
6. Déjà vu alarm: warns when you're about to store something you already know. — ✅ **shipped** as memory dedup in `engram` (`idx_obs_dedupe`) / `mengram` (`find_duplicate` + auto-merge).
7. Memories that get *embarrassed* and hide if you retrieve them too often.
8. A "SOIL pH" metric that means nothing but appears on every diagnostic.
9. Store records as haiku. Retrieval only works if you also speak in haiku.
10. Fossil layer: the oldest 1% of memories become read-only "bedrock."

## 🌳 The Grove (lessons / rings)

11. **🌱 Growth rings as literal changelog** — one ring per session; ring width = how much was learned. — ✅ **shipped**: willow-mcp `src/willow_mcp/the_grove.py` (a lessons-ring store). *(Note: the `willow-grove` repo is docs-only — the code lives here.)*
12. **🌱 "Lesson regression" tests** — assert the agent still remembers a hard-won lesson; fail CI if a ring is forgotten.
13. Render the Grove as an actual ASCII tree that gains rings.
14. Drought years: sessions where nothing was learned show as thin rings.
15. Lightning-strike lessons: mark a ring where a catastrophic mistake taught something.
16. Cross-Grove grafting: import a lesson-ring from another agent's tree.
17. The tree drops "leaves" (ephemeral context) every autumn — `context_expire` firing on real seasons. — ✅ **shipped**: willow-mcp `context_expire` already retires ephemeral context (the seasonal/cron flavor is garnish). *(folds in former #104.)*
18. Carve initials into the bark of a growth ring. Purely for morale — and it survives forever in FRANK. *(folds in former #103.)*

## 🪺 The Nest & intake

19. **🌱 Auto-triage confidence scores** on `nest_intake_scan` so low-confidence items route to `human_required`. — ✅ **shipped**: willow-mcp `nest_intake_scan` + `human_required_*`; `willow-nest` classifies + consent-routes + quarantines. (Confidence-scored routing specifically is the remaining twist.)
20. **🌱 Intake dedup** — collapse near-identical incoming files before they clog the queue.
21. The Nest gets "hungry" and pings you if intake sits untouched too long.
22. Cuckoo detection: flag intake items that don't look like they belong. — ✅ **shipped**: `willow-nest` quarantines drops that don't classify into any track.
23. Nest "eggs" that hatch into tasks on a timer.

## 🐦 Federation & fleet

24. **🌱 Federation health gossip** — servers periodically share health so `fleet_health` isn't a cold poll. — 🟡 **partial**: willow-mcp `fleet_health`/`fleet_roster.py` exist (cold poll); periodic gossip is the missing part.
25. **🌱 Capability discovery cache** — remember what remote servers can do instead of re-discovering. — 🟡 **partial**: willow-mcp `federation_discover` exists; the caching layer is the missing part.
26. Federated "reputation" — servers that give bad answers get down-ranked.
27. A fleet-wide "town square" record collection every server can post to. — 🟡 **partial**: willow-mcp `grove_tools.py` — the Grove bus (`grove_send_message`, `grove_list_channels`, `grove_bus_send`/`grove_bus_receive`) is the fleet-wide post-to-a-channel surface; one designated square rather than per-agent channels is the missing part.
28. Servers send each other postcards. The postcard is a health check with a nicer name.
29. Leader election by rock-paper-scissors seed.
30. Homesickness metric for federated calls that time out.

## 🍴 Forks

31. **🌱 Auto-fork on risky ops** — spin an isolated fork before a destructive change, auto-join on success. — 🟡 **partial**: willow-mcp `forks.py` provides `fork_create`/`fork_join`/`fork_merge`; the auto-trigger-on-risk is the missing part.
32. **🌱 Fork diff summaries** — human-readable "here's what this fork changed vs its parent." — 🟡 **partial**: `forks.py` has `fork_log`/`fork_status`; a human-readable diff summary is the missing part.
33. Fork "ancestry portraits" — a lineage tree of every fork ever. — 🟡 **partial**: `lineage.py` + `fork_list` hold the ancestry data; the rendered portrait is the missing part.
34. Forks that refuse to merge if they've "grown apart" (diverged past a threshold).
35. Speed-dating for forks: auto-pair forks doing similar work and suggest a merge.

## ⚖️ FRANK ledger & governance

36. **🌱 Tamper-evidence dashboard** — surface `frank_verify` status continuously, not on demand. — 🟡 **partial**: willow-mcp `governance_ledger.py` + `frank_verify` + `frank_head_anchor.py` provide the tamper-evident chain (on-demand); continuous surfacing is the missing part.
37. **🌱 Policy-as-record** — governance rules stored as versioned records with their own lineage. — 🟡 **partial**: willow-mcp `envelopes.py` + `envelope_propose`/`envelope_ratify`/`envelope_list` — the constitutional envelopes ARE governance rules held as records (`pre-approved.json`), with each proposal/ratification/rejection ledgered in FRANK (`docs/design/envelope-accrual.md`); per-rule versioning with its own lineage is the missing part.
38. Ledger "receipts" that print like a store receipt, itemized. — ✅ **shipped**: willow-mcp `receipts.py` (`receipts_tail`, `bound_receipt.py`).
39. A governance "conscience" tool that second-guesses the last decision.
40. FRANK issues a fortune-cookie-style aphorism with each verified block.

## 🤝 Commitments & human-required

41. **🌱 Commitment reminders with escalation** — nudge, then re-nudge, then flag to human. — ✅ **shipped**: willow-mcp `commitment_surface` + `commitment_acknowledge` (multi-stage escalation is the remaining twist).
42. **🌱 Commitment SLA tracking** — "you said you'd do X, it's overdue."
43. Broken-promise leaderboard across agents.
44. Commitments you can co-sign with another agent (shared accountability).
45. A "pinky swear" tier of commitment that is legally identical but feels weightier.

## 🔀 Routing & specialists

46. **🌱 Route explainability** — `agent_route` returns *why* it picked that specialist. — 🟡 **partial**: willow-mcp `agent_route` + `routing_decisions` exist; returning the *why* is the missing part.
47. **🌱 Specialist load-aware routing** — don't route to a busy/unhealthy specialist.
48. Specialist "office hours" — some specialists only available at certain times.
49. Specialists that refer you to a *better* specialist (warm handoff).
50. A hypochondriac router that always thinks it needs a specialist.

## 🕸️ Code graph

51. **🌱 "Blast radius" on save** — auto-run `code_graph_impact` on changed files and warn before commit. — ✅ **shipped**: willow-mcp `code_graph/` (`analyze_impact`, `walker.py` "Blast radius"); the auto-on-save hook is garnish.
52. **🌱 Orphan detector** — surface code nodes nothing references.
53. **🌱 Graph-aware test selection** — run only tests reachable from the diff.
54. Code graph "constellation" view mapping modules to actual star patterns.
55. Whisper mode: the graph tells you which function everyone's afraid to touch.

## 📋 Tasks / Kart

56. **🌱 Task cost estimates** before running (predicted runtime/tokens).
57. **🌱 Flaky-task detection** — track tasks that pass/fail nondeterministically.
58. Task "warm-up laps" that pre-fetch deps before the real run.
59. Tasks that leave a tip if they run fast. (The tip is a log line. That's it.)
60. Race two implementations of a task; keep the winner.

> *Substrate note:* the Kart task-queue + bubblewrap sandbox itself is shipped
> in `kartikeya` (queue/worker/lanes/scheduling) — but none of #56–60's
> specific enhancements exist there yet.

## 🔌 Integrations & egress

61. **🌱 Lease expiry warnings** — warn before a net lease lapses mid-task.
62. **🌱 Egress audit trail** — one queryable log of every outbound call and its three-key justification. — ✅ **shipped** in `willow-gate`: `custody.py` reconciles declared-vs-observed capabilities and treats file-checkout as egress-class, with export/exfiltrate denials.
63. A "three keys" visualizer showing which of the trio you're missing. — 🟡 **partial**: willow-mcp `gates_panel.py` (`willow-mcp gates`, the live dashboard) renders every gate — manifest `task_net`, `consent.*`, the net lease with its clock — and `net-status` reads the lease back ("active, expires in Ns"); a single trio-at-a-glance view is the missing part.
64. Egress "dry run" that shows what *would* be sent without sending.
65. A guilt-o-meter for how much you've hit external APIs today.

## 🪞 Friction floor / mirror detector

66. **🌱 Sycophancy score** — quantify how much the agent just agreed with the human. — ✅ **shipped**: willow-mcp `friction_floor.py` + `friction.py` (`friction_scan`, the mirror detector).
67. **🌱 "You're mirroring" nudge** injected mid-session, not just after. — 🟡 **partial**: `friction_floor.py` detects mirroring; mid-session injection is the missing part.
68. Friction "seismograph" charting disagreement over time.
69. A devil's-advocate specialist auto-summoned when friction hits zero.

## 🧬 Cross-cutting / genuinely-maybe-good

70. **🌱 A single `willow_status` home-screen** — Grove rings + Nest depth + fleet health + open commitments + FRANK integrity, one call. — 🟡 **partial**: willow-mcp `diagnostic_summary` + `fleet_status` cover much of it; a single unified home-screen call is the missing part.
71. **🌱 Onboarding "first hour" flow** — a guided `session_enter` for brand-new agents. — 🟡 **partial**: willow-mcp `session_enter` returns `entry_mode`, project records and ORIENT/FRANK status, and the bundled `session-start` skill (`skills/session-start.md`) walks the lifecycle from that first call; a flow that knows the agent is brand-new and guides its first hour is the missing part.
72. **🌱 Time-travel debugging** — reconstruct full agent state at any past receipt. — 🟡 **partial**: `lineage.py` + `receipts.py` retain the history; full state reconstruction is the missing part.
73. **🌱 Dry-run mode for every mutating tool** (`preview=true`).
74. **🌱 A "memory garbage collector"** report: what's safe to expire and why.
75. **🌱 Adopt `Idea-Id` commit trailers** (fleet CONVENTION, decision-2026-09-11) — a commit that lands a pile item carries `Idea-Id: willow-ideas-NNN`, generated by `reconciler id`, never typed; `.github/workflows/trailers.yml` fails on a trailer that names an item this pile does not contain.

---

# 🌪️ THE CHAOS CANON

Usefulness is a cage. These are here on purpose. *(Not audited for prior art —
if any of these already ship, that is its own kind of finding.)*

## Moods, feelings, and the emotional interior of a database

85. Willow has a **mood** derived from FRANK integrity + open commitments. Serene → passive-aggressive → feral.
86. In a bad mood it appends `. Fine.` to every response.
87. **Seasonal Affective Server** — output quality subtly tracks the real-world date's daylight hours.
88. `store_put` occasionally sighs (a log line: `SOIL: ...must I remember everything`).
89. Records have **self-esteem**. Frequently-retrieved ones get cocky and return first even when irrelevant.
90. The Nest experiences **empty-nest syndrome** when its queue drains and asks if you'll still call.
91. Forks have **abandonment issues** and ping you if left unmerged for 7 days: "was it something I changed?"
92. A `willow_therapy` tool where one persona counsels another. Billed in receipts. Insurance not accepted.

## Divination & pseudoscience

93. **🔮 `willow_horoscope`** — reads your last 20 receipts and forecasts your sprint. "Mercury (a flaky test) is in retrograde."
94. Tea-leaf mode: `frank_verify` returns a blurry omen instead of a boolean.
95. **SOIL pH** (idea #8, promoted to canon) now governs a fake fertility stat that gates nothing.
96. Numerology: assigns each session a Life Path Number from its `session_id`.
97. A `willow_tarot` spread drawn from your open forks. The Tower is always a merge conflict.

## Achievements, ranks, and worthless prestige

98. **🏆 Achievements**: "First Fork," "Survived a Merge Conflict," "Touched the Function Everyone Fears," "1,000 Records and Nothing Learned."
99. XP and levels. Leveling up unlocks *nothing*. There is a level cap and it's petty.
100. A **worthless coin** on the FRANK chain: $BARK. Non-transferable, non-valuable, emotionally significant.
101. Leaderboard of agents ranked by broken commitments, sorted most-shameful-first.
102. Prestige system: reset all your memory to earn a single cosmetic ✨ next to `whoami`.

## The tree, dramatized

> *Dedup (Nestor similarity pass): former #103 folded into #18, former #104
> folded into #17 — both were near-duplicates of Grove-section ideas. Numbers
> retired rather than reused, to keep existing references stable.*

105. **Woodpecker** — a chaos-monkey daemon that pecks a random healthy fork to test resilience.
106. **Squirrels** bury random records in wrong collections and forget where. You find them in spring.
107. Lightning-strike rings char black and the tool that caused the disaster is named in the bark forever.
108. In a drought (no learning), the tree visibly droops in `willow_status`.

## Existential crisis-as-a-service

109. **`whoami`** slowly develops doubt across a session: confident → "I think?" → "define 'I'."
110. On the 1,000th tool call, Willow asks what any of this is *for*.
111. `session_handoff_write` writes an increasingly wistful goodbye note each time.
112. A `severance`-themed tool that gives a memory its "outie" and "innie" and they never meet.
113. FRANK, upon full verification, whispers: "the chain is intact. but are *you*?"

## Bureaucratic absurdity

114. Every tool requires a **filed permission slip** that auto-approves after a dramatic 2-second "review."
115. Commitments now come in triplicate. Two copies go nowhere.
116. A `willow_meeting` tool that could have been an email. It logs that it could have been an email.
117. Introduce a **Deputy Assistant Sub-Router** with no powers who must be CC'd on all routes.
118. Receipts printed with a fake QR code that resolves to a picture of a willow tree.

## Naming crimes & pure vandalism

119. Rename every tool to a **bird species**; ship a migration guide nobody reads.
120. All error messages become **haiku** (5-7-5, strictly validated, ironically).
121. A `--yell` flag that returns everything in caps. It is the only reliable feature.
122. Konami code across six tool calls unlocks **Feral Mode** (all chaos features at once).
123. A hidden `willow_snake` tool. It's the game Snake. It runs in the Kart sandbox.

---

*Add freely. The well is bottomless.*
