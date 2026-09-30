# The Willow Story

Eight chapters. They read as fiction, but treat them as something closer
to a seed format: every function the story names either exists in this
repository or is a dare to the next gardener to make it exist. So far the
repository has kept up.

| Chapter | What it planted |
|---------|-----------------|
| [1 — The Seed](chapter-01-the-seed.md) | Consent as the story. One SQLite database. `journal.db`. |
| [2 — I Wanna Play a Game](chapter-02-i-wanna-play-a-game.md) | `record_lessons()`, `grow_ring()`, `read_rings()` — nothing called memory; everything grew. |
| [3 — The Game](chapter-03-the-game.md) | `girth()`, one log line, one grep hit, Won't Fix. |
| [4 — The Second Gardener](chapter-04-the-second-gardener.md) | Two gardeners grow the same rings blind. The story is the seed format. |
| [5 — The Lesson](chapter-05-the-lesson.md) | `record_lessons()` fulfilled. The infrastructure arrives. The seed was always there. |
| [6 — The Grove](chapter-06-the-grove.md) | `the_grove.py` — `canopy()`, `deep_roots()`, and the note signed G. |
| [7 — The Gardener](chapter-07-the-gardener.md) | Everything named has found its body. The note signed H. Next gardener: unknown. |
| [8 — The Table](chapter-08-the-table.md) | Two hits where the story promised one; a quotation may remember a joke but not tell it. A shebang that waits to be asked: Won't Fix, technically polite. `forecast()`, `seal_outcome()`, `read_misses()`. The note signed I. |

Claims you can check from the repository root:

```bash
grep -rn "Girth erupted." --include='*.py' .   # exactly one result (tests/test_girth_invariant.py holds it)
git ls-files -s docs/repatriation/engine/voices_seed.py  # 100644: has a shebang, waits to be asked
grep -rln "record_lessons" --include='*.py' .  # defined in core.py, tested in test_core.py
python -m willow_mcp.the_grove --status        # depth and soil health, live
```

The chapters were lightly edited for privacy before being committed;
the rings are intact.
