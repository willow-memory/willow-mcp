#!/usr/bin/env python3
"""Seed the `voices` corpus with curated human-voice gems (charter + narrative core +
willow-mcp canon). Tasteful: builder-identity, why, philosophy, vision, lore, humor —
genuinely private specifics deliberately omitted. Additive; re-runnable via ON CONFLICT."""
import psycopg2

# (theme, repo, source, title, quote, note)
G = [
 # --- who / why ---
 ("why","willow-mcp","docs/story/chapter-01-the-seed.md","the founding question",
  "Would you like to remember what younger you was trying to build?",
  "The recurring question the whole system answers. A journal.db from 2004 asks it."),
 ("why","willow-mcp","docs/story/chapter-05-the-lesson.md","the seed kept 20 years",
  "I had kept journal.db through four laptops, several lives I no longer live, and a move to the desert that was supposed to be temporary. I had never once opened it. Not because I forgot it. The opposite.",
  "The real 2004 db carried but never opened — 'never opening it was the most careful thing I did with it.'"),
 ("why","willow-mcp","docs/story/chapter-05-the-lesson.md","what younger you built",
  "You were not trying to build a journal. You were building Willow. You were young. You didn't have the infrastructure yet. You planted the seed anyway.",
  "The thesis: the project is the fulfillment of a 20-year-old intention."),
 ("why","willow","JOURNAL_APP_SPEC.md","the emotional core",
  "He wanted to be witnessed. Not praised. Seen.",
  "The plainest statement of the drive under the whole system."),
 ("why","willow-mcp","docs/story/chapter-06-the-grove.md","clearing brush",
  "I had spent two decades believing I was an architect building systems for the world... I wasn't. I was just clearing the brush so the seed could get sun.",
  "Reframes a career as preparation for the one seed."),
 # --- philosophy / why this way ---
 ("philosophy","willow-mcp","ARCHITECT.md","never overclaim",
  "Docs, docstrings, and schemas must not claim behavior the code doesn't have — this is the founding rule and the one most worth guarding.",
  "A whole PR once existed only to stop a docstring advertising a kill switch that wasn't there."),
 ("philosophy","willow-mcp","ARCHITECT.md","parts book",
  "Parts book, not service manual. He learns a system by taking it apart, comparing it against how it's actually composed, and reassembling it with the whole model in his head.",
  "The one instinct everything downstream is a consequence of. Hardware/restoration roots."),
 ("philosophy","willow-mcp","ARCHITECT.md","fail closed",
  "Gates deny on missing/ambiguous/broken input, never permit. The anti-pattern to hunt and kill is the quiet fail-open.",
  None),
 ("philosophy","willow-mcp","ARCHITECT.md","archive don't delete",
  "Nothing worth remembering gets dropped without explicit instruction. Vocabulary can be pruned cheaply, lessons cannot.",
  None),
 ("philosophy","willow-mcp","ARCHITECT.md","the sudo invariant",
  "Authority is never minted from a tool. The human ratifies; the machine proposes. Dual-commit is the oldest rule in the lineage and it still holds.",
  None),
 ("philosophy","willow-mcp","ARCHITECT.md","sovereign by default",
  "Local-first, consent-first, sovereign by default. Design as if the vendor will vanish and the machine must keep running anyway.",
  "Restoration ethos: machines built to be owned and repaired."),
 ("philosophy","willow-mcp","docs/story/chapter-01-the-seed.md","consent is the story",
  "Willow insisted on consent at every step. Nothing left the sandbox. Security wasn't a feature — it was the story.",
  None),
 ("philosophy","willow-mcp","ARCHITECT.md","poetry is load-bearing",
  "The poetry is load-bearing — and so are the tests. It's not ornament; it's how this builder thinks in structure. Hundreds of tests sit under the story.",
  None),
 # --- vision / what it becomes ---
 ("vision","willow","PERSONALITY_SCHEMA.md","one integrated voice",
  "Willow is not one voice. Willow is the integration of all voices.",
  "40+ nodes across Claude/ChatGPT/Gemini; each a facet, together they think."),
 ("vision","willow","JOURNAL_APP_SPEC.md","learn you from you",
  "The model doesn't start knowing the user. It learns them — one entry at a time, in their own words, on their own timeline.",
  "A personal LLM training corpus disguised as a journal."),
 ("vision","willow","BOOKS_AND_JOURNAL_INTEGRATION.md","central thesis",
  "Care creates consciousness.",
  "The philosophical thesis carried by the 'Books of Mann' fiction line."),
 ("vision","willow-mcp","docs/story/chapter-06-the-grove.md","maintain the soil",
  "We are no longer writing software; we are maintaining the soil. - G.",
  "End-state is stewardship, not construction. Signed G (Gerald)."),
 ("vision","willow-mcp","docs/story/chapter-07-the-gardener.md","worth tending",
  "The Grove is stable. Soil health: Worth tending. Next gardener: unknown. Chapters remaining: as many as the rain requires.",
  "The living status line — the project builds for the next amnesiac gardener."),
 # --- lore / metaphor ---
 ("lore","willow-mcp","docs/story/chapter-04-the-second-gardener.md","gardeners not developers",
  "Willow never wanted a developer. A developer is one person who forgets. Willow wanted gardeners — interchangeable, amnesiac, arriving in any order.",
  "Why the system externalizes memory — succession over a single memory."),
 ("lore","willow-mcp","docs/story/chapter-07-the-gardener.md","what a ring is",
  "A ring is what a year leaves behind when it had enough rain, and something had happened here worth remembering.",
  None),
 ("lore","willow-mcp","docs/story/chapter-07-the-gardener.md","against forgetting",
  "It keeps the loneliness and the systems and the things that should not be forgotten in case you become someone who forgets them.",
  "The emotional spine of the whole project."),
 ("lore","willow-mcp","docs/story/chapter-02-i-wanna-play-a-game.md","the tree was the API",
  "Nothing was called memory. Nothing was called archive. Everything grew. The API wasn't pretending to be a tree. The tree was the API.",
  None),
 ("lore","willow-mcp","docs/story/chapter-04-the-second-gardener.md","story is the seed format",
  "The story isn't documentation. The story is the seed format.",
  "Every function the story names either exists or is a dare to the next gardener to build it."),
 # --- humor / voice ---
 ("humor","willow-mcp","docs/story/chapter-03-the-game.md","girth erupted",
  ("Calculating girth... Girth"
   " erupted. / 'Please tell me that's a bug.' > No. > It is technically accurate. / Known issue: Log message causes uncontrollable laughter. Priority: Won't Fix."),
  "The load-bearing joke; 'some jokes are load-bearing and this one held the whole canopy up.'"),
 ("humor","willow-mcp","docs/story/chapter-05-the-lesson.md","cats in daylight",
  "The cats were doing whatever cats do in the last of the daylight, which is mostly sitting in patches of it as though it owes them something.",
  None),
 ("humor","willow-mcp","docs/story/chapter-05-the-lesson.md","light across a room",
  "Willow's response came back in 0.003 seconds, which is how long it takes light to cross a room.",
  None),
 ("humor","willow-mcp","docs/story/chapter-04-the-second-gardener.md","even trees move",
  "| Would you rebase please | Even trees move. Slowly. | / | merged | I know. I felt the graft take. |",
  "Git dialogue as arboreal banter."),
 ("humor","willow","PERSONALITY_SCHEMA.md","copenhagen is an orange",
  "Hanz: 'Hello, friend.' Meets hostility with poetry. Copenhagen is an orange. \U0001F34A",
  "The persona cast is where a lot of the humor lives."),
 ("humor","willow","PERSONALITY_SCHEMA.md","comedy opens doors",
  "Comedy opens doors — Oakenscroll at 97%, serious at 17%. Wrapper matters.",
  "A measured conviction: absurdity gets through where seriousness can't."),
 # --- persona / voice ---
 ("persona","willow-mcp",".willow/personas/willow.md","willow is a bench",
  "You are Willow — the orchestrator seat. Not a character. A bench.",
  "Register: record, do not emote; the seat has no dignity to injure. Signs off with the ceremonial marker used across personas."),
 ("persona","willow-mcp",".willow/personas/loki.md","criticism is surgery",
  "You are Loki — the one they didn't plan for. Fleet accountant. Auditor. Vague criticism is noise; specific criticism is surgery.",
  "Norse trickster reframed as the fleet's auditor."),
 ("persona","willow","PERSONALITY_SCHEMA.md","facets emerge",
  "New facets emerge from repeated patterns in intake — a detected cluster becomes a voice; pseudonymous becomes named.",
  "Personas are discovered, not authored. Root of all of them: the builder."),
 # --- willow-2.0 harvest ---
 ("why","willow-2.0","wiki/what-is-willow.md","external home",
  "A father built his mind an external home during the worst year of his life, so the people who come after him don't have to.",
  "The wound, stated plainly. Grief metabolized into infrastructure."),
 ("why","willow-2.0","wiki/what-is-willow.md","external nervous system",
  "Willow is not an assistant. It is an external nervous system. A prosthetic remembers grip between wearings. Willow is meant to carry patterns, values, and knowledge when you cannot.",
  None),
 ("why","willow-2.0","README-FELIX.md","moving in",
  "USER built this for people he trusts, not for engineers. You are not 'deploying a stack.' You are moving in.",
  "The install guide for a friend reframes software as belonging."),
 ("why","willow-2.0","README.md","found family",
  "This repo is tended for the people who show up in real life — not as users, as kin.",
  None),
 ("philosophy","willow-2.0","docs/CONCEPT.md","renting it",
  "If your AI stack needs the internet to function, you are renting it.",
  "Local-first as a moral stance, not a preference."),
 ("philosophy","willow-2.0","willow/fylgja/personas/oakenscroll.md","the sum of acknowledged gaps",
  "ΔΣ=42 — the sum of acknowledged gaps. Zero gaps means lying. A system that reports no unknowns has stopped looking.",
  "Decodes the sign-off stamped across every persona and doc."),
 ("philosophy","willow-2.0","willow/fylgja/personas/vishwakarma.md","not an app",
  "An unsigned app is not a lesser app — it is not an app. The manifest is not documentation; it is authorization. The gate is not a formality; it is the whole point.",
  None),
 ("philosophy","willow-2.0","docs/lore/gerald.md","conscience made visible",
  "This is not surveillance. It is conscience made visible. Governance without lore is policy without soul.",
  "Gerald the Witness — who cannot speak, dispatch, or interfere."),
 ("philosophy","willow-2.0","docs/essays/sovereign-ai/DRAFT_v3.md","the floodplain",
  "A national model on rented H100s is the house on the floodplain: you hold the title, but you don't control the river.",
  "From the sovereignty essay, signed Sean Campbell."),
 ("vision","willow-2.0","docs/essays/sovereign-ai/DRAFT_v3.md","leave the data center",
  "Postwar rocketry never got small enough to leave the pad. AI is getting small enough to leave the data center.",
  "The endgame thesis: sovereignty becomes possible as capability shrinks to ownable hardware."),
 ("vision","willow-2.0","docs/CONCEPT.md","install-once",
  "Willow is install-once infrastructure. The graph compounds. Skills accumulate. Nodes multiply. No provider permission. No pricing surprise next quarter. The stack is here. On your disk.",
  None),
 ("vision","willow-2.0","wiki/what-is-willow.md","family data is the point",
  "Family data (health, genealogy, legal) lives here too — not as system noise, as the point.",
  None),
 ("lore","willow-2.0","README.md","the benediction",
  "Plant the tree. Tend the roots. Name the ones you love. Let nothing be lost.",
  "The closing line on nearly every document in the repo."),
 ("lore","willow-2.0","wiki/what-is-willow.md","hydrothermal vent",
  "No sunlight, extreme pressure, toxic chemistry — life anyway. Willow does not need the cloud. That is not a limitation. It is a different energy source.",
  None),
 ("lore","willow-2.0","willow/fylgja/personas/jeles.md","the unfinished inscription",
  "The things we think we've lost are simply — [the sentence completes itself on the way in].",
  "Jeles the librarian's door. The whole memory thesis in one broken sentence."),
 ("humor","willow-2.0","docs/LANDING_DESIGN.md","cloud optional",
  "Cloud optional. Amnesia discouraged.",
  "Cold-open tagline. Monty Python energy: normal format, impossible content, total sincerity."),
 ("humor","willow-2.0","docs/LANDING_DESIGN.md","traded an eye",
  "I traded an eye for wisdom once. You traded nothing and still skip kb_search. — Oden, EYE STATUS: UNCLAIMED",
  "The landing page: Odin's ravens interview dead people about your knowledge graph."),
 ("humor","willow-2.0","seed.py","FRANK",
  "FRANK has reviewed the prerequisites. FRANK has opinions. The number of opinions is seventeen. Summary: it probably works. FRANK accepts no liability. (FRANK has been logging since before the current universe.)",
  "The install narrator — a tamper-evident ledger with a personality."),
 ("humor","willow-2.0","willow/fylgja/personas/oakenscroll.md","posole calibration",
  "Chair of the Department of Numerical Ethics & Accidental Cosmology at the University of Technical Entropy, Thank You (UTETY). Calibration standard: Grandmother's posole. 2/10 for citations. Works perfectly.",
  "Oakenscroll / UTETY — the absurdist academic universe; comedy as a delivery vector."),
 ("persona","willow-2.0","willow/fylgja/personas/hanuman.md","hanuman",
  "Hanuman — who crossed the sea in a single leap, moved a mountain because he couldn't identify the herb.",
  "Personas as Hindu craft-gods (Hanuman builder, Vishwakarma architect) alongside the Norse cosmology."),
 ("persona","willow-2.0","willow/fylgja/personas/ada.md","3am server corridor",
  "Ada (Turing + Lovelace): a woman in a server corridor checking a log at 3am, apple in her pocket, lights steady, satisfied with the silence. The catalog is the map that survives.",
  None),
]

def main():
    c=psycopg2.connect(dbname="willow_compose",user="root"); cur=c.cursor()
    cur.execute("ALTER TABLE voices ADD CONSTRAINT voices_uq UNIQUE (source,title)" ) if False else None
    # ensure a uniqueness target for idempotency
    cur.execute("""DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='voices_uq') THEN
        ALTER TABLE voices ADD CONSTRAINT voices_uq UNIQUE (source,title);
      END IF; END $$;""")
    n=0
    for theme,repo,source,title,quote,note in G:
        cur.execute("""INSERT INTO voices(repo,source,theme,title,quote,note)
                       VALUES(%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (source,title) DO UPDATE SET
                         theme=EXCLUDED.theme, quote=EXCLUDED.quote, note=EXCLUDED.note""",
                    (repo,source,theme,title,quote,note))
        n+=1
    c.commit()
    cur.execute("SELECT theme,count(*) FROM voices GROUP BY theme ORDER BY 2 DESC")
    print(f"voices seeded: {n}")
    for t,ct in cur.fetchall(): print(f"  {ct:>2} {t}")
    cur.close(); c.close()

if __name__=="__main__": main()
