# Contributing

Thanks for your interest in willow-mcp. This is a small, focused MCP server;
contributions that keep it agent-neutral and fail-closed are welcome.

## Development setup

```bash
git clone https://github.com/willow-memory/willow-mcp
cd willow-mcp
python3 -m venv .venv
.venv/bin/python3 -m pip install -e . pytest
```

Requires Python 3.11+. The repo-local venv matters for MCP clients: the stdio
server is launched as `.venv/bin/python3 -m willow_mcp`, and a missing import in
a bare host interpreter crashes the server before the MCP handshake.

## Running tests

```bash
.venv/bin/python3 -m pytest tests/ -q
```

Some tests exercise the Postgres knowledge base and expect a reachable server.
CI runs them against a `postgres:15` service with these env vars — set the same
locally if your Postgres needs them:

```bash
PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=postgres \
  .venv/bin/python3 -m pytest tests/ -q
```

The full suite must be green before a change can merge (see below).

CI (`.github/workflows/tests.yml`) also runs daily on a schedule, not just on
push/PR — this repo can go quiet for a while between changes, and a schedule
catches drift (a Postgres/Python point release, a transitive dependency bump)
that no code change would otherwise surface. The same job also runs a CLI
smoke test that exercises the actual `willow-mcp` console-script end to end
(`gates`, `tree`, `allow-permission`/`deny-permission`, `grant-net`/
`revoke-net`/`net-status`) rather than just the underlying functions the unit
tests already cover, so a broken packaging or argparse wiring fails there
even if every unit test still passes. A second smoke-test step starts
`willow-mcp gates --serve` and hits its real HTTP API (`GET /`, `POST
/api/action`) the same way the live dashboard's own JS does, confirming a
button-click-equivalent actually flips the manifest on disk.

## Branching and pull requests

`master` is protected by a **no-bypass ruleset**: all changes land through a
pull request with a green `test` check. Direct pushes to `master` are rejected.

1. Branch off the latest `master` (`git checkout -b my-change origin/master`).
2. Make the change **and its tests in the same PR** — new behavior ships with
   coverage; "no prior test" is not a reason to skip one.
3. Open a PR against `master`; wait for the `test` check to pass.
4. Merges use `--merge` (merge commit), not squash — the history is kept linear
   by first-parent, and each PR stays a reviewable unit.

## Code layout

| Path | What it is |
|------|------------|
| `src/willow_mcp/server.py` | Tool definitions, the guard pipeline, and `main()` |
| `src/willow_mcp/gate.py` | Manifest-based ACL — permission groups, fail-closed checks |
| `src/willow_mcp/oauth.py` | Serve-mode OAuth 2.0 + PKCE provider (Google/Apple) |
| `src/willow_mcp/identity_binding.py` | `(issuer, subject) → app_id` bindings, `email_basis`, drift |
| `src/willow_mcp/vault.py` | Local encrypted credential vault |
| `src/willow_mcp/schema_profile.py` | Host-DB schema adaptation and confirm gate |
| `src/willow_mcp/db.py` | Postgres access |
| `hooks/`, `skills/` | Claude Code plugin surface (see `.claude-plugin/plugin.json`) |
| `docs/design/` | Design docs — schema adaptation, hooks-and-skills |

## Conventions

- **Fail closed.** A missing manifest, an unconfirmed binding, or an unconfirmed
  schema mapping denies the operation. Preserve that posture.
- Keep the tool surface agent-neutral — no personal, fleet-, or host-specific
  references in the public code or docs.
- New tools that carry a footgun should ship their hook and/or skill in the same
  change, not as a later add-on.
- **Do not edit `CHANGELOG.md` by hand.** release-please regenerates it from the
  commits on `master`, and there is deliberately no `[Unreleased]` section to
  add to — the open `chore: release X.Y.Z` pull request *is* the unreleased
  section. A hand-added entry is a second copy that drifts, and
  `tests/test_changelog_dedup.py` holds the generated shape in place. Say what
  changed in the commit subject instead; that is the input the file is built
  from. (`CHANGELOG.md`'s own header explains the exceptions, all of which are
  corrections to what release-please emitted, not additions to it.)
- `skills/` and `hooks/` are duplicated under `src/willow_mcp/bundle/` so the
  installed wheel carries them. The two copies must stay **byte-identical** —
  `tests/test_skills_sync.py` and the hook mutation check fail otherwise. Apply
  every change twice.

## Commit and PR titles decide releases

This is not cosmetic and it is the easiest way to land a red PR on an otherwise
correct change. Commit subjects are **conventional commits**, and because merges
use merge commits, GitHub writes the **PR title** into the merge commit body —
release-please parses both, and the most release-y type across either one wins.
`.github/workflows/pr-title.yml` therefore checks the title in *two* directions,
and both are blocking:

1. **A title may not cut a release its commits would not.** Open a PR titled
   `fix(ci): …` over commits that are all `ci:` and it fails — that exact
   asymmetry tagged and published willow-mcp v2.1.1 for CI-only changes.
2. **A commit may not cut a release that changes nothing installable.** If any
   commit carries a releasing type, the PR must touch `src/willow_mcp/` or
   `pyproject.toml`. `fix(ci):` over `tools/` and `.github/` cut 2.1.5, which
   shipped nothing; a PyPI version can never be reused.

The releasing types are read from `release-please-config.json`, not restated in
the workflow, so this list moves when that file does. Today:

| cuts a release | rides along (hidden) |
|---|---|
| `feat` `fix` `security` `perf` `refactor` `build` `deps` | `docs` `test` `ci` `chore`, plus the fleet-local prefixes `hooks:` `gate:` `skills:` `server:` `envelopes:` |

`!` or a `BREAKING CHANGE:` footer cuts a major on either side. When in doubt,
pick a hidden type: the change still ships, in the next release that has
something installable in it.
