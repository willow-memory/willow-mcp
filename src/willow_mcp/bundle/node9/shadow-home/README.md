# node9 shadow-home

Deliberately empty. The shadow shim (`../shadow-eval.mjs`) always runs with
`HOME` pointed at a copy of this directory (installed read-only under
`$WILLOW_HOME/venvs/node9/shadow-home/`), never the operator's real `$HOME`.

Because this directory holds no `.node9/` at all, `node9`'s own config
waterfall falls back to tier 1 — its built-in defaults — for every run. That
is "node9 defaults and the default shields only" (sealed `a6d054b3`): the
AST-level checks the proposal calls out (project-jail's sensitive-file/rm-rf
detectors, the pipe-chain detector, the chmod-777 detector) run
unconditionally inside `evaluatePolicy`'s "Layer-1" — they are not gated by
`~/.node9/shields.json`'s `active` list — so an empty HOME already carries
them. Verified by reading `packages/policy-engine/src/policy/index.ts`
around the "Layer-1 invariant" comment in node9-proxy's own source.

Do not add a `config.toml` or `shields.json` here without re-checking that
comment: the moment either optional-shield behavior is added to node9 and
made shields.json-gated, this directory needs an explicit `active` list to
keep pulling those shields in.
