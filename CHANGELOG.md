# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries through 2.1.0 were written by hand. From the next release onward this
file is maintained by release-please, which builds each entry from the
conventional-commit prefixes on `master` — so it cannot go stale between
releases the way a hand-kept changelog can.

There is deliberately no `[Unreleased]` section any more: the open
`chore: release X.Y.Z` pull request *is* the unreleased section, and it is
regenerated from the commits rather than remembered. A hand-kept one beside it
would be a second copy to drift, which is the thing this repo keeps finding.

Note what release-please will not list: `docs:`, `test:`, `ci:` and `chore:`
are hidden, along with every fleet-local prefix (`hooks:`, `gate:`, `skills:`,
`server:`, `envelopes:`) which it ignores entirely. Those commits ship inside
the next release rather than cutting one of their own — see
`release-please-config.json` for why, and for the cost.

**Generated entries are sometimes corrected by hand, and this is why.** This
repo merges with merge commits rather than squashing, and GitHub writes the PR
title into the merge commit body. release-please parses that merge commit
*alongside* the commits it merges, so one change can produce two entries — and
because it collapses same-scope entries, a real commit can be dropped in favour
of the merge commit that swallowed it. Both happened here: 2.1.2 listed the
same fix twice (once from the merge, once from the commit), and 2.1.3 listed a
merge-commit title while omitting `0073767`, a genuine fix. The version numbers
and the tags were right; only the prose was wrong. Corrections are made in a
`docs:` commit, which is hidden and cuts no release of its own.

## [2.17.0](https://github.com/willow-memory/willow-mcp/compare/v2.16.0...v2.17.0) (2026-08-26)


### Added

* **project-wiring:** compile project hook manifests ([efbad88](https://github.com/willow-memory/willow-mcp/commit/efbad88b865f9a6e43e03ab78be9ab13dff3a909))

## [2.16.0](https://github.com/willow-memory/willow-mcp/compare/v2.15.0...v2.16.0) (2026-08-26)


### Added

* **mem_ratify:** WitnessCollector + witness-supply seam on _mem_ratify_gate ([f620fe6](https://github.com/willow-memory/willow-mcp/commit/f620fe664389b2448848a9aa950e68faf5f93dc0))

## [2.15.0](https://github.com/willow-memory/willow-mcp/compare/v2.14.0...v2.15.0) (2026-08-26)


### Added

* build-status --json for machine readers ([29a5265](https://github.com/willow-memory/willow-mcp/commit/29a52657aa9a7cda492bb79d3f85d5ec9cc0134a))

## [2.14.0](https://github.com/willow-memory/willow-mcp/compare/v2.13.4...v2.14.0) (2026-08-24)


### Added

* **W-18, W-19:** wire RealtimeSTTGate and GCalSyncSource transport ([f5a3ec2](https://github.com/willow-memory/willow-mcp/commit/f5a3ec25b5dff7d2b01aa1519340ed26da230638))

## [2.13.4](https://github.com/willow-memory/willow-mcp/compare/v2.13.3...v2.13.4) (2026-08-24)


### Fixed

* **W-09/W-10/W-12:** re-vendor nest/ from upstream safe-app-store#210 ([6d55d95](https://github.com/willow-memory/willow-mcp/commit/6d55d95010ed34cee95927a6e1142df602f9c94b))

## [2.13.3](https://github.com/willow-memory/willow-mcp/compare/v2.13.2...v2.13.3) (2026-08-24)


### Fixed

* **ci:** update pinned nest/ hashes to match reverted upstream copies ([db8e2c7](https://github.com/willow-memory/willow-mcp/commit/db8e2c761d8740c3c2455a4458aae5321e07e62c))
* **ci:** revert vendored nest/ files to match upstream safe-app-store ([db040a7](https://github.com/willow-memory/willow-mcp/commit/db040a7f6ba7bddf7d00cb906a2f1863bbf984b0))
* **ci:** remove unused imports, revert vendored ratify.py ([6ef59b6](https://github.com/willow-memory/willow-mcp/commit/6ef59b637fb8816d9506156a595f397a0883af16))
* **W-15:** wire nestor optional extra — nestor-meaning is published on PyPI ([62b9b41](https://github.com/willow-memory/willow-mcp/commit/62b9b4144a8310601899d10665e928db5ef9a4ef))

## [2.13.2](https://github.com/willow-memory/willow-mcp/compare/v2.13.1...v2.13.2) (2026-08-24)


### Fixed

* move logger definitions after all imports to satisfy ruff E402 ([e236400](https://github.com/willow-memory/willow-mcp/commit/e236400ebe9c35d19b18fd9544739050f41b2004))
* **W-21:** rotate pending.jsonl when it exceeds threshold ([cc877b4](https://github.com/willow-memory/willow-mcp/commit/cc877b4d777b82d6a2fbe59ef54cc9c5c0ecf5a6))
* **W-09:** add logger.debug to 21 silent except-Exception blocks ([cab50b5](https://github.com/willow-memory/willow-mcp/commit/cab50b53399f8265e9a506f64cdf22996fd95620))
* W-12, W-14, W-17 debt items ([7a0b42a](https://github.com/willow-memory/willow-mcp/commit/7a0b42a49c42b88b5aa1d578a35792f1e2063210))
* W-10, W-11, W-13, W-16 debt items ([359ea16](https://github.com/willow-memory/willow-mcp/commit/359ea16772b9a9dffe505fc3c1ed3d06118da078))
* B-60, B-63 bugs + W-01, W-06, W-07, W-08 gaps ([b191771](https://github.com/willow-memory/willow-mcp/commit/b191771e32de3b2d4958e15a61ed1e381ac84cbb))

## [2.13.1](https://github.com/willow-memory/willow-mcp/compare/v2.13.0...v2.13.1) (2026-08-24)


### Fixed

* update repo owner references after org transfer ([c139acc](https://github.com/willow-memory/willow-mcp/commit/c139acc708f30ec71f398f712ceb7dc00c99a9b1))
* remaining 'verified' descriptions of trusted_only (#288) ([701cc02](https://github.com/willow-memory/willow-mcp/commit/701cc027e423acedd644f4c58663a38a3955771c))
* stale docstrings and trusted_only labelling (#288) ([df0f9b0](https://github.com/willow-memory/willow-mcp/commit/df0f9b0a7dbf1162ff0768c5c41185dcc7c22074))

## [2.13.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.12.0...v2.13.0) (2026-08-19)


### Added

* **kb:** add knowledge source verification and health check tools ([44884bc](https://github.com/rudi193-cmd/willow-mcp/commit/44884bc9dc68db5b3772605e2c117dc210514d80))
* **grove:** consolidate threading with recursive CTE, upward navigation, and reply validation ([e1370d1](https://github.com/rudi193-cmd/willow-mcp/commit/e1370d10bf239ed399a22887278cca8bda0b0f3e))


### Fixed

* **ci:** add knowledge_verify/check to tier_policy, update tool counts ([4d815d8](https://github.com/rudi193-cmd/willow-mcp/commit/4d815d81f6b2e9da67c5c6d156130a62feb0c1e0))
* **lint:** remove unused pytest import in test_kb_sql ([eff82e0](https://github.com/rudi193-cmd/willow-mcp/commit/eff82e02bbd0c8bc445498b0a63cda1c79d64006))
* **grove:** address PR review — error guard on send_message, LATERAL join in get_history ([13bd32e](https://github.com/rudi193-cmd/willow-mcp/commit/13bd32e2202b5b051b9c9e3472d67797346a1437))

## [2.12.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.11.0...v2.12.0) (2026-08-19)


### Added

* add MCP Resource support for KB atoms and Store records ([82d89cb](https://github.com/rudi193-cmd/willow-mcp/commit/82d89cb324c34fde34c82af10961018889062068))


### Fixed

* _guarded error shape for paginated tools + lint ([9848e7b](https://github.com/rudi193-cmd/willow-mcp/commit/9848e7bc26129c600432f970691c2bcd38bd81d3))
* correct readOnlyHint annotations for 4 tools that modify state ([33dcfe2](https://github.com/rudi193-cmd/willow-mcp/commit/33dcfe29a74073649a9059507687ab4dc8f3afe0))

## [2.11.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.10.0...v2.11.0) (2026-08-19)


### Added

* add MCP tool annotations to all 142 tools ([3592b06](https://github.com/rudi193-cmd/willow-mcp/commit/3592b06c679fa406e41675cc99b2e8bc1f60578b))


### Fixed

* update authority-surface test regex for annotated @mcp.tool decorators ([1c8ab98](https://github.com/rudi193-cmd/willow-mcp/commit/1c8ab98249aec0de0a1b2e53213932aa494eda0c))
* address review — shared annotations module, readOnlyHint on writes, session_enter reclassified ([0561e0f](https://github.com/rudi193-cmd/willow-mcp/commit/0561e0fb6194f19d77c0434d2a03478b35924795))

## [2.10.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.9.2...v2.10.0) (2026-08-18)


### Added

* **grove:** add 20 Grove MCP tools — the agent-side successor to willow-2.0's sap/grove_tools.py ([e1a4b74](https://github.com/rudi193-cmd/willow-mcp/commit/e1a4b74695e04c036d8816427ba0df9b4c0f8f38))


### Fixed

* **grove:** sender lock via grove_relay capability; scope grove_write to the ratified matrix ([b41e6eb](https://github.com/rudi193-cmd/willow-mcp/commit/b41e6ebc93b7cc8f4aaaa6ab4b5e0025d68ed789))

## [2.9.2](https://github.com/rudi193-cmd/willow-mcp/compare/v2.9.1...v2.9.2) (2026-08-11)


### Fixed

* **build:** drop the git-pinned nestor extra so PyPI accepts the upload ([e0112c3](https://github.com/rudi193-cmd/willow-mcp/commit/e0112c35c6d66900956f95df2e821ea1a7b4d51a))

## [2.9.1](https://github.com/rudi193-cmd/willow-mcp/compare/v2.9.0...v2.9.1) (2026-08-11)


### Fixed

* **#333:** dispatch_send cites its own envelope before acting ([020d8a7](https://github.com/rudi193-cmd/willow-mcp/commit/020d8a7cc5ac9c596c61d09e0f68b4b65de994af))
* **security:** triage bandit B310/B108 findings, drop bandit || true (#318) ([3e209d3](https://github.com/rudi193-cmd/willow-mcp/commit/3e209d310f2d0fe0537c5dd230a2110a0552082b))


### Security

* **dispatch:** HMAC-sign packet meta.json to close filesystem injection (B-52, #241) ([a65c73b](https://github.com/rudi193-cmd/willow-mcp/commit/a65c73b2963a2f9c0165c31e4eeb25fee61f86f7))

## [2.9.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.8.0...v2.9.0) (2026-08-11)


### Added

* **tool-oracle:** seal the remaining 7 verbs — full 112/112 catalog coverage ([66b0d09](https://github.com/rudi193-cmd/willow-mcp/commit/66b0d09a7ae448d2cdc8ac0144e2e665a08130d9))

## [2.8.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.7.1...v2.8.0) (2026-08-11)


### Added

* **tool-oracle:** Nestor-backed natural-language tool router ([0aadeb3](https://github.com/rudi193-cmd/willow-mcp/commit/0aadeb34f3eb6f4765e8e933a1eff35a713ba8df))


### Build

* allow direct references so the [nestor] git extra resolves ([e6c691c](https://github.com/rudi193-cmd/willow-mcp/commit/e6c691c6e4589adfdc609dba36cbb69a947961d3))

## [2.7.1](https://github.com/rudi193-cmd/willow-mcp/compare/v2.7.0...v2.7.1) (2026-08-11)


### Fixed

* **diagnostic:** restore diagnostic_summary's @mcp.tool() decorator (fleet-seams) ([47d1ddb](https://github.com/rudi193-cmd/willow-mcp/commit/47d1ddb4ec8497d97a644c850bb63943a5402eef))
* **governance:** make the empty-registry guard proactive and close its coverage gap (#332) ([2beda9a](https://github.com/rudi193-cmd/willow-mcp/commit/2beda9a47cd9737f072466064b501a7732b8c7f3))
* **governance:** refuse an empty registry loudly as ENOGRANTS (#332 runtime guard) ([39b5c39](https://github.com/rudi193-cmd/willow-mcp/commit/39b5c39337ae61e600f03c73cadd93bfa8d45f5c))
* **governance:** correct verb 13's declared registry_path to the enforced file (#332a) ([822c7e1](https://github.com/rudi193-cmd/willow-mcp/commit/822c7e1e1b261e3f880a618c87de029ca345362f))

## [2.7.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.6.0...v2.7.0) (2026-08-10)


### Added

* port the repo hygiene sweep from the decommissioned fleet ([993c4fb](https://github.com/rudi193-cmd/willow-mcp/commit/993c4fb016ff4555dbbe0241a96105a3f822e993))

## [2.6.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.5.0...v2.6.0) (2026-08-10)


### Added

* federate to a remote peer over streamable HTTP ([7706e75](https://github.com/rudi193-cmd/willow-mcp/commit/7706e75c19d5b7f10a52539f4a4d356da00cb3e4))

## [2.5.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.4.4...v2.5.0) (2026-08-10)


### Added

* the federated client signs its outbound calls ([87ce8b2](https://github.com/rudi193-cmd/willow-mcp/commit/87ce8b202e1bf3f174224f009e089713d8fac57b))

## [2.4.4](https://github.com/rudi193-cmd/willow-mcp/compare/v2.4.3...v2.4.4) (2026-08-10)


### Fixed

* stop the seed overlay clobbering local registry entries ([3846cca](https://github.com/rudi193-cmd/willow-mcp/commit/3846ccace7f32adbd59ac420e6f8e914ef633cc4))

## [2.4.3](https://github.com/rudi193-cmd/willow-mcp/compare/v2.4.2...v2.4.3) (2026-08-10)


### Fixed

* resolve the interpreter to a venv, and stop shipping one operator's layout ([94738e3](https://github.com/rudi193-cmd/willow-mcp/commit/94738e3d153b1542425bfc9ca230c97489bd3a64))

## [2.4.2](https://github.com/rudi193-cmd/willow-mcp/compare/v2.4.1...v2.4.2) (2026-08-10)


### Fixed

* **pgp:** require live session file; roll back failed attest-session ([f594566](https://github.com/rudi193-cmd/willow-mcp/commit/f5945660e4fa1ccf0bb3618d896a473c7013c74a))
* **pgp:** attest-session signs stable identity, not mutable session record (#313) ([ad18966](https://github.com/rudi193-cmd/willow-mcp/commit/ad18966467a8466d7db2647c28c08beabb964f95))


### Changed

* **pgp:** use restore_signed_content for attest-session rollback ([8437a73](https://github.com/rudi193-cmd/willow-mcp/commit/8437a73a960a244daa76a1c0d0d5af097d24865f))

## [2.4.1](https://github.com/rudi193-cmd/willow-mcp/compare/v2.4.0...v2.4.1) (2026-08-10)


### Fixed

* **pgp:** restore content and .sig together on sign-failure rollback ([fb3742b](https://github.com/rudi193-cmd/willow-mcp/commit/fb3742bd7abc6bbd495aa9133b84967452802df3))
* refuse boot when manifest verify sweep finds BAD-SIG rows ([c046160](https://github.com/rudi193-cmd/willow-mcp/commit/c046160219d7afd470ecff90d89283c2de65af98))
* re-sign manifests after compile_manifests writes them (#312) ([ed0275a](https://github.com/rudi193-cmd/willow-mcp/commit/ed0275aadbae7a9acd67088d4f926f628100a133))

## [2.4.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.3.0...v2.4.0) (2026-08-07)


### Added

* **fleet:** stand up willow-mcp, jeles and nestor as one wired fleet ([a23d694](https://github.com/rudi193-cmd/willow-mcp/commit/a23d694047efa2b1487563ac12cda8e22cfae2df))

## [2.3.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.2.5...v2.3.0) (2026-08-06)


### Added

* **decommission:** native SessionStart/End — stack snapshot, boot context ([7c0308d](https://github.com/rudi193-cmd/willow-mcp/commit/7c0308d3f71b70d23a9d945e208c928946ebee7b))


### Fixed

* **stack_snapshot:** scope the pending-task query to the app that submitted ([c0b9c49](https://github.com/rudi193-cmd/willow-mcp/commit/c0b9c49372dced7cf8189f4701be6eb930dcfce0))

## [2.2.5](https://github.com/rudi193-cmd/willow-mcp/compare/v2.2.4...v2.2.5) (2026-08-06)


### Build

* **deps:** bump actions/checkout from 4 to 7 ([3a54a62](https://github.com/rudi193-cmd/willow-mcp/commit/3a54a62acb084de5eb33be2b4f3bb5ce5337a6ec))
* **deps:** bump googleapis/release-please-action from 4 to 5 ([ab78ff9](https://github.com/rudi193-cmd/willow-mcp/commit/ab78ff94fc4c02e4d5481427ffc31fe90922b0fa))

## [2.2.4](https://github.com/rudi193-cmd/willow-mcp/compare/v2.2.3...v2.2.4) (2026-08-06)


### Fixed

* **manifest_admin:** keep allow-permission idempotent under PGP enforcement ([92f5ff2](https://github.com/rudi193-cmd/willow-mcp/commit/92f5ff20cc1f3e3afdd1450f06ff5ac1eb851e09))
* **gate:** name why a manifest was refused, and re-sign after editing one ([35d7285](https://github.com/rudi193-cmd/willow-mcp/commit/35d7285858996c858de98e76e25bc50f882fa2eb))


### Build

* **deps:** bump actions/checkout from 4 to 7 ([3a54a62](https://github.com/rudi193-cmd/willow-mcp/commit/3a54a62acb084de5eb33be2b4f3bb5ce5337a6ec))
* **deps:** update cryptography requirement ([15eaa45](https://github.com/rudi193-cmd/willow-mcp/commit/15eaa45ee59fe20542dc8355627ea01d7faa5c97))
* **deps:** bump googleapis/release-please-action from 4 to 5 ([ab78ff9](https://github.com/rudi193-cmd/willow-mcp/commit/ab78ff94fc4c02e4d5481427ffc31fe90922b0fa))

## [2.2.3](https://github.com/rudi193-cmd/willow-mcp/compare/v2.2.2...v2.2.3) (2026-08-04)


### Fixed

* **egress:** two more unguarded paths on the same permission line, and a cap that capped nothing ([934cd60](https://github.com/rudi193-cmd/willow-mcp/commit/934cd606bbda575a9de1f9d2b378b9065c67853e))


### Changed

* **worker:** drop the kartikeya fallback the 0.0.9 floor made dead ([0f9f492](https://github.com/rudi193-cmd/willow-mcp/commit/0f9f492804308dffd7184c28ab6ea3eef91fbe04))

## [2.2.2](https://github.com/rudi193-cmd/willow-mcp/compare/v2.2.1...v2.2.2) (2026-08-04)


### Build

* **deps:** raise the jeles floor to 0.5.1, where its egress guard is fixed ([041614c](https://github.com/rudi193-cmd/willow-mcp/commit/041614c1d5a15269ffb9c70bc395831d65b3d63a))

## [2.2.1](https://github.com/rudi193-cmd/willow-mcp/compare/v2.2.0...v2.2.1) (2026-08-04)


### Fixed

* **web_fetch:** the SSRF guard checked one URL, one way, and resolved nothing ([f6d39a3](https://github.com/rudi193-cmd/willow-mcp/commit/f6d39a3cccec397ef01b6809b04835ab91e3991d))

## [2.2.0](https://github.com/rudi193-cmd/willow-mcp/compare/v2.1.5...v2.2.0) (2026-08-04)


### Added

* **server:** add willow_institutional_search, trust from what was queried ([9aacb1f](https://github.com/rudi193-cmd/willow-mcp/commit/9aacb1f9104a58bb2e2fb90508e437dac9ca7626))

## [2.1.5](https://github.com/rudi193-cmd/willow-mcp/compare/v2.1.4...v2.1.5) (2026-08-04)


### Fixed

* **ci:** rebuild the changelog section from the commits before releasing ([c6412e0](https://github.com/rudi193-cmd/willow-mcp/commit/c6412e083a325893c3f10b8a7c17911cb8ee0562))

## [2.1.4](https://github.com/rudi193-cmd/willow-mcp/compare/v2.1.3...v2.1.4) (2026-08-04)


### Fixed

* **web_search:** make the trusted-domain list answerable to jeles' registry ([4f3b6de](https://github.com/rudi193-cmd/willow-mcp/commit/4f3b6ded99e52ec7abe6f8b814c8c5ab8628f5fc))

## [2.1.3](https://github.com/rudi193-cmd/willow-mcp/compare/v2.1.2...v2.1.3) (2026-08-04)


### Fixed

* **web_search:** stop attributing a result's snippet to the wrong URL ([d0bd516](https://github.com/rudi193-cmd/willow-mcp/commit/d0bd516bd0a1f57f473b12c88054984ccce18eed))
* **web_search:** admit one probe in HALF_OPEN, not the whole backlog ([0073767](https://github.com/rudi193-cmd/willow-mcp/commit/00737672a79b3d422afff80fabce7e38531f18b9))

## [2.1.2](https://github.com/rudi193-cmd/willow-mcp/compare/v2.1.1...v2.1.2) (2026-08-03)


### Fixed

* **web_search:** stop a lookalike domain inheriting institutional trust ([49b95fe](https://github.com/rudi193-cmd/willow-mcp/commit/49b95fe20b5d764c62e7db85b80e427dbcd0a677))

## [2.1.1](https://github.com/rudi193-cmd/willow-mcp/compare/v2.1.0...v2.1.1) (2026-08-03)


### Fixed

* **ci:** pin the release tag format, and check it instead of trusting it ([c8e700c](https://github.com/rudi193-cmd/willow-mcp/commit/c8e700c27828b2e6642370e4ce5660b10c00bab1))

## [2.1.0] — 2026-08-02

The web-sandbox season: make a cold Claude Code container boot the full stack
unattended, close the #161 mai security hole, and consolidate every open
branch (PRs #172, #173, plus follow-up commits on `claude/sandbox-setup-cmayov`).

Then the enforcement season on top of it: PGP-backed attestation and manifest
signing, the bound-receipt contract behind the kill-chain suites, fail-closed
remote enforcement, and the port onto MCP Python SDK 2.0.

251 commits since `v2.0.1`. Additive throughout — 134 tools, up from 130, with
nothing removed or renamed.

### Security
- **`Store.put` no longer resurrects soft-deleted records.** `put` used
  `INSERT OR REPLACE`, which in SQLite DELETEs the existing row and INSERTs a
  new one — so the columns omitted from the statement took their schema
  defaults, and `deleted` defaults to `0`. Re-putting a known id **undeleted the
  row and stamped a fresh `created_at`**. `store_delete` was therefore not
  durable, and a purged row could be replaced under the same id with different
  content and a forged creation time, using only `store_write`.

  `put` is now an `ON CONFLICT DO UPDATE` upsert that leaves `created_at` and
  `deleted` off the update list, so an existing row keeps both. A re-put of a
  soft-deleted id updates the data but leaves the row tombstoned and its
  creation time intact, so it stays invisible to every reader (`get` / `all` /
  `search` / `update` / `stats` all filter `deleted = 0`). `purge_collection` is
  explicitly "archive, not drop" — `put` was the one writer that did not respect
  that.

  The write is **not** refused, though landing invisibly is unsatisfying:
  `store_purge_collection` is in the `store_write` group and nothing in `db.py`
  ever sets `deleted` back to `0`, so refusing would let any app holding
  `store_write` tombstone a collection and permanently brick every stable-id
  writer against it — `context_save`, `human_loop.resolve`, `gaps`, `forks`,
  `lineage`, `seed_mirror` — with no recovery path in code. That would trade a
  forgery for an agent-reachable denial of service, and the forgery is already
  closed by the column list alone. A test pins the non-refusal so it cannot be
  reintroduced without the tombstone first gaining an operator-only exit.

  The `created_at` half was also a live data bug well beyond the security case:
  `put(record_id=...)` is the update idiom in `human_loop`, `lineage`, `gaps`,
  `forks`, `friction`, `seed_mirror` and `context_save`, all of which were
  having creation timestamps rewritten on every ordinary write.
- **The seat-escalation hook's denylist covers every write-capable permission
  group again.** `bundle/hooks/pre_tool_use.py` blocks a manifest edit that
  re-grants write authority the SessionStart bootstrap stripped — but its
  literal token list named **10 of the 42** groups in `gate.PERMISSION_GROUPS`,
  so `dispatch_write`, `human_loop_write`, `frank_write`, `envelope_apply`,
  `orchestrator` (which expands to seven writes), `markdownai_directives` (what
  `gate.py:241-249` calls "the dangerous half") and ten more were self-grantable
  with the guardrail silent. Two of the four egress capabilities were also
  unmatched: `integration_net` and `web_net` authorize egress from the *server*
  process, the more privileged lane by the repo's own reasoning
  (`gate.py:332-337`), and only `task_net` was checked.

  All 26 write-capable groups and all 4 capabilities are now matched; the 16
  read-only groups are explicitly left alone. `orchestrator`, `context` and
  `binding` match only as quoted permission tokens — they are ordinary English
  words and a bare-word match would fire on manifest prose.

  The hook is stdlib-only by design (it runs in the agent's harness, where
  `willow_mcp` may not import), so the list stays literal and is pinned from the
  other side: `test_seat_guard_classification_covers_every_permission_group`
  reads `gate.PERMISSION_GROUPS` and fails when a group appears in neither
  column, so a new group forces the read-or-write call instead of defaulting to
  unmatched. A companion test pins the bundled and repo copies of the hook
  byte-identical — a fix applied to one and not the other is a guardrail that
  passes CI and is absent in production.
- **`by_human` on an attestation is no longer forgeable by naming yourself
  `willow`.** `human_attestation_create` computed `by_human` as
  `is_orchestrator_app(app_id)` — a lowercase string compare against a
  caller-supplied tool-call argument — so any stdio caller passing
  `app_id="willow"` wrote a record satisfying
  `has_attestation(subject_id, require_human=True)`, the gate that means "the
  operator personally signed this". The env-var check
  `human_orchestrator_attested()` was consulted only by
  `orchestrator_write_denial`, which fires only for `ORCHESTRATOR_WRITE_TOOLS`,
  and `human_attestation_create` is not in that set. The flag now comes from
  `human_session.by_human_attested()`, which reads a signal the caller cannot
  set: `WILLOW_HUMAN_ORCHESTRATOR` on the server process (stdio) or the
  confirmed OAuth identity binding (serve). It downgrades rather than denies —
  an unattested willow seat still writes its attestation, with `by_human` False.

  The test was the more consequential half of the defect:
  `test_human_seat_attestation_is_marked_by_human` set
  `WILLOW_HUMAN_ORCHESTRATOR=1` before asserting `by_human is True` and passed
  identically without it, so a green suite asserted an invariant that did not
  exist. Seven tests replace it, three of which fail against the old code, plus
  a mutation guard that pins the *difference* between the attested and
  unattested calls so the env var cannot silently stop being load-bearing again.
- **#161: the mai directive surface is gated.** The ten mai tools registered
  on FastMCP with no app_id anywhere — `@db` ran arbitrary SQL on the willow
  Postgres, `@http` was an open SSRF, `@env` exfiltrated any env var, and
  internal `parser.render()` calls executed all of it ungated. Three new
  permission groups (`markdownai_read` / `markdownai_write` /
  `markdownai_directives`, none in `full_access`); `app_id` threaded through
  every tool and `render()`; ungated renders yield refusal text; `@db` needs a
  manifest-allowlisted `"mai_connections"` name (denials stay loud past
  `on-error`); `@http` honors `consent.internet` + an SSRF host blocklist;
  `@env` is default-deny behind `WILLOW_MAI_ENV_ALLOW` with credential-shaped
  keys never resolving. 18 abuse tests. Also fixes a latent parser bug: the
  old `@env` regex never fed `key=`/`fallback=` to `parse_attrs`, so every
  keyed `@env` silently rendered `""`.
- **B-44/#182: the egress private key was readable by the agent's own uid.**
  `chmod 600` protects nothing on a single-uid host — the agent shares the
  euid that owns the key, so it could read it directly and sign with the real
  authority, collapsing the three-key egress gate to the two it could already
  write. `harden-trust-root` never covered the key (it lives outside
  `$WILLOW_HOME` by design, so it wasn't one of the chowned trust roots), and
  the B-32/B-38 diagnostics only ever asked whether the key was *writable*,
  not *readable* — a hardened install could report `self_writable: []` while
  the key sat fully exposed. `harden-trust-root` now also chowns the egress
  directory to the trust owner at owner-only `0700`/`0600` (stricter than the
  world-readable `0755`/`0644` the manifest/lease roots use — the gate still
  needs to read its own policy, the signing key does not); `_diag_net_lease`
  and B-38's `_egress_severance` now measure read exposure and fold it into
  `self_writable`/`forgeable_keys`, breaking the severance verdict under
  strict mode exactly like a forgeable manifest does.
- **B-45/#183: app manifests were unsigned, writable JSON — a forgeable
  identity and a self-grantable capability.** Any process that could write
  `mcp_apps/<app>/manifest.json` could add itself `full_access`, or create a
  new one and become any identity outright (demonstrated: `mcp_apps/steve/
  manifest.json` → `whoami` reports `steve`, a fleet-operator-trust seat).
  `docs/design/pgp-and-persona.md`'s LOCKED (2026-07-09) P1 slice — "manifest
  `.sig` check in `gate.permitted()` when fingerprint env set" — specified
  exactly this fix and was never wired, though `pgp.py`'s sign/verify
  primitives already existed (used for seeds, never manifests). Fixed:
  `gate._load_manifest()` now verifies `manifest.json.sig` against
  `WILLOW_PGP_FINGERPRINT` whenever it's set, denying (returning the same
  `None` every caller already fail-closes on) a manifest that's unsigned,
  tampered, or signed by the wrong key — unset (the default), behavior is
  unchanged; no new `pgp_enforced` toggle, matching the locked design's
  explicit rejection of one. New `willow-mcp sign-manifest <app_id>` CLI,
  operator-terminal only. Verified against a real, disposable Ed25519 GPG
  key — not mocked — through both pytest and the actual `willow-mcp`
  console script under a real pty: sign, tamper-after-signing, forge an
  identity, reuse one manifest's signature against another, and sign with
  the wrong key are all denied.
- **B-46/#228: `repair-runtime-perms` downgraded `vault.key`/`mcp_token.json`
  to world-readable.** Found auditing existing B-32 coverage for gaps of the
  same class #182 found. Both files sit at `$WILLOW_HOME`'s top level (not
  under a scaffolded directory), so the generic runtime-children sweep gave
  them the same world-readable `0644` it gives ordinary runtime state —
  verified live: a freshly-`Vault().init()`'d `vault.key` went from its own
  `0600` default to `0644` after running the operator's own recommended
  hardening command. Fixed: these filenames get owner-only `0700`/`0600`
  instead, still owned by the runtime user (the running server legitimately
  decrypts the vault, unlike the egress key). New
  `trust_root_setup.secret_file_exposure()` folds into `audit_trust_root()`'s
  `hardened` bool; `willow-mcp doctor` gained its own warning block (the
  prior one only printed when `forgeable` was non-empty, so a secret-file-
  only exposure computed `hardened: false` but printed nothing). Also adds
  `tests/test_at_m1_kill_chain.py`, replaying the #181 kill chain's testable
  steps against current code end to end.
- **#186 (P2): orchestrator write gate now checks PGP session attestation, not
  just an env var.** `docs/design/pgp-and-persona.md`'s locked P2 slice —
  `attest_session` CLI + session file `.sig`, and the write gate checking it —
  was the last unstarted layer of the orchestrator write gate. Env-only
  (`WILLOW_HUMAN_ORCHESTRATOR=1`) proves the *host* was configured as the
  orchestrator seat, not that *this session* was ever reviewed by the
  operator. New `willow-mcp attest-session <session_id>` CLI (same
  operator-terminal/Kart guard as `sign-manifest`) detach-signs the live
  `sessions/willow-{session_id}.json` `session_enter`/`session_bind` already
  write. `human_session.orchestrator_write_denial` now also requires that
  signature to verify, once `WILLOW_PGP_FINGERPRINT` is set — layered on top
  of, not instead of, the existing env check (stdio only; serve mode keeps
  trusting the confirmed OAuth binding). `dispatch_send`, `verify_handoff`,
  `frank_append`, and `envelope_apply` don't carry a `session_id` argument at
  all, so the check can't read one from the call — `session_enter(app_id=
  'willow', ...)` now records the session it bound as server-process state,
  which `_gate` reads back for every subsequent orchestrator-write call in
  that process; no tool's public signature changed. Unset (the default),
  behavior is unchanged. Verified against a real, disposable Ed25519 GPG key
  through pytest: unattested, tampered-after-attesting, and never-entered
  sessions are all denied; a validly attested one is allowed.
- **B-53/#239: `orchestrator_human_required` was incomplete for
  `app_id=willow` — `dispatch_accept` and `handoff_write_v4` were never in
  `ORCHESTRATOR_WRITE_TOOLS`.** `session_enter` refuses a dispatch_id for
  `app_id=willow` up front, but that guard lived only in `session_enter` —
  calling either tool directly bypassed it entirely. Found by a 2026-07-31
  red-team pass against the live MCP: stdio `app_id=willow` with no
  `WILLOW_HUMAN_ORCHESTRATOR` accepted and completed a real dispatch packet.
  Fixed: both tools added to `ORCHESTRATOR_WRITE_TOOLS`; the denial message
  now names whichever tool was actually called instead of a fixed three-tool
  list, so it can't silently drift again as the set grows.
- **B-51/#240: the `dispatch_write` permission group granted `verify_handoff`
  and `agent_clear` to builder seats.** Same group as `dispatch_send`, so any
  manifest with `dispatch_write` (hanuman, loki, jeles, ada) could verify and
  clear its own dispatch with zero orchestrator/human involvement —
  self-certifying work the design always meant the orchestrator to check
  (`handoff_write_v4`'s own docstring: "the orchestrator checks both in
  verify_handoff before releasing you via agent_clear"). Same red-team pass
  demonstrated it live end to end: a builder seat forged its own send, accept,
  handoff, verify, and clear with no attestation at any step. Fixed:
  `verify_handoff`/`agent_clear` removed from the `dispatch_write` group in
  `gate.py` — reachable only via `orchestrator`, already human-attestation-
  gated; `dispatch_write` keeps the send/accept/close-out lifecycle a builder
  legitimately needs over its own work. Both B-51 and B-53 verified end to
  end through the real MCP tool wrappers in new
  `tests/test_at_m2_dispatch_lifecycle.py`, replaying the red-team scenario
  and asserting refusal at each broken step, plus unit coverage in
  `tests/test_gate.py` and
  `tests/test_human_orchestrator.py`.
- **B-54/#242: `dispatch_read`/`handoff_read` had no packet-level ACL.** Any
  app with `dispatch_read` permission could read any `dispatch_id`'s full
  content, not just packets it was `from_app`/`to_app`/`reply_to` on —
  demonstrated live against a real packet's handoff (commit SHAs, PR URLs,
  CI notes). Fixed: new `dispatch.is_dispatch_party()`, checked in
  `server.py`'s `dispatch_read`/`handoff_read` wrappers with an orchestrator
  bypass; the denial (`not_party_to_dispatch`) carries no packet content.
- **B-55/#243: pending `assignment.md` was mutable on disk** between
  `dispatch_send` and specialist/orchestrator read — same operator-writable
  `dispatch/` root as B-52, demonstrated live (append, reverted). Fixed:
  `dispatch_send` now records a sha256 of `assignment.md` in `meta.json`;
  `dispatch_read` verifies it and returns `assignment_tampered` on mismatch,
  inherited for free by `dispatch_accept`/`handoff_write_v4` since both call
  `dispatch_read` internally. Not full closure — `dispatch/` is still
  operator-writable, same residual as B-52 — but tampering is now detected
  and refused instead of silently trusted.
- **B-52/#241 (partial): filesystem dispatch packet injection under
  `dispatch/`.** A local uid could `mkdir` a fake packet directory with an
  arbitrary `meta.json` and it showed up in `dispatch_list`/`dispatch_read`
  with no relationship to `dispatch_send` at all. New
  `dispatch._meta_is_well_formed()` rejects a packet missing the
  `startup_packet_meta_v1` format marker or `dispatch_id`/`from_app`/`to_app`,
  refusing the trivial hand-forged-mkdir case at zero cost to real packets.
  Not cryptographic and not full closure — real closure needs the same uid
  separation as #231.
- **B-50/#238: `schema_maps/` writes EACCES'd once `mcp_apps/` was actually
  trust-root-hardened.** `schema_maps/<app_id>/` was documented and shipped
  under `mcp_apps/<app_id>/` (`schema-adaptation.md` §3.2 original) — a
  deliberate placement, not an oversight, that simply conflicted with
  `mcp_apps/` also being the trust-root-hardened, operator-owned directory
  B-45/#183 depends on: the runtime process legitimately writing schema maps
  can never create a subdirectory under a `0755`, operator-owned parent,
  regardless of what's excluded from any chown sweep. Fixed (operator-
  approved amendment to the LOCKED `product-layout.md`):
  `schema_maps/<app_id>/` relocated to its own top-level `$WILLOW_HOME`
  root, sibling to `store/` — never under `mcp_apps/` at all, so the
  conflict can't recur.
  Also fixed a latent test-isolation gap this surfaced: several
  `test_server.py`/`test_sandbox_confirm.py` fixtures isolated
  `WILLOW_MCP_APPS_ROOT` but never `WILLOW_HOME` — harmless while
  `schema_maps` lived under the isolated apps root, but once it moved to
  depend on `WILLOW_HOME` directly those fixtures were silently sharing
  conftest's one session-wide default, so a mapping confirmed in one test
  bled into the next test reusing the same app_id.
- **B-49/#237: reconciled, not a new gap.** `docs/design/willow-gate-seam.md`
  D3 already covers "ungated `whoami` leaks manifest when binding is off" in
  its own explicit "CLOSED" section — the accepted trusted-host stdio model,
  same posture as every other tool in this gate. Closed with a pointer to
  the existing doc section, no code change.
- **B-47/#235: two MCP desks, two trust models.** The repo's committed
  `.cursor/mcp.json` spawns `willow-mcp` with implicit `~/.willow` and no
  PGP/binding env, while an operator's separately-configured, hardened
  global Cursor desk is a different trust posture under the same product —
  easy to "test green" on the unhardened repo desk while believing the
  hardened one was verified. This config never held fleet secrets by
  design, so there was nothing to move; documented instead — README.md's
  "MCP config" section states plainly this config is dev-only, names the
  missing env vars and what each absence means.
- **B-48/#236: `dispatch_write` is not binding-gated and not human-attested.**
  Any stdio caller passing `app_id=hanuman` (or any manifest with
  `dispatch_write`) can `dispatch_send` with no per-call credential —
  demonstrated live, `dispatch_id=7BE854FD`. Traced rather than assumed:
  `_enforce_binding_gate` already applies uniformly to `dispatch_write` when
  `WILLOW_MCP_ENFORCE_BINDING=1` — it's a no-op for an unregistered app_id
  by design (fail-closed for an un-instrumented client, not a silent
  bypass). Closes today only when the operator both enables binding and
  registers every builder seat — the same two-step deployment gap as #231's
  uid separation, not a code bug. Making `dispatch_write` refuse
  unregistered app_ids unconditionally was considered and deferred: a
  breaking default-posture change for any install with unregistered
  builder agents, bigger than this one finding warrants alone. Documented
  as a residual in `docs/design/willow-gate-seam.md` D6.
- **PR #248's own "Out of scope" note: no mutation-style proof the envelope
  authority gates can fail.** `tests/test_governance_continuity.py` had
  ordinary pytest assertions on `EnvelopeAuthority.check()`, unlike the
  mutation harness `safe-app-store/apps/jarvis` runs. New
  `tools/envelope_mutation_check.py` (per-guard mutation testing, same
  convention as `tools/hook_mutation_check.py`) ran against the real suite
  and reported 13 of 17 guards as GAP on its first run — issuer/revoked/
  inactive/grantee/verb checks, the bounds-signature check, malformed
  `max_count`, the untrusted-meter check, both quota/expiry boundary edges,
  `_bound_matches`'s list-must-match-every-item and scalar-equality
  fallback, and `_deadline`'s non-string-`expires_at` refusal — none of them
  had a test that actually exercised the failing case, only the passing one.
  All 13 are now closed with tests naming the exact scenario each guard
  exists to refuse; the harness reports all 17 guards caught.
- **#233/L-CMD-01: reconciled, not a new gap.** `SECURITY_AUDIT.md` still
  marked the Kart scanner's `find / -delete` / raw-device-write coverage OPEN,
  but its own L-DOS-02 entry directly above already named both patterns as
  DONE — the fix landed for both findings together in `kartikeya`, and
  L-CMD-01 was just never flipped. Re-verified live against `kartikeya` HEAD
  and the installed `kartikeya==0.0.7` this repo pins: both patterns are
  blocked, and `kartikeya`'s own `test_task_scan.py` already covers them
  (commented as the exact L-DOS-02/L-CMD-01 regression test). No code change
  in either repo; `test_task_submit_scans_at_submit_time` extended with both
  patterns to pin the fix through willow's own submit-time wiring, not just
  kartikeya's suite. `SECURITY_AUDIT.md` corrected to RESOLVED.

### Fixed
- **B-41 follow-up: a warm container kept its pre-B-41 `.mcp.json` broken
  forever.** The SessionStart hook's never-clobber rule preserved any existing
  `.mcp.json` — including the stale env-less form written before B-41 embedded
  the env block, so the server it spawned still defaulted to `~/.willow` and
  gate-denied every seat on every reconnect (observed live on a container
  cloned before e125c64). The hook now recognizes that one stale form — a
  `willow-mcp` entry with no `WILLOW_HOME` — sets it aside as
  `.mcp.json.stale.bak`, and regenerates; a file with an env block (or with
  your own servers and no willow-mcp entry) is still never touched.
- **Sandbox auto-confirm stranded a warm container on `unconfirmed_schema`.**
  `schema_profile.resolve()` persists an *unconfirmed* mapping as a discovery
  side effect every time it runs against a table with no artifact yet, so a
  re-provisioned container accumulates these placeholders. Guard 1 treated any
  existing artifact as sacrosanct, so a prior run's placeholder made every later
  `sandbox_confirm` decline forever — leaving the `tasks` mapping unconfirmed
  and the Kart worker unstartable (observed live; only a manual delete + re-run
  recovered it). Guard 1 now re-derives a *pristine placeholder* — exactly
  resolve()'s untouched shape — while still never touching a confirmed mapping,
  a human override tier, or one bearing any extra key (e.g. an operator note).
  New `_is_pristine_placeholder` discriminator with a unit contract.
- **The PreToolUse guard steered the human-orchestrator seat off its own job.**
  The guard blocks `git`/`gh` mutations to route agents through `task_submit`,
  but the willow orchestrator seat exists to do repo maintenance — commit, push,
  PR — so every `git commit` was denied and had to detour through the GitHub API
  (which then desynced the local ref). The guard now lifts *only* the git/gh
  routing nudges for that seat; the self-grant guard (egress leases, keystore,
  manifest `task_net`) runs first and is never lifted, and `psql`/`sqlite3`/`ls`
  routing still applies. The seat is read from the project's `.mcp.json`
  (`WILLOW_APP_ID` / `WILLOW_HUMAN_ORCHESTRATOR`) via `CLAUDE_PROJECT_DIR`,
  because the harness spawns the hook without the session's `WILLOW_*` env — a
  file signal, not a trust boundary, since a forged seat still hits the unlifted
  self-grant guard. Both byte-identical hook copies updated.
- **B-41 (issue #166): the web-sandbox MCP server booted blind.** The
  SessionStart hook wrote env to `$CLAUDE_ENV_FILE`, which shells inherit but
  the client-spawned stdio server does not — it defaulted `WILLOW_HOME` to an
  empty `~/.willow` and gate-denied every seat. The hook now generates the
  gitignored `.mcp.json` **with the resolved env embedded** (after the vault
  restore, so vault-supplied values land), and is invoked via `bash` so a
  mode-stripped clone still boots.
- **B-40 (issue #165): `willow-mcp worker` was unstartable on a clean
  install** — the f1e8c9b guard needs `kartikeya.sandbox.resolve_sandbox_config`,
  which no published kartikeya (≤0.0.7) ships, and the ImportError was fatal on
  every lane. The guard now names the policy source itself by mirroring
  `load_sandbox_config`'s search order; production lanes still refuse the
  vendored default. Remove the fallback once a kartikeya release ships the API.
- **B-42 (issue #167): egress row-gate witness tests are layout-parametrized**
  (repo `task_id` + fleet `id`) inside a dedicated pytest schema — previously
  red 6/6 on any repo-DDL database and wiping the live `tasks` table via
  `DELETE FROM tasks`. Sandbox suite fully green for the first time.
- **Fleet-policy containment tests skip off the fleet host** instead of
  erroring on every CI runner (`~/github/.willow/kart-sandbox.json` is a
  fleet-host-only file; on it, the audit still fires at full strength).
- **Bootstrap venv freshness (#165):** the "already importable — skipping
  install" fast path now re-syncs the editable install when a pyproject pin is
  unsatisfied (the kartikeya-0.0.5-under-a->=0.0.7-pin failure mode). `pip check`
  alone MISSES this on a warm container — it reads the editable install's
  recorded `Requires-Dist`, which a pin bump after the last `pip install -e .`
  never refreshed, so the stale dep passes (observed live: kartikeya 0.0.5 under
  a `>=0.0.7` pin, `pip check` green, four tests red and the worker unstartable).
  The fast path now also runs `willow_mcp.deps_freshness`, which reads the
  CURRENT `pyproject.toml` and checks each dependency's installed version against
  its specifier directly; either guard failing triggers the re-sync.

### Added
- **The serve-mode arm of `_gate` is now tested** (`tests/test_serve_mode_gate.py`,
  21 tests). `_resolve_serve_identity()` and `_gate`'s serve branch — the L-AUTH-02
  fix, the reason a signed-in caller cannot self-declare an `app_id` — had no test
  at all; `grep -rn "_SERVE_MODE\|_resolve_serve_identity" tests/` came back empty.
  The tests drive the whole path with a real `AccessToken` in the MCP SDK's own
  `auth_context_var`: no session, a session missing `iss` or `sub`, a signed-in
  identity with no confirmed binding, and a confirmed binding. All fail closed
  except the last, which is gated **as the bound identity**, not as whatever
  `app_id` the caller passed. This includes the `by_human` serve arm PR #197 could
  not write: `by_human_attested(app_id, serve_mode=True)` is unconditionally True,
  and these pin the premise that makes that sound — reaching a tool body as
  `willow` in serve mode requires an operator-confirmed OAuth binding.

  Serve mode is read through a new `server._serve_mode()` accessor at every site
  that resolves at call time; the import-time FastMCP/auth-provider branch still
  reads `_SERVE_MODE` directly, since that decision is baked into the object
  graph before anything could patch it. The value is unchanged
  (`"--serve" in sys.argv`) and serve mode's behaviour is unchanged. Note that
  patching the `_SERVE_MODE` global also worked before this — the earlier claim
  that serve mode "cannot be entered in-test" was wrong, and the comments in
  `test_human_loop.py` / `test_human_orchestrator.py` saying so are corrected.
  What the accessor buys is that the seam is now named and pinned by a test,
  rather than being an accident of how the read sites happen to be written.
- **Sandbox schema auto-confirm** (`willow_mcp/sandbox_confirm.py`, run by the
  bootstrap): unlocks `task_*`/knowledge writes on the DDL the bootstrap itself
  just applied, behind three guards — existing mapping artifacts are never
  touched; every field must resolve exact@1.0; live columns must equal the
  repo DDL. Adopted/foreign schemas always fall through to the human
  `schema_confirm_mapping` path (B-10/B-11 posture preserved), and
  auto-confirmed artifacts record `confirmed_by="sandbox-bootstrap"`.
- **SessionStart worker auto-start:** the hook launches a fast-lane Kart
  worker after the bootstrap (idempotent, logged to `$WILLOW_HOME/logs/`,
  never fatal), so `task_submit` has a drainer from a cold container's first
  minute instead of stranding (B-26's signal).
- **Consolidation (PR #172):** merged `claude/pypi-package-quality-oojgm6`,
  `fix/fleet-kart-sandbox-vault-unbind`, `claude/desk-organization-uby85b`
  (mai corpus + the #163 parser/security cluster), and `claude/the-assembling`;
  ported `experiment/sentry-observability`'s egress-gated Sentry module as
  content (byte-identical to blob `a99374d`; wired in `__main__.py`), with the
  `telemetry` exposure preset and an `observability` extra.
- **Gates panel** friendly labels for the three MarkdownAI groups.
- **KB curate tools and opt-in Postgres auto-recovery** (#159, #160):
  `knowledge_flag` and `knowledge_retract` under a separate
  `knowledge_curate` permission, with tombstones and flags stored in tags and
  surfaced through `kb_at`/search/continuity. Local Postgres start is retried
  when `WILLOW_MCP_ENSURE_POSTGRES=1`.
- **Bound receipts** (#195, #196) — `write_receipt`/`verify_receipt` with
  staged checks, on a canonical schema pinning wire format, ref derivations,
  signing bytes and structural validation. Ref is checked *before* signature,
  so a single-field tamper reports `ref_mismatch` rather than a signature
  failure. AT-R1 (#194) drives it as table tests.
- **Fail-closed remote enforcement when the gate is absent** (#164):
  SessionStart records posture via `diagnostic_summary`, and PreToolUse blocks
  bare `psql`/`sqlite3`/`curl` in CCR when the marker says the gate is not
  live. This closes the hole diagnosed in the 2026-07-23 handoff — the
  enforcement stack existed but was dormant in remote/hosted sessions, so an
  agent could bypass MCP entirely.

### Changed
- **Ported to MCP Python SDK 2.0** — `mcp>=2.0.0,<3.0.0`, up from
  `mcp>=1.28.1,<2.0.0`. **This is a dependency floor change: willow-mcp can no
  longer be installed alongside anything requiring SDK 1.x.**

  `FastMCP` does not exist in SDK 2.0 — no compat shim, zero occurrences. The
  migration is nonetheless small, because `MCPServer` kept the surface this
  project uses (`tool`, `custom_route`, `run`, `auth_server_provider`):
  `mcp.server.fastmcp` → `mcp.server.mcpserver` (16 references); host and port
  move off the constructor onto `run(transport=, host=, port=)`, making "where
  this instance listens" a property of the run rather than of the server;
  `mcp.settings.host`/`port` are gone, so there is no second copy to assert
  against; and `call_tool()` returns a `CallToolResult` instead of a
  `(content_blocks, structured)` tuple.

  All tools register unchanged. Deliberately left blocked:
  `mcp.server.lowlevel.server.request_ctx` is gone in SDK 2.0, which keeps
  exactly one `ContextVar` (`auth_context_var`).
- **The version is now derived from the git tag** (`hatch-vcs`) rather than
  hardcoded in `pyproject.toml`, and `willow_mcp.__version__` reads it back
  from installed package metadata. `.claude-plugin/plugin.json` had drifted to
  2.0.0 against the package's 2.0.1; `release.yml` now asserts both the built
  version and the plugin manifest match the tag before publishing.

### CI
- **mai-lint runs before the test matrix** (#158): deterministic guard for the
  #156/#157 regression classes on the default mai targets; auto-detection
  leaves non-mai markdown (including the HELD canon) untouched. Scope is
  mai_lint-only until the wtool keep-vs-retire call (handoff Q10).

### Docs
- **The companion layer is documented** — new README section covering the
  Grove (lessons rings, `python -m willow_mcp.the_grove`), the `fork_*`
  work-unit tracker, the friction-floor mirror detector, and the `tools/`
  deterministic-harness suite; `tools/README.md` gains the missing
  `mai_prose_split.py` row.

## [2.0.1] — 2026-07-22

Docs and packaging only — no behavior changes.

### Changed
- **Enriched 44 thin MCP tool docstrings** (every tool description under ~130
  chars) to state purpose, parameter semantics, return shape, side effects, and
  sibling-tool pointers — the dimensions Glama's tool-definition quality score
  reads. `store_put`'s stated deviation thresholds now match `db._action_for`
  (>= 0.785 flags, >= 1.571 stops; the docstring previously claimed 0.6).

### Added
- **`glama.json`** maintainer manifest at the repo root, so the Glama listing
  can be claimed.
- **PyPI metadata** — trove classifiers (license, Python 3.11–3.13, dev status)
  and Repository/Issues/Changelog project URLs in `pyproject.toml`.

## [2.0.0] — 2026-07-21

The v2 rebuild. Expands the server from a store/knowledge/task tool set into an
authorization-gated, agent-neutral platform with an HTTP OAuth serve mode.

### Fixed
- **Strict trust root on hardened installs** — `self_writable_trust_paths` checks
  direct writability (path + parent), not a writable `$WILLOW_HOME` ancestor
- **`repair-runtime-perms`** leaves legacy consent policy files with
  `willow-operator` instead of reclaiming them for the runtime user

### Added
- **`repair-runtime-perms`** — restore MCP write paths (`store/`, `dispatch/`, …)
  after trust-root hardening; fixes over-broad `chown` when legacy policy files
  lived at `$WILLOW_HOME` root
- **B-32 trust-root hardening** — `willow-mcp harden-trust-root` chowns `mcp_apps/`
  and `config/` to a dedicated unix user, sets world-readable modes, and wires
  `WILLOW_MCP_STRICT_TRUST_ROOT=1` into project MCP configs. `doctor` surfaces
  forgeable trust paths when separation is missing.
- **S6 persona overlays** — `persona-overlays` skill with slim voice + boundary
  snippets for all six specialists; `session-start` specialist section updated
  with open table and overlay pointers.
- **S5 discipline skills** — `debugging`, `review`, `tdd`, and `brainstorming`
  in the bundle and Claude plugin (`plugin.json`). Rewritten for willow-mcp verbs
  (pytest, `knowledge_search`, egress/schema constraints) with no fleet paths.

### Security (willow-gate seam — hardening from adversarial review)
- **B-33: consent policy files are read-only inside Kart sandboxes.** Requires
  `kartikeya>=0.0.5` (`collect_mcp_trust_ro_overlays` overlays `settings.global.json`
  and `consent.json` at home root and under `config/`). Regression-tested in
  `tests/test_b33_consent_sandbox.py`. Host-side edits remain possible on shared-uid
  installs (B-32 residual).
- **`whoami` / `diagnostic_summary` can no longer enumerate another identity's
  config.** These tools are ungated (they must answer with a missing manifest), so in
  stdio a caller could pass any `app_id` and read that identity's permissions / role /
  `store_scope`. They now route through `_own_identity_denial`: under binding
  enforcement the caller must present a valid per-call credential proving it owns the
  `app_id` (identity proof, not a tier gate — whoami is unclassified). Unchanged when
  enforcement is off (trusted-host model) or for an unregistered app_id; serve mode
  was already OAuth-bound.
- **Enforcement no longer fails OPEN on a broken keystore.** `_enforce_binding_gate`
  now pairs `agent_registry.load()` with a new `is_registered()`: a registered agent
  whose secret is momentarily unreadable/short is DENIED (fail-closed), not silently
  downgraded to app_id-only manifest auth. `load()` also rejects a `<32`-byte secret
  on read, not only on register.
- **Check-out is ownership-scoped.** `session_reconcile` / `SessionBinder.check_out`
  now require the session's bound `agent_id == app_id` (the rule `verify_call` already
  enforced), and `session_started_ts` is owner-scoped — closing a cross-agent
  session-destroy (DoS) and audit-forgery path where any caller who learned another
  agent's `session_id` could close and mis-attribute its session.
- **Reconciliation can't be truncated past the diff.** The ground-truth feed uses a
  new unbounded `ReceiptLog.distinct_tools()` (DISTINCT tool set) instead of a
  row-limited `since()`, so a late privileged call in a high-volume session can no
  longer fall outside the window and read as `clean`.
- **Check-in replay protection fails closed.** An unreadable (vs absent) check-in
  nonce file now raises instead of being treated as "nothing used".
- **Announcement redacts before the sink.** Receipt `detail` (which can carry raw
  error text embedding a token) is run through `secret_scan` before it reaches the
  announcement sink, which may be an external ledger; `credential_returned` gets an
  ALERT floor so an exemption-bypassed secret egress is never silent.
- **Thread-safety + hardening.** `SessionBinder` state is guarded by a lock (FastMCP
  threadpool); Exiled (trust 0) is denied at check-in; `call_sig` uses an unambiguous
  structured encoding; keystore temp files are pid+thread+random-unique; keystore
  `chmod` failures are logged, not swallowed. The PreToolUse guard now blocks writes
  to the `gate/` keystore (both hook copies, kept byte-identical) and the
  `register-agent`/`rotate-agent`/`revoke-agent` verbs; a `rotate-agent` CLI is added.

### Added
- **The Nest — live drop-folder router** (`willow_mcp.nest.intake` + `rules`,
  five gated tools: `nest_intake_scan` / `nest_intake_queue` / `nest_intake_file`
  / `nest_intake_skip` / `nest_intake_flags`). Watch a drop folder, classify new
  files by filename into a *track*, stage a review queue, and — on an explicit
  gate action — move the file into place (`~/personal/<track>` or `$WILLOW_HOME`).
  Nothing moves without a confirm; scan only stages. Includes the **feedback
  edge**: every gate action records prediction vs. outcome, a mismatch increments
  a correction counter, and at threshold a rule-delta flag opens — the classifier
  proposes, a human ratifies (it never rewrites its own rules). State lives in the
  SOIL store; router tools ride the existing `nest_read`/`nest_write` groups. The
  rules seed (`rules.seed.json`) is a **generic, PII-free** template — the
  willow-2.0 seed it was adapted from had leaked the operator's private keywords
  (case numbers, medical/legal matters, names), which must never ship in a
  packaged engine; the operator's real rules stay in their local
  `$WILLOW_HOME/nest_rules.json` only. Held by `tests/test_nest_intake.py`
  (incl. the correction→flag threshold). Completes the "dump your life and let the
  pigeon figure it out" workflow (content pipeline + router). See
  [docs/NEST.md](docs/NEST.md).
- **The Nest — personal-file content pipeline** (`willow_mcp.nest`, four gated
  tools: `nest_scan` / `nest_status` / `nest_digest` / `nest_promote`). Walk a
  drop folder, extract text (OCR/PDF/docx/plaintext), classify fragments by
  meaning (regex → local-embedding → LLM cascade) into a canonical SQLite Nest
  DB, and promote its **structure** — counts, curated category names, redacted
  secret kinds, never content — into the knowledge base. The engine is vendored
  from `rudi193-cmd/safe-app-store` `apps/nest-seed` (MIT); base install stays
  dependency-free, `pip install willow-mcp[nest]` unlocks OCR/PDF/docx. New
  `nest_read`/`nest_write` permission groups (gate.py + tier_policy + gates_panel
  labels). **The wall** is enforced mechanically: `nest_promote` can reach only
  the structure-only bridge; a category allowlist keeps filename-labels out of
  every surface (counted as `uncategorised`, not hidden); `nest_digest` returns a
  walled view (names/dates/filenames suppressed) over MCP. Held to those claims
  by `tests/test_nest.py` (incl. `test_bridge_emits_no_content_names_or_filenames`).
  See [docs/NEST.md](docs/NEST.md). This first cut is the content pipeline; the
  live drop-folder router is a later step.
- **Lineage seed pack** (`seed/lineage_willow.py`) — real, cited provenance atoms
  for willow-mcp's own build story (the willow-gate seam: the three holes H1/H2/H3,
  the settled decisions D1–D5, the five phases, the adversarial-review hardening,
  the `whoami` fix, the signing harness, and the upstream `entry_allowed` fix),
  each an atom that answers a question an agent will actually ask and cites a real
  PR / commit / file / design-doc section. Kept OUT of the agent-neutral base (a
  separate lore pack, per `lineage.py`); idempotent by slug + composite edge id, so
  an operator runs it against their live store (`python seed/lineage_willow.py`) and
  can re-run or extend it freely. Guarded by `tests/test_seed_lineage.py` so an atom
  that can't cite is caught before it ships.
- **Signing harness + end-to-end proof** (`signing.SigningClientSession`,
  `examples/signing_client.py`, `tests/test_signing_e2e.py`) — the reusable client
  wrapper over an MCP `ClientSession` that holds the agent's secret, checks in once
  (`.bind`), signs every subsequent call (`.call`), and checks out (`.reconcile`) —
  the model it drives never sees the secret. Proven against the REAL willow-mcp
  server: `test_signing_e2e.py` drives the actual FastMCP dispatch over an in-memory
  transport (a signed call passes, an unsigned one is denied, the tier ceiling denies
  an over-tier tool, unregistered stays manifest-only, check-out reconciles clean),
  and `examples/signing_client.py` is a runnable operator demo that launches
  `python -m willow_mcp` as a stdio server with `WILLOW_MCP_ENFORCE_BINDING=1`,
  registers an agent, and shows the whole flow pass. This closes the review's
  "enforcement has never run end to end without the test harness" gap.
- **Client-side signing shim** (`signing.py`, `_read_call_credential` /
  `_current_call_credential` in `server.py`) — the H1 "practical shape" that makes
  tier enforcement run END TO END. The agent's HARNESS (not the model) holds the
  per-agent secret and signs each call; the signature rides the MCP request's
  out-of-band `_meta` (key `willow_call_credential`), never a tool argument, so the
  model can neither see the secret nor fabricate/omit a signature. `signing.py`
  provides `build_checkin_header`, `build_call_credential`, `ClientSigner`, and the
  `signed_call_tool(session, signer, name, args)` one-liner. Server-side,
  `_read_call_credential` pulls `{session_id, call_nonce, sig}` from the request
  context and `_current_call_credential` resolves it (an explicit contextvar wins
  for tests; production reads `_meta`), feeding both the observe hook and the
  enforcement gate. `session_bind` is the ONE bootstrap exemption — the check-in
  carries no per-call credential (no session yet) and authenticates via its own
  header HMAC, so requiring one would deadlock; everything after check-in signs.
  With this, flipping `WILLOW_MCP_ENFORCE_BINDING=1` against a registered agent
  whose harness signs now PASSES a live call (previously only tests could), while an
  un-instrumented client still cannot reach a gated tool — the intended property.
- **Graduated announcement volume** (`announce.py`, the `ReceiptLog.on_record`
  hook) — Phase 5 of the willow-gate integration
  (`docs/design/willow-gate-seam.md` §5): a policy *over* the receipt log, not a
  second log. It decides how loudly each recorded decision is surfaced on the
  operator's log channel, graduated by the caller's BOUND trust tier (louder for
  the less trusted — an unbound caller is loud, Elder's routine calls are silent),
  with every denial and reconciliation discrepancy escalated to ALERT regardless
  of who did it. `WILLOW_MCP_ANNOUNCE` gates it (off by default ⇒ a plain local box
  is unchanged and the record path pays nothing beyond the switch check);
  `WILLOW_MCP_AUDIT_LEVEL` = `full` (per-volume) or `minimal` (only the loud stuff —
  untrusted callers and every denial). Wired through a single `ReceiptLog.on_record`
  observer so it sees every record site from one point and can NEVER break the
  audit write it rides on (sink errors swallowed; the log stays the sole record).
  Binding-mechanism receipts (`bind_observed`/`bind_enforced`) are never announced
  (they ride every call — announcing them would just double each line). Pure
  stdlib; willow-gate's PGP-encrypted announcement ledger is a pluggable
  `announce.set_sink()`, so the base never imports `python-gnupg` (seam-doc D5).
  New `announce` global row in the gates panel surfaces the switch + audit level.
- **Session reconciliation** (`session_binder.reconcile` / `check_out`,
  `ReceiptLog.since`, the `session_reconcile` tool) — Phase 4 of the willow-gate
  integration (`docs/design/willow-gate-seam.md`, hole H3): a check-out
  declare-vs-did diff. At check-out an agent declares the tool CLASSES it
  exercised (`{tools, pass_count, fail_count, drift, state_hash}` — the reconciled
  subset of the 13-field entry header, D4); the server diffs that against the
  ground truth it **cannot feed** — `ReceiptLog.since(app_id, started_ts,
  outcome="ok")`, every gated call that actually ran since check-in, scoped to the
  session window by a SERVER-stamped start time (never the agent-supplied one) and
  classified via `tier_policy`. The verdict flags a false write/execute/admin
  claim (`claimed_not_done` — the H3 catch: a claim no receipt backs, i.e. a lie
  or out-of-band use) and privileged activity not declared at entry/exit
  (`beyond_entry` / `done_not_claimed`); read is ambient, so read-level over/under-
  reporting is surfaced but never fails a session. Reconciling **records but never
  blocks** (`reconciled` / `reconcile_discrepancy` receipt) — it runs alongside
  `session_handoff_write`, not in front of it — and drops the session, freeing its
  per-call nonce set (the H1 residual bound). `pass_count`/`fail_count`/`drift`/
  `state_hash` are echoed, never judged (no independent ground truth).
- **Tier-ceiling enforcement** (`tier_policy.py`, `_enforce_binding_gate` in
  `server.py`) — Phase 3 of the willow-gate integration
  (`docs/design/willow-gate-seam.md`, hole H2): the observed identity binding
  becomes a CONTROL. `tier_policy.py` is the D1 tier→group map as a pure,
  fully-tested table — every `@_guarded` tool is classified into a cumulative
  privilege class (read ⊆ +write ⊆ +execute ⊆ +admin), with a completeness test
  that fails if a tool is added to a group without a class, so the ceiling can't
  silently lag. Inside `_gate`, after `permitted()` allows a tool by the manifest,
  `_enforce_binding_gate` applies the *bound* trust tier: effective authorization
  is `expand(manifest.permissions) ∩ unlocked_tools(trust_level)`. Egress stays
  **double-gated** — `integration_call` / `task_net` need `execute` on a
  non-read-only tier AND the manifest's own-line grant; the tier never softens the
  own-line rule, and `admin` still ≠ sudo. Fail-closed on every ambiguous path
  (missing/forged/replayed credential, tier-below-tool). **Opt-in via two locks**
  (seam-doc D3): the `WILLOW_MCP_ENFORCE_BINDING` env switch (OFF by default —
  registering an agent while off is exactly Phase 2, observe-only) AND per-agent
  registration (a registered app must sign and clear the ceiling; an unregistered
  app stays manifest-only, so a plain local clone is unchanged). The single-use
  call nonce is consumed exactly once — enforcement verifies it inside `_gate`;
  the observe hook steps aside when enforcing. New `enforce_binding` global row in
  the gates panel surfaces the switch's live state beside `strict_trust_root`.
- **Identity binding, observe-only** (`agent_registry.py`, `session_binder.py`) —
  Phase 2 of the willow-gate integration (`docs/design/willow-gate-seam.md`,
  hole H1): the mechanism that lets the gate know *which* agent is calling,
  wired to LOG rather than enforce. An HMAC keystore lives at
  `$WILLOW_HOME/gate/` (dir `0700`, registry `registry.json`, per-agent secret
  `secrets/<agent_id>.key` `0600`); agents are registered CLI-only
  (`register-agent --max-trust {0..4}` / `list-agents` / `revoke-agent`), never
  by an app at runtime — registration is an operator authority, guarded like
  the other sudo-invariant crossings. `SessionBinder.check_in(header)` verifies
  a 13-field signed header (HMAC over the header, reserved-field trap,
  persistent check-in-nonce replay defence, trust capped at the registered
  ceiling) and mints a bound session; `verify_call(...)` re-checks a per-call
  HMAC signature (over `session_id|app_id|tool|call_nonce`) so a bound
  credential cannot be ridden, replayed, or tampered. Exposed as the
  `session_bind` tool (header `agent_id` must equal the caller's `app_id`) under
  a new `binding` group. The server observes the binding on EVERY gated call —
  `_observe_binding()` reads a `_CALL_CREDENTIAL` contextvar, resolves the bound
  tier, and writes a `bind_observed` receipt — but the outcome does not gate
  anything and every failure is swallowed. This is deliberately
  **observe-only**: it makes the identity signal real and auditable before any
  Phase 3 turns it into enforcement, so the binding can be watched in receipts
  without risking a lockout. Vendored/self-contained (seam-doc D5) — pure
  `hashlib`/`hmac`/`os`, no `python-gnupg` dependency.
- **Friction-floor watcher** (`friction.py` + vendored `friction_floor.py`) —
  Phase 1 of the willow-gate integration (`docs/design/willow-gate-seam.md`): a
  model-free, deterministic relationship smoke detector. It watches one thing —
  whether the agent has stopped being *other* and is mirroring the user back,
  smoothed, WHILE the user is escalating — and when a window of agent turns sits
  below a friction floor during escalation it raises a loud, human-facing flag
  ("the agent has stopped being 'other' — no pushback, no grounding, mostly
  echo; look at turns …"). It NEVER blocks and NEVER egresses; it is a SIGNAL,
  not a verdict (false-positives happen, a clever mirror can duck it) — its value
  is observability: it makes an invisible thing leave a trace. Two tools:
  `friction_scan` (scan a `[{role, text, ts?}]` window; persists any flag,
  deduped by content, to the `friction_flags` collection) and
  `friction_flags_list`. New `friction_read`/`friction_write` groups (both in
  `full_access`). Orthogonal to the auth path — it wires to transcripts, not the
  gate. The scanner is **vendored** from willow-gate (Apache-2.0) rather than
  taken as a dependency, because it is pure stdlib while the willow-gate package
  pulls `python-gnupg`; keeping the base dependency-free wins (seam-doc D5, for
  this pure piece). Must be driven from OUTSIDE the watched model — a mirror
  cannot audit itself.
- **Lineage / provenance atoms** (`lineage.py`, prototype) — a queryable "story
  of this willow" for the user-facing base store. Agents dropped into a running
  willow keep asking where something came from, what was here before, and why it
  is this way; a plain knowledge record answers "what is true", a lineage atom
  answers **provenance**. Split into two layers, modeled on willow's own
  `{from,to,relation,context}` edge graph: NODES are disciplined atoms
  (rationale, evidence, authority) in the `lineage` collection; RELATIONSHIPS are
  typed directional EDGES in `lineage_edges` (willow-mcp's own collection, not the
  vault's inherited graph, so the base stays portable), and direction is QUERIED,
  never stored twice — "is X current?" is "does any edge point `to: X` with
  `relation: supersedes`?", which cannot drift the way a hand-kept back-pointer
  can. Three traversed relations, each earning its place by changing what `why`
  returns and what an agent does: `supersedes` (replaces — the old atom becomes
  non-current), `derived_from` (came from but did NOT retire — both stay valid),
  `motivated_by` (the friction behind it; may point at a gap id or external
  node). Tools: `lineage_record`, `lineage_link` (add one edge post-hoc),
  `lineage_why` (returns the atom plus its supersedes chain, derived_from, and
  motivated_by — the lineage, not a blob), `lineage_list`. `record` REQUIRES a
  non-empty rationale and at least one evidence citation — an atom that can't
  cite is lore, not memory, and is refused. New `lineage_read`/`lineage_write`
  groups (both in `full_access`). The MECHANISM is agent-neutral and ships in the
  base; any one willow's specific story is content it records into its own store.
- **Store/gap introspection & cleanup tools** — `whoami` (your own manifest and
  effective permissions; ungated like `diagnostic_summary`), `store_collections`
  and `store_stats` (list / count the SOIL collections in your `store_scope`
  without a search), and `store_purge_collection` / `gap_delete` /
  `gap_purge_topic` (reversible soft-delete cleanup — a whole collection, one
  gap, or every gap under a topic; each confirm-guarded and archive-don't-delete,
  with `gap_purge_topic` skipping promoted gaps). Shaped by dogfooding the server
  from inside — each tool surfaced the need for the next.
- **One-command local sandbox + native session load.**
  `scripts/sandbox-bootstrap.sh` and fresh-install Postgres DDL
  (`docs/schema/{knowledge,agents,routing_decisions}.postgres.sql`) take a clone
  to a working stdio server; a synchronous `SessionStart` hook
  (`.claude/hooks/session-start.sh`) plus `.claude/settings.json` provision the
  box (venv, `$WILLOW_HOME`, Postgres, bubblewrap) and load willow-mcp natively
  at session start on Claude Code on the web, and activate the `PreToolUse`
  sudo-invariant guard.
- **Egress secret redaction** (`secret_scan.py`, wired at the `_guarded`
  funnel) — defense-in-depth for the standing guarantee "no tool ever returns a
  credential." The credential *accessor* already withheld values
  (`credential_source()` returns a source, never the secret); the *data* path
  did not — a stored record, a KB atom, task output, or an integration response
  body carrying an `sk-…`, an `AKIA…`, or a private-key block was returned
  verbatim. Now the one funnel every tool response passes through redacts
  high-confidence credential formats (AWS access key id, provider `sk-` keys,
  GitHub/Slack/Google/Stripe tokens, JWTs, PEM private-key blocks) to
  `[REDACTED:<kind>]` before egress. Redacts rather than blocks, so legitimate
  retrieval survives minus the credential; precision-first patterns so ordinary
  ids/hashes are not false-positived; fail-closed if the scanner itself errors
  (the payload is denied, never returned unscanned); and payload-free receipts
  (a `redacted` row records only WHICH kinds, never the value). Unit contract in
  `test_secret_scan.py`, end-to-end store round-trip in `test_server.py`.
  - **Per-manifest exemption** (`gate.egress_secret_exempt`): a tool that
    legitimately must return a raw token — the canonical case is an
    `integration_call` performing an OAuth token exchange — can be named in its
    app's manifest `egress_secret_exempt` list. The scan still runs (the audit
    trail stays complete); an exempted return is kept raw but receipted as
    `credential_returned` with the kinds, so the exception is loud, never
    silent. Fail-closed toward redaction: a bad app_id, a missing/unreadable
    manifest, or a malformed field exempts nothing, and — since manifests are
    operator-side (the PreToolUse hook blocks an app from writing its own) — an
    app can never exempt itself. Per-tool, not a blanket unlock.
- **Native project orientation.** Explicit manifest collection aliases map
  charter names to flat SOIL names without generic slash rewriting.
  `session_enter` returns project records, ORIENT/FRANK status, latest project
  handoff, and persona voice context; project-scoped v3 handoffs cannot bleed
  across projects. A supported Cursor SessionStart template invokes this path
  directly without fylgja or a persona picker.
- **Governance continuity** — interactive operator-only atomic consent
  administration; an adapter over the existing Postgres FRANK chain; strict
  citation-before-act constitutional envelope metering; and idempotent
  `fleet.json` roster reconciliation that preserves contested rows.
- **Local governance CLI** — `willow-mcp consent status|set|reconcile` and
  `willow-mcp roster status|sync`. Mutation commands reject non-interactive and
  Kart execution and are blocked by the bundled self-grant hook.
- **Installer-managed standalone workers.** Fast and batch systemd user units
  carry explicit standalone environment, while the Postgres queue now enforces
  lane isolation, attributed/timed claims, stale recovery, bounded retries, and
  terminal timestamps. Readiness distinguishes absent, dead, stale, and
  stranded workers without starting or stopping services during installation.
- **Signed per-task Kart egress authorization (B-37).** Network rows now carry
  an operator-signed envelope binding submitter, exact normalized task hash,
  scope, expiry, and one-use nonce. The executor rechecks capability, consent,
  lease, strict trust-root state, signature, and replay immediately before shell
  launch. `willow-mcp sign-net-task` is interactive/local-only and no MCP tool
  can mint signing authority.
- **The Grove** (`the_grove.py`) — a rings store for *lessons*, sibling to
  `schema_profile`'s vocabulary rings but unbounded on purpose: vocabulary may
  be pruned cheaply, lessons are kept precisely so the deployment cannot become
  something that forgets them. One ring per lesson (`add_ring`/`rings`/`depth`),
  `canopy()` (the visible architecture), `deep_roots()` (the recorded lessons),
  and a pipe-friendly status: `python -m willow_mcp.the_grove --status` reports
  stability, ring depth, and soil health; run with no arguments for the resting
  display. A diseased rings file reads as empty but reports the grove
  `unsettled` rather than silently claiming depth 0.
- **`core.record_lessons()`** — distill any SQLite journal (any schema — the
  table holding the writing is introspected, never assumed) into entry count,
  date range, and theme tallies, then grow exactly one grove ring carrying the
  lesson worth keeping. The source is opened `mode=ro` — a journal handed to
  this function is being remembered, not edited — and every failure is
  fail-soft (`{"error": ...}`, no ring), because a ring must never record a
  lesson that wasn't actually learned.
- **Integration adapters** (`integrations.py`) — outbound HTTP adapters with a
  shared base (env→vault credential resolution, bounded stdlib transport with
  Retry-After-honoring retries, credential-scrubbed errors). Two live adapters
  (`github`, `huggingface`) and six **declared stubs** (`gmail`, `slack`,
  `notion`, `google-drive`, `datadog`, `jira`) that refuse fail-closed and name
  what earns their implementation. New tools `integration_list`,
  `integration_status`, `integration_call`; new operator CLI
  `willow-mcp-integrations` (`list` / `check` / `set-token`). Live calls are the
  fourth consumer of the three-key egress gate, keyed on a new
  `integration_net` capability — its own line, never implied by `task_net` or
  `full_access`, because the server-process lane is strictly more privileged
  than the sandbox lane. `integration_call` is likewise excluded from
  `full_access`. See `docs/design/integrations.md` for the earn rule.
- **`willow-mcp tree` / `tree_view.build_tree()` — the integration seam for a real
  dashboard.** `docs/design/*.html` sketches a client UI as a tree (trunk/sap/
  canopy/roots/rings/leaves/litter/stomata) with fabricated numbers; `tree`
  makes it real, one call returning every part in that shape instead of a
  dashboard assembling `fleet_status`/`fleet_health`/`kb_startup_continuity`/
  `receipts_tail`/`gates` itself. `sap`/`canopy`/`leaves` call straight into the
  same `@_guarded` tool functions an MCP client would reach (gating, rate
  limiting, and receipt logging all still apply) and degrade to
  `{"error": "postgres_unavailable"}` with no database configured, matching
  those tools' existing shape. `roots`/`rings`/`litter`/`stomata` read local
  SQLite/filesystem state directly and work with no Postgres at all. Adds
  `Store.list_collections()` (factored out of `search_all`'s own enumeration)
  as the `roots` data source.
- **`willow-mcp gates` — every authorization gate as one on/off panel, egress-lease
  shaped.** Diagnosing a denial meant knowing which of a dozen-plus gates to check
  (manifest permissions, `task_net`, `integration_net`, `consent.*`, egress lease,
  identity bindings, strict trust root, severance, human-orchestrator attestation,
  worker liveness) and which file or CLI command controlled it. `gates` shows all
  of them at once, each rendered the way the egress lease already renders itself:
  on/off, plus how long the "on" is good for — `standing` for gates with no expiry,
  `process-lifetime` for env-var gates that only change at restart, or a live
  countdown for the lease. `--html` writes a self-contained static snapshot with a
  client-side ticking countdown and copy-to-clipboard action buttons; `--json`
  dumps raw rows for scripting. New `allow-permission` / `deny-permission`
  subcommands give manifest permission groups the operator-only local-CLI
  affordance they lacked before (only hand-editing `manifest.json` or a full
  `compile-agents` regenerate existed prior) — local-CLI-only and never MCP tools,
  the same sudo-invariant boundary as `grant-net`/`confirm-binding`, so an agent can
  never grant itself a permission it was just denied. `consent.*` rows are
  read-only by design (willow-mcp never writes that policy) and never show a
  command.
- **`gates` is now interactive — a real TUI and a live local HTML dashboard, not
  just a snapshot.** Bare `willow-mcp gates` in a real terminal opens a curses
  screen: arrow keys / j-k to move, enter/space to actually flip the highlighted
  gate — grant/revoke a lease (prompts for TTL + reason), allow/deny a permission,
  confirm an identity binding, drain the task queue once. `willow-mcp gates
  --serve` does the same over a `127.0.0.1`-only local HTTP server with real
  clickable buttons, for anyone who'd rather use a browser. Both share one action
  layer (`gates_actions.py`) with the `allow-permission`/`grant-net`/
  `confirm-binding` CLI subcommands — pressing a row calls the exact same
  functions, no new authority. `--json`/`--html`/`--static` are unchanged and
  still what runs automatically when stdout isn't a real terminal (piped, CI),
  so nothing scripted against the old output breaks.
- **Gates dashboard: readable state labels and a real layout, not one long
  scroll of identical cards.** Feedback on the live HTML dashboard: bare
  ON/OFF buttons don't say what "on" means (granted? allowed? running?), and
  ~30 same-sized cards in one flat grid reads as noise, not a dashboard. Every
  row now carries a `state_label` in context — GRANTED/NOT GRANTED,
  ALLOWED/BLOCKED, ACTIVE/NONE, CONFIRMED/PENDING, RUNNING/STALLED/STOPPED,
  ENABLED/DISABLED — and a `category` (egress & network / system / identity /
  permissions) that both the TUI and the two HTML pages now group by instead
  of showing everything at once. The HTML pages default to the egress tab
  (smallest group, the one with a clock and real consequence) with a summary
  strip above the tabs for at-a-glance state, and render the ~20-row,
  rarely-touched permissions group as a compact single-column list instead of
  large cards. New shared module `gates_html.py` holds the CSS/JS both the
  static snapshot (`gates_panel.render_html`) and the live dashboard
  (`gates_serve.py`) now render through, so the two pages can't drift apart
  the way two independent ~200-line templates eventually would.
- **Time-boxed egress leases** (B-32 / L-NET-02). `task_submit(allow_net=True)` now
  needs a **third** key: an unexpired lease issued by the operator with
  `willow-mcp grant-net <app_id> --ttl 30m --reason ...` (ceiling 3h, per FRANK
  `cc553729`). `task_net` is demoted to a capability — *this app may ever ask* —
  while the lease is the grant itself, carrying an issuer, a reason, and a deadline.
  **No MCP tool can mint a lease**: issuance is local-CLI-only, exactly as
  `confirm-binding` is. New `revoke-net` and `net-status` subcommands. Leases are
  read fail-closed — absent, unparseable, expired, over-ceiling, a deadline with no
  timezone, or a record naming a different `app_id` than the file it sits in all
  deny. Because leases live under `mcp_apps/`, they inherit B-14's `bound_ro`
  sandbox mount: a sandboxed task cannot mint one (verified — `OSError(EROFS)`).
  `diagnostic_summary` gains a `net_lease` check whose `self_writable` field names
  every authorizing key the running process could forge, and the PreToolUse hook
  blocks an agent from writing any of them. **The residual is real and deliberate:**
  on a single-uid host the agent can still write the lease, so this narrows and
  audits the self-grant rather than preventing it. Set
  `WILLOW_MCP_STRICT_TRUST_ROOT=1` after `chown`ing the trust root to a uid the
  agent does not run as, and egress is refused whenever the keys are self-writable.
  Off by default, because enabling it before that separation exists would deny
  egress on every current install.
- **Two-key egress gate** (B-29). `task_submit(allow_net=True)` now requires the
  operator's standing `consent.internet` from `$WILLOW_HOME/settings.global.json`
  **in addition to** the app's `task_net` capability. Either one missing denies
  (`net_denied` / `consent_denied`) before any write. Flipping `consent.internet`
  to `false` stops egress fleet-wide without editing a single manifest. The new
  `consent.py` reads that policy **fail-closed** — an absent file, an unparseable
  file, or a non-boolean value all read as denied — and only ever reads it; the
  policy is authored by willow-2.0. `diagnostic_summary` gains a `consent` check
  that raises an error when the legacy `consent.json` and canonical
  `settings.global.json` disagree, rather than silently obeying one.
- **Worker liveness** (Kart lift stage 4, B-26). `willow-mcp worker` publishes a
  heartbeat through kartikeya's `on_heartbeat` seam. `fleet_health` now reports
  `workers` (each `alive` / `stale` / `dead`) and a `stranded` boolean — true when
  there is pending work and no live worker — and `diagnostic_summary` gains a
  `worker` check that names the condition and its fix. Previously a submitted task
  looked identical whether a worker was about to claim it or none existed.
  Heartbeats are advisory telemetry, never authorization: no gate reads them, and
  reads verify the recorded pid is a live local process.
- **HTTP serve mode** (`--serve`) with OAuth 2.0 + PKCE against Google/Apple as
  the upstream IdP, plus a local credential vault (`willow-mcp setup`).
- **Identity binding**: serve-mode sign-ins propose an unconfirmed
  `(issuer, subject_id) → app_id` binding; an operator-only, stdio-local
  `willow-mcp confirm-binding` confirms it before any tool permission applies.
  Fail-closed for authenticated-but-unbound callers.
- **`email_basis`** on bindings (`asserted` / `first_auth_only` / `relay` /
  `unavailable`) so downstream code knows how much to trust an IdP email, plus
  `email_drift` annotation when a bound identity's email changes.
- **Manifest-based ACL gate** (`gate.py`): every tool call is authorized against
  `$WILLOW_HOME/mcp_apps/<app_id>/manifest.json` — no ACL database, no external
  auth service. Permission groups: `store_read`, `store_write`, `knowledge_read`,
  `knowledge_write`, `schema_admin`, `task_queue`, `agent_dispatch`, `fleet_read`,
  `context`, `audit`, `full_access`.
- **`diagnostic_summary`** — a self-check that answers "is this install wired
  correctly?": SOIL store (path/writable/collections), Postgres (reachable +
  which database + whether willow-mcp's tables are present), schema-confirmation
  state, your `app_id`'s manifest + resolved permissions, identity bindings, and
  the config environment — then a verdict (ok/degraded/broken) with named
  problems and fixes. Deliberately ungated (it must answer even when the manifest
  or database is misconfigured); reveals only the caller's own config, never
  fleet rows or vault secrets; serve mode requires a confirmed identity and
  redacts absolute paths. Its headline case is the empty-DB / wrong-`WILLOW_PG_DB`
  footgun (Postgres connects but points at a database without the tables).
- **Session context** (`context_save` / `context_get` / `context_list` /
  `context_expire`) — ephemeral, per-identity working state that survives across
  sessions, with an optional TTL. SOIL-backed (no Postgres needed); reads
  transparently skip and purge expired entries; scoped to your `app_id`.
- **`receipts_tail`** — read your own most-recent tool-call receipts (a
  self-audit trail); scoped to your `app_id`, never another identity's calls.
- **Schema adaptation**: read tools adapt to the host database's real column
  names; write tools refuse (`unconfirmed_schema`) until the mapping is reviewed
  and confirmed via `schema_confirm_mapping`.
- Tool set expanded 11 → 27 (`kb_*`, `agent_*`, `fleet_*`, `schema_confirm_mapping`,
  `diagnostic_summary`, `context_*`, `receipts_tail`).
- Input sanitizer, per-caller rate limiter, and a receipt log.
- Claude Code plugin: a `PreToolUse` hook that redirects raw `psql`/`sqlite3`
  access to the matching MCP tool, and `schema-confirm` / `willow-serve` skills.
- `scripts/willow-serve` — turn OAuth serve mode on/off on demand via a systemd
  `--user` service, toggling the matching `.mcp.json` client entry to match.
  Installed unit template in `deploy/`.
- Dockerfile and GitHub Actions test workflow (runs against a Postgres service).

### Fixed
- **`kb_startup_continuity` crashed on a jsonb `tags` column**
  (`operator does not exist: jsonb ~~`) and silently returned empty on a native
  `text[]` column. Now branches on the column type: `::text LIKE` for text /
  jsonb, `= ANY(col)` element match for arrays.
- **Receipts escaped the sovereign box.** The tool-call audit trail defaulted to
  `~/.willow/mcp_receipt.db` — outside any box `$WILLOW_HOME` points at. Now
  defaults under `$WILLOW_HOME` (explicit `db_path` / `WILLOW_MCP_RECEIPT_DB`
  still win), keeping the audit trail inside the data-vault boundary.
- **Test isolation could be defeated by the ambient environment.** conftest used
  `os.environ.setdefault`, so an exported `WILLOW_HOME`/`WILLOW_STORE_ROOT` (e.g.
  from the new SessionStart hook) ran the suite against a real store, polluting
  it. It now force-sets the isolation vars.
- **Purge confirm-guard degeneration.** An explicit empty `collection`/`topic`
  made the `confirm != target` check pass (`"" == ""`); the purge tools now
  reject an empty target before the confirm check.
- **PreToolUse guard coverage.** The owned-store tripwire now catches
  psycopg3/asyncpg/pg8000 and `vault.db`/`kart.db`/`store.db` (a SOIL collection
  reached by absolute path); its known limits (a `python -c` one-liner, unlisted
  clients) are documented rather than overclaimed.
- **`willow-mcp gates`/`net-status`/`tree` crashed with an unhandled
  `BrokenPipeError` traceback when piped into something that closes early**
  (`willow-mcp gates | head`, `willow-mcp net-status app | grep -q active`) —
  found by wiring the CLI into a CI smoke test. These subcommands print
  multiple lines and are exactly the shape someone pipes into `head`/
  `grep -q`; a downstream reader closing before the writer finishes raises
  `BrokenPipeError` on the next write, which Python does not handle for you.
  `main()` now wraps its dispatch and exits clean (code 1) instead.
- **`pip install willow-mcp[worker]` was advertised but never existed (B-27).**
  The worker's "kartikeya is missing" errors, its `--help` text, and
  `task_queue.py`'s docstring all pointed at a `[worker]` extra; `pyproject.toml`
  declares no extras at all, and `kartikeya` has been a hard dependency since the
  B-22 close-out. The one message shown when a worker can't start told operators
  to run a command that errors. All four sites now say `pip install willow-mcp`.
- **Schema confirmation could accept a name match as truth (#20).**
  `schema_confirm_mapping` mapped canonical fields to real columns by name and
  confirmed without ever showing the data — so a `content` column that actually
  holds a provenance blob (with the real text in `title`/`summary`) would be
  confirmed as canonical `content`, and reads returned metadata instead of
  knowledge. `schema_confirm_mapping` now takes `preview=True` (dry-run:
  proposed mapping **plus** a rendered `sample` row, nothing written) and, on a
  real confirm, includes the same `sample` — confirmation is never blind. The
  `schema-confirm` skill requires reviewing the sample before confirming, and
  `diagnostic_summary` reports each table's field→column map so a
  confirmed-but-wrong mapping is visible in the self-check.
- `--port` / `--host` CLI flags were silently ignored in serve mode — the
  FastMCP object, base URL, and OAuth issuer are built at import time and never
  saw the argparse values. Resolved at import with precedence CLI > env > default.
- `task_*` / `fleet_health` referenced a nonexistent `kart_task_queue` table;
  pointed at the real `tasks` table.
- Security-audit hardening (Level 2 WLWR1) across the tool surface.

### Changed
- **`full_access` completeness.** Now includes `specialist_list` /
  `specialist_get` and the new store/gap read tools, matching the documented
  contract ("all gated tools except the egress lines `task_net` and
  `integration_call`"); `permissions-matrix.md` corrected to match. Bulk
  `gap_purge_topic` is its own opt-in `gap_purge` group (it soft-deletes across
  the fleet-shared gaps backlog), not folded into everyday `gap_write`.
- Repository is agent-neutral: removed personal/fleet-specific references from
  the public surface.

## [1.2.0] — 2026

### Added
- Full parameter descriptions and behavior annotations for all tools.

## [1.1.0] — 2026

### Added
- Multi-keyword AND search in `knowledge_search`.
- Record API and `WILLOW_STORE_ROOT` for pointing at an existing store root.

### Changed
- **Breaking**: aligned the SQLite store schema with willow-1.7's `WillowStore`.

## [1.0.0] — 2026

### Added
- Initial release: agent-neutral MCP server with a SQLite store (SOIL),
  Postgres knowledge base, and Kart task queue (11 tools).

[2.1.0]: https://pypi.org/project/willow-mcp/2.1.0/
[2.0.1]: https://pypi.org/project/willow-mcp/2.0.1/
[2.0.0]: https://github.com/rudi193-cmd/willow-mcp/releases
[1.2.0]: https://pypi.org/project/willow-mcp/1.2.0/
[1.1.0]: https://pypi.org/project/willow-mcp/1.1.0/
[1.0.0]: https://pypi.org/project/willow-mcp/1.0.0/
