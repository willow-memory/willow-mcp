"""scrub_reach.py -- RETIRED. Tombstone (flatten-2 F12, retired in the integration).

This was willow-mcp's one door to ``onescript/scrub.py``, through
``onescript_reach``. It put the one script on the trust-owner path: keyring ->
net_signer -> unit_install_executor -> pull_executor -> push_executor ->
scrub_reach -> onescript_reach (and unit_status -> secret_scan likewise).
The operator's ruling, 2026-10-21 ("1 yes"): trust-owner code never reaches the
one script, "and anything they import, lazily too". "2 carry copies": willow-mcp
carries parity-tested copies so an installed server still works.

So every willow-mcp scrub caller (secret_scan, push_executor, observability,
nest/secrets) now imports ``scrub_local``, a byte copy of the one script's
``onescript/scrub.py``, held to it by ``tests/test_scrub_parity.py``. The home
of the rule is still ``onescript/scrub.py`` in willow-bot's one-script. Nothing
imports this module.
"""
