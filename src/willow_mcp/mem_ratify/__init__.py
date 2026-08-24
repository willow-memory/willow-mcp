# Vendored from willow (willow-memory/Willow, mem_ratify/__init__.py), Apache-2.0.
# See ratify.py's header for why this is a vendored copy and not a dependency.
# Kept byte-for-byte from the module docstring onward (this header excepted).
"""mem_ratify — Article IV Canon-promotion gate (advisory, off-by-default).

See ``mem_ratify/ratify.py`` and ``mem_ratify/README.md``. Importing this
package changes no behavior; it only exposes the pure decision function.
"""

from .ratify import (  # noqa: F401
    CANONICAL_MIN_WITNESSES,
    ENFORCE_ENV_VAR,
    FRONTIER_MIN_WITNESSES,
    REQUIRE_STEPWISE_PROMOTION,
    Decision,
    RatifyRequest,
    Tier,
    Witness,
    enforcement_enabled,
    ratify,
)

__all__ = [
    "Tier",
    "Witness",
    "RatifyRequest",
    "Decision",
    "ratify",
    "enforcement_enabled",
    "ENFORCE_ENV_VAR",
    "FRONTIER_MIN_WITNESSES",
    "CANONICAL_MIN_WITNESSES",
    "REQUIRE_STEPWISE_PROMOTION",
]
