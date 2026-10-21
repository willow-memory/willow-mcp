"""onescript_reach.py -- find the one script, then hand off to ``onescript.reach``.

THIS FILE IS A COPY. The template is willow-bot's
``one-script/onescript/reach_bootstrap.py``; every consuming repo carries it
byte for byte as ``onescript_reach.py`` and a test holds it there. Edit the
template, then copy it out; never edit a copy.

Why it exists (flatten-2 F6.5): a repo cannot import the reach from the one
script before it has found the one script. This is the only part that cannot
live there: it finds the one script, puts it on ``sys.path`` and hands off.
Everything after that, and every "why" the one script can make, is
``onescript.reach``'s. The operator: "Using the onescript at every path."

It looks at ``home`` if given, else ``$ONESCRIPT_HOME``, else
``<repos>/willow-bot/one-script``, where ``<repos>`` is the directory holding
the git checkout this file sits in (found by walking up to a ``.git``). The
law is ``grove``, else ``$ONESCRIPT_GROVE``, else ``<repos>/willows-grove``.
Inside no git checkout (an installed package) and with no env, there is
nowhere to look: ``unreachable``, with a reason naming ``ONESCRIPT_HOME``.
It never guesses a path and never falls back to a copy of the one script.

Imports only the standard library. Reach is by filesystem only: a consumer
does not declare willow-bot as a dependency.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

ENV_HOME = "ONESCRIPT_HOME"
ENV_GROVE = "ONESCRIPT_GROVE"


class Unreachable(RuntimeError):
    """The one script, or the law it reads, is not where it was looked for."""


def _repos():
    for d in Path(__file__).resolve().parents:
        if (d / ".git").exists():
            return d.parent
    return None


def where(home=None, grove=None) -> dict:
    """Where the one script and the law are looked for (a path, or None)."""
    repos = _repos()
    home = home or os.environ.get(ENV_HOME)
    grove = grove or os.environ.get(ENV_GROVE)
    return {
        "onescript": Path(home).expanduser()
        if home
        else (repos / "willow-bot" / "one-script" if repos else None),
        "grove": Path(grove).expanduser()
        if grove
        else (repos / "willows-grove" if repos else None),
    }


def _handoff(w):
    home = w["onescript"]
    if home is None:
        raise Unreachable(
            "no one-script: this copy sits in no git checkout, so there is no "
            f"sibling to look beside (set {ENV_HOME})"
        )
    if not (home / "onescript" / "reach.py").is_file():
        raise Unreachable(f"no one-script at {home} (set {ENV_HOME})")
    if str(home) not in sys.path:
        sys.path.insert(0, str(home))
    try:
        return importlib.import_module("onescript.reach")
    except ImportError as e:
        raise Unreachable(f"the one-script at {home} would not import: {e}") from e


def reach(home=None, grove=None, law: bool = True) -> dict:
    """``{"state": "reachable", "onescript", "grove"}`` or
    ``{"state": "unreachable", "why"}`` (``onescript.reach.reach``)."""
    w = where(home, grove)
    try:
        r = _handoff(w)
    except Unreachable as e:
        return {"state": "unreachable", "why": str(e)}
    return r.reach(home=w["onescript"], grove=w["grove"], law=law)


def module(name: str, home=None):
    """One of the one script's modules (``onescript.<name>``). Raises
    ``Unreachable`` (with why) when it is not there."""
    w = where(home)
    r = _handoff(w)
    try:
        return r.module(name, home=w["onescript"])
    except r.Unreachable as e:
        raise Unreachable(str(e)) from e
