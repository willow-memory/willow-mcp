"""The one reach's bootstrap copy in willow-mcp (flatten-2 F6.5; D-a: "I am thinking all
need to import it"). Unused by the package yet; it is held here to prove it
is willow-bot's template byte for byte, that it reaches the one script when
beside, and that it says ``unreachable`` when not.

Reach is by filesystem only: willow-mcp does not depend on willow-bot, and an
installed server with no willow-bot beside it (and no ``ONESCRIPT_HOME``)
gets ``unreachable`` with a reason naming ``ONESCRIPT_HOME``.

The template is ``onescript/reach_bootstrap.py`` in the one script, found the
way the copy finds it (CI sets ``ONESCRIPT_HOME`` to its willow-bot checkout).
Locally, with no willow-bot beside, the beside-tests skip and say so; in CI
(``CI`` is set) they fail instead.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from willow_mcp import onescript_reach

COPY = Path(onescript_reach.__file__).resolve()


def _home():
    return onescript_reach.where()["onescript"]


def _beside_or_say_why(path):
    if path is not None and path.is_file():
        return
    if os.environ.get("CI"):
        pytest.fail(f"CI has no willow-bot beside: {path}")
    pytest.skip(f"no willow-bot beside (set ONESCRIPT_HOME): {path}")


def test_the_copy_is_the_template_byte_for_byte():
    home = _home()
    template = home / "onescript" / "reach_bootstrap.py" if home else None
    _beside_or_say_why(template)
    assert COPY.read_bytes() == template.read_bytes()


def test_it_reaches_the_one_script_when_beside():
    home = _home()
    _beside_or_say_why(home / "onescript" / "reach.py" if home else None)
    got = onescript_reach.reach(law=False)
    assert got["state"] == "reachable" and got["onescript"] == home
    assert onescript_reach.module("states").STATES[-1] == "unreachable"


def test_it_says_unreachable_when_not(tmp_path):
    gone = tmp_path / "nowhere"
    got = onescript_reach.reach(home=gone)
    assert got["state"] == "unreachable"
    assert "ONESCRIPT_HOME" in got["why"] and str(gone) in got["why"]
    with pytest.raises(onescript_reach.Unreachable, match="ONESCRIPT_HOME"):
        onescript_reach.module("states", home=gone)


def test_installed_with_no_checkout_and_no_env_it_names_the_variable(tmp_path):
    """An installed server: the copy sits in no git checkout, no env is set."""
    lone = tmp_path / "onescript_reach.py"
    lone.write_bytes(COPY.read_bytes())
    code = (
        "import onescript_reach as r; got = r.reach(); "
        "assert got['state'] == 'unreachable', got; print(got['why'])"
    )
    env = {
        k: v for k, v in os.environ.items() if k not in ("ONESCRIPT_HOME", "ONESCRIPT_GROVE")
    }
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=tmp_path, env=env, check=False, capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert "ONESCRIPT_HOME" in out.stdout
