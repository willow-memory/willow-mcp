"""A retired home must refuse the implicit fallback, and only the implicit one.

Written after six `allow-permission` commands succeeded, printed success, and
reached nothing: the operator's shell had no `WILLOW_HOME`, so `willow_home()`
fell back to `~/.willow` — a tombstoned pre-migration tree that still held its
own `fleet.json`, `vault.key`, `dispatch_signing.key` and a full `mcp_apps/`.
The live seat kept its old manifest. Nothing in the output said so.

The property under test is narrow: an *unchosen* default that has been retired
fails loudly, while an *explicit* `WILLOW_HOME` is honoured whatever it points
at, because that is what a migration tool needs.
"""
from __future__ import annotations

import pytest

from willow_mcp import paths


@pytest.fixture(autouse=True)
def clear_cache():
    paths._retired_home_cache.clear()
    yield
    paths._retired_home_cache.clear()


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """A `~` whose `.willow` we control, with WILLOW_HOME unset."""
    monkeypatch.delenv("WILLOW_HOME", raising=False)
    monkeypatch.setattr(paths.Path, "home", staticmethod(lambda: tmp_path))
    home = tmp_path / ".willow"
    home.mkdir()
    return home


def _retire(home):
    (home / paths.TOMBSTONE_MARKER).write_text("retired\n", encoding="utf-8")


# ── the fallback ─────────────────────────────────────────────────────────────

def test_a_live_default_still_resolves(fake_home):
    assert paths.willow_home() == fake_home


def test_a_retired_default_is_refused(fake_home):
    _retire(fake_home)
    with pytest.raises(paths.RetiredHomeError) as e:
        paths.willow_home()
    assert str(fake_home) in str(e.value)
    assert "WILLOW_HOME" in str(e.value)


def test_the_refusal_says_why_it_matters(fake_home):
    """A message that only says 'retired' invites the reader to force past it."""
    _retire(fake_home)
    with pytest.raises(paths.RetiredHomeError) as e:
        paths.willow_home()
    assert "reach nothing" in str(e.value)


def test_a_missing_default_is_not_retired(tmp_path, monkeypatch):
    """No directory at all is an ordinary first run, not a tombstone."""
    monkeypatch.delenv("WILLOW_HOME", raising=False)
    monkeypatch.setattr(paths.Path, "home", staticmethod(lambda: tmp_path))
    assert paths.willow_home() == tmp_path / ".willow"


def test_a_marker_that_is_a_directory_does_not_trip_the_guard(fake_home):
    """`is_file()`, not `exists()` — a directory of that name is not a marker."""
    (fake_home / paths.TOMBSTONE_MARKER).mkdir()
    assert paths.willow_home() == fake_home


# ── the explicit override ────────────────────────────────────────────────────

def test_an_explicit_home_is_honoured_even_when_retired(fake_home, monkeypatch):
    """The one job that must still work: reading the old home on purpose."""
    _retire(fake_home)
    monkeypatch.setenv("WILLOW_HOME", str(fake_home))
    assert paths.willow_home() == fake_home


def test_an_explicit_home_elsewhere_ignores_the_default_entirely(
        fake_home, tmp_path, monkeypatch):
    _retire(fake_home)
    live = tmp_path / "box"
    monkeypatch.setenv("WILLOW_HOME", str(live))
    assert paths.willow_home() == live


# ── the memo ─────────────────────────────────────────────────────────────────

def test_the_check_is_memoised_per_path(fake_home):
    """willow_home() is called on nearly every operation; one stat per path."""
    _retire(fake_home)
    with pytest.raises(paths.RetiredHomeError):
        paths.willow_home()
    assert paths._retired_home_cache == {str(fake_home): True}

    # Marker removed, but the answer is already cached — deliberately. A home
    # that changes retirement status under a running process is a restart,
    # the same reasoning keyring.get_keyring() gives for its own cache.
    (fake_home / paths.TOMBSTONE_MARKER).unlink()
    with pytest.raises(paths.RetiredHomeError):
        paths.willow_home()


def test_an_unreadable_default_is_treated_as_live(fake_home, monkeypatch):
    """Fail *open* here on purpose. This guard exists to stop a silent write to
    a known-dead home, not to become a new way for a path lookup to die."""
    def _boom(self):
        raise OSError("permission denied")

    monkeypatch.setattr(paths.Path, "is_file", _boom)
    assert paths.willow_home() == fake_home
