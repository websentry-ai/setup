"""Backward-compat + robustness of `unbound-hook setup` argument parsing.

The MDM onboarding wrapper builds this argv, and already-deployed policies still
pass a stale ``--discovery-key``. ``_parse_args`` must accept and ignore it
WITHOUT swallowing the flag that follows it, and a plain ``--api-key`` setup must
still parse. None of this was covered before, and the swallow-next-arg case is a
real bug class: a valueless flag that eats the following flag silently drops it.
"""

from unbound_hook import setup_cmd


def test_api_key_alone_parses():
    opts = setup_cmd._parse_args(["--api-key", "admin-key"])
    assert opts is not None
    assert opts["api_key"] == "admin-key"


def test_discovery_key_with_value_accepted_and_ignored():
    # A stale "--discovery-key <value>" is consumed and ignored; the rest parses.
    opts = setup_cmd._parse_args(
        ["--api-key", "k", "--discovery-key", "stale", "--backfill"]
    )
    assert opts is not None
    assert opts["api_key"] == "k"
    assert opts["backfill"] is True
    assert "discovery_key" not in opts  # ignored, never stored


def test_discovery_key_does_not_swallow_the_next_flag():
    # "--discovery-key" immediately followed by another flag must NOT eat that
    # flag. Pre-fix it stored "--backfill" as the value and dropped --backfill.
    opts = setup_cmd._parse_args(["--api-key", "k", "--discovery-key", "--backfill"])
    assert opts is not None
    assert opts["backfill"] is True, "the next flag was swallowed by --discovery-key"


def test_trailing_discovery_key_without_value_is_tolerated():
    # A trailing valueless "--discovery-key" must not crash or reject the setup.
    opts = setup_cmd._parse_args(["--api-key", "k", "--discovery-key"])
    assert opts is not None
    assert opts["api_key"] == "k"


def test_discovery_key_before_api_key_still_parses_api_key():
    # Position independence: the stale flag first must not hide --api-key.
    opts = setup_cmd._parse_args(["--discovery-key", "stale", "--api-key", "k"])
    assert opts is not None
    assert opts["api_key"] == "k"
