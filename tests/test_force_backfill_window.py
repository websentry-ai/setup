"""How far back a forced re-walk reaches, for every installer a user runs directly.

The force request is one timestamp on the organization with no tool in it, so each
installer decides for itself where the walk starts. This is the arithmetic that decides
whether an org's request actually reaches the history it was asked to reach, and each
tool carries its own copy of it.
"""

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.conftest import load_module

# The installers a user runs for themselves. The MDM copies collect per profile behind a
# privilege drop, so their equivalent lives beside each tool.
USER_SCOPE = {
    "copilot/hooks/setup.py": None,
    "claude-code/hooks/setup.py": (".claude", "projects"),
    "codex/hooks/setup.py": (".codex", "sessions"),
}


def _forced_cutoff(relpath, force_days, persisted, tmp_path):
    """The mtime floor a forced run actually walks from."""
    module = load_module(relpath)
    seen = {}

    def _capture(*args):
        # copilot passes the cutoff alone; the others pass a root as well.
        seen["cutoff"] = args[-1]
        return iter(())

    root = USER_SCOPE[relpath]
    if root:
        (tmp_path / root[0] / root[1]).mkdir(parents=True)

    stack = [
        patch.object(module, "_backfill_read_cutoff", lambda home: persisted),
        patch.object(module, "_backfill_force_config", lambda *a: (1e12, force_days)),
        patch.object(module, "_backfill_iter_transcripts", _capture),
        patch.object(module, "_backfill_write_cutoff", lambda *a: None),
        patch.object(module, "Path", type("P", (), {"home": staticmethod(lambda: tmp_path)})),
    ]
    if hasattr(module, "_copilot_home"):
        stack.append(patch.object(module, "_copilot_home", lambda: tmp_path))
    for ctx in stack:
        ctx.start()
    try:
        module.run_backfill("key", "https://backend")
    finally:
        for ctx in reversed(stack):
            ctx.stop()
    return seen["cutoff"]


@pytest.mark.parametrize("relpath", sorted(USER_SCOPE))
class TestForceWindow:
    def test_the_window_widens_the_walk(self, relpath, tmp_path):
        cutoff = _forced_cutoff(relpath, 45, time.time() - 86400, tmp_path)
        assert abs((time.time() - cutoff) / 86400 - 45) < 1

    def test_no_window_keeps_the_installer_default(self, relpath, tmp_path):
        module = load_module(relpath)
        cutoff = _forced_cutoff(relpath, None, time.time() - 86400, tmp_path)
        assert abs((time.time() - cutoff) / 86400 - module.BACKFILL_MAX_AGE_DAYS) < 1

    def test_a_narrow_window_never_gives_up_ground_already_reached(self, relpath, tmp_path):
        # The run advances the cutoff on success, so anything a narrow window skips is
        # never visited again. Force may widen the walk; it may not shrink it.
        sixty_days_ago = time.time() - 60 * 86400
        cutoff = _forced_cutoff(relpath, 10, sixty_days_ago, tmp_path)
        assert abs(cutoff - sixty_days_ago) < 2


# The managed installers, which collect per profile behind a privilege drop. One run
# walks several homes under a single device key, and profiles backfill at different
# times, so a request can cover some and not others.
MDM = sorted(s for s in ("copilot/hooks/mdm/setup.py",
                         "claude-code/hooks/mdm/setup.py",
                         "codex/hooks/mdm/setup.py"))


@pytest.mark.parametrize("relpath", MDM)
class TestForceStaysScopedToTheProfilesBehind:
    """Sessions from a profile that is not behind the request must never ride an upload
    asserting force, or that profile's settled sessions get reopened."""

    @staticmethod
    def _uploads(relpath, collect_by_user):
        module = load_module(relpath)
        uploads = []

        def _fake_run_as_user(username, fn, *args, **kwargs):
            if fn is module._backfill_collect_sessions:
                return collect_by_user[username]
            return None

        def _fake_send(api_key, backend_url, sessions, forced=False):
            uploads.append((sorted(s["session_id"] for s in sessions), forced))
            return len(sessions), 1, 0

        stack = [
            patch.object(module, "_run_as_user", _fake_run_as_user),
            patch.object(module, "_backfill_force_config", lambda *a: (1000.0, None)),
            patch.object(module, "_backfill_send_sessions", _fake_send),
        ]
        if hasattr(module, "get_device_identifier"):
            stack.append(patch.object(module, "get_device_identifier", lambda: "serial"))
        for ctx in stack:
            ctx.start()
        try:
            homes = [(u, Path("/home/%s" % u)) for u in collect_by_user]
            module.run_backfill("key", "https://backend", homes)
        finally:
            for ctx in reversed(stack):
                ctx.stop()
        return uploads

    def test_a_forced_and_an_unforced_profile_upload_separately(self, relpath):
        uploads = self._uploads(relpath, {
            # (sessions, capped, forced)
            "alice": ([{"session_id": "A1", "entries": [{}]}], False, True),
            "bob": ([{"session_id": "B1", "entries": [{}]}], False, False),
        })
        assert len(uploads) == 2, uploads
        assert (["A1"], True) in uploads
        assert (["B1"], False) in uploads

    def test_one_profile_behind_does_not_force_the_others_sessions(self, relpath):
        uploads = self._uploads(relpath, {
            "alice": ([{"session_id": "A1", "entries": [{}]}], False, True),
            "bob": ([{"session_id": "B1", "entries": [{}]},
                     {"session_id": "B2", "entries": [{}]}], False, False),
        })
        forced = [ids for ids, is_forced in uploads if is_forced]
        assert forced == [["A1"]], "only the profile behind may be forced: %s" % uploads


@pytest.mark.parametrize("relpath", MDM)
class TestOneProfileCannotSinkTheDevice:
    """One MDM run walks every profile on the machine under a single device key. A
    profile with nothing to contribute must cost that profile nothing, not the run."""

    def test_a_profile_with_no_history_returns_the_shape_the_caller_unpacks(self, relpath, tmp_path):
        # run_backfill unpacks three. Returning two raises ValueError out of the
        # collector, and the run's own except swallows it as "skipped due to error",
        # taking every remaining profile with it.
        module = load_module(relpath)
        result = module._backfill_collect_sessions(tmp_path / "no-such-home", 1e12, 45)
        assert len(result) == 3, result
        sessions, capped, forced = result
        assert sessions == [] and capped is False

    def test_an_empty_profile_does_not_stop_the_others(self, relpath, tmp_path):
        module = load_module(relpath)
        uploaded = []

        def _fake_run_as_user(username, fn, *args, **kwargs):
            if fn is not module._backfill_collect_sessions:
                return None
            if username == "empty":
                # The real collector's answer for a home with no transcript directory.
                return module._backfill_collect_sessions(tmp_path / "no-such-home", *args[1:])
            return ([{"session_id": "S1", "entries": [{}]}], False, False)

        stack = [
            patch.object(module, "_run_as_user", _fake_run_as_user),
            patch.object(module, "_backfill_force_config", lambda *a: (1000.0, None)),
            patch.object(module, "_backfill_send_sessions",
                         lambda *a, **k: (uploaded.extend(a[2]), (len(a[2]), 1, 0))[1]),
        ]
        if hasattr(module, "get_device_identifier"):
            stack.append(patch.object(module, "get_device_identifier", lambda: "serial"))
        for ctx in stack:
            ctx.start()
        try:
            module.run_backfill("key", "https://backend",
                                [("empty", tmp_path / "empty"), ("busy", tmp_path / "busy")])
        finally:
            for ctx in reversed(stack):
                ctx.stop()

        assert [s["session_id"] for s in uploaded] == ["S1"], (
            "the profile with history must still upload")
