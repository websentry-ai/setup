"""
Regression tests for the Stop-event duplicate-count bug in the claude-code hook.

Background
----------
Claude Code fires multiple `Stop` events per user turn (one per agent turn).
`process_stop_event` rebuilds the exchange window from the persisted audit log:
it resets the window on each `UserPromptSubmit` and appends every event after.
Commit 16d1ffe removed the post-send prune of already-shipped events (to fix a
`get_recent_user_prompts_for_session` lookback regression). With the prune gone,
every Stop re-shipped ALL PostToolUse events accumulated since the last
UserPromptSubmit, so one file edit got counted 1 + 2 + ... + N times across N
Stops.

These tests pin both halves of the contract:
  - each PostToolUse tool_use is shipped exactly once across multiple Stops
    (idempotent), and
  - the user-prompt lookback still returns prior prompts (what 16d1ffe protected).
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


def _entry(session_id, hook_event_name, timestamp, **event_fields):
    event = {'session_id': session_id, 'hook_event_name': hook_event_name}
    event.update(event_fields)
    return {'timestamp': timestamp, 'session_id': session_id, 'event': event}


class StopDedupTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.audit_log = self.tmp / "agent-audit.log"
        self._audit_patcher = patch.object(unbound, "AUDIT_LOG", self.audit_log)
        self._audit_patcher.start()
        self.addCleanup(self._audit_patcher.stop)

        # Capture every exchange handed to send_to_api; pretend the send
        # succeeded so the shipped-marker path runs.
        self.sent_exchanges = []

        def _fake_send(exchange, api_key):
            self.sent_exchanges.append(exchange)
            return True

        self._send_patcher = patch.object(unbound, "send_to_api", _fake_send)
        self._send_patcher.start()
        self.addCleanup(self._send_patcher.stop)

        # Identity probe shells out / reads config; stub it.
        self._identity_patcher = patch.object(
            unbound, "build_account_identity", lambda probe=False: {}
        )
        self._identity_patcher.start()
        self.addCleanup(self._identity_patcher.stop)

    def _write_log(self, entries):
        unbound.save_logs(entries)

    def _all_shipped_tool_paths(self):
        """Flatten every tool_use file_path shipped across all sends."""
        paths = []
        for exchange in self.sent_exchanges:
            for msg in exchange.get('messages', []):
                for tu in msg.get('tool_use', []) or []:
                    paths.append(tu.get('tool_input', {}).get('file_path'))
        return paths


class TestStopEventIdempotent(StopDedupTestBase):
    """Multiple Stops in one turn must ship each tool_use exactly once."""

    def _turn_with_two_edits(self):
        sid = "sess-1"
        return [
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:00:00Z',
                   prompt='please edit two files'),
            _entry(sid, 'PostToolUse', '2026-06-15T00:00:01Z',
                   tool_name='Edit', tool_input={'file_path': '/a.py'},
                   tool_response={'ok': True}),
            _entry(sid, 'PostToolUse', '2026-06-15T00:00:02Z',
                   tool_name='Edit', tool_input={'file_path': '/b.py'},
                   tool_response={'ok': True}),
        ]

    def _stop_event(self, sid="sess-1", msg="done"):
        return {
            'session_id': sid,
            'hook_event_name': 'Stop',
            'transcript_path': 'undefined',
            'last_assistant_message': msg,
        }

    def test_single_stop_ships_each_tool_once(self):
        self._write_log(self._turn_with_two_edits())

        unbound.process_stop_event(self._stop_event(), api_key='k')

        paths = self._all_shipped_tool_paths()
        self.assertEqual(sorted(paths), ['/a.py', '/b.py'])

    def test_repeated_stops_do_not_reship(self):
        # The bug: 2nd/3rd Stop in the same turn re-ship the same tool_uses.
        self._write_log(self._turn_with_two_edits())

        for _ in range(3):
            unbound.process_stop_event(self._stop_event(), api_key='k')

        paths = self._all_shipped_tool_paths()
        # Exactly one tool_use per edited file across ALL Stops — no inflation.
        self.assertEqual(sorted(paths), ['/a.py', '/b.py'])

    def test_new_tool_after_first_stop_is_shipped_once(self):
        # First Stop ships /a.py. Then a new edit lands and a second Stop fires:
        # /b.py must ship, /a.py must NOT ship again.
        sid = "sess-1"
        self._write_log([
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:00:00Z', prompt='go'),
            _entry(sid, 'PostToolUse', '2026-06-15T00:00:01Z',
                   tool_name='Edit', tool_input={'file_path': '/a.py'},
                   tool_response={'ok': True}),
        ])
        unbound.process_stop_event(self._stop_event(), api_key='k')

        # A new PostToolUse arrives (as main() would append it), then Stop again.
        unbound.append_to_audit_log(
            _entry(sid, 'PostToolUse', '2026-06-15T00:00:03Z',
                   tool_name='Edit', tool_input={'file_path': '/b.py'},
                   tool_response={'ok': True})
        )
        unbound.process_stop_event(self._stop_event(), api_key='k')

        paths = self._all_shipped_tool_paths()
        self.assertEqual(sorted(paths), ['/a.py', '/b.py'])

    def test_stop_with_nothing_new_does_not_send(self):
        # A turn with only a prompt and an already-shipped edit: a redundant
        # Stop must not produce any send at all.
        self._write_log(self._turn_with_two_edits())
        unbound.process_stop_event(self._stop_event(), api_key='k')
        sends_after_first = len(self.sent_exchanges)

        unbound.process_stop_event(self._stop_event(), api_key='k')
        self.assertEqual(len(self.sent_exchanges), sends_after_first)

    def test_tool_free_turn_ships_exactly_once(self):
        # A pure-conversation turn (no PostToolUse) must still ship once — and
        # only once — across multiple Stops. Guards against over-narrowing the
        # send to tool-bearing turns only.
        sid = "sess-1"
        self._write_log([
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:00:00Z',
                   prompt='just answer, no tools'),
        ])

        for _ in range(3):
            unbound.process_stop_event(self._stop_event(msg='here is the answer'),
                                       api_key='k')

        self.assertEqual(len(self.sent_exchanges), 1)


class TestLookbackStillWorks(StopDedupTestBase):
    """The thing 16d1ffe protected: prior user prompts remain in the log and are
    returned by get_recent_user_prompts_for_session after Stops are processed."""

    def test_prior_prompts_survive_stop_processing(self):
        sid = "sess-1"
        self._write_log([
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:00:00Z', prompt='first prompt'),
            _entry(sid, 'PostToolUse', '2026-06-15T00:00:01Z',
                   tool_name='Edit', tool_input={'file_path': '/a.py'},
                   tool_response={'ok': True}),
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:01:00Z', prompt='second prompt'),
            _entry(sid, 'PostToolUse', '2026-06-15T00:01:01Z',
                   tool_name='Edit', tool_input={'file_path': '/b.py'},
                   tool_response={'ok': True}),
        ])

        stop = {
            'session_id': sid,
            'hook_event_name': 'Stop',
            'transcript_path': 'undefined',
            'last_assistant_message': 'done',
        }
        # Process a couple of Stops, which is when the old code wiped the log.
        unbound.process_stop_event(stop, api_key='k')
        unbound.process_stop_event(stop, api_key='k')

        prompts = unbound.get_recent_user_prompts_for_session(sid, n=5)
        self.assertEqual(prompts, ['first prompt', 'second prompt'])

    def test_shipped_marker_does_not_drop_postooluse_entries(self):
        # Marking entries shipped must keep them in the log (size unchanged),
        # only annotate them — otherwise rotation/lookback assumptions break.
        sid = "sess-1"
        self._write_log([
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:00:00Z', prompt='go'),
            _entry(sid, 'PostToolUse', '2026-06-15T00:00:01Z',
                   tool_name='Edit', tool_input={'file_path': '/a.py'},
                   tool_response={'ok': True}),
        ])
        before = len(unbound.load_existing_logs())

        stop = {
            'session_id': sid,
            'hook_event_name': 'Stop',
            'transcript_path': 'undefined',
            'last_assistant_message': 'done',
        }
        unbound.process_stop_event(stop, api_key='k')

        after_logs = unbound.load_existing_logs()
        # Nothing is dropped — entries are annotated in place, not pruned.
        self.assertEqual(len(after_logs), before)
        # The PostToolUse entry is now flagged shipped.
        flagged_tools = [
            l for l in after_logs
            if l.get(unbound.SHIPPED_FLAG)
            and l.get('event', {}).get('hook_event_name') == 'PostToolUse'
        ]
        self.assertEqual(len(flagged_tools), 1)


if __name__ == '__main__':
    unittest.main()
