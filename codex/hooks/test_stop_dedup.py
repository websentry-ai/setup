"""
Regression tests for the Stop-event duplicate-count bug in the codex hook.

Like the claude-code hook, codex fires multiple `Stop` events per user turn and
`process_stop_event` rebuilds the exchange each time. Codex sources its
tool_uses from the transcript (scoped by the turn's user-prompt timestamp), so a
second Stop in the same turn re-ships the same tool_uses. Commit 16d1ffe removed
the post-send prune, so nothing stopped the resend.

These tests pin the contract:
  - a turn is shipped exactly once across multiple Stops (idempotent), and
  - prior user prompts remain in the audit log for the lookback.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


def _entry(session_id, hook_event_name, timestamp, **event_fields):
    event = {'session_id': session_id, 'hook_event_name': hook_event_name}
    event.update(event_fields)
    return {'timestamp': timestamp, 'session_id': session_id, 'event': event}


class CodexStopDedupBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.audit_log = self.tmp / "agent-audit.log"
        self._audit_patcher = patch.object(unbound, "AUDIT_LOG", self.audit_log)
        self._audit_patcher.start()
        self.addCleanup(self._audit_patcher.stop)

        self.sent_exchanges = []
        self._send_patcher = patch.object(
            unbound, "send_to_api",
            lambda exchange, api_key: self.sent_exchanges.append(exchange) or True,
        )
        self._send_patcher.start()
        self.addCleanup(self._send_patcher.stop)

        # Codex sources tool_uses from the transcript — stub it to a fixed set.
        self._tools_patcher = patch.object(
            unbound, "parse_codex_transcript_for_tools",
            lambda path, ts=None: [
                {'type': 'PostToolUse', 'tool_name': 'apply_patch',
                 'tool_input': {'file_path': '/a.py'}, 'tool_response': {}},
            ],
        )
        self._tools_patcher.start()
        self.addCleanup(self._tools_patcher.stop)

        self._usage_patcher = patch.object(
            unbound, "parse_codex_transcript_for_usage", lambda path, ts=None: None
        )
        self._usage_patcher.start()
        self.addCleanup(self._usage_patcher.stop)

    def _stop(self, sid="sess-1"):
        return {
            'session_id': sid,
            'hook_event_name': 'Stop',
            'transcript_path': '/transcript.jsonl',
            'last_assistant_message': 'done',
        }


class TestCodexStopIdempotent(CodexStopDedupBase):
    def test_repeated_stops_ship_turn_once(self):
        sid = "sess-1"
        unbound.save_logs([
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:00:00Z', prompt='go'),
        ])

        for _ in range(3):
            unbound.process_stop_event(self._stop(), api_key='k')

        # The turn is shipped exactly once across all three Stops.
        self.assertEqual(len(self.sent_exchanges), 1)

    def test_new_turn_ships_again(self):
        sid = "sess-1"
        unbound.save_logs([
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:00:00Z', prompt='first'),
        ])
        unbound.process_stop_event(self._stop(), api_key='k')

        # A new prompt opens a new turn — it must ship.
        unbound.append_to_audit_log(
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:01:00Z', prompt='second')
        )
        unbound.process_stop_event(self._stop(), api_key='k')

        self.assertEqual(len(self.sent_exchanges), 2)


class TestCodexLookback(CodexStopDedupBase):
    def test_prior_prompts_survive(self):
        sid = "sess-1"
        unbound.save_logs([
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:00:00Z', prompt='first'),
            _entry(sid, 'UserPromptSubmit', '2026-06-15T00:01:00Z', prompt='second'),
        ])
        unbound.process_stop_event(self._stop(), api_key='k')
        unbound.process_stop_event(self._stop(), api_key='k')

        prompts = unbound.get_recent_user_prompts_for_session(sid, n=5)
        self.assertEqual(prompts, ['first', 'second'])


if __name__ == '__main__':
    unittest.main()
