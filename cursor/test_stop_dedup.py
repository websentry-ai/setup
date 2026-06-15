"""
Regression tests for the Stop-event duplicate-count guard in the cursor hook.

Cursor groups audit events by generation_id and process_stop_event ships only
the generation matching the incoming stop. That isolates turns better than the
claude-code hook, but if a generation_id ever receives more than one `stop`
event the exchange (and its tool_uses) would be re-shipped — the same
duplicate-count class fixed in 16d1ffe's wake.

These tests pin the contract:
  - a generation is shipped exactly once even if `stop` fires twice for it, and
  - prior user prompts remain in the audit log for the lookback.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


def _entry(conversation_id, generation_id, hook_event_name, timestamp, **fields):
    event = {
        'conversation_id': conversation_id,
        'generation_id': generation_id,
        'hook_event_name': hook_event_name,
    }
    event.update(fields)
    return {'timestamp': timestamp, 'event': event}


class CursorStopDedupBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.audit_log = self.tmp / "agent-audit.log"
        self._audit_patcher = patch.object(unbound, "AUDIT_LOG", self.audit_log)
        self._audit_patcher.start()
        self.addCleanup(self._audit_patcher.stop)

        self.sent_exchanges = []
        self._send_patcher = patch.object(
            unbound, "send_to_api",
            lambda exchange, api_key=None: self.sent_exchanges.append(exchange) or True,
        )
        self._send_patcher.start()
        self.addCleanup(self._send_patcher.stop)

        self._serial_patcher = patch.object(
            unbound, "_device_serial", lambda probe=False: None
        )
        self._serial_patcher.start()
        self.addCleanup(self._serial_patcher.stop)

    def _generation(self, conv="conv-1", gen="gen-1"):
        return [
            _entry(conv, gen, 'beforeSubmitPrompt', '2026-06-15T00:00:00Z', prompt='go'),
            _entry(conv, gen, 'afterFileEdit', '2026-06-15T00:00:01Z',
                   file_path='/a.py', edits=[{'old': 'x', 'new': 'y'}]),
            _entry(conv, gen, 'afterAgentResponse', '2026-06-15T00:00:02Z', text='done'),
            _entry(conv, gen, 'stop', '2026-06-15T00:00:03Z'),
        ]


class TestCursorStopIdempotent(CursorStopDedupBase):
    def test_repeated_stops_for_same_generation_ship_once(self):
        unbound.save_logs(self._generation())

        unbound.process_stop_event('gen-1', api_key='k')
        unbound.process_stop_event('gen-1', api_key='k')

        self.assertEqual(len(self.sent_exchanges), 1)

    def test_new_generation_ships_again(self):
        unbound.save_logs(self._generation(gen='gen-1'))
        unbound.process_stop_event('gen-1', api_key='k')

        for entry in self._generation(gen='gen-2'):
            unbound.append_to_audit_log(entry)
        unbound.process_stop_event('gen-2', api_key='k')

        self.assertEqual(len(self.sent_exchanges), 2)


class TestCursorLookback(CursorStopDedupBase):
    def test_prior_prompts_survive(self):
        logs = self._generation(gen='gen-1')
        logs += [
            _entry('conv-1', 'gen-2', 'beforeSubmitPrompt', '2026-06-15T00:01:00Z',
                   prompt='second'),
            _entry('conv-1', 'gen-2', 'stop', '2026-06-15T00:01:01Z'),
        ]
        unbound.save_logs(logs)

        unbound.process_stop_event('gen-1', api_key='k')
        unbound.process_stop_event('gen-1', api_key='k')

        prompts = unbound.get_recent_user_prompts_for_session('conv-1', 5)
        self.assertEqual(prompts, ['go', 'second'])


if __name__ == '__main__':
    unittest.main()
