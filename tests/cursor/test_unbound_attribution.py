"""Unbound attribution footer, driven through Cursor's preToolUse and
beforeShellExecution entry points.

With the org setting on, every block the hook itself decides ends its
user_message with "Enforced by Unbound · Trace ID <id>"; with it off, output
is unchanged. agent_message never carries the footer."""

import json
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests.conftest import tool_module

unbound = tool_module("cursor")

TRACE_ID = '3f2b8c1e-5d4a-4e9b-9c7f-1a2b3c4d5e6f'
FOOTER = '\n\nEnforced by Unbound · Trace ID ' + TRACE_ID
ORG_POLICY = {
    'id': 12, 'name': 'Block Non-Unbound Repos',
    'github_org': 'unboundsec',
    'repositories': [], 'include_forks': False,
}
REPO_BLOCK_REASON = (
    'Blocked by organization policy. "acme/widgets" is outside your '
    'organization\'s allowed repository scope.'
)
APPROVAL_REQUIRED = {
    'decision': 'approval_required',
    'approvalCheck': {'policyIds': ['p1'], 'applicationId': 'a1', 'requestId': 'r1'},
    'unbound_trace_id': TRACE_ID,
}
HOLD = 'An approval request has been sent to your Slack DMs. Please approve it there.'


class AttributionCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.post = MagicMock()
        self.poll = MagicMock(return_value='deny')
        self._patches = [
            patch.object(unbound, 'POLICY_CACHE_FILE', self.tmp / '.policy_cache.json'),
            patch.object(unbound, '_APPROVAL_MARKER_FILE', self.tmp / '.approval_pending'),
            patch.object(unbound, 'AUDIT_LOG', self.tmp / 'agent-audit.log'),
            patch.object(unbound, 'ERROR_LOG', self.tmp / 'error.log'),
            patch.object(unbound, '_repo_gate_post', self.post),
            patch.object(unbound, '_cached_api_key', 'KEY'),
            patch.object(unbound, 'poll_approval_status', self.poll),
            patch.object(unbound, 'report_error_to_gateway'),
            patch.object(unbound, 'build_account_identity', return_value={}),
            patch.object(unbound, 'get_recent_user_prompts_for_session', return_value=[]),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def write(self, file_path='/work/notes.md', gateway=None):
        event = {'hook_event_name': 'preToolUse', 'conversation_id': 'C1',
                 'tool_name': 'Write', 'tool_input': {'file_path': str(file_path)}}
        with patch.object(unbound, 'send_to_hook_api', return_value=gateway):
            return unbound.process_pre_tool_use(event, 'KEY')

    def shell(self, gateway=None):
        event = {'hook_event_name': 'beforeShellExecution', 'conversation_id': 'C1',
                 'command': 'ls', 'cwd': str(self.tmp)}
        with patch.object(unbound, 'send_to_hook_api', return_value=gateway):
            return unbound.process_pre_tool_use_execution(event, 'KEY', 'Shell', 'ls')

    def set_attribution(self, enabled, **cache):
        unbound.save_policy_cache(tools_to_check=['Write'], unbound_attribution_enabled=enabled, **cache)

    def out_of_scope_file(self):
        root = self.tmp / 'widgets'
        root.mkdir()
        subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin',
                        'https://github.com/acme/widgets.git'], check=True, capture_output=True)
        return root / 'main.py'


class TestAttributionCache(AttributionCase):
    def test_gateway_flag_round_trips_through_cache(self):
        self.shell(gateway={'decision': 'allow', 'tools_to_check': [], 'unbound_attribution_enabled': True})
        self.assertTrue(unbound.get_unbound_attribution_enabled())

        # A later policy pull that omits the flag keeps the cached value.
        self.shell(gateway={'decision': 'allow', 'tools_to_check': ['Write']})
        self.assertTrue(unbound.get_unbound_attribution_enabled())

        self.shell(gateway={'decision': 'allow', 'unbound_attribution_enabled': False})
        self.assertFalse(unbound.get_unbound_attribution_enabled())

    def test_missing_or_corrupt_cache_defaults_off(self):
        self.assertFalse(unbound.get_unbound_attribution_enabled())
        unbound.POLICY_CACHE_FILE.write_text('not json')
        self.assertFalse(unbound.get_unbound_attribution_enabled())


class TestRepoGateAttribution(AttributionCase):
    def test_on_reports_trace_id_and_shows_it_last(self):
        self.set_attribution(True, repo_policies=[ORG_POLICY])
        response = self.write(self.out_of_scope_file())

        (call,) = self.post.call_args_list
        trace_id = json.loads(call.args[0])['repo_gate']['trace_id']
        self.assertEqual(str(uuid.UUID(trace_id)), trace_id)
        self.assertEqual(response['user_message'],
                         REPO_BLOCK_REASON + '\n\nEnforced by Unbound · Trace ID ' + trace_id)
        self.assertNotIn('Enforced by Unbound', response['agent_message'])

    def test_off_is_unchanged(self):
        self.set_attribution(False, repo_policies=[ORG_POLICY])
        response = self.write(self.out_of_scope_file())

        (call,) = self.post.call_args_list
        self.assertNotIn('trace_id', json.loads(call.args[0])['repo_gate'])
        self.assertEqual(response['user_message'], REPO_BLOCK_REASON)


class TestApprovalAttribution(AttributionCase):
    def test_hold_ends_with_footer_and_marker_keeps_id(self):
        for run in (self.write, self.shell):
            with self.subTest(run=run.__name__):
                response = run(gateway=APPROVAL_REQUIRED)
                self.assertEqual(response['user_message'], HOLD + FOOTER)
                self.assertNotIn('Enforced by Unbound', response['agent_message'])
                marker = json.loads(unbound._APPROVAL_MARKER_FILE.read_text())
                self.assertEqual(marker['unboundTraceId'], TRACE_ID)

    def test_hold_without_trace_id_is_unchanged(self):
        gateway = dict(APPROVAL_REQUIRED)
        del gateway['unbound_trace_id']
        self.assertEqual(self.write(gateway=gateway)['user_message'], HOLD)

    def test_slack_denial_reuses_trace_id(self):
        self.poll.return_value = 'deny'
        self.write(gateway=APPROVAL_REQUIRED)
        self.assertEqual(self.write()['user_message'],
                         'Blocked by organization policy. This action was denied via Slack.' + FOOTER)
        self.shell(gateway=APPROVAL_REQUIRED)
        self.assertEqual(self.shell()['user_message'],
                         'Blocked by organization policy. This command was denied via Slack.' + FOOTER)

    def test_timeout_reuses_trace_id(self):
        self.poll.return_value = 'timeout'
        self.write(gateway=APPROVAL_REQUIRED)
        self.assertEqual(self.write()['user_message'],
                         'Blocked by organization policy. Approval request timed out — '
                         'check your Slack DMs and retry.' + FOOTER)
        self.shell(gateway=APPROVAL_REQUIRED)
        self.assertEqual(self.shell()['user_message'],
                         'Blocked by organization policy. Approval request timed out — '
                         'check your Slack DMs and retry the command.' + FOOTER)


class TestUnreachableAttribution(AttributionCase):
    def test_block_on_ends_with_footer_without_id(self):
        self.set_attribution(True, policy_check_failure_action='block')
        for run in (self.write, self.shell):
            with self.subTest(run=run.__name__):
                self.assertEqual(run(gateway=None)['user_message'],
                                 'policy engine unavailable — please retry\n\nEnforced by Unbound')

    def test_block_off_is_unchanged(self):
        self.set_attribution(False, policy_check_failure_action='block')
        for run in (self.write, self.shell):
            with self.subTest(run=run.__name__):
                self.assertEqual(run(gateway=None)['user_message'],
                                 'policy engine unavailable — please retry')


if __name__ == '__main__':
    unittest.main()
