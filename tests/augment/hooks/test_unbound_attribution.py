"""Unbound attribution footer, driven through process_pre_tool_use.

Augment renders only permissionDecisionReason, which folds in additionalContext
after a blank line. With the org setting on, every block ends with
"Enforced by Unbound · Trace ID <id>" after that context; with it off, output
is unchanged."""

import json
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests.conftest import tool_module

unbound = tool_module("augment/hooks")

TRACE_ID = '3f2b8c1e-5d4a-4e9b-9c7f-1a2b3c4d5e6f'
FOOTER = '\n\nEnforced by Unbound · Trace ID ' + TRACE_ID
ORG_POLICY = {
    'id': 12, 'name': 'Block Non-Unbound Repos',
    'github_org': 'unboundsec',
    'repositories': [], 'include_forks': False,
}
PATH_BLOCK_REASON = (
    'Blocked by organization policy. This action works in the repository '
    '"acme/widgets", which is outside your organization\'s allowed repository '
    'scope. Move this work to an in-scope repository.'
)
WORKSPACE_BLOCK_REASON = (
    'Blocked by organization policy. This workspace is the repository '
    '"acme/widgets", which is outside your organization\'s allowed repository '
    'scope, so every tool call here is blocked. Move this work to an in-scope '
    'repository and start a new session there.'
)
APPROVAL_REQUIRED = {
    'decision': 'approval_required',
    'approvalCheck': {'policyIds': ['p1'], 'applicationId': 'a1', 'requestId': 'r1'},
    'unbound_trace_id': TRACE_ID,
}


class AttributionCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.post = MagicMock()
        self.poll = MagicMock(return_value='deny')
        self._patches = [
            patch.object(Path, 'home', return_value=self.tmp),
            patch.object(unbound, 'POLICY_CACHE_FILE', self.tmp / '.policy_cache.json'),
            patch.object(unbound, '_APPROVAL_MARKER_FILE', self.tmp / '.approval_pending'),
            patch.object(unbound, 'AUDIT_LOG', self.tmp / 'agent-audit.log'),
            patch.object(unbound, 'ERROR_LOG', self.tmp / 'error.log'),
            patch.object(unbound, '_repo_gate_post', self.post),
            patch.object(unbound, '_cached_api_key', 'KEY'),
            patch.object(unbound, '_device_serial', return_value=None),
            patch.object(unbound, 'poll_approval_status', self.poll),
            patch.object(unbound, 'report_error_to_gateway'),
            patch.object(unbound, 'build_account_identity', return_value={}),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def run_tool(self, tool_name, tool_input, cwd=None, gateway=None):
        event = {
            'hook_event_name': 'PreToolUse', 'session_id': 'S1', 'is_mcp_tool': False,
            'tool_name': tool_name, 'tool_input': tool_input, 'cwd': str(cwd or self.tmp),
        }
        with patch.object(unbound, 'send_to_hook_api', return_value=gateway):
            return unbound.process_pre_tool_use(event, 'KEY')

    def shell(self, gateway=None):
        return self.run_tool('launch-process', {'command': 'ls'}, gateway=gateway)

    def reason(self, response):
        """The user-visible text with the model context Augment splices in removed,
        after checking the context sits before the footer."""
        shown = response['hookSpecificOutput']['permissionDecisionReason']
        body, context = shown.split('\n\n', 1)
        footer_at = context.find('\n\nEnforced by Unbound')
        if footer_at == -1:
            return body
        self.assertNotIn('Enforced by Unbound', context[:footer_at])
        return body + context[footer_at:]

    def set_attribution(self, enabled, **cache):
        unbound.save_policy_cache(tools_to_check=['launch-process'],
                                  unbound_attribution_enabled=enabled, **cache)

    def out_of_scope_repo(self):
        root = self.tmp / 'widgets'
        root.mkdir()
        subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin',
                        'https://github.com/acme/widgets.git'], check=True, capture_output=True)
        return root

    def assert_reported_trace_id(self):
        (call,) = self.post.call_args_list
        trace_id = json.loads(call.args[0])['repo_gate']['trace_id']
        self.assertEqual(str(uuid.UUID(trace_id)), trace_id)
        return trace_id

    def assert_reported_without_trace_id(self):
        (call,) = self.post.call_args_list
        self.assertNotIn('trace_id', json.loads(call.args[0])['repo_gate'])


class TestAttributionCache(AttributionCase):
    def test_gateway_flag_round_trips_through_cache(self):
        self.shell(gateway={'decision': 'allow', 'tools_to_check': [], 'unbound_attribution_enabled': True})
        self.assertTrue(unbound.get_unbound_attribution_enabled())

        # A later policy pull that omits the flag keeps the cached value.
        self.shell(gateway={'decision': 'allow', 'tools_to_check': ['launch-process']})
        self.assertTrue(unbound.get_unbound_attribution_enabled())

        self.shell(gateway={'decision': 'allow', 'unbound_attribution_enabled': False})
        self.assertFalse(unbound.get_unbound_attribution_enabled())

    def test_missing_or_corrupt_cache_defaults_off(self):
        self.assertFalse(unbound.get_unbound_attribution_enabled())
        unbound.POLICY_CACHE_FILE.write_text('not json')
        self.assertFalse(unbound.get_unbound_attribution_enabled())


class TestRepoGateAttribution(AttributionCase):
    def write_out_of_scope(self):
        path = self.out_of_scope_repo() / 'main.py'
        return self.run_tool('save-file', {'path': str(path), 'file_content': 'x'})

    def write_in_out_of_scope_workspace(self):
        repo = self.out_of_scope_repo()
        return self.run_tool('save-file', {'path': 'main.py', 'file_content': 'x'}, cwd=repo)

    def test_path_gate_on_reports_trace_id_and_shows_it_last(self):
        self.set_attribution(True, repo_policies=[ORG_POLICY])
        response = self.write_out_of_scope()
        trace_id = self.assert_reported_trace_id()
        self.assertEqual(self.reason(response),
                         PATH_BLOCK_REASON + '\n\nEnforced by Unbound · Trace ID ' + trace_id)

    def test_path_gate_off_is_unchanged(self):
        self.set_attribution(False, repo_policies=[ORG_POLICY])
        response = self.write_out_of_scope()
        self.assert_reported_without_trace_id()
        self.assertEqual(self.reason(response), PATH_BLOCK_REASON)

    def test_workspace_gate_on_reports_trace_id_and_shows_it_last(self):
        self.set_attribution(True, repo_policies=[ORG_POLICY])
        response = self.write_in_out_of_scope_workspace()
        trace_id = self.assert_reported_trace_id()
        self.assertEqual(self.reason(response),
                         WORKSPACE_BLOCK_REASON + '\n\nEnforced by Unbound · Trace ID ' + trace_id)

    def test_workspace_gate_off_is_unchanged(self):
        self.set_attribution(False, repo_policies=[ORG_POLICY])
        response = self.write_in_out_of_scope_workspace()
        self.assert_reported_without_trace_id()
        self.assertEqual(self.reason(response), WORKSPACE_BLOCK_REASON)


class TestApprovalAttribution(AttributionCase):
    def test_hold_ends_with_footer_and_marker_keeps_id(self):
        response = self.shell(gateway=APPROVAL_REQUIRED)
        self.assertEqual(
            self.reason(response),
            'An approval request has been sent to your Slack DMs. Please approve it there.' + FOOTER)
        marker = json.loads(unbound._APPROVAL_MARKER_FILE.read_text())
        self.assertEqual(marker['unboundTraceId'], TRACE_ID)

    def test_hold_without_trace_id_is_unchanged(self):
        gateway = dict(APPROVAL_REQUIRED)
        del gateway['unbound_trace_id']
        self.assertEqual(
            self.reason(self.shell(gateway=gateway)),
            'An approval request has been sent to your Slack DMs. Please approve it there.')

    def test_slack_denial_reuses_trace_id(self):
        self.shell(gateway=APPROVAL_REQUIRED)
        self.poll.return_value = 'deny'
        self.assertEqual(
            self.reason(self.shell()),
            'Blocked by organization policy. This command was denied via Slack.' + FOOTER)

    def test_timeout_reuses_trace_id(self):
        self.shell(gateway=APPROVAL_REQUIRED)
        self.poll.return_value = 'timeout'
        self.assertEqual(
            self.reason(self.shell()),
            'Blocked by organization policy. Approval request timed out — '
            'check your Slack DMs and retry the command.' + FOOTER)


class TestGatewayFooterOrdering(AttributionCase):
    def test_footer_moves_after_additional_context(self):
        response = self.shell(gateway={
            'decision': 'deny', 'reason': 'Blocked by policy X.' + FOOTER,
            'additionalContext': 'Do not retry.', 'unbound_trace_id': TRACE_ID,
        })
        self.assertEqual(response['hookSpecificOutput']['permissionDecisionReason'],
                         'Blocked by policy X.\n\nDo not retry.' + FOOTER)

    def test_without_trace_id_is_unchanged(self):
        response = self.shell(gateway={
            'decision': 'deny', 'reason': 'Blocked by policy X.',
            'additionalContext': 'Do not retry.',
        })
        self.assertEqual(response['hookSpecificOutput']['permissionDecisionReason'],
                         'Blocked by policy X.\n\nDo not retry.')


class TestUnreachableAttribution(AttributionCase):
    def test_block_on_ends_with_footer_without_id(self):
        self.set_attribution(True, policy_check_failure_action='block')
        self.assertEqual(self.reason(self.shell(gateway=None)),
                         'policy engine unavailable — please retry\n\nEnforced by Unbound')

    def test_block_off_is_unchanged(self):
        self.set_attribution(False, policy_check_failure_action='block')
        self.assertEqual(self.reason(self.shell(gateway=None)),
                         'policy engine unavailable — please retry')


if __name__ == '__main__':
    unittest.main()
