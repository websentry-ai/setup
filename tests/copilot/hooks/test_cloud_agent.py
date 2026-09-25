"""
Tests for the Copilot cloud agent path in copilot/hooks/unbound.py.

Everything here guards a failure that is silent: the sandbox sends no event name, so an
unresolved one captures nothing at all, and a preToolUse that outruns its timeout is killed
and fails OPEN. RUNNING_CLOUD is read at import, so the call-time readers are patched.
"""

import json
import re
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from tests.conftest import REPO, tool_module

unbound = tool_module("copilot/hooks")

TRAILER = (
    'Add a thing\n\n'
    'Co-authored-by: Nanda Pranesh <12345+nandapranesh@users.noreply.github.com>\n'
)


class _Completed:
    def __init__(self, stdout=b'', returncode=0, stderr=b''):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class TestCloudEventName(unittest.TestCase):
    """The payload carries no event name; the loader passes the registered one through."""

    def test_every_registered_event_maps_to_a_dispatched_name(self):
        for declared, expected in unbound.CLOUD_EVENT_NAMES.items():
            with patch.dict(unbound.os.environ, {'UNBOUND_HOOK_EVENT': declared}):
                self.assertEqual(unbound._copilot_event_name({}), expected)

    def test_the_payloads_own_name_still_wins(self):
        with patch.dict(unbound.os.environ, {'UNBOUND_HOOK_EVENT': 'preToolUse'}):
            self.assertEqual(unbound._copilot_event_name({'hook_event_name': 'Stop'}), 'Stop')

    def test_an_unmapped_event_passes_through_rather_than_vanishing(self):
        with patch.dict(unbound.os.environ, {'UNBOUND_HOOK_EVENT': 'errorOccurred'}):
            self.assertEqual(unbound._copilot_event_name({}), 'errorOccurred')


class TestCloudEventNormalization(unittest.TestCase):
    """Audit rows are written as they arrive, and every reader matches snake_case names.

    A raw cloud row matches none of them — worst of all the previous-Stop lookup, which
    loses the turn's usage floor and reports the whole session's usage as that turn's.
    """

    def _normalize(self, event, name, cloud=True):
        with patch.object(unbound, 'RUNNING_CLOUD', cloud):
            return unbound._normalize_cloud_event(event, name)

    def test_the_resolved_name_is_written_onto_the_event(self):
        event = self._normalize({'sessionId': 's1'}, 'Stop')
        self.assertEqual(event['hook_event_name'], 'Stop')

    def test_camelcase_identity_is_mirrored_for_the_readers(self):
        event = self._normalize({'sessionId': 's1', 'transcriptPath': '/t.jsonl'}, 'Stop')
        self.assertEqual(event['session_id'], 's1')
        self.assertEqual(event['transcript_path'], '/t.jsonl')

    def test_a_normalized_stop_is_found_by_the_usage_floor_lookup(self):
        logs = [{'timestamp': 't1', 'event': self._normalize(
            {'sessionId': 's1', 'transcriptPath': '/t.jsonl'}, 'Stop')}]
        with patch.object(unbound, 'load_existing_logs', return_value=logs):
            self.assertEqual(unbound.get_previous_stop_timestamp_for_session({'transcript_path': '/t.jsonl'}), 't1')

    def test_a_raw_cloud_stop_is_invisible_to_that_lookup(self):
        logs = [{'timestamp': 't1', 'event': {'sessionId': 's1', 'transcriptPath': '/t.jsonl'}}]
        with patch.object(unbound, 'load_existing_logs', return_value=logs):
            self.assertIsNone(unbound.get_previous_stop_timestamp_for_session({'transcript_path': '/t.jsonl'}))

    def test_a_normalized_prompt_is_found_by_the_prompt_lookup(self):
        logs = [{'timestamp': 't1', 'event': self._normalize(
            {'sessionId': 's1', 'prompt': 'hello'}, 'UserPromptSubmit')}]
        with patch.object(unbound, 'load_existing_logs', return_value=logs):
            self.assertEqual(unbound.get_recent_user_prompts_for_session('s1', 5), ['hello'])

    def test_the_payloads_own_names_are_never_overwritten(self):
        event = self._normalize(
            {'hook_event_name': 'Stop', 'session_id': 'real', 'sessionId': 'other'}, 'SessionEnd')
        self.assertEqual(event['hook_event_name'], 'Stop')
        self.assertEqual(event['session_id'], 'real')

    def test_a_laptop_event_is_returned_untouched(self):
        original = {'sessionId': 's1', 'transcriptPath': '/t.jsonl'}
        self.assertIs(self._normalize(original, 'Stop', cloud=False), original)


class TestGithubActor(unittest.TestCase):
    """The sandbox names only the bot; the requester is the commit co-author."""

    def _run(self, env, completed):
        with patch.dict(unbound.os.environ, env, clear=True), \
                patch.object(unbound.subprocess, 'run', return_value=completed) as run:
            return unbound._github_actor(), run

    def test_takes_the_login_not_the_display_name(self):
        actor, _ = self._run({'COPILOT_AGENT_BASE_COMMIT': 'abc'}, _Completed(TRAILER.encode()))
        self.assertEqual(actor, 'nandapranesh')

    def test_reads_the_id_less_noreply_form_too(self):
        body = b'Fix\n\nCo-authored-by: Octo <octocat@users.noreply.github.com>\n'
        actor, _ = self._run({'COPILOT_AGENT_BASE_COMMIT': 'abc'}, _Completed(body))
        self.assertEqual(actor, 'octocat')

    def test_scoped_to_this_sessions_first_parent_commits(self):
        _, run = self._run({'COPILOT_AGENT_BASE_COMMIT': 'abc'}, _Completed(TRAILER.encode()))
        self.assertEqual(run.call_args[0][0],
                         ['git', 'log', 'abc..HEAD', '--first-parent', '--no-merges', '--format=%B'])

    def test_no_base_commit_means_no_unscoped_search(self):
        with patch.dict(unbound.os.environ, {}, clear=True), \
                patch.object(unbound.subprocess, 'run') as run:
            self.assertIsNone(unbound._github_actor())
            run.assert_not_called()

    def test_a_real_address_is_not_mistaken_for_a_login(self):
        body = b'Fix\n\nCo-authored-by: Nanda <nanda@unboundsecurity.ai>\n'
        actor, _ = self._run({'COPILOT_AGENT_BASE_COMMIT': 'abc'}, _Completed(body))
        self.assertIsNone(actor)

    def test_a_failed_git_log_yields_nothing(self):
        actor, _ = self._run({'COPILOT_AGENT_BASE_COMMIT': 'abc'},
                             _Completed(b'', returncode=128, stderr=b'bad revision'))
        self.assertIsNone(actor)


class TestGithubContext(unittest.TestCase):
    def test_a_laptop_sends_no_github_block(self):
        with patch.object(unbound, 'RUNNING_CLOUD', False):
            self.assertIsNone(unbound.build_github_context())

    def test_provenance_is_repo_session_and_trigger(self):
        env = {'GITHUB_REPOSITORY': 'websentry-ai/setup',
               'COPILOT_AGENT_SESSION_ID': 'sess-1',
               'COPILOT_JOB_EVENT_TYPE': 'issues'}
        with patch.object(unbound, 'RUNNING_CLOUD', True), \
                patch.dict(unbound.os.environ, env, clear=True), \
                patch.object(unbound, '_github_actor', return_value='octocat'):
            self.assertEqual(unbound.build_github_context(),
                             {'actor': 'octocat', 'repo': 'websentry-ai/setup',
                              'session': 'sess-1', 'event': 'issues'})

    def test_absent_fields_are_dropped_rather_than_sent_empty(self):
        with patch.object(unbound, 'RUNNING_CLOUD', True), \
                patch.dict(unbound.os.environ, {'COPILOT_AGENT_SESSION_ID': 'sess-1'}, clear=True), \
                patch.object(unbound, '_github_actor', return_value=None):
            self.assertEqual(unbound.build_github_context(), {'session': 'sess-1'})


class TestCloudSurface(unittest.TestCase):
    """The cloud agent is a fourth Copilot surface, named on the same field as the rest."""

    def test_a_cloud_session_names_itself_whatever_the_transcript_is(self):
        with patch.object(unbound, 'RUNNING_CLOUD', True):
            self.assertEqual(unbound.copilot_surface('/tmp/session/events.jsonl'), 'cloud')
            self.assertEqual(unbound.copilot_surface(None), 'cloud')

    def test_the_laptop_surfaces_are_unchanged(self):
        with patch.object(unbound, 'RUNNING_CLOUD', False):
            self.assertEqual(unbound.copilot_surface('/x/events.jsonl'), 'cli')
            self.assertEqual(unbound.copilot_surface('/x/chat.json'), 'vscode')
            self.assertIsNone(unbound.copilot_surface(None))


class TestCloudUntrustedTmpState(unittest.TestCase):
    """/tmp is agent-writable, so sandbox state that can produce an allow is not read."""

    def test_a_planted_policy_cache_cannot_wave_a_native_write_through(self):
        planted = {'last_synced': datetime.utcnow().isoformat() + 'Z', 'tools_to_check': []}
        with patch.object(unbound, 'RUNNING_CLOUD', True), \
                patch.object(unbound, 'load_policy_cache', return_value=planted) as loader, \
                patch.object(unbound, 'send_to_hook_api', return_value={}) as gateway, \
                patch.object(unbound, 'get_session_start_model', return_value='auto'), \
                patch.object(unbound, 'get_recent_user_prompts_for_session', return_value=[]):
            unbound._evaluate_pre_tool_use_policies(
                {'tool_name': 'Write', 'tool_input': {'filePath': '/workspace/x.py'},
                 'session_id': 's1'}, 'key')
        loader.assert_not_called()
        self.assertTrue(gateway.called, 'the write short-circuited without asking the gateway')

    def test_the_laptop_still_uses_its_cache(self):
        with patch.object(unbound, 'RUNNING_CLOUD', False), \
                patch.object(unbound, 'load_policy_cache', return_value=None) as loader, \
                patch.object(unbound, 'send_to_hook_api', return_value={}), \
                patch.object(unbound, 'get_session_start_model', return_value='auto'), \
                patch.object(unbound, 'get_recent_user_prompts_for_session', return_value=[]):
            unbound._evaluate_pre_tool_use_policies(
                {'tool_name': 'Write', 'tool_input': {'filePath': '/x.py'}, 'session_id': 's1'},
                'key')
        loader.assert_called_once()


class TestCloudAuditTail(unittest.TestCase):
    """An oversized audit log must not stall preToolUse into its fail-open timeout."""

    def _log_with(self, tmp, rows, filler_bytes=0):
        path = Path(tmp) / 'agent-audit.log'
        with open(path, 'w', encoding='utf-8') as f:
            if filler_bytes:
                f.write(json.dumps({'event': {'pad': 'x' * filler_bytes}}) + '\n')
            for row in rows:
                f.write(json.dumps(row) + '\n')
        return path

    def test_an_oversized_log_is_read_from_the_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = [{'timestamp': 't%d' % i, 'event': {'hook_event_name': 'Stop'}}
                    for i in range(3)]
            path = self._log_with(tmp, rows, filler_bytes=unbound.CLOUD_AUDIT_READ_LIMIT)
            with patch.object(unbound, 'RUNNING_CLOUD', True), \
                    patch.object(unbound, 'AUDIT_LOG', path):
                logs = unbound.load_existing_logs()
        self.assertEqual([log['timestamp'] for log in logs], ['t0', 't1', 't2'])

    def test_a_log_under_the_limit_is_read_whole(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = [{'timestamp': 't0', 'event': {'hook_event_name': 'Stop'}}]
            path = self._log_with(tmp, rows)
            with patch.object(unbound, 'RUNNING_CLOUD', True), \
                    patch.object(unbound, 'AUDIT_LOG', path):
                self.assertEqual(len(unbound.load_existing_logs()), 1)


class TestCloudPreToolBudget(unittest.TestCase):
    """A preToolUse killed by the hook timeout fails open, so the budget must fit inside it."""

    def _attempts(self, cloud):
        with patch.object(unbound, 'RUNNING_CLOUD', cloud), \
                patch.object(unbound.subprocess, 'run',
                             side_effect=unbound.subprocess.TimeoutExpired('curl', 1)) as run, \
                patch.object(unbound.time, 'sleep'):
            unbound.send_to_hook_api({'a': 1}, 'key')
        return [call.kwargs['timeout'] for call in run.call_args_list]

    # GitHub kills a hook at timeoutSec, which DEFAULTS TO 30 even though the config asks
    # for 60. Assert against the default: the config's value may simply not be honoured,
    # and being wrong here means a killed preToolUse, which fails OPEN.
    HOOK_TIMEOUT_FLOOR = 30

    def _loader_fetch_budget(self):
        """The -m the loader spends fetching the hook, read from the loader itself so the
        two files cannot drift apart into a total that no longer fits."""
        loader = (REPO / 'copilot/cloud/unbound.sh').read_text()
        match = re.search(r'curl [^\n]*?-m (\d+)', loader)
        self.assertIsNotNone(match, 'loader no longer caps its fetch')
        return int(match.group(1))

    def test_the_whole_pretool_budget_fits_inside_the_default_timeout(self):
        timeouts = self._attempts(True)
        self.assertEqual(timeouts, [8, 8])
        # +0.5s per gap between attempts; the loader's fetch is spent before any of it.
        total = self._loader_fetch_budget() + sum(timeouts) + 0.5 * (len(timeouts) - 1)
        self.assertLess(total, self.HOOK_TIMEOUT_FLOOR,
                        'worst case %.1fs exceeds the %ds default; preToolUse would be '
                        'killed and fail OPEN' % (total, self.HOOK_TIMEOUT_FLOOR))

    def test_the_laptop_budget_is_unchanged(self):
        self.assertEqual(self._attempts(False), [20, 20, 20])


class TestCloudApprovalRetry(unittest.TestCase):
    def test_a_planted_marker_never_starts_a_poll_in_the_sandbox(self):
        with patch.object(unbound, 'RUNNING_CLOUD', True), \
                patch.object(unbound.Path, 'exists', return_value=True) as exists:
            self.assertFalse(unbound._is_approval_retry('rm -rf /'))
            exists.assert_not_called()


if __name__ == '__main__':
    unittest.main()
