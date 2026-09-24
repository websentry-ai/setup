"""
Tests for the Copilot cloud agent path in copilot/hooks/unbound.py.

Everything here guards a failure that is silent: the sandbox sends no event name, so an
unresolved one captures nothing at all, and a preToolUse that outruns its timeout is killed
and fails OPEN. RUNNING_CLOUD is read at import, so the call-time readers are patched.
"""

import unittest
from unittest.mock import patch

from tests.conftest import tool_module

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


class TestCloudPreToolBudget(unittest.TestCase):
    """A preToolUse killed by the hook timeout fails open, so the budget must fit inside it."""

    def _attempts(self, cloud):
        with patch.object(unbound, 'RUNNING_CLOUD', cloud), \
                patch.object(unbound.subprocess, 'run',
                             side_effect=unbound.subprocess.TimeoutExpired('curl', 1)) as run, \
                patch.object(unbound.time, 'sleep'):
            unbound.send_to_hook_api({'a': 1}, 'key')
        return [call.kwargs['timeout'] for call in run.call_args_list]

    def test_cloud_budget_stays_well_inside_the_configured_timeout(self):
        timeouts = self._attempts(True)
        self.assertEqual(timeouts, [8, 8])
        self.assertLess(sum(timeouts), 60)

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
