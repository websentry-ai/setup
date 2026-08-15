"""Repo-scope gate tests, driven through process_pre_tool_use against real git repos on disk."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import unbound


def _make_repo(root: Path, origin: str) -> Path:
    """A real git repo at `root` with `origin` set, holding one file."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '-q', str(root)], check=True,
                   capture_output=True)
    subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin', origin],
                   check=True, capture_output=True)
    src = root / 'src'
    src.mkdir(exist_ok=True)
    (src / 'main.py').write_text('x = 1\n', encoding='utf-8')
    return root


ORG_POLICY = {
    'id': 12, 'name': 'Block Non-Unbound Repos',
    'github_org': 'unboundsec',
    'repositories': [], 'include_forks': False,
    'grace_turns': 2,
}


class RepoGateCase(unittest.TestCase):
    """Isolates the policy cache and gate state onto a temp dir, and builds an
    in-scope repo, an out-of-scope repo, and a plain non-repo directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        state_dir = self.tmp / 'state'
        state_dir.mkdir()
        self.cache_file = state_dir / '.policy_cache.json'
        self.gate_file = state_dir / '.repo_gate_state.json'
        self.audit_log = state_dir / 'agent-audit.log'
        # The seam for incident reporting: _repo_gate_post is the only thing on
        # that path that touches the network, so patching it both records what
        # would have been sent and keeps a real curl out of the test suite.
        self.post = MagicMock()
        self.real_post = unbound._repo_gate_post
        self._patches = [
            patch.object(unbound, 'POLICY_CACHE_FILE', self.cache_file),
            patch.object(unbound, 'REPO_GATE_STATE_FILE', self.gate_file),
            # main() audit-logs the prompt event; keep it off the real log.
            patch.object(unbound, 'AUDIT_LOG', self.audit_log),
            patch.object(unbound, 'ERROR_LOG', state_dir / 'error.log'),
            patch.object(unbound, '_repo_gate_post', self.post),
            # main() caches the key in a module global that outlives the test.
            patch.object(unbound, '_cached_api_key', 'KEY'),
        ]
        for p in self._patches:
            p.start()

        self.in_scope = _make_repo(self.tmp / 'work' / 'setup',
                                   'git@github.com:unboundsec/setup.git')
        self.out_scope = _make_repo(self.tmp / 'work' / 'widgets',
                                    'https://github.com/acme/widgets.git')
        self.no_repo = self.tmp / 'notes'
        (self.no_repo / 'deep').mkdir(parents=True)
        (self.no_repo / 'deep' / 'todo.md').write_text('hi\n', encoding='utf-8')

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    # -- helpers ---------------------------------------------------------

    def set_policies(self, policies, tools_to_check=None):
        unbound.save_policy_cache(tools_to_check=tools_to_check or [],
                                  repo_policies=policies)

    def run_tool(self, tool_name, tool_input, prompt_id='turn-1',
                 session_id='S1', cwd=None, gateway=None, prompts=None):
        event = {
            'hook_event_name': 'PreToolUse',
            'session_id': session_id,
            'prompt_id': prompt_id,
            'tool_name': tool_name,
            'tool_input': tool_input,
            'cwd': cwd or str(self.tmp),
        }
        if prompt_id is None:
            del event['prompt_id']
        with patch.object(unbound, 'send_to_hook_api', return_value=gateway or {}), \
             patch.object(unbound, 'report_error_to_gateway'), \
             patch.object(unbound, 'build_account_identity', return_value={}), \
             patch.object(unbound, 'get_recent_user_prompts_for_session',
                          return_value=prompts or []):
            return unbound.process_pre_tool_use(event, 'KEY')

    def write_file(self, repo: Path, **kw):
        """The default gated file call: a write, not a read. Reads are out of scope entirely."""
        return self.run_tool('Edit', {'file_path': str(repo / 'src' / 'main.py'),
                                      'old_string': 'x', 'new_string': 'y'}, **kw)

    def read_file(self, repo: Path, **kw):
        return self.run_tool('Read', {'file_path': str(repo / 'src' / 'main.py')}, **kw)

    def bash(self, command, **kw):
        return self.run_tool('Bash', {'command': command}, **kw)

    def run_prompt(self, cwd=None, prompt_id='turn-1', session_id='S1',
                   prompt='fix the bug', gateway=None):
        """Drive a whole UserPromptSubmit through main(), the real entry point
        the session gate is wired into, and return the JSON it printed. The
        gateway stub is left on self.api for call assertions."""
        event = {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': session_id,
            'prompt_id': prompt_id,
            'prompt': prompt,
            'cwd': cwd if cwd is not None else str(self.tmp),
        }
        if prompt_id is None:
            del event['prompt_id']
        if cwd is None:
            del event['cwd']
        out = io.StringIO()
        self.api = MagicMock(return_value=gateway or {})
        with patch.object(sys, 'stdin', io.StringIO(json.dumps(event))), \
             patch.object(sys, 'stdout', out), \
             patch.object(unbound, 'get_api_key', return_value='KEY'), \
             patch.object(unbound, 'build_account_identity', return_value={}), \
             patch.object(unbound, 'report_error_to_gateway'), \
             patch.object(unbound, 'send_to_hook_api', self.api):
            unbound.main()
        return json.loads(out.getvalue().strip() or '{}')

    # -- prompt-path assertions -------------------------------------------

    def assertPromptAllowed(self, response):
        self.assertNotEqual(response.get('decision'), 'block')
        self.assertNotIn('outside your organization', json.dumps(response))

    # assertPromptWarned/assertPromptBlocked are gone: a prompt is never gated now.

    # -- incident reports --------------------------------------------------

    def reports(self):
        """Every incident report dispatched so far, decoded."""
        return [json.loads(call.args[0]) for call in self.post.call_args_list]

    def assertNoReports(self):
        self.assertEqual(self.reports(), [])

    def assertOneReport(self, decision, repo, surface, **extra):
        """Exactly one report, carrying the fields the analytics row is keyed
        on. Cardinality is the point of `assertEqual(len(...), 1)`: one gate
        verdict must produce one report, never a duplicate pair."""
        got = self.reports()
        self.assertEqual(len(got), 1, got)
        report = got[0]
        self.assertEqual(report['decision'], decision)
        self.assertEqual(report['repository'], repo)
        self.assertEqual(report['surface'], surface)
        self.assertEqual(report['agent'], 'claude-code')
        self.assertEqual(report['policy_id'], ORG_POLICY['id'])
        self.assertEqual(report['policy_name'], ORG_POLICY['name'])
        for key, value in extra.items():
            self.assertEqual(report[key], value, report)
        return report

    def grace_used(self):
        """Grace burned so far, per the on-disk state file."""
        if not self.gate_file.exists():
            return 0
        return json.loads(self.gate_file.read_text(encoding='utf-8'))['used']

    # -- assertions ------------------------------------------------------

    def assertAllowed(self, response):
        out = response.get('hookSpecificOutput') or {}
        self.assertNotIn('permissionDecision', out)
        self.assertNotIn('warning', json.dumps(response).lower())

    def assertWarned(self, response, repo, remaining_phrase=None):
        out = response.get('hookSpecificOutput') or {}
        self.assertNotIn('permissionDecision', out)
        context = out.get('additionalContext') or ''
        self.assertIn(repo, context)
        if remaining_phrase:
            self.assertIn(remaining_phrase, context)
        # The developer sees the warning too, not just the model.
        self.assertIn(repo, response.get('systemMessage') or '')

    def assertBlocked(self, response, repo):
        out = response.get('hookSpecificOutput') or {}
        self.assertEqual(out.get('permissionDecision'), 'deny')
        self.assertIn(repo, out.get('permissionDecisionReason') or '')


class TestCoreDecisions(RepoGateCase):
    def test_path_inside_allowed_org_is_allowed(self):
        self.set_policies([ORG_POLICY])
        self.assertAllowed(self.write_file(self.in_scope))
        self.assertEqual(self.grace_used(), 0)

    def test_out_of_org_warns_warns_then_blocks(self):
        self.set_policies([ORG_POLICY])  # grace_turns: 2
        self.assertWarned(self.write_file(self.out_scope, prompt_id='t1'),
                          'acme/widgets', '1 warning left')
        self.assertEqual(self.grace_used(), 1)

        self.assertWarned(self.write_file(self.out_scope, prompt_id='t2'),
                          'acme/widgets', 'final warning')
        self.assertEqual(self.grace_used(), 2)

        self.assertBlocked(self.write_file(self.out_scope, prompt_id='t3'),
                           'acme/widgets')
        self.assertEqual(self.grace_used(), 2, 'a block must not burn grace')

        # Still blocked on every later turn.
        self.assertBlocked(self.write_file(self.out_scope, prompt_id='t4'),
                           'acme/widgets')

    def test_many_violating_calls_in_one_turn_burn_one_grace(self):
        self.set_policies([ORG_POLICY])
        for _ in range(20):
            response = self.write_file(self.out_scope, prompt_id='same-turn')
            self.assertWarned(response, 'acme/widgets')
        self.assertEqual(self.grace_used(), 1)

    def test_burned_turn_never_escalates_to_block_midway(self):
        """A turn granted its last warning keeps it for all of its calls."""
        self.set_policies([dict(ORG_POLICY, grace_turns=1)])
        self.assertWarned(self.write_file(self.out_scope, prompt_id='t1'),
                          'acme/widgets')
        self.assertWarned(self.write_file(self.out_scope, prompt_id='t1'),
                          'acme/widgets')
        self.assertBlocked(self.write_file(self.out_scope, prompt_id='t2'),
                           'acme/widgets')

    def test_no_git_anywhere_above_is_allowed(self):
        self.set_policies([ORG_POLICY])
        response = self.run_tool(
            'Write', {'file_path': str(self.no_repo / 'deep' / 'todo.md'),
                      'content': 'x'})
        self.assertAllowed(response)
        self.assertEqual(self.grace_used(), 0)

    def test_grace_zero_blocks_immediately(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        self.assertBlocked(self.write_file(self.out_scope), 'acme/widgets')
        self.assertEqual(self.grace_used(), 0)

    def test_new_session_resets_grace(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=1)])
        self.assertWarned(self.write_file(self.out_scope, prompt_id='t1'),
                          'acme/widgets')
        self.assertBlocked(self.write_file(self.out_scope, prompt_id='t2'),
                           'acme/widgets')
        self.assertWarned(
            self.write_file(self.out_scope, prompt_id='t1', session_id='S2'),
            'acme/widgets')

    def test_write_and_edit_are_gated(self):
        self.set_policies([ORG_POLICY])
        target = str(self.out_scope / 'src' / 'main.py')
        self.assertWarned(
            self.run_tool('Edit', {'file_path': target, 'old_string': 'x',
                                   'new_string': 'y'}, prompt_id='t1'),
            'acme/widgets')
        self.assertWarned(
            self.run_tool('NotebookEdit',
                          {'notebook_path': str(self.out_scope / 'nb.ipynb')},
                          prompt_id='t2'),
            'acme/widgets')

    def test_turn_identity_falls_back_to_user_prompt(self):
        """Clients too old to send prompt_id still burn one grace per turn."""
        self.set_policies([ORG_POLICY])
        for _ in range(3):
            self.write_file(self.out_scope, prompt_id=None, prompts=['fix the bug'])
        self.assertEqual(self.grace_used(), 1)
        self.write_file(self.out_scope, prompt_id=None, prompts=['now ship it'])
        self.assertEqual(self.grace_used(), 2)


class TestUnidentifiableTurn(RepoGateCase):
    """A client that sends no prompt_id and has no user prompt to hash leaves
    the turn unidentifiable. REPO_GATE_UNKNOWN_TURN records that as an unknown,
    not as an identity — memoizing it the way a real turn id is memoized would
    create one bucket that is entered once and never left, freezing the counter
    one short of the limit and warning forever. That is the defect that made
    Copilot's tool calls never escalate; the arbitration is shared, so it is
    pinned here too."""

    def test_unknown_turn_escalates_per_call(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=2)])
        for _ in range(2):
            self.assertWarned(self.write_file(self.out_scope, prompt_id=None),
                              'acme/widgets')
        self.assertBlocked(self.write_file(self.out_scope, prompt_id=None),
                           'acme/widgets')
        self.assertEqual(self.grace_used(), 2)

    def test_unknown_turn_is_never_recorded_as_a_turn(self):
        self.set_policies([ORG_POLICY])
        self.write_file(self.out_scope, prompt_id=None)
        state = json.loads(self.gate_file.read_text(encoding='utf-8'))
        self.assertEqual(state['turns'], [])
        self.assertEqual(state['used'], 1)

    def test_an_identifiable_turn_still_burns_exactly_one(self):
        """Regression guard: per-call charging must apply ONLY to the unknown
        case, never to a turn the client actually named."""
        self.set_policies([ORG_POLICY])
        for _ in range(5):
            self.assertWarned(self.write_file(self.out_scope, prompt_id='t1'),
                              'acme/widgets')
        self.assertEqual(self.grace_used(), 1)


class TestPromptPathRefreshesThePolicyCache(RepoGateCase):
    """Warming the cache on the prompt path is what makes the session's first gated call enforceable."""

    def test_the_refresh_makes_the_first_tool_call_enforceable(self):
        self.assertFalse(self.cache_file.exists(), 'starts genuinely cold')
        policy = dict(ORG_POLICY, grace_turns=0)
        gateway = {'decision': 'allow', 'tools_to_check': [],
                   'repo_policies': [policy]}
        self.assertPromptAllowed(
            self.run_prompt(cwd=str(self.out_scope), prompt_id='t1',
                            gateway=gateway))
        self.assertIs(self.api.call_args[0][0].get('pull_policies'), True)
        self.assertEqual(unbound.get_repo_policies(), [policy])
        # Same turn, first tool call — enforced, because the prompt warmed it.
        self.assertBlocked(self.write_file(self.out_scope, prompt_id='t1'),
                           'acme/widgets')

    def test_without_the_refresh_the_first_write_would_be_unenforced(self):
        """States the regression directly: a cold cache means an empty policy
        list, and an empty policy list is an allow."""
        self.assertFalse(self.cache_file.exists())
        self.assertAllowed(self.write_file(self.out_scope))

    def test_fresh_cache_is_not_re_pulled(self):
        self.set_policies([ORG_POLICY])
        self.run_prompt(cwd=str(self.in_scope))
        self.assertNotIn('pull_policies', self.api.call_args[0][0])

    def test_stale_cache_is_refreshed(self):
        self.set_policies([ORG_POLICY])
        cache = json.loads(self.cache_file.read_text(encoding='utf-8'))
        cache['last_synced'] = '2000-01-01T00:00:00Z'
        self.cache_file.write_text(json.dumps(cache), encoding='utf-8')
        self.run_prompt(cwd=str(self.in_scope))
        self.assertIs(self.api.call_args[0][0].get('pull_policies'), True)

    def test_a_gate_block_still_costs_no_round_trip(self):
        """Ordering is the safety property: only this machine can resolve a path
        to a git root, so a blocked call must cost zero network round trips."""
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        api = MagicMock(return_value={})
        with patch.object(unbound, 'send_to_hook_api', api), \
             patch.object(unbound, 'report_error_to_gateway'), \
             patch.object(unbound, 'build_account_identity', return_value={}):
            response = unbound.process_pre_tool_use({
                'hook_event_name': 'PreToolUse', 'session_id': 'S1',
                'prompt_id': 't1', 'tool_name': 'Edit',
                'tool_input': {'file_path': str(self.out_scope / 'main.py')},
                'cwd': str(self.out_scope)}, 'KEY')
        self.assertBlocked(response, 'acme/widgets')
        api.assert_not_called()

    def test_a_bare_response_does_not_clobber_cached_policies(self):
        self.set_policies([ORG_POLICY])
        self.run_prompt(cwd=str(self.in_scope), gateway={'decision': 'allow'})
        self.assertEqual(unbound.get_repo_policies(), [ORG_POLICY])


class TestConversationIsNeverGated(RepoGateCase):
    """The gate fires on work, not on talking: a conversation's own cwd is never the violation."""

    def test_conversation_in_out_of_scope_repo_is_allowed(self):
        """grace_turns=0, so the old rule would have blocked the first prompt.
        Three turns in a row are allowed instead."""
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        for turn in ('t1', 't2', 't3'):
            self.assertPromptAllowed(
                self.run_prompt(cwd=str(self.out_scope), prompt_id=turn))

    def test_conversation_burns_no_grace(self):
        """The grace a later write needs must still be there afterwards."""
        self.set_policies([dict(ORG_POLICY, grace_turns=1)])
        for turn in ('t1', 't2'):
            self.run_prompt(cwd=str(self.out_scope), prompt_id=turn)
        self.assertEqual(self.grace_used(), 0)
        self.assertFalse(self.gate_file.exists(),
                         'a prompt must not create the counter file')
        self.assertWarned(self.write_file(self.out_scope, prompt_id='t3'),
                          'acme/widgets')

    def test_conversation_in_allowed_org_is_allowed(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        self.assertPromptAllowed(self.run_prompt(cwd=str(self.in_scope)))
        self.assertEqual(self.grace_used(), 0)

    def test_conversation_with_no_git_root_is_allowed(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        self.assertPromptAllowed(self.run_prompt(cwd=str(self.no_repo)))
        self.assertEqual(self.grace_used(), 0)
        self.assertFalse(self.gate_file.exists(),
                         'a non-repo cwd must not touch the counter')

    def test_the_session_gate_is_gone_from_the_module(self):
        for gone in ('_repo_gate_evaluate_session',
                     '_repo_gate_prompt_deny_response',
                     '_with_repo_gate_prompt_context'):
            self.assertFalse(hasattr(unbound, gone), gone)

    def test_a_gateway_prompt_block_still_blocks(self):
        """Removing the gate from this path must not remove the gateway's own
        verdict from it."""
        self.set_policies([ORG_POLICY])
        gateway = {'decision': 'deny', 'reason': 'Blocked: prompt contains a secret'}
        response = self.run_prompt(cwd=str(self.out_scope), gateway=gateway)
        self.assertEqual(response['decision'], 'block')
        self.assertEqual(response['reason'], 'Blocked: prompt contains a secret')

    def test_a_gateway_prompt_warning_still_rides_through(self):
        self.set_policies([ORG_POLICY])
        gateway = {'decision': 'allow',
                   'additionalContext': "You've used $80 of your $100 limit."}
        response = self.run_prompt(cwd=str(self.out_scope), gateway=gateway)
        context = response['hookSpecificOutput']['additionalContext']
        self.assertIn('$80 of your $100 limit', context)
        # ...and the gate adds nothing of its own to it any more.
        self.assertNotIn('acme/widgets', json.dumps(response))

    def test_an_allowed_prompt_is_audit_logged(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        self.run_prompt(cwd=str(self.out_scope))
        logged = self.audit_log.read_text(encoding='utf-8').strip().splitlines()
        self.assertEqual(len(logged), 1)
        self.assertEqual(json.loads(logged[0])['event']['hook_event_name'],
                         'UserPromptSubmit')


class TestReadsAreUngated(RepoGateCase):
    """Read/Grep/Glob are out of scope: a read names no intent to change anything."""

    def test_read_in_an_out_of_scope_repo_is_allowed(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        self.assertAllowed(self.read_file(self.out_scope))
        self.assertEqual(self.grace_used(), 0)

    def test_grep_and_glob_in_an_out_of_scope_repo_are_allowed(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        for tool_name in ('Grep', 'Glob'):
            with self.subTest(tool=tool_name):
                self.assertAllowed(self.run_tool(
                    tool_name, {'path': str(self.out_scope)}))
        self.assertEqual(self.grace_used(), 0)

    def test_reads_are_out_of_the_gate_scope_by_name(self):
        for tool_name in ('Read', 'Grep', 'Glob'):
            self.assertNotIn(tool_name, unbound._REPO_GATE_TOOLS)
            self.assertFalse(unbound._repo_gate_applies(tool_name, None))

    def test_many_reads_never_escalate_a_later_write(self):
        """Reads must not quietly spend the grace a write still needs."""
        self.set_policies([dict(ORG_POLICY, grace_turns=1)])
        for turn in ('t1', 't2', 't3'):
            self.assertAllowed(self.read_file(self.out_scope, prompt_id=turn))
        self.assertWarned(self.write_file(self.out_scope, prompt_id='t4'),
                          'acme/widgets')


class TestShellDirectoryChanges(RepoGateCase):
    """Writing or running git after a cd is the violation; the cd alone is not."""

    def test_cd_into_out_of_scope_repo_then_git_or_write_is_caught(self):
        self.set_policies([ORG_POLICY])
        for tail in ('git commit -m wip', 'rm README.md', 'echo x > out.txt'):
            with self.subTest(tail=tail):
                self.gate_file.unlink(missing_ok=True)
                self.assertWarned(
                    self.bash('cd %s && %s' % (self.out_scope, tail),
                              cwd=str(self.in_scope)),
                    'acme/widgets')

    def test_bare_cd_with_no_git_or_write_is_allowed(self):
        """Walking into an out-of-scope repo is not gated, and neither is reading once there."""
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        for command in ('cd %s', 'cd %s && cat README.md', 'cd %s && ls -la'):
            with self.subTest(command=command):
                self.assertAllowed(self.bash(command % self.out_scope,
                                             cwd=str(self.in_scope)))
        self.assertEqual(self.grace_used(), 0)

    def test_relative_traversal_out_of_the_allowed_repo_is_caught(self):
        self.set_policies([ORG_POLICY])
        self.assertWarned(
            self.bash('cd %s/../widgets && git commit -m wip' % self.in_scope,
                      cwd=str(self.in_scope)),
            'acme/widgets')

    def test_cd_within_the_allowed_repo_is_allowed(self):
        self.set_policies([ORG_POLICY])
        self.assertAllowed(
            self.bash('cd %s && git commit -m wip' % self.in_scope,
                      cwd=str(self.tmp)))
        self.assertEqual(self.grace_used(), 0)


class TestBashPaths(RepoGateCase):
    def test_absolute_path_in_a_gated_command_violates(self):
        self.set_policies([ORG_POLICY])
        command = 'rm %s/src/main.py' % self.out_scope
        self.assertWarned(self.bash(command), 'acme/widgets')

    def test_gated_command_with_cwd_inside_out_of_scope_repo_violates(self):
        self.set_policies([ORG_POLICY])
        for command in ('git push', 'rm main.py', 'echo x > out.txt'):
            with self.subTest(command=command):
                self.gate_file.unlink(missing_ok=True)
                self.assertWarned(self.bash(command, cwd=str(self.out_scope)),
                                  'acme/widgets')

    def test_gated_command_in_allowed_repo_is_allowed(self):
        self.set_policies([ORG_POLICY])
        for command in ('git push', 'rm main.py', 'echo x > out.txt'):
            with self.subTest(command=command):
                self.assertAllowed(self.bash(command, cwd=str(self.in_scope)))
        self.assertEqual(self.grace_used(), 0)

    def test_gated_command_outside_any_repo_is_allowed(self):
        self.set_policies([ORG_POLICY])
        for command in ('git push', 'rm main.py', 'echo x > out.txt'):
            with self.subTest(command=command):
                self.assertAllowed(self.bash(command, cwd=str(self.no_repo)))
        self.assertEqual(self.grace_used(), 0)


class TestOnlyGitAndShellWritesAreGated(RepoGateCase):
    """A Bash call is in scope only when it runs git or mutates the working tree."""

    # No absolute paths here: a command that names one resolves against THAT
    # path, not the cwd, which is a separate axis covered by TestBashPaths.
    GATED = ['git push', 'git commit -m wip', '/usr/bin/git status',
             'sudo git push', 'GIT_SSH_COMMAND=ssh git push', 'git log | head',
             'rm auth.py', 'rm -rf build/', 'mv a b', 'cp a b', 'touch new.py',
             'mkdir -p src/x', "sed -i 's/a/b/' f", "perl -pi -e 's/a/b/' f",
             'tee out.txt', 'truncate -s 0 f', 'dd if=a of=b', 'ln -s a b',
             'patch < fix.diff', 'echo x > file', 'make >> build.log']
    # git or a write command appears in the LINE but is not what is invoked.
    UNGATED = ['ls -la', 'cat README.md', 'npm test', 'python -m pytest',
               'cat git-notes.md', 'cat rm-notes.md', 'git-lfs push',
               '/opt/homebrew/bin/git-lfs --help', 'grep -r "rm -rf" .',
               'grep git README.md', 'echo "moved to archive"',
               'echo "a && git push"', 'npm run remove-stale',
               'make 2>&1', 'cmd 1>&2', 'chmod +x run.sh']

    def test_gated_commands_are_caught_in_an_out_of_scope_repo(self):
        self.set_policies([ORG_POLICY])
        for command in self.GATED:
            with self.subTest(command=command):
                self.gate_file.unlink(missing_ok=True)
                self.assertWarned(self.bash(command, cwd=str(self.out_scope)),
                                  'acme/widgets')

    def test_ungated_commands_are_allowed_in_an_out_of_scope_repo(self):
        """grace_turns=0, so anything in scope would block outright."""
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        for command in self.UNGATED:
            with self.subTest(command=command):
                self.assertAllowed(self.bash(command, cwd=str(self.out_scope)))
        self.assertEqual(self.grace_used(), 0)

    def test_a_2_to_1_redirect_is_not_a_write(self):
        """`2>&1` and `1>&2` move an existing stream; they create nothing."""
        self.assertFalse(unbound._is_shell_write_command('make 2>&1'))
        self.assertFalse(unbound._is_shell_write_command('cmd 1>&2'))
        self.assertTrue(unbound._is_shell_write_command('make 2>&1 > out.txt'))

    def test_indirect_invocation_is_deliberately_not_gated(self):
        """The documented conservative miss: a command reached through another
        program cannot be classified with confidence."""
        for command in ('xargs git commit', 'sh -c "git push"', 'xargs rm'):
            with self.subTest(command=command):
                self.assertFalse(unbound._is_git_command(command))
                self.assertFalse(unbound._is_shell_write_command(command))

    def test_the_write_command_set_is_one_reviewable_constant(self):
        self.assertIn('rm', unbound._SHELL_WRITE_COMMANDS)
        # chmod/chown change metadata, not repository content.
        self.assertNotIn('chmod', unbound._SHELL_WRITE_COMMANDS)
        self.assertNotIn('chown', unbound._SHELL_WRITE_COMMANDS)

    def test_homebrew_path_is_not_a_violation(self):
        """WEB-5433: system checkouts are dropped before git resolution, so a
        Homebrew formula never reads as work in homebrew/brew."""
        self.set_policies([ORG_POLICY])
        self.assertAllowed(self.run_tool(
            'Read', {'file_path': '/opt/homebrew/Library/Taps/core/jq.rb'}))
        self.assertAllowed(self.run_tool(
            'Bash', {'command': '/opt/homebrew/bin/jq . data.json'},
            cwd=str(self.in_scope)))
        self.assertEqual(self.grace_used(), 0)


class TestPolicySemantics(RepoGateCase):
    def test_stray_action_key_is_ignored(self):
        # Rows written before the action field was dropped must still enforce.
        self.set_policies([dict(ORG_POLICY, action='ALLOW')])
        self.assertWarned(self.write_file(self.out_scope), 'acme/widgets')

    def test_compliant_with_any_block_policy_is_compliant(self):
        """Multiple BLOCK policies: a path violates only if outside them all."""
        self.set_policies([
            ORG_POLICY,
            dict(ORG_POLICY, id=13, github_org='acme', grace_turns=9),
        ])
        self.assertAllowed(self.write_file(self.in_scope))
        self.assertAllowed(self.write_file(self.out_scope))
        self.assertEqual(self.grace_used(), 0)

    def test_minimum_grace_across_block_policies_wins(self):
        self.set_policies([
            dict(ORG_POLICY, grace_turns=7),
            dict(ORG_POLICY, id=13, grace_turns=0),
        ])
        self.assertBlocked(self.write_file(self.out_scope), 'acme/widgets')

    def test_org_match_is_case_insensitive(self):
        self.set_policies([dict(ORG_POLICY, github_org='UnBoundSec')])
        self.assertAllowed(self.write_file(self.in_scope))

    def test_repo_policies_survive_a_cache_round_trip(self):
        unbound.save_policy_cache(tools_to_check=['Bash'],
                                  repo_policies=[ORG_POLICY])
        # A later write that omits repo_policies must not drop them.
        unbound.save_policy_cache(tools_to_check=['Bash', 'Read'])
        self.assertEqual(unbound.get_repo_policies(), [ORG_POLICY])
        # An explicit empty list clears them.
        unbound.save_policy_cache(repo_policies=[])
        self.assertEqual(unbound.get_repo_policies(), [])

    def test_gateway_response_populates_repo_policies(self):
        gateway = {'decision': 'allow', 'tools_to_check': ['Bash'],
                   'repo_policies': [ORG_POLICY]}
        self.run_tool('Bash', {'command': 'echo hi'}, gateway=gateway)
        self.assertEqual(unbound.get_repo_policies(), [ORG_POLICY])


class TestNeverDowngradesABlock(RepoGateCase):
    def test_gateway_deny_survives_a_gate_warning(self):
        self.set_policies([ORG_POLICY], tools_to_check=['Bash'])
        gateway = {'decision': 'deny', 'reason': 'Blocked: secret exfiltration',
                   'additionalContext': 'Stop and tell the user.'}
        response = self.run_tool(
            'Bash', {'command': 'rm %s/src/main.py' % self.out_scope},
            gateway=gateway)
        out = response['hookSpecificOutput']
        self.assertEqual(out['permissionDecision'], 'deny')
        self.assertEqual(out['permissionDecisionReason'],
                         'Blocked: secret exfiltration')
        self.assertIn('Stop and tell the user.', out['additionalContext'])
        self.assertIn('acme/widgets', out['additionalContext'])

    def test_gate_block_does_not_call_the_gateway(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)],
                          tools_to_check=['Bash'])
        event = {
            'hook_event_name': 'PreToolUse', 'session_id': 'S1',
            'prompt_id': 't1', 'tool_name': 'Bash',
            'tool_input': {'command': 'rm %s/src/main.py' % self.out_scope},
            'cwd': str(self.tmp),
        }
        with patch.object(unbound, 'send_to_hook_api') as api:
            response = self.run_tool(
                'Bash', event['tool_input'], prompt_id='t1')
        api.assert_not_called()
        self.assertBlocked(response, 'acme/widgets')


class TestFailsOpen(RepoGateCase):
    def test_cold_cache_allows(self):
        self.assertFalse(self.cache_file.exists())
        self.assertAllowed(self.write_file(self.out_scope))
        self.assertEqual(self.grace_used(), 0)

    def test_git_binary_missing_allows(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        with patch.object(unbound, '_git_origin_url',
                          side_effect=FileNotFoundError('git')):
            self.assertAllowed(self.write_file(self.out_scope))
        self.assertEqual(self.grace_used(), 0)

    def test_git_timeout_allows(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        timeout = subprocess.TimeoutExpired(cmd='git', timeout=10)
        with patch.object(unbound, '_git_origin_url', side_effect=timeout):
            self.assertAllowed(self.write_file(self.out_scope))
        self.assertEqual(self.grace_used(), 0)

    def test_repo_without_origin_allows(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        bare = _make_repo(self.tmp / 'work' / 'local', 'origin')
        subprocess.run(['git', '-C', str(bare), 'remote', 'remove', 'origin'],
                       check=True, capture_output=True)
        self.assertAllowed(self.write_file(bare))

    def test_hostless_origin_allows(self):
        """file:///srv/git/x parses as org "srv", repo "git" — a half-parse the
        gate must never judge against a GitHub org."""
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        weird = _make_repo(self.tmp / 'work' / 'weird', 'file:///srv/git/x')
        self.assertAllowed(self.write_file(weird))

    def test_remote_host_parsing(self):
        self.assertEqual(unbound._remote_host('git@github.com:o/r.git'),
                         'github.com')
        self.assertEqual(unbound._remote_host('https://github.com/o/r.git'),
                         'github.com')
        self.assertEqual(unbound._remote_host('ssh://git@ghe.acme.com/o/r'),
                         'ghe.acme.com')
        self.assertIsNone(unbound._remote_host('file:///srv/git/x'))
        self.assertIsNone(unbound._remote_host('/srv/git/x'))
        self.assertIsNone(unbound._remote_host(''))

    def test_self_hosted_github_enterprise_is_still_gated(self):
        self.set_policies([ORG_POLICY])
        ghe = _make_repo(self.tmp / 'work' / 'ghe',
                         'git@ghe.acme.com:acme/internal.git')
        self.assertWarned(self.write_file(ghe), 'acme/internal')

    def test_malformed_repo_policies_allow(self):
        for policies in (
            'not-a-list',
            [None, 3, 'x'],
            [{}],
            [dict(ORG_POLICY, grace_turns='three')],
            [dict(ORG_POLICY, grace_turns=None)],
            [dict(ORG_POLICY, grace_turns=-1)],
            [dict(ORG_POLICY, scope_mode='organization', github_org='')],
            [dict(ORG_POLICY, scope_mode='organization', github_org=None)],
        ):
            with self.subTest(policies=policies):
                self.cache_file.write_text(json.dumps({
                    'last_synced': unbound.datetime.utcnow().isoformat() + 'Z',
                    'tools_to_check': [],
                    'repo_policies': policies,
                }), encoding='utf-8')
                self.assertAllowed(self.write_file(self.out_scope))
                self.assertEqual(self.grace_used(), 0)

    def test_corrupt_state_file_allows_and_is_treated_as_unused(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=1)])
        for junk in ('', '{', 'null', '[]', '{"used": "many"}',
                     '{"session_id": "S1", "used": -4, "turns": []}',
                     '{"session_id": "S1", "used": 9, "turns": "t1"}'):
            with self.subTest(junk=junk):
                self.gate_file.write_text(junk, encoding='utf-8')
                self.assertWarned(self.write_file(self.out_scope, prompt_id='t1'),
                                  'acme/widgets')

    def test_unwritable_state_dir_still_warns(self):
        self.set_policies([ORG_POLICY])
        with patch.object(unbound, 'REPO_GATE_STATE_FILE',
                          Path('/proc/nonexistent/.repo_gate_state.json')):
            self.assertWarned(self.write_file(self.out_scope), 'acme/widgets')

    def test_corrupt_policy_cache_allows(self):
        self.cache_file.write_text('{not json', encoding='utf-8')
        self.assertAllowed(self.write_file(self.out_scope))

    def test_ungated_tool_names_are_untouched(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        response = self.run_tool('WebFetch', {'url': 'https://example.com'})
        self.assertEqual(response, {})


if __name__ == '__main__':
    unittest.main()


class TestIncidentReporting(RepoGateCase):
    """Exactly one report per non-allow verdict; the gate decides on-device, so an unreported verdict leaves no trace."""

    def test_a_warned_tool_call_reports_one_warn(self):
        self.set_policies([ORG_POLICY])
        self.assertWarned(self.write_file(self.out_scope), 'acme/widgets')
        report = self.assertOneReport(
            'WARN', 'acme/widgets', 'tool',
            tool_name='Edit', session_id='S1', prompt_text=None)
        self.assertEqual(report['tool_input'],
                         str(self.out_scope / 'src' / 'main.py'))
        # grace_turns is 2 and this call spent the first of them.
        self.assertEqual(report['turn'], 1)

    def test_a_blocked_tool_call_reports_one_block(self):
        self.set_policies([ORG_POLICY])
        self.write_file(self.out_scope, prompt_id='turn-1')
        self.write_file(self.out_scope, prompt_id='turn-2')
        self.post.reset_mock()
        self.assertBlocked(self.write_file(self.out_scope, prompt_id='turn-3'),
                           'acme/widgets')
        self.assertOneReport('BLOCK', 'acme/widgets', 'tool', tool_name='Edit')

    def test_a_compliant_repo_reports_nothing(self):
        self.set_policies([ORG_POLICY])
        self.assertAllowed(self.write_file(self.in_scope))
        self.assertNoReports()

    def test_a_path_under_no_git_root_reports_nothing(self):
        self.set_policies([ORG_POLICY])
        response = self.run_tool(
            'Read', {'file_path': str(self.no_repo / 'deep' / 'todo.md')})
        self.assertAllowed(response)
        self.assertNoReports()

    def test_a_tool_the_gate_ignores_reports_nothing(self):
        self.set_policies([ORG_POLICY])
        self.run_tool('WebFetch', {'url': 'https://example.com'},
                      cwd=str(self.out_scope))
        self.assertNoReports()

    def test_a_read_reports_nothing(self):
        """Reads left the gate, so they reach no verdict and file no
        incident — including in an out-of-scope repo with grace spent."""
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        self.assertAllowed(self.read_file(self.out_scope))
        self.assertNoReports()

    def test_an_ungated_shell_command_reports_nothing(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        for command in ('ls -la', 'cat README.md', 'npm test'):
            self.assertAllowed(self.bash(command, cwd=str(self.out_scope)))
        self.assertNoReports()

    def test_a_prompt_never_reports_anything(self):
        """`surface` is now always "tool": the conversation gate was the only
        producer of surface="prompt", leaving that value of the server's enum
        unreachable from this hook."""
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        for cwd in (str(self.out_scope), str(self.in_scope), str(self.no_repo),
                    None):
            self.assertPromptAllowed(self.run_prompt(cwd=cwd))
        self.assertNoReports()
        source = Path(unbound.__file__).read_text(encoding='utf-8')
        self.assertNotIn("'surface': 'prompt'", source)

    def test_one_turn_of_violating_calls_files_one_report_each(self):
        """The pinned cardinality: three calls, one burned grace, three
        reports. The grace assertion is the semantics guard — reporting must
        not have changed how grace is counted."""
        self.set_policies([ORG_POLICY])
        for _ in range(3):
            self.write_file(self.out_scope, prompt_id='turn-1')
        self.assertEqual(self.grace_used(), 1)
        reports = self.reports()
        self.assertEqual([r['decision'] for r in reports], ['WARN'] * 3)

    def test_the_prompt_adds_nothing_to_a_turns_reports(self):
        """The prompt of a turn is not a verdict any more, so only the turn's
        gated tool calls report — and they still share the one grace."""
        self.set_policies([ORG_POLICY])
        self.run_prompt(cwd=str(self.out_scope), prompt_id='turn-1')
        self.write_file(self.out_scope, prompt_id='turn-1')
        self.bash('git push', prompt_id='turn-1', cwd=str(self.out_scope))
        self.assertEqual(self.grace_used(), 1)
        self.assertEqual([(r['surface'], r['decision']) for r in self.reports()],
                         [('tool', 'WARN'), ('tool', 'WARN')])

    # -- nothing about a report can reach a decision ----------------------

    def test_the_dispatch_never_waits_on_curl(self):
        """The detachment proof. _repo_gate_post hands the body to curl and
        returns; nothing waits on the child, so a hung gateway cannot stall a
        decision — it can only outlive the hook."""
        proc = MagicMock()
        proc.communicate.side_effect = AssertionError('the decision path waited')
        proc.wait.side_effect = AssertionError('the decision path waited')
        with patch.object(unbound.subprocess, 'Popen', return_value=proc) as popen:
            self.real_post('{"repository": "acme/widgets"}', 'KEY')
        argv = popen.call_args.args[0]
        self.assertEqual(argv[0], 'curl')
        self.assertTrue(argv[-1].endswith('/v1/hooks/repo-gate'))
        self.assertIn('Authorization: Bearer KEY', argv)
        self.assertIn('--max-time', argv)
        proc.stdin.write.assert_called_once_with(b'{"repository": "acme/widgets"}')
        proc.stdin.close.assert_called_once_with()

    def test_a_hung_gateway_still_blocks(self):
        """End to end through the real dispatch with only the curl process
        replaced. The Popen patch is scoped to the dispatch alone: the gate
        resolves git roots through subprocess too, and patching it wholesale
        would fail the gate open and prove nothing."""
        proc = MagicMock()
        proc.communicate.side_effect = AssertionError('the decision path waited')
        proc.wait.side_effect = AssertionError('the decision path waited')

        def hung_post(body, api_key):
            with patch.object(unbound.subprocess, 'Popen', return_value=proc):
                self.real_post(body, api_key)

        self.post.side_effect = hung_post
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        self.assertBlocked(self.write_file(self.out_scope), 'acme/widgets')
        proc.stdin.close.assert_called_once_with()

    def test_a_raising_report_never_changes_the_decision(self):
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        for boom in (OSError('curl not found'),
                     subprocess.TimeoutExpired('curl', 10),
                     ValueError('malformed response'),
                     RuntimeError('gateway down')):
            with self.subTest(boom=type(boom).__name__):
                self.post.side_effect = boom
                self.assertBlocked(self.write_file(self.out_scope), 'acme/widgets')
                self.assertBlocked(
                    self.bash('git push', cwd=str(self.out_scope)),
                    'acme/widgets')

    def test_a_raising_report_never_changes_a_warning(self):
        self.post.side_effect = RuntimeError('gateway down')
        self.set_policies([ORG_POLICY])
        self.assertWarned(self.write_file(self.out_scope), 'acme/widgets')
        self.assertEqual(self.grace_used(), 1)

    def test_a_missing_api_key_still_blocks_and_files_nothing(self):
        """No key is not a reason to let the call through. It is only a reason
        for the incident to go unrecorded."""
        self.set_policies([dict(ORG_POLICY, grace_turns=0)])
        with patch.object(unbound, '_cached_api_key', None), \
             patch.object(unbound, 'get_api_key', return_value=None):
            self.assertBlocked(self.write_file(self.out_scope), 'acme/widgets')
        self.assertNoReports()

    def test_report_never_raises_on_hostile_input(self):
        """_repo_gate_report is total by construction — its whole body sits
        inside one catch-all — because it is called from inside the gate's own
        try block, where an escaping exception would turn a deny into an
        allow."""
        cases = [
            (None, [ORG_POLICY], {}),
            ({'decision': 'deny'}, [], {}),
            ({'decision': 'deny', 'repo': 'a/b'}, [{}], {}),
            ({'decision': 'warn', 'repo': 'a/b', 'remaining': 'two'},
             [ORG_POLICY], None),
            ('not a dict', [ORG_POLICY], {}),
        ]
        for gate, policies, context in cases:
            with self.subTest(gate=gate):
                self.assertIsNone(
                    unbound._repo_gate_report(gate, policies, context))

    def test_allow_is_never_reported(self):
        """Rule 5: the server refuses an ALLOW anyway, but the client does not
        send one. None is the gate's allow verdict."""
        unbound._repo_gate_report(None, [ORG_POLICY], {'surface': 'tool'})
        unbound._repo_gate_report({'decision': 'allow', 'repo': 'a/b'},
                                  [ORG_POLICY], {'surface': 'tool'})
        self.assertNoReports()

    # -- payload shape -----------------------------------------------------

    def test_long_fields_are_capped_so_the_body_fits_the_pipe(self):
        """The write into curl's stdin must never block, which it cannot as
        long as the body stays far inside the 64KB pipe buffer."""
        cap = unbound.REPO_GATE_REPORT_MAX_CHARS
        self.set_policies([ORG_POLICY])
        self.bash('rm %s/%s' % (self.out_scope, 'x' * 99999))
        body = self.post.call_args.args[0]
        self.assertLess(len(body), 16 * 1024)
        self.assertEqual(len(json.loads(body)['tool_input']), cap)

    def test_the_report_names_the_policy_whose_grace_governed(self):
        """A repo outside every policy's scope is denied by all of them; the
        report names the one whose grace decided warn-vs-block."""
        strict = dict(ORG_POLICY, id=7, name='Strict', grace_turns=0)
        lax = dict(ORG_POLICY, id=8, name='Lax', grace_turns=9)
        self.set_policies([lax, strict])
        self.assertBlocked(self.write_file(self.out_scope), 'acme/widgets')
        report = self.reports()[0]
        self.assertEqual((report['policy_id'], report['policy_name']),
                         (7, 'Strict'))
