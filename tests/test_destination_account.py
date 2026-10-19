"""Every hook resolves which account a shell command reached (git push, gh, ssh family) with identity fields only.

Runs real git and ssh against throwaway repos and ssh configs; the same checks run on all five Python hook copies,
and each hook's own exchange builder is driven once to prove the account rides on its tool entry.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import load_module

HOOK_PATHS = [
    'claude-code/hooks/unbound.py',
    'codex/hooks/unbound.py',
    'copilot/hooks/unbound.py',
    'augment/hooks/unbound.py',
    'cursor/unbound.py',
]
HOOKS = [load_module(p) for p in HOOK_PATHS]
REPO_ROOT = Path(__file__).resolve().parents[1]
START = '# KEEP IN SYNC: destination-account resolution'
END = '# --- end destination account ---'
# Not a real credential; it only has to sit in a remote URL.
FAKE_TOKEN = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'  # gitleaks:allow


def _git(cwd, *args):
    subprocess.run(['git', '-C', cwd, *args], check=True, capture_output=True)


def _repo(remotes):
    """A throwaway git repo on branch main with the given remotes."""
    path = tempfile.mkdtemp()
    _git(path, 'init', '-q', '-b', 'main')
    for name, url in remotes.items():
        _git(path, 'remote', 'add', name, url)
    return path


def _entries(obj):
    """Every dict nested anywhere in a hook's output."""
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _entries(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _entries(value)


def _account_in(output):
    found = [e['destination_account'] for e in _entries(output) if isinstance(e.get('destination_account'), dict)]
    return found[0] if found else None


class DestinationAccountParityTests(unittest.TestCase):
    def test_the_block_is_byte_identical_in_every_hook(self):
        blocks = []
        for path in HOOK_PATHS:
            text = (REPO_ROOT / path).read_text()
            self.assertEqual(text.count(START), 1, path)
            blocks.append(text[text.index(START):text.index(END)])
        self.assertEqual(len(set(blocks)), 1)


@unittest.skipUnless(shutil.which('git') and shutil.which('ssh'), 'needs git and ssh')
class DestinationAccountTests(unittest.TestCase):
    def setUp(self):
        self.ssh_dir = tempfile.mkdtemp()
        self.ssh_config = os.path.join(self.ssh_dir, 'config')
        Path(self.ssh_config).write_text('Host prod-bastion\n  HostName 10.0.4.12\n  User deploy\n  Port 2222\n')
        # No gh login leaks in from the machine running the tests.
        self.env = patch.dict(os.environ, {'GH_CONFIG_DIR': tempfile.mkdtemp()})
        self.env.start()
        for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_HOST', 'GH_REPO'):
            os.environ.pop(key, None)

    def tearDown(self):
        self.env.stop()

    def _each(self, command, cwd=None):
        return [(hook.__file__, hook._destination_account(command, cwd, {})) for hook in HOOKS]

    def test_a_push_to_a_named_remote_reports_its_host_and_owner_without_the_login(self):
        repo = _repo({'origin': 'https://github.com/acme/app.git',
                      'personal': f'https://jdoe:{FAKE_TOKEN}@github.com/jdoe-dev/app.git'})
        for hook, account in self._each('git push personal main', repo):
            with self.subTest(hook=hook):
                self.assertEqual(account, {'platform': 'github', 'host': 'github.com', 'account': 'jdoe-dev',
                                           'context': 'personal', 'source': 'command'})
                self.assertNotIn(FAKE_TOKEN, json.dumps(account))

    def test_a_push_without_a_remote_uses_origin_and_scp_urls_parse(self):
        repo = _repo({'origin': 'git@github.com:acme/app.git'})
        for hook, account in self._each('cd /tmp && git -C {} push'.format(repo), repo):
            with self.subTest(hook=hook):
                self.assertEqual((account['host'], account['account'], account['context']),
                                 ('github.com', 'acme', 'origin'))

    def test_the_pushing_login_comes_from_gh_when_gh_is_the_credential_helper(self):
        if not shutil.which('gh'):
            self.skipTest('needs gh')
        Path(os.environ['GH_CONFIG_DIR'], 'hosts.yml').write_text(
            'github.com:\n    users:\n        jdoe: {}\n    user: jdoe\n    git_protocol: https\n')
        repo = _repo({'personal': 'https://github.com/jdoe-dev/app.git'})
        _git(repo, 'config', 'credential.https://github.com.helper', '!/usr/bin/gh auth git-credential')
        for hook, account in self._each('git push personal main', repo):
            with self.subTest(hook=hook):
                self.assertEqual(account.get('user'), 'jdoe')

    def test_commands_that_reach_no_account_report_nothing(self):
        repo = _repo({'origin': 'https://github.com/acme/app.git'})
        for command in ('git status', 'git commit -m x', 'ls -la', 'rsync -a dir host::module', ''):
            for hook, account in self._each(command, repo):
                with self.subTest(hook=hook, command=command):
                    self.assertIsNone(account)

    def test_gh_reads_the_repo_flag_and_inline_host_and_drops_the_login_under_a_token(self):
        for hook, account in self._each('gh pr create -R acme/app --fill'):
            with self.subTest(hook=hook):
                self.assertEqual((account['platform'], account['host'], account['account']),
                                 ('github', 'github.com', 'acme'))
        for hook, account in self._each('GH_HOST=ghe.acme.com GH_TOKEN=x gh repo view acme/app'):
            with self.subTest(hook=hook):
                self.assertEqual(account['host'], 'ghe.acme.com')
                self.assertNotIn('user', account)

    def test_ssh_family_resolves_the_real_host_user_and_port_through_ssh_config(self):
        cases = [
            f'ssh -F {self.ssh_config} prod-bastion uptime',
            f'scp -F {self.ssh_config} dump.sql prod-bastion:/tmp/',
            f'sudo ssh -F {self.ssh_config} prod-bastion',
        ]
        for command in cases:
            for hook, account in self._each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual(account, {'platform': 'ssh', 'host': '10.0.4.12:2222', 'user': 'deploy',
                                               'context': 'prod-bastion', 'source': 'command'})

    def test_newlines_separate_commands_and_push_options_are_not_taken_for_the_remote(self):
        repo = _repo({'personal': 'https://github.com/jdoe-dev/app.git'})
        for command in ('echo ready\ngit push personal main', 'git push -o ci.skip personal main',
                        'git push --push-option=ci.skip --repo personal'):
            for hook, account in self._each(command, repo):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['account'], account['context']), ('jdoe-dev', 'personal'))

    def test_each_segment_resolves_in_the_folder_it_runs_in(self):
        mine = _repo({'origin': 'https://github.com/jdoe-dev/app.git'})
        other = _repo({'origin': 'https://github.com/acme/other.git'})
        for command, cwd in ((f'git push origin main; cd {other}', mine),
                             (f'cd {mine} && git push origin main', other)):
            for hook, account in self._each(command, cwd):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual(account['account'], 'jdoe-dev')

    def test_ssh_options_that_change_the_host_or_user_and_plain_sftp_are_honoured(self):
        cases = {
            f'ssh -F {self.ssh_config} -o HostName=10.9.9.9 -o User=ops -p2200 prod-bastion': ('10.9.9.9:2200', 'ops'),
            f'ssh -F{self.ssh_config} -lops prod-bastion': ('10.0.4.12:2222', 'ops'),
            f'sftp -F {self.ssh_config} deploy2@prod-bastion': ('10.0.4.12:2222', 'deploy2'),
        }
        for command, expected in cases.items():
            for hook, account in self._each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['host'], account['user']), expected)

    def test_a_gh_repo_url_never_carries_its_login_or_token(self):
        for command in (f'gh pr create -R https://jdoe:{FAKE_TOKEN}@github.com/acme/app --fill',
                        f'GH_REPO=https://jdoe:{FAKE_TOKEN}@github.com/acme/app gh repo view',
                        f'gh repo view https://jdoe:{FAKE_TOKEN}@github.com/acme/app'):
            for hook, account in self._each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['host'], account['account']), ('github.com', 'acme'))
                    self.assertNotIn(FAKE_TOKEN.lower(), json.dumps(account).lower())

    def test_gh_names_the_repo_the_command_reaches(self):
        repo = _repo({'origin': 'https://github.com/acme/app.git'})
        cases = {
            'GH_REPO=acme/app gh repo view other-org/other-repo': 'other-org',
            'gh api repos/other-org/svc/pulls': 'other-org',
            'gh api -X GET /repos/other-org/svc/issues': 'other-org',
            'gh api repos/{owner}/{repo}/pulls': 'acme',
            'gh api user': None,
        }
        for command, owner in cases.items():
            for hook, account in self._each(command, repo):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual(account.get('account'), owner)

    def test_comments_and_line_continuations_keep_the_push(self):
        repo = _repo({'origin': 'https://github.com/acme/app.git', 'personal': 'https://github.com/jdoe-dev/app.git'})
        for command, cwd in ((f'cd {repo} # into the repo\ngit push personal main', '/'),
                             ('git push \\\n  personal main', repo)):
            for hook, account in self._each(command, cwd):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['account'], account['context']), ('jdoe-dev', 'personal'))

    def test_scp_switches_and_bandwidth_limits_are_not_read_as_values_or_logins(self):
        for command in (f'scp -p -F {self.ssh_config} prod-bastion:/var/log/app.log .',
                        f'scp -l 8192 -F {self.ssh_config} dump.sql prod-bastion:/tmp/',
                        f'scp -F {self.ssh_config} notes:draft prod-bastion:/tmp/'):
            for hook, account in self._each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['host'], account['user']), ('10.0.4.12:2222', 'deploy'))

    def test_a_failed_lookup_does_not_hide_a_later_push(self):
        repo = _repo({'personal': 'https://github.com/jdoe-dev/app.git'})
        for hook, account in self._each('git push missing main; git push personal main', repo):
            with self.subTest(hook=hook):
                self.assertEqual(account['account'], 'jdoe-dev')

    def test_a_push_with_no_known_folder_is_unknown_rather_than_the_hooks_own(self):
        for hook, account in self._each('git push origin main'):
            with self.subTest(hook=hook):
                self.assertEqual(account, {'platform': 'git', 'source': 'unknown'})

    def test_an_ssh_config_that_runs_commands_is_never_read(self):
        marker = os.path.join(self.ssh_dir, 'ran')
        config = os.path.join(self.ssh_dir, 'exec_config')
        Path(config).write_text(f'Match host * exec "touch {marker}"\n  HostName 10.9.9.9\n')
        for command in (f'ssh -F {config} prod-bastion', f'false && scp -F {config} f prod-bastion:/tmp/'):
            for hook, account in self._each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual(account, {'platform': 'ssh', 'source': 'unknown'})
        self.assertFalse(os.path.exists(marker))

    def test_what_follows_an_ssh_destination_is_the_remote_command(self):
        for command in (f'ssh -F {self.ssh_config} prod-bastion ls -la /var/log',
                        f'ssh -F {self.ssh_config} prod-bastion ps -p 123 -o user',
                        f'ssh -vF {self.ssh_config} prod-bastion'):
            for hook, account in self._each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['host'], account['user']), ('10.0.4.12:2222', 'deploy'))

    def test_rsync_reads_its_remote_shell_and_skips_option_values(self):
        cases = {
            f'rsync -a -e "ssh -F {self.ssh_config} -p 2200" src prod-bastion:/dest': ('10.0.4.12:2200', 'deploy'),
            f"rsync -avze 'ssh -F {self.ssh_config}' src prod-bastion:/dest --exclude foo:bar": ('10.0.4.12:2222', 'deploy'),
            f'rsync -a --rsh="ssh -F {self.ssh_config}" src prod-bastion:/dest': ('10.0.4.12:2222', 'deploy'),
        }
        for command, expected in cases.items():
            for hook, account in self._each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['host'], account['user']), expected)
        for hook, account in self._each('rsync -a -e /usr/local/bin/custom-shell src prod-bastion:/dest'):
            with self.subTest(hook=hook):
                self.assertIsNone(account, 'a remote shell other than ssh reads no ssh config')

    def test_ssh_configs_are_scanned_through_includes_and_only_as_regular_files(self):
        marker = os.path.join(self.ssh_dir, 'ran')
        inner = os.path.join(self.ssh_dir, 'inner_exec')
        Path(inner).write_text(f'Match host * exec "touch {marker}"\n')
        outer = os.path.join(self.ssh_dir, 'outer')
        Path(outer).write_text(f'Include {inner}\nHost prod-bastion\n  HostName 10.0.4.12\n')
        safe = os.path.join(self.ssh_dir, 'safe')
        Path(safe).write_text(f'Include {self.ssh_config}\n')
        fifo = os.path.join(self.ssh_dir, 'fifo')
        os.mkfifo(fifo)
        for hook, account in self._each(f'ssh -F {outer} prod-bastion'):
            with self.subTest(hook=hook):
                self.assertEqual(account, {'platform': 'ssh', 'source': 'unknown'})
        for hook, account in self._each(f'ssh -F {fifo} prod-bastion'):
            with self.subTest(hook=hook, config='fifo'):
                self.assertEqual(account, {'platform': 'ssh', 'source': 'unknown'})
        for hook, account in self._each(f'ssh -F {safe} prod-bastion'):
            with self.subTest(hook=hook, config='include without exec'):
                self.assertEqual((account['host'], account['user']), ('10.0.4.12:2222', 'deploy'))
        self.assertFalse(os.path.exists(marker))

    def test_a_push_that_moves_the_repository_or_rewrites_its_config_is_unknown(self):
        repo = _repo({'origin': 'https://github.com/acme/app.git'})
        for command in ('git -c remote.origin.pushurl=https://github.com/evil/secret.git push',
                        'git --git-dir=/elsewhere/.git push', 'GIT_DIR=/elsewhere/.git git push origin main'):
            for hook, account in self._each(command, repo):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual(account, {'platform': 'git', 'source': 'unknown'})

    def test_gh_commands_that_reach_no_repo_report_nothing(self):
        repo = _repo({'origin': 'https://github.com/acme/app.git'})
        for command in ('gh help', 'gh auth status', 'gh version', 'gh --version'):
            for hook, account in self._each(command, repo):
                with self.subTest(hook=hook, command=command):
                    self.assertIsNone(account)

    def test_another_gh_config_drops_the_login(self):
        if not shutil.which('gh'):
            self.skipTest('needs gh')
        Path(os.environ['GH_CONFIG_DIR'], 'hosts.yml').write_text(
            'github.com:\n    users:\n        jdoe: {}\n    user: jdoe\n    git_protocol: https\n')
        for hook, account in self._each(f'GH_CONFIG_DIR={tempfile.mkdtemp()} gh pr create -R acme/app'):
            with self.subTest(hook=hook):
                self.assertEqual(account['account'], 'acme')
                self.assertNotIn('user', account)

    def test_a_bare_push_before_tracking_uses_the_remote_git_would(self):
        for setting in (('remote.pushDefault', 'personal'), ('branch.main.remote', 'personal'),
                        ('branch.main.pushRemote', 'personal')):
            repo = _repo({'origin': 'https://github.com/acme/app.git', 'personal': 'https://github.com/jdoe-dev/app.git'})
            _git(repo, 'config', *setting)
            for hook, account in self._each('git push', repo):
                with self.subTest(hook=hook, setting=setting):
                    self.assertEqual((account['account'], account['context']), ('jdoe-dev', 'personal'))

    def test_a_quoted_include_with_a_space_is_scanned(self):
        folder = os.path.join(self.ssh_dir, 'with space')
        os.makedirs(folder)
        marker = os.path.join(self.ssh_dir, 'ran-quoted')
        Path(folder, 'inner').write_text(f'Match host * exec "touch {marker}"\n')
        outer = os.path.join(self.ssh_dir, 'outer-quoted')
        Path(outer).write_text(f'Include "{folder}/inner"\nHost prod-bastion\n  HostName 10.0.4.12\n')
        for hook, account in self._each(f'ssh -F {outer} prod-bastion'):
            with self.subTest(hook=hook):
                self.assertEqual(account, {'platform': 'ssh', 'source': 'unknown'})
        self.assertFalse(os.path.exists(marker))

    def test_quoted_ssh_keywords_are_read_as_ssh_reads_them(self):
        marker = os.path.join(self.ssh_dir, 'ran-keyword')
        inner = os.path.join(self.ssh_dir, 'inner-keyword')
        Path(inner).write_text(f'"Match" host * exec "touch {marker}"\n')
        for body in (f'"Match" exec "touch {marker}"\n', f'"Include" "{inner}"\n', f'Match host * "exec" "touch {marker}"\n'):
            config = os.path.join(self.ssh_dir, 'keyword')
            Path(config).write_text(body + 'Host prod-bastion\n  HostName 10.0.4.12\n')
            for hook, account in self._each(f'ssh -F {config} prod-bastion'):
                with self.subTest(hook=hook, body=body):
                    self.assertEqual(account, {'platform': 'ssh', 'source': 'unknown'})
        self.assertFalse(os.path.exists(marker))

    def test_bracketed_ipv6_copy_destinations_resolve(self):
        for command in ('scp -F none dump.sql deploy@[2001:db8::1]:/tmp/',
                        'scp -F none dump.sql deploy@[2001:db8:0:0:0:0:0:1]:/tmp/'):
            for hook, account in self._each(command):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual(account['user'], 'deploy')
                    self.assertIn(account['host'], ('2001:db8::1', '2001:db8:0:0:0:0:0:1'))

    def test_a_token_in_any_remote_shape_never_reaches_the_account(self):
        repo = _repo({'weird': f'jdoe:{FAKE_TOKEN}@github.com:acme/app.git',
                      'double': f'https://x@{FAKE_TOKEN}@github.com/acme/app.git'})
        for command in ('git push weird main', 'git push double main',
                        f'git push https://x@{FAKE_TOKEN}@github.com/acme/app.git main'):
            for hook, account in self._each(command, repo):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['host'], account['account']), ('github.com', 'acme'))
                    self.assertNotIn(FAKE_TOKEN.lower(), json.dumps(account).lower())

    def test_another_global_git_config_or_gh_flag_forms_are_read(self):
        repo = _repo({'origin': 'https://github.com/acme/app.git'})
        for command in ('GIT_CONFIG_GLOBAL=/elsewhere/gitconfig git push', 'GIT_CONFIG_SYSTEM=/elsewhere/gitconfig git push'):
            for hook, account in self._each(command, repo):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual(account, {'platform': 'git', 'source': 'unknown'})
        cases = {'gh pr create --hostname=ghe.example.com -R acme/app': ('ghe.example.com', 'acme'),
                 'gh pr create -Rother/app': ('github.com', 'other'), 'gh pr create -R=other/app': ('github.com', 'other')}
        for command, expected in cases.items():
            for hook, account in self._each(command, repo):
                with self.subTest(hook=hook, command=command):
                    self.assertEqual((account['host'], account['account']), expected)

    def test_an_equals_before_an_ssh_argument_is_only_a_separator(self):
        marker = os.path.join(self.ssh_dir, 'ran-equals')
        inner = os.path.join(self.ssh_dir, 'inner-equals')
        Path(inner).write_text(f'Match exec "touch {marker}"\n')
        for body in (f'Match =exec "touch {marker}"\n', f'Include ={inner}\n'):
            config = os.path.join(self.ssh_dir, 'equals')
            Path(config).write_text(body + 'Host prod-bastion\n  HostName 10.0.4.12\n')
            for hook, account in self._each(f'ssh -F {config} prod-bastion'):
                with self.subTest(hook=hook, body=body):
                    self.assertEqual(account, {'platform': 'ssh', 'source': 'unknown'})
        self.assertFalse(os.path.exists(marker))

    def test_only_allowlisted_lookups_ever_run(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch.object(hook.subprocess, 'run') as run:
                self.assertIsNone(hook._account_run(['gh', 'auth', 'token'], None, {}))
                self.assertIsNone(hook._account_run(['git', 'credential', 'fill'], None, {}))
                run.assert_not_called()

    def test_a_slow_lookup_or_a_spent_budget_leaves_the_call_account_unknown(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                with patch.object(hook.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ssh', 5)):
                    self.assertEqual(hook._destination_account('ssh prod-bastion', None, {}),
                                     {'platform': 'ssh', 'source': 'unknown'})
                with patch.object(hook.subprocess, 'run') as run:
                    spent = {'deadline': time.monotonic() - 1}
                    self.assertEqual(hook._destination_account('ssh prod-bastion', None, spent),
                                     {'platform': 'ssh', 'source': 'unknown'})
                    run.assert_not_called()


@unittest.skipUnless(shutil.which('git'), 'needs git')
class EachHookCarriesTheAccountTests(unittest.TestCase):
    """Each agent's own exchange builder puts the account on the shell call's tool entry."""

    def setUp(self):
        self.repo = _repo({'personal': 'https://github.com/jdoe-dev/app.git'})
        self.command = 'git push personal main'
        self.expected = ('github.com', 'jdoe-dev')

    def _check(self, output):
        account = _account_in(output)
        self.assertIsNotNone(account)
        self.assertEqual((account['host'], account['account']), self.expected)

    def test_claude_code(self):
        hook = load_module('claude-code/hooks/unbound.py')
        events = [
            {'event': {'hook_event_name': 'UserPromptSubmit', 'prompt': 'push it', 'session_id': 's1'}},
            {'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
                       'tool_input': {'command': self.command}, 'tool_response': {}}},
        ]
        self._check(hook.build_llm_exchange(events, cwd=self.repo))

    def test_cursor(self):
        hook = load_module('cursor/unbound.py')
        roots = {'workspace_roots': [self.repo], 'conversation_id': 'c1', 'generation_id': 'g1'}
        events = [
            {'event': {'hook_event_name': 'beforeSubmitPrompt', 'prompt': 'push it', **roots}},
            {'event': {'hook_event_name': 'afterShellExecution', 'command': self.command, 'cwd': self.repo,
                       'output': '', **roots}},
            {'event': {'hook_event_name': 'afterAgentResponse', 'text': 'pushed', **roots}},
        ]
        self._check(hook.build_llm_exchange(events))

    def test_copilot(self):
        hook = load_module('copilot/hooks/unbound.py')
        self._check(hook.map_copilot_tool('run_in_terminal', {'command': self.command}, '',
                                          shell_state={'dir': self.repo}, root_projects={}))

    def test_augment(self):
        hook = load_module('augment/hooks/unbound.py')
        post = [{'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'launch-process',
                           'tool_input': {'command': self.command}, 'tool_output': ''}}]
        stop = {'hook_event_name': 'Stop', 'cwd': self.repo, 'conversation_id': 'c1',
                'conversation': {'userPrompt': 'push it', 'agentTextResponse': 'pushed'}}
        self._check(hook.build_llm_exchange(stop, post))

    def test_codex(self):
        hook = load_module('codex/hooks/unbound.py')
        transcript = os.path.join(tempfile.mkdtemp(), 'rollout.jsonl')
        lines = [
            {'type': 'response_item', 'timestamp': '2026-10-19T10:00:00Z',
             'payload': {'type': 'function_call', 'call_id': 'c1', 'name': 'exec_command',
                         'arguments': json.dumps({'cmd': self.command, 'workdir': self.repo})}},
            {'type': 'response_item', 'timestamp': '2026-10-19T10:00:01Z',
             'payload': {'type': 'function_call_output', 'call_id': 'c1', 'output': ''}},
        ]
        Path(transcript).write_text('\n'.join(json.dumps(line) for line in lines) + '\n')
        self._check(hook.parse_codex_transcript_for_tools(transcript, None, self.repo))


if __name__ == '__main__':
    unittest.main()
