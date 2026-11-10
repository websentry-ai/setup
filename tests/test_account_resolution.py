"""Every hook records which account each git and gh call acted as, checked on all five Python hooks with fake
`git` and `gh` programs on PATH so the resolution runs for real and every command run is logged."""
import hashlib
import json
import os
import sys
import tempfile
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
START = '# KEEP IN SYNC: account resolution'
END = '# --- end account resolution ---'
# The cursor-plugin repo's hooks/unbound.py carries the same block and pins the same digest in its own test, so a
# change made in one repo and not the other fails there. Update both together.
BLOCK_SHA256 = '2a3efcfe90a6fbe183839a917a3d66e213344058572af75a9f619d0c9777c8a9'
# Not a real credential; it only has to sit where a token goes.
FAKE_TOKEN = 'gho_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'  # gitleaks:allow

# A `git` stand-in: answers `config --get`, `remote get-url --push` and `symbolic-ref` from FAKE_GIT_ANSWERS,
# honours GIT_CONFIG_GLOBAL as git does, and logs every call.
FAKE_GIT = '''#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_RUN_LOG'], 'a') as log:
    log.write(json.dumps({{'argv': ['git'] + args, 'cwd': os.getcwd(),
                           'env': {{k: v for k, v in os.environ.items() if k.startswith('GIT_')}}}}) + '\\n')
answers = json.loads(os.environ.get('FAKE_GIT_ANSWERS') or '{{}}')
if args[:2] == ['config', '--get']:
    name = args[2]
    # A global config file named in the environment wins, exactly as git's own precedence does.
    override = os.environ.get('GIT_CONFIG_GLOBAL')
    if override and os.path.exists(override):
        for line in open(override):
            if line.strip().startswith(name.split('.')[-1] + ' ='):
                print(line.split('=', 1)[1].strip())
                sys.exit(0)
    if name in answers:
        print(answers[name])
        sys.exit(0)
    sys.exit(1)
if args[:3] == ['remote', 'get-url', '--push']:
    url = answers.get('remote.' + args[3])
    if url is None:
        sys.exit(2)
    print(url)
    sys.exit(0)
if args[:1] == ['symbolic-ref']:
    branch = answers.get('branch')
    if branch is None:
        sys.exit(1)
    print(branch)
    sys.exit(0)
sys.exit(3)
'''

# A `gh` stand-in: answers `config get -h <host> user` from FAKE_GH_USERS and logs every call. Its config file holds
# an oauth_token, which nothing may ever read.
FAKE_GH = '''#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_RUN_LOG'], 'a') as log:
    log.write(json.dumps({{'argv': ['gh'] + args, 'cwd': os.getcwd()}}) + '\\n')
users = json.loads(os.environ.get('FAKE_GH_USERS') or '{{}}')
if args[:2] == ['config', 'get'] and '-h' in args:
    host = args[args.index('-h') + 1]
    if args[-1] == 'user' and host in users:
        print(users[host])
        sys.exit(0)
    sys.exit(1)
sys.exit(3)
'''


class AccountResolutionTests(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.repo = tempfile.mkdtemp()
        bin_dir = tempfile.mkdtemp()
        # gh's own config, with a token in it, so a test can prove nothing reads the file.
        config = Path(self.home, '.config', 'gh')
        config.mkdir(parents=True)
        Path(config, 'hosts.yml').write_text(
            'github.com:\n    user: file-only-login\n    oauth_token: %s\n' % FAKE_TOKEN)
        for name, source in (('git', FAKE_GIT), ('gh', FAKE_GH)):
            path = Path(bin_dir, name)
            path.write_text(source.format(python=sys.executable))
            path.chmod(0o755)
        self.run_log = os.path.join(bin_dir, 'runs.jsonl')
        Path(self.run_log).touch()
        env = {'PATH': bin_dir + os.pathsep + os.environ.get('PATH', ''), 'HOME': self.home,
               'FAKE_RUN_LOG': self.run_log,
               'FAKE_GIT_ANSWERS': json.dumps({'user.email': 'jdoe@gmail.com', 'branch': 'main',
                                               'remote.origin': 'https://github.com/acme/app.git',
                                               'remote.personal': 'git@github.com:jdoe-dev/app.git/'}),
               'FAKE_GH_USERS': json.dumps({'github.com': 'jdoe', 'github.acme.com': 'j.doe'})}
        patcher = patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        # A token or host this machine's shell exports would change what is resolved; the dict patch puts it back.
        for key in [k for k in os.environ if k in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_HOST', 'GH_ENTERPRISE_TOKEN',
                                                   'GITHUB_ENTERPRISE_TOKEN', 'GIT_CONFIG_GLOBAL',
                                                   'GIT_COMMITTER_EMAIL', 'GIT_AUTHOR_EMAIL')]:
            del os.environ[key]

    def runs(self):
        """Every command the hook actually ran, as argv lists."""
        with open(self.run_log) as log:
            return [json.loads(line)['argv'] for line in log if line.strip()]

    def resolve(self, hook, command, state=None, cwd=None):
        return hook._accounts(command, cwd or self.repo, state if state is not None else {})

    def each(self, command, state=None, cwd=None):
        """The same call resolved by every hook, so a divergence between them fails here."""
        return [(path, self.resolve(hook, command, {} if state is None else dict(state), cwd))
                for path, hook in zip(HOOK_PATHS, HOOKS)]

    # -- the block is one block ------------------------------------------------

    def test_the_account_block_is_identical_in_every_hook(self):
        blocks = {}
        for path in HOOK_PATHS:
            text = Path(path).read_text()
            blocks[path] = text[text.index(START):text.index(END) + len(END)]
        self.assertEqual(len(set(blocks.values())), 1, 'the account block has diverged between hooks')
        digest = hashlib.sha256(next(iter(blocks.values())).encode()).hexdigest()
        self.assertEqual(digest, BLOCK_SHA256,
                         'the account block changed: update BLOCK_SHA256 here and in the cursor-plugin repo')

    # -- what each call resolves to -------------------------------------------

    def test_a_push_carries_the_named_remotes_repository_and_not_origins(self):
        for path, resolved in self.each('git push personal main'):
            self.assertEqual(resolved['pushed_repo'], 'jdoe-dev/app', path)

    def test_the_push_url_loses_the_trailing_slash_git_returns(self):
        for path, resolved in self.each('git push personal main'):
            self.assertNotIn('/app/', resolved['pushed_repo'], path)
            self.assertFalse(resolved['pushed_repo'].endswith('/'), path)

    def test_the_committer_identity_is_a_separate_fact_from_the_repository(self):
        for path, resolved in self.each('git push personal main'):
            self.assertEqual(resolved['accounts'],
                             [{'platform': 'git', 'email': 'jdoe@gmail.com', 'source': 'command'}], path)
            self.assertEqual(resolved['pushed_repo'], 'jdoe-dev/app', path)

    def test_a_commit_carries_the_committer_identity_and_no_repository(self):
        for path, resolved in self.each('git commit -m "wip"'):
            self.assertEqual(resolved, {'accounts': [{'platform': 'git', 'email': 'jdoe@gmail.com',
                                                      'source': 'command'}]}, path)

    def test_a_purely_local_git_call_resolves_nothing_and_runs_nothing(self):
        for path, resolved in self.each('git status --short'):
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    def test_gh_carries_an_account_and_no_destination(self):
        for path, resolved in self.each('gh pr list'):
            self.assertEqual(resolved, {'accounts': [{'platform': 'github', 'host': 'github.com',
                                                      'login': 'jdoe', 'source': 'command'}]}, path)
            self.assertNotIn('pushed_repo', resolved, path)

    def test_an_enterprise_host_is_recorded_as_itself(self):
        for path, resolved in self.each('gh pr list --hostname github.acme.com'):
            self.assertEqual(resolved['accounts'][0]['host'], 'github.acme.com', path)
            self.assertEqual(resolved['accounts'][0]['login'], 'j.doe', path)

    def test_a_repo_url_names_the_host_it_points_at(self):
        for path, resolved in self.each('gh pr view --repo https://github.acme.com/acme/app'):
            self.assertEqual(resolved['accounts'][0]['host'], 'github.acme.com', path)

    def test_an_unset_committer_identity_resolves_to_unknown(self):
        with patch.dict(os.environ, {'FAKE_GIT_ANSWERS': json.dumps({'branch': 'main'})}):
            for path, resolved in self.each('git commit -m wip'):
                self.assertIsNone(resolved, path)

    def test_a_token_in_the_environment_leaves_the_login_unknown(self):
        with patch.dict(os.environ, {'GH_TOKEN': FAKE_TOKEN}):
            for path, resolved in self.each('gh pr list'):
                self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    # -- the push remote follows git's own order -------------------------------

    def test_the_push_remote_falls_back_through_gits_own_order(self):
        answers = {'user.email': 'jdoe@gmail.com', 'branch': 'work',
                   'remote.origin': 'https://github.com/acme/app.git',
                   'remote.chosen': 'https://github.com/acme/chosen.git'}
        for setting in ('branch.work.pushRemote', 'remote.pushDefault', 'branch.work.remote'):
            with patch.dict(os.environ, {'FAKE_GIT_ANSWERS': json.dumps({**answers, setting: 'chosen'})}):
                for path, resolved in self.each('git push'):
                    self.assertEqual(resolved['pushed_repo'], 'acme/chosen', '%s via %s' % (path, setting))

    def test_a_push_naming_no_remote_and_no_setting_uses_origin(self):
        for path, resolved in self.each('git push'):
            self.assertEqual(resolved['pushed_repo'], 'acme/app', path)

    # -- an export earlier in the turn still decides ---------------------------

    def test_an_export_in_an_earlier_call_is_honoured_by_a_later_one(self):
        other = Path(self.home, 'work.gitconfig')
        other.write_text('[user]\n    email = jdoe@acme.com\n')
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            self.resolve(hook, 'export GIT_CONFIG_GLOBAL=%s' % other, state)
            for _ in range(3):
                self.resolve(hook, 'git status', state)
            resolved = self.resolve(hook, 'git commit -m wip', state)
            self.assertEqual(resolved['accounts'][0]['email'], 'jdoe@acme.com', path)

    def test_an_inline_assignment_decides_the_call_it_prefixes(self):
        for path, resolved in self.each('GIT_COMMITTER_EMAIL=ci@acme.com git commit -m wip'):
            self.assertEqual(resolved['accounts'][0]['email'], 'ci@acme.com', path)

    # -- cost and safety -------------------------------------------------------

    def test_twenty_gh_calls_in_a_turn_resolve_the_login_once(self):
        hook = HOOKS[0]
        state = {}
        for _ in range(20):
            self.resolve(hook, 'gh pr list', state)
        self.assertEqual(self.runs(), [['gh', 'config', 'get', '-h', 'github.com', 'user']])

    def test_only_allowlisted_commands_are_ever_run(self):
        hook = HOOKS[0]
        state = {}
        for command in ('git push personal main', 'gh pr list', 'git commit -m wip', 'git clone https://x/y'):
            self.resolve(hook, command, state)
        allowed = hook._ACCOUNT_ALLOWED_RUNS
        for argv in self.runs():
            self.assertTrue(any(tuple(argv[:len(p)]) == p for p in allowed), argv)

    def test_no_token_from_ghs_own_config_reaches_the_payload(self):
        hook = HOOKS[0]
        resolved = self.resolve(hook, 'gh pr list', {})
        self.assertNotIn(FAKE_TOKEN, json.dumps(resolved))
        self.assertNotIn('file-only-login', json.dumps(resolved))
        # Nothing opened the file: the login came from the command.
        for argv in self.runs():
            self.assertNotIn('hosts.yml', ' '.join(argv))

    def test_an_exhausted_budget_stops_the_lookups_and_resolves_nothing(self):
        for path, hook in zip(HOOK_PATHS, HOOKS):
            resolved = self.resolve(hook, 'git push personal main', {'budget': -1.0})
            self.assertIsNone(resolved, path)

    def test_a_command_that_only_may_have_run_resolves_nothing(self):
        for path, resolved in self.each('false && git commit -m wip'):
            self.assertIsNone(resolved, path)

    def test_a_refused_lookup_never_raises(self):
        with patch.dict(os.environ, {'PATH': '/nonexistent'}):
            for path, resolved in self.each('git push personal main'):
                self.assertIsNone(resolved, path)


if __name__ == '__main__':
    unittest.main()
