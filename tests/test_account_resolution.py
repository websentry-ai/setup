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
from tests.test_transfer_destination import _entries

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
BLOCK_SHA256 = 'b2aae92352e32ea4370db43756cd4b11ddf33cf73d1917d686135022b076055e'
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
    # Keyed by folder as well as remote, so a `-C` that is ignored answers for the wrong checkout.
    url = answers.get('remote.' + args[3] + '@' + os.getcwd(), answers.get('remote.' + args[3]))
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

    def _run_entries(self):
        """Every command the hook ran, with the folder it ran in and the git environment it was given."""
        with open(self.run_log) as log:
            return [json.loads(line) for line in log if line.strip()]

    def runs(self):
        """Every command the hook actually ran, as argv lists."""
        return [entry['argv'] for entry in self._run_entries()]

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

    def test_the_push_names_the_remote_it_reached_so_other_actions_are_not_stamped_with_it(self):
        """A chained `git fetch upstream && git push personal` must not record the fetch against the push."""
        for path, resolved in self.each('git push personal main'):
            self.assertEqual(resolved['pushed_remote'], 'personal', path)
        for path, resolved in self.each('git push'):
            self.assertEqual(resolved['pushed_remote'], 'origin', path)

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

    def test_an_explicitly_unset_variable_does_not_fall_back_to_the_hooks_own(self):
        """`env -u` and `unset` leave the shell without it, which is not the same as never having had it."""
        with patch.dict(os.environ, {'GIT_COMMITTER_EMAIL': 'hook@example.com'}):
            for path, resolved in self.each('env -u GIT_COMMITTER_EMAIL git commit -m wip'):
                self.assertEqual(resolved['accounts'][0]['email'], 'jdoe@gmail.com', path)

    def test_nothing_is_looked_up_from_a_folder_we_do_not_know(self):
        """git reads its configuration from the folder it runs in, so an unknown folder resolves nothing."""
        for path, hook in zip(HOOK_PATHS, HOOKS):
            resolved = hook._accounts('git commit -m wip', None, {})
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    def test_a_subcommands_own_option_is_not_read_as_gits(self):
        """`git commit -C <commit>` reuses that commit's message; it is not git's global `-C <dir>`."""
        for path, resolved in self.each('git commit -C HEAD~1 --amend'):
            self.assertEqual(resolved['accounts'][0]['email'], 'jdoe@gmail.com', path)
        # Nothing ran in a folder the option named, because it never named one.
        for entry in self._run_entries():
            self.assertEqual(os.path.realpath(entry['cwd']), os.path.realpath(self.repo))

    def test_a_committer_identity_set_from_a_substitution_is_unknown(self):
        """It is set to something this process cannot see, which is not the same as unset."""
        for path, resolved in self.each('GIT_COMMITTER_EMAIL=$(id -un)@acme.com git commit -m wip'):
            self.assertIsNone(resolved, path)

    def test_a_token_with_a_literal_prefix_and_a_substitution_is_still_a_token(self):
        for path, resolved in self.each('GH_TOKEN=gho_$(cat ~/.suffix) gh pr list'):
            self.assertIsNone(resolved, path)

    def test_gh_reads_the_host_from_the_checkouts_own_remote(self):
        answers = json.loads(os.environ['FAKE_GIT_ANSWERS'])
        answers['remote.origin.url'] = 'git@github.acme.com:acme/app.git'
        with patch.dict(os.environ, {'FAKE_GIT_ANSWERS': json.dumps(answers)}):
            for path, resolved in self.each('gh pr list'):
                self.assertEqual(resolved['accounts'][0]['host'], 'github.acme.com', path)
                self.assertEqual(resolved['accounts'][0]['login'], 'j.doe', path)

    def test_push_repo_names_where_the_push_goes(self):
        """`git push --repo <repository>` names the destination, so its value is the remote."""
        for path, resolved in self.each('git push --repo personal'):
            self.assertEqual(resolved['pushed_repo'], 'jdoe-dev/app', path)
            self.assertEqual(resolved['pushed_remote'], 'personal', path)

    def test_a_config_steering_variable_we_cannot_read_refuses_the_lookup(self):
        """A substituted `GIT_CONFIG_GLOBAL` would make git answer from the default file instead."""
        for path, resolved in self.each('GIT_CONFIG_GLOBAL=$(mktemp) git commit -m wip'):
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    def test_an_override_we_cannot_read_leaves_the_identity_unknown(self):
        for path, resolved in self.each('git --config-env=user.email=MISSING commit -m wip'):
            self.assertIsNone(resolved, path)

    def test_the_checkouts_remote_outranks_gh_host(self):
        """gh reads the repository's own remote before falling back to GH_HOST."""
        answers = __import__('json').loads(os.environ['FAKE_GIT_ANSWERS'])
        answers['remote.origin.url'] = 'git@github.acme.com:acme/app.git'
        with patch.dict(os.environ, {'FAKE_GIT_ANSWERS': __import__('json').dumps(answers),
                                     'GH_HOST': 'github.com'}):
            for path, resolved in self.each('gh pr list'):
                self.assertEqual(resolved['accounts'][0]['host'], 'github.acme.com', path)

    def test_an_unset_variable_is_part_of_the_question_a_memo_answers(self):
        """`unset GIT_CONFIG_GLOBAL` must not share an answer with a call that never had it."""
        hook = HOOKS[0]
        state = {}
        self.resolve(hook, 'git commit -m one', state)
        self.resolve(hook, 'unset GIT_CONFIG_GLOBAL; git commit -m two', state)
        # Asked again rather than answered from the first call's memo. (Each call reads committer.email
        # then user.email, so one lookup per call is two commands.)
        asked = [call for call in self.runs() if call[-1] == 'user.email']
        self.assertEqual(len(asked), 2, self.runs())

    def test_the_committer_email_setting_comes_before_user_email(self):
        """git gives `committer.email` precedence over `user.email`."""
        answers = {'user.email': 'base@example.com', 'committer.email': 'actual@example.com', 'branch': 'main'}
        with patch.dict(os.environ, {'FAKE_GIT_ANSWERS': __import__('json').dumps(answers)}):
            for path, resolved in self.each('git commit -m wip'):
                self.assertEqual(resolved['accounts'][0]['email'], 'actual@example.com', path)

    def test_a_variable_the_shell_unset_does_not_reach_the_lookup(self):
        """Removing it from the child's environment, not just from our own reading of it."""
        other = Path(self.home, 'hook.gitconfig')
        other.write_text('[user]\n    email = hook@example.com\n')
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(other)}):
            for path, resolved in self.each('unset GIT_CONFIG_GLOBAL; git commit -m wip'):
                self.assertEqual(resolved['accounts'][0]['email'], 'jdoe@gmail.com', path)

    def test_an_optional_value_flag_does_not_swallow_the_remote(self):
        """`--force-with-lease` takes an optional value, so bare the next word is the remote."""
        for flag in ('--force-with-lease', '--signed'):
            for path, resolved in self.each('git push %s personal main' % flag):
                self.assertEqual(resolved['pushed_repo'], 'jdoe-dev/app', '%s via %s' % (path, flag))
        # Its `=` form is one token, so the remote still follows.
        for path, resolved in self.each('git push --force-with-lease=main personal main'):
            self.assertEqual(resolved['pushed_repo'], 'jdoe-dev/app', path)

    def test_a_config_env_override_is_honoured(self):
        """`--config-env=user.email=VAR` names a configuration value held in a variable."""
        for path, resolved in self.each('VAR=ci@acme.com git --config-env=user.email=VAR commit -m wip'):
            self.assertEqual(resolved['accounts'][0]['email'], 'ci@acme.com', path)

    def test_a_push_naming_no_remote_and_no_setting_uses_origin(self):
        for path, resolved in self.each('git push'):
            self.assertEqual(resolved['pushed_repo'], 'acme/app', path)

    # -- an export earlier in the turn still decides ---------------------------

    def test_an_export_in_an_earlier_call_does_not_decide_a_later_one(self):
        """These agents run each command in a fresh shell, so no export survives into the next call.

        The hook COMPUTES where the next command starts rather than asking the shell, which is what you do
        when the shell does not persist — so a carried export would attribute the call to an identity git
        never used.
        """
        other = Path(self.home, 'work.gitconfig')
        other.write_text('[user]\n    email = jdoe@acme.com\n')
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            self.resolve(hook, 'export GIT_CONFIG_GLOBAL=%s' % other, state)
            self.resolve(hook, 'export GIT_COMMITTER_EMAIL=ci@acme.com', state)
            resolved = self.resolve(hook, 'git commit -m wip', state)
            self.assertEqual(resolved['accounts'][0]['email'], 'jdoe@gmail.com', path)

    def test_an_inline_assignment_decides_the_call_it_prefixes(self):
        for path, resolved in self.each('GIT_COMMITTER_EMAIL=ci@acme.com git commit -m wip'):
            self.assertEqual(resolved['accounts'][0]['email'], 'ci@acme.com', path)

    # -- git's own options decide which checkout and which configuration ------

    def test_a_c_option_resolves_the_checkout_it_names(self):
        """`git -C other push` reaches the other checkout's remote, not the one the call started in."""
        other = os.path.realpath(tempfile.mkdtemp())
        answers = json.loads(os.environ['FAKE_GIT_ANSWERS'])
        answers['remote.personal@' + other] = 'git@github.com:acme/other-app.git'
        with patch.dict(os.environ, {'FAKE_GIT_ANSWERS': json.dumps(answers)}):
            for path, resolved in self.each('git -C %s push personal main' % other):
                self.assertEqual(resolved['pushed_repo'], 'acme/other-app', path)

    def test_a_c_config_override_beats_the_configured_identity(self):
        for path, resolved in self.each('git -c user.email=ci@acme.com commit -m wip'):
            self.assertEqual(resolved['accounts'][0]['email'], 'ci@acme.com', path)
        # The override answers it outright, so git is never asked for user.email.
        self.assertNotIn(['git', 'config', '--get', 'user.email'], self.runs())

    def test_the_author_email_does_not_stand_in_for_the_committer(self):
        """`GIT_AUTHOR_EMAIL` sets the author; git still commits as `user.email`."""
        for path, resolved in self.each('GIT_AUTHOR_EMAIL=external@example.com git commit -m wip'):
            self.assertEqual(resolved['accounts'][0]['email'], 'jdoe@gmail.com', path)

    def test_two_calls_with_different_config_files_resolve_separately(self):
        """The memo keys on the environment, or the second call reuses the first one's identity."""
        work = Path(self.home, 'work.gitconfig')
        work.write_text('[user]\n    email = jdoe@acme.com\n')
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            first = self.resolve(hook, 'git commit -m one', state)
            second = self.resolve(hook, 'GIT_CONFIG_GLOBAL=%s git commit -m two' % work, state)
            self.assertEqual(first['accounts'][0]['email'], 'jdoe@gmail.com', path)
            self.assertEqual(second['accounts'][0]['email'], 'jdoe@acme.com', path)

    def test_nothing_is_resolved_after_a_source_or_an_eval(self):
        """The sourced text may have set the committer or a token to anything.

        Sequenced with `;`, so the git call surely runs and is not skipped for being uncertain.
        """
        for path, resolved in self.each('source ./.env; git commit -m wip'):
            self.assertIsNone(resolved, path)
        for path, resolved in self.each('eval "$(cat setup.sh)"; gh pr list'):
            self.assertIsNone(resolved, path)

    def test_a_call_run_as_another_user_resolves_that_users_identity_not_ours(self):
        for path, resolved in self.each('sudo -u deploy git commit -m wip'):
            self.assertIsNone(resolved, path)

    def test_a_command_that_rewires_its_remote_leaves_the_repository_unknown(self):
        """git's own `insteadOf` and `pushurl` rewrites are not reimplemented here."""
        for path, resolved in self.each(
                'git -c remote.personal.pushurl=git@github.com:other/x.git push personal main'):
            self.assertNotIn('pushed_repo', resolved or {}, path)

    def test_a_host_qualified_repository_names_its_own_host(self):
        """gh accepts `HOST/OWNER/REPO`, which named no host and fell through to dotcom."""
        for path, resolved in self.each('gh pr view --repo github.acme.com/acme/app'):
            self.assertEqual(resolved['accounts'][0]['host'], 'github.acme.com', path)
            self.assertEqual(resolved['accounts'][0]['login'], 'j.doe', path)

    def test_a_token_the_walk_could_not_read_is_still_a_token(self):
        """`GH_TOKEN=$(...)` signs the call in as whoever owns it, which cannot be read offline."""
        for path, resolved in self.each('GH_TOKEN=$(cat ~/.work-token) gh pr create'):
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    # -- through the turn log, where the folder is tracked across calls -------

    def test_a_call_is_resolved_from_the_folder_it_started_in(self):
        """A `cd` earlier in the same call must move the lookup once, not twice.

        The hook tracks where the persistent shell is; resolving from the folder the call ENDED in
        replayed the call's own `cd` a second time and reached `child/child`.
        """
        hook = load_module('claude-code/hooks/unbound.py')
        child = os.path.join(self.repo, 'child')
        os.makedirs(child, exist_ok=True)
        answers = json.loads(os.environ['FAKE_GIT_ANSWERS'])
        answers['remote.personal@' + os.path.realpath(child)] = 'git@github.com:acme/child-app.git'
        events = [
            {'timestamp': '2026-10-22T16:39:58.000001Z',
             'event': {'hook_event_name': 'UserPromptSubmit', 'prompt': 'ship it', 'session_id': 's1',
                       'cwd': self.repo}},
            {'timestamp': '2026-10-22T16:40:00.250000Z',
             'event': {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
                       'tool_input': {'command': 'cd child && git push personal main'}, 'tool_response': {}}},
        ]
        with patch.dict(os.environ, {'FAKE_GIT_ANSWERS': json.dumps(answers)}):
            entries = [e for e in _entries(hook.build_llm_exchange(events, cwd=self.repo))
                       if 'tool_use_id' in e]
        self.assertEqual([e.get('pushed_repo') for e in entries], ['acme/child-app'])

    # -- cost and safety -------------------------------------------------------

    def test_twenty_gh_calls_in_a_turn_resolve_the_login_once(self):
        hook = HOOKS[0]
        state = {}
        for _ in range(20):
            self.resolve(hook, 'gh pr list', state)
        # Two questions, each asked once: which host the checkout points at, and who is signed in there.
        self.assertEqual(self.runs(), [['git', 'config', '--get', 'remote.origin.url'],
                                       ['gh', 'config', 'get', '-h', 'github.com', 'user']])

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
