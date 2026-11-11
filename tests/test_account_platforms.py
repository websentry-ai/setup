"""Every hook records which cloud, cluster and registry account each call acted as: read from the config file where
it is INI or JSON, from the CLI only where it is YAML or the file cannot answer, and never from a credential store."""
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
# Not real credentials; they only have to sit where one goes.
FAKE_SECRET = 'Zx9' + 'Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LzXcVbNm'  # gitleaks:allow
ECR_HOST = '210987654321.dkr.ecr.us-west-2.amazonaws.com'

AWS_CONFIG = '''[default]
region = us-west-2
sso_account_id = 111111111111
sso_role_name = Engineer

[profile home]
region = us-west-2
sso_account_id = 987654321098

[profile assumed]
role_arn = arn:aws:iam::222222222222:role/Deploy
source_profile = home

[profile static]
region = eu-west-1
'''

AZURE_PROFILE = {
    'subscriptions': [
        {'id': '00000000-0000-0000-0000-000000000001', 'name': 'Acme Production', 'isDefault': True,
         'tenantId': '00000000-0000-0000-0000-0000000000aa', 'tenantDefaultDomain': 'acme.onmicrosoft.com',
         'user': {'name': 'jdoe@acme.com', 'type': 'user'}},
        {'id': '00000000-0000-0000-0000-000000000002', 'name': 'Acme Sandbox', 'isDefault': False,
         'tenantId': '00000000-0000-0000-0000-0000000000aa'},
    ],
}

# A `kubectl` stand-in: answers `config view -o jsonpath=` from FAKE_KUBE and logs every call. It would print a
# credential if asked for one, so a test can prove nothing asks.
FAKE_KUBECTL = '''#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_RUN_LOG'], 'a') as log:
    log.write(json.dumps({{'argv': ['kubectl'] + args, 'cwd': os.getcwd()}}) + '\\n')
if args[:2] != ['config', 'view']:
    sys.exit(3)
answers = json.loads(os.environ.get('FAKE_KUBE') or '{{}}')
context = args[args.index('--context') + 1] if '--context' in args else answers.get('current', '')
cluster = answers.get('clusters', {{}}).get(context)
if cluster is None:
    sys.exit(1)
out = []
for path in [p for p in args if p.startswith('jsonpath=')][0][len('jsonpath='):].split('|'):
    if 'server' in path:
        out.append(cluster['server'])
    elif 'clusters[0].name' in path:
        out.append(cluster['name'])
    elif 'namespace' in path:
        out.append(cluster.get('namespace', ''))
    elif 'users' in path or 'client-key' in path:
        out.append('{secret}')
    else:
        out.append('')
sys.stdout.write('|'.join(out))
'''

# An `aws` stand-in: answers `sts get-caller-identity` from FAKE_AWS_STS and logs every call.
FAKE_AWS = '''#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_RUN_LOG'], 'a') as log:
    log.write(json.dumps({{'argv': ['aws'] + args, 'cwd': os.getcwd()}}) + '\\n')
if args[:2] != ['sts', 'get-caller-identity']:
    sys.exit(3)
answers = json.loads(os.environ.get('FAKE_AWS_STS') or '{{}}')
profile = args[args.index('--profile') + 1] if '--profile' in args else 'default'
if profile not in answers:
    sys.exit(1)
print(answers[profile])
'''

# An `az` stand-in: answers `account show` from FAKE_AZ_SHOW and logs every call.
FAKE_AZ = '''#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_RUN_LOG'], 'a') as log:
    log.write(json.dumps({{'argv': ['az'] + args, 'cwd': os.getcwd()}}) + '\\n')
if args[:2] != ['account', 'show']:
    sys.exit(3)
body = os.environ.get('FAKE_AZ_SHOW')
if not body:
    sys.exit(1)
sys.stdout.write(body)
'''

# A credential helper, which nothing may ever run.
FAKE_HELPER = '''#!{python}
import json, os, sys
with open(os.environ['FAKE_RUN_LOG'], 'a') as log:
    log.write(json.dumps({{'argv': ['docker-credential-osxkeychain'] + sys.argv[1:]}}) + '\\n')
print(json.dumps({{'ServerURL': 'https://index.docker.io/v1/', 'Username': 'should-never-be-read'}}))
'''


class AccountPlatformTests(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.repo = tempfile.mkdtemp()
        bin_dir = tempfile.mkdtemp()
        aws = Path(self.home, '.aws')
        aws.mkdir()
        Path(aws, 'config').write_text(AWS_CONFIG)
        # The credentials file holds keys; nothing may open it.
        Path(aws, 'credentials').write_text('[home]\naws_secret_access_key = %s\n' % FAKE_SECRET)
        azure = Path(self.home, '.azure')
        azure.mkdir()
        # Azure writes this file with a UTF-8 BOM, which a plain utf-8 read fails on outright.
        Path(azure, 'azureProfile.json').write_bytes(
            b'\xef\xbb\xbf' + json.dumps(AZURE_PROFILE).encode('utf-8'))
        Path(azure, 'msal_token_cache.json').write_text('{"AccessToken": {"secret": "%s"}}' % FAKE_SECRET)
        docker = Path(self.home, '.docker')
        docker.mkdir()
        Path(docker, 'config.json').write_text(json.dumps(
            {'auths': {'https://index.docker.io/v1/': {'auth': FAKE_SECRET}},
             'credsStore': 'osxkeychain'}))
        for name, source in (('kubectl', FAKE_KUBECTL), ('aws', FAKE_AWS), ('az', FAKE_AZ),
                             ('docker-credential-osxkeychain', FAKE_HELPER)):
            path = Path(bin_dir, name)
            path.write_text(source.format(python=sys.executable, secret=FAKE_SECRET))
            path.chmod(0o755)
        self.run_log = os.path.join(bin_dir, 'runs.jsonl')
        Path(self.run_log).touch()
        env = {'PATH': bin_dir + os.pathsep + os.environ.get('PATH', ''), 'HOME': self.home,
               'FAKE_RUN_LOG': self.run_log,
               'FAKE_AWS_STS': json.dumps({'static': '333333333333'}),
               'FAKE_AZ_SHOW': json.dumps(AZURE_PROFILE['subscriptions'][1]),
               'FAKE_KUBE': json.dumps({
                   'current': 'prod-eks',
                   'clusters': {'prod-eks': {'server': 'https://' + 'a1b2c3d4' * 4 +
                                                       '.gr7.us-west-2.eks.amazonaws.com',
                                             'name': 'prod', 'namespace': 'payments'}}})}
        patcher = patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        for key in [k for k in os.environ if k in ('AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_CONFIG_FILE',
                                                   'AWS_ACCESS_KEY_ID', 'KUBECONFIG', 'DOCKER_CONFIG')]:
            del os.environ[key]

    def runs(self):
        with open(self.run_log) as log:
            return [json.loads(line)['argv'] for line in log if line.strip()]

    def resolve(self, hook, command, state=None, cwd=None):
        return hook._accounts(command, cwd or self.repo, state if state is not None else {})

    def each(self, command, state=None):
        return [(path, self.resolve(hook, command, {} if state is None else dict(state)))
                for path, hook in zip(HOOK_PATHS, HOOKS)]

    # -- AWS: the file answers, the CLI only when it cannot -------------------

    def test_a_profile_resolves_from_the_config_file_with_nothing_run(self):
        for path, resolved in self.each('aws s3 ls --profile home'):
            self.assertEqual(resolved['accounts'], [{'platform': 'aws', 'account_id': '987654321098',
                                                     'profile': 'home', 'source': 'file'}], path)
        self.assertEqual(self.runs(), [])

    def test_an_exported_profile_does_not_decide_a_later_call(self):
        """Each command runs in its own shell, so the export is gone by the next one."""
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            self.resolve(hook, 'export AWS_PROFILE=home', state)
            resolved = self.resolve(hook, 'aws s3 ls', state)
            self.assertEqual(resolved['accounts'][0]['account_id'], '111111111111', path)

    def test_a_call_that_chooses_the_config_location_never_runs_the_cli(self):
        """An AWS config can name a `credential_process`, so running the CLI under one the call chose would
        run its code. The file is still read; the CLI is not."""
        for path, resolved in self.each('AWS_CONFIG_FILE=./planted aws s3 ls --profile p'):
            self.assertIsNone(resolved, path)
        self.assertEqual([argv for argv in self.runs() if argv[0] == 'aws'], [])

    def test_an_unreadable_profile_leaves_the_account_unknown_not_default(self):
        """Falling through to `default` would name the organisation's main account with full confidence."""
        for command in ('AWS_PROFILE=$(cat .p) aws s3 ls', 'aws --profile $(cat .p) s3 ls',
                        'AWS_ACCESS_KEY_ID=$(cat .k) aws s3 ls'):
            for path, resolved in self.each(command):
                self.assertIsNone(resolved, '%s / %s' % (path, command))

    def test_a_kubeconfig_list_is_left_to_kubectl(self):
        """`KUBECONFIG=a:b` is valid for kubectl and invalid as one `--kubeconfig` path."""
        os.environ['KUBECONFIG'] = os.pathsep.join(('/tmp/one.kc', '/tmp/two.kc'))
        for path, hook in zip(HOOK_PATHS, HOOKS):
            open(self.run_log, 'w').close()
            self.resolve(hook, 'kubectl get pods')
            asked = [argv for argv in self.runs() if argv[0] == 'kubectl']
            self.assertEqual(len(asked), 1, path)
            self.assertNotIn('--kubeconfig', asked[0], path)

    def test_a_selector_we_cannot_read_never_resolves_the_default(self):
        """A profile, subscription, context or image we cannot read says nothing about which account ran."""
        for command in ('aws s3 ls --profile $(cat .p)',
                        'az group list --subscription $(cat .s)',
                        'kubectl --context $(cat .c) get pods',
                        'kubectl --kubeconfig $(cat .k) get pods',
                        'docker push $(cat .img)'):
            for path, resolved in self.each(command):
                self.assertIsNone(resolved, '%s / %s' % (path, command))

    def test_a_relative_home_is_not_our_own_home(self):
        """`HOME=./sandbox` points at a folder we do not own, so the ambient config must not answer for it."""
        for path, resolved in self.each('HOME=./sandbox aws s3 ls --profile home'):
            self.assertIsNone(resolved, path)

    def test_a_home_with_a_space_still_selects_its_own_config(self):
        """A home is a path, so it may hold spaces."""
        home = Path(tempfile.mkdtemp(), 'My Home')
        aws = Path(home, '.aws')
        aws.mkdir(parents=True)
        Path(aws, 'config').write_text('[profile home]\nsso_account_id = 555555555555\n')
        for path, resolved in self.each("HOME='%s' aws s3 ls --profile home" % home):
            self.assertEqual(resolved['accounts'][0]['account_id'], '555555555555', path)

    def test_the_endpoint_a_call_names_is_the_cluster_it_reached(self):
        """`kubectl --server` names the endpoint outright, and `--cluster` picks one this lookup cannot ask for."""
        for path, resolved in self.each('kubectl --server https://eks.example.com get pods'):
            self.assertEqual(resolved['accounts'],
                             [{'platform': 'kubernetes', 'server': 'https://eks.example.com',
                               'source': 'command'}], path)
        for path, resolved in self.each('kubectl --cluster other get pods'):
            self.assertIsNone(resolved, path)

    def test_an_option_in_the_command_being_run_is_not_this_call_s(self):
        """`kubectl exec … -- curl -s host` names curl's option, not a cluster endpoint."""
        for path, resolved in self.each('kubectl exec deploy/api -- curl -s localhost:8080/health'):
            self.assertNotEqual((resolved or {}).get('accounts', [{}])[0].get('server'),
                                'localhost:8080/health', path)

    def test_a_config_file_path_with_a_space_is_read_not_ignored(self):
        """A path is not an identity, so the home profile must not answer in its place."""
        folder = Path(tempfile.mkdtemp(), 'My Config')
        folder.mkdir()
        Path(folder, 'config').write_text('[profile home]\nsso_account_id = 222222222222\n')
        for path, resolved in self.each("AWS_CONFIG_FILE='%s' aws s3 ls --profile home" % Path(folder, 'config')):
            self.assertEqual(resolved['accounts'][0]['account_id'], '222222222222', path)

    def test_a_relative_config_file_is_not_read_against_our_own_folder(self):
        for path, resolved in self.each('AWS_CONFIG_FILE=config aws s3 ls --profile home'):
            self.assertIsNone(resolved, path)

    def test_a_home_set_to_nothing_is_not_the_password_database_home(self):
        """`HOME=` was set to nothing on purpose; answering from the passwd home defeats that."""
        for path, resolved in self.each('HOME= aws s3 ls --profile home'):
            self.assertIsNone(resolved, path)

    def test_the_default_profile_variable_wins_as_botocore_reads_it(self):
        """botocore reads AWS_DEFAULT_PROFILE before AWS_PROFILE, so that is the account the CLI used."""
        for path, resolved in self.each('AWS_DEFAULT_PROFILE=home AWS_PROFILE=other aws s3 ls'):
            self.assertEqual(resolved['accounts'][0]['profile'], 'home', path)

    def test_a_kubeconfig_named_on_the_command_still_resolves_the_cluster(self):
        """A kubeconfig names no code to run, so naming one does not stop the lookup."""
        for path, resolved in self.each('KUBECONFIG=/tmp/one.kc kubectl get pods'):
            self.assertEqual(resolved['accounts'][0]['platform'], 'kubernetes', path)

    def test_the_last_profile_a_call_names_wins(self):
        """The AWS CLI keeps the last `--profile`, so an override appended to a command is the one that ran."""
        for path, resolved in self.each('aws s3 ls --profile default --profile home'):
            self.assertEqual(resolved['accounts'][0]['account_id'], '987654321098', path)

    def test_a_web_identity_role_signs_the_call_in_ahead_of_the_profile(self):
        """botocore assumes the role these name ahead of the profile's own account."""
        web = 'AWS_ROLE_ARN=arn:aws:iam::999999999999:role/ci AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/t '
        for path, resolved in self.each(web + 'aws s3 ls'):
            self.assertEqual(resolved['accounts'][0]['account_id'], '999999999999', path)

    def test_an_explicit_profile_turns_the_environment_web_identity_off(self):
        """botocore sets `disable_env_vars` when a profile is named, so the profile answers."""
        web = 'AWS_ROLE_ARN=arn:aws:iam::999999999999:role/ci AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/t '
        for path, resolved in self.each(web + 'aws s3 ls --profile home'):
            self.assertEqual(resolved['accounts'][0]['account_id'], '987654321098', path)

    def test_an_unreadable_config_file_drops_only_the_aws_account(self):
        """The other platforms on the same command still resolve."""
        for path, resolved in self.each('docker push %s/app:1; AWS_CONFIG_FILE=./config aws s3 ls' % ECR_HOST):
            self.assertEqual(resolved['accounts'][0]['registry'], ECR_HOST, path)

    def test_a_profile_name_with_a_space_is_that_profile_not_the_default(self):
        config = Path(tempfile.mkdtemp(), 'config')
        config.write_text('[profile my profile]\nsso_account_id = 555555555555\n')
        for path, resolved in self.each("AWS_CONFIG_FILE=%s AWS_PROFILE='my profile' aws s3 ls" % config):
            self.assertEqual(resolved['accounts'][0]['account_id'], '555555555555', path)

    def test_half_a_web_identity_pair_is_not_web_identity(self):
        """botocore needs both variables; one alone leaves the profile to answer."""
        for path, resolved in self.each('AWS_ROLE_ARN=arn:aws:iam::999999999999:role/ci aws s3 ls --profile home'):
            self.assertEqual(resolved['accounts'][0]['account_id'], '987654321098', path)

    def test_the_role_a_profile_assumes_is_the_account_not_the_one_it_names(self):
        """A profile with `role_arn` assumes that role, whatever account hint it also carries."""
        config = Path(tempfile.mkdtemp(), 'config')
        config.write_text('[profile ops]\nrole_arn = arn:aws:iam::444444444444:role/ops\n'
                          'source_profile = home\nsso_account_id = 111111111111\n')
        for path, resolved in self.each('AWS_CONFIG_FILE=%s aws s3 ls --profile ops' % config):
            self.assertEqual(resolved['accounts'][0]['account_id'], '444444444444', path)

    def test_an_explicit_profile_turns_the_environment_keys_off(self):
        """botocore drops the environment's keys when `--profile` names a profile, so the profile answers."""
        for path, resolved in self.each('AWS_ACCESS_KEY_ID=AKIA' + 'EXAMPLEEXAMPLE12 aws s3 ls --profile home'):  # gitleaks:allow
            self.assertEqual(resolved['accounts'][0]['account_id'], '987654321098', path)

    def test_a_relative_kubeconfig_is_asked_again_from_another_folder(self):
        """kubectl reads `./kc` from the call's own folder, so the memo answers per folder."""
        first, second = tempfile.mkdtemp(), tempfile.mkdtemp()
        for path, hook in zip(HOOK_PATHS, HOOKS):
            open(self.run_log, 'w').close()
            state = {}
            hook._accounts('kubectl --kubeconfig ./kc get pods', first, state)
            hook._accounts('kubectl --kubeconfig ./kc get pods', second, state)
            self.assertEqual(len([argv for argv in self.runs() if argv[0] == 'kubectl']), 2, path)

    def test_a_list_given_to_the_kubeconfig_flag_is_not_the_default_cluster(self):
        """The flag takes one file; kubectl cannot open a list there, so the default config did not answer."""
        for path, resolved in self.each('kubectl --kubeconfig /tmp/a.kc:/tmp/b.kc get pods'):
            self.assertIsNone(resolved, path)

    def test_a_single_dash_long_option_is_not_an_attached_server(self):
        """kubectl reads `-server` as a flag, not `-s` with `erver` attached."""
        for path, resolved in self.each('kubectl logs pod -since=1h'):
            self.assertNotEqual((resolved or {}).get('accounts', [{}])[0].get('server'), 'ince=1h', path)

    def test_docker_short_global_options_take_their_value(self):
        """`-c` is `--context` and `-l` is `--log-level`; their value is not the subcommand."""
        for command in ('docker -c prod push %s/app:1' % ECR_HOST, 'docker -l debug push %s/app:1' % ECR_HOST):
            for path, resolved in self.each(command):
                self.assertEqual(resolved['accounts'][0]['registry'], ECR_HOST, '%s / %s' % (path, command))

    def test_a_cloud_call_whose_home_cannot_be_read_resolves_nothing(self):
        """A substituted `HOME` is not our own home, so the ambient config file must not answer for it."""
        for path, resolved in self.each('HOME=$(cat .where) aws s3 ls --profile home'):
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    def test_a_config_file_that_cannot_be_read_resolves_nothing(self):
        for path, resolved in self.each('AWS_CONFIG_FILE=$(cat .where) aws s3 ls --profile home'):
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    def test_azure_reads_the_profile_its_config_directory_names(self):
        """The CLI honours `AZURE_CONFIG_DIR`, so the home folder's profile is the wrong subscription."""
        folder = Path(tempfile.mkdtemp(), 'azure')
        folder.mkdir()
        Path(folder, 'azureProfile.json').write_bytes(b'\xef\xbb\xbf' + json.dumps(
            {'subscriptions': [{'id': '00000000-0000-0000-0000-000000000003', 'name': 'Other Tenant',
                                'isDefault': True}]}).encode('utf-8'))
        for path, resolved in self.each('AZURE_CONFIG_DIR=%s az group list' % folder):
            self.assertEqual(resolved['accounts'][0]['subscription_id'],
                             '00000000-0000-0000-0000-000000000003', path)
        self.assertEqual(self.runs(), [])

    def test_an_azure_config_directory_with_no_profile_resolves_nothing(self):
        """The CLI is not run under a directory the call chose, so an empty one leaves the subscription unknown
        rather than falling back to the home profile."""
        for path, resolved in self.each('AZURE_CONFIG_DIR=%s az group list' % tempfile.mkdtemp()):
            self.assertIsNone(resolved, path)
        self.assertEqual([argv for argv in self.runs() if argv[0] == 'az'], [])

    def test_a_docker_image_push_reaches_the_same_registry_as_a_push(self):
        """docker's management form: `docker image push` is the same call as `docker push`."""
        for path, resolved in self.each('docker image push %s/app:v1' % ECR_HOST):
            self.assertEqual(resolved['accounts'], [
                {'platform': 'docker', 'registry': ECR_HOST, 'source': 'hostname'},
                {'platform': 'aws', 'account_id': '210987654321', 'source': 'hostname'}], path)

    def test_a_cloud_call_after_a_source_resolves_nothing(self):
        for path, resolved in self.each('source ./.env; aws s3 ls --profile home'):
            self.assertIsNone(resolved, path)

    def test_an_inline_profile_decides_the_call_it_prefixes(self):
        for path, resolved in self.each('AWS_PROFILE=home aws s3 ls'):
            self.assertEqual(resolved['accounts'][0]['account_id'], '987654321098', path)
        self.assertEqual(self.runs(), [])

    def test_a_call_with_no_profile_reads_the_default_section(self):
        for path, resolved in self.each('aws s3 ls'):
            self.assertEqual(resolved['accounts'][0]['account_id'], '111111111111', path)

    def test_the_account_inside_a_role_arn_is_read(self):
        for path, resolved in self.each('aws s3 ls --profile assumed'):
            self.assertEqual(resolved['accounts'][0]['account_id'], '222222222222', path)

    def test_a_profile_the_file_cannot_resolve_falls_through_to_the_cli(self):
        for path, resolved in self.each('aws s3 ls --profile static'):
            self.assertEqual(resolved['accounts'], [{'platform': 'aws', 'account_id': '333333333333',
                                                     'profile': 'static', 'source': 'command'}], path)
        self.assertEqual(self.runs()[0][:3], ['aws', 'sts', 'get-caller-identity'])

    def test_a_profile_absent_from_the_file_is_unknown_and_never_the_default(self):
        for path, resolved in self.each('aws s3 ls --profile nosuchprofile'):
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    def test_keys_in_the_environment_leave_the_account_unknown(self):
        with patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE'}):
            for path, resolved in self.each('aws s3 ls'):
                self.assertIsNone(resolved, path)

    def test_a_second_call_with_the_same_profile_does_not_look_it_up_again(self):
        hook = HOOKS[0]
        state = {}
        for _ in range(5):
            self.resolve(hook, 'aws s3 ls --profile static', state)
        self.assertEqual(len(self.runs()), 1)

    def test_nothing_opens_the_credentials_file(self):
        hook = HOOKS[0]
        with patch('builtins.open', side_effect=open) as opened:
            self.resolve(hook, 'aws s3 ls --profile home', {})
        for call in opened.call_args_list:
            self.assertNotIn('credentials', str(call.args[0]))

    # -- Azure: JSON behind a byte-order mark ---------------------------------

    def test_the_default_subscription_is_read_through_the_byte_order_mark(self):
        for path, resolved in self.each('az storage blob upload --file x'):
            self.assertEqual(resolved['accounts'], [{
                'platform': 'azure', 'subscription_id': '00000000-0000-0000-0000-000000000001',
                'subscription_name': 'Acme Production', 'tenant_id': '00000000-0000-0000-0000-0000000000aa',
                'tenant_domain': 'acme.onmicrosoft.com', 'source': 'file'}], path)
        self.assertEqual(self.runs(), [])

    def test_a_named_subscription_is_matched_by_name_or_by_id(self):
        for named in ('"Acme Sandbox"', '00000000-0000-0000-0000-000000000002'):
            for path, resolved in self.each('az storage blob upload --subscription %s' % named):
                self.assertEqual(resolved['accounts'][0]['subscription_id'],
                                 '00000000-0000-0000-0000-000000000002', '%s via %s' % (path, named))

    def test_a_subscription_absent_from_the_file_is_unknown_and_never_the_default(self):
        for path, resolved in self.each('az storage blob upload --subscription nosuchsub'):
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    def test_azure_falls_through_to_the_cli_when_the_file_is_missing(self):
        os.remove(os.path.join(self.home, '.azure', 'azureProfile.json'))
        for path, resolved in self.each('az storage blob upload --file x'):
            self.assertEqual(resolved['accounts'][0]['subscription_id'],
                             '00000000-0000-0000-0000-000000000002', path)
        self.assertEqual(self.runs()[0][:3], ['az', 'account', 'show'])

    def test_a_turn_that_never_runs_az_reads_nothing_about_azure(self):
        hook = HOOKS[0]
        with patch('builtins.open', side_effect=open) as opened:
            self.resolve(hook, 'kubectl get pods', {})
        for call in opened.call_args_list:
            self.assertNotIn('.azure', str(call.args[0]))
        self.assertNotIn(['az', 'account', 'show', '-o', 'json'], self.runs())

    # -- Kubernetes: the CLI, because the kubeconfig is YAML ------------------

    def test_a_kubectl_call_carries_its_cluster_and_never_a_credential(self):
        for path, resolved in self.each('kubectl --context prod-eks apply -f deploy.yaml'):
            self.assertEqual(resolved['accounts'], [{
                'platform': 'kubernetes',
                'server': 'https://' + 'a1b2c3d4' * 4 + '.gr7.us-west-2.eks.amazonaws.com',
                'cluster': 'prod', 'context': 'prod-eks', 'source': 'command'}], path)
            self.assertNotIn(FAKE_SECRET, json.dumps(resolved), path)

    def test_the_users_block_is_never_asked_for(self):
        self.resolve(HOOKS[0], 'kubectl get pods', {})
        for argv in self.runs():
            query = ' '.join(argv)
            self.assertNotIn('users', query)
            self.assertNotIn('client-key', query)
            self.assertIn('--minify', query)

    def test_a_context_the_kubeconfig_does_not_have_is_unknown(self):
        for path, resolved in self.each('kubectl --context nosuchcontext get pods'):
            self.assertIsNone(resolved, path)

    # -- Docker: the hostname, never a credential helper ----------------------

    def test_a_push_to_ecr_carries_the_aws_account_from_the_hostname(self):
        for path, resolved in self.each('docker push %s/app:1' % ECR_HOST):
            self.assertEqual(resolved['accounts'], [
                {'platform': 'docker', 'registry': ECR_HOST, 'source': 'hostname'},
                {'platform': 'aws', 'account_id': '210987654321', 'source': 'hostname'}], path)
        self.assertEqual(self.runs(), [])

    def test_no_credential_helper_is_ever_executed(self):
        hook = HOOKS[0]
        state = {}
        for command in ('docker push %s/app:1' % ECR_HOST, 'docker pull acme/app', 'docker login ghcr.io'):
            self.resolve(hook, command, state)
        for argv in self.runs():
            self.assertNotIn('docker-credential', argv[0])
        self.assertEqual(self.runs(), [])

    def test_an_image_with_no_registry_is_docker_hub(self):
        for path, resolved in self.each('docker push acme/app:latest'):
            self.assertEqual(resolved['accounts'],
                             [{'platform': 'docker', 'registry': 'docker.io', 'source': 'hostname'}], path)

    def test_a_local_docker_call_names_no_registry(self):
        for path, resolved in self.each('docker ps -a'):
            self.assertIsNone(resolved, path)

    def test_an_azure_registry_is_recorded_without_an_aws_account(self):
        for path, resolved in self.each('docker push acme.azurecr.io/app:1'):
            self.assertEqual([a['platform'] for a in resolved['accounts']], ['docker'], path)

    # -- the whole payload ----------------------------------------------------

    def test_no_secret_from_any_credential_store_reaches_the_payload(self):
        hook = HOOKS[0]
        state = {}
        found = []
        for command in ('aws s3 ls --profile home', 'az storage blob upload --file x',
                        'kubectl get pods', 'docker push %s/app:1' % ECR_HOST):
            found.append(self.resolve(hook, command, state))
        self.assertNotIn(FAKE_SECRET, json.dumps(found))

    def test_a_command_from_the_never_run_list_is_refused_by_the_allowlist(self):
        """The never-run list needs no rule of its own: the allow-list is a prefix match, so nothing else runs."""
        hook = HOOKS[0]
        for argv in (['aws', 'configure', 'export-credentials'], ['databricks', 'auth', 'env'],
                     ['gcloud', 'auth', 'print-access-token'], ['vault', 'token', 'lookup'],
                     ['helm', 'env'], ['kind', 'get', 'kubeconfig'], ['stripe', 'config', '--list'],
                     ['kubectl', 'config', 'view', '--raw']):
            self.assertIsNone(hook._account_run(argv, self.repo, {}, {}), argv)
        self.assertEqual(self.runs(), [])

    def test_every_platform_is_one_handler_and_one_registry_line(self):
        """The registry is the whole extension point: a new platform is a function and a line, never new machinery."""
        hook = HOOKS[0]
        self.assertEqual(sorted(hook._ACCOUNT_HANDLERS), ['aws', 'az', 'docker', 'gh', 'git', 'kubectl'])
        for program, handler in hook._ACCOUNT_HANDLERS.items():
            self.assertEqual(handler.__name__.startswith('_account_'), True, program)


if __name__ == '__main__':
    unittest.main()
