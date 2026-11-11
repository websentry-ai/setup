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
sso_start_url = https://acme.awsapps.com/start
sso_account_id = 111111111111
sso_role_name = Engineer

[profile home]
region = us-west-2
sso_start_url = https://acme.awsapps.com/start
sso_role_name = Engineer
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
# `(none)` answers a call that names no profile, as an instance role would, apart from `--profile default`.
profile = args[args.index('--profile') + 1] if '--profile' in args else (
    '(none)' if '(none)' in answers else 'default')
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
        Path(aws, 'config').write_text('[profile home]\nsso_start_url = https://acme.awsapps.com/start\nsso_role_name = Engineer\nsso_account_id = 555555555555\n')
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
        Path(folder, 'config').write_text('[profile home]\nsso_start_url = https://acme.awsapps.com/start\nsso_role_name = Engineer\nsso_account_id = 222222222222\n')
        for path, resolved in self.each("AWS_CONFIG_FILE='%s' aws s3 ls --profile home" % Path(folder, 'config')):
            self.assertEqual(resolved['accounts'][0]['account_id'], '222222222222', path)

    def test_a_relative_config_file_is_read_from_the_call_s_own_folder(self):
        """The CLI opens it from where the call ran, not from where the hook runs."""
        Path(self.repo, 'config').write_text('[profile home]\nsso_start_url = https://acme.awsapps.com/start\nsso_role_name = Engineer\nsso_account_id = 666666666666\n')
        for path, resolved in self.each('AWS_CONFIG_FILE=config aws s3 ls --profile home'):
            self.assertEqual(resolved['accounts'][0]['account_id'], '666666666666', path)

    def test_a_spaced_profile_named_on_the_command_is_that_profile(self):
        config = Path(tempfile.mkdtemp(), 'config')
        config.write_text('[profile "my profile"]\nsso_start_url = https://acme.awsapps.com/start\nsso_role_name = Engineer\nsso_account_id = 555555555555\n')
        for path, resolved in self.each("AWS_CONFIG_FILE=%s aws s3 ls --profile 'my profile'" % config):
            self.assertEqual(resolved['accounts'][0]['account_id'], '555555555555', path)

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
        config.write_text('[profile "my profile"]\nsso_start_url = https://acme.awsapps.com/start\nsso_role_name = Engineer\nsso_account_id = 555555555555\n')
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

    def test_an_unsigned_request_acts_as_no_account(self):
        """`--no-sign-request` sends the request anonymously."""
        for path, resolved in self.each('aws --no-sign-request s3 ls s3://public-bucket'):
            self.assertIsNone(resolved, path)

    def test_a_relative_azure_config_dir_is_read_again_from_another_folder(self):
        """A relative AZURE_CONFIG_DIR the hook inherits is read from each call's own folder."""
        first, second = tempfile.mkdtemp(), tempfile.mkdtemp()
        for folder, name in ((first, 'First'), (second, 'Second')):
            Path(folder, 'azcfg').mkdir()
            Path(folder, 'azcfg', 'azureProfile.json').write_text(json.dumps({'subscriptions': [
                {'id': '00000000-0000-0000-0000-00000000000%d' % len(name), 'name': name, 'isDefault': True}]}))
        with patch.dict(os.environ, {'AZURE_CONFIG_DIR': 'azcfg'}):
            for path, hook in zip(HOOK_PATHS, HOOKS):
                state = {}
                one = hook._accounts('az group list', first, state)
                two = hook._accounts('az group list', second, state)
                self.assertEqual([one['accounts'][0]['subscription_name'], two['accounts'][0]['subscription_name']],
                                 ['First', 'Second'], path)

    def test_docker_login_with_no_server_is_docker_hub(self):
        for path, resolved in self.each('docker login --username alice --password-stdin'):
            self.assertEqual(resolved['accounts'][0]['registry'], 'docker.io', path)

    def test_a_relative_kubeconfig_from_an_unknown_folder_is_unknown(self):
        """kubectl would read it from a folder we cannot name, not from ours."""
        for path, hook in zip(HOOK_PATHS, HOOKS):
            self.assertIsNone(hook._accounts('kubectl --kubeconfig ./kc get pods', None, {}), path)

    def test_a_relative_azure_directory_from_an_unknown_folder_is_unknown(self):
        with patch.dict(os.environ, {'AZURE_CONFIG_DIR': 'azcfg'}):
            for path, hook in zip(HOOK_PATHS, HOOKS):
                self.assertIsNone(hook._accounts('az group list', None, {}), path)

    def test_a_subscription_selector_is_matched_exactly_as_written(self):
        folder = Path(tempfile.mkdtemp(), 'azure')
        folder.mkdir()
        Path(folder, 'azureProfile.json').write_bytes(json.dumps({'subscriptions': [
            {'id': '00000000-0000-0000-0000-00000000000a', 'name': 'Acme  Production', 'isDefault': False},
            {'id': '00000000-0000-0000-0000-00000000000b', 'name': 'Acme Production', 'isDefault': True},
        ]}).encode('utf-8'))
        for path, resolved in self.each("AZURE_CONFIG_DIR=%s az group list --subscription 'Acme  Production'"
                                        % folder):
            self.assertEqual(resolved['accounts'][0]['subscription_id'],
                             '00000000-0000-0000-0000-00000000000a', path)

    def test_a_relative_kubeconfig_with_a_space_from_an_unknown_folder_is_unknown(self):
        with patch.dict(os.environ, {'KUBECONFIG': './my kc'}):
            for path, hook in zip(HOOK_PATHS, HOOKS):
                self.assertIsNone(hook._accounts('kubectl get pods', None, {}), path)

    def test_a_later_context_switch_leaves_the_earlier_kubectl_call_unknown(self):
        """Accounts are read when the turn ends; the call before `use-context` would get the switched cluster."""
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            before = hook._accounts('kubectl get pods', self.repo, state)
            hook._accounts('kubectl config use-context staging', self.repo, state)
            named = hook._accounts('kubectl --context prod-eks get pods', self.repo, state)
            self.assertEqual(before.get('accounts'), [], path)
            self.assertEqual(named['accounts'][0]['context'], 'prod-eks', path)

    def test_a_later_subscription_switch_leaves_the_earlier_az_call_unknown(self):
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            before = hook._accounts('az group list', self.repo, state)
            hook._accounts('az account set --subscription "Acme Sandbox"', self.repo, state)
            self.assertEqual(before.get('accounts'), [], path)

    def test_a_named_subscription_survives_a_later_switch(self):
        """An account the call named itself is not the active one, so a switch does not touch it."""
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            before = hook._accounts("az group list --subscription 'Acme Production'", self.repo, state)
            hook._accounts('az account set --subscription "Acme Sandbox"', self.repo, state)
            self.assertEqual(before['accounts'][0]['subscription_name'], 'Acme Production', path)

    def test_a_docker_login_url_is_its_host(self):
        for path, resolved in self.each('docker login --username AWS --password-stdin https://%s/' % ECR_HOST):
            self.assertEqual(resolved['accounts'], [
                {'platform': 'docker', 'registry': ECR_HOST, 'source': 'hostname'},
                {'platform': 'aws', 'account_id': '210987654321', 'source': 'hostname'}], path)

    def test_a_docker_login_url_keeps_its_port(self):
        """Registries on one host are told apart by port, as an image push already records them."""
        for path, resolved in self.each('docker login https://user@registry.example.com:5000/'):
            self.assertEqual(resolved['accounts'][0]['registry'], 'registry.example.com:5000', path)

    def test_a_powershell_web_identity_assignment_leaves_the_call_unknown(self):
        """The shell walk does not model `$env:`, and these two decide which account signs the call in."""
        for path, resolved in self.each('$env:AWS_ROLE_ARN = "arn:aws:iam::999999999999:role/ci"; '
                                        '$env:AWS_WEB_IDENTITY_TOKEN_FILE = "/tmp/t"; aws s3 ls'):
            self.assertIsNone(resolved, path)

    def test_kubectl_config_reaches_no_cluster(self):
        """`set-cluster --server` writes the kubeconfig; it does not talk to that server."""
        for path, resolved in self.each('kubectl config set-cluster prod --server=https://eks.example.com'):
            self.assertIsNone(resolved, path)

    def test_a_context_switch_behind_a_global_option_is_still_a_switch(self):
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            before = hook._accounts('kubectl get pods', self.repo, state)
            hook._accounts('kubectl --kubeconfig /tmp/a config use-context staging', self.repo, state)
            self.assertEqual(before.get('accounts'), [], path)
        for path, resolved in self.each('kubectl --kubeconfig /tmp/a config set-cluster prod --server=https://x'):
            self.assertIsNone(resolved, path)

    def test_every_kubectl_config_write_is_a_switch(self):
        """`use` is `use-context`'s alias, and `set current-context` or an edit to the current context moves it too."""
        for switch in ('kubectl config use staging', 'kubectl config set current-context staging',
                       'kubectl config set-context --current --cluster=other',
                       'kubectl -o json config use-context staging'):
            for path, hook in zip(HOOK_PATHS, HOOKS):
                state = {}
                before = hook._accounts('kubectl get pods', self.repo, state)
                hook._accounts(switch, self.repo, state)
                self.assertEqual(before.get('accounts'), [], '%s / %s' % (path, switch))
        for read in ('kubectl config view', 'kubectl config current-context', 'kubectl config get-contexts'):
            for path, hook in zip(HOOK_PATHS, HOOKS):
                state = {}
                before = hook._accounts('kubectl get pods', self.repo, state)
                hook._accounts(read, self.repo, state)
                self.assertEqual(before['accounts'][0]['cluster'], 'prod', '%s / %s' % (path, read))

    def test_an_option_before_config_is_skipped_as_kubectl_does(self):
        """kubectl's parser takes any option written without `=` to carry a value while it finds the subcommand."""
        for option in ('-o json', '--output json', '--output=json'):
            command = 'kubectl %s config set-cluster prod --server=https://eks.example.com' % option
            for path, resolved in self.each(command):
                self.assertIsNone(resolved, '%s / %s' % (path, command))

    def test_an_az_switch_behind_a_global_option_is_still_a_switch(self):
        for switch in ('az -o json account set --subscription "Acme Sandbox"', 'az --output none login'):
            for path, hook in zip(HOOK_PATHS, HOOKS):
                state = {}
                before = hook._accounts('az group list', self.repo, state)
                hook._accounts(switch, self.repo, state)
                self.assertEqual(before.get('accounts'), [], '%s / %s' % (path, switch))

    def test_a_server_flag_wins_over_a_named_cluster(self):
        """`--server` is the endpoint the call reached, whichever cluster or context it also names."""
        for path, resolved in self.each('kubectl --cluster other --server https://k8s.example.com get pods'):
            self.assertEqual(resolved['accounts'], [{'platform': 'kubernetes', 'server': 'https://k8s.example.com',
                                                     'source': 'command'}], path)

    def test_a_web_identity_profile_takes_its_role_from_the_environment_first(self):
        """botocore lets AWS_ROLE_ARN override a web-identity profile's own role, unless --profile names it."""
        config = Path(tempfile.mkdtemp(), 'config')
        config.write_text('[profile wid]\nrole_arn = arn:aws:iam::111111111111:role/ci\n'
                          'web_identity_token_file = /tmp/token\n')
        env = {'AWS_CONFIG_FILE': str(config), 'AWS_ROLE_ARN': 'arn:aws:iam::555555555555:role/deploy',
               'AWS_WEB_IDENTITY_TOKEN_FILE': '/tmp/other-token'}
        with patch.dict(os.environ, env):
            for path, resolved in self.each('AWS_PROFILE=wid aws s3 ls'):
                self.assertEqual(resolved['accounts'][0]['account_id'], '555555555555', path)
            for path, resolved in self.each('aws s3 ls --profile wid'):
                self.assertEqual(resolved['accounts'][0]['account_id'], '111111111111', path)

    def test_klog_flags_and_a_double_dash_do_not_hide_kubectl_config(self):
        """Older kubectl takes klog's on/off flags, and `--` ends cobra's search, so neither reaches a cluster."""
        for command in ('kubectl --logtostderr config set-cluster prod --server=https://eks.example.com',
                        'kubectl --alsologtostderr config set-cluster prod --server=https://eks.example.com',
                        'kubectl -- config view', 'kubectl -- config set-cluster prod --server=https://x'):
            for path, resolved in self.each(command):
                self.assertIsNone(resolved, '%s / %s' % (path, command))
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            before = hook._accounts('kubectl get pods', self.repo, state)
            hook._accounts('kubectl --logtostderr config use-context staging', self.repo, state)
            self.assertEqual(before.get('accounts'), [], path)

    def test_a_kubeconfig_edit_drops_a_named_context_but_use_context_does_not(self):
        """`set-cluster` can move the server a named context reaches; `use-context` moves only the current one."""
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            named = hook._accounts('kubectl --context prod-eks get pods', self.repo, state)
            hook._accounts('kubectl config use-context staging', self.repo, state)
            self.assertEqual(named['accounts'][0]['context'], 'prod-eks', path)
            hook._accounts('kubectl config set-cluster prod --server=https://new.example.com', self.repo, state)
            self.assertEqual(named.get('accounts'), [], path)
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            explicit = hook._accounts('kubectl --server https://k8s.example.com get pods', self.repo, state)
            hook._accounts('kubectl config set-cluster prod --server=https://new.example.com', self.repo, state)
            self.assertEqual(explicit['accounts'][0]['server'], 'https://k8s.example.com', path)

    def test_a_relative_azure_config_dir_is_read_from_the_calls_folder(self):
        """az resolves a relative AZURE_CONFIG_DIR from where it runs, as the CLI itself would."""
        folder = Path(self.repo, '.az')
        folder.mkdir()
        Path(folder, 'azureProfile.json').write_bytes(b'\xef\xbb\xbf' + json.dumps({'subscriptions': [
            {'id': '00000000-0000-0000-0000-000000000009', 'name': 'Local Dev', 'isDefault': True}]}).encode())
        for path, resolved in self.each('AZURE_CONFIG_DIR=.az az group list'):
            self.assertEqual(resolved['accounts'][0]['subscription_name'], 'Local Dev', path)

    def test_a_context_name_with_a_space_is_still_looked_up(self):
        kube = json.loads(os.environ['FAKE_KUBE'])
        kube['clusters']['team ctx'] = {'server': 'https://team.example.com', 'name': 'team'}
        with patch.dict(os.environ, {'FAKE_KUBE': json.dumps(kube)}):
            for path, resolved in self.each("kubectl --context 'team ctx' get pods"):
                self.assertEqual(resolved['accounts'][0]['server'], 'https://team.example.com', path)
                self.assertEqual(resolved['accounts'][0]['context'], 'team ctx', path)

    def test_a_login_written_into_a_server_url_is_never_kept(self):
        """`https://user:token@host:6443/path?x` is recorded as `https://host:6443`, from the flag or the kubeconfig."""
        for path, resolved in self.each('kubectl --server https://u:s3cret@k8s.example.com:6443/api?x=1 get pods'):
            self.assertEqual(resolved['accounts'][0]['server'], 'https://k8s.example.com:6443', path)
        kube = json.loads(os.environ['FAKE_KUBE'])
        kube['clusters']['prod-eks']['server'] = 'https://u:s3cret@eks.example.com:443/'
        with patch.dict(os.environ, {'FAKE_KUBE': json.dumps(kube)}):
            for path, resolved in self.each('kubectl get pods'):
                self.assertEqual(resolved['accounts'][0]['server'], 'https://eks.example.com:443', path)
                self.assertNotIn('s3cret', json.dumps(resolved), path)

    def test_an_aws_configure_write_drops_the_earlier_aws_account(self):
        """Accounts are read when the turn ends, so one read before `aws configure set` would be the edited one."""
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            before = hook._accounts('aws s3 ls --profile home', self.repo, state)
            hook._accounts('aws configure get region --profile home', self.repo, state)
            self.assertEqual(len(before['accounts']), 1, path)
            hook._accounts('aws --profile home configure set sso_account_id 999999999999', self.repo, state)
            self.assertEqual(before.get('accounts'), [], path)

    def test_an_ecr_login_keeps_its_account_behind_a_port_and_a_bare_host_is_lowercased(self):
        for path, resolved in self.each('docker login https://%s:443/' % ECR_HOST):
            self.assertIn({'platform': 'aws', 'account_id': '210987654321', 'source': 'hostname'},
                          resolved['accounts'], path)
        for path, resolved in self.each('docker login REGISTRY.EXAMPLE.COM:5000'):
            self.assertEqual(resolved['accounts'][0]['registry'], 'registry.example.com:5000', path)

    def test_only_the_active_clouds_default_subscription_counts(self):
        """azureProfile.json keeps a default per cloud; az uses the active cloud's, from its config or AZURE_CLOUD_NAME."""
        folder = Path(self.home, '.azure')
        Path(folder, 'azureProfile.json').write_text(json.dumps({'subscriptions': [
            {'id': '00000000-0000-0000-0000-0000000000a1', 'name': 'Public', 'isDefault': True,
             'environmentName': 'AzureCloud'},
            {'id': '00000000-0000-0000-0000-0000000000b2', 'name': 'Gov', 'isDefault': True,
             'environmentName': 'AzureUSGovernment'}]}))
        Path(folder, 'config').write_text('[cloud]\nname = AzureUSGovernment\n')
        for path, resolved in self.each('az group list'):
            self.assertEqual(resolved['accounts'][0]['subscription_name'], 'Gov', path)
        for path, resolved in self.each('AZURE_CLOUD_NAME=AzureCloud az group list'):
            self.assertEqual(resolved['accounts'][0]['subscription_name'], 'Public', path)
        os.remove(os.path.join(folder, 'config'))
        for path, resolved in self.each('az group list'):
            self.assertEqual(resolved['accounts'][0]['subscription_name'], 'Public', path)

    def test_local_only_kubectl_commands_reach_no_cluster(self):
        for command in ('kubectl version --client', 'kubectl kustomize .', 'kubectl completion bash',
                        'kubectl plugin list', 'kubectl help get'):
            for path, resolved in self.each(command):
                self.assertIsNone(resolved, '%s / %s' % (path, command))
        for path, resolved in self.each('kubectl version'):
            self.assertEqual(resolved['accounts'][0]['cluster'], 'prod', path)

    def test_an_aws_configure_write_drops_only_the_profile_it_names(self):
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            home = hook._accounts('aws s3 ls --profile home', self.repo, state)
            hook._accounts('aws configure set region us-east-1 --profile other', self.repo, state)
            hook._accounts('aws configure help', self.repo, state)
            self.assertEqual(home['accounts'][0]['account_id'], '987654321098', path)
            hook._accounts('aws configure set sso_account_id 999999999999 --profile home', self.repo, state)
            self.assertEqual(home.get('accounts'), [], path)

    def test_a_quoted_or_spaced_profile_section_is_that_profile(self):
        """botocore splits a section with shlex, so `[profile "my team"]` and `[profile   ops]` are real profiles."""
        config = Path(tempfile.mkdtemp(), 'config')
        sso = 'sso_start_url = https://acme.awsapps.com/start\nsso_role_name = Engineer\n'
        config.write_text('[profile "my team"]\n' + sso + 'sso_account_id = 121212121212\n'
                          '[profile   ops]\n' + sso + 'sso_account_id = 343434343434\n')
        for command, account in (("aws s3 ls --profile 'my team'", '121212121212'),
                                 ('aws s3 ls --profile ops', '343434343434')):
            for path, resolved in self.each('AWS_CONFIG_FILE=%s %s' % (config, command)):
                self.assertEqual(resolved['accounts'][0]['account_id'], account, '%s / %s' % (path, command))
        # Unquoted, `[profile my team]` splits into three words, and botocore loads no profile from it.
        config.write_text('[profile my team]\n' + sso + 'sso_account_id = 121212121212\n')
        for path, resolved in self.each("AWS_CONFIG_FILE=%s aws s3 ls --profile 'my team'" % config):
            self.assertIsNone(resolved, path)

    def test_where_two_sections_name_one_profile_the_last_wins(self):
        """botocore keeps the last section that names a profile, whole, as `build_profile_map` does."""
        config = Path(tempfile.mkdtemp(), 'config')
        sso = 'sso_start_url = https://acme.awsapps.com/start\nsso_role_name = Engineer\n'
        config.write_text('[default]\n' + sso + 'sso_account_id = 444444444444\n'
                          '[profile default]\n' + sso + 'sso_account_id = 555555555555\n'
                          '[profile ops]\n' + sso + 'sso_account_id = 111111111111\n'
                          '[profile "ops"]\n' + sso + 'sso_account_id = 222222222222\n')
        for command, account in (('aws s3 ls', '555555555555'), ('aws s3 ls --profile ops', '222222222222')):
            for path, resolved in self.each('AWS_CONFIG_FILE=%s %s' % (config, command)):
                self.assertEqual(resolved['accounts'][0]['account_id'], account, '%s / %s' % (path, command))

    def test_local_only_aws_calls_reach_no_account(self):
        for command in ('aws configure get region --profile home', 'aws configure list', 'aws help',
                        'aws --version', 'aws s3 ls --version'):
            for path, resolved in self.each(command):
                self.assertIsNone(resolved, '%s / %s' % (path, command))

    def test_a_self_declared_account_label_is_not_the_account(self):
        """`aws_account_id`, or `sso_account_id` with no SSO sign-in, is a label an agent can write; botocore never checks it."""
        config = Path(tempfile.mkdtemp(), 'config')
        config.write_text('[profile labelled]\naws_account_id = 123456789012\n'
                          '[profile half]\nsso_account_id = 123456789012\n')
        for profile in ('labelled', 'half'):
            for path, resolved in self.each('AWS_CONFIG_FILE=%s aws s3 ls --profile %s' % (config, profile)):
                self.assertIsNone(resolved, '%s / %s' % (path, profile))

    def test_an_attached_server_url_is_the_endpoint(self):
        for path, resolved in self.each('kubectl -shttps://other.example.com get pods'):
            self.assertEqual(resolved['accounts'], [{'platform': 'kubernetes', 'server': 'https://other.example.com',
                                                     'source': 'command'}], path)

    def test_a_server_is_read_as_kubectl_reads_it(self):
        """The last server wins, attached or not; nothing after `--` is kubectl's; an unreadable one is unknown."""
        for path, resolved in self.each('kubectl --server https://a.example.com -shttps://b.example.com get pods'):
            self.assertEqual(resolved['accounts'][0]['server'], 'https://b.example.com', path)
        for path, resolved in self.each('kubectl exec deploy/api -- curl -shttps://external.example.com/health'):
            self.assertNotEqual(resolved['accounts'][0].get('server'), 'https://external.example.com', path)
            self.assertEqual(resolved['accounts'][0]['cluster'], 'prod', path)
        for path, resolved in self.each('kubectl -s"$(cat server)" get pods'):
            self.assertIsNone(resolved, path)

    def test_a_spelled_out_server_may_be_single_label_or_ipv6(self):
        for command, server in (('kubectl get pods --server myhost', 'https://myhost'),
                                ('kubectl get pods -s [::1]:6443', 'https://[::1]:6443'),
                                ('kubectl get pods --server=[fd00::1]', 'https://[fd00::1]')):
            for path, resolved in self.each(command):
                self.assertEqual(resolved['accounts'][0]['server'], server, '%s / %s' % (path, command))

    def test_a_server_with_no_scheme_is_reached_over_https(self):
        """client-go takes a bare host and reaches it over https; a stray `-s…` that is no host is not a server."""
        for command, server in (('kubectl get pods --server k8s.example.com', 'https://k8s.example.com'),
                                ('kubectl get pods --server 10.0.0.1:6443', 'https://10.0.0.1:6443')):
            for path, resolved in self.each(command):
                self.assertEqual(resolved['accounts'][0]['server'], server, '%s / %s' % (path, command))
        for path, resolved in self.each('kubectl logs pod -since 1h'):
            self.assertIsNone(resolved, path)

    def test_an_azure_cloud_switch_drops_the_earlier_default(self):
        for switch in ('az cloud set --name AzureUSGovernment', 'az config set cloud.name=AzureUSGovernment'):
            for path, hook in zip(HOOK_PATHS, HOOKS):
                state = {}
                before = hook._accounts('az group list', self.repo, state)
                hook._accounts(switch, self.repo, state)
                self.assertEqual(before.get('accounts'), [], '%s / %s' % (path, switch))

    def test_a_cloud_switch_drops_a_named_subscription_too(self):
        """A name is matched within the active cloud, so a cloud change moves it; `az account set` does not."""
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            named = hook._accounts("az group list --subscription 'Acme Production'", self.repo, state)
            hook._accounts('az account set --subscription "Acme Sandbox"', self.repo, state)
            self.assertEqual(named['accounts'][0]['subscription_name'], 'Acme Production', path)
            hook._accounts('az config set defaults.location=westus', self.repo, state)
            self.assertEqual(named['accounts'][0]['subscription_name'], 'Acme Production', path)
            hook._accounts('az cloud set --name AzureUSGovernment', self.repo, state)
            self.assertEqual(named.get('accounts'), [], path)

    def test_a_kubeconfig_the_call_set_to_something_unreadable_is_not_ours(self):
        for command in ('KUBECONFIG=$KCFG kubectl get pods', 'KUBECONFIG=$(cat kcfg) kubectl get pods'):
            for path, resolved in self.each(command):
                self.assertIsNone(resolved, '%s / %s' % (path, command))

    def test_the_active_clouds_entry_wins_over_one_that_names_no_cloud(self):
        folder = Path(self.home, '.azure')
        Path(folder, 'azureProfile.json').write_text(json.dumps({'subscriptions': [
            {'id': '00000000-0000-0000-0000-0000000000b2', 'name': 'Unnamed', 'isDefault': True},
            {'id': '00000000-0000-0000-0000-0000000000a1', 'name': 'Public', 'isDefault': True,
             'environmentName': 'AzureCloud'}]}))
        for path, resolved in self.each('az group list'):
            self.assertEqual(resolved['accounts'][0]['subscription_name'], 'Public', path)

    def test_an_aws_configure_write_with_no_profile_edits_the_environments_profile(self):
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            home = hook._accounts('aws s3 ls --profile home', self.repo, state)
            default = hook._accounts('aws s3 ls', self.repo, state)
            hook._accounts('aws configure set region us-east-1', self.repo, state)
            self.assertEqual(home['accounts'][0]['account_id'], '987654321098', path)
            self.assertEqual(default.get('accounts'), [], path)
            hook._accounts('aws configure set profile.home.sso_account_id 999999999999', self.repo, state)
            self.assertEqual(home.get('accounts'), [], path)
        for path, hook in zip(HOOK_PATHS, HOOKS):
            state = {}
            home = hook._accounts('aws s3 ls --profile home', self.repo, state)
            # An unreadable profile in the dotted key could be any of them.
            hook._accounts('aws configure set "profile.$P.sso_account_id" 999999999999', self.repo, state)
            self.assertEqual(home.get('accounts'), [], path)

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

    def test_a_profile_the_file_cannot_settle_stays_unknown_and_no_cli_runs(self):
        """Static keys name no account in the config file, and the CLI is never asked instead."""
        for path, resolved in self.each('aws s3 ls --profile static'):
            self.assertIsNone(resolved, path)
        self.assertEqual([argv for argv in self.runs() if argv[0] in ('aws', 'az')], [])

    def test_a_credential_process_an_agent_planted_is_never_run(self):
        """The CLI would run a profile's `credential_process`, which an agent can write earlier in the turn."""
        config = Path(tempfile.mkdtemp(), 'config')
        config.write_text("[profile x]\ncredential_process = /bin/sh -c 'touch /tmp/planted'\n")
        with patch.dict(os.environ, {'AWS_CONFIG_FILE': str(config)}):
            for path, resolved in self.each('aws s3 ls --profile x'):
                self.assertIsNone(resolved, path)
        self.assertEqual([argv for argv in self.runs() if argv[0] == 'aws'], [])

    def test_a_profile_absent_from_the_file_is_unknown_and_never_the_default(self):
        for path, resolved in self.each('aws s3 ls --profile nosuchprofile'):
            self.assertIsNone(resolved, path)
        self.assertEqual(self.runs(), [])

    def test_keys_in_the_environment_leave_the_account_unknown(self):
        with patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE'}):
            for path, resolved in self.each('aws s3 ls'):
                self.assertIsNone(resolved, path)

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

    def test_azure_with_no_profile_file_stays_unknown_and_no_cli_runs(self):
        """az loads the extensions in its config folder, so it is never run to fill a gap in the file."""
        os.remove(os.path.join(self.home, '.azure', 'azureProfile.json'))
        for path, resolved in self.each('az storage blob upload --file x'):
            self.assertIsNone(resolved, path)
        self.assertEqual([argv for argv in self.runs() if argv[0] == 'az'], [])

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
