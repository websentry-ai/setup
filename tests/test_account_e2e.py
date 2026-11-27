"""Every shipped hook, run as its editor runs it against a recording server, sends the accounts each shell call acted
as on the turn log, and nothing else changes.

Each test runs the hook file as a subprocess, with a sandboxed $HOME holding fake AWS, kubeconfig, Azure, gh and git
configuration, the real `git`, `gh` and `kubectl`, and every proxy pointed at a closed port. The comparisons against
the hook as it was before account resolution load that version from `origin/staging`.

Set UNBOUND_ACCOUNT_E2E_OUT to a folder to keep each turn-log body there as <test>_<tool>.json, and
UNBOUND_ACCOUNT_E2E_STAGING to an extracted origin/staging tree where this checkout has no git history.
"""

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.conftest import REPO
from tests.test_transfer_e2e import (  # noqa: F401  (gateway and sandbox are fixtures)
    HOOKS, TURN_LOG_PATHS, command_of, gateway, hook_env, sandbox, tool_entries, turn_log, write_jsonl,
)

TOOLS = sorted(HOOKS)
# The keys account resolution adds to a shell call's turn-log entry; nothing else may differ from the old hook.
NEW_KEYS = frozenset({'accounts', 'pushed_repo', 'pushed_remote', 'pushed'})
# The hook's own per-turn lookup budget (_ACCOUNT_TURN_BUDGET).
TURN_BUDGET = 10.0

# Credentials planted in every file a CLI keeps them in; none may ever reach the gateway.
GH_TOKEN = 'gho_E2ESECRETghTOKEN0123456789abcdef'
AWS_SECRET = 'E2ESECRETawsSecretKey/0123456789abcdefXYZ'
AWS_KEY_ID = 'AKIAE2ESECRET0000001'
KUBE_TOKEN = 'E2ESECRETkubeBearerToken.0123456789'
KUBE_KEY_RAW = 'E2ESECRETkubeClientKeyData'
# kubeconfig keeps key data base64-encoded, and kubectl refuses the file otherwise.
KUBE_KEY = base64.b64encode(KUBE_KEY_RAW.encode()).decode()
AZURE_TOKEN = 'E2ESECRETazureRefreshToken0123456789'
DOCKER_AUTH = 'E2ESECRETdockerAuth0123456789'
GIT_CREDENTIAL = 'E2ESECRETgitPassword0123456789'
SECRETS = (GH_TOKEN, AWS_SECRET, AWS_KEY_ID, KUBE_TOKEN, KUBE_KEY, KUBE_KEY_RAW, AZURE_TOKEN, DOCKER_AUTH, GIT_CREDENTIAL)

EMAIL = 'dev@acme.test'
GH_LOGIN = 'acme-dev'
PROD_ACCOUNT = '111122223333'
DEFAULT_ROLE_ACCOUNT = '444455556666'
ECR_ACCOUNT = '123456789012'
PROD_SERVER = 'https://prod.k8s.acme.test:6443'
DEV_SERVER = 'https://dev.k8s.acme.test:6443'
SUB_PROD = '11111111-1111-4111-8111-111111111111'
SUB_DEV = '22222222-2222-4222-8222-222222222222'
TENANT = '99999999-9999-4999-8999-999999999999'
ECR_IMAGE = '%s.dkr.ecr.us-east-1.amazonaws.com/app:1' % ECR_ACCOUNT

GIT_ACCOUNT = {'platform': 'git', 'email': EMAIL, 'source': 'command'}
GH_ACCOUNT = {'platform': 'github', 'host': 'github.com', 'login': GH_LOGIN, 'source': 'command'}
AWS_PROD = {'platform': 'aws', 'account_id': PROD_ACCOUNT, 'profile': 'prod', 'source': 'file'}
AWS_DEFAULT = {'platform': 'aws', 'account_id': DEFAULT_ROLE_ACCOUNT, 'profile': 'default', 'source': 'file'}
KUBE_PROD = {'platform': 'kubernetes', 'server': PROD_SERVER, 'cluster': 'prod-cluster', 'context': 'prod',
             'source': 'command'}
KUBE_CURRENT = {'platform': 'kubernetes', 'server': PROD_SERVER, 'cluster': 'prod-cluster', 'source': 'command'}
AZURE_PROD = {'platform': 'azure', 'subscription_id': SUB_PROD, 'subscription_name': 'Acme Prod', 'tenant_id': TENANT,
              'tenant_domain': 'acme.onmicrosoft.com', 'source': 'file'}
DOCKER_ECR = [{'platform': 'docker', 'registry': ECR_IMAGE.split('/')[0], 'source': 'hostname'},
              {'platform': 'aws', 'account_id': ECR_ACCOUNT, 'source': 'hostname'}]

AWS_CONFIG = """\
[default]
role_arn = arn:aws:iam::%s:role/deploy
source_profile = base

[profile base]
region = us-east-1

[profile prod]
sso_start_url = https://acme.awsapps.com/start
sso_region = us-east-1
sso_account_id = %s
sso_role_name = Admin
""" % (DEFAULT_ROLE_ACCOUNT, PROD_ACCOUNT)
AWS_CREDENTIALS = '[base]\naws_access_key_id = %s\naws_secret_access_key = %s\n' % (AWS_KEY_ID, AWS_SECRET)
KUBECONFIG = """\
apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: %s
- name: dev-cluster
  cluster:
    server: %s
contexts:
- name: prod
  context: {cluster: prod-cluster, user: prod-admin}
- name: dev
  context: {cluster: dev-cluster, user: dev-admin}
users:
- name: prod-admin
  user: {token: %s}
- name: dev-admin
  user: {client-key-data: %s}
""" % (PROD_SERVER, DEV_SERVER, KUBE_TOKEN, KUBE_KEY)
GH_HOSTS = 'github.com:\n    user: %s\n    oauth_token: %s\n    git_protocol: https\n' % (GH_LOGIN, GH_TOKEN)
AZURE_PROFILE = {'installationId': 'e2e', 'subscriptions': [
    {'id': SUB_PROD, 'name': 'Acme Prod', 'state': 'Enabled', 'tenantId': TENANT,
     'tenantDefaultDomain': 'acme.onmicrosoft.com', 'isDefault': True, 'environmentName': 'AzureCloud',
     'user': {'name': EMAIL, 'type': 'user'}},
    {'id': SUB_DEV, 'name': 'Acme Dev', 'state': 'Enabled', 'tenantId': TENANT, 'isDefault': False,
     'environmentName': 'AzureCloud', 'user': {'name': EMAIL, 'type': 'user'}}]}

# One command per platform, each with the accounts the hook must send for it.
PLATFORM_CALLS = [
    ('git commit -m "ship it"', [GIT_ACCOUNT]),
    ('gh pr create --title ship --body done', [GH_ACCOUNT]),
    ('aws --profile prod s3 ls', [AWS_PROD]),
    ('kubectl --context prod get pods', [KUBE_PROD]),
    ('az vm list --subscription "Acme Prod"', [AZURE_PROD]),
    ('docker push %s' % ECR_IMAGE, DOCKER_ECR),
]

STAGING_HOOKS = {}

WINDOWS = os.name == 'nt'
# What Python and the CLIs need to start on Windows, passed through from the runner's own environment.
_WINDOWS_PASSTHROUGH = ('SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'PROCESSOR_ARCHITECTURE',
                        'NUMBER_OF_PROCESSORS', 'USERNAME', 'USERDOMAIN')

pytestmark = pytest.mark.skipif(not all(shutil.which(name) for name in ('git', 'gh', 'kubectl')),
                                reason='needs the real git, gh and kubectl')


# --- Sandbox -----------------------------------------------------------------------------------------------------


def _home_env(home):
    """The variables every CLI reads its home from: HOME, and on Windows the profile and AppData folders too."""
    env = {'HOME': str(home)}
    if WINDOWS:
        drive, rest = os.path.splitdrive(str(home))
        env.update({'USERPROFILE': str(home), 'HOMEDRIVE': drive, 'HOMEPATH': rest,
                    'APPDATA': str(home / 'AppData' / 'Roaming'), 'LOCALAPPDATA': str(home / 'AppData' / 'Local')})
        env.update({name: os.environ[name] for name in _WINDOWS_PASSTHROUGH if name in os.environ})
    return env


def _system_path():
    """The system folders, with git; on Windows git's own folder, since it is not in System32."""
    if WINDOWS:
        root = os.environ.get('SYSTEMROOT', r'C:\Windows')
        return os.pathsep.join([os.path.dirname(shutil.which('git')), os.path.join(root, 'System32'), root])
    return '/usr/bin:/bin:/usr/sbin:/sbin'


def _git(project, home, *args):
    subprocess.run(['git', *args], cwd=str(project), check=True, capture_output=True,
                   env={**_home_env(home), 'PATH': _system_path(), 'GIT_CONFIG_NOSYSTEM': '1'})


def _gh_hosts(home):
    """Where gh keeps its logins: AppData on Windows, ~/.config elsewhere."""
    if WINDOWS:
        return home / 'AppData' / 'Roaming' / 'GitHub CLI' / 'hosts.yml'
    return home / '.config' / 'gh' / 'hosts.yml'


def _add_tools(bin_dir):
    """The real gh and kubectl, which the hook runs for its two lookups; copied where a link cannot be made."""
    for name in ('gh', 'kubectl'):
        found = shutil.which(name)
        target = bin_dir / os.path.basename(found)
        if WINDOWS:
            shutil.copy2(found, str(target))
        else:
            os.symlink(found, str(target))


def _write_accounts(home):
    (home / '.gitconfig').write_text('[user]\n\temail = %s\n\tname = Dev\n' % EMAIL)
    (home / '.git-credentials').write_text('https://%s:%s@github.com\n' % (GH_LOGIN, GIT_CREDENTIAL))
    (home / '.aws').mkdir()
    (home / '.aws' / 'config').write_text(AWS_CONFIG)
    (home / '.aws' / 'credentials').write_text(AWS_CREDENTIALS)
    (home / '.kube').mkdir()
    (home / '.kube' / 'config').write_text(KUBECONFIG)
    _gh_hosts(home).parent.mkdir(parents=True)
    _gh_hosts(home).write_text(GH_HOSTS)
    (home / '.azure').mkdir()
    # The Azure CLI writes its profile with a UTF-8 BOM.
    (home / '.azure' / 'azureProfile.json').write_bytes(b'\xef\xbb\xbf' + json.dumps(AZURE_PROFILE).encode())
    (home / '.azure' / 'msal_token_cache.json').write_text(json.dumps({'RefreshToken': {'x': {'secret': AZURE_TOKEN}}}))
    (home / '.docker').mkdir()
    (home / '.docker' / 'config.json').write_text(json.dumps({'auths': {ECR_IMAGE.split('/')[0]: {'auth': DOCKER_AUTH}}}))


@pytest.fixture
def accounts(sandbox):
    """The transfer sandbox, with every platform's configuration and a checkout that has two GitHub remotes."""
    home, project = sandbox['home'], sandbox['project']
    _write_accounts(home)
    _git(project, home, 'init', '-q', '-b', 'main')
    _git(project, home, 'remote', 'add', 'origin', 'https://github.com/acme/app.git')
    _git(project, home, 'remote', 'add', 'backup', 'https://github.com/acme-backup/app.git')
    _add_tools(sandbox['bin'])
    return sandbox


def env_for(sandbox, gateway):
    if not WINDOWS:
        return {**hook_env(sandbox, gateway), 'SHELL': '/bin/zsh'}
    tmp = str(sandbox['tmp'])
    return {**hook_env(sandbox, gateway), **_home_env(sandbox['home']), 'TEMP': tmp, 'TMP': tmp,
            'PATH': os.pathsep.join([str(sandbox['bin']), _system_path()])}


def staging_hook(tool, tmp_root):
    """The hook file as it is on origin/staging, before account resolution, written outside the repository."""
    relative = HOOKS[tool].relative_to(REPO)
    if tool not in STAGING_HOOKS:
        staging_tree = os.environ.get('UNBOUND_ACCOUNT_E2E_STAGING')
        try:
            text = (Path(staging_tree) / relative).read_text(encoding='utf-8') if staging_tree else subprocess.run(['git', 'show', 'origin/staging:%s' % relative.as_posix()], cwd=str(REPO),
                                  check=True, capture_output=True, text=True).stdout
        except (OSError, subprocess.CalledProcessError):
            pytest.skip('origin/staging is not available to compare against')
        assert 'KEEP IN SYNC: account resolution' not in text, 'origin/staging already resolves accounts'
        STAGING_HOOKS[tool] = text
    path = tmp_root / 'staging-hooks' / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(STAGING_HOOKS[tool], encoding='utf-8')
    return path


# --- One turn of several shell calls, through the events each agent fires ----------------------------------------


class Turn:
    """Fires each event of one turn at a hook file and keeps how long the hook took."""

    def __init__(self, hook, env, cwd):
        self.hook, self.env, self.cwd, self.seconds, self.last = hook, env, str(cwd), 0.0, 0.0

    def fire(self, event):
        started = time.monotonic()
        result = subprocess.run([sys.executable, str(self.hook)], input=json.dumps(event), capture_output=True,
                                text=True, timeout=120, env=self.env, cwd=self.cwd)
        self.last = time.monotonic() - started
        self.seconds += self.last
        assert result.returncode == 0, '%s %s exited %d: %s' % (
            self.hook, event.get('hook_event_name'), result.returncode, result.stderr[-600:])
        if result.stdout.strip():
            answer = json.loads(result.stdout)
            assert answer.get('decision') not in ('block', 'deny'), answer
            assert answer.get('permission') != 'deny', answer
        return result


def _stamp(t0, offset):
    return (t0 + timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


PROMPT = 'ship the release'
REPLY = 'Shipped.'


def turn_claude(turn, sandbox, commands, session, t0, pre):
    project = str(sandbox['project'])
    transcript = sandbox['home'] / '.claude' / 'projects' / 'project' / ('%s.jsonl' % session)
    base = {'session_id': session, 'transcript_path': str(transcript), 'cwd': project, 'permission_mode': 'default'}
    turn.fire({**base, 'hook_event_name': 'UserPromptSubmit', 'prompt': PROMPT})
    lines = [{'type': 'user', 'sessionId': session, 'cwd': project, 'timestamp': _stamp(t0, 1), 'uuid': 'u0',
              'message': {'role': 'user', 'content': PROMPT}}]
    for i, command in enumerate(commands):
        tool_id, tool_input = 'toolu_e2e_%02d' % i, {'command': command, 'description': 'step %d' % i}
        call = {**base, 'tool_name': 'Bash', 'tool_input': tool_input, 'tool_use_id': tool_id}
        if pre:
            turn.fire({**call, 'hook_event_name': 'PreToolUse'})
        turn.fire({**call, 'hook_event_name': 'PostToolUse', 'tool_response': {
            'stdout': '', 'stderr': '', 'interrupted': False, 'isImage': False}})
        lines += [
            {'type': 'assistant', 'sessionId': session, 'cwd': project, 'timestamp': _stamp(t0, 2 + 2 * i),
             'uuid': 'a%d' % i, 'message': {'id': 'msg_%d' % i, 'role': 'assistant', 'model': 'claude-sonnet-4-5',
                                             'content': [{'type': 'tool_use', 'id': tool_id, 'name': 'Bash',
                                                          'input': tool_input}],
                                             'usage': {'input_tokens': 10, 'output_tokens': 5}}},
            {'type': 'user', 'sessionId': session, 'cwd': project, 'timestamp': _stamp(t0, 3 + 2 * i),
             'uuid': 'r%d' % i, 'message': {'role': 'user', 'content': [
                 {'type': 'tool_result', 'tool_use_id': tool_id, 'content': '', 'is_error': False}]}}]
    lines.append({'type': 'assistant', 'sessionId': session, 'cwd': project,
                  'timestamp': _stamp(t0, 4 + 2 * len(commands)), 'uuid': 'end',
                  'message': {'id': 'msg_end', 'role': 'assistant', 'model': 'claude-sonnet-4-5',
                              'content': [{'type': 'text', 'text': REPLY}],
                              'usage': {'input_tokens': 12, 'output_tokens': 7}}})
    write_jsonl(transcript, lines)
    turn.fire({**base, 'hook_event_name': 'Stop', 'stop_hook_active': False, 'last_assistant_message': REPLY})


def turn_cursor(turn, sandbox, commands, session, t0, pre):
    project = str(sandbox['project'])
    base = {'conversation_id': session, 'generation_id': session[::-1], 'model': 'claude-4.5-sonnet',
            'cursor_version': '2.0.77', 'workspace_roots': [project], 'user_email': EMAIL, 'transcript_path': None}
    turn.fire({**base, 'hook_event_name': 'beforeSubmitPrompt', 'prompt': PROMPT, 'attachments': []})
    for i, command in enumerate(commands):
        shell = {'tool_name': 'Shell', 'tool_input': {'command': command, 'cwd': project},
                 'tool_use_id': 'call_e2e_%02d' % i}
        if pre:
            turn.fire({**base, **shell, 'hook_event_name': 'preToolUse'})
            turn.fire({**base, 'hook_event_name': 'beforeShellExecution', 'command': command, 'cwd': project})
        turn.fire({**base, 'hook_event_name': 'afterShellExecution', 'command': command, 'cwd': project,
                   'output': '', 'duration': 412})
        turn.fire({**base, **shell, 'hook_event_name': 'postToolUse', 'tool_output': '', 'duration': 412})
    turn.fire({**base, 'hook_event_name': 'afterAgentResponse', 'text': REPLY})
    turn.fire({**base, 'hook_event_name': 'stop', 'status': 'completed', 'loop_count': 0})


def turn_copilot(turn, sandbox, commands, session, t0, pre):
    project = str(sandbox['project'])
    events = sandbox['home'] / '.copilot' / 'session-state' / session / 'events.jsonl'
    base = {'session_id': session, 'cwd': project, 'transcript_path': str(events)}
    write_jsonl(events, [
        {'type': 'session.start', 'id': 'e0', 'timestamp': _stamp(t0, 0), 'data': {'sessionId': session}},
        {'type': 'user.message', 'id': 'e1', 'timestamp': _stamp(t0, 0), 'data': {'content': PROMPT}},
    ])
    turn.fire({**base, 'hook_event_name': 'UserPromptSubmit', 'prompt': PROMPT, 'timestamp': _stamp(t0, 0)})
    lines = []
    for i, command in enumerate(commands):
        arguments = {'command': command, 'description': 'step %d' % i}
        call = {'tool_name': 'bash', 'tool_input': arguments}
        if pre:
            turn.fire({**base, **call, 'hook_event_name': 'PreToolUse'})
        turn.fire({**base, **call, 'hook_event_name': 'PostToolUse', 'tool_response': {'output': ''}})
        call_id = 'call_e2e_%02d' % i
        lines += [
            {'type': 'assistant.message', 'id': 'm%d' % i, 'timestamp': _stamp(t0, 1 + i), 'data': {
                'content': '', 'model': 'claude-sonnet-4.5',
                'toolRequests': [{'toolCallId': call_id, 'name': 'bash', 'arguments': arguments}]}},
            {'type': 'tool.execution_start', 'id': 's%d' % i, 'timestamp': _stamp(t0, 1 + i),
             'data': {'toolCallId': call_id, 'toolName': 'bash', 'arguments': arguments}},
            {'type': 'tool.execution_complete', 'id': 'c%d' % i, 'timestamp': _stamp(t0, 1.5 + i),
             'data': {'toolCallId': call_id, 'success': True, 'result': {'content': '<exited with exit code 0>'}}}]
    lines.append({'type': 'assistant.message', 'id': 'end', 'timestamp': _stamp(t0, 2 + len(commands)),
                  'data': {'content': REPLY, 'model': 'claude-sonnet-4.5'}})
    with open(events, 'a') as handle:
        for line in lines:
            handle.write(json.dumps(line) + '\n')
    turn.fire({**base, 'hook_event_name': 'Stop', 'stop_hook_active': False})


def turn_codex(turn, sandbox, commands, session, t0, pre):
    project = str(sandbox['project'])
    rollout = sandbox['home'] / '.codex' / 'sessions' / '2026' / '10' / '28' / ('rollout-%s.jsonl' % session)
    base = {'session_id': session, 'transcript_path': str(rollout), 'cwd': project, 'model': 'gpt-5-codex',
            'permission_mode': 'default'}
    write_jsonl(rollout, [{'timestamp': _stamp(t0, -5), 'type': 'session_meta',
                           'payload': {'id': session, 'cwd': project, 'originator': 'codex_cli_rs'}}])
    turn.fire({**base, 'hook_event_name': 'UserPromptSubmit', 'turn_id': 'turn-1', 'prompt': PROMPT})
    output = 'Chunk ID: 1a2b3c\nWall time: 0.4 seconds\nProcess exited with code 0\nOriginal token count: 0\nOutput:\n'
    lines = [{'timestamp': _stamp(t0, 1), 'type': 'response_item', 'payload': {
        'type': 'message', 'role': 'user', 'content': [{'type': 'input_text', 'text': PROMPT}]}}]
    for i, command in enumerate(commands):
        call = {'tool_name': 'Bash', 'tool_input': {'command': command}, 'tool_use_id': 'call_e2e_%02d' % i,
                'turn_id': 'turn-1'}
        if pre:
            turn.fire({**base, **call, 'hook_event_name': 'PreToolUse'})
        turn.fire({**base, **call, 'hook_event_name': 'PostToolUse', 'tool_response': output})
        lines += [
            {'timestamp': _stamp(t0, 2 + i), 'type': 'response_item', 'payload': {
                'type': 'function_call', 'name': 'exec_command', 'call_id': 'call_e2e_%02d' % i,
                'arguments': json.dumps({'cmd': command, 'workdir': project})}},
            {'timestamp': _stamp(t0, 2.5 + i), 'type': 'response_item', 'payload': {
                'type': 'function_call_output', 'call_id': 'call_e2e_%02d' % i, 'output': output}}]
    end = 3 + len(commands)
    lines += [
        {'timestamp': _stamp(t0, end), 'type': 'response_item', 'payload': {
            'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': REPLY}]}},
        {'timestamp': _stamp(t0, end), 'type': 'event_msg', 'payload': {
            'type': 'token_count', 'info': {'last_token_usage': {
                'input_tokens': 10, 'cached_input_tokens': 0, 'output_tokens': 5, 'total_tokens': 15}}}}]
    with open(rollout, 'a') as handle:
        for line in lines:
            handle.write(json.dumps(line) + '\n')
    turn.fire({**base, 'hook_event_name': 'Stop', 'turn_id': 'turn-1', 'stop_hook_active': False,
               'last_assistant_message': REPLY})


def turn_augment(turn, sandbox, commands, session, t0, pre):
    project = str(sandbox['project'])
    base = {'conversation_id': session, 'workspace_roots': [project], 'context': {'userEmail': EMAIL}}
    for i, command in enumerate(commands):
        call = {'tool_name': 'launch-process', 'tool_use_id': 'toolu_aug_e2e_%02d' % i,
                'tool_input': {'command': command, 'wait': True, 'max_wait_seconds': 60, 'cwd': project}}
        if pre:
            turn.fire({**base, **call, 'hook_event_name': 'PreToolUse'})
        turn.fire({**base, **call, 'hook_event_name': 'PostToolUse', 'tool_error': None, 'file_changes': [],
                   'tool_output': 'Here are the results from executing the command.\n<return-code>\n0\n'
                                  '</return-code>\n<output>\n\n</output>'})
    turn.fire({**base, 'hook_event_name': 'Stop', 'agent_stop_cause': 'end_turn', 'conversation': {
        'userPrompt': PROMPT, 'agentTextResponse': REPLY}})


TURNS = {'claude-code': turn_claude, 'cursor': turn_cursor, 'copilot': turn_copilot, 'codex': turn_codex,
         'augment': turn_augment}


def run_turn(tool, sandbox, gateway, commands, hook=None, session=None, t0=None, pre=True, env=None):
    """One turn of `commands` through the hook, its turn log and the Turn that timed it."""
    turn = Turn(hook or HOOKS[tool], env or env_for(sandbox, gateway), sandbox['project'])
    TURNS[tool](turn, sandbox, commands, session or str(uuid.uuid4()),
                t0 or datetime.now(timezone.utc), pre)
    return turn_log(gateway, tool), turn


def calls_by_command(body, commands):
    """Each command's one turn-log entry; a command missing or logged twice fails here."""
    entries = tool_entries(body)
    found = {}
    for command in commands:
        matched = [entry for entry in entries if command_of(entry) == command]
        assert len(matched) == 1, 'expected %r once, got %d in %s' % (command, len(matched), json.dumps(entries)[:3000])
        found[command] = matched[0]
    return found


def keep(test, tool, body):
    out = os.environ.get('UNBOUND_ACCOUNT_E2E_OUT')
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / ('%s_%s.json' % (test, tool))).write_text(json.dumps(body, indent=2) + '\n')


def assert_no_secret(gateway):
    seen = gateway.everything()
    for secret in SECRETS:
        assert secret not in seen, '%r reached the gateway' % secret


# --- B1–B6: each platform's account, through every hook ----------------------------------------------------------


@pytest.mark.parametrize('tool', TOOLS)
def test_b1_a_push_to_a_named_remote_sends_that_remotes_repository_and_the_committer(tool, accounts, gateway):
    commands = ['git push backup main', 'git push']
    body, _ = run_turn(tool, accounts, gateway, commands)
    keep('b1', tool, body)
    named, bare = (calls_by_command(body, commands)[c] for c in commands)
    assert named.get('pushed_repo') == 'acme-backup/app', json.dumps(named, indent=2)
    assert named.get('pushed_remote') == 'backup', json.dumps(named, indent=2)
    assert named.get('accounts') == [GIT_ACCOUNT], json.dumps(named, indent=2)
    # A bare push goes to origin, git's own default with nothing else configured.
    assert bare.get('pushed_repo') == 'acme/app', json.dumps(bare, indent=2)
    assert bare.get('pushed_remote') == 'origin', json.dumps(bare, indent=2)
    assert 'pushed' not in named and 'pushed' not in bare
    assert_no_secret(gateway)


@pytest.mark.parametrize('tool', TOOLS)
def test_b2_gh_sends_the_login_gh_holds_and_never_its_token(tool, accounts, gateway):
    command = 'gh pr create --title ship --body done'
    body, _ = run_turn(tool, accounts, gateway, [command])
    keep('b2', tool, body)
    entry = calls_by_command(body, [command])[command]
    assert entry.get('accounts') == [GH_ACCOUNT], json.dumps(entry, indent=2)
    assert 'pushed_repo' not in entry
    assert_no_secret(gateway)


@pytest.mark.parametrize('tool', TOOLS)
def test_b3_aws_sends_the_account_the_profile_names(tool, accounts, gateway):
    commands = ['aws --profile prod s3 ls', 'aws sts get-caller-identity']
    body, _ = run_turn(tool, accounts, gateway, commands)
    keep('b3', tool, body)
    named, default = (calls_by_command(body, commands)[c] for c in commands)
    assert named.get('accounts') == [AWS_PROD], json.dumps(named, indent=2)
    # No profile named: the default profile's role decides the account.
    assert default.get('accounts') == [AWS_DEFAULT], json.dumps(default, indent=2)
    assert_no_secret(gateway)


@pytest.mark.parametrize('tool', TOOLS)
def test_b4_kubectl_sends_the_cluster_of_the_context_it_used(tool, accounts, gateway):
    commands = ['kubectl --context prod get pods', 'kubectl get nodes']
    body, _ = run_turn(tool, accounts, gateway, commands)
    keep('b4', tool, body)
    named, current = (calls_by_command(body, commands)[c] for c in commands)
    assert named.get('accounts') == [KUBE_PROD], json.dumps(named, indent=2)
    assert current.get('accounts') == [KUBE_CURRENT], json.dumps(current, indent=2)
    assert_no_secret(gateway)


@pytest.mark.parametrize('tool', TOOLS)
def test_b5_az_sends_the_subscription_it_acted_in(tool, accounts, gateway):
    commands = ['az vm list --subscription "Acme Prod"', 'az group list', 'az account list']
    body, _ = run_turn(tool, accounts, gateway, commands)
    keep('b5', tool, body)
    named, default, local = (calls_by_command(body, commands)[c] for c in commands)
    assert named.get('accounts') == [AZURE_PROD], json.dumps(named, indent=2)
    # No subscription named: the one marked default in the active cloud.
    assert default.get('accounts') == [AZURE_PROD], json.dumps(default, indent=2)
    # Listing this machine's subscriptions acts in none of them.
    assert 'accounts' not in local, json.dumps(local, indent=2)
    assert_no_secret(gateway)


@pytest.mark.parametrize('tool', TOOLS)
def test_b6_a_push_to_ecr_sends_the_registry_and_the_aws_account_its_hostname_names(tool, accounts, gateway):
    commands = ['docker push %s' % ECR_IMAGE, 'docker push acme/app:1']
    body, _ = run_turn(tool, accounts, gateway, commands)
    keep('b6', tool, body)
    ecr, hub = (calls_by_command(body, commands)[c] for c in commands)
    assert ecr.get('accounts') == DOCKER_ECR, json.dumps(ecr, indent=2)
    assert hub.get('accounts') == [{'platform': 'docker', 'registry': 'docker.io', 'source': 'hostname'}], \
        json.dumps(hub, indent=2)
    assert_no_secret(gateway)


# --- B7: a switch later in the turn leaves earlier calls unknown -------------------------------------------------


@pytest.mark.parametrize('tool', TOOLS)
def test_b7_a_switch_later_in_the_turn_leaves_the_calls_it_moves_unknown(tool, accounts, gateway):
    moved = ['aws sts get-caller-identity', 'az group list', 'kubectl get nodes', 'gh pr list',
             'git commit -m "first"']
    # Named outright, so none of the switches below moves them.
    kept = {'aws --profile prod s3 ls': [AWS_PROD], 'kubectl --context prod get pods': [KUBE_PROD],
            'docker push %s' % ECR_IMAGE: DOCKER_ECR}
    switches = ['aws configure set region eu-west-1', 'az login', 'kubectl config use-context dev',
                'gh auth switch', 'git config user.email other@acme.test']
    commands = moved + list(kept) + switches
    body, _ = run_turn(tool, accounts, gateway, commands)
    keep('b7', tool, body)
    entries = calls_by_command(body, commands)
    for command in moved:
        # Withdrawn in place, so the entry may keep an empty list; either way no account is sent for it.
        assert not entries[command].get('accounts'), '%s: %s' % (command, json.dumps(entries[command], indent=2))
    for command, expected in kept.items():
        assert entries[command].get('accounts') == expected, '%s: %s' % (command, json.dumps(entries[command]))
    for command in switches:
        # A gh auth call is itself a gh call, signed in as whoever gh holds when the turn ends: the one switched to.
        expected = [GH_ACCOUNT] if command.startswith('gh ') else None
        assert entries[command].get('accounts') == expected, '%s: %s' % (command, json.dumps(entries[command]))
    assert_no_secret(gateway)


# --- B8: no credential reaches the gateway, while every platform resolves ----------------------------------------


@pytest.mark.parametrize('tool', TOOLS)
def test_b8_every_platform_resolves_and_no_credential_reaches_the_gateway(tool, accounts, gateway):
    commands = [command for command, _ in PLATFORM_CALLS] + ['git push backup main']
    body, _ = run_turn(tool, accounts, gateway, commands)
    entries = calls_by_command(body, commands)
    for command, expected in PLATFORM_CALLS:
        assert entries[command].get('accounts') == expected, '%s: %s' % (command, json.dumps(entries[command]))
    # Nothing from any credential file, in any request the hook made: policy checks, turn log, anything else.
    assert gateway.requests, 'the hook sent nothing'
    assert_no_secret(gateway)


# --- B9, B12: everything else is as the old hook sent it ---------------------------------------------------------

_ISO = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?')
_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
# Values that differ between any two runs of the same hook: when it ran, and how long each step took.
_VOLATILE = frozenset({'call_ts', 'duration', 'duration_ms', 'elapsed', 'elapsed_ms', 'latency_ms'})


def _normalise(value, root):
    if isinstance(value, dict):
        return {key: ('<volatile>' if key in _VOLATILE else _normalise(item, root)) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalise(item, root) for item in value]
    if isinstance(value, str):
        text = value
        for spelling in {str(root), str(root).replace('\\', '/'), os.path.realpath(str(root))}:
            text = text.replace(spelling, '<root>')
        if text != value or not text.startswith('{'):
            return _UUID.sub('<uuid>', _ISO.sub('<ts>', text))
        # A JSON document inside a string (the turn log's assistant message) is compared as data.
        try:
            return json.dumps(_normalise(json.loads(text), root), sort_keys=True)
        except ValueError:
            return _UUID.sub('<uuid>', _ISO.sub('<ts>', text))
    return value


def _without_new_keys(body):
    for entry in tool_entries(body):
        for key in NEW_KEYS:
            entry.pop(key, None)
    return body


def _same_turn_twice(tool, tmp_path, gateway_factory, commands, pre=True):
    """The turn log and policy checks the PR hook and the staging hook send for one identical turn."""
    # One session for both, but each run's own clock: the hook drops transcript lines older than the prompt it saw.
    session, results = str(uuid.uuid4()), {}
    for version in ('pr', 'staging'):
        root = tmp_path / version
        box = _sandbox_at(root)
        capture = gateway_factory()
        try:
            hook = HOOKS[tool] if version == 'pr' else staging_hook(tool, tmp_path)
            body, turn = run_turn(tool, box, capture, commands, hook=hook, session=session, pre=pre)
            checks = [r['body'] for r in capture.requests if 'pretool' in r['path']]
            results[version] = {'body': _normalise(body, root), 'checks': _normalise(checks, root), 'turn': turn,
                                'paths': sorted({r['path'] for r in capture.requests})}
        finally:
            capture.close()
    return results


def _sandbox_at(root):
    """The same sandbox as the fixtures build, at a path the caller picks, so two runs differ only in their root."""
    home, project, tmp, bin_dir = root / 'home', root / 'project', root / 'tmp', root / 'bin'
    for folder in (home / '.ssh', home / '.unbound', project, tmp, bin_dir):
        folder.mkdir(parents=True)
    (home / '.unbound' / 'config.json').write_text(json.dumps({'api_key': 'test-key'}))
    _write_accounts(home)
    _git(project, home, 'init', '-q', '-b', 'main')
    _git(project, home, 'remote', 'add', 'origin', 'https://github.com/acme/app.git')
    _git(project, home, 'remote', 'add', 'backup', 'https://github.com/acme-backup/app.git')
    _add_tools(bin_dir)
    return {'root': root, 'home': home, 'project': project, 'tmp': tmp, 'bin': bin_dir}


@pytest.fixture
def gateways():
    from tests.test_transfer_e2e import Capture
    return Capture


@pytest.mark.parametrize('tool', TOOLS)
def test_b9_a_turn_with_no_platform_command_is_sent_exactly_as_before(tool, tmp_path, gateways):
    commands = ['ls -la', 'npm test', 'echo "deploy notes" > notes.txt']
    results = _same_turn_twice(tool, tmp_path, gateways, commands)
    pr, staging = results['pr'], results['staging']
    assert pr['paths'] == staging['paths']
    for entry in tool_entries(pr['body']):
        assert not NEW_KEYS & set(entry), json.dumps(entry, indent=2)
    assert pr['body'] == staging['body'], _diff(pr['body'], staging['body'])


@pytest.mark.parametrize('tool', TOOLS)
def test_b9_a_platform_turn_differs_from_before_only_in_the_account_keys(tool, tmp_path, gateways):
    commands = [command for command, _ in PLATFORM_CALLS] + ['git push backup main']
    results = _same_turn_twice(tool, tmp_path, gateways, commands)
    pr, staging = results['pr'], results['staging']
    assert any(NEW_KEYS & set(entry) for entry in tool_entries(pr['body'])), 'the PR hook resolved nothing'
    assert _without_new_keys(pr['body']) == staging['body'], _diff(pr['body'], staging['body'])


@pytest.mark.parametrize('tool', TOOLS)
def test_b12_the_policy_check_is_sent_exactly_as_before(tool, tmp_path, gateways):
    commands = [command for command, _ in PLATFORM_CALLS] + ['git push backup main']
    results = _same_turn_twice(tool, tmp_path, gateways, commands)
    pr, staging = results['pr'], results['staging']
    assert pr['checks'], 'the hook sent no policy check'
    assert pr['checks'] == staging['checks'], _diff(pr['checks'], staging['checks'])
    assert 'accounts' not in json.dumps(pr['checks'])


def _diff(left, right):
    import difflib
    a = json.dumps(left, indent=1, sort_keys=True).splitlines()
    b = json.dumps(right, indent=1, sort_keys=True).splitlines()
    return '\n'.join(list(difflib.unified_diff(b, a, 'staging', 'pr', lineterm='', n=2))[:120])


# --- B10: a broken configuration never breaks the turn -----------------------------------------------------------


def _break(home, how):
    files = [home / '.aws' / 'config', home / '.kube' / 'config', home / '.azure' / 'azureProfile.json',
             _gh_hosts(home)]
    for path in files:
        if how == 'garbage':
            path.write_bytes(b'\x00\xff\xfe[[[ not: a: config\n\x89PNG\r\n' * 64)
        elif WINDOWS:
            # chmod only sets the read-only flag on Windows; a deny entry is what stops a read.
            subprocess.run(['icacls', str(path), '/deny', '%s:(R)' % os.environ['USERNAME']], check=True,
                           capture_output=True)
        else:
            path.chmod(0)
    if how == 'unreadable':
        for path in files:
            with pytest.raises(OSError):
                path.read_bytes()
    return files


def _mend(files):
    for path in files:
        if WINDOWS:
            subprocess.run(['icacls', str(path), '/remove:d', os.environ['USERNAME']], capture_output=True)
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


@pytest.mark.parametrize('how', ['garbage', 'unreadable'])
@pytest.mark.parametrize('tool', TOOLS)
def test_b10_a_corrupt_or_unreadable_config_sends_the_turn_and_no_account_for_that_platform(tool, how, accounts,
                                                                                          gateway):
    if how == 'unreadable' and hasattr(os, 'geteuid') and os.geteuid() == 0:
        pytest.skip('root reads any file')
    broken = _break(accounts['home'], how)
    try:
        commands = ['aws --profile prod s3 ls', 'kubectl get nodes', 'az group list', 'gh pr list',
                    'git commit -m "still known"']
        body, _ = run_turn(tool, accounts, gateway, commands)
    finally:
        _mend(broken)
    entries = calls_by_command(body, commands)
    for command in commands[:-1]:
        assert 'accounts' not in entries[command], '%s: %s' % (command, json.dumps(entries[command], indent=2))
    # One platform's broken file says nothing about another's.
    assert entries[commands[-1]].get('accounts') == [GIT_ACCOUNT], json.dumps(entries[commands[-1]], indent=2)
    assert_no_secret(gateway)


# --- B11: fifty account commands in one turn stay inside the lookup budget ----------------------------------------


@pytest.mark.parametrize('tool', TOOLS)
def test_b11_fifty_account_commands_cost_at_most_the_lookup_budget_over_the_old_hook(tool, tmp_path, gateways):
    commands = []
    for i in range(10):
        commands += ['git commit -m "step %d"' % i, 'kubectl get pods -n ns%d' % i, 'gh pr view %d' % (i + 1),
                     'aws --profile prod s3 ls s3://bucket-%d' % i, 'docker push %s%d' % (ECR_IMAGE, i)]
    session, timings = str(uuid.uuid4()), {}
    for version in ('staging', 'pr'):
        root = tmp_path / version
        box = _sandbox_at(root)
        capture = gateways()
        try:
            hook = HOOKS[tool] if version == 'pr' else staging_hook(tool, tmp_path)
            # Only the events that log a call; the policy checks are B12's concern and only slow this down.
            body, turn = run_turn(tool, box, capture, commands, hook=hook, session=session, pre=False)
            timings[version] = (turn.seconds, turn.last)
            if version == 'pr':
                entries = calls_by_command(body, commands)
                unresolved = [c for c in commands if not entries[c].get('accounts')]
                assert not unresolved, 'unresolved within the budget: %s' % unresolved
        finally:
            capture.close()
    (pr_total, pr_last), (staging_total, staging_last) = timings['pr'], timings['staging']
    # Every lookup shares one turn budget, so the whole turn may cost at most that much more than before, with
    # room for the noise of 51 process starts on a loaded machine.
    assert pr_total - staging_total < TURN_BUDGET + 0.15 * len(commands), timings
    assert pr_last - staging_last < TURN_BUDGET + 2, timings
