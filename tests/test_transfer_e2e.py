"""Every shipped hook, run as its editor runs it against a recording server, sends the gateway a `transfer` block.

The ssh config is passed with -F: ssh reads ~/.ssh/config from the account's real home, which a sandboxed $HOME does
not move. Set UNBOUND_TRANSFER_E2E_OUT to a folder to keep each hook's turn-log body there as <tool>.json.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from tests.conftest import REPO

HOOKS = {
    'claude-code': REPO / 'claude-code' / 'hooks' / 'unbound.py',
    'cursor': REPO / 'cursor' / 'unbound.py',
    'copilot': REPO / 'copilot' / 'hooks' / 'unbound.py',
    'codex': REPO / 'codex' / 'hooks' / 'unbound.py',
    'augment': REPO / 'augment' / 'hooks' / 'unbound.py',
}
PI_BUNDLE = REPO / 'pi' / 'index.js'
# Where each agent's end-of-turn log goes.
TURN_LOG_PATHS = {
    'claude-code': '/v1/hooks/claude',
    'cursor': '/v1/hooks/cursor',
    'copilot': '/v1/hooks/copilot',
    'codex': '/v1/hooks/codex',
    'augment': '/v1/hooks/augment',
    'pi': '/v1/hooks/pi',
}
KEY = 'test-key'
SECRET = 'SECRET-ROW-123'
COMMAND = 'scp -F backup.conf customers.sql backup:/srv'
EXPECTED = {'tool': 'scp', 'endpoints': [
    {'direction': 'out', 'host': 'backup', 'resolved_host': '10.0.4.12', 'address': 'private'}]}
SSH_CONFIG = 'Host backup\n  HostName 10.0.4.12\n'
# Every proxy points at a closed port, so anything but the capture server fails instead of leaving the machine.
DEAD = 'http://127.0.0.1:9'

pytestmark = pytest.mark.skipif(not os.path.isfile('/usr/bin/ssh'), reason='needs the system ssh')


class Capture:
    """A gateway stand-in on 127.0.0.1 that keeps every request and allows every check."""

    def __init__(self):
        self.requests, self.lock = [], threading.Lock()
        capture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                # Lets the Pi driver wait for the turn log, which pi posts after agent_end returns.
                url = urlparse(self.path)
                wanted = parse_qs(url.query).get('path', [''])[0]
                with capture.lock:
                    n = sum(1 for r in capture.requests if r['path'] == wanted)
                self._reply({'n': n})

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get('Content-Length') or 0))
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
                with capture.lock:
                    capture.requests.append({'path': urlparse(self.path).path, 'headers': dict(self.headers.items()),
                                             'raw': raw.decode('utf-8', 'replace'), 'body': body})
                self._reply({'decision': 'allow', 'policy_check_failure_action': 'allow'}
                            if 'pretool' in self.path else {})

            def _reply(self, payload):
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def bodies(self, path):
        with self.lock:
            return [r['body'] for r in self.requests if r['path'] == path]

    def everything(self):
        """Every path, header and body received, as one text, for the privacy checks."""
        with self.lock:
            return json.dumps([[r['path'], r['headers'], r['raw']] for r in self.requests])

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def gateway():
    capture = Capture()
    yield capture
    capture.close()


@pytest.fixture
def sandbox(tmp_path):
    home, project, tmp = tmp_path / 'home', tmp_path / 'project', tmp_path / 'tmp'
    for folder in (home / '.ssh', project, tmp):
        folder.mkdir(parents=True)
    (home / '.ssh' / 'config').write_text(SSH_CONFIG)
    (home / '.unbound').mkdir()
    (home / '.unbound' / 'config.json').write_text(json.dumps({'api_key': KEY}))
    (project / 'backup.conf').write_text(SSH_CONFIG)
    (project / 'customers.sql').write_text(SECRET + '\n')
    return {'root': tmp_path, 'home': home, 'project': project, 'tmp': tmp}


def hook_env(sandbox, gateway):
    env = {
        'HOME': str(sandbox['home']),
        'USER': os.environ.get('USER', 'tester'),
        'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
        'TMPDIR': str(sandbox['tmp']),
        'UNBOUND_GATEWAY_URL': gateway.url,
        'NO_PROXY': '127.0.0.1,localhost',
        'no_proxy': '127.0.0.1,localhost',
    }
    for name in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'all_proxy'):
        env[name] = DEAD
    for name in ('UNBOUND_CLAUDE_API_KEY', 'UNBOUND_CURSOR_API_KEY', 'UNBOUND_COPILOT_API_KEY',
                 'UNBOUND_CODEX_API_KEY', 'UNBOUND_AUGMENT_API_KEY', 'UNBOUND_PI_API_KEY'):
        env[name] = KEY
    return env


def fire(tool, event, env, cwd):
    """One hook invocation, as the editor makes it: the event on stdin, the answer on stdout."""
    result = subprocess.run([sys.executable, str(HOOKS[tool])], input=json.dumps(event), capture_output=True,
                            text=True, timeout=90, env=env, cwd=str(cwd))
    assert result.returncode == 0, '%s %s exited %d: %s' % (tool, event.get('hook_event_name'), result.returncode,
                                                            result.stderr[-600:])
    if result.stdout.strip():
        answer = json.loads(result.stdout)
        assert answer.get('decision') not in ('block', 'deny'), answer
        assert answer.get('permission') != 'deny', answer
    return result


def stamp(offset=0.0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def write_jsonl(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(line) + '\n' for line in lines))
    return str(path)


def tool_entries(body):
    return [entry for message in (body or {}).get('messages', []) if isinstance(message, dict)
            for entry in message.get('tool_use') or []]


def command_of(entry):
    tool_input = entry.get('tool_input')
    return entry.get('command') or (tool_input.get('command') if isinstance(tool_input, dict) else None)


def turn_log(gateway, tool, wait=5.0):
    """The one turn-log body the hook sent; a hook that posts its turn log twice fails here."""
    deadline = time.monotonic() + wait
    while not gateway.bodies(TURN_LOG_PATHS[tool]) and time.monotonic() < deadline:
        time.sleep(0.05)
    bodies = gateway.bodies(TURN_LOG_PATHS[tool])
    assert bodies, '%s posted no turn log; got %s' % (tool, sorted({r['path'] for r in gateway.requests}))
    assert len(bodies) == 1, '%s posted its turn log %d times' % (tool, len(bodies))
    return bodies[0]


def keep(tool, body):
    out = os.environ.get('UNBOUND_TRANSFER_E2E_OUT')
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / ('%s.json' % tool)).write_text(json.dumps(body, indent=2) + '\n')


def assert_private(gateway, *needles):
    seen = gateway.everything()
    for needle in (SECRET,) + needles:
        assert needle not in seen, '%r reached the gateway' % needle


# --- One shell call per agent, through the events that agent fires -----------------------------------------------


def run_claude(sandbox, env, command=COMMAND, failed=False):
    session, project = str(uuid.uuid4()), str(sandbox['project'])
    transcript = sandbox['home'] / '.claude' / 'projects' / 'project' / ('%s.jsonl' % session)
    base = {'session_id': session, 'transcript_path': str(transcript), 'cwd': project, 'permission_mode': 'default'}
    prompt = 'copy the customers table to the backup host'
    fire('claude-code', {**base, 'hook_event_name': 'UserPromptSubmit', 'prompt': prompt}, env, project)
    tool_input = {'command': command, 'description': 'Copy the dump to the backup host'}
    call = {**base, 'tool_name': 'Bash', 'tool_input': tool_input, 'tool_use_id': 'toolu_01E2E'}
    fire('claude-code', {**call, 'hook_event_name': 'PreToolUse'}, env, project)
    if failed:
        fire('claude-code', {**call, 'hook_event_name': 'PostToolUseFailure',
                             'error': 'Exit code 1\nssh: connect to host 10.0.4.12 port 22: Operation timed out\r\n'
                                      'lost connection', 'is_interrupt': False}, env, project)
    else:
        fire('claude-code', {**call, 'hook_event_name': 'PostToolUse', 'tool_response': {
            'stdout': '', 'stderr': '', 'interrupted': False, 'isImage': False}}, env, project)
    write_jsonl(transcript, [
        {'type': 'user', 'sessionId': session, 'cwd': project, 'timestamp': stamp(1),
         'uuid': 'u1', 'message': {'role': 'user', 'content': prompt}},
        {'type': 'assistant', 'sessionId': session, 'cwd': project, 'timestamp': stamp(2), 'uuid': 'a1',
         'message': {'id': 'msg_1', 'role': 'assistant', 'model': 'claude-sonnet-4-5', 'content': [
             {'type': 'tool_use', 'id': 'toolu_01E2E', 'name': 'Bash', 'input': tool_input}],
             'usage': {'input_tokens': 10, 'output_tokens': 5}}},
        {'type': 'user', 'sessionId': session, 'cwd': project, 'timestamp': stamp(3), 'uuid': 'u2',
         'message': {'role': 'user', 'content': [
             {'type': 'tool_result', 'tool_use_id': 'toolu_01E2E', 'content': '', 'is_error': failed}]}},
        {'type': 'assistant', 'sessionId': session, 'cwd': project, 'timestamp': stamp(4), 'uuid': 'a2',
         'message': {'id': 'msg_2', 'role': 'assistant', 'model': 'claude-sonnet-4-5', 'content': [
             {'type': 'text', 'text': 'Copied the dump to backup.'}], 'usage': {'input_tokens': 12, 'output_tokens': 7}}},
    ])
    fire('claude-code', {**base, 'hook_event_name': 'Stop', 'stop_hook_active': False,
                         'last_assistant_message': 'Copied the dump to backup.'}, env, project)


def run_cursor(sandbox, env, command=COMMAND):
    project = str(sandbox['project'])
    base = {'conversation_id': str(uuid.uuid4()), 'generation_id': str(uuid.uuid4()), 'model': 'claude-4.5-sonnet',
            'cursor_version': '2.0.77', 'workspace_roots': [project], 'user_email': 'dev@example.com',
            'transcript_path': None}
    fire('cursor', {**base, 'hook_event_name': 'beforeSubmitPrompt',
                    'prompt': 'copy the customers table to the backup host', 'attachments': []}, env, project)
    shell = {'tool_name': 'Shell', 'tool_input': {'command': command, 'cwd': project}, 'tool_use_id': 'call_e2e'}
    fire('cursor', {**base, **shell, 'hook_event_name': 'preToolUse'}, env, project)
    fire('cursor', {**base, 'hook_event_name': 'beforeShellExecution', 'command': command, 'cwd': project}, env, project)
    fire('cursor', {**base, 'hook_event_name': 'afterShellExecution', 'command': command, 'cwd': project,
                    'output': '', 'duration': 412}, env, project)
    fire('cursor', {**base, **shell, 'hook_event_name': 'postToolUse', 'tool_output': '', 'duration': 412},
         env, project)
    fire('cursor', {**base, 'hook_event_name': 'afterAgentResponse', 'text': 'Copied the dump to backup.'}, env, project)
    fire('cursor', {**base, 'hook_event_name': 'stop', 'status': 'completed', 'loop_count': 0}, env, project)


def run_copilot(sandbox, env, command=COMMAND):
    session, project = str(uuid.uuid4()), str(sandbox['project'])
    events = sandbox['home'] / '.copilot' / 'session-state' / session / 'events.jsonl'
    base = {'session_id': session, 'cwd': project, 'transcript_path': str(events)}
    prompt = 'copy the customers table to the backup host'
    write_jsonl(events, [
        {'type': 'session.start', 'id': 'e0', 'timestamp': stamp(), 'data': {'sessionId': session}},
        {'type': 'user.message', 'id': 'e1', 'timestamp': stamp(), 'data': {'content': prompt}},
    ])
    fire('copilot', {**base, 'hook_event_name': 'UserPromptSubmit', 'prompt': prompt, 'timestamp': stamp()},
         env, project)
    call = {'tool_name': 'bash', 'tool_input': {'command': command, 'description': 'Copy the dump'}}
    fire('copilot', {**base, **call, 'hook_event_name': 'PreToolUse'}, env, project)
    fire('copilot', {**base, **call, 'hook_event_name': 'PostToolUse', 'tool_response': {'output': ''}}, env, project)
    arguments = {'command': command, 'description': 'Copy the dump'}
    with open(events, 'a') as f:
        for line in [
            {'type': 'assistant.message', 'id': 'e2', 'timestamp': stamp(1), 'data': {
                'content': '', 'model': 'claude-sonnet-4.5',
                'toolRequests': [{'toolCallId': 'call_e2e', 'name': 'bash', 'arguments': arguments}]}},
            {'type': 'tool.execution_start', 'id': 'e3', 'timestamp': stamp(1),
             'data': {'toolCallId': 'call_e2e', 'toolName': 'bash', 'arguments': arguments}},
            {'type': 'tool.execution_complete', 'id': 'e4', 'timestamp': stamp(2),
             'data': {'toolCallId': 'call_e2e', 'success': True, 'result': {'content': '<exited with exit code 0>'}}},
            {'type': 'assistant.message', 'id': 'e5', 'timestamp': stamp(3),
             'data': {'content': 'Copied the dump to backup.', 'model': 'claude-sonnet-4.5'}},
        ]:
            f.write(json.dumps(line) + '\n')
    fire('copilot', {**base, 'hook_event_name': 'Stop', 'stop_hook_active': False}, env, project)


def run_codex(sandbox, env, command=COMMAND):
    session, project = str(uuid.uuid4()), str(sandbox['project'])
    rollout = sandbox['home'] / '.codex' / 'sessions' / '2026' / '10' / '28' / ('rollout-%s.jsonl' % session)
    base = {'session_id': session, 'transcript_path': str(rollout), 'cwd': project, 'model': 'gpt-5-codex',
            'permission_mode': 'default'}
    prompt = 'copy the customers table to the backup host'
    write_jsonl(rollout, [{'timestamp': stamp(-5), 'type': 'session_meta',
                           'payload': {'id': session, 'cwd': project, 'originator': 'codex_cli_rs'}}])
    fire('codex', {**base, 'hook_event_name': 'UserPromptSubmit', 'turn_id': 'turn-1', 'prompt': prompt}, env, project)
    time.sleep(0.01)
    call = {'tool_name': 'Bash', 'tool_input': {'command': command}, 'tool_use_id': 'call_e2e', 'turn_id': 'turn-1'}
    fire('codex', {**base, **call, 'hook_event_name': 'PreToolUse'}, env, project)
    output = ('Chunk ID: 1a2b3c\nWall time: 0.4 seconds\nProcess exited with code 0\nOriginal token count: 0\n'
              'Output:\n')
    fire('codex', {**base, **call, 'hook_event_name': 'PostToolUse', 'tool_response': output}, env, project)
    with open(rollout, 'a') as f:
        for line in [
            {'timestamp': stamp(1), 'type': 'response_item', 'payload': {
                'type': 'message', 'role': 'user', 'content': [{'type': 'input_text', 'text': prompt}]}},
            {'timestamp': stamp(2), 'type': 'response_item', 'payload': {
                'type': 'function_call', 'name': 'exec_command', 'call_id': 'call_e2e',
                'arguments': json.dumps({'cmd': command, 'workdir': project})}},
            {'timestamp': stamp(3), 'type': 'response_item', 'payload': {
                'type': 'function_call_output', 'call_id': 'call_e2e', 'output': output}},
            {'timestamp': stamp(4), 'type': 'response_item', 'payload': {
                'type': 'message', 'role': 'assistant',
                'content': [{'type': 'output_text', 'text': 'Copied the dump to backup.'}]}},
            {'timestamp': stamp(4), 'type': 'event_msg', 'payload': {
                'type': 'token_count', 'info': {'last_token_usage': {
                    'input_tokens': 10, 'cached_input_tokens': 0, 'output_tokens': 5, 'total_tokens': 15}}}},
        ]:
            f.write(json.dumps(line) + '\n')
    fire('codex', {**base, 'hook_event_name': 'Stop', 'turn_id': 'turn-1', 'stop_hook_active': False,
                   'last_assistant_message': 'Copied the dump to backup.'}, env, project)


def run_augment(sandbox, env, command=COMMAND):
    conversation, project = str(uuid.uuid4()), str(sandbox['project'])
    base = {'conversation_id': conversation, 'workspace_roots': [project],
            'context': {'userEmail': 'dev@example.com'}}
    call = {'tool_name': 'launch-process', 'tool_use_id': 'toolu_aug_e2e',
            'tool_input': {'command': command, 'wait': True, 'max_wait_seconds': 60, 'cwd': project}}
    fire('augment', {**base, **call, 'hook_event_name': 'PreToolUse'}, env, project)
    fire('augment', {**base, **call, 'hook_event_name': 'PostToolUse', 'tool_error': None, 'file_changes': [],
                     'tool_output': 'Here are the results from executing the command.\n<return-code>\n0\n'
                                    '</return-code>\n<output>\n\n</output>'}, env, project)
    fire('augment', {**base, 'hook_event_name': 'Stop', 'agent_stop_cause': 'end_turn', 'conversation': {
        'userPrompt': 'copy the customers table to the backup host',
        'agentTextResponse': 'Copied the dump to backup.'}}, env, project)


PI_DRIVER = r'''
import { pathToFileURL } from "node:url";
const [, , bundle, cwd, command, gateway] = process.argv;
const handlers = new Map();
const pi = { on(name, fn) { handlers.set(name, fn); return () => {}; } };
const { default: extension } = await import(pathToFileURL(bundle).href);
await extension(pi);
const ctx = {
  cwd, mode: "tui", hasUI: true, signal: new AbortController().signal,
  sessionManager: { getSessionId: () => "pi-e2e-session" },
  model: { id: "claude-sonnet-4-5", provider: "anthropic" },
  ui: { confirm: async () => true, notify() {}, select: async () => undefined, input: async () => undefined,
        setStatus() {} },
};
const call = { type: "tool_call", toolName: "bash", toolCallId: "toolu_pi_e2e", input: { command } };
const answers = [];
answers.push(await handlers.get("session_start")({ type: "session_start", reason: "startup" }, ctx));
answers.push(await handlers.get("input")({ type: "input", text: "copy the customers table to the backup host",
                                           source: "interactive" }, ctx));
answers.push(await handlers.get("tool_call")(call, ctx));
answers.push(await handlers.get("tool_result")({ type: "tool_result", toolCallId: call.toolCallId, toolName: "bash",
  input: { command }, content: [{ type: "text", text: "" }], isError: false }, ctx));
answers.push(handlers.get("agent_end")({ type: "agent_end", messages: [
  { role: "assistant", content: [{ type: "toolCall", id: call.toolCallId, name: "bash", arguments: { command } }] },
  { role: "toolResult", toolCallId: call.toolCallId, toolName: "bash", content: [{ type: "text", text: "" }],
    isError: false },
  { role: "assistant", content: [{ type: "text", text: "Copied the dump to backup." }] },
] }, ctx));
const deadline = Date.now() + 15000;
while (Date.now() < deadline) {
  const seen = await (await fetch(`${gateway}/__count?path=/v1/hooks/pi`)).json();
  if (seen.n > 0) break;
  await new Promise((done) => setTimeout(done, 50));
}
process.stdout.write(JSON.stringify(answers));
process.exit(0);
'''


def run_pi(sandbox, env, command=COMMAND):
    node = shutil.which('node') or shutil.which('node', path='/opt/homebrew/bin:/usr/local/bin')
    if not node:
        pytest.skip('needs node to load the Pi extension')
    driver = sandbox['root'] / 'pi-driver.mjs'
    driver.write_text(PI_DRIVER)
    result = subprocess.run([node, str(driver), str(PI_BUNDLE), str(sandbox['project']), command,
                             env['UNBOUND_GATEWAY_URL']], capture_output=True, text=True, timeout=60, env=env,
                            cwd=str(sandbox['project']))
    assert result.returncode == 0, result.stderr[-800:]
    for answer in json.loads(result.stdout):
        assert not (isinstance(answer, dict) and answer.get('block')), answer


RUNS = {'claude-code': run_claude, 'cursor': run_cursor, 'copilot': run_copilot, 'codex': run_codex,
        'augment': run_augment, 'pi': run_pi}


@pytest.mark.parametrize('tool', sorted(RUNS))
def test_the_real_hook_sends_where_the_transfer_went(tool, sandbox, gateway):
    RUNS[tool](sandbox, hook_env(sandbox, gateway))
    body = turn_log(gateway, tool)
    keep(tool, body)
    calls = [entry for entry in tool_entries(body) if command_of(entry) == COMMAND]
    assert len(calls) == 1, 'expected the scp call once in %s, got %s' % (tool, json.dumps(tool_entries(body)))
    assert calls[0].get('transfer') == EXPECTED, json.dumps(calls[0], indent=2)
    assert_private(gateway)


def test_claude_a_failed_bash_call_is_logged_once_with_its_transfer(sandbox, gateway):
    run_claude(sandbox, hook_env(sandbox, gateway), failed=True)
    body = turn_log(gateway, 'claude-code')
    calls = [entry for entry in tool_entries(body) if command_of(entry) == COMMAND]
    assert len(calls) == 1, json.dumps(tool_entries(body), indent=2)
    assert calls[0].get('transfer') == EXPECTED, json.dumps(calls[0], indent=2)
    assert_private(gateway)


def test_claude_never_sends_what_curlrc_holds(sandbox, gateway):
    # A ~/.curlrc with an option outside the safe ones may send the upload anywhere, so the hook claims no destination
    # for it; whatever it does, the login in it never leaves the machine, in the turn log or anywhere else.
    (sandbox['home'] / '.curlrc').write_text('user = admin:hunter2\n')
    command = 'curl -T customers.sql https://files.example.com/up'
    run_claude(sandbox, hook_env(sandbox, gateway), command=command)
    body = turn_log(gateway, 'claude-code')
    calls = [entry for entry in tool_entries(body) if command_of(entry) == command]
    assert len(calls) == 1, json.dumps(tool_entries(body), indent=2)
    assert 'transfer' not in calls[0], json.dumps(calls[0], indent=2)
    assert_private(gateway, 'hunter2', base64.b64encode(b'admin:hunter2').decode())
