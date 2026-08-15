"""The repository-scope gate must decide identically on all five hooks."""
import importlib.util
import io
import json
import subprocess
import sys
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from conftest import TOOL_PY

ALL_HOOKS = sorted(TOOL_PY)
# Every hook but Augment, which has no pre-prompt event at all
# (https://docs.augmentcode.com/cli/hooks lists PreToolUse, PostToolUse, Stop,
# SessionStart, SessionEnd and nothing else).
PROMPT_HOOKS = [h for h in ALL_HOOKS if h != 'augment']
# The hooks that have a warning phase at all. Augment has no turn id and no
# prompt event to derive one from, so it carries no grace machinery whatsoever
# — no counter file, no _repo_gate_decide, no warning text. It denies from the
# first violating call on both its gates. See the Augment section at the end.
GRACE_HOOKS = PROMPT_HOOKS
# Hooks whose PreToolUse payload carries a native turn identifier, so a tool
# call can be attributed to the turn that issued it. Copilot's does not: it
# dates the turn from the audit-logged prompt instead, and has no turn id at all
# when the session has yet to log one.
NATIVE_TURN_ID_HOOKS = ['claude-code', 'codex', 'cursor']

BLOCK_ORG = {
    'id': 12, 'name': 'Block Non-Unbound Repos',
    'github_org': 'unboundsec',
    'repositories': [], 'include_forks': False,
    'grace_turns': 3,
}


def _load(tool):
    path = TOOL_PY[tool]
    spec = importlib.util.spec_from_file_location(
        "gate_%s" % tool.replace('-', '_'), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _prepare(tool, tmp_path):
    """A hook module with every file it writes redirected onto a temp dir."""
    mod = _load(tool)
    mod.POLICY_CACHE_FILE = tmp_path / ".policy_cache.json"
    mod.REPO_GATE_STATE_FILE = tmp_path / ".repo_gate_state.json"
    mod.AUDIT_LOG = tmp_path / "agent-audit.log"
    mod.ERROR_LOG = tmp_path / "error.log"
    mod.tool_name = tool
    return mod


@pytest.fixture(params=ALL_HOOKS)
def hook(request, tmp_path):
    """A hook module with its policy cache and gate state on a temp dir."""
    return _prepare(request.param, tmp_path)


@pytest.fixture(params=PROMPT_HOOKS)
def prompt_hook(request, tmp_path):
    """The same, for the four hooks that have a prompt-level event."""
    return _prepare(request.param, tmp_path)


@pytest.fixture(params=GRACE_HOOKS)
def grace_hook(request, tmp_path):
    """The same, for the four hooks that have a warning phase and a grace
    counter. Augment is excluded because it has neither."""
    return _prepare(request.param, tmp_path)


@pytest.fixture(params=NATIVE_TURN_ID_HOOKS)
def native_turn_hook(request, tmp_path):
    """The same, for hooks whose tool payload names the turn it belongs to."""
    return _prepare(request.param, tmp_path)


# -- policy interpretation --------------------------------------------------

def test_block_policies_kept(hook):
    assert hook._repo_gate_block_policies([BLOCK_ORG]) == [BLOCK_ORG]


def test_stray_action_key_ignored(hook):
    # Rows predating the action field's removal must still enforce.
    legacy = dict(BLOCK_ORG, action='ALLOW')
    assert hook._repo_gate_block_policies([legacy]) == [legacy]


@pytest.mark.parametrize("policies", [
    None,
    [],
    [None, 3, 'x'],
    [{}],
    [dict(BLOCK_ORG, grace_turns='three')],
    [dict(BLOCK_ORG, grace_turns=None)],
    [dict(BLOCK_ORG, grace_turns=-1)],
    [dict(BLOCK_ORG, grace_turns=True)],
    [dict(BLOCK_ORG, github_org='')],
    [dict(BLOCK_ORG, github_org=None)],
])
def test_malformed_policies_are_dropped(hook, policies):
    assert hook._repo_gate_block_policies(policies) == []


def test_org_scope_matching_is_case_insensitive(hook):
    policy = dict(BLOCK_ORG, github_org='UnBoundSec')
    assert hook._repo_gate_scope_allows(policy, 'unboundsec', 'setup') is True
    assert hook._repo_gate_scope_allows(policy, 'acme', 'widgets') is False


# -- remote parsing ---------------------------------------------------------

@pytest.mark.parametrize("url,host", [
    ('git@github.com:org/repo.git', 'github.com'),
    ('https://github.com/org/repo.git', 'github.com'),
    ('ssh://git@ghe.acme.com/org/repo', 'ghe.acme.com'),
    ('https://user:pw@github.com/org/repo', 'github.com'),
    ('file:///srv/git/x', None),
    ('/srv/git/x', None),
    ('', None),
    (None, None),
])
def test_remote_host(hook, url, host):
    assert hook._remote_host(url) == host


def test_hostless_remote_is_never_judged(hook, tmp_path):
    """file:///srv/git/x parses as org "srv", repo "git" — a half-parse that
    must not be compared against a GitHub org."""
    repo = tmp_path / "weird"
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin',
                    'file:///srv/git/x'], check=True, capture_output=True)
    assert hook._get_git_origin_org_repo(str(repo)) == (None, None)


def test_github_remote_resolves(hook, tmp_path):
    repo = tmp_path / "setup"
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin',
                    'git@github.com:UnboundSec/Setup.git'], check=True,
                   capture_output=True)
    assert hook._get_git_origin_org_repo(str(repo)) == ('unboundsec', 'setup')


def test_git_failure_propagates_for_fail_open(hook, monkeypatch):
    """_get_git_origin_org_repo must NOT swallow a git-unavailable error — the
    evaluate() layer catches it and allows. Swallowing it here would make an
    unreadable repo look like a resolved one."""
    def boom(_cwd):
        raise FileNotFoundError('git')
    monkeypatch.setattr(hook, '_git_origin_url', boom)
    with pytest.raises(FileNotFoundError):
        hook._get_git_origin_org_repo('/anywhere')


# -- violation detection ----------------------------------------------------

def test_no_git_root_never_violates(hook, tmp_path):
    plain = tmp_path / "notes" / "deep"
    plain.mkdir(parents=True)
    assert hook._repo_gate_violating_repo([str(plain)], [BLOCK_ORG], {}) is None


def test_out_of_scope_repo_violates(hook, tmp_path):
    repo = tmp_path / "widgets"
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin',
                    'https://github.com/acme/widgets.git'], check=True,
                   capture_output=True)
    assert hook._repo_gate_violating_repo(
        [str(repo)], [BLOCK_ORG], {}) == 'acme/widgets'
    # Compliant against at least one BLOCK policy ⇒ not a violation.
    acme_ok = dict(BLOCK_ORG, github_org='acme')
    assert hook._repo_gate_violating_repo(
        [str(repo)], [BLOCK_ORG, acme_ok], {}) is None


def test_origin_lookup_is_cached_per_root(hook, tmp_path, monkeypatch):
    repo = tmp_path / "widgets"
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(repo), 'remote', 'add', 'origin',
                    'https://github.com/acme/widgets.git'], check=True,
                   capture_output=True)
    calls = []
    real = hook._git_origin_url
    monkeypatch.setattr(hook, '_git_origin_url',
                        lambda c: (calls.append(c), real(c))[1])
    cache = {}
    for _ in range(5):
        hook._repo_gate_violating_repo([str(repo)], [BLOCK_ORG], cache)
    assert len(calls) == 1, "git must run at most once per repo root"


def test_system_checkout_roots_are_shared(hook):
    """WEB-5433: a Homebrew path must never resolve as work in homebrew/brew."""
    assert hook._is_system_checkout_path('/opt/homebrew/bin/jq') is True
    assert hook._is_system_checkout_path('/nix/store/x') is True
    assert hook._is_system_checkout_path('/Users/me/project') is False


# -- grace bookkeeping ------------------------------------------------------

def test_state_round_trip_and_session_scoping(grace_hook):
    grace_hook._save_repo_gate_state('S1', {'used': 2, 'turns': ['t1', 't2']})
    assert grace_hook._load_repo_gate_state('S1') == {'used': 2, 'turns': ['t1', 't2']}
    # A different session starts with full grace — this is the reset.
    assert grace_hook._load_repo_gate_state('S2') == {'used': 0, 'turns': []}


def test_state_turn_list_is_bounded(grace_hook):
    turns = ['t%d' % i for i in range(100)]
    grace_hook._save_repo_gate_state('S1', {'used': 100, 'turns': turns})
    loaded = grace_hook._load_repo_gate_state('S1')
    assert loaded['used'] == 100
    assert len(loaded['turns']) == grace_hook.REPO_GATE_TURN_MEMORY
    assert loaded['turns'][-1] == 't99'


@pytest.mark.parametrize("junk", [
    '', '{', 'null', '[]', 'true', '"str"',
    '{"used": "many"}',
    '{"session_id": "S1", "used": -4, "turns": []}',
    '{"session_id": "S1", "used": true, "turns": []}',
    '{"session_id": "S1", "used": 9, "turns": "t1"}',
])
def test_corrupt_state_reads_as_unused_grace(grace_hook, junk):
    grace_hook.REPO_GATE_STATE_FILE.write_text(junk, encoding='utf-8')
    assert grace_hook._load_repo_gate_state('S1') == {'used': 0, 'turns': []}


def test_missing_state_reads_as_unused_grace(grace_hook):
    assert not grace_hook.REPO_GATE_STATE_FILE.exists()
    assert grace_hook._load_repo_gate_state('S1') == {'used': 0, 'turns': []}


def test_unwritable_state_dir_is_survivable(grace_hook):
    grace_hook.REPO_GATE_STATE_FILE = grace_hook.REPO_GATE_STATE_FILE.parent / "nope" / "x" / "s.json"
    grace_hook.REPO_GATE_STATE_FILE.parent.parent.write_text("i am a file", encoding='utf-8')
    grace_hook._save_repo_gate_state('S1', {'used': 1, 'turns': ['t1']})  # must not raise
    assert grace_hook._load_repo_gate_state('S1') == {'used': 0, 'turns': []}


# -- policy cache plumbing --------------------------------------------------

def test_repo_policies_round_trip_and_survive_partial_writes(hook):
    hook.save_policy_cache(tools_to_check=['Bash'], repo_policies=[BLOCK_ORG])
    assert hook.get_repo_policies() == [BLOCK_ORG]
    # A later write that omits repo_policies must not silently drop them.
    hook.save_policy_cache(tools_to_check=['Bash', 'Read'])
    assert hook.get_repo_policies() == [BLOCK_ORG]
    # An explicit empty list clears them (policy removed server-side).
    hook.save_policy_cache(repo_policies=[])
    assert hook.get_repo_policies() == []


def test_cold_and_corrupt_cache_yield_no_policies(hook):
    assert hook.get_repo_policies() == []
    hook.POLICY_CACHE_FILE.write_text('{not json', encoding='utf-8')
    assert hook.get_repo_policies() == []
    hook.POLICY_CACHE_FILE.write_text('{"repo_policies": "nope"}', encoding='utf-8')
    assert hook.get_repo_policies() == []


def test_block_context_never_downgrades_a_deny(grace_hook):
    denied = {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                                     'permissionDecision': 'deny',
                                     'permissionDecisionReason': 'secret leak',
                                     'additionalContext': 'stop'}}
    if grace_hook.tool_name == 'cursor':
        denied = {'permission': 'deny', 'user_message': 'secret leak',
                  'agent_message': 'stop'}
    merged = grace_hook._with_repo_gate_context(denied, 'repo warning')
    if grace_hook.tool_name == 'cursor':
        assert merged['permission'] == 'deny'
        assert merged['user_message'] == 'secret leak'
        assert 'stop' in merged['agent_message']
        assert 'repo warning' in merged['agent_message']
    else:
        out = merged['hookSpecificOutput']
        assert out['permissionDecision'] == 'deny'
        assert out['permissionDecisionReason'] == 'secret leak'
        assert 'stop' in out['additionalContext']
        assert 'repo warning' in out['additionalContext']


def test_warning_text_names_repo_and_remaining(grace_hook):
    assert 'acme/widgets' in grace_hook._repo_gate_warning('acme/widgets', 2)
    assert '2 warnings left' in grace_hook._repo_gate_warning('acme/widgets', 2)
    assert '1 warning left' in grace_hook._repo_gate_warning('acme/widgets', 1)
    assert 'final warning' in grace_hook._repo_gate_warning('acme/widgets', 0)


def test_block_reason_names_the_repo(hook):
    """Every hook, Augment included — it is the one string Augment renders."""
    assert 'acme/widgets' in hook._repo_gate_block_reason('acme/widgets')


# ===========================================================================
# Conversation is never gated; what must survive is the policy-cache refresh sharing this event.
# ===========================================================================

def _make_repo(root, origin):
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '-q', str(root)], check=True,
                   capture_output=True)
    subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin', origin],
                   check=True, capture_output=True)
    (root / 'README.md').write_text('hi\n', encoding='utf-8')
    return root


@pytest.fixture
def repos(tmp_path):
    """An in-scope repo, an out-of-scope repo, and a directory under no repo —
    real `git init`s, because resolving a path to a git origin is the entire
    job under test."""
    work = tmp_path / "work"
    plain = tmp_path / "notes"
    plain.mkdir(parents=True)
    return SimpleNamespace(
        in_scope=str(_make_repo(work / "setup",
                                'git@github.com:unboundsec/setup.git')),
        out_scope=str(_make_repo(work / "widgets",
                                 'https://github.com/acme/widgets.git')),
        plain=str(plain),
    )


def _set_policies(hook, policies):
    hook.save_policy_cache(tools_to_check=[], repo_policies=policies)


def _grace_used(hook):
    if not hook.REPO_GATE_STATE_FILE.exists():
        return 0
    return json.loads(
        hook.REPO_GATE_STATE_FILE.read_text(encoding='utf-8'))['used']


def _stubs(hook, api, posts=None, real_post=False):
    """Patches that keep a hook's entry points off the network and off the
    developer's real config, skipping helpers a given hook does not have.

    _repo_gate_post is patched on every hook by default: it is the one thing on
    the incident-reporting path that touches the network, so stubbing it keeps
    a real curl out of the suite. Pass `posts` to collect what would have been
    sent, or `real_post` to keep the real one — for the tests that patch the
    curl underneath it instead."""
    out = [patch.object(hook, 'send_to_hook_api', api)]
    for name in ('get_api_key', 'build_account_identity'):
        if hasattr(hook, name):
            out.append(patch.object(hook, name, MagicMock(return_value='KEY')))
    if hasattr(hook, 'report_error_to_gateway'):
        out.append(patch.object(hook, 'report_error_to_gateway', MagicMock()))

    def record(body, api_key):
        if posts is not None:
            posts.append(json.loads(body))

    if not real_post:
        out.append(patch.object(hook, '_repo_gate_post',
                                MagicMock(side_effect=record)))
    # main() caches the api key in a module global that outlives the test, so
    # whether a report is dispatched at all must not depend on test order.
    out.append(patch.object(hook, '_cached_api_key', 'KEY'))
    return out


def _run_main(hook, event, gateway=None, posts=None):
    """Drive a whole event through the hook's real main(). Returns
    (printed json, exit code, gateway stub)."""
    out = io.StringIO()
    api = MagicMock(return_value=gateway or {})
    code = 0
    with patch.object(sys, 'stdin', io.StringIO(json.dumps(event))), \
         patch.object(sys, 'stdout', out):
        stack = _stubs(hook, api, posts)
        for p in stack:
            p.start()
        try:
            hook.main()
        except SystemExit as exc:
            code = exc.code
        finally:
            for p in stack:
                p.stop()
    return json.loads(out.getvalue().strip() or '{}'), code, api


def _drive_tool(hook, event):
    """The hook's real tool entry point, with the stubs already started.

    Cursor splits tool calls over two entry points, so the event's own name
    picks the one under test: file tools arrive on preToolUse, shell commands on
    beforeShellExecution."""
    if hook.tool_name == 'cursor':
        if event.get('hook_event_name') == 'preToolUse':
            return hook.process_pre_tool_use(event, 'KEY')
        return hook.process_pre_tool_use_execution(
            event, 'KEY', 'Shell', event.get('command', ''))
    return hook.process_pre_tool_use(event, 'KEY')


def _run_tool(hook, event, gateway=None, posts=None):
    """Drive one tool call through the hook's real PreToolUse entry point."""
    api = MagicMock(return_value=gateway or {})
    stack = _stubs(hook, api, posts)
    for p in stack:
        p.start()
    try:
        return _drive_tool(hook, event)
    finally:
        for p in stack:
            p.stop()


def _prompt_event(tool, cwd, turn='t1'):
    """That hook's prompt-level event, in its own vocabulary."""
    if tool == 'cursor':
        return {'hook_event_name': 'beforeSubmitPrompt', 'conversation_id': 'S1',
                'generation_id': turn, 'prompt': 'fix the bug',
                'workspace_roots': [cwd] if cwd else []}
    event = {'hook_event_name': 'UserPromptSubmit', 'session_id': 'S1',
             'prompt': 'fix the bug'}
    if cwd:
        event['cwd'] = cwd
    if tool == 'claude-code':
        event['prompt_id'] = turn
    elif tool == 'codex':
        event['turn_id'] = turn
    # Copilot deliberately gets no turn id: it derives one from the audit-log
    # timestamp of the prompt main() has just written.
    return event


# The default command must be one the gate is in scope for: `git status` runs git.
GATED_COMMAND = 'git status'
# Commands the gate now ignores entirely, whatever repo they resolve in.
UNGATED_COMMANDS = ['ls -la', 'cat README.md', 'npm test', 'python -m pytest']


def _tool_event(tool, cwd, turn='t1', command=GATED_COMMAND):
    """A shell tool call in that hook's own vocabulary."""
    if tool == 'cursor':
        return {'hook_event_name': 'beforeShellExecution', 'conversation_id': 'S1',
                'generation_id': turn, 'command': command,
                'workspace_roots': [cwd] if cwd else []}
    event = {'hook_event_name': 'PreToolUse', 'session_id': 'S1',
             'tool_name': 'launch-process' if tool == 'augment' else 'Bash',
             'tool_input': {'command': command}}
    if cwd:
        event['cwd'] = cwd
    if tool == 'claude-code':
        event['prompt_id'] = turn
    elif tool == 'codex':
        event['turn_id'] = turn
    return event


# That hook's write tool, and the key it names its target path under. Codex
# hides the path inside the patch body, which _repo_gate_candidates recovers by
# scanning the serialized input — hence the free-form key.
_WRITE_TOOL = {
    'claude-code': ('Edit', 'file_path'),
    'codex': ('apply_patch', 'input'),
    'copilot': ('Edit', 'filePath'),
    'cursor': ('Write', 'file_path'),
    'augment': ('save-file', 'path'),
}
# That hook's read tool, which the gate must now ignore.
_READ_TOOL = {
    'claude-code': ('Read', 'file_path'),
    'copilot': ('Read', 'filePath'),
    'cursor': ('Read', 'file_path'),
    'augment': ('view', 'path'),
}


def _file_event(tool, repo_dir, turn='t1', table=_WRITE_TOOL, target=None):
    """A file-tool call naming a path inside `repo_dir`, in that hook's own
    vocabulary. Returns None when the hook has no such tool (Codex has no read
    tool the gate ever saw). `target` overrides the named path, so the same
    builder can name it relative to `repo_dir` instead of absolutely."""
    entry = table.get(tool)
    if entry is None:
        return None
    tool_name, key = entry
    target = target or '%s/notes.txt' % repo_dir
    if tool == 'cursor':
        return {'hook_event_name': 'preToolUse', 'conversation_id': 'S1',
                'generation_id': turn, 'tool_name': tool_name,
                'file_path': target, 'workspace_roots': [repo_dir]}
    event = {'hook_event_name': 'PreToolUse', 'session_id': 'S1',
             'tool_name': tool_name, 'tool_input': {key: target},
             'cwd': repo_dir}
    if tool == 'claude-code':
        event['prompt_id'] = turn
    elif tool == 'codex':
        event['turn_id'] = turn
    return event


def _assert_prompt_allowed(out, repo='acme/widgets'):
    assert out.get('decision') != 'block'
    assert out.get('continue') is not False
    assert repo not in json.dumps(out)


def _assert_tool_warned(hook, response, repo):
    if hook.tool_name == 'cursor':
        assert response.get('permission') != 'deny'
        assert repo in (response.get('agent_message') or '')
    else:
        out = response.get('hookSpecificOutput') or {}
        assert out.get('permissionDecision') != 'deny'
        assert repo in (out.get('additionalContext') or '')


def _assert_tool_denied(hook, response, repo):
    if hook.tool_name == 'cursor':
        assert response.get('permission') == 'deny'
        assert repo in (response.get('user_message') or '')
    else:
        out = response.get('hookSpecificOutput') or {}
        assert out.get('permissionDecision') == 'deny'
        assert repo in (out.get('permissionDecisionReason') or '')


def _assert_tool_allowed(response, repo='acme/widgets'):
    assert repo not in json.dumps(response)


def test_conversation_in_out_of_scope_repo_is_allowed(prompt_hook, repos):
    """A conversation inside an out-of-scope repo is not a violation: talking is not working."""
    _set_policies(prompt_hook, [dict(BLOCK_ORG, grace_turns=0)])
    for turn in ('t1', 't2', 't3'):
        out, code, _ = _run_main(
            prompt_hook,
            _prompt_event(prompt_hook.tool_name, repos.out_scope, turn))
        _assert_prompt_allowed(out)
        assert code == 0, "no hook may exit non-zero for a conversation"


def test_conversation_in_out_of_scope_repo_burns_no_grace(prompt_hook, repos):
    """The grace a later write or git command needs must still be there: the
    prompt event must not touch the counter at all."""
    _set_policies(prompt_hook, [dict(BLOCK_ORG, grace_turns=1)])
    for turn in ('t1', 't2'):
        _run_main(prompt_hook,
                  _prompt_event(prompt_hook.tool_name, repos.out_scope, turn))
    assert _grace_used(prompt_hook) == 0
    assert not prompt_hook.REPO_GATE_STATE_FILE.exists(), \
        "a prompt must not create the counter file"
    # The grace is intact, so the first gated tool call still gets its warning.
    response = _run_tool(
        prompt_hook, _tool_event(prompt_hook.tool_name, repos.out_scope, 't3'))
    _assert_tool_warned(prompt_hook, response, 'acme/widgets')


def test_conversation_in_the_allowed_org_is_allowed(prompt_hook, repos):
    _set_policies(prompt_hook, [dict(BLOCK_ORG, grace_turns=0)])
    out, _, _ = _run_main(prompt_hook,
                          _prompt_event(prompt_hook.tool_name, repos.in_scope))
    _assert_prompt_allowed(out)
    assert _grace_used(prompt_hook) == 0


def test_conversation_under_no_git_root_is_allowed(prompt_hook, repos):
    _set_policies(prompt_hook, [dict(BLOCK_ORG, grace_turns=0)])
    out, _, _ = _run_main(prompt_hook,
                          _prompt_event(prompt_hook.tool_name, repos.plain))
    _assert_prompt_allowed(out)
    assert not prompt_hook.REPO_GATE_STATE_FILE.exists(), \
        "a cwd under no repo must not touch the counter"


def test_no_hook_carries_a_conversation_gate_any_more(hook):
    """The deletion, pinned. Every prompt-side entry point of the gate is gone
    on every hook — the session evaluator and both of its response shapes."""
    for gone in ('_repo_gate_evaluate_session', '_repo_gate_prompt_deny_response',
                 '_with_repo_gate_prompt_context'):
        assert not hasattr(hook, gone), gone


def test_no_hook_dispatches_the_gate_on_its_prompt_event(hook):
    """Source-level guard: the prompt handler may still refresh the policy
    cache, but nothing on it may reach the gate."""
    source = TOOL_PY[hook.tool_name].read_text(encoding='utf-8')
    assert '_repo_gate_evaluate_session' not in source
    assert 'session_gate' not in source


def test_a_gateway_prompt_block_still_blocks(prompt_hook, repos):
    """Removing the gate from this path must not remove the gateway's own
    verdict from it: a real policy block still blocks, in an out-of-scope repo
    exactly as anywhere else."""
    _set_policies(prompt_hook, [BLOCK_ORG])
    gateway = {'decision': 'deny', 'reason': 'Blocked: prompt contains a secret'}
    out, _, _ = _run_main(prompt_hook,
                          _prompt_event(prompt_hook.tool_name, repos.out_scope),
                          gateway=gateway)
    if prompt_hook.tool_name == 'cursor':
        assert out.get('continue') is False
        assert 'prompt contains a secret' in (out.get('user_message') or '')
    else:
        assert out.get('decision') == 'block'
        assert 'prompt contains a secret' in (out.get('reason') or '')


# ===========================================================================
# FAIL-OPEN, end to end through the tool gate.
#
# These used to be asserted on the prompt event. That event no longer reaches
# the gate at all, so the same properties are pinned where the gate now lives —
# they are the reason a broken gate is a missed inspection and never a false
# block on a developer's machine.
# ===========================================================================

@pytest.mark.parametrize("policies", [
    None,
    'not-a-list',
    [{}],
    [dict(BLOCK_ORG, grace_turns='three')],
])
def test_tool_gate_fails_open_on_malformed_policies(hook, repos, policies):
    hook.POLICY_CACHE_FILE.write_text(
        json.dumps({'tools_to_check': [], 'repo_policies': policies}),
        encoding='utf-8')
    response = _run_tool(hook, _tool_event(hook.tool_name, repos.out_scope))
    _assert_tool_allowed(response)
    assert _grace_used(hook) == 0


def test_tool_gate_fails_open_without_a_cwd(hook):
    """No cwd and no path in the command: nothing resolves, so nothing is
    judged."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    _assert_tool_allowed(_run_tool(hook, _tool_event(hook.tool_name, None)))
    assert _grace_used(hook) == 0


def test_tool_gate_fails_open_when_git_is_unavailable(hook, repos):
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    for boom in (FileNotFoundError('git'),
                 subprocess.TimeoutExpired(cmd='git', timeout=10)):
        original = hook._git_origin_url
        hook._git_origin_url = MagicMock(side_effect=boom)
        try:
            response = _run_tool(hook, _tool_event(hook.tool_name, repos.out_scope))
        finally:
            hook._git_origin_url = original
        _assert_tool_allowed(response)
    assert _grace_used(hook) == 0


@pytest.mark.parametrize("junk", ['', '{', 'null', '{"used": "many"}'])
def test_tool_gate_survives_corrupt_state(grace_hook, repos, junk):
    """Unreadable state reads as unused grace, so the call is warned, not
    blocked."""
    _set_policies(grace_hook, [dict(BLOCK_ORG, grace_turns=1)])
    grace_hook.REPO_GATE_STATE_FILE.write_text(junk, encoding='utf-8')
    response = _run_tool(grace_hook, _tool_event(grace_hook.tool_name, repos.out_scope))
    _assert_tool_warned(grace_hook, response, 'acme/widgets')


def test_tool_block_never_calls_the_gateway(hook, repos):
    """Only this machine can resolve a path to a git root, so the decision is
    already final — and a blocked call must not cost a round trip."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    api = MagicMock(return_value={})
    stack = _stubs(hook, api)
    with _started(stack):
        response = _drive_tool(hook, _tool_event(hook.tool_name, repos.out_scope))
    _assert_tool_denied(hook, response, 'acme/widgets')
    api.assert_not_called()


def test_tool_gate_never_downgrades_a_gateway_block(grace_hook, repos):
    """A warn rides on top of whatever the gateway said; it never replaces a
    real deny with an advisory. Augment is excluded because it has no warning
    phase to downgrade anything into — see the test below."""
    _set_policies(grace_hook, [dict(BLOCK_ORG, grace_turns=3)])
    gateway = {'decision': 'deny', 'reason': 'Blocked: command leaks a secret'}
    response = _run_tool(grace_hook,
                         _tool_event(grace_hook.tool_name, repos.out_scope),
                         gateway=gateway)
    _assert_tool_denied(grace_hook, response, 'command leaks a secret')


def test_augment_gate_deny_still_denies_a_gateway_blocked_call(augment, repos):
    """Augment's gate denies from the first violating call, so it decides before
    the gateway is ever consulted. The call is still denied — a block replaced
    by a different block, never by an allow."""
    _set_policies(augment, [BLOCK_ORG])
    gateway = {'decision': 'deny', 'reason': 'Blocked: command leaks a secret'}
    response = _run_tool(augment, _augment_event(repos.out_scope), gateway=gateway)
    _assert_tool_denied(augment, response, 'acme/widgets')


# ===========================================================================
# The prompt path must still refresh the policy cache, or a cold session's first gated call sails through.
# ===========================================================================

def _cache(hook):
    if not hook.POLICY_CACHE_FILE.exists():
        return None
    return json.loads(hook.POLICY_CACHE_FILE.read_text(encoding='utf-8'))


def test_prompt_refresh_makes_the_first_tool_call_enforceable(prompt_hook, repos):
    """The regression this guards: with the prompt refresh removed, the cache is
    still cold when the turn's first tool call is decided, so the first write or
    git command of every session goes unenforced."""
    tool = prompt_hook.tool_name
    assert _cache(prompt_hook) is None, "starts genuinely cold"
    gateway = {'decision': 'allow', 'tools_to_check': [],
               'repo_policies': [dict(BLOCK_ORG, grace_turns=0)]}

    out, _, api = _run_main(prompt_hook, _prompt_event(tool, repos.out_scope, 't1'),
                            gateway=gateway)
    _assert_prompt_allowed(out)
    assert api.call_args[0][0].get('pull_policies') is True, \
        "a cold cache must ask the gateway for policies"
    assert _cache(prompt_hook)['repo_policies'] == [dict(BLOCK_ORG, grace_turns=0)]

    # Same turn, first tool call — enforced, because the prompt warmed the cache.
    response = _run_tool(prompt_hook, _tool_event(tool, repos.out_scope, 't1'))
    _assert_tool_denied(prompt_hook, response, 'acme/widgets')


def test_prompt_path_respects_the_cache_ttl(prompt_hook, repos):
    """A fresh cache is not re-pulled; a stale one is. Without the TTL check a
    cold cache would re-pull on every single prompt."""
    tool = prompt_hook.tool_name
    _set_policies(prompt_hook, [dict(BLOCK_ORG, grace_turns=9)])
    _, _, api = _run_main(prompt_hook, _prompt_event(tool, repos.in_scope, 't1'))
    assert 'pull_policies' not in api.call_args[0][0], "fresh cache must not re-pull"

    stale = _cache(prompt_hook)
    stale['last_synced'] = '2000-01-01T00:00:00Z'
    prompt_hook.POLICY_CACHE_FILE.write_text(json.dumps(stale), encoding='utf-8')
    _, _, api = _run_main(prompt_hook, _prompt_event(tool, repos.in_scope, 't2'))
    assert api.call_args[0][0].get('pull_policies') is True


def test_prompt_refresh_does_not_clobber_policies_on_a_bare_response(
        prompt_hook, repos):
    """A gateway reply carrying no policy fields must leave the cache alone,
    not blank it."""
    _set_policies(prompt_hook, [dict(BLOCK_ORG, grace_turns=9)])
    _run_main(prompt_hook, _prompt_event(prompt_hook.tool_name, repos.in_scope),
              gateway={'decision': 'allow'})
    assert _cache(prompt_hook)['repo_policies'] == [dict(BLOCK_ORG, grace_turns=9)]


def test_tool_path_still_caches_policies(hook, repos):
    """Unchanged behaviour on the tool path, now that both paths share
    _cache_policies_from_response. Augment included."""
    gateway = {'decision': 'allow', 'tools_to_check': ['Bash'],
               'repo_policies': [BLOCK_ORG]}
    _run_tool(hook, _tool_event(hook.tool_name, repos.in_scope), gateway=gateway)
    assert hook.get_repo_policies() == [BLOCK_ORG]


def test_cache_helper_ignores_a_missing_or_non_dict_response(hook):
    """Fail open: a gateway that returned nothing must not raise here."""
    for response in (None, {}, 'nope', []):
        hook._cache_policies_from_response(response)
    assert hook.get_repo_policies() == []


# -- shared grace arbitration ------------------------------------------------

def test_decide_is_a_no_op_without_a_violating_repo(grace_hook):
    event = _tool_event(grace_hook.tool_name, None)
    assert grace_hook._repo_gate_decide(event, [BLOCK_ORG], None) is None
    assert _grace_used(grace_hook) == 0


def test_decide_burns_one_grace_per_turn(native_turn_hook):
    """Called twice for the same turn — as the session gate and the tool gate
    both do — it burns exactly one. Only meaningful where the payload names the
    turn; see test_decide_charges_per_call_when_the_turn_is_unknown."""
    event = _tool_event(native_turn_hook.tool_name, None, 't1')
    first = native_turn_hook._repo_gate_decide(event, [BLOCK_ORG], 'acme/widgets')
    second = native_turn_hook._repo_gate_decide(event, [BLOCK_ORG], 'acme/widgets')
    assert first['decision'] == second['decision'] == 'warn'
    assert first['remaining'] == second['remaining'] == 2
    assert _grace_used(native_turn_hook) == 1


def test_decide_denies_once_grace_is_spent(grace_hook):
    policies = [dict(BLOCK_ORG, grace_turns=0)]
    verdict = grace_hook._repo_gate_decide(
        _tool_event(grace_hook.tool_name, None), policies, 'acme/widgets')
    assert verdict == {'decision': 'deny', 'repo': 'acme/widgets'}
    assert _grace_used(grace_hook) == 0, "a deny must not burn grace"


def test_unknown_turn_is_never_memoized_as_an_identity(grace_hook):
    """REPO_GATE_UNKNOWN_TURN means "which turn is this?", not "turn X".

    Recording it in state['turns'] the way a real turn id is recorded would
    create one bucket that is entered once and never left: `used` freezes one
    short of `grace` and the gate warns forever, leaving the policy configured
    but permanently unenforced. This is the defect that made Copilot's tool
    calls never escalate."""
    event = {}  # no turn id under any hook's spelling
    assert grace_hook._repo_gate_turn_id(event) == grace_hook.REPO_GATE_UNKNOWN_TURN
    grace_hook._repo_gate_decide(event, [BLOCK_ORG], 'acme/widgets')
    assert grace_hook.REPO_GATE_UNKNOWN_TURN not in \
        grace_hook._load_repo_gate_state(None)['turns']


def test_decide_charges_per_call_when_the_turn_is_unknown(grace_hook):
    """An unidentifiable turn is charged per CALL — stricter than per turn, but
    it escalates, which a frozen counter never does."""
    policies = [dict(BLOCK_ORG, grace_turns=2)]
    event = {}
    verdicts = [grace_hook._repo_gate_decide(event, policies, 'acme/widgets')
                for _ in range(4)]
    assert [v['decision'] for v in verdicts] == ['warn', 'warn', 'deny', 'deny']
    assert _grace_used(grace_hook) == 2


# ===========================================================================
# Scope: write tools always, a shell call only when it runs git or mutates the working tree.
# ===========================================================================

GIT_COMMANDS = [
    'git push',
    'git status --short',
    '/usr/bin/git push',
    'cd /tmp/x && git commit -m wip',
    'cd /tmp/x; git log',
    'false || git fetch',
    'sudo git push',
    'GIT_DIR=/tmp/x git status',
    '(cd /tmp/x && git push)',
    'git log | head -5',
]
SHELL_WRITE_COMMANDS = [
    'rm auth.py',
    'rm -rf build/',
    'mv a.py b.py',
    'cp src.py dest.py',
    'touch new.py',
    'mkdir -p src/x',
    "sed -i 's/a/b/' auth.py",
    "perl -pi -e 's/a/b/' auth.py",
    'tee out.txt',
    'truncate -s 0 f',
    'dd if=a of=b',
    'echo x > file',
    'make >> build.log',
    'cd /tmp/x && rm auth.py',
    'ln -s a b',
    'patch < fix.diff',
]
# The anti-false-positive set: git or a write command appears in the LINE but is
# not the command being invoked. An over-eager block here stops legitimate work.
NOT_COMMANDS = [
    'cat git-notes.md',
    'cat rm-notes.md',
    '/opt/homebrew/bin/git-lfs --help',
    'git-lfs push',
    'grep -r "rm -rf" .',
    'grep git README.md',
    'echo "moved to archive"',
    'echo "a && git push"',
    'npm run remove-stale',
    'make 2>&1',
    'cmd 1>&2',
    'ls -la',
    'cat README.md',
    'npm test',
    'python -m pytest',
    'cd /tmp/x',
    'cd /tmp/x && npm run build',
]


@pytest.mark.parametrize("command", GIT_COMMANDS)
def test_git_commands_are_in_scope(hook, command):
    assert hook._is_git_command(command) is True


@pytest.mark.parametrize("command", SHELL_WRITE_COMMANDS)
def test_shell_writes_are_in_scope(hook, command):
    assert hook._is_shell_write_command(command) is True


@pytest.mark.parametrize("command", NOT_COMMANDS)
def test_a_mention_is_never_an_invocation(hook, command):
    """Detection reads the command WORD of each segment, never a substring of
    the line, so these are out of scope however much they look like a match."""
    assert hook._is_git_command(command) is False
    assert hook._is_shell_write_command(command) is False


@pytest.mark.parametrize("command", [None, '', 123, {}, [], b'git push'])
def test_detection_fails_open_on_junk(hook, command):
    assert hook._is_git_command(command) is False
    assert hook._is_shell_write_command(command) is False


def test_indirect_invocation_is_deliberately_not_detected(hook):
    """The documented conservative miss. A command reached through another
    program cannot be classified with confidence, so it is not gated — the write
    TOOLS still cover the ordinary case."""
    for command in ('xargs git commit', 'sh -c "git push"', 'xargs rm',
                    'sh -c "rm x"'):
        assert hook._is_git_command(command) is False
        assert hook._is_shell_write_command(command) is False


def test_the_shell_write_command_set_is_one_reviewable_constant(hook):
    """Kept in one named place so the policy call is editable without touching
    the detector. chmod/chown are deliberately absent: they change metadata, not
    repository content."""
    assert 'rm' in hook._SHELL_WRITE_COMMANDS
    assert 'chmod' not in hook._SHELL_WRITE_COMMANDS
    assert 'chown' not in hook._SHELL_WRITE_COMMANDS
    assert hook._is_shell_write_command('chmod +x run.sh') is False


def test_read_tools_are_out_of_scope_entirely(hook):
    """_READ_TOOLS is gone from the gate. Whatever a hook calls its read tool,
    the gate does not apply to it."""
    entry = _READ_TOOL.get(hook.tool_name)
    if entry is None:
        return  # Codex has no read tool the gate ever saw
    assert hook._repo_gate_applies(entry[0], None) is False


def test_write_tools_are_always_in_scope(hook):
    """No command to inspect and none needed: a write tool is gated on its
    name."""
    assert hook._repo_gate_applies(_WRITE_TOOL[hook.tool_name][0], None) is True


# ===========================================================================
# `cd` into an out-of-scope repository, on every hook.
#
# This is the "personal repo" bypass: the workspace/cwd is a repo the policy
# allows, and the agent simply walks out of it. Every hook must catch it. What
# differs is only the verdict — the four hooks with a warning phase warn and
# then escalate, Augment (which has no warning phase at all) denies outright.
# ===========================================================================

def _assert_cd_caught(hook, response, repo='acme/widgets'):
    """Caught in that hook's own idiom: denied on Augment, warned elsewhere."""
    if hook.tool_name == 'augment':
        _assert_tool_denied(hook, response, repo)
    else:
        _assert_tool_warned(hook, response, repo)


@pytest.mark.parametrize("command", ['cd %s && git commit -m wip',
                                     'cd %s && rm README.md',
                                     'cd %s && echo x > out.txt'])
def test_cd_into_an_out_of_scope_repo_is_caught(hook, repos, command):
    _set_policies(hook, [BLOCK_ORG])
    response = _run_tool(hook, _tool_event(
        hook.tool_name, repos.in_scope, 't1', command % repos.out_scope))
    _assert_cd_caught(hook, response)


def test_bare_cd_with_no_git_or_write_is_allowed(hook, repos):
    """Walking into an out-of-scope repo is not gated; only writing or running git there is."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    for command in ('cd %s', 'cd %s && cat README.md', 'cd %s && ls -la'):
        response = _run_tool(hook, _tool_event(
            hook.tool_name, repos.in_scope, 't1', command % repos.out_scope))
        _assert_tool_allowed(response)
    assert _grace_used(hook) == 0


def test_relative_traversal_out_of_the_allowed_repo_is_caught(hook, repos):
    _set_policies(hook, [BLOCK_ORG])
    response = _run_tool(hook, _tool_event(
        hook.tool_name, repos.in_scope, 't1',
        'cd %s/../widgets && git commit -m wip' % repos.in_scope))
    _assert_cd_caught(hook, response)


def test_cd_within_the_allowed_repo_is_allowed(hook, repos):
    _set_policies(hook, [BLOCK_ORG])
    response = _run_tool(hook, _tool_event(
        hook.tool_name, repos.plain, 't1',
        'cd %s && git commit -m wip' % repos.in_scope))
    _assert_tool_allowed(response)
    assert _grace_used(hook) == 0


def test_cd_escape_escalates_to_a_block_on_the_next_turn(native_turn_hook, repos):
    """Regression guard for Codex and Cursor: their `cd` handling is correct and
    must stay that way — warn once, then block, driven by the native turn id."""
    _set_policies(native_turn_hook, [dict(BLOCK_ORG, grace_turns=1)])
    command = 'cd %s && git commit -m wip' % repos.out_scope
    first = _run_tool(native_turn_hook, _tool_event(
        native_turn_hook.tool_name, repos.in_scope, 't1', command))
    _assert_tool_warned(native_turn_hook, first, 'acme/widgets')
    second = _run_tool(native_turn_hook, _tool_event(
        native_turn_hook.tool_name, repos.in_scope, 't2', command))
    _assert_tool_denied(native_turn_hook, second, 'acme/widgets')


# ===========================================================================
# The scope table, end to end on every hook.
#
#                        | inside allowed org | outside it | no git repo
#   read / grep / glob   | allow              | allow      | allow
#   write tool           | allow              | warn→block | allow
#   git command          | allow              | warn→block | allow
#   shell write          | allow              | warn→block | allow
#   any other command    | allow              | allow      | allow
# ===========================================================================

@pytest.mark.parametrize("command", [GATED_COMMAND, 'git push', 'rm notes.txt',
                                     'mv a b', 'echo x > out.txt'])
def test_gated_commands_in_an_out_of_scope_repo_warn_then_block(grace_hook, repos,
                                                                command):
    _set_policies(grace_hook, [dict(BLOCK_ORG, grace_turns=1)])
    tool = grace_hook.tool_name
    first = _run_tool(grace_hook, _tool_event(tool, repos.out_scope, 't1', command))
    _assert_tool_warned(grace_hook, first, 'acme/widgets')
    second = _run_tool(grace_hook, _tool_event(tool, repos.out_scope, 't2', command))
    _assert_tool_denied(grace_hook, second, 'acme/widgets')


@pytest.mark.parametrize("command", UNGATED_COMMANDS)
def test_ungated_commands_in_an_out_of_scope_repo_are_allowed(hook, repos, command):
    """grace_turns=0, so anything the gate is in scope for would block outright.
    These do not, and they leave the counter untouched."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    response = _run_tool(hook, _tool_event(
        hook.tool_name, repos.out_scope, 't1', command))
    _assert_tool_allowed(response)
    assert _grace_used(hook) == 0


@pytest.mark.parametrize("command", ['git push', 'rm notes.txt',
                                     'echo x > out.txt'])
def test_gated_commands_in_a_non_git_directory_are_allowed(hook, repos, command):
    """A directory under no git root has no origin to judge, so there is nothing
    to be outside of."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    response = _run_tool(hook, _tool_event(
        hook.tool_name, repos.plain, 't1', command))
    _assert_tool_allowed(response)
    assert _grace_used(hook) == 0


@pytest.mark.parametrize("command", ['git push', 'rm notes.txt',
                                     'echo x > out.txt'])
def test_gated_commands_inside_the_allowed_org_are_allowed(hook, repos, command):
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    response = _run_tool(hook, _tool_event(
        hook.tool_name, repos.in_scope, 't1', command))
    _assert_tool_allowed(response)
    assert _grace_used(hook) == 0


def test_a_write_tool_in_an_out_of_scope_repo_warns_then_blocks(grace_hook, repos):
    _set_policies(grace_hook, [dict(BLOCK_ORG, grace_turns=1)])
    tool = grace_hook.tool_name
    _assert_tool_warned(
        grace_hook, _run_tool(grace_hook, _file_event(tool, repos.out_scope, 't1')),
        'acme/widgets')
    _assert_tool_denied(
        grace_hook, _run_tool(grace_hook, _file_event(tool, repos.out_scope, 't2')),
        'acme/widgets')


def test_a_write_tool_is_allowed_in_scope_and_under_no_repo(hook, repos):
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    for where in ('in_scope', 'plain'):
        response = _run_tool(hook, _file_event(hook.tool_name,
                                               getattr(repos, where)))
        _assert_tool_allowed(response)
    assert _grace_used(hook) == 0


# -- relative write paths ---------------------------------------------------
# A write tool may name its target relative to the directory the call is made
# from. Resolving it is what stops `Edit src/main.py` from walking out of the
# gate's reach: three hooks used to derive no repository at all from a relative
# path, so the write was allowed with neither warning nor block.

RELATIVE_TARGET = 'src/main.py'


def test_a_relative_write_path_is_judged_in_the_repo_it_resolves_in(hook, repos):
    """The bypass itself: a relative path in an out-of-scope repo must be
    resolved against the call's own directory, not discarded."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    event = _file_event(hook.tool_name, repos.out_scope, target=RELATIVE_TARGET)
    _assert_tool_denied(hook, _run_tool(hook, event), 'acme/widgets')


def test_a_relative_write_path_in_scope_is_still_allowed(hook, repos):
    """Resolving must not invent a violation: the same relative path inside an
    allowed repo stays allowed and spends no grace."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    event = _file_event(hook.tool_name, repos.in_scope, target=RELATIVE_TARGET)
    _assert_tool_allowed(_run_tool(hook, event))
    assert _grace_used(hook) == 0


def test_a_relative_write_path_with_nothing_to_resolve_against_allows(hook, repos):
    """Fail-open is absolute. With no cwd the path names no repository, so the
    gate has nothing to judge and must allow rather than block."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    event = _file_event(hook.tool_name, repos.out_scope, target=RELATIVE_TARGET)
    event.pop('cwd', None)
    event.pop('workspace_roots', None)
    _assert_tool_allowed(_run_tool(hook, event))


def test_a_read_tool_in_an_out_of_scope_repo_is_allowed(hook, repos):
    """The other half of the semantic change: reads are ungated everywhere, and
    burn no grace, even with grace_turns=0."""
    event = _file_event(hook.tool_name, repos.out_scope, table=_READ_TOOL)
    if event is None:
        pytest.skip('%s has no read tool the gate ever saw' % hook.tool_name)
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    _assert_tool_allowed(_run_tool(hook, event))
    assert _grace_used(hook) == 0


def test_grace_is_spent_once_per_turn_across_several_gated_calls(native_turn_hook,
                                                                 repos):
    """Four gated calls of one turn — a git command, a shell write and two write
    tools — cost one grace between them, not four."""
    _set_policies(native_turn_hook, [dict(BLOCK_ORG, grace_turns=2)])
    tool = native_turn_hook.tool_name
    events = [
        _tool_event(tool, repos.out_scope, 't1', 'git push'),
        _tool_event(tool, repos.out_scope, 't1', 'rm notes.txt'),
        _file_event(tool, repos.out_scope, 't1'),
        _file_event(tool, repos.out_scope, 't1'),
    ]
    for event in events:
        _assert_tool_warned(native_turn_hook, _run_tool(native_turn_hook, event),
                            'acme/widgets')
    assert _grace_used(native_turn_hook) == 1


def test_copilot_successive_tool_calls_escalate_to_a_block(repos, tmp_path):
    """Copilot has no turn id, so memoizing the unknown-turn sentinel would warn forever and never block."""
    hook = _prepare('copilot', tmp_path)
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=1)])
    event = _tool_event('copilot', repos.out_scope, 't1')
    _assert_tool_warned(hook, _run_tool(hook, event), 'acme/widgets')
    for _ in range(3):
        _assert_tool_denied(hook, _run_tool(hook, event), 'acme/widgets')


def test_copilot_cd_into_an_out_of_scope_repo_blocks(repos, tmp_path):
    """The same escalation, reached by walking out of an in-scope workspace."""
    hook = _prepare('copilot', tmp_path)
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=1)])
    event = _tool_event('copilot', repos.in_scope, 't1',
                        'cd %s && git commit -m wip' % repos.out_scope)
    _assert_tool_warned(hook, _run_tool(hook, event), 'acme/widgets')
    _assert_tool_denied(hook, _run_tool(hook, event), 'acme/widgets')


# ===========================================================================
# Augment: what the platform makes impossible, and what is done instead.
#
# https://docs.augmentcode.com/cli/hooks — five events (PreToolUse,
# PostToolUse, Stop, SessionStart, SessionEnd) and no pre-prompt event. Exit 2
# is "Blocking Error — PreToolUse only: Blocks tool execution"; on SessionStart
# the same code means "Hook failed at startup, user needs to fix". So
# conversation-level blocking is impossible and no longer wanted; only in-scope calls are denied.
# ===========================================================================

@pytest.fixture
def augment(tmp_path):
    return _prepare('augment', tmp_path)


def _augment_event(cwd, tool_name='launch-process', tool_input=None, **extra):
    event = {'hook_event_name': 'PreToolUse', 'session_id': 'S1',
             'tool_name': tool_name,
             'tool_input': (tool_input if tool_input is not None
                            else {'command': GATED_COMMAND}),
             'cwd': cwd}
    event.update(extra)
    return event


def test_augment_has_no_prompt_event_to_gate(augment):
    """Documented, not aspirational: there is no UserPromptSubmit/
    beforeSubmitPrompt handler and no session gate to call."""
    assert not hasattr(augment, '_repo_gate_evaluate_session')
    assert not hasattr(augment, 'process_user_prompt_submit')
    source = TOOL_PY['augment'].read_text(encoding='utf-8')
    # No dispatch on any prompt-shaped event name (mentions in comments are the
    # documentation of exactly this gap, so match the dispatch, not the word).
    assert "== 'UserPromptSubmit'" not in source
    assert 'beforeSubmitPrompt' not in source


@pytest.mark.parametrize("tool_name,tool_input", [
    ('launch-process', {'command': 'git push'}),
    ('launch-process', {'command': 'rm auth.py'}),
    ('save-file', {'path': 'notes.txt'}),
    ('str-replace-editor', {'path': 'notes.txt'}),
    ('remove-files', {'path': 'notes.txt'}),
])
def test_augment_out_of_scope_workspace_denies_gated_tools(augment, repos,
                                                           tool_name, tool_input):
    """The workspace gate still denies, but only within the gate's scope: a
    write tool, or a shell command that runs git or writes."""
    _set_policies(augment, [BLOCK_ORG])
    response = _run_tool(augment, _augment_event(
        repos.out_scope, tool_name, tool_input))
    _assert_tool_denied(augment, response, 'acme/widgets')
    assert 'in-scope repository' in (
        response['hookSpecificOutput']['permissionDecisionReason'])


@pytest.mark.parametrize("tool_name,tool_input", [
    ('launch-process', {'command': 'ls -la'}),
    ('launch-process', {'command': 'cat README.md'}),
    ('launch-process', {'command': 'npm test'}),
    ('view', {'path': 'README.md'}),
    ('read-file', {'path': 'README.md'}),
    ('mcp__github__create_issue', {'title': 'x'}),
    ('some-future-tool', {}),
])
def test_augment_out_of_scope_workspace_allows_ungated_tools(augment, repos,
                                                             tool_name, tool_input):
    """Reads, plain shell commands and MCP calls pass even when the workspace is out of scope."""
    _set_policies(augment, [BLOCK_ORG])
    response = _run_tool(augment, _augment_event(
        repos.out_scope, tool_name, tool_input,
        is_mcp_tool=tool_name.startswith('mcp')))
    _assert_tool_allowed(response)


@pytest.mark.parametrize("grace", [0, 1, 3, None])
def test_augment_workspace_deny_ignores_grace_turns(augment, repos, grace):
    """No turn id means a counter that can never advance, so a warning phase
    would leave the policy configured but never enforcing. It denies from the
    first call whatever grace_turns says."""
    policy = dict(BLOCK_ORG)
    if grace is None:
        policy.pop('grace_turns')
        # A policy with no grace at all is malformed and drops out entirely.
        _set_policies(augment, [policy])
        _assert_tool_allowed(_run_tool(augment, _augment_event(repos.out_scope)))
        return
    policy['grace_turns'] = grace
    _set_policies(augment, [policy])
    response = _run_tool(augment, _augment_event(repos.out_scope))
    _assert_tool_denied(augment, response, 'acme/widgets')
    assert _grace_used(augment) == 0
    assert not augment.REPO_GATE_STATE_FILE.exists(), \
        "the workspace gate must not read or write the grace counter"


def test_augment_in_scope_workspace_still_gates_individual_paths(augment, repos):
    """The per-path gate governs individual paths when the workspace itself is
    in scope — and denies, because Augment has no warning phase."""
    _set_policies(augment, [BLOCK_ORG])
    response = _run_tool(augment, _augment_event(
        repos.in_scope, 'save-file', {'path': '%s/notes.txt' % repos.out_scope}))
    _assert_tool_denied(augment, response, 'acme/widgets')


@pytest.mark.parametrize("command", [
    'cd %s && git log --oneline',
    'cd %s && rm README.md',
    'cd %s && echo x > out.txt',
])
def test_augment_cd_out_of_an_in_scope_workspace_is_denied(augment, repos, command):
    """The personal-repo bypass: an in-scope workspace must not let a per-path violation warn forever."""
    _set_policies(augment, [BLOCK_ORG])
    response = _run_tool(augment, _augment_event(
        repos.in_scope, 'launch-process',
        {'command': command % repos.out_scope}))
    _assert_tool_denied(augment, response, 'acme/widgets')
    # Augment renders only permissionDecisionReason, so it must say what to do.
    reason = response['hookSpecificOutput']['permissionDecisionReason']
    assert 'in-scope repository' in reason


def test_augment_absolute_path_into_a_personal_repo_is_denied(augment, repos):
    """The same bypass without a `cd`: a WRITE tool naming an absolute path
    inside an out-of-scope repo from an in-scope workspace."""
    _set_policies(augment, [BLOCK_ORG])
    response = _run_tool(augment, _augment_event(
        repos.in_scope, 'str-replace-editor',
        {'path': '%s/README.md' % repos.out_scope}))
    _assert_tool_denied(augment, response, 'acme/widgets')


def test_augment_reading_a_personal_repo_is_allowed(augment, repos):
    """The read half of the same shape: naming a path inside an out-of-scope
    repo with a READ tool is no longer a violation."""
    _set_policies(augment, [BLOCK_ORG])
    for tool_name in ('view', 'read-file'):
        response = _run_tool(augment, _augment_event(
            repos.in_scope, tool_name,
            {'path': '%s/README.md' % repos.out_scope}))
        _assert_tool_allowed(response)


@pytest.mark.parametrize("grace", [0, 1, 3])
@pytest.mark.parametrize("workspace_in_scope", [True, False])
def test_augment_denies_on_the_first_call_whatever_grace_says(
        augment, repos, grace, workspace_in_scope):
    """No warning phase on EITHER path: the workspace gate and the per-path
    (cd) gate both deny from the first violating call for every grace_turns."""
    _set_policies(augment, [dict(BLOCK_ORG, grace_turns=grace)])
    if workspace_in_scope:
        event = _augment_event(
            repos.in_scope, 'launch-process',
            {'command': 'cd %s && git commit -m wip' % repos.out_scope})
    else:
        event = _augment_event(repos.out_scope)
    _assert_tool_denied(augment, _run_tool(augment, event), 'acme/widgets')


def test_augment_carries_no_grace_machinery_at_all(augment):
    """The absence is the design, not an omission: with no turn id and no prompt
    event, a counter could never advance, so there is none to drift or corrupt."""
    for absent in ('_repo_gate_decide', '_repo_gate_warning', '_repo_gate_turn_id',
                   '_load_repo_gate_state', '_save_repo_gate_state',
                   '_with_repo_gate_context', 'REPO_GATE_TURN_MEMORY'):
        assert not hasattr(augment, absent), absent
    source = TOOL_PY['augment'].read_text(encoding='utf-8')
    assert "'decision': 'warn'" not in source


def test_augment_never_writes_a_grace_counter_file(augment, repos, tmp_path):
    """Whatever the path taken, no state file is created — there is nothing to
    count. _prepare still points REPO_GATE_STATE_FILE at the temp dir, so this
    would catch any reintroduced write."""
    _set_policies(augment, [BLOCK_ORG])
    for event in (_augment_event(repos.out_scope),
                  _augment_event(repos.in_scope, 'launch-process',
                                 {'command': 'cd %s && git commit -m wip'
                                  % repos.out_scope}),
                  _augment_event(repos.in_scope)):
        _run_tool(augment, event)
    assert not (tmp_path / ".repo_gate_state.json").exists()


def test_augment_workspace_without_a_git_origin_allows_everything(augment, repos):
    _set_policies(augment, [dict(BLOCK_ORG, grace_turns=0)])
    for tool_name in ('launch-process', 'view', 'save-file', 'mcp__x__y'):
        response = _run_tool(augment, _augment_event(repos.plain, tool_name, {}))
        _assert_tool_allowed(response)
    assert _grace_used(augment) == 0


def test_augment_in_scope_workspace_allows(augment, repos):
    _set_policies(augment, [dict(BLOCK_ORG, grace_turns=0)])
    _assert_tool_allowed(_run_tool(augment, _augment_event(repos.in_scope)))


def _augment_session_start(augment, cwd):
    event = {'hook_event_name': 'SessionStart', 'session_id': 'S1',
             'workspace_roots': [cwd] if cwd else []}
    with patch.object(augment, '_device_serial', MagicMock()), \
         patch.object(augment, '_check_self_update', MagicMock()), \
         patch.object(augment, '_dispatch_discovery', MagicMock()):
        out, _, _ = _run_main(augment, event)
    return out


def test_augment_session_start_advises_in_an_out_of_scope_workspace(augment, repos,
                                                                    monkeypatch):
    """Advisory only — SessionStart cannot block — and it must not spend the
    grace the per-path gate still needs."""
    monkeypatch.delenv('AUGMENT_PROJECT_DIR', raising=False)
    _set_policies(augment, [BLOCK_ORG])
    out = _augment_session_start(augment, repos.out_scope)
    context = out['hookSpecificOutput']['additionalContext']
    assert out['hookSpecificOutput']['hookEventName'] == 'SessionStart'
    assert 'acme/widgets' in context
    assert 'systemMessage' not in out, "not documented for SessionStart"
    assert _grace_used(augment) == 0


def test_augment_session_start_is_silent_when_in_scope(augment, repos, monkeypatch):
    monkeypatch.delenv('AUGMENT_PROJECT_DIR', raising=False)
    _set_policies(augment, [BLOCK_ORG])
    assert _augment_session_start(augment, repos.in_scope) == {}
    assert _augment_session_start(augment, repos.plain) == {}
    assert _augment_session_start(augment, None) == {}


def test_augment_session_start_fails_open(augment, repos, monkeypatch):
    monkeypatch.delenv('AUGMENT_PROJECT_DIR', raising=False)
    augment.POLICY_CACHE_FILE.write_text('{not json', encoding='utf-8')
    assert _augment_session_start(augment, repos.out_scope) == {}


def test_augment_fails_open_on_a_corrupt_cache_and_missing_workspace(augment, repos,
                                                                     monkeypatch):
    monkeypatch.delenv('AUGMENT_PROJECT_DIR', raising=False)
    augment.POLICY_CACHE_FILE.write_text('{not json', encoding='utf-8')
    _assert_tool_allowed(_run_tool(augment, _augment_event(repos.out_scope)))
    _set_policies(augment, [BLOCK_ORG])
    event = _augment_event(repos.out_scope)
    del event['cwd']
    _assert_tool_allowed(_run_tool(augment, event))


# ===========================================================================
# INCIDENT REPORTING
#
# The gate decides on-device and returns without a network round trip, so a
# WARN or a BLOCK leaves no trace off this machine unless it is reported. A
# report is telemetry hung off a decision already made, and the tests below pin
# both halves of that: the right report leaves the right surface on every hook,
# and nothing about a report — its failure, its absence, its slowness — can
# reach the decision it describes.
#
# CARDINALITY: exactly one report per non-allow verdict. The gate reaches one
# verdict per GATED tool call — there is no prompt verdict any more — so a turn
# with N violating tool calls files N reports and never a multiple of N. An
# ALLOW files none, which now includes every prompt and every read.
# ===========================================================================

@contextmanager
def _started(patches):
    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in patches:
            p.stop()


def _violating_event(hook, cwd, **kw):
    """A tool call working in `cwd`, in that hook's own vocabulary."""
    if hook.tool_name == 'augment':
        return _augment_event(cwd, **kw)
    return _tool_event(hook.tool_name, cwd, **kw)


def _reported_tool(hook, event, gateway=None):
    """(response, reports) for one tool call through the real entry point."""
    posts = []
    return _run_tool(hook, event, gateway=gateway, posts=posts), posts


def _reported_prompt(hook, event, gateway=None):
    posts = []
    return _run_main(hook, event, gateway=gateway, posts=posts)[0], posts


def _assert_report(report, hook, decision, surface, repo='acme/widgets'):
    """The fields the analytics row is keyed on."""
    assert report['decision'] == decision
    assert report['repository'] == repo
    assert report['surface'] == surface
    assert report['agent'] == hook.tool_name
    assert report['policy_id'] == BLOCK_ORG['id']
    assert report['policy_name'] == BLOCK_ORG['name']
    assert report['session_id'] == 'S1'


def test_agent_label_is_the_hook_it_ships_with(hook):
    """One label per tree, and it is the tree's own name — a copy-paste that
    left claude-code's label on another hook would silently mis-attribute every
    incident that hook ever files."""
    assert hook.REPO_GATE_AGENT == hook.tool_name


def test_tool_warn_reports_one_incident(grace_hook, repos):
    _set_policies(grace_hook, [dict(BLOCK_ORG, grace_turns=1)])
    event = _violating_event(grace_hook, repos.out_scope)
    response, reports = _reported_tool(grace_hook, event)
    _assert_tool_warned(grace_hook, response, 'acme/widgets')
    assert len(reports) == 1, reports
    _assert_report(reports[0], grace_hook, 'WARN', 'tool')
    assert reports[0]['tool_input'] == GATED_COMMAND
    assert reports[0]['prompt_text'] is None


def test_tool_block_reports_one_incident(hook, repos):
    """grace_turns=0 blocks from the first violating call on every hook,
    including Augment, which has no warning phase at all."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    response, reports = _reported_tool(hook, _violating_event(hook, repos.out_scope))
    _assert_tool_denied(hook, response, 'acme/widgets')
    assert len(reports) == 1, reports
    _assert_report(reports[0], hook, 'BLOCK', 'tool')


@pytest.mark.parametrize("where", ['in_scope', 'plain'])
def test_an_allowed_call_reports_nothing(hook, repos, where):
    """A compliant repo and a path under no git root are both ALLOW, and an
    ALLOW is not an incident."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    event = _violating_event(hook, getattr(repos, where))
    response, reports = _reported_tool(hook, event)
    _assert_tool_allowed(response)
    assert reports == []


def test_no_policies_configured_reports_nothing(hook, repos):
    _set_policies(hook, [])
    _, reports = _reported_tool(hook, _violating_event(hook, repos.out_scope))
    assert reports == []


def test_a_prompt_never_reports_an_incident(prompt_hook, repos):
    """`surface` is now always "tool": the conversation gate was the only
    producer of surface="prompt", so that value of the server's enum is
    unreachable from any hook. A prompt in an out-of-scope repo is an ALLOW, and
    an ALLOW is not an incident."""
    _set_policies(prompt_hook, [dict(BLOCK_ORG, grace_turns=0)])
    for cwd in (repos.out_scope, repos.in_scope, repos.plain):
        out, reports = _reported_prompt(
            prompt_hook, _prompt_event(prompt_hook.tool_name, cwd))
        _assert_prompt_allowed(out)
        assert reports == []


def test_no_hook_can_emit_the_prompt_surface(hook, repos):
    """Every report any hook can still file names the tool surface."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    posts = []
    for command in ('git push', 'rm notes.txt'):
        _run_tool(hook, _tool_event(hook.tool_name, repos.out_scope, 't1', command),
                  posts=posts)
    assert posts, "the gate must have reported something to make this meaningful"
    assert {p['surface'] for p in posts} == {'tool'}
    source = TOOL_PY[hook.tool_name].read_text(encoding='utf-8')
    assert "'surface': 'prompt'" not in source


def test_one_turn_of_violating_calls_reports_once_per_call(hook, repos):
    """The pinned cardinality, on every hook. Three violating calls reach three
    verdicts and so file three reports — one per verdict, never a duplicate
    pair per call, and never a storm beyond what the decisions themselves
    produce."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=1)])
    posts = []
    for _ in range(3):
        _run_tool(hook, _violating_event(hook, repos.out_scope, turn='t1'),
                  posts=posts)
    assert len(posts) == 3, posts


def test_a_warned_turn_reports_a_warn_for_every_one_of_its_calls(native_turn_hook,
                                                                 repos):
    """Grace is still burned once per turn, so all three calls of a warned turn
    are warns and all three reports say so. Copilot is excluded: without a
    native turn id it charges grace per call, and escalates to BLOCK partway —
    which is the existing documented behaviour, reported faithfully."""
    _set_policies(native_turn_hook, [dict(BLOCK_ORG, grace_turns=1)])
    posts = []
    for _ in range(3):
        _run_tool(native_turn_hook,
                  _violating_event(native_turn_hook, repos.out_scope, turn='t1'),
                  posts=posts)
    assert _grace_used(native_turn_hook) == 1
    assert [p['decision'] for p in posts] == ['WARN'] * 3


# -- nothing about a report can reach a decision ----------------------------

def test_report_is_handed_off_without_ever_being_waited_on(hook):
    """The detachment proof, at the one place it can be proved: _repo_gate_post
    hands the body to curl and returns. Nothing waits on the child, so a hung
    gateway cannot stall a decision — it can only outlive the hook."""
    proc = MagicMock()
    proc.communicate.side_effect = AssertionError('the decision path waited')
    proc.wait.side_effect = AssertionError('the decision path waited')
    with patch.object(hook.subprocess, 'Popen', return_value=proc) as popen:
        hook._repo_gate_post('{"repository": "acme/thing"}', 'KEY')
    argv = popen.call_args.args[0]
    assert argv[0] == 'curl'
    assert argv[-1].endswith('/v1/hooks/repo-gate')
    assert 'Authorization: Bearer KEY' in argv
    assert '--max-time' in argv, 'a hung gateway must not leave curl forever'
    proc.stdin.write.assert_called_once_with(b'{"repository": "acme/thing"}')
    proc.stdin.close.assert_called_once_with()


def test_a_hung_gateway_still_returns_the_deny(hook, repos):
    """End to end through the real _repo_gate_post, with only the curl process
    replaced — a mock that fails the test if anything ever waits on it. The
    Popen patch is scoped to the dispatch alone because the gate resolves git
    roots through subprocess too, and patching it wholesale would fail the gate
    open and prove nothing."""
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    proc = MagicMock()
    proc.communicate.side_effect = AssertionError('the decision path waited')
    proc.wait.side_effect = AssertionError('the decision path waited')
    real_post = hook._repo_gate_post

    def hung_post(body, api_key):
        with patch.object(hook.subprocess, 'Popen', return_value=proc):
            real_post(body, api_key)

    stack = _stubs(hook, MagicMock(return_value={}), real_post=True)
    stack.append(patch.object(hook, '_repo_gate_post', hung_post))
    with _started(stack):
        response = _drive_tool(hook, _violating_event(hook, repos.out_scope))
    _assert_tool_denied(hook, response, 'acme/widgets')
    proc.stdin.close.assert_called_once_with()


@pytest.mark.parametrize("boom", [
    OSError('curl not found'),
    subprocess.TimeoutExpired('curl', 10),
    ValueError('malformed response'),
    RuntimeError('gateway down'),
])
def test_a_failing_report_never_changes_the_decision(hook, repos, boom):
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    stack = _stubs(hook, MagicMock(return_value={}), real_post=True)
    stack.append(patch.object(hook, '_repo_gate_post', MagicMock(side_effect=boom)))
    with _started(stack):
        response = _drive_tool(hook, _violating_event(hook, repos.out_scope))
    _assert_tool_denied(hook, response, 'acme/widgets')


def test_a_missing_api_key_still_denies_and_files_nothing(hook, repos, monkeypatch):
    """No api key is not a reason to let the call through. It is only a reason
    for the incident to go unrecorded."""
    for var in ('UNBOUND_CLAUDE_API_KEY', 'UNBOUND_CURSOR_API_KEY',
                'UNBOUND_COPILOT_API_KEY', 'UNBOUND_CODEX_API_KEY',
                'UNBOUND_AUGMENT_API_KEY'):
        monkeypatch.delenv(var, raising=False)
    _set_policies(hook, [dict(BLOCK_ORG, grace_turns=0)])
    posts = []
    stack = _stubs(hook, MagicMock(return_value={}), posts)
    stack.append(patch.object(hook, '_cached_api_key', None))
    if hasattr(hook, 'get_api_key'):
        stack.append(patch.object(hook, 'get_api_key', MagicMock(return_value=None)))
    with _started(stack):
        response = _drive_tool(hook, _violating_event(hook, repos.out_scope))
    _assert_tool_denied(hook, response, 'acme/widgets')
    assert posts == []


@pytest.mark.parametrize("gate,policies,context", [
    (None, [BLOCK_ORG], {}),
    ({'decision': 'deny'}, [], {}),
    ({'decision': 'deny', 'repo': 'a/b'}, [{}], {}),
    ({'decision': 'warn', 'repo': 'a/b', 'remaining': None}, [BLOCK_ORG], None),
    ('not a dict', [BLOCK_ORG], {}),
])
def test_report_never_raises_on_hostile_input(hook, gate, policies, context):
    """_repo_gate_report is total by construction — its whole body sits inside
    one catch-all — because it is called from inside the gate's own try block:
    an exception escaping there would turn a deny into an allow."""
    with patch.object(hook, '_repo_gate_post', MagicMock()):
        assert hook._repo_gate_report(gate, policies, context) is None


def test_allow_is_never_reported_even_when_asked_directly(hook):
    """Rule 5: the server refuses an ALLOW anyway, but the client does not send
    one. None is the gate's allow verdict."""
    post = MagicMock()
    with patch.object(hook, '_repo_gate_post', post):
        hook._repo_gate_report(None, [BLOCK_ORG], {'surface': 'tool'})
        hook._repo_gate_report({'decision': 'allow', 'repo': 'a/b'},
                               [BLOCK_ORG], {'surface': 'tool'})
    post.assert_not_called()


# -- payload shape ----------------------------------------------------------

def test_long_fields_are_capped_so_the_body_fits_the_pipe(hook):
    """The write into curl's stdin must never block, which it cannot as long as
    the body stays far inside the 64KB pipe buffer."""
    cap = hook.REPO_GATE_REPORT_MAX_CHARS
    assert hook._repo_gate_clip('x' * (cap * 3)) == 'x' * cap
    assert hook._repo_gate_clip('') is None
    assert hook._repo_gate_clip(None) is None
    post = MagicMock()
    with patch.object(hook, '_repo_gate_post', post):
        hook._repo_gate_report(
            {'decision': 'deny', 'repo': 'acme/thing'}, [BLOCK_ORG],
            {'surface': 'tool', 'prompt_text': 'p' * 99999,
             'tool_input': {'command': 'c' * 99999}})
    body = post.call_args.args[0]
    assert len(body) < 16 * 1024
    payload = json.loads(body)
    assert len(payload['prompt_text']) == cap
    assert len(payload['tool_input']) == cap


def test_binding_policy_is_the_one_that_governed_the_timing(hook):
    """A repo outside every policy's scope is denied by all of them; the report
    names the one whose grace decided warn-vs-block, which is the same `min`
    the verdict itself took."""
    strict = dict(BLOCK_ORG, id=7, name='Strict', grace_turns=0)
    lax = dict(BLOCK_ORG, id=8, name='Lax', grace_turns=9)
    assert hook._repo_gate_binding_policy([lax, strict])['id'] == 7
    assert hook._repo_gate_binding_policy([strict, lax])['id'] == 7
    assert hook._repo_gate_binding_policy([lax])['id'] == 8


def test_augment_session_start_advisory_files_no_incident(augment, repos, monkeypatch):
    """An advisory is not a block. SessionStart cannot deny anything, so
    reporting a BLOCK there would invent an incident that never happened."""
    monkeypatch.delenv('AUGMENT_PROJECT_DIR', raising=False)
    _set_policies(augment, [BLOCK_ORG])
    posts = []
    event = {'hook_event_name': 'SessionStart', 'session_id': 'S1',
             'workspace_roots': [repos.out_scope]}
    with patch.object(augment, '_device_serial', MagicMock()), \
         patch.object(augment, '_check_self_update', MagicMock()), \
         patch.object(augment, '_dispatch_discovery', MagicMock()):
        out, _, _ = _run_main(augment, event, posts=posts)
    assert 'acme/widgets' in out['hookSpecificOutput']['additionalContext']
    assert posts == []


def test_augment_reports_no_turn_ordinal(augment, repos):
    """Augment keeps no grace counter and is sent no turn id, so there is no
    turn to report and grace_turns describes nothing it enforced."""
    _set_policies(augment, [BLOCK_ORG])
    _, reports = _reported_tool(augment, _augment_event(repos.out_scope))
    assert len(reports) == 1
    assert reports[0]['turn'] is None


def test_augment_reports_the_path_gate_and_the_workspace_gate_once_each(augment, repos):
    """Two gates, one report per denied call: the workspace gate returns before
    the per-path gate is ever consulted, so a call denied by both files one
    incident, not two."""
    _set_policies(augment, [BLOCK_ORG])
    _, workspace = _reported_tool(augment, _augment_event(repos.out_scope))
    assert len(workspace) == 1
    _, path = _reported_tool(augment, _augment_event(
        repos.in_scope, 'launch-process',
        {'command': 'cd %s && git commit -m wip' % repos.out_scope}))
    assert len(path) == 1


def test_cursor_file_tool_reports_the_path_it_names(tmp_path, repos):
    """Cursor's other tool entry point. preToolUse carries no `command`, and
    names its path on the event itself rather than under tool_input, so the
    report has to fall back to the event to say what was blocked."""
    cursor = _prepare('cursor', tmp_path)
    _set_policies(cursor, [dict(BLOCK_ORG, grace_turns=0)])
    target = '%s/README.md' % repos.out_scope
    event = {'hook_event_name': 'preToolUse', 'conversation_id': 'S1',
             'generation_id': 't1', 'tool_name': 'Write', 'file_path': target,
             'workspace_roots': [repos.out_scope]}
    posts = []
    stack = _stubs(cursor, MagicMock(return_value={}), posts)
    with _started(stack):
        response = cursor.process_pre_tool_use(event, 'KEY')
    _assert_tool_denied(cursor, response, 'acme/widgets')
    assert len(posts) == 1, posts
    _assert_report(posts[0], cursor, 'BLOCK', 'tool')
    assert posts[0]['tool_name'] == 'Write'
    assert posts[0]['tool_input'] == target


def test_cursor_read_tool_is_no_longer_gated(tmp_path, repos):
    """The same entry point with Cursor's read tool: allowed, and silent."""
    cursor = _prepare('cursor', tmp_path)
    _set_policies(cursor, [dict(BLOCK_ORG, grace_turns=0)])
    event = {'hook_event_name': 'preToolUse', 'conversation_id': 'S1',
             'generation_id': 't1', 'tool_name': 'Read',
             'file_path': '%s/README.md' % repos.out_scope,
             'workspace_roots': [repos.out_scope]}
    posts = []
    stack = _stubs(cursor, MagicMock(return_value={}), posts)
    with _started(stack):
        response = cursor.process_pre_tool_use(event, 'KEY')
    _assert_tool_allowed(response)
    assert posts == []
