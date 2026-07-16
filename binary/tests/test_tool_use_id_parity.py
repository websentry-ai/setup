"""Every tool call must carry a stable tool_use_id so the backend dedups by id.

The hooks resolve an id as `native_id or synthetic_id`, where the synthetic id is a
DETERMINISTIC hash of replay-stable content. Two invariants keep it from creating the
very duplicate it prevents:

  * DETERMINISM  — the same call always hashes to the same id (a resender replaying its
    history re-derives the SAME id, so the backend drops the replay).
  * PRE == POST  — the PreToolUse emit and the completion emit for the same call derive
    the identical id, so a pre command re-appearing in post is never a NEW id.

Native-id precedence is also asserted: a real tool id is never overwritten by a synthetic
one. Copilot is intentionally excluded from synthetic minting — its completion path carries
the native transcript toolCallId and its pretool row dedups on content/request_id, so a
minted pre id (which could never equal the transcript id) would fork the row.
"""
import importlib.util

from conftest import TOOL_PY


def _load(tool):
    path = TOOL_PY[tool]
    spec = importlib.util.spec_from_file_location("hook_%s" % tool.replace('-', '_'), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_claude_native_precedence_and_pre_post_parity():
    m = _load("claude-code")
    pre = {'session_id': 'S1', 'prompt_id': 'P1', 'tool_name': 'Bash',
           'tool_input': {'command': 'ls -la'}}
    post = {**pre, 'tool_response': {'stdout': 'x'}}
    assert m.resolve_tool_use_id({**pre, 'tool_use_id': 'toolu_9'}) == 'toolu_9'
    assert m.resolve_tool_use_id(pre) == m.resolve_tool_use_id(post)
    assert m.resolve_tool_use_id(pre).startswith('unb-')
    assert m.resolve_tool_use_id(pre) == m.resolve_tool_use_id(dict(pre))  # deterministic
    # prompt_id is NOT in the key, so a PostToolUse that omits it still matches the pre id.
    assert m.resolve_tool_use_id(pre) == m.resolve_tool_use_id(
        {'session_id': 'S1', 'tool_name': 'Bash', 'tool_input': {'command': 'ls -la'}})
    # MCP input is canonicalized: key order must not diverge the id.
    mcp_a = {'session_id': 'S1', 'tool_name': 'mcp__x__y', 'tool_input': {'q': 1, 'a': 2}}
    mcp_b = {'session_id': 'S1', 'tool_name': 'mcp__x__y', 'tool_input': {'a': 2, 'q': 1}}
    assert m.resolve_tool_use_id(mcp_a) == m.resolve_tool_use_id(mcp_b)


def test_codex_synthetic_fallback_is_deterministic_and_paired():
    m = _load("codex")
    cmd = m.extract_command_for_pretool({'tool_name': 'mcp__foo__bar', 'tool_input': {'a': 1}})
    pre = m._synthetic_tool_use_id('S1', 'T1', 'mcp__foo__bar', cmd)
    post = m._synthetic_tool_use_id('S1', 'T1', 'mcp__foo__bar', cmd)
    assert pre == post and pre.startswith('unb-')
    other = m._synthetic_tool_use_id(
        'S1', 'T1', 'mcp__foo__bar',
        m.extract_command_for_pretool({'tool_name': 'mcp__foo__bar', 'tool_input': {'a': 2}}))
    assert pre != other  # a different call -> a different id


def test_cursor_pre_post_parity_shell_and_mcp():
    m = _load("cursor")
    sh_pre = {'hook_event_name': 'beforeShellExecution', 'conversation_id': 'C1',
              'generation_id': 'G1', 'command': 'ls -la /tmp'}
    sh_post = {'hook_event_name': 'afterShellExecution', 'conversation_id': 'C1',
               'generation_id': 'G1', 'command': 'ls -la /tmp', 'output': 'files'}
    assert m._resolve_tool_use_id(sh_pre) == m._resolve_tool_use_id(sh_post)
    # MCP: after* drops the server 'command' and may reorder tool_input keys -> both are
    # excluded/normalized so the id still matches.
    mcp_pre = {'hook_event_name': 'beforeMCPExecution', 'conversation_id': 'C1',
               'generation_id': 'G2', 'command': 'my-server', 'tool_name': 'search',
               'tool_input': {'q': 1, 'a': 2}}
    mcp_post = {'hook_event_name': 'afterMCPExecution', 'conversation_id': 'C1',
                'generation_id': 'G2', 'tool_name': 'search', 'tool_input': {'a': 2, 'q': 1},
                'result_json': '{}'}
    assert m._resolve_tool_use_id(mcp_pre) == m._resolve_tool_use_id(mcp_post)
    assert m._resolve_tool_use_id({'tool_use_id': 'nativeX', 'command': 'y'}) == 'nativeX'
    assert m._resolve_tool_use_id(sh_pre) != m._resolve_tool_use_id({**sh_pre, 'generation_id': 'G9'})
    # File events (afterFileEdit) carry no command/tool_input: must key on path (+edits),
    # so distinct files get distinct ids (not all collapsing onto an empty-content hash),
    # and the same edit replays to the same id.
    fe1 = {'hook_event_name': 'afterFileEdit', 'conversation_id': 'C1', 'generation_id': 'G3',
           'file_path': '/a.py', 'edits': [{'old': 'x', 'new': 'y'}]}
    fe2 = {'hook_event_name': 'afterFileEdit', 'conversation_id': 'C1', 'generation_id': 'G3',
           'file_path': '/b.py', 'edits': [{'old': 'x', 'new': 'y'}]}
    assert m._resolve_tool_use_id(fe1) == m._resolve_tool_use_id(dict(fe1))  # stable on replay
    assert m._resolve_tool_use_id(fe1) != m._resolve_tool_use_id(fe2)        # distinct files


def test_augment_pre_post_parity_and_native_precedence():
    m = _load("augment")
    pre = {'session_id': 'C1', 'tool_name': 'launch-process', 'tool_input': {'command': 'ls -la'}}
    post = {**pre, 'tool_response': {'stdout': 'x'}}
    assert m._resolve_tool_use_id(pre) == m._resolve_tool_use_id(post)
    assert m._resolve_tool_use_id({'tool_use_id': 'nativeY', 'tool_name': 'x'}) == 'nativeY'
    assert m._resolve_tool_use_id(pre).startswith('unb-')
    # File edit: pre carries the path in tool_input; the completion may carry it only in
    # file_changes[0].path -- both must resolve to the same id.
    f_pre = {'session_id': 'C1', 'tool_name': 'str-replace-editor', 'tool_input': {'file_path': '/a.py'}}
    f_post = {'session_id': 'C1', 'tool_name': 'str-replace-editor', 'tool_input': {},
              'file_changes': [{'path': '/a.py'}]}
    assert m._resolve_tool_use_id(f_pre) == m._resolve_tool_use_id(f_post)
    # MCP input canonicalized: key order must not diverge the id.
    a = {'session_id': 'C1', 'tool_name': 'srv', 'is_mcp_tool': True, 'tool_input': {'q': 1, 'a': 2}}
    b = {'session_id': 'C1', 'tool_name': 'srv', 'is_mcp_tool': True, 'tool_input': {'a': 2, 'q': 1}}
    assert m._resolve_tool_use_id(a) == m._resolve_tool_use_id(b)


def test_copilot_forwards_native_id_and_mints_nothing():
    # Copilot intentionally has no synthetic minting helper; it forwards the native
    # transcript toolCallId on completion (see build_exchange_from_transcript).
    m = _load("copilot")
    assert not hasattr(m, '_synthetic_tool_use_id')
    assert not hasattr(m, '_resolve_tool_use_id')
