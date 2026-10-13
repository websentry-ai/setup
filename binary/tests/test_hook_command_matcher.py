import json

from unbound_hook import setup_cmd
from unbound_hook._resources import HOOK_BINARY


def test_matcher_handles_quoted_bare_and_launcher_forms():
    match = setup_cmd._command_targets_hook
    assert match(str(HOOK_BINARY), HOOK_BINARY)
    assert match(f'"{HOOK_BINARY}"', HOOK_BINARY)
    assert match(f'"{HOOK_BINARY}" hook codex PreToolUse', HOOK_BINARY)
    assert match(f'py -3 "{HOOK_BINARY}" hook codex PreToolUse', HOOK_BINARY)
    assert not match("/opt/other/hook", HOOK_BINARY)
    assert not match(f'/opt/other/hook --target "{HOOK_BINARY}"', HOOK_BINARY)
    assert not match(f"{HOOK_BINARY}.backup hook codex PreToolUse", HOOK_BINARY)
    assert not match("", HOOK_BINARY)
