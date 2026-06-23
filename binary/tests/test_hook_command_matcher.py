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


def test_merge_does_not_duplicate_quoted_entry(tmp_path):
    hooks_path = tmp_path / "hooks.json"
    wrapper = tmp_path / ".codex" / "hooks" / "unbound.py"
    hook_command = str(wrapper)
    config = setup_cmd._codex_hooks_config(hook_command)
    for event, items in config.items():
        for item in items:
            for hook in item["hooks"]:
                hook["command"] = f'"{wrapper}"'
    hooks_path.write_text(json.dumps({"hooks": config}))

    setup_cmd._merge_codex_hooks_json(hooks_path, hook_command)

    result = json.loads(hooks_path.read_text())
    for event, items in result["hooks"].items():
        total = sum(len(item["hooks"]) for item in items)
        assert total == 1, f"{event} duplicated: {items}"
