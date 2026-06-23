import json

from unbound_hook import setup_cmd
from unbound_hook._resources import HOOK_BINARY, hook_command_for_event


def test_matcher_handles_quoted_bare_and_launcher_forms():
    match = setup_cmd._command_targets_hook
    assert match(str(HOOK_BINARY), HOOK_BINARY)
    assert match(f'"{HOOK_BINARY}"', HOOK_BINARY)
    assert match(f'"{HOOK_BINARY}" hook codex PreToolUse', HOOK_BINARY)
    assert match(f'py -3 "{HOOK_BINARY}" hook codex PreToolUse', HOOK_BINARY)
    assert not match("/opt/other/hook", HOOK_BINARY)
    assert not match("", HOOK_BINARY)


def test_merge_does_not_duplicate_quoted_entry(tmp_path):
    hooks_path = tmp_path / "hooks.json"
    canonical = hook_command_for_event("codex", "PreToolUse")
    config = setup_cmd._codex_hooks_config(canonical)
    for event, items in config.items():
        for item in items:
            for hook in item["hooks"]:
                hook["command"] = f'"{HOOK_BINARY}" hook codex {event}'
    hooks_path.write_text(json.dumps({"hooks": config}))

    setup_cmd._merge_codex_hooks_json(hooks_path, canonical)

    result = json.loads(hooks_path.read_text())
    for event, items in result["hooks"].items():
        total = sum(len(item["hooks"]) for item in items)
        assert total == 1, f"{event} duplicated: {items}"
