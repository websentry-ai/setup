"""The MDM `unbound-hook` binary vendors `claude-code/hooks/unbound.py` verbatim
(unbound-hook.spec), so the prompt-doubling fix must live in the module the binary
loads: a UserPromptSubmit logged twice by two registered hooks (same prompt_id)
collapses to one prompt, not "<prompt>\n\n<prompt>". If the vendoring or the fix
regresses, customers on the packaged binary get doubled prompts again.
"""
import importlib.util

from conftest import TOOL_PY


def _load(tool):
    path = TOOL_PY[tool]
    spec = importlib.util.spec_from_file_location("hook_%s" % tool.replace('-', '_'), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _user_messages(exchange):
    return [m["content"] for m in (exchange or {}).get("messages", []) if m.get("role") == "user"]


def _submit(ts, prompt, prompt_id=None):
    ev = {"hook_event_name": "UserPromptSubmit", "session_id": "S1", "prompt": prompt}
    if prompt_id is not None:
        ev["prompt_id"] = prompt_id
    return {"timestamp": ts, "session_id": "S1", "event": ev}


def test_vendored_claude_hook_dedupes_double_logged_submit():
    m = _load("claude-code")
    exchange = m.build_llm_exchange(
        [_submit("2026-08-20T10:00:00Z", "now", "p1"),
         _submit("2026-08-20T10:00:00Z", "now", "p1")],
        stop_assistant_message="done")
    assert _user_messages(exchange) == ["now"]


def test_vendored_claude_hook_keeps_distinct_prompt_ids():
    m = _load("claude-code")
    exchange = m.build_llm_exchange(
        [_submit("2026-08-20T10:00:00Z", "again", "p1"),
         _submit("2026-08-20T10:00:10Z", "again", "p2")],
        stop_assistant_message="done")
    assert _user_messages(exchange) == ["again\n\nagain"]
