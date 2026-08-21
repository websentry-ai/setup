"""
Tests for generations that carry more than one prompt in cursor/unbound.py.

Typing while Cursor is still working can add prompts to the running generation. Covers:
  - build_llm_exchange  (every prompt kept, joined into one message, anchored on the first)
"""

import unittest

import unbound

CONVERSATION = "conv-1"
GENERATION = "gen-1"
FIRST_PROMPT = "2026-08-20T10:00:00Z"
SECOND_PROMPT = "2026-08-20T10:00:10Z"
STOP = "2026-08-20T10:00:20Z"


def _log(hook_event_name, timestamp, **fields):
    event = {"hook_event_name": hook_event_name,
             "conversation_id": CONVERSATION,
             "generation_id": GENERATION,
             "model": "auto"}
    event.update(fields)
    return {"timestamp": timestamp, "event": event}


def _user_messages(exchange):
    return [m["content"] for m in (exchange or {}).get("messages", [])
            if m.get("role") == "user"]


class TestGenerationCarryingSeveralPrompts(unittest.TestCase):
    def test_two_prompts_become_one_joined_message(self):
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt="first"),
            _log("beforeSubmitPrompt", SECOND_PROMPT, prompt="second"),
            _log("stop", STOP, agentTextResponse="done"),
        ])
        self.assertEqual(_user_messages(exchange), ["first\n\nsecond"])

    def test_turn_anchors_on_the_first_prompt(self):
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt="first"),
            _log("beforeSubmitPrompt", SECOND_PROMPT, prompt="second"),
            _log("stop", STOP, agentTextResponse="done"),
        ])
        self.assertEqual(exchange.get("requestInitialized"), FIRST_PROMPT)

    def test_single_prompt_generation_is_unchanged(self):
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt="only"),
            _log("stop", STOP, agentTextResponse="done"),
        ])
        self.assertEqual(_user_messages(exchange), ["only"])
        self.assertEqual(exchange.get("requestInitialized"), FIRST_PROMPT)

    def test_empty_prompt_is_ignored(self):
        exchange = unbound.build_llm_exchange([
            _log("beforeSubmitPrompt", FIRST_PROMPT, prompt=""),
            _log("beforeSubmitPrompt", SECOND_PROMPT, prompt="real"),
            _log("stop", STOP, agentTextResponse="done"),
        ])
        self.assertEqual(_user_messages(exchange), ["real"])


if __name__ == "__main__":
    unittest.main()
