"""
Regression tests for the UserPromptSubmit deny response schema in unbound.py.

Claude Code reads suppressOriginalPrompt only inside hookSpecificOutput; a
top-level flag is silently ignored and the denied prompt is echoed back to the
user. Pin the exact nested shape so an edit can't regress it. The binary parity
harness compares same-source runs and would not catch a schema regression here.
"""

import unittest

import unbound


class TestPromptDenyResponse(unittest.TestCase):
    def test_deny_nests_suppress_flag_in_hook_specific_output(self):
        out = unbound.transform_response_for_claude_prompt(
            {'decision': 'deny', 'reason': 'Blocked by policy'}
        )
        self.assertEqual(out.get('decision'), 'block')
        self.assertEqual(out.get('reason'), 'Blocked by policy')
        hso = out.get('hookSpecificOutput')
        self.assertIsInstance(hso, dict)
        self.assertEqual(hso.get('hookEventName'), 'UserPromptSubmit')
        self.assertIs(hso.get('suppressOriginalPrompt'), True)

    def test_deny_does_not_emit_top_level_suppress_flag(self):
        # top-level placement is the broken shape Claude Code ignores
        out = unbound.transform_response_for_claude_prompt(
            {'decision': 'deny', 'reason': 'x'}
        )
        self.assertNotIn('suppressOriginalPrompt', out)

    def test_allow_with_context_injects_hook_specific_output(self):
        out = unbound.transform_response_for_claude_prompt(
            {'additionalContext': 'note'}
        )
        hso = out.get('hookSpecificOutput', {})
        self.assertEqual(hso.get('hookEventName'), 'UserPromptSubmit')
        self.assertEqual(hso.get('additionalContext'), 'note')
        self.assertNotIn('decision', out)

    def test_empty_response_is_noop(self):
        self.assertEqual(unbound.transform_response_for_claude_prompt({}), {})


if __name__ == '__main__':
    unittest.main()
