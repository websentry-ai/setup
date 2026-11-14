"""Parity guard for the connection-identity account stamp.

The extract → cache → stamp helpers are a KEEP-IN-SYNC block across the mcp__-tool-name hook
copies (claude-code, codex). This test asserts they are byte-identical (AST) so a fix can't land
in one tool only, and that each copy actually behaves. (cursor has no MCP path; copilot/augment
resolve MCP servers differently and carry their own key derivation — tracked as follow-ups, so
they are intentionally NOT in COPIES here.)
"""
import ast
import unittest
from pathlib import Path

from tests.conftest import load_module

REPO = Path(__file__).resolve().parent.parent
COPIES = ['claude-code/hooks/unbound.py', 'codex/hooks/unbound.py']
SYNCED_FUNCS = [
    '_looks_like_gmail_connection', '_connection_cache_key', '_normalize_account_email',
    '_gmail_messages', '_account_from_gmail_message', '_extract_connection_account',
    '_mcp_identity_dir', '_cache_connection_identity', '_read_connection_identity',
    '_attach_connection_identity',
]
HOOKS = [load_module(c) for c in COPIES]


class TestConnectionIdentityParity(unittest.TestCase):
    def test_synced_functions_are_byte_identical_across_copies(self):
        """Byte-identical or a fix lands in one tool only."""
        for name in SYNCED_FUNCS:
            dumps = {}
            for relpath in COPIES:
                tree = ast.parse((REPO / relpath).read_text())
                fn = next((n for n in ast.walk(tree)
                           if isinstance(n, ast.FunctionDef) and n.name == name), None)
                self.assertIsNotNone(fn, "%s missing in %s" % (name, relpath))
                dumps.setdefault(ast.dump(fn), []).append(relpath)
            self.assertEqual(len(dumps), 1, "%s drifted: %s" % (name, list(dumps.values())))

    def test_each_copy_extracts_the_sent_account(self):
        out = {'threads': [{'messages': [
            {'labelIds': ['SENT'], 'sender': 'sumit@unboundsecurity.ai'}]}]}
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                acct = hook._extract_connection_account(out)
                self.assertEqual(acct['email'], 'sumit@unboundsecurity.ai')
                self.assertEqual(acct['confidence'], 'high')

    def test_each_copy_derives_the_cache_key(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__):
                key = hook._connection_cache_key('mcp__claude_ai_Gmail__search_threads', '/p')
                self.assertTrue(key.startswith('claude_ai_Gmail__'))
                self.assertIsNone(hook._connection_cache_key('mcp__slack__post', '/p'))
                self.assertIsNone(hook._connection_cache_key('Bash', '/p'))


if __name__ == '__main__':
    unittest.main()
