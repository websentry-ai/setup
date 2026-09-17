"""Unit tests for the connection-identity account stamp (v0: Gmail).

Covers the extract → cache (PostToolUse) → stamp (PreToolUse) path and its fail-open edges.
Mirrors the ai-gateway-data mcp_identity_service extraction rules (SENT→sender /
INBOX→deliveredTo|single toRecipients) so the endpoint stamp agrees with the control-plane
observe attribution.
"""
import json
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


# ── extraction ───────────────────────────────────────────────────────────────

class ExtractAccountTests(unittest.TestCase):
    def test_sent_thread_is_the_sender_high(self):
        out = {'threads': [{'id': 't1', 'messages': [
            {'labelIds': ['SENT'], 'sender': 'sumit@unboundsecurity.ai',
             'toRecipients': ['neha@supersourcing.com']},
        ]}]}
        acct = unbound._extract_connection_account(out)
        self.assertEqual(acct['email'], 'sumit@unboundsecurity.ai')
        self.assertEqual(acct['domain'], 'unboundsecurity.ai')
        self.assertEqual(acct['confidence'], 'high')

    def test_received_prefers_delivered_to_medium(self):
        out = {'threads': [{'messages': [
            {'labelIds': ['INBOX', 'IMPORTANT'], 'sender': 'news@substack.com',
             'deliveredTo': 'sumit@unboundsecurity.ai',
             'toRecipients': ['sumit@unboundsecurity.ai', 'other@x.com']},
        ]}]}
        acct = unbound._extract_connection_account(out)
        self.assertEqual(acct['email'], 'sumit@unboundsecurity.ai')
        self.assertEqual(acct['confidence'], 'medium')

    def test_received_single_recipient_when_no_delivered_to(self):
        out = {'messages': [
            {'labelIds': ['INBOX'], 'sender': 'a@b.com', 'toRecipients': ['me@corp.com']},
        ]}
        self.assertEqual(unbound._extract_connection_account(out)['email'], 'me@corp.com')

    def test_received_multi_recipient_no_delivered_to_is_ambiguous(self):
        # single_only: several To recipients + no deliveredTo → attribute nothing, don't guess.
        out = {'messages': [
            {'labelIds': ['INBOX'], 'sender': 'a@b.com',
             'toRecipients': ['x@corp.com', 'y@corp.com']},
        ]}
        self.assertIsNone(unbound._extract_connection_account(out))

    def test_flat_get_message_shape(self):
        out = {'labelIds': ['SENT'], 'sender': 'sumit@unboundsecurity.ai',
               'toRecipients': ['x@p.com']}
        self.assertEqual(
            unbound._extract_connection_account(out)['email'], 'sumit@unboundsecurity.ai')

    def test_display_name_is_unwrapped(self):
        out = {'labelIds': ['SENT'], 'sender': 'Sumit Badsara <sumit@gmail.com>'}
        self.assertEqual(unbound._extract_connection_account(out)['email'], 'sumit@gmail.com')

    def test_garbage_sender_rejected(self):
        for bad in ('gmail.com>', 'not an email', 'a@b', '', 'x@y@z.com', 'a b@c.com'):
            out = {'labelIds': ['SENT'], 'sender': bad}
            self.assertIsNone(unbound._extract_connection_account(out), bad)

    def test_json_string_response_is_parsed(self):
        out = json.dumps({'labelIds': ['SENT'], 'sender': 'sumit@unboundsecurity.ai'})
        self.assertEqual(
            unbound._extract_connection_account(out)['email'], 'sumit@unboundsecurity.ai')

    def test_non_gmail_and_garbage_yield_none(self):
        for bad in (None, 'not json', 42, {'files': [{'owner': 'a@b.com'}]}, {'foo': 'bar'}):
            self.assertIsNone(unbound._extract_connection_account(bad))

    def test_most_frequent_mailbox_wins_across_messages(self):
        # A thread seen from one mailbox: it is the sender of its SENT msg and the recipient of
        # the received ones — all the same account; a stray counterparty must not win.
        out = {'threads': [{'messages': [
            {'labelIds': ['SENT'], 'sender': 'me@corp.com', 'toRecipients': ['peer@x.com']},
            {'labelIds': ['INBOX'], 'sender': 'peer@x.com', 'deliveredTo': 'me@corp.com'},
        ]}]}
        self.assertEqual(unbound._extract_connection_account(out)['email'], 'me@corp.com')


# ── server-key derivation ─────────────────────────────────────────────────────

class ServerKeyTests(unittest.TestCase):
    def test_parses_and_sanitizes(self):
        self.assertEqual(
            unbound._connection_server_key('mcp__claude_ai_Gmail__search_threads'),
            'claude_ai_Gmail')

    def test_non_mcp_is_none(self):
        self.assertIsNone(unbound._connection_server_key('Bash'))
        self.assertIsNone(unbound._connection_server_key(''))
        self.assertIsNone(unbound._connection_server_key(None))

    def test_path_traversal_chars_are_stripped(self):
        key = unbound._connection_server_key('mcp__../../etc/passwd__x')
        self.assertNotIn('/', key)
        self.assertNotIn('..', key.replace('.', ''))  # dots kept but no slash escape


# ── cache round-trip + stamp ──────────────────────────────────────────────────

class CacheAndStampTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._tmp.name)
        p = patch.object(unbound, '_unbound_state_dir_candidates',
                         return_value=[self.state_dir])
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)

    def _sent_event(self, tool='mcp__claude_ai_Gmail__search_threads'):
        return {
            'tool_name': tool,
            'tool_response': {'threads': [{'messages': [
                {'labelIds': ['SENT'], 'sender': 'sumit@unboundsecurity.ai'}]}]},
        }

    def test_cache_then_stamp_round_trip(self):
        unbound._cache_connection_identity(self._sent_event())
        meta = {'mcp_server': 'Gmail'}  # display name differs from the raw key — keyed by tool_name
        unbound._attach_connection_identity(meta, 'mcp__claude_ai_Gmail__send_message')
        ci = meta['connection_identity']
        self.assertEqual(ci['status'], 'resolved')
        self.assertEqual(ci['account']['email'], 'sumit@unboundsecurity.ai')
        self.assertEqual(ci['account']['domain'], 'unboundsecurity.ai')
        self.assertEqual(ci['source'], 'endpoint_hook_cache')

    def test_no_account_no_cache_no_stamp(self):
        unbound._cache_connection_identity(
            {'tool_name': 'mcp__claude_ai_Gmail__search_threads',
             'tool_response': {'files': [{'owner': 'x@y.com'}]}})
        meta = {}
        unbound._attach_connection_identity(meta, 'mcp__claude_ai_Gmail__send_message')
        self.assertNotIn('connection_identity', meta)

    def test_non_mcp_event_is_ignored(self):
        unbound._cache_connection_identity(
            {'tool_name': 'Bash', 'tool_response': {'labelIds': ['SENT'], 'sender': 'a@b.com'}})
        self.assertEqual(list(self.state_dir.glob('**/*.json')), [])

    def test_expired_entry_is_not_stamped(self):
        unbound._cache_connection_identity(self._sent_event())
        cache = self.state_dir / unbound._MCP_IDENTITY_DIRNAME / 'claude_ai_Gmail.json'
        rec = json.loads(cache.read_text())
        rec['ts'] = int(time.time()) - unbound._MCP_IDENTITY_TTL_SECONDS - 10
        cache.write_text(json.dumps(rec))
        meta = {}
        unbound._attach_connection_identity(meta, 'mcp__claude_ai_Gmail__send_message')
        self.assertNotIn('connection_identity', meta)

    def test_corrupt_and_oversize_entries_fail_open(self):
        cache_dir = self.state_dir / unbound._MCP_IDENTITY_DIRNAME
        cache_dir.mkdir(parents=True)
        (cache_dir / 'a.json').write_text('{not json')
        self.assertIsNone(unbound._read_connection_identity('a'))
        (cache_dir / 'b.json').write_text(
            json.dumps({'account': {'email': 'x@y.com'}, 'ts': int(time.time()),
                        'pad': 'z' * (unbound._MCP_IDENTITY_MAX_BYTES + 10)}))
        self.assertIsNone(unbound._read_connection_identity('b'))

    def test_missing_entry_is_none(self):
        self.assertIsNone(unbound._read_connection_identity('nope'))
        self.assertIsNone(unbound._read_connection_identity(None))

    def test_stamp_is_absent_for_non_mcp_tool(self):
        meta = {}
        unbound._attach_connection_identity(meta, 'Bash')
        self.assertNotIn('connection_identity', meta)


if __name__ == '__main__':
    unittest.main()
