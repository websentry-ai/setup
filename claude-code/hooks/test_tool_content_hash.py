"""
Tests for the MCP tool risk-scoring section in claude-code/hooks/unbound.py:
the local mcp-tools-cache.json lookup that attaches `tool_content_hash` to the
outgoing mcp_server_config on MCP PreToolUse, and the single name-inclusive
config-hash cache keying shared with the discovery tool.

The section is embedded identically in every hook variant; a drift-guard test
below asserts the copies stay byte-identical modulo the per-hook constants.
"""

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound

HASH_A = 'a' * 64
SLACK_CFG = {'url': 'https://mcp.slack.com/mcp', 'type': 'http'}
SLACK_KEY = unbound.compute_mcp_cache_key(
    name='slack', command=None, url='https://mcp.slack.com/mcp', args=None,
)
USER = Path.home().name  # home_user convention: home-directory basename


def _config_hash(subset):
    return hashlib.sha256(
        json.dumps(subset, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()


def _cache_payload(coding_tool='Claude Code', user=USER, cache_key=SLACK_KEY,
                   tool='post_message', content_hash=HASH_A):
    return {
        'updated_at': '2026-07-13T00:00:00Z',
        'tools': {coding_tool: {user: {cache_key: {tool: content_hash}}}},
    }


def _metadata(server='slack', tool='post_message', cfg=None):
    if cfg is None:
        cfg = dict(SLACK_CFG)
    return {'mcp_server': server, 'mcp_tool': tool, 'mcp_server_config': cfg}


class _CacheDirMixin(unittest.TestCase):
    """Points the state-dir resolution at a temp dir the test controls."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._tmp.name)
        patcher = patch.object(
            unbound, '_unbound_state_dir_candidates',
            return_value=[self.state_dir],
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def write_cache(self, payload):
        path = self.state_dir / 'mcp-tools-cache.json'
        path.write_text(payload if isinstance(payload, str) else json.dumps(payload))
        return path


class TestComputeMcpCacheKey(unittest.TestCase):
    """The single name-inclusive config-hash contract (SPEC §6 v3), shared
    byte-identically with coding-discovery-tool's mcp_tools_cache module."""

    def test_name_only_server(self):
        # Empty-config servers (connectors, claude.ai integrations, IDE
        # builtins) key on their name alone — no pattern identities.
        self.assertEqual(
            unbound.compute_mcp_cache_key('claude.ai Atlassian', None, None, None),
            _config_hash({'name': 'claude.ai Atlassian'}),
        )

    def test_name_and_command(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key('srv', 'builtin', None, None),
            _config_hash({'name': 'srv', 'command': 'builtin'}),
        )

    def test_full_config(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key(
                'slack', 'npx', 'https://mcp.slack.com/mcp', ['-y', '@slack/mcp']),
            _config_hash({'name': 'slack', 'url': 'https://mcp.slack.com/mcp',
                          'command': 'npx', 'args': ['-y', '@slack/mcp']}),
        )

    def test_strings_stripped_and_empty_dropped(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key(' slack ', '   ', ' https://a.example/m ', None),
            _config_hash({'name': 'slack', 'url': 'https://a.example/m'}),
        )

    def test_canonical_json_form_pinned(self):
        # sort_keys + compact separators over the non-empty subset.
        key = unbound.compute_mcp_cache_key('s', 'node', 'https://a.example', ['x'])
        expected = hashlib.sha256(
            '{"args":["x"],"command":"node","name":"s","url":"https://a.example"}'.encode('utf-8')
        ).hexdigest()
        self.assertEqual(key, expected)

    def test_name_changes_the_key(self):
        a = unbound.compute_mcp_cache_key('name-one', None, 'https://a.example', None)
        b = unbound.compute_mcp_cache_key('name-two', None, 'https://a.example', None)
        self.assertNotEqual(a, b)

    def test_all_empty_returns_none(self):
        self.assertIsNone(unbound.compute_mcp_cache_key(None, None, None, None))
        self.assertIsNone(unbound.compute_mcp_cache_key('', '', '', []))
        self.assertIsNone(unbound.compute_mcp_cache_key('   ', '  ', '  ', None))


class TestAttachToolContentHash(_CacheDirMixin):
    def test_hit_attaches_hash(self):
        self.write_cache(_cache_payload())
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertEqual(md['mcp_server_config']['tool_content_hash'], HASH_A)

    def test_coding_tool_key_matched_case_insensitively(self):
        self.write_cache(_cache_payload(coding_tool='CLAUDE CODE'))
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertEqual(md['mcp_server_config']['tool_content_hash'], HASH_A)

    def test_cowork_surface_matches_too(self):
        self.write_cache(_cache_payload(coding_tool='Claude Cowork'))
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertEqual(md['mcp_server_config']['tool_content_hash'], HASH_A)

    def test_name_only_server_hit(self):
        # Empty-config server (e.g. a connector): keyed on name alone.
        self.write_cache(_cache_payload(cache_key=_config_hash({'name': 'Gmail'})))
        md = _metadata(server='Gmail', cfg={'additional_data': {'scope': 'claude-connector'}})
        unbound._attach_tool_content_hash(md)
        self.assertEqual(md['mcp_server_config']['tool_content_hash'], HASH_A)

    def test_empty_server_name_attaches_nothing(self):
        # No name and an empty config -> no cache key -> no field.
        self.write_cache(_cache_payload())
        md = _metadata(server='', cfg={'type': 'http'})
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_miss_unknown_tool_omits_field(self):
        self.write_cache(_cache_payload())
        md = _metadata(tool='other_tool')
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_miss_unknown_cache_key_omits_field(self):
        self.write_cache(_cache_payload(cache_key=_config_hash({'url': 'https://other.example'})))
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_miss_other_coding_tool_omits_field(self):
        self.write_cache(_cache_payload(coding_tool='Cursor'))
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_miss_other_user_omits_field(self):
        self.write_cache(_cache_payload(user=USER + '-someone-else'))
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_missing_cache_file_omits_field(self):
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_corrupt_cache_file_is_a_miss_not_a_crash(self):
        self.write_cache('{not json!!')
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_non_dict_cache_json_is_a_miss(self):
        self.write_cache('[1, 2, 3]')
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_oversized_cache_file_is_a_miss(self):
        payload = _cache_payload()
        payload['padding'] = 'x' * (unbound._MCP_TOOLS_CACHE_MAX_BYTES + 1)
        self.write_cache(payload)
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_non_sha256_cached_value_not_attached(self):
        self.write_cache(_cache_payload(content_hash='not-a-hash'))
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_malformed_cache_shapes_are_a_miss(self):
        for tools in (
            'string', ['list'],
            {'Claude Code': 'string'},
            {'Claude Code': {USER: 'string'}},
            {'Claude Code': {USER: {SLACK_KEY: 'string'}}},
        ):
            self.write_cache({'tools': tools})
            md = _metadata()
            unbound._attach_tool_content_hash(md)
            self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_no_config_is_a_noop(self):
        md = {'mcp_server': 'slack', 'mcp_tool': 'post_message'}
        unbound._attach_tool_content_hash(md)  # must not raise
        self.assertNotIn('mcp_server_config', md)

    def test_internal_error_never_escapes(self):
        self.write_cache(_cache_payload())
        md = _metadata()
        with patch.object(unbound, '_lookup_tool_content_hash', side_effect=RuntimeError('boom')):
            unbound._attach_tool_content_hash(md)  # must not raise
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])


class TestDispatchPassesCodingTool(unittest.TestCase):
    """SPEC §9: the single-server scan dispatch carries this hook's
    discovery-report coding-tool name so the scanner's cache write lands under
    a key the lookup matches."""

    def test_env_contains_unbound_coding_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / 'config.json'
            config_path.write_text(json.dumps(
                {'api_key': 'k', 'base_url': 'https://backend.example'}))
            fake_bin = Path(tmp) / 'unbound-discovery'
            fake_bin.write_text('')
            with patch.object(unbound, 'UNBOUND_CONFIG_PATH', config_path), \
                 patch.object(unbound, 'RUNNING_FROZEN', True), \
                 patch.object(unbound, 'FROZEN_DISCOVERY_BIN', str(fake_bin)), \
                 patch.object(unbound.subprocess, 'Popen') as popen:
                unbound._dispatch_mcp_server_scan('srv', {'url': 'https://a.example'})
        self.assertTrue(popen.called)
        env = popen.call_args.kwargs['env']
        self.assertEqual(env['UNBOUND_CODING_TOOL'], 'Claude Code')
        self.assertEqual(unbound._UNBOUND_CODING_TOOL, 'Claude Code')


class TestCrossHookSectionConsistency(unittest.TestCase):
    """The risk-scoring section is embedded per hook (single-file self-update
    constraint). It must stay byte-identical across variants, modulo the three
    per-hook coding-tool constants."""

    START = '# KEEP IN SYNC: coding-discovery-tool mcp_tools_cache.py + all 5 hook copies'
    END = '# ───────────────────────── end MCP tool risk-scoring section ─────────────────'
    HOOK_FILES = (
        'claude-code/hooks/unbound.py',
        'codex/hooks/unbound.py',
        'copilot/hooks/unbound.py',
        'augment/hooks/unbound.py',
        'cursor/unbound.py',
    )

    def _section(self, text):
        section = text[text.index(self.START):text.index(self.END)]
        section = re.sub(r'_MCP_CACHE_CODING_TOOL_NAMES = .*', '<PER-HOOK>', section)
        section = re.sub(r'_MCP_CACHE_CODING_TOOL_PREFIXES = .*', '<PER-HOOK>', section)
        return re.sub(r'_UNBOUND_CODING_TOOL = .*', '<PER-HOOK>', section)

    def test_sections_identical_across_hooks(self):
        repo_root = Path(__file__).resolve().parents[2]
        paths = [repo_root / rel for rel in self.HOOK_FILES]
        missing = [p for p in paths if not p.is_file()]
        if missing:
            self.skipTest(f'hook files not found: {missing}')
        base = self._section(paths[0].read_text(encoding='utf-8'))
        for path in paths[1:]:
            with self.subTest(hook=str(path)):
                self.assertEqual(
                    self._section(path.read_text(encoding='utf-8')), base,
                    f'{path} drifted from {paths[0]} — keep the embedded '
                    f'risk-scoring sections in sync across all hook variants',
                )


if __name__ == '__main__':
    unittest.main()
