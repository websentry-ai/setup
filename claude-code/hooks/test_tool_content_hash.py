import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound

HASH_A = 'a' * 64
HASH_B = 'b' * 64
SLACK_CFG = {'url': 'https://mcp.slack.com/mcp', 'type': 'http'}
SLACK_KEY = unbound.compute_mcp_cache_key(
    name='slack', command=None, url='https://mcp.slack.com/mcp', args=None,
)
USER = Path.home().name  # home_user convention: home-directory basename


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
    def test_unknown_name_only_server_has_no_fingerprint(self):
        self.assertIsNone(
            unbound.compute_mcp_cache_key('unknown server', None, None, None)
        )

    def test_intellij_builtin(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key('srv', 'builtin', None, None),
            'intellij:srv',
        )

    def test_url_has_priority_over_command(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key(
                'slack', 'npx', 'https://mcp.slack.com/mcp', ['-y', '@slack/mcp']),
            'url:mcp.slack.com/mcp',
        )

    def test_url_credentials_query_and_fragment_are_removed(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key(
                'slack', None,
                'https://user:secret@mcp.slack.com/mcp?token=x#fragment', None,
            ),
            'url:mcp.slack.com/mcp',
        )

    def test_invalid_port_has_no_fingerprint(self):
        self.assertIsNone(
            unbound.compute_mcp_cache_key(
                'broken', None, 'https://mcp.example.com:99999/mcp', None,
            )
        )

    def test_git_credentials_are_removed(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key(
                'server', 'npx', None,
                ['git+https://user:secret@github.com/owner/repo.git'],
            ),
            'git:github.com/owner/repo',
        )

    def test_bare_npm_package(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key('one', 'npx', None, ['-y', 'mcp-server']),
            'npm:mcp-server',
        )

    def test_name_does_not_change_package_identity(self):
        a = unbound.compute_mcp_cache_key('name-one', None, 'https://a.example', None)
        b = unbound.compute_mcp_cache_key('name-two', None, 'https://a.example', None)
        self.assertEqual(a, b)

    def test_connector_scope_uses_name(self):
        self.assertEqual(
            unbound.compute_mcp_cache_key(
                'Gmail', None, 'https://registration.example/id', None,
                additional_data={'scope': 'claude-connector'},
            ),
            'claude-connector:gmail',
        )

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
        self.write_cache(_cache_payload(cache_key='claude-connector:gmail'))
        md = _metadata(server='Gmail', cfg={'additional_data': {'scope': 'claude-connector'}})
        unbound._attach_tool_content_hash(md)
        self.assertEqual(md['mcp_server_config']['tool_content_hash'], HASH_A)

    def test_precomputed_fingerprint_survives_argument_redaction(self):
        self.write_cache(_cache_payload(cache_key='npm:mcp-server'))
        md = _metadata(cfg={
            'command': 'npx',
            'args': [],
            '_unbound_fingerprint': 'npm:mcp-server',
        })
        unbound._attach_tool_content_hash(md)
        cfg = md['mcp_server_config']
        self.assertEqual(cfg['tool_content_hash'], HASH_A)
        self.assertNotIn('_unbound_fingerprint', cfg)

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
        self.write_cache(_cache_payload(cache_key='url:other.example'))
        md = _metadata()
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('tool_content_hash', md['mcp_server_config'])

    def test_ambiguous_cached_hashes_are_ignored(self):
        self.write_cache(_cache_payload(content_hash=[HASH_A, 'b' * 64]))
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

    def test_unknown_server_without_config_is_a_noop(self):
        md = {'mcp_server': 'unknown server', 'mcp_tool': 'post_message'}
        unbound._attach_tool_content_hash(md)
        self.assertNotIn('mcp_server_config', md)

    def test_builtin_without_config_attaches_hash(self):
        self.write_cache(_cache_payload(cache_key='claude-builtin:computer-use'))
        md = {'mcp_server': 'computer-use', 'mcp_tool': 'post_message'}
        unbound._attach_tool_content_hash(md)
        self.assertEqual(md['mcp_server_config']['tool_content_hash'], HASH_A)

    def test_bad_home_cache_does_not_shadow_valid_fallback(self):
        home_state_dir = self.state_dir / '.unbound'
        fallback_state_dir = self.state_dir / 'fallback'
        home_state_dir.mkdir(mode=0o700)
        fallback_state_dir.mkdir(mode=0o700)
        (home_state_dir / 'mcp-tools-cache.json').write_text('{not json')
        (fallback_state_dir / 'mcp-tools-cache.json').write_text(
            json.dumps(_cache_payload(user=self.state_dir.name))
        )

        with patch.object(Path, 'home', return_value=home_state_dir.parent), patch.object(
            unbound,
            '_unbound_state_dir_candidates',
            return_value=[home_state_dir, fallback_state_dir],
        ):
            md = _metadata()
            unbound._attach_tool_content_hash(md)

        self.assertEqual(md['mcp_server_config']['tool_content_hash'], HASH_A)

    def test_newer_fallback_cache_wins_over_valid_stale_home_cache(self):
        home_state_dir = self.state_dir / '.unbound'
        fallback_state_dir = self.state_dir / 'fallback'
        home_state_dir.mkdir(mode=0o700)
        fallback_state_dir.mkdir(mode=0o700)
        home_cache = home_state_dir / 'mcp-tools-cache.json'
        fallback_cache = fallback_state_dir / 'mcp-tools-cache.json'
        user = self.state_dir.name
        home_cache.write_text(json.dumps(_cache_payload(user=user)))
        fallback_cache.write_text(json.dumps(_cache_payload(user=user, content_hash=HASH_B)))
        os.utime(home_cache, (1, 1))
        os.utime(fallback_cache, (2, 2))

        with patch.object(Path, 'home', return_value=self.state_dir), patch.object(
            unbound,
            '_unbound_state_dir_candidates',
            return_value=[home_state_dir, fallback_state_dir],
        ):
            md = _metadata()
            unbound._attach_tool_content_hash(md)

        self.assertEqual(md['mcp_server_config']['tool_content_hash'], HASH_B)

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


class TestClaudeBuiltinFingerprint(unittest.TestCase):
    def test_each_builtin_server_has_a_distinct_fingerprint(self):
        expected = {
            'computer-use': 'claude-builtin:computer-use',
            'claude_in_chrome': 'claude-builtin:claude-in-chrome',
            'claude_browser': 'claude-builtin:claude-browser',
            'claude_preview': 'claude-builtin:claude-preview',
            'claude_design': 'claude-builtin:claude-design',
            'ccd_session': 'claude-builtin:ccd-session',
            'ccd_session_mgmt': 'claude-builtin:ccd-session-mgmt',
            'ide': 'claude-builtin:ide',
        }
        for name, fingerprint in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    unbound.compute_fingerprint(
                        name=name,
                        command=None,
                        url=None,
                        args=[],
                        additional_data=None,
                    ),
                    fingerprint,
                )


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
