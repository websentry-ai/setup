"""Tests for the null-fingerprint MCP diagnostic in claude-code/hooks/unbound.py:
secret scrubbing, resolution-replay fidelity vs the live ladder, and log
suppression so the passive replay can't pollute the shared error.log."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import unbound

_RESOLVERS_MISS = (
    '_read_mcp_server_config',
    '_resolve_claude_ai_connector',
    '_resolve_plugin_mcp_config',
    '_resolve_claude_code_session_connector',
    '_resolve_launch_mcp_config',
    '_read_mcp_server_config_worktree_union',
)


class TestDiagRedaction(unittest.TestCase):
    def test_host_of_strips_userinfo(self):
        self.assertEqual(
            unbound._mcp_diag_host_of('https://user:pass@api.acme.com:8443/mcp?t=1'),
            'https://api.acme.com:8443',
        )

    def test_host_of_plain(self):
        self.assertEqual(
            unbound._mcp_diag_host_of('https://api.acme.com/mcp'), 'https://api.acme.com'
        )

    def test_host_of_unparseable(self):
        self.assertEqual(unbound._mcp_diag_host_of('not-a-url'), '<unparseable-url>')

    def test_scrub_strips_url_userinfo(self):
        out = unbound._mcp_diag_scrub('conn https://user:pw@h.com/path tail')
        self.assertNotIn('user:pw', out)
        self.assertNotIn('pw@', out)

    def test_scrub_drops_credential_lines(self):
        out = unbound._mcp_diag_scrub('authorization: Bearer sk-secret')
        self.assertNotIn('sk-secret', out)
        self.assertIn('suppressed', out)


class TestDiagResolutionLadder(unittest.TestCase):
    def _run(self, server, extra=None):
        patchers = [patch.object(unbound, name, return_value=None) for name in _RESOLVERS_MISS]
        patchers += extra or []
        for p in patchers:
            p.start()
        try:
            return unbound._mcp_diag_resolution(server, '/tmp')
        finally:
            for p in patchers:
                p.stop()

    def test_all_seven_sources_present(self):
        r = self._run(
            'some-server',
            [patch.object(unbound, '_resolve_plugin_mcp_config_by_server_key', return_value=None)],
        )
        self.assertEqual(
            set(r['sources']),
            {'claude_json', 'claude_ai_connector', 'plugin_cache',
             'session_connector', 'launch_config', 'plugin_by_key',
             'worktree_union'},
        )
        self.assertFalse(r['resolved'])

    def test_plugin_by_key_skipped_for_non_plugin_server(self):
        mock = MagicMock(return_value=None)
        r = self._run(
            'normal-server',
            [patch.object(unbound, '_resolve_plugin_mcp_config_by_server_key', mock)],
        )
        self.assertEqual(r['sources']['plugin_by_key'], 'miss')
        mock.assert_not_called()

    def test_plugin_by_key_matches_live_signature(self):
        # --plugin-url present -> live disables suffix guessing; the replay must too.
        mock = MagicMock(return_value=None)
        self._run(
            'plugin_foo_bar',
            [
                patch.object(unbound, '_resolve_plugin_mcp_config_by_server_key', mock),
                patch.object(unbound, '_claude_plugin_launch_values',
                             return_value=(['/dir'], ['http://plugin'])),
            ],
        )
        mock.assert_called_once()
        kwargs = mock.call_args.kwargs
        self.assertEqual(kwargs['extra_dirs'], ['/dir'])
        self.assertFalse(kwargs['allow_suffix_guess'])


class TestDiagLogSuppression(unittest.TestCase):
    def test_log_error_noops_when_suppressed(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / 'error.log'
            with patch.object(unbound, 'ERROR_LOG', log), \
                 patch.object(unbound, '_suppress_error_logging', True):
                unbound.log_error('should not be written')
            self.assertFalse(log.exists() and 'should not' in log.read_text())

    def test_replay_does_not_pollute_error_log(self):
        def _noisy(*_a, **_k):
            unbound.log_error('resolver-miss-noise')
            return None

        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / 'error.log'
            patchers = [
                patch.object(unbound, 'ERROR_LOG', log),
                patch.object(unbound, '_read_mcp_server_config', side_effect=_noisy),
                patch.object(unbound, '_resolve_claude_ai_connector', return_value=None),
                patch.object(unbound, '_resolve_plugin_mcp_config', return_value=None),
                patch.object(unbound, '_resolve_claude_code_session_connector', return_value=None),
                patch.object(unbound, '_resolve_launch_mcp_config', return_value=None),
                patch.object(unbound, '_resolve_plugin_mcp_config_by_server_key', return_value=None),
            ]
            for p in patchers:
                p.start()
            try:
                unbound._mcp_diag_resolution('some-server', '/tmp')
            finally:
                for p in patchers:
                    p.stop()
            polluted = log.exists() and 'resolver-miss-noise' in log.read_text()
        self.assertFalse(polluted)
        self.assertFalse(unbound._suppress_error_logging)


class TestDiagUpload(unittest.TestCase):
    def _proc(self, returncode):
        proc = MagicMock()
        proc.communicate.return_value = (None, None)
        proc.returncode = returncode
        return proc

    def test_curl_failure_is_logged(self):
        with patch.object(unbound.subprocess, 'Popen', return_value=self._proc(22)), \
             patch.object(unbound, 'log_error') as mock_log:
            unbound._upload_mcp_diagnostic({'server': 'x'}, 'key')
        self.assertTrue(any('curl exit' in str(c) for c in mock_log.call_args_list))

    def test_curl_success_is_not_logged(self):
        with patch.object(unbound.subprocess, 'Popen', return_value=self._proc(0)), \
             patch.object(unbound, 'log_error') as mock_log:
            unbound._upload_mcp_diagnostic({'server': 'x'}, 'key')
        mock_log.assert_not_called()


class TestDiagInventory(unittest.TestCase):
    def test_summarize_entry_url_strips_userinfo_and_marks_query(self):
        s = unbound._diag_summarize_entry({'url': 'https://user:pw@h.com/mcp?t=1', 'type': 'http'})
        self.assertIn('https://h.com', s)
        self.assertNotIn('user:pw', s)
        self.assertIn('…', s)  # query marker

    def test_summarize_entry_command_missing_on_disk(self):
        s = unbound._diag_summarize_entry({'command': '/no/such/bin/xyz', 'args': ['a', 'b']})
        self.assertIn('cmd=xyz', s)
        self.assertIn('MISSING-ON-DISK', s)
        self.assertIn('args=2', s)

    def test_summarize_entry_counts_env_and_headers(self):
        s = unbound._diag_summarize_entry({'command': 'x', 'env': {'A': 1, 'B': 2}, 'headers': {'H': 1}})
        self.assertIn('env=2 keys', s)
        self.assertIn('headers=1 keys', s)

    def test_servers_from_json_wrapped_and_unwrapped(self):
        import json as _json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            wrapped = Path(d) / 'a.json'
            wrapped.write_text(_json.dumps({'mcpServers': {'s1': {'command': 'x'}}}))
            self.assertEqual(set(unbound._diag_servers_from_json(wrapped)), {'s1'})
            root = Path(d) / 'b.json'
            root.write_text(_json.dumps({'s2': {'url': 'http://h'}}))
            self.assertEqual(set(unbound._diag_servers_from_json(root)), {'s2'})

    def test_target_appears_exact_and_near(self):
        inv = [{'source': 'src', 'file': 'f',
                'servers': {'acme-mcp': 'cmd=x', 'plugin_bar_acme_mcp': 'cmd=y', 'other': 'cmd=z'}}]
        res = unbound._diag_target_appears('acme-mcp', inv)
        self.assertEqual([e['name'] for e in res['exact']], ['acme-mcp'])
        self.assertIn('plugin_bar_acme_mcp', [n['name'] for n in res['near']])
        self.assertNotIn('other', [n['name'] for n in res['near']])


class TestDiagRender(unittest.TestCase):
    def test_render_produces_text_with_sections(self):
        d = {
            'version': 'v2', 'server': 'acme-mcp', 'cwd': '/p', 'cwd_resolved': '/p',
            'platform': 'darwin', 'python': '3.11', 'claude_version': '1.2', 'claude_path': '/bin/claude',
            'env_vars': {'CLAUDE_CONFIG_DIR': '/cfg'},
            'hook': {'running': {'path': '/run/unbound.py', 'sha256': 'a' * 64},
                     'installed': [{'path': '/inst/unbound.py', 'sha256': 'b' * 64}],
                     'registration': 'persisted'},
            'hook_registration': [{'file': '/s.json', 'events': ['PreToolUse [unbound]'], 'commands': ['python unbound.py']}],
            'claude_json': {'present': True, 'size': 10, 'mtime': 't', 'parse_ok': True,
                            'top_level_servers': ['figma'], 'project_count': 1, 'project_entry': None, 'scoped_under': []},
            'resolution': {'sources': {'claude_json': 'miss', 'plugin_by_key': 'miss'}, 'resolved': False, 'via': None, 'config': None},
            'mcp_inventory': [{'source': 'plugin installed:context7', 'file': '/c/.mcp.json', 'servers': {'context7': 'cmd=npx, args=2'}}],
            'target_appears': {'exact': [], 'near': []},
            'unbound_client': {'org_name': 'unbound', 'api_key': 'present'},
            'plugin_registries': {'installed_plugins.json': ['context7'], 'cache_dir': '/cache'},
            'launch_flags': ['--permission-mode auto'],
            'project_mcp_json': [{'file': '/.mcp.json', 'servers': ['x']}],
            'claude_mcp_list': 'server: ok',
            'claude_mcp_get': '<no output>',
            'error_log_tail': ['some mcp error'],
        }
        r = unbound._render_mcp_diagnostic(d)
        self.assertIsInstance(r, str)
        for marker in ('server=acme-mcp', '=== environment ===', 'MCP server inventory',
                       'context7', 'claude mcp list', 'installed:context7',
                       '/inst/unbound.py', 'registration'):
            self.assertIn(marker, r)


class TestDiagValueScrub(unittest.TestCase):
    def test_strips_proxy_userinfo(self):
        self.assertEqual(
            unbound._diag_scrub_value('http://user:pw@proxy.corp:8080'),
            'http://proxy.corp:8080',
        )

    def test_redacts_credential_bearing_value(self):
        self.assertEqual(unbound._diag_scrub_value('Bearer sk-abc123'), '<redacted>')

    def test_plain_value_passes_through(self):
        self.assertEqual(unbound._diag_scrub_value('cli'), 'cli')

    def test_settings_registration_scrubs_hook_commands(self):
        import json as _json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            s = Path(d) / 'settings.json'
            s.write_text(_json.dumps({'hooks': {'PreToolUse': [
                {'hooks': [{'command': 'python hook.py --token=sk-leak'}]}]}}))
            with patch.object(unbound, '_diag_settings_files', return_value=[s]):
                out = unbound._diag_settings_registration('/cwd')
        cmds = out[0]['commands']
        self.assertIn('<redacted>', cmds)
        self.assertFalse(any('sk-leak' in c for c in cmds))


class TestDiagLaunchContext(unittest.TestCase):
    def test_forwarded_launch_argv_is_honored(self):
        env = {'UNBOUND_DIAG_LAUNCH_PID': '4321',
               'UNBOUND_DIAG_LAUNCH_ARGV': '["claude", "--plugin-url", "http://x"]'}
        with patch.dict('os.environ', env):
            got = unbound._claude_launch_argv()
        self.assertEqual(got, (4321, ['claude', '--plugin-url', 'http://x']))

    def test_no_forwarded_env_falls_back_to_walk(self):
        # With no forwarding env, it must not raise and returns a tuple-or-None.
        import os as _os
        _os.environ.pop('UNBOUND_DIAG_LAUNCH_ARGV', None)
        got = unbound._claude_launch_argv()
        self.assertTrue(got is None or isinstance(got, tuple))


class TestDiagDispatchFrozen(unittest.TestCase):
    def _capture_cmd(self, frozen, env=None):
        popen = MagicMock()
        with patch.object(unbound, 'RUNNING_FROZEN', frozen), \
             patch.object(unbound, '_mcp_diag_on_cooldown', return_value=False), \
             patch.object(unbound, '_mcp_diag_mark_dispatched'), \
             patch.dict('os.environ', env or {}, clear=False), \
             patch.object(unbound.subprocess, 'Popen', popen):
            unbound._dispatch_mcp_diagnostic('nullfp_demo', '/cwd', 'key')
        return popen.call_args[0][0] if popen.call_args else None

    def test_frozen_reinvokes_binary_subcommand(self):
        cmd = self._capture_cmd(True, {'UNBOUND_HOOK_TOOL': 'claude-code'})
        self.assertEqual(cmd[1:], ['mcp-diagnostic', 'claude-code'])

    def test_frozen_defaults_tool_when_env_missing(self):
        import os as _os
        _os.environ.pop('UNBOUND_HOOK_TOOL', None)
        cmd = self._capture_cmd(True)
        self.assertEqual(cmd[1:], ['mcp-diagnostic', 'claude-code'])

    def test_non_frozen_reinvokes_self_with_flag(self):
        cmd = self._capture_cmd(False)
        self.assertIn('--mcp-diagnostic', cmd)
        self.assertTrue(cmd[1].endswith('unbound.py'))


if __name__ == '__main__':
    unittest.main()
