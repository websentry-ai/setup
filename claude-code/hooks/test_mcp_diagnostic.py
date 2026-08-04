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

    def test_all_six_sources_present(self):
        r = self._run(
            'some-server',
            [patch.object(unbound, '_resolve_plugin_mcp_config_by_server_key', return_value=None)],
        )
        self.assertEqual(
            set(r['sources']),
            {'claude_json', 'claude_ai_connector', 'plugin_cache',
             'session_connector', 'launch_config', 'plugin_by_key'},
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


if __name__ == '__main__':
    unittest.main()
