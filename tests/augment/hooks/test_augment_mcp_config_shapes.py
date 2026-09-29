"""Augment writes its MCP servers in three different shapes.

The hook recovers the real server behind a munged tool name (`<tool>_<Server>`)
by reading `~/.augment/settings.json`. Augment does not always wrap the servers
under `mcpServers` -- the discovery client's own extractor documents a nested
form and a flat form alongside it. A shape the hook cannot parse yields no
servers at all, so `resolve_augment_mcp` returns on its first line and every
call from that machine is attributed to `unknown`: no fingerprint, no policy
match, no server in analytics, and nothing in the logs to say why.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from augment.hooks import unbound  # noqa: E402

SERVER = 'Splunk'
RAW_TOOL = 'splunk_run_query_Splunk'          # Augment's munged `<tool>_<Server>`
ENTRY = {'command': 'splunk-mcp', 'args': ['--stdio']}


class AugmentMcpConfigShapes(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        patcher = patch.object(unbound.Path, 'home', return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Same reason as the Devin tests: the hook prefers these when set, and CI
        # sets them, so without this the fixtures land outside the temp home.
        env = patch.dict('os.environ', {
            'APPDATA': str(self.home / 'AppData' / 'Roaming'),
            'XDG_CONFIG_HOME': str(self.home / '.config'),
        })
        env.start()
        self.addCleanup(env.stop)

    def _write_settings(self, payload):
        path = self.home / '.augment' / 'settings.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding='utf-8')

    def _resolve(self):
        return unbound.resolve_augment_mcp(
            RAW_TOOL, unbound.read_augment_mcp_servers({}))

    # ── the three shapes ────────────────────────────────────────────────

    def test_wrapped_shape_resolves(self):
        """The canonical form. Guards the path that already works."""
        self._write_settings({'mcpServers': {SERVER: ENTRY}})
        server, tool, _ = self._resolve()
        self.assertEqual(SERVER, server)
        self.assertEqual('splunk_run_query', tool)

    def test_nested_shape_resolves(self):
        """`augment.advanced.mcpServers` -- what the settings UI writes."""
        self._write_settings({'augment': {'advanced': {'mcpServers': {SERVER: ENTRY}}}})
        server, tool, _ = self._resolve()
        self.assertEqual(SERVER, server)
        self.assertEqual('splunk_run_query', tool)

    def test_flat_shape_resolves(self):
        """No wrapper at all: `{name: {command|url}}` at the top level."""
        self._write_settings({SERVER: ENTRY})
        server, tool, _ = self._resolve()
        self.assertEqual(SERVER, server)
        self.assertEqual('splunk_run_query', tool)

    # ── what the flat shape must NOT swallow ────────────────────────────

    def test_flat_shape_ignores_keys_that_are_not_servers(self):
        """Every unrecognised settings key sits at this same level, so a server
        is only a dict carrying `command` or `url`. Without that test a `theme`
        or a feature-flag block becomes a server and the suffix match guesses."""
        self._write_settings({
            SERVER: ENTRY,
            'theme': 'dark',                          # scalar
            'telemetry': {'enabled': True},           # dict, but no command/url
            'editor': {'fontSize': 13},
        })
        servers = unbound.read_augment_mcp_servers({})
        self.assertEqual({SERVER}, set(servers))

    def test_an_ambiguous_suffix_is_still_declined(self):
        """Two servers whose names both match the suffix, with different
        fingerprints -> unresolved rather than a guess. The wider parsing must
        not weaken that."""
        self._write_settings({
            'Splunk': {'command': 'a'},
            'run_query_Splunk': {'command': 'b'},
        })
        self.assertEqual((None, None, None), self._resolve())

    def test_nothing_configured_is_not_an_error(self):
        self.assertEqual({}, unbound.read_augment_mcp_servers({}))

    def test_a_malformed_settings_file_does_not_raise(self):
        path = self.home / '.augment' / 'settings.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{not json', encoding='utf-8')
        self.assertEqual({}, unbound.read_augment_mcp_servers({}))


    # ── the two live surfaces ───────────────────────────────────────────

    def test_pre_tool_use_forwards_the_resolved_server(self):
        """PreToolUse is the enforcement path: the gateway matches policy on the
        server, so an unresolved one silently evaluates against nothing."""
        self._write_settings({'augment': {'advanced': {'mcpServers': {SERVER: ENTRY}}}})
        captured = {}

        def _capture(body, key):
            captured['body'] = body
            return {'decision': 'allow'}

        event = {'hook_event_name': 'PreToolUse', 'session_id': 's',
                 'tool_name': RAW_TOOL, 'tool_input': {'q': 1}, 'is_mcp_tool': True}
        with patch.object(unbound, 'send_to_hook_api', side_effect=_capture):
            unbound.process_pre_tool_use(event, 'sk-test')

        meta = captured['body']['pre_tool_use_data']['metadata']
        self.assertEqual(SERVER, meta.get('mcp_server'))
        self.assertEqual('splunk_run_query', meta.get('mcp_tool'))

    def test_post_tool_use_names_the_server_in_the_tool_name(self):
        """PostToolUse feeds analytics and risk scoring. Unresolved, the row
        stores as `mcp__unknown__<tool>` -- which is the shape that leaves the
        server missing from inventory and caps the score as uncorroborated."""
        self._write_settings({SERVER: ENTRY})          # the flat shape
        ev = {'tool_name': RAW_TOOL, 'tool_input': {'q': 1}, 'is_mcp_tool': True,
              'tool_use_id': 'tu-1'}
        out = unbound._augment_posttooluse_to_exchange(
            ev, unbound.read_augment_mcp_servers({}))
        self.assertEqual('mcp__%s__splunk_run_query' % SERVER, out['tool_name'])

if __name__ == '__main__':
    unittest.main()
