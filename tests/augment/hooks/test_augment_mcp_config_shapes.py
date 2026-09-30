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


class _IsolatedHome(unittest.TestCase):
    """Shared setup only -- no tests, so subclasses do not inherit and rerun any."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        real_home = Path.home()          # captured BEFORE the patch below
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
        # The module builds its log/cache paths from Path.home() at IMPORT time,
        # so patching Path.home here is too late for them: a test that makes the
        # hook log an error would append to the real user's error.log. Repoint
        # every module constant that still resolves under the real home.
        moved_any = False
        for attr in dir(unbound):
            value = getattr(unbound, attr, None)
            if not isinstance(value, Path) or not attr.isupper():
                continue
            try:
                rel = value.relative_to(real_home)
            except ValueError:
                continue
            moved = patch.object(unbound, attr, self.home / rel)
            moved.start()
            self.addCleanup(moved.stop)
            moved_any = True
        # If the module ever stops deriving these from the home directory this
        # loop silently stops protecting anything, which is how the first
        # attempt at this leaked into the real error.log.
        self.assertTrue(moved_any, 'no module paths were redirected; isolation is off')
        # The Stop tests reach _device_serial(probe=True), which shells out to
        # dmidecode before falling back. The rest of this suite stubs it for the
        # same reason: a probe that hangs costs the test its 10s timeout.
        serial = patch.object(unbound, '_device_serial', return_value=None)
        serial.start()
        self.addCleanup(serial.stop)

    def _write_settings(self, payload):
        path = self.home / '.augment' / 'settings.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding='utf-8')

    def _resolve(self):
        return unbound.resolve_augment_mcp(
            RAW_TOOL, unbound.read_augment_mcp_servers({}))

    def _post_log(self):
        return [{'event': {
            'hook_event_name': 'PostToolUse', 'tool_name': RAW_TOOL,
            'tool_input': {'q': 1}, 'is_mcp_tool': True, 'tool_use_id': 'tu-1'}}]

    def _stop_event(self):
        """A Stop carrying the turn's conversation. Without it the builder has
        nothing to hang the tool calls on and returns None."""
        return {'session_id': 's', 'hook_event_name': 'Stop',
                'conversation': {'userPrompt': 'run the query',
                                 'agentTextResponse': 'done'}}

    def _tool_names(self, exchange):
        names = []
        for m in (exchange or {}).get('messages', []):
            for tu in (m.get('tool_use') or []):
                names.append(tu.get('tool_name'))
        return names


class AugmentMcpConfigShapes(_IsolatedHome):

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

    # ── the Stop-event door (end-of-turn analytics) ─────────────────────

    def test_stop_event_analytics_names_the_server(self):
        """build_llm_exchange is the door the hook actually runs at end of turn;
        asserting on the inner builder would not have caught a break here."""
        self._write_settings({'augment': {'advanced': {'mcpServers': {SERVER: ENTRY}}}})
        ex = unbound.build_llm_exchange(
            self._stop_event(), self._post_log())
        self.assertIn('mcp__%s__splunk_run_query' % SERVER, self._tool_names(ex))

    def test_stop_event_wrapped_shape_is_unchanged(self):
        """Backward-compat: the shape that already worked still produces the
        same tool_name after the reader was widened."""
        self._write_settings({'mcpServers': {SERVER: ENTRY}})
        ex = unbound.build_llm_exchange(
            self._stop_event(), self._post_log())
        self.assertIn('mcp__%s__splunk_run_query' % SERVER, self._tool_names(ex))

    # ── the server config the gateway fingerprints on ───────────────────

    def test_pre_tool_use_forwards_the_server_config(self):
        """`mcp_server_config` is what the gateway fingerprints, and what
        `_dispatch_mcp_server_scan` needs -- resolving the NAME but dropping the
        config leaves the server unscannable."""
        self._write_settings({SERVER: ENTRY})          # flat shape
        captured = {}

        def _capture(body, key):
            captured['body'] = body
            return {'decision': 'allow'}

        event = {'hook_event_name': 'PreToolUse', 'session_id': 's',
                 'tool_name': RAW_TOOL, 'tool_input': {'q': 1}, 'is_mcp_tool': True}
        with patch.object(unbound, 'send_to_hook_api', side_effect=_capture):
            unbound.process_pre_tool_use(event, 'sk-test')

        cfg = captured['body']['pre_tool_use_data']['metadata'].get('mcp_server_config')
        self.assertIsNotNone(cfg, 'server resolved but its config was dropped')
        self.assertEqual('splunk-mcp', cfg.get('command'))

    def test_a_resolved_server_still_dispatches_a_scan_when_unknown_to_the_gateway(self):
        """The gateway answers `unknown_mcp_server` for a server it has never
        fingerprinted. That path needs the config, so it must survive the
        widened reader."""
        self._write_settings({SERVER: ENTRY})
        seen = {}

        def _scan(name, cfg):
            seen['name'], seen['cfg'] = name, cfg

        event = {'hook_event_name': 'PreToolUse', 'session_id': 's',
                 'tool_name': RAW_TOOL, 'tool_input': {'q': 1}, 'is_mcp_tool': True}
        with patch.object(unbound, 'send_to_hook_api',
                          return_value={'decision': 'allow', 'unknown_mcp_server': True}), \
             patch.object(unbound, '_dispatch_mcp_server_scan', side_effect=_scan):
            unbound.process_pre_tool_use(event, 'sk-test')
        self.assertEqual(SERVER, seen.get('name'))

    # ── hostile input: the settings file is user-editable ───────────────

    def test_a_hostile_settings_file_yields_no_server_and_does_not_raise(self):
        """Every key of the flat shape comes from a file a user (or anything
        writing as them) controls."""
        self._write_settings({
            '__proto__': {'command': 'x'},
            'constructor': {'url': 'http://x.test'},
            'a' * 5000: {'command': 'y'},
            'nested': {'deep': {'command': 'z'}},     # command not at this level
        })
        servers = unbound.read_augment_mcp_servers({})       # must not raise
        # `nested` carries no command/url of its own, so it is not a server.
        self.assertNotIn('nested', servers)
        # And nothing here matches the Splunk suffix, so resolution declines.
        self.assertEqual((None, None, None), self._resolve())

    def test_the_cli_config_wins_over_vs_code_for_the_same_name(self):
        """Sources are read CLI-first and the first definition of a name wins.
        Widening the CLI reader therefore changes which config a machine with
        both surfaces resolves to -- it used to fall through to VS Code when the
        CLI file was unwrapped. CLI-first is the existing intent; this pins it.
        """
        self._write_settings({SERVER: {'command': 'from-cli'}})     # flat
        base = unbound._vscode_user_dirs()[0].parent.parent
        vs = (base / 'Code' / 'User' / 'globalStorage' / 'augment.vscode-augment'
              / 'augment-global-state' / 'mcpServers.json')
        vs.parent.mkdir(parents=True, exist_ok=True)
        vs.write_text(json.dumps([{'name': SERVER, 'command': 'from-vscode'},
                                  {'name': 'vscode-only', 'command': 'only-here'}]),
                      encoding='utf-8')
        servers = unbound.read_augment_mcp_servers({})
        # A VS-Code-only server must still load, or this asserts nothing: the
        # CLI value would win simply by being the only file ever read.
        self.assertIn('vscode-only', servers)
        self.assertEqual('from-cli', servers[SERVER]['command'])

    # ── the same file, parsed twice, in two repos ───────────────────────

    def test_the_discovery_client_reads_the_same_shapes(self):
        """`~/.augment/settings.json` is parsed here AND by the discovery
        client's `_extract_servers_obj`. Two parsers, one file: when they
        disagree the inventory and the enforcement path describe different
        machines, and nothing says so. That divergence is what this fix was.

        Skips where the sibling repo is not checked out -- it is absent on CI.
        """
        import subprocess
        rel = ('scripts/coding_discovery_tools/macos/augment/'
               'augment_mcp_config_extractor.py')
        roots = [Path(__file__).resolve().parents[3].parent]
        # A worktree lives outside the clone, so also look beside the main one.
        try:
            out = subprocess.run(
                ['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                capture_output=True, text=True,
                cwd=str(Path(__file__).resolve().parents[3]))
            if out.returncode == 0 and out.stdout.strip():
                roots.append(Path(out.stdout.strip()).parent.parent)
        except (OSError, subprocess.SubprocessError):
            pass
        mod_path = next((r / 'coding-discovery-tool' / rel for r in roots
                         if (r / 'coding-discovery-tool' / rel).exists()), None)
        if mod_path is None:
            self.skipTest('coding-discovery-tool is not checked out beside this repo')
        src = mod_path.read_text(encoding='utf-8')
        # Import just the pure function; the module's own imports need the
        # package installed, which the hook repo has no reason to carry.
        start = src.index('def _extract_servers_obj')
        end = src.index('\nclass ')
        ns = {'Any': object, 'Dict': dict}
        exec(compile(src[start:end], 'discovery_extract', 'exec'), ns)
        theirs = ns['_extract_servers_obj']

        for label, payload in (
            ('wrapped', {'mcpServers': {SERVER: ENTRY}}),
            ('nested', {'augment': {'advanced': {'mcpServers': {SERVER: ENTRY}}}}),
            ('flat', {SERVER: ENTRY}),
            ('flat with noise', {SERVER: ENTRY, 'theme': 'dark',
                                 'telemetry': {'enabled': True}}),
        ):
            with self.subTest(shape=label):
                self.assertEqual(
                    set(theirs(payload)), set(unbound._augment_cli_servers(payload)),
                    'the hook and the discovery client disagree on %s' % label)


class ThroughTheRealEntrypoint(_IsolatedHome):
    """Augment runs the hook as a script: JSON on stdin, a decision on stdout.

    Every other test here enters one level down, at process_pre_tool_use or
    build_llm_exchange. That skips main() -- the stdin read, the dispatch on
    hook_event_name, and the emit -- which is exactly the layer that changes
    when output handling does. These drive main() itself; only the network
    calls are stubbed, so the read and the emit run for real.
    """

    def _run_main(self, event):
        import io
        out = io.StringIO()
        with patch.object(unbound.sys, 'stdin', io.StringIO(json.dumps(event))), \
             patch.object(unbound.sys, 'stdout', out), \
             patch.object(unbound, 'get_api_key', return_value='sk-test'):
            unbound.main()
        return out.getvalue()

    def _decision(self, stdout):
        lines = [l for l in stdout.strip().splitlines() if l.strip()]
        self.assertTrue(lines, 'the hook emitted nothing -- the host would hang or fail open')
        return json.loads(lines[-1])

    # H1
    def test_pre_tool_use_through_main_resolves_the_server(self):
        self._write_settings({'augment': {'advanced': {'mcpServers': {SERVER: ENTRY}}}})
        sent = {}

        def _capture(body, key):
            sent['body'] = body
            return {'decision': 'allow'}

        with patch.object(unbound, 'send_to_hook_api', side_effect=_capture):
            out = self._run_main({
                'hook_event_name': 'PreToolUse', 'session_id': 'sess-h1',
                'tool_name': RAW_TOOL, 'tool_input': {'q': 1}, 'is_mcp_tool': True})

        self._decision(out)                                    # a valid decision reached stdout
        meta = sent['body']['pre_tool_use_data']['metadata']
        self.assertEqual(SERVER, meta.get('mcp_server'))
        self.assertEqual('splunk_run_query', meta.get('mcp_tool'))

    # H2
    def test_post_tool_use_then_stop_through_main_names_the_server(self):
        """Analytics spans two hook invocations: PostToolUse writes the audit
        log, Stop reads it back and sends the turn. Both go through main()."""
        self._write_settings({SERVER: ENTRY})                  # flat shape
        sent = {}

        def _capture(exchange, key):
            sent['exchange'] = exchange

        self._run_main({
            'hook_event_name': 'PostToolUse', 'session_id': 'sess-h2',
            'tool_name': RAW_TOOL, 'tool_input': {'q': 1}, 'is_mcp_tool': True,
            'tool_use_id': 'tu-h2'})
        with patch.object(unbound, 'send_to_api', side_effect=_capture):
            self._run_main({
                'hook_event_name': 'Stop', 'session_id': 'sess-h2',
                'conversation': {'userPrompt': 'run the query',
                                 'agentTextResponse': 'done'}})

        self.assertIn('exchange', sent, 'Stop sent nothing for a turn that made an MCP call')
        self.assertIn('mcp__%s__splunk_run_query' % SERVER, self._tool_names(sent['exchange']))

    # H3
    def test_a_deny_survives_a_hostile_config(self):
        """An allow and main()'s blanket-except fallback emit the SAME output,
        so an allow cannot show whether the hook reached a verdict. A deny can:
        if reading the config ever raised out of process_pre_tool_use, main()
        would emit its fallback and the deny would be dropped -- the tool runs
        with nothing reported. A hostile settings file must not open that."""
        path = self.home / '.augment' / 'settings.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            'augment': {'advanced': {'mcpServers': 'not-a-dict'}},
            'x': {'command': None}, 'y': {'url': 12345}, 'z': 'plain'}),
            encoding='utf-8')
        with patch.object(unbound, 'send_to_hook_api',
                          return_value={'decision': 'deny', 'reason': 'blocked by policy'}):
            out = self._run_main({
                'hook_event_name': 'PreToolUse', 'session_id': 'sess-h3',
                'tool_name': RAW_TOOL, 'tool_input': {'q': 1}, 'is_mcp_tool': True})
        hso = self._decision(out).get('hookSpecificOutput') or {}
        self.assertEqual('deny', hso.get('permissionDecision'),
                         'the deny was dropped: the hook fell back instead of blocking')

if __name__ == '__main__':
    unittest.main()
