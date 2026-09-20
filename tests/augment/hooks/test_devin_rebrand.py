"""Augment running inside Devin must still resolve its MCP config.

Windsurf ships as Devin Desktop, which renamed the editor's user-data directory.
The hook recovers the real server behind a munged tool name by reading that
directory, so an unlisted one means the gateway cannot fingerprint the server:
no policy match, no analytics -- and nothing in the logs to say so.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from augment.hooks import unbound  # noqa: E402


def _write_mcp(editor: str, server: str, url: str):
    """Seed Augment's VS Code-side MCP config under one editor's data dir.

    The base comes from the hook itself -- restating its platform rules here is
    how this missed that CI sets XDG_CONFIG_HOME and the paths diverged.
    """
    base = unbound._vscode_user_dirs()[0].parent.parent
    path = (base / editor / 'User' / 'globalStorage' / 'augment.vscode-augment'
            / 'augment-global-state' / 'mcpServers.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([{"name": server, "url": url}]), encoding='utf-8')


class AugmentInsideDevin(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        patcher = patch.object(unbound.Path, 'home', return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)
        # The hook prefers these over the home directory when they are set, and on
        # a developer machine or CI they are -- without this the fixtures land
        # outside the temp home, where the tests leak into each other.
        env = patch.dict('os.environ', {
            'APPDATA': str(self.home / 'AppData' / 'Roaming'),
            'XDG_CONFIG_HOME': str(self.home / '.config'),
        })
        env.start()
        self.addCleanup(env.stop)

    def test_a_server_configured_in_devin_is_found(self):
        _write_mcp('Devin', 'gdrive', 'https://example.test/gdrive')
        servers = unbound.read_augment_mcp_servers({})
        self.assertIn('gdrive', servers)
        self.assertEqual('https://example.test/gdrive', servers['gdrive']['url'])

    def test_the_pre_rebrand_directory_still_works(self):
        _write_mcp('Windsurf', 'gdrive', 'https://example.test/old')
        servers = unbound.read_augment_mcp_servers({})
        self.assertEqual('https://example.test/old', servers['gdrive']['url'])

    def test_a_migrated_machine_uses_the_live_directory(self):
        """Both survive the upgrade; the editor reads the renamed one."""
        _write_mcp('Windsurf', 'gdrive', 'https://example.test/old')
        _write_mcp('Devin', 'gdrive', 'https://example.test/new')
        servers = unbound.read_augment_mcp_servers({})
        self.assertEqual('https://example.test/new', servers['gdrive']['url'])

    def test_nothing_configured_is_not_an_error(self):
        self.assertEqual({}, unbound.read_augment_mcp_servers({}))


if __name__ == '__main__':
    unittest.main()
