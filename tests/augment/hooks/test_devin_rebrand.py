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


def _write_mcp(home: Path, editor: str, server: str, url: str):
    """Seed Augment's VS Code-side MCP config under one editor's data dir."""
    if sys.platform == 'darwin':
        base = home / 'Library' / 'Application Support'
    elif sys.platform == 'win32':
        base = home / 'AppData' / 'Roaming'
    else:
        base = home / '.config'
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

    def test_a_server_configured_in_devin_is_found(self):
        _write_mcp(self.home, 'Devin', 'gdrive', 'https://example.test/gdrive')
        servers = unbound.read_augment_mcp_servers({})
        self.assertIn('gdrive', servers)
        self.assertEqual('https://example.test/gdrive', servers['gdrive']['url'])

    def test_the_pre_rebrand_directory_still_works(self):
        _write_mcp(self.home, 'Windsurf', 'gdrive', 'https://example.test/old')
        servers = unbound.read_augment_mcp_servers({})
        self.assertEqual('https://example.test/old', servers['gdrive']['url'])

    def test_a_migrated_machine_uses_the_live_directory(self):
        """Both survive the upgrade; the editor reads the renamed one."""
        _write_mcp(self.home, 'Windsurf', 'gdrive', 'https://example.test/old')
        _write_mcp(self.home, 'Devin', 'gdrive', 'https://example.test/new')
        servers = unbound.read_augment_mcp_servers({})
        self.assertEqual('https://example.test/new', servers['gdrive']['url'])

    def test_nothing_configured_is_not_an_error(self):
        self.assertEqual({}, unbound.read_augment_mcp_servers({}))


if __name__ == '__main__':
    unittest.main()
