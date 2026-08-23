"""Runtime path resolution in unbound.py, checked against what Claude Code does.

Every constant here is a path Claude Code also computes. If the two disagree the
hook reads or writes somewhere Claude never looks, which fails silently — so
these assertions mirror the resolver in the shipped Claude Code bundle.
"""

import importlib
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


def _reload(**env):
    """Reload unbound with `env` applied, since the paths resolve at import."""
    base = {k: v for k, v in os.environ.items()
            if k not in ('CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_PLUGIN_CACHE_DIR')}
    base.update({k: v for k, v in env.items() if v is not None})
    with patch.dict(os.environ, base, clear=True):
        return importlib.reload(unbound)


class TestConfigDirResolution(unittest.TestCase):
    def tearDown(self):
        _reload()  # leave the module as the rest of the suite expects it

    def test_default_when_env_unset(self):
        m = _reload(HOME='/home/jane')
        self.assertEqual(m._CONFIG_DIR, Path('/home/jane/.claude'))

    def test_relocated_when_env_set(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc')
        self.assertEqual(m._CONFIG_DIR, Path('/opt/cc'))

    def test_leading_tilde_is_not_expanded(self):
        # Claude Code reads the value verbatim and makes a literal "~" directory.
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='~/cc')
        self.assertNotEqual(m._CONFIG_DIR, Path('/home/jane/cc'))
        self.assertEqual(m._CONFIG_DIR, Path(os.path.abspath('~/cc')))

    def test_blank_env_falls_back_to_home(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='   ')
        self.assertEqual(m._CONFIG_DIR, Path('/home/jane/.claude'))

    def test_enforcement_paths_follow_the_relocated_dir(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc')
        self.assertEqual(m.AUDIT_LOG, Path('/opt/cc/hooks/agent-audit.log'))
        self.assertEqual(m.POLICY_CACHE_FILE, Path('/opt/cc/hooks/.policy_cache.json'))
        self.assertEqual(m.SELF_SCRIPT_PATH, Path('/opt/cc/hooks/unbound.py'))
        self.assertEqual(m.CLAUDE_SKILLS_ROOT, Path('/opt/cc/skills'))


class TestClaudeJsonLocation(unittest.TestCase):
    """Claude resolves it as (CLAUDE_CONFIG_DIR or homedir) + '/.claude.json' —
    beside the config dir when relocated, never nested under ~/.claude."""

    def tearDown(self):
        _reload()

    def test_sits_in_home_not_under_dot_claude_by_default(self):
        m = _reload(HOME='/home/jane')
        self.assertEqual(m.CLAUDE_MCP_CONFIG_PATH, Path('/home/jane/.claude.json'))

    def test_moves_into_the_relocated_dir(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc')
        self.assertEqual(m.CLAUDE_MCP_CONFIG_PATH, Path('/opt/cc/.claude.json'))


class TestPluginCacheDir(unittest.TestCase):
    def tearDown(self):
        _reload()

    def test_defaults_under_the_config_dir(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc')
        self.assertEqual(m.CLAUDE_PLUGIN_CACHE_DIR, Path('/opt/cc/plugins/cache'))

    def test_env_override_wins_over_the_config_dir(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc',
                    CLAUDE_CODE_PLUGIN_CACHE_DIR='/var/pcache')
        self.assertEqual(m.CLAUDE_PLUGIN_CACHE_DIR, Path('/var/pcache/cache'))

    def test_blank_override_is_ignored(self):
        m = _reload(HOME='/home/jane', CLAUDE_CONFIG_DIR='/opt/cc',
                    CLAUDE_CODE_PLUGIN_CACHE_DIR='  ')
        self.assertEqual(m.CLAUDE_PLUGIN_CACHE_DIR, Path('/opt/cc/plugins/cache'))


if __name__ == '__main__':
    unittest.main()
