"""Every Python hook names the shell an agent's terminal command runs in, from one shared block.

The end-to-end tests in test_transfer_e2e.py run each real hook on this machine; these cover the Windows rules, the
VS Code settings Copilot reads, and failing open, on every hook's copy of the block."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import load_module

HOOK_PATHS = [
    'claude-code/hooks/unbound.py',
    'codex/hooks/unbound.py',
    'copilot/hooks/unbound.py',
    'augment/hooks/unbound.py',
    'cursor/unbound.py',
]
HOOKS = [load_module(p) for p in HOOK_PATHS]
REPO_ROOT = Path(__file__).resolve().parents[1]
START = '# KEEP IN SYNC: shell detection'
END = '# --- end shell detection ---'


class TheBlockIsSharedTests(unittest.TestCase):
    def test_the_block_is_byte_identical_in_every_hook(self):
        blocks = set()
        for path in HOOK_PATHS:
            text = (REPO_ROOT / path).read_text(encoding='utf-8')
            self.assertEqual((text.count(START), text.count(END)), (1, 1), path)
            blocks.add(text[text.index(START):text.index(END)])
        self.assertEqual(len(blocks), 1)


class ShellTestCase(unittest.TestCase):
    """A throwaway home, an empty PATH unless a test adds pwsh, and a fresh cache in every hook."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.bin = tempfile.mkdtemp()
        env = {'HOME': self.home, 'USERPROFILE': self.home, 'APPDATA': os.path.join(self.home, 'AppData', 'Roaming'),
               'PATH': self.bin, 'SHELL': '/bin/zsh'}
        patcher = patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        for hook in HOOKS:
            hook._SHELL_CACHE.clear()
            self.addCleanup(hook._SHELL_CACHE.clear)

    def add_pwsh(self):
        pwsh = Path(self.bin, 'pwsh')
        pwsh.write_text('#!/bin/sh\n')
        pwsh.chmod(0o755)

    def each(self, agent, tool=None, cwd=None, windows=False):
        """(hook file, detected) for every hook, as Windows when asked."""
        out = []
        for hook in HOOKS:
            hook._SHELL_CACHE.clear()
            with patch.object(hook, '_shell_windows', return_value=windows):
                out.append((hook.__file__, hook.detect_shell(agent, tool, cwd)))
        return out

    def assert_shell(self, agent, tool, expected, cwd=None, windows=False):
        for path, got in self.each(agent, tool, cwd, windows):
            with self.subTest(hook=path, agent=agent, tool=tool, windows=windows):
                self.assertEqual(got, expected)


def _shell(name, source):
    return {'shell': name, 'shell_source': source}


class WindowsRuleTests(ShellTestCase):
    def test_each_agent_names_powershell_7_when_it_is_installed_and_windows_powershell_when_not(self):
        for has_pwsh, ps in ((False, 'powershell'), (True, 'pwsh')):
            if has_pwsh:
                self.add_pwsh()
            self.assert_shell('codex', 'Bash', _shell(ps, 'agent_rule'), windows=True)
            self.assert_shell('cursor', 'Shell', _shell(ps, 'agent_rule'), windows=True)
            self.assert_shell('claude-code', 'PowerShell', _shell(ps, 'tool'), windows=True)
            self.assert_shell('copilot', 'powershell', _shell(ps, 'tool'), windows=True)

    def test_claude_codes_bash_tool_is_git_bash_on_windows(self):
        self.assert_shell('claude-code', 'Bash', _shell('bash', 'tool'), windows=True)

    def test_copilot_clis_pascal_case_bash_is_powershell_on_windows_and_bash_elsewhere(self):
        self.assert_shell('copilot', 'Bash', _shell('powershell', 'agent_rule'), windows=True)
        self.assert_shell('copilot', 'Bash', _shell('bash', 'agent_rule'))
        self.assert_shell('copilot', 'bash', _shell('bash', 'tool'), windows=True)

    def test_augment_runs_windows_powershell_unless_its_settings_pick_a_shell(self):
        self.assert_shell('augment', 'launch-process', _shell('powershell', 'agent_rule'), windows=True)
        Path(self.home, '.augment').mkdir()
        Path(self.home, '.augment', 'settings.json').write_text(json.dumps({'shellPath': 'C:\\Program Files\\PowerShell\\7\\pwsh.exe'}))
        self.assert_shell('augment', 'launch-process', _shell('pwsh', 'agent_rule'), windows=True)


class VSCodeTests(ShellTestCase):
    def user_settings(self, settings):
        path = Path(os.environ['APPDATA'], 'Code', 'User', 'settings.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(settings)

    def test_an_unset_profile_is_powershell_on_windows_and_the_users_shell_elsewhere(self):
        self.assert_shell('copilot', 'run_in_terminal', _shell('powershell', 'agent_rule'), windows=True)
        self.assert_shell('copilot', 'run_in_terminal', _shell('zsh', 'agent_rule'))

    def test_a_default_profile_by_name_by_path_and_command_prompt_running_as_powershell(self):
        for settings, expected in (
                ({'terminal.integrated.defaultProfile.windows': 'Git Bash'}, 'bash'),
                ({'terminal.integrated.defaultProfile.windows': 'Command Prompt'}, 'powershell'),
                ({'terminal.integrated.defaultProfile.windows': 'Dev',
                  'terminal.integrated.profiles.windows': {'Dev': {'path': ['C:\\tools\\pwsh.exe', 'x']}}}, 'pwsh')):
            self.user_settings(json.dumps(settings))
            self.assert_shell('copilot', 'run_in_terminal', _shell(expected, 'agent_rule'), windows=True)

    def test_copilots_own_profile_and_the_workspace_win_and_comments_are_allowed(self):
        self.user_settings('{\n  // mine\n  "terminal.integrated.defaultProfile.windows": "Command Prompt",\n'
                           '  "chat.tools.terminal.terminalProfile.windows": {"path": "C:\\\\Git\\\\bin\\\\bash.exe"},\n}')
        self.assert_shell('copilot', 'run_in_terminal', _shell('bash', 'agent_rule'), windows=True)
        workspace = tempfile.mkdtemp()
        Path(workspace, '.vscode').mkdir()
        Path(workspace, '.vscode', 'settings.json').write_text(json.dumps(
            {'chat.tools.terminal.terminalProfile.windows': {'path': 'pwsh.exe'}}))
        self.assert_shell('copilot', 'run_in_terminal', _shell('pwsh', 'agent_rule'), cwd=workspace, windows=True)

    def test_unreadable_settings_fall_back_to_the_default(self):
        self.user_settings('{ not json')
        self.assert_shell('copilot', 'run_in_terminal', _shell('powershell', 'agent_rule'), windows=True)


class FailOpenTests(ShellTestCase):
    def test_a_detection_error_or_an_unknown_shell_names_nothing(self):
        for hook in HOOKS:
            with self.subTest(hook=hook.__file__), patch.object(hook, '_shell_detect', side_effect=OSError('boom')):
                hook._SHELL_CACHE.clear()
                self.assertEqual(hook.detect_shell('cursor', 'Shell'), {})
        with patch.dict(os.environ, {'SHELL': '/opt/bin/nu'}):
            for hook in HOOKS:
                with self.subTest(hook=hook.__file__), patch.object(hook, '_shell_login', return_value=None):
                    hook._SHELL_CACHE.clear()
                    self.assertEqual(hook.detect_shell('cursor', 'Shell'), {})

    def test_an_agent_with_no_rule_names_nothing(self):
        self.assert_shell('windsurf', 'Bash', {})


if __name__ == '__main__':
    unittest.main()
