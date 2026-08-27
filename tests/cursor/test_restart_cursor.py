"""On Windows, restart_cursor must never make the shell resolve a bare name.

`start cursor` from an elevated or SYSTEM shell cannot find Cursor's per-user
launcher, so ShellExecute raises a "Windows cannot find 'cursor'" dialog.
"""

import importlib.util
import unittest
from unittest.mock import patch

from tests.conftest import REPO


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BOTH = [_load("cursor_mdm_setup", "cursor/mdm/setup.py"),
        _load("cursor_user_setup", "cursor/setup.py")]


class TestWindowsRestart(unittest.TestCase):
    def test_launches_the_resolved_exe_never_a_bare_name(self):
        exe = r"C:\Users\alice\AppData\Local\Programs\cursor\Cursor.exe"
        for mod in BOTH:
            with self.subTest(module=mod.__name__):
                with patch.object(mod.platform, "system", return_value="Windows"), \
                     patch.object(mod, "find_cursor_exe", return_value=exe), \
                     patch.object(mod.subprocess, "run"), \
                     patch.object(mod.subprocess, "Popen") as popen, \
                     patch.object(mod.time, "sleep"):
                    popen.return_value.poll.return_value = None
                    self.assertTrue(mod.restart_cursor())
                self.assertEqual(popen.call_args[0][0], [exe])
                self.assertNotIn("shell", popen.call_args[1])

    def test_cursor_not_found_prints_a_line_and_kills_nothing(self):
        for mod in BOTH:
            with self.subTest(module=mod.__name__):
                with patch.object(mod.platform, "system", return_value="Windows"), \
                     patch.object(mod, "find_cursor_exe", return_value=None), \
                     patch.object(mod.subprocess, "run") as run, \
                     patch.object(mod.subprocess, "Popen") as popen, \
                     patch("builtins.print") as printed:
                    self.assertFalse(mod.restart_cursor())
                run.assert_not_called()
                popen.assert_not_called()
                self.assertIn("Restart Cursor", [c[0][0] for c in printed.call_args_list if c[0]])

    def test_find_cursor_exe_ignores_the_cmd_shim_on_path(self):
        """`cursor` on PATH is a .cmd, which CreateProcess cannot run without a shell."""
        for mod in BOTH:
            with self.subTest(module=mod.__name__):
                with patch.object(mod.shutil, "which", return_value=None), \
                     patch.object(mod.Path, "is_file", return_value=False):
                    self.assertIsNone(mod.find_cursor_exe())


if __name__ == "__main__":
    unittest.main()
