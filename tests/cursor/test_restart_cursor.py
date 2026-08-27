"""On Windows, restart_cursor must never make the shell resolve a bare name.

`start cursor` from an elevated or SYSTEM shell cannot find Cursor's per-user launcher,
so ShellExecute raises a "Windows cannot find 'cursor'" dialog. Resolving the path
ourselves fixes that, but the MDM script runs elevated, so it must resolve only to
machine-wide roots: a per-user path there would run a planted binary as SYSTEM.
"""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import REPO


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MDM = _load("cursor_mdm_setup", "cursor/mdm/setup.py")
USER = _load("cursor_user_setup", "cursor/setup.py")
BOTH = [MDM, USER]


class TestWindowsRestart(unittest.TestCase):
    def test_launches_the_resolved_exe_never_a_bare_name(self):
        exe = r"C:\Program Files\cursor\Cursor.exe"
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


class TestElevatedLookupIsMachineWideOnly(unittest.TestCase):
    """A user-writable path launched by the elevated MDM script is a privilege escalation."""

    def test_mdm_never_probes_a_per_user_path(self):
        probed = []

        def record(self):
            probed.append(str(self))
            return False

        with patch.object(Path, "is_file", record), \
             patch.dict(os.environ, {"SystemDrive": "C:"}, clear=True):
            self.assertIsNone(MDM.find_cursor_exe())

        self.assertTrue(probed, "expected at least one candidate")
        for candidate in probed:
            self.assertNotIn("AppData", candidate)
            self.assertNotIn("Users", candidate)

    def test_mdm_accepts_a_machine_wide_install(self):
        with patch.dict(os.environ, {"SystemDrive": "C:"}, clear=True), \
             patch.object(Path, "is_file", lambda self: "Program Files" in str(self)):
            self.assertIn("Program Files", MDM.find_cursor_exe())

    def test_user_level_may_use_localappdata(self):
        """No privilege boundary is crossed when the script runs as the user who owns that path."""
        with patch.dict(os.environ, {"LOCALAPPDATA": r"C:\Users\alice\AppData\Local"}, clear=True), \
             patch.object(Path, "is_file", lambda self: "AppData" in str(self)):
            self.assertIn("AppData", USER.find_cursor_exe())


class TestSetupDoesNotDependOnCursorBeingInstalled(unittest.TestCase):
    """Hooks live in the machine-wide enterprise dir, so they enforce whenever Cursor arrives."""

    def test_hooks_install_with_no_cursor_on_the_machine(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        enterprise = Path(tmp.name) / "ProgramData" / "Cursor"

        def fake_download(url, dest):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text('{"version":1,"hooks":{"preToolUse":[{"command":"./hooks/unbound.py"}]}}')
            return True

        with patch.object(MDM, "get_enterprise_hooks_dir", return_value=enterprise), \
             patch.object(MDM, "download_file", side_effect=fake_download), \
             patch.object(MDM.platform, "system", return_value="Windows"), \
             patch.object(MDM, "find_cursor_exe", return_value=None):
            success, _ = MDM.setup_hooks()

        self.assertTrue(success)
        self.assertTrue((enterprise / "hooks.json").is_file())
        self.assertTrue((enterprise / "hooks" / "unbound.py").is_file())

    def test_a_failed_restart_cannot_fail_the_run(self):
        """Callers invoke restart_cursor() bare. Guard against someone wiring it into a return."""
        for relpath in ("cursor/setup.py", "cursor/mdm/setup.py"):
            with self.subTest(path=relpath):
                for line in (REPO / relpath).read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if "restart_cursor()" in stripped and not stripped.startswith("def "):
                        self.assertEqual(stripped, "restart_cursor()")


if __name__ == "__main__":
    unittest.main()
