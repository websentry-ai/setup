"""Windows MDM sets up WSL through a per-user logon task; every user's logon runs its interpreter."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import load_module

mdm = load_module("claude-code/hooks/mdm/setup.py")


class TestTrustedLauncher(unittest.TestCase):
    def _launcher(self, executable, env):
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(mdm.sys, "executable", executable), \
                mock.patch.object(mdm.Path, "is_file", return_value=True):
            return mdm._trusted_windows_launcher()

    def test_accepts_all_users_python_under_program_files(self):
        self.assertEqual(self._launcher("/pf/Python313/python.exe", {"ProgramFiles": "/pf"}),
                         str(Path("/pf/Python313/pythonw.exe")))

    def test_rejects_python_in_user_writable_folder(self):
        self.assertIsNone(self._launcher("/python312/python.exe", {"ProgramFiles": "/pf"}))

    def test_rejects_sibling_folder_sharing_a_prefix(self):
        self.assertIsNone(self._launcher("/pfx/Python313/python.exe", {"ProgramFiles": "/pf"}))

    def test_rejects_system_root_and_missing_env(self):
        self.assertIsNone(self._launcher("/win/temp/python.exe", {"SystemRoot": "/win"}))


class TestInstallTask(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.managed = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _install(self, body, ps_result=None):
        def fake_download(url, dest, gateway_url=None):
            self.assertEqual(url, mdm.WSL_SETUP_URL)
            dest.write_bytes(body)
            return True
        done = ps_result or subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(mdm, "_trusted_windows_launcher", return_value="/pf/Python313/pythonw.exe"), \
                mock.patch.object(mdm, "get_managed_settings_dir", return_value=self.managed), \
                mock.patch.object(mdm, "download_file", side_effect=fake_download), \
                mock.patch.object(mdm, "_run_powershell", return_value=done) as ps:
            mdm.install_wsl_logon_task()
        return ps

    def test_no_trusted_launcher_registers_nothing(self):
        with mock.patch.object(mdm, "_trusted_windows_launcher", return_value=None), \
                mock.patch.object(mdm, "download_file") as dl, mock.patch.object(mdm, "_run_powershell") as ps:
            mdm.install_wsl_logon_task()
        dl.assert_not_called()
        ps.assert_not_called()

    def test_paths_reach_powershell_as_env_not_script_text(self):
        ps = self._install(b"print('ok')\n")
        script, env = ps.call_args.args
        self.assertNotIn(str(self.managed), script)
        self.assertEqual(env["UNBOUND_TASK_EXE"], "/pf/Python313/pythonw.exe")
        self.assertEqual(env["UNBOUND_TASK_ARGS"], '-I "%s" --wsl' % (self.managed / "wsl_setup.py"))
        self.assertIn("S-1-5-32-545", script)
        self.assertIn("-RunLevel Limited", script)

    def test_truncated_download_registers_nothing(self):
        self.assertFalse(self._install(b"def broken(:\n").called)

    def test_failed_download_registers_nothing(self):
        with mock.patch.object(mdm, "_trusted_windows_launcher", return_value="/pf/Python313/pythonw.exe"), \
                mock.patch.object(mdm, "get_managed_settings_dir", return_value=self.managed), \
                mock.patch.object(mdm, "download_file", return_value=False), \
                mock.patch.object(mdm, "_run_powershell") as ps:
            mdm.install_wsl_logon_task()
        ps.assert_not_called()

    def test_powershell_timeout_or_absence_never_aborts_setup(self):
        for exc in (subprocess.TimeoutExpired("powershell", 120), FileNotFoundError("powershell")):
            with mock.patch.object(mdm.subprocess, "run", side_effect=exc), \
                    mock.patch.object(mdm, "get_managed_settings_dir", return_value=self.managed):
                self.assertEqual(mdm._run_powershell("x", {}).returncode, 1)
                mdm.remove_wsl_logon_task()
        self._install(b"print('ok')\n", ps_result=subprocess.CompletedProcess([], 1, "", "timed out"))


if __name__ == "__main__":
    unittest.main()
