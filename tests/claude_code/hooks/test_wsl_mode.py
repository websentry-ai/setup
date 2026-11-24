"""`setup.py --wsl`: from Windows, set up each of the user's WSL distros that lacks our hooks."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import load_module

setup = load_module("claude-code/hooks/setup.py")


class TestRunInWsl(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        (self.home / ".unbound").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, config, distros, probe_codes):
        if config is not None:
            (self.home / ".unbound" / "config.json").write_text(json.dumps(config))
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if cmd[4] == "sh":
                return subprocess.CompletedProcess(cmd, probe_codes[cmd[2]])
            return subprocess.CompletedProcess(cmd, 0)

        with mock.patch.object(setup.platform, "system", return_value="Windows"), \
                mock.patch.object(setup.Path, "home", return_value=self.home), \
                mock.patch.object(setup, "_wsl_distros", return_value=distros), \
                mock.patch.object(setup.subprocess, "run", side_effect=fake_run):
            ok = setup.run_in_wsl()
        return ok, calls

    def test_off_windows_refuses(self):
        with mock.patch.object(setup.platform, "system", return_value="Linux"):
            self.assertFalse(setup.run_in_wsl())

    def test_installs_only_where_hooks_are_missing(self):
        cfg = {"device_token": "dev-key", "base_url": "https://b.example", "gateway_url": "https://g.example"}
        ok, calls = self._run(cfg, ["Ubuntu", "Debian"], {"Ubuntu": 0, "Debian": 1})
        self.assertTrue(ok)
        installs = [c for c, _ in calls if c[4] == "python3"]
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0][:6], ["wsl.exe", "-d", "Debian", "--exec", "python3", "-"])
        self.assertEqual(installs[0][6:], ["--api-key", "dev-key", "--backend-url", "https://b.example",
                                           "--gateway-url", "https://g.example"])

    def test_probe_counts_either_mode_and_checks_the_key(self):
        self.assertIn("hooks/unbound", setup.WSL_HOOKS_PROBE)
        self.assertIn("anthropic_key", setup.WSL_HOOKS_PROBE)
        self.assertIn('"$1"', setup.WSL_HOOKS_PROBE)
        _, calls = self._run({"api_key": "rotated"}, ["Ubuntu"], {"Ubuntu": 0})
        self.assertEqual(calls[0][0][4:], ["sh", "-c", setup.WSL_HOOKS_PROBE, "sh", "rotated"])

    def test_probe_runs_against_a_real_shell(self):
        home = self.home / "linuxhome"
        (home / ".claude").mkdir(parents=True)
        (home / ".unbound").mkdir()
        (home / ".claude" / "settings.json").write_text('{"command": "python3 ~/.claude/hooks/unbound.py"}')
        (home / ".unbound" / "config.json").write_text('{"api_key": "old"}')
        probe = lambda key: subprocess.run(["sh", "-c", setup.WSL_HOOKS_PROBE, "sh", key],
                                           env={"HOME": str(home), "PATH": os.environ["PATH"]}).returncode
        self.assertEqual(probe("old"), 0)
        self.assertNotIn(probe("new"), (0, 3))

    def test_distro_without_python3_is_skipped_not_failed(self):
        ok, calls = self._run({"api_key": "k"}, ["NoPy"], {"NoPy": 3})
        self.assertTrue(ok)
        self.assertEqual([c for c, _ in calls if c[4] == "python3"], [])

    def test_distro_with_its_own_mdm_install_is_not_a_failure(self):
        (self.home / ".unbound" / "config.json").write_text(json.dumps({"api_key": "k"}))
        with mock.patch.object(setup.platform, "system", return_value="Windows"), \
                mock.patch.object(setup.Path, "home", return_value=self.home), \
                mock.patch.object(setup, "_wsl_distros", return_value=["Ubuntu"]), \
                mock.patch.object(setup.subprocess, "run",
                                  side_effect=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1 if cmd[4] == "sh" else 3)):
            self.assertTrue(setup.run_in_wsl())

    def test_hung_distro_reports_failure(self):
        (self.home / ".unbound" / "config.json").write_text(json.dumps({"api_key": "k"}))
        with mock.patch.object(setup.platform, "system", return_value="Windows"), \
                mock.patch.object(setup.Path, "home", return_value=self.home), \
                mock.patch.object(setup, "_wsl_distros", return_value=["Ubuntu"]), \
                mock.patch.object(setup.subprocess, "run", side_effect=subprocess.TimeoutExpired("wsl", 120)):
            self.assertFalse(setup.run_in_wsl())

    def test_no_key_does_nothing(self):
        ok, calls = self._run({"base_url": "https://b.example"}, ["Ubuntu"], {"Ubuntu": 1})
        self.assertTrue(ok)
        self.assertEqual(calls, [])

    def test_failed_install_reports_failure(self):
        cfg = {"api_key": "k"}
        with mock.patch.object(setup.platform, "system", return_value="Windows"), \
                mock.patch.object(setup.Path, "home", return_value=self.home), \
                mock.patch.object(setup, "_wsl_distros", return_value=["Ubuntu"]), \
                mock.patch.object(setup.subprocess, "run",
                                  side_effect=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1)):
            (self.home / ".unbound" / "config.json").write_text(json.dumps(cfg))
            self.assertFalse(setup.run_in_wsl())


if __name__ == "__main__":
    unittest.main()
