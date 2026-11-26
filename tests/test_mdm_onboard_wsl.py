"""mdm/onboard.py on Windows: a logon task sets up each user's WSL distros as that user."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import load_module

onboard = load_module("mdm/onboard.py")
RECORDER = "import json, os\ndef setup_wsl(args):\n    open(os.environ['REC'], 'a').write(json.dumps([__name__, args]) + '\\n')\n"


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home, self.stage = self.tmp / "home", self.tmp / "stage"
        (self.home / ".unbound").mkdir(parents=True)
        self.stage.mkdir()
        (self.stage / "run.py").write_text(onboard.WSL_RUNNER)
        self.rec = self.tmp / "rec.jsonl"

    def _run(self, config):
        if config is not None:
            (self.home / ".unbound" / "config.json").write_text(json.dumps(config))
        env = {**os.environ, "HOME": str(self.home), "USERPROFILE": str(self.home),
               "LOCALAPPDATA": str(self.tmp / "local"), "REC": str(self.rec)}
        subprocess.run([sys.executable, "-I", str(self.stage / "run.py")], env=env, check=True, timeout=60)
        calls = [json.loads(line) for line in self.rec.read_text().splitlines()] if self.rec.exists() else []
        return calls, (self.tmp / "local" / "Unbound" / "wsl_setup.log").read_text()

    def test_runs_each_staged_installer_with_the_users_key_and_urls(self):
        for name in ("cursor-setup.py", "claude-code-hooks-setup.py"):
            (self.stage / name).write_text(RECORDER)
        calls, _ = self._run({"device_token": "K", "base_url": "https://b", "gateway_url": "https://g",
                              "frontend_url": "https://f"})
        self.assertEqual([c[0] for c in calls], ["claude_code_hooks_setup", "cursor_setup"])
        self.assertEqual(calls[0][1], ["--api-key", "K", "--backend-url", "https://b", "--gateway-url", "https://g",
                                       "--domain", "https://f"])

    def test_no_key_runs_nothing(self):
        (self.stage / "cursor-setup.py").write_text(RECORDER)
        calls, log = self._run(None)
        self.assertEqual(calls, [])
        self.assertIn("no key", log)

    def test_one_broken_installer_does_not_stop_the_rest(self):
        (self.stage / "a-setup.py").write_text("raise RuntimeError('boom')\n")
        (self.stage / "b-setup.py").write_text(RECORDER)
        calls, log = self._run({"api_key": "K"})
        self.assertEqual(calls, [["b_setup", ["--api-key", "K"]]])
        self.assertIn("boom", log)


class TestInstall(unittest.TestCase):
    def setUp(self):
        self.pf = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, {"ProgramFiles": str(self.pf)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_stages_user_level_installers_and_registers_the_users_logon_task(self):
        urls = [f"{onboard._RAW_SETUP}/claude-code/hooks/mdm/setup.py", f"{onboard._RAW_SETUP}/cursor/mdm/setup.py"]
        with mock.patch.object(onboard, "_all_users_pythonw", return_value=Path(r"C:\PF\Python\pythonw.exe")), \
                mock.patch.object(onboard, "fetch_script", side_effect=lambda url: f"URL = {url!r}\n".encode()) as fetch, \
                mock.patch.object(onboard, "_powershell", return_value=True) as ps:
            self.assertTrue(onboard.install_wsl_logon_task(urls))
        self.assertEqual([c.args[0] for c in fetch.call_args_list],
                         [u.replace("/mdm/setup.py", "/setup.py") for u in urls])
        stage = self.pf / "Unbound WSL"
        self.assertEqual(sorted(p.name for p in stage.iterdir()),
                         ["claude-code-hooks-setup.py", "cursor-setup.py", "run.py"])
        script, env = ps.call_args.args
        self.assertIn("-GroupId 'S-1-5-32-545'", script)
        self.assertIn("-AtLogOn", script)
        self.assertIn("-MultipleInstances Parallel", script)
        self.assertEqual(env["UNB_ARGS"], f'-I "{stage / "run.py"}"')
        self.assertEqual(env["UNB_TASK"], "Unbound WSL Setup")

    def test_a_failed_tool_keeps_its_staged_installer_and_the_rest_still_stage(self):
        stage = self.pf / "Unbound WSL"
        stage.mkdir()
        (stage / "cursor-setup.py").write_text("GOOD = 1\n")
        bad = {"cursor/setup.py": RuntimeError("offline"), "codex/hooks/setup.py": b"def broken(:\n"}

        def fetch(url):
            result = next((v for k, v in bad.items() if url.endswith(k)), b"OK = 1\n")
            if isinstance(result, Exception):
                raise result
            return result
        urls = [f"{onboard._RAW_SETUP}/{t}/mdm/setup.py" for t in ("cursor", "codex/hooks", "augment/hooks")]
        with mock.patch.object(onboard, "_all_users_pythonw", return_value=Path("pythonw.exe")), \
                mock.patch.object(onboard, "fetch_script", side_effect=fetch), \
                mock.patch.object(onboard, "_powershell", return_value=True) as ps, \
                mock.patch("builtins.print"):
            self.assertTrue(onboard.install_wsl_logon_task(urls))
        self.assertEqual((stage / "cursor-setup.py").read_text(), "GOOD = 1\n")
        self.assertFalse((stage / "codex-hooks-setup.py").exists())
        self.assertEqual((stage / "augment-hooks-setup.py").read_text(), "OK = 1\n")
        ps.assert_called_once()

    def test_a_failed_write_keeps_the_staged_installer(self):
        stage = self.pf / "Unbound WSL"
        stage.mkdir()
        (stage / "cursor-setup.py").write_text("GOOD = 1\n")
        real = Path.write_bytes

        def disk_full(path, data):
            if path.suffix == ".tmp":
                real(path, data[:3])
                raise OSError("disk full")
            return real(path, data)
        with mock.patch.object(onboard, "_all_users_pythonw", return_value=Path("pythonw.exe")), \
                mock.patch.object(onboard, "fetch_script", return_value=b"NEW = 1\n"), \
                mock.patch.object(onboard.Path, "write_bytes", disk_full), \
                mock.patch.object(onboard, "_powershell", return_value=True), \
                mock.patch("builtins.print"):
            onboard.install_wsl_logon_task([f"{onboard._RAW_SETUP}/cursor/mdm/setup.py"])
        self.assertEqual((stage / "cursor-setup.py").read_text(), "GOOD = 1\n")
        self.assertEqual(sorted(p.name for p in stage.glob("*-setup.py")), ["cursor-setup.py"])

    def test_python_users_could_replace_is_refused(self):
        with mock.patch.object(onboard, "_all_users_pythonw", return_value=None), \
                mock.patch.object(onboard, "_powershell") as ps:
            self.assertFalse(onboard.install_wsl_logon_task(["x"]))
        ps.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Windows paths")
    def test_only_a_program_files_python_is_trusted(self):
        with mock.patch.object(onboard.sys, "executable", str(self.pf / "Python" / "python.exe")):
            (self.pf / "Python").mkdir()
            (self.pf / "Python" / "pythonw.exe").write_bytes(b"")
            self.assertEqual(onboard._all_users_pythonw(), self.pf / "Python" / "pythonw.exe")
        with mock.patch.object(onboard.sys, "executable", str(Path.home() / "AppData" / "python.exe")):
            self.assertIsNone(onboard._all_users_pythonw())


class TestMain(unittest.TestCase):
    def _main(self, argv, system="Windows", failing=()):
        with mock.patch.object(onboard.platform, "system", return_value=system), \
                mock.patch.object(onboard, "check_admin_privileges", return_value=True), \
                mock.patch.object(onboard, "run_tool", side_effect=lambda name, url, args: name not in failing), \
                mock.patch.object(onboard, "should_install_pi", return_value=False), \
                mock.patch.object(onboard, "fetch_device_owner_key", return_value=None), \
                mock.patch.object(onboard, "install_wsl_logon_task", return_value=True) as install, \
                mock.patch.object(onboard, "remove_wsl_logon_task", return_value=True) as remove, \
                mock.patch.object(onboard.sys, "argv", ["onboard.py", *argv]), \
                mock.patch("builtins.print"):
            onboard.main()
        return install, remove

    def test_windows_install_covers_only_the_tools_that_installed(self):
        install, remove = self._main(["--api-key", "k"], failing=("Cursor",))
        urls = install.call_args.args[0]
        self.assertEqual(len(urls), len(onboard.TOOLS) - 1)
        self.assertFalse(any("/cursor/" in u for u in urls))
        remove.assert_not_called()

    def test_windows_clear_removes_the_task(self):
        install, remove = self._main(["--clear"])
        remove.assert_called_once()
        install.assert_not_called()

    def test_other_platforms_untouched(self):
        install, remove = self._main(["--api-key", "k"], system="Darwin")
        install.assert_not_called()
        remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
