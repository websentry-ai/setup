"""Every user-level installer, run on Windows, also runs itself inside the user's WSL distros."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import load_module

INSTALLERS = [
    "augment/hooks/setup.py", "claude-code/gateway/setup.py", "claude-code/hooks/setup.py",
    "codex/gateway/setup.py", "codex/hooks/setup.py", "copilot/hooks/setup.py", "cursor/setup.py",
    "gemini-cli/gateway/setup.py", "pi/setup.py",
]


class TestSetupWsl(unittest.TestCase):
    def _run(self, mod, argv, system="Windows", codes=None, distros=("Ubuntu", "Debian"),
             release="10", py="/mnt/c/Windows/py.exe"):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            code = (codes or {}).get(cmd[2], 0)
            out = b"execvpe(python3) failed" if code == 1 else b"boom\n" if code == 2 else b""
            return subprocess.CompletedProcess(cmd, code, out, b"")

        with mock.patch.object(mod.platform, "system", return_value=system), \
                mock.patch.object(mod.platform, "release", return_value=release), \
                mock.patch.object(mod.shutil, "which", lambda name, path=None: py if name == "py.exe" else None), \
                mock.patch.dict(mod.os.environ, {"SystemRoot": "C:\\Windows"}), \
                mock.patch.object(mod.Path, "is_file", lambda p: p.name == "wsl.exe" and p.parent.name == "System32"), \
                mock.patch.object(mod, "_wsl_distros", return_value=list(distros)), \
                mock.patch.object(mod.subprocess, "run", side_effect=fake_run), \
                mock.patch("builtins.print") as printed:
            mod.setup_wsl(argv)
        return calls, [c.args[0] for c in printed.call_args_list]

    def test_each_installer_reruns_itself_in_every_distro(self):
        for path in INSTALLERS:
            with self.subTest(path):
                mod = load_module(path)
                calls, lines = self._run(mod, ["--api-key", "k", "--config-dir", "C:\\x", "--backfill"])
                self.assertEqual([c[:6] for c, _ in calls],
                                 [[str(mod.Path("C:\\Windows") / "System32" / "wsl.exe"), "-d", d, "--exec", "python3", "-"]
                                  for d in ("Ubuntu", "Debian")])
                self.assertEqual(calls[0][0][6:], ["--backfill"])
                self.assertEqual(calls[0][1]["input"],
                                 b"import sys; sys.argv[1:1] = ['--api-key', 'k']\n" + open(mod.__file__, "rb").read())
                self.assertEqual(lines, ["WSL Ubuntu: done", "WSL Debian: done"])

    def test_each_installer_in_wsl_reruns_itself_on_windows(self):
        for path in INSTALLERS:
            with self.subTest(path):
                mod = load_module(path)
                calls, lines = self._run(mod, ["--api-key", "k", "--config-dir", "/home/u/.claude", "--backfill"],
                                         system="Linux", release="5.15.167.4-microsoft-standard-WSL2", codes={"-X": 3})
                self.assertEqual([c for c, _ in calls], [["/mnt/c/Windows/py.exe", "-3", "-X", "utf8", "-", "--backfill"]])
                self.assertEqual(calls[0][1]["input"],
                                 b"import sys; sys.argv[1:1] = ['--api-key', 'k']\n" + open(mod.__file__, "rb").read())
                self.assertEqual(lines, ["Windows: managed by MDM"])

    def test_wsl_without_windows_python_says_so(self):
        calls, lines = self._run(load_module("cursor/setup.py"), ["--api-key", "k"], system="Linux",
                                 release="4.4.0-19041-Microsoft", py=None)
        self.assertEqual((calls, lines), ([], ["Windows: skipped, py.exe not found"]))

    def test_wsl_finds_py_exe_only_on_windows_drives(self):
        mod = load_module("cursor/setup.py")
        launcher = "/mnt/c/Users/u/AppData/Local/Programs/Python/Launcher"
        searched = []
        path = os.pathsep.join(["/home/u/proj/.venv/bin", "/usr/bin", "/mnt/wsl/x", launcher, "/mnt/c/WINDOWS"])
        with mock.patch.dict(mod.os.environ, {"PATH": path}), \
                mock.patch.object(mod.platform, "system", return_value="Linux"), \
                mock.patch.object(mod.platform, "release", return_value="5.15.167.4-microsoft-standard-WSL2"), \
                mock.patch.object(mod.os.path, "isfile", return_value=False), \
                mock.patch.object(mod.shutil, "which", lambda name, path=None: searched.append(path)), \
                mock.patch.object(mod.subprocess, "run") as run, mock.patch("builtins.print"):
            mod.setup_wsl(["--api-key", "k"])
        self.assertEqual(searched, [os.pathsep.join([launcher, "/mnt/c/WINDOWS"])])
        run.assert_not_called()

    def test_wsl_prefers_the_all_users_launcher(self):
        mod = load_module("cursor/setup.py")
        with mock.patch.object(mod.os.path, "isfile", lambda p: p == "/mnt/c/Windows/py.exe"):
            calls, _ = self._run(mod, ["--api-key", "k"], system="Linux",
                                 release="5.15.167.4-microsoft-standard-WSL2", py="/home/u/.venv/bin/py.exe")
        self.assertEqual(calls[0][0][0], "/mnt/c/Windows/py.exe")

    def test_plain_linux_does_nothing(self):
        mod = load_module("cursor/setup.py")
        self.assertEqual(self._run(mod, ["--api-key", "k"], system="Linux", release="6.8.0-45-generic"), ([], []))

    def test_a_run_fed_on_stdin_never_fans_back_out(self):
        # A planted file named <stdin> in cwd must not be read and run on the other side.
        cwd = tempfile.mkdtemp()
        (Path(cwd) / "<stdin>").write_text("print('planted')\n")
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(cwd)
        for system, release in (("Windows", "10"), ("Linux", "5.15.167.4-microsoft-standard-WSL2")):
            with self.subTest(system):
                mod = load_module("codex/hooks/setup.py")
                with mock.patch.object(mod, "__file__", "<stdin>"):
                    self.assertEqual(self._run(mod, ["--api-key", "k"], system=system, release=release), ([], []))

    def test_main_runs_the_wsl_step_first(self):
        for path in INSTALLERS:
            with self.subTest(path):
                mod = load_module(path)
                with mock.patch.object(mod, "setup_wsl", side_effect=RuntimeError("wsl step")), \
                        mock.patch.object(mod.sys, "argv", ["setup.py", "--api-key", "k"]):
                    with self.assertRaisesRegex(RuntimeError, "wsl step"):
                        mod.main()

    def test_no_wsl_exe_in_system_dir_does_nothing(self):
        mod = load_module("cursor/setup.py")
        with mock.patch.object(mod.platform, "system", return_value="Windows"), \
                mock.patch.object(mod.Path, "is_file", lambda p: False), \
                mock.patch.object(mod, "_wsl_distros", return_value=["Ubuntu"]), \
                mock.patch.object(mod.subprocess, "run") as run:
            mod.setup_wsl(["--api-key", "k"])
        run.assert_not_called()

    def test_clear_reaches_wsl_too(self):
        calls, _ = self._run(load_module("cursor/setup.py"), ["--clear"])
        self.assertEqual(calls[0][0][6:], ["--clear"])
        self.assertEqual(calls[0][1]["input"], open(load_module("cursor/setup.py").__file__, "rb").read())

    def test_key_reaches_wsl_on_stdin_not_argv(self):
        mod = load_module("codex/hooks/setup.py")
        calls, _ = self._run(mod, ["--api-key", "s3cr'et\n", "--domain", "https://x"], distros=("Ubuntu",))
        self.assertNotIn("s3cr'et\n", " ".join(calls[0][0]))
        header = calls[0][1]["input"].split(b"\n", 1)[0] + b"\nprint(repr(sys.argv))\n"
        out = subprocess.run([sys.executable, "-", "--domain", "https://x"], input=header, capture_output=True).stdout
        self.assertEqual(out.decode().strip(), repr(["-", "--api-key", "s3cr'et\n", "--domain", "https://x"]))

    def test_equals_form_api_key_reaches_wsl_on_stdin(self):
        mod = load_module("claude-code/gateway/setup.py")
        calls, _ = self._run(mod, ["--api-key=k", "--gateway-url", "https://g"], distros=("Ubuntu",))
        self.assertEqual(calls[0][0][6:], ["--gateway-url", "https://g"])
        self.assertTrue(calls[0][1]["input"].startswith(b"import sys; sys.argv[1:1] = ['--api-key', 'k']\n"))

    def test_off_windows_or_without_a_key_does_nothing(self):
        mod = load_module("codex/hooks/setup.py")
        self.assertEqual(self._run(mod, ["--api-key", "k"], system="Linux")[0], [])
        self.assertEqual(self._run(mod, ["--domain", "https://x"])[0], [])

    def test_reports_mdm_missing_python_and_failures_without_raising(self):
        mod = load_module("claude-code/hooks/setup.py")
        _, lines = self._run(mod, ["--api-key", "k"], codes={"A": 3, "B": 1, "C": 2}, distros=("A", "B", "C"))
        self.assertEqual(lines, ["WSL A: managed by MDM", "WSL B: skipped, python3 not installed",
                                 "WSL C: failed (exit 2): boom"])
        with mock.patch.object(mod.platform, "system", return_value="Windows"), \
                mock.patch.object(mod.Path, "is_file", lambda p: True), \
                mock.patch.object(mod, "_wsl_distros", return_value=["A"]), \
                mock.patch.object(mod.subprocess, "run", side_effect=subprocess.TimeoutExpired("wsl", 900)), \
                mock.patch("builtins.print") as printed:
            mod.setup_wsl(["--api-key", "k"])
        printed.assert_called_once_with("WSL A: failed (TimeoutExpired)")


if __name__ == "__main__":
    unittest.main()
