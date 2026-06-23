"""Install-path tests for the Copilot MDM setup (WEB copilot-mdm-install-fix).

Covers the bug where per-user install silently failed and main() still exited 0:
- install_hooks_for_user must write unbound.py + unbound.json into the user's home
  (it runs as the target user; running as the current user is permitted).
- main() must return False (non-zero exit) when no user gets the hook installed,
  so the MDM orchestrator stops reporting a silent failure as success.
"""
import getpass
import importlib.util
import json
import os
import platform
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_spec = importlib.util.spec_from_file_location(
    "_copilot_mdm_setup", os.path.join(os.path.dirname(__file__), "setup.py")
)
mdm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mdm)

_SCRIPT = "#!/usr/bin/env python3\nprint('unbound copilot hook')\n"


class TestInstallHooksForUser(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.me = getpass.getuser()
        # _run_as_user forks + setuid/setgroups (root-only); the install bug lived
        # in the inner write path, so run it directly under the test user while
        # preserving its contract (return None on failure).
        def _direct(_u, fn, *a, **k):
            try:
                return fn(*a, **k)
            except Exception:
                return None

        p = mock.patch.object(mdm, "_run_as_user", _direct)
        p.start()
        self.addCleanup(p.stop)

    def test_writes_script_and_config(self):
        ok = mdm.install_hooks_for_user(self.me, self.home, _SCRIPT)
        self.assertTrue(ok)

        script_path = self.home / ".copilot" / "hooks" / "unbound.py"
        hooks_json = self.home / ".copilot" / "hooks" / "unbound.json"
        self.assertEqual(script_path.read_text(), _SCRIPT)

        config = json.loads(hooks_json.read_text())
        self.assertEqual(config["version"], 1)
        self.assertIn("PreToolUse", config["hooks"])

    @unittest.skipIf(platform.system().lower() == "windows", "POSIX mode bits")
    def test_script_is_executable(self):
        mdm.install_hooks_for_user(self.me, self.home, _SCRIPT)
        script_path = self.home / ".copilot" / "hooks" / "unbound.py"
        self.assertTrue(os.stat(script_path).st_mode & stat.S_IXUSR)

    @unittest.skipIf(platform.system().lower() == "windows", "O_NOFOLLOW is POSIX")
    def test_symlinked_script_path_is_refused(self):
        hooks_dir = self.home / ".copilot" / "hooks"
        hooks_dir.mkdir(parents=True)
        target = Path(tempfile.mkdtemp()) / "evil"
        (hooks_dir / "unbound.py").symlink_to(target)
        ok = mdm.install_hooks_for_user(self.me, self.home, _SCRIPT)
        self.assertFalse(ok)
        self.assertFalse(target.exists())


class TestApplyGatewayUrl(unittest.TestCase):
    def test_rewrites_non_default_url(self):
        text = f'GATEWAY = "{mdm.DEFAULT_GATEWAY_URL}"'
        out = mdm._apply_gateway_url(text, "https://gw.example.com")
        self.assertIn('"https://gw.example.com"', out)
        self.assertNotIn(mdm.DEFAULT_GATEWAY_URL, out)

    def test_default_url_is_unchanged(self):
        text = f'GATEWAY = "{mdm.DEFAULT_GATEWAY_URL}"'
        self.assertEqual(mdm._apply_gateway_url(text, mdm.DEFAULT_GATEWAY_URL), text)


def _patch_main_deps(homes, install_results=True, script_text=_SCRIPT):
    install = (
        mock.Mock(side_effect=install_results)
        if isinstance(install_results, list)
        else mock.Mock(return_value=install_results)
    )
    notify = mock.Mock()
    patches = [
        mock.patch.object(mdm.sys, "argv", ["setup.py", "--api-key", "k"]),
        mock.patch.object(mdm, "check_admin_privileges", return_value=True),
        mock.patch.object(mdm, "get_device_identifier", return_value="dev-1"),
        mock.patch.object(mdm, "fetch_api_key_from_mdm", return_value="api-key"),
        mock.patch.object(mdm, "set_env_var_system_wide", return_value=(True, True)),
        mock.patch.object(mdm, "_fetch_hook_script", return_value=script_text),
        mock.patch.object(mdm, "detect_install_state", return_value="fresh"),
        mock.patch.object(mdm, "get_all_user_homes", return_value=homes),
        mock.patch.object(mdm, "write_unbound_config_for_user"),
        mock.patch.object(mdm, "install_hooks_for_user", install),
        mock.patch.object(mdm, "notify_setup_complete", notify),
    ]
    return patches, install, notify


class TestMainExitSemantics(unittest.TestCase):
    def _run_main(self, homes, install_results=True, script_text=_SCRIPT):
        patches, install, notify = _patch_main_deps(homes, install_results, script_text)
        for p in patches:
            p.start()
        self.addCleanup(mock.patch.stopall)
        return mdm.main(), install, notify

    def test_full_success_returns_true_and_notifies(self):
        result, _, notify = self._run_main([("u1", Path("/tmp/h1"))])
        self.assertTrue(result)
        notify.assert_called_once()

    def test_no_users_returns_false(self):
        result, install, notify = self._run_main([])
        self.assertFalse(result)
        install.assert_not_called()
        notify.assert_not_called()

    def test_partial_failure_returns_false_and_does_not_notify(self):
        result, _, notify = self._run_main(
            [("u1", Path("/tmp/h1")), ("u2", Path("/tmp/h2"))],
            install_results=[True, False],
        )
        self.assertFalse(result)
        notify.assert_not_called()

    def test_download_failure_returns_false(self):
        result, install, notify = self._run_main([("u1", Path("/tmp/h1"))], script_text=None)
        self.assertFalse(result)
        install.assert_not_called()
        notify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
