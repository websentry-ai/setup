"""The gateway-mode codex installer must carry --frontend-url into config.json.

Mirror of the claude-code gateway coverage: the device-deployment page appends
--frontend-url for every mode, so a gateway-mode custom-tenant device that
dropped it left frontend_url out of the config the runtime reads.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import tool_module

gw = tool_module("codex/gateway/mdm", "setup")


class TestWriterPersistsFrontendUrl(unittest.TestCase):
    def _write(self, **kwargs):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        with mock.patch.object(gw, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)):
            gw.write_unbound_config_for_user("alice", home, "ub-key", **kwargs)
        return json.loads((home / ".unbound" / "config.json").read_text())

    def test_frontend_url_is_written(self):
        cfg = self._write(frontend_url="https://tenant.unboundsecurity.ai")
        self.assertEqual(cfg["frontend_url"], "https://tenant.unboundsecurity.ai")

    def test_absent_frontend_url_leaves_no_key(self):
        cfg = self._write()
        self.assertNotIn("frontend_url", cfg)


class TestMainParsesAndPersistsFrontendUrl(unittest.TestCase):
    """Drive main() with its collaborators mocked but the real writer, then read
    config.json off disk — the end-to-end proof the flag survives arg parsing."""

    def test_flag_lands_in_config(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        frontend = "https://tenant.unboundsecurity.ai"
        argv = ["setup.py", "--api-key", "auth", "--gateway-url",
                "https://gw.example.com", "--frontend-url", frontend]

        with mock.patch.object(gw.sys, "argv", argv), \
             mock.patch.object(gw, "check_admin_privileges", return_value=True), \
             mock.patch.object(gw, "get_device_identifier", return_value="dev-1"), \
             mock.patch.object(gw, "detect_install_state", return_value="fresh"), \
             mock.patch.object(gw, "fetch_api_key_from_mdm", return_value="codex-key"), \
             mock.patch.object(gw, "get_all_user_homes", return_value=[("alice", home)]), \
             mock.patch.object(gw, "remove_env_var_from_user"), \
             mock.patch.object(gw, "set_env_var_system_wide", return_value=(True, True)), \
             mock.patch.object(gw, "write_codex_config_for_user", return_value=True), \
             mock.patch.object(gw, "remove_hooks_unbound_script_for_user"), \
             mock.patch.object(gw, "disable_codex_hooks_feature_for_user"), \
             mock.patch.object(gw, "notify_setup_complete"), \
             mock.patch.object(gw, "_run_as_user", side_effect=lambda u, fn, *a, **k: fn(*a, **k)):
            self.assertTrue(gw.main())

        cfg = json.loads((home / ".unbound" / "config.json").read_text())
        self.assertEqual(cfg["frontend_url"], frontend)


if __name__ == "__main__":
    unittest.main()
