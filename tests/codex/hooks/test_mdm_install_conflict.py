"""A user-level codex install refuses to run beside an MDM one, or every hook would fire twice."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import tool_module

setup = tool_module("codex/hooks", kind="setup")


class TestMdmInstallConflict(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        patcher = mock.patch.object(setup, "get_managed_settings_dir", return_value=self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_mdm_install(self):
        self.assertFalse(setup.check_enterprise_hooks_conflict())

    def test_the_binary_install_in_codex_s_system_hooks_json(self):
        command = '"/opt/unbound/current/unbound-hook/unbound-hook" hook codex'
        (self.dir / "hooks.json").write_text(json.dumps({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": command}]}]}}))
        self.assertTrue(setup.check_enterprise_hooks_conflict())

    def test_a_command_that_only_shares_our_prefix_is_not_an_mdm_install(self):
        (self.dir / "hooks.json").write_text(json.dumps({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "/opt/unbound/other-tool"}]}]}}))
        self.assertFalse(setup.check_enterprise_hooks_conflict())

    def test_an_organisations_own_hooks_are_not_an_mdm_install(self):
        (self.dir / "hooks.json").write_text(json.dumps({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "/usr/local/bin/org-hook"}]}]}}))
        self.assertFalse(setup.check_enterprise_hooks_conflict())

    def test_the_python_era_mdm_script(self):
        (self.dir / "hooks").mkdir()
        (self.dir / "hooks" / "unbound.py").write_text("")
        self.assertTrue(setup.check_enterprise_hooks_conflict())


class TestSystemFolder(unittest.TestCase):
    def test_codex_s_system_folder_on_each_os(self):
        for system, expected in (("Darwin", Path("/etc/codex")), ("Linux", Path("/etc/codex"))):
            with mock.patch.object(setup.platform, "system", return_value=system):
                self.assertEqual(setup.get_managed_settings_dir(), expected)
        with mock.patch.object(setup.platform, "system", return_value="Windows"), \
                mock.patch.dict(setup.os.environ, {"ProgramData": r"D:\PD"}):
            self.assertEqual(setup.get_managed_settings_dir(), Path(r"D:\PD") / "OpenAI" / "Codex")


if __name__ == "__main__":
    unittest.main()
