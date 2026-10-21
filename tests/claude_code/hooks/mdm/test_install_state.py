"""A config file existing is not our install; only our own hook entries are.

managed-settings.json is Claude Code's own enterprise policy file, so a device
that has never run our setup can already have one. Judging it by existence
reported every such first install as tampered.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import REPO as _REPO

_spec = importlib.util.spec_from_file_location(
    "_cc_mdm_setup_state", str(_REPO / "claude-code/hooks/mdm" / "setup.py"))
mdm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mdm)


class TestDetectInstallState(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.managed = Path(self._tmp.name) / "ClaudeCode"
        (self.managed / "hooks").mkdir(parents=True)
        self.script = self.managed / "hooks" / "unbound.py"
        self._patch = mock.patch.object(
            mdm, "get_managed_settings_dir", return_value=self.managed)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def _write(self, name, settings):
        path = self.managed / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(settings), encoding="utf-8")

    def _ours(self):
        return {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": f'"{self.script}"'}]}]}}

    def _theirs(self):
        return {"forceLoginOrgUUID": "org-uuid", "hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [{"command": "/opt/acme/their-hook"}]}]}}

    def test_nothing_installed_is_fresh(self):
        self.assertEqual(mdm.detect_install_state(), "fresh")

    def test_foreign_enterprise_policy_is_fresh(self):
        self._write("managed-settings.json", self._theirs())
        self.assertEqual(mdm.detect_install_state(), "fresh")

    def test_our_dropin_beside_foreign_policy_is_persisted(self):
        self._write("managed-settings.json", self._theirs())
        self._write("managed-settings.d/unbound.json", self._ours())
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "persisted")

    def test_our_entries_without_the_script_is_tampered(self):
        self._write("managed-settings.d/unbound.json", self._ours())
        self.assertEqual(mdm.detect_install_state(), "tampered")

    def test_our_script_without_our_entries_is_tampered(self):
        self._write("managed-settings.json", self._theirs())
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "tampered")

    def test_unreadable_config_is_unknown(self):
        (self.managed / "managed-settings.json").write_text("{ not json")
        self.assertIsNone(mdm.detect_install_state())

    def test_our_dropin_outranks_an_unreadable_org_policy(self):
        # managed-settings.json is often the org's. One we cannot parse must not
        # mask our own drop-in answering definitively, or deleting our hooks while
        # that file is corrupt would leave the device reading healthy forever.
        self._write("managed-settings.d/unbound.json", self._ours())
        (self.managed / "managed-settings.json").write_text("{ not json")
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "persisted")

    def test_binary_install_entries_count_as_ours(self):
        self._write("managed-settings.d/unbound.json", {"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [{"command": "/opt/unbound/current/unbound-hook/unbound-hook hook"}]}]}})
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "persisted")

    def test_skip_settings_judges_the_script_alone(self):
        self.assertEqual(mdm.detect_install_state(skip_settings=True), "fresh")
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(skip_settings=True), "persisted")


if __name__ == "__main__":
    unittest.main()
