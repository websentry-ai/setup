"""An enterprise hooks.json existing is not our install; our own entries are.

Cursor's enterprise hooks.json is a format the org can deploy itself, so judging
it by existence reported a first install on such a device as tampered.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import REPO as _REPO

_spec = importlib.util.spec_from_file_location(
    "_cursor_mdm_setup_state", str(_REPO / "cursor/mdm" / "setup.py"))
mdm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mdm)


class TestDetectInstallState(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.enterprise = Path(self._tmp.name) / "Cursor"
        (self.enterprise / "hooks").mkdir(parents=True)
        self.script = self.enterprise / "hooks" / "unbound.py"
        self.hooks_json = self.enterprise / "hooks.json"
        self._patch = mock.patch.object(
            mdm, "get_enterprise_hooks_dir", return_value=self.enterprise)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def _write(self, settings):
        self.hooks_json.write_text(json.dumps(settings), encoding="utf-8")

    def test_nothing_installed_is_fresh(self):
        self.assertEqual(mdm.detect_install_state(), "fresh")

    def test_foreign_enterprise_hooks_are_fresh(self):
        self._write({"version": 1, "hooks": {
            "preToolUse": [{"command": "./hooks/acme.sh"}]}})
        self.assertEqual(mdm.detect_install_state(), "fresh")

    def test_our_entries_and_script_are_persisted(self):
        self._write({"version": 1, "hooks": {
            "preToolUse": [{"command": "./hooks/unbound.py"}]}})
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "persisted")

    def test_our_entries_without_the_script_is_tampered(self):
        self._write({"version": 1, "hooks": {
            "preToolUse": [{"command": "./hooks/unbound.py"}]}})
        self.assertEqual(mdm.detect_install_state(), "tampered")

    def test_our_script_without_our_entries_is_tampered(self):
        self._write({"version": 1, "hooks": {
            "preToolUse": [{"command": "./hooks/acme.sh"}]}})
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "tampered")

    def test_windows_launcher_command_counts_as_ours(self):
        self._write({"version": 1, "hooks": {
            "preToolUse": [{"command": f'py -3 "{self.script}"'}]}})
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "persisted")

    def test_a_foreign_hook_whose_path_ends_the_same_is_not_ours(self):
        # Matching the path anywhere in the command would read an org's own hook as
        # ours, which is the false positive this detector exists to avoid.
        self._write({"version": 1, "hooks": {
            "preToolUse": [{"command": "python /opt/vendor/hooks/unbound.py"}]}})
        self.assertEqual(mdm.detect_install_state(), "fresh")

    def test_a_decoy_that_only_mentions_our_path_is_not_ours(self):
        self._write({"version": 1, "hooks": {
            "preToolUse": [{"command": "/bin/true # hooks/unbound.py"}]}})
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "tampered")

    def test_a_decoy_that_mentions_our_absolute_path_is_not_ours(self):
        self._write({"version": 1, "hooks": {
            "preToolUse": [{"command": f"/bin/true # {self.script}"}]}})
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "tampered")

    def test_binary_install_command_counts_as_ours(self):
        self._write({"version": 1, "hooks": {"preToolUse": [
            {"command": "/opt/unbound/current/unbound-hook/unbound-hook hook"}]}})
        self.script.write_text("x", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "persisted")

    def test_a_non_string_command_does_not_crash(self):
        self._write({"version": 1, "hooks": {"preToolUse": [{"command": {"a": 1}}, 7]}})
        self.assertEqual(mdm.detect_install_state(), "fresh")

    def test_an_unparseable_config_is_tampered(self):
        # Cursor refuses the whole file, so our hooks are not running.
        self.hooks_json.write_text("{ not json", encoding="utf-8")
        self.assertEqual(mdm.detect_install_state(), "tampered")

    def test_a_config_that_cannot_be_read_is_unknown(self):
        self.hooks_json.write_text("{}", encoding="utf-8")
        with mock.patch.object(mdm, "open", side_effect=OSError("EIO")):
            self.assertIsNone(mdm.detect_install_state())


if __name__ == "__main__":
    unittest.main()
