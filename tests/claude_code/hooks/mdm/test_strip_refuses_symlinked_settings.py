"""managed-settings.json is never written through a link.

Replacing it swaps an admin-maintained link for a regular file and strands the
target, which is where their edits keep going. Following it writes wherever the
link points, as root. Both writers refuse. Skip mode never touches the file at
all; binary/tests covers that.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from tests.conftest import REPO as _REPO

_spec = importlib.util.spec_from_file_location(
    "_cc_mdm_setup_strip", str(_REPO / "claude-code/hooks/mdm" / "setup.py"))
mdm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mdm)


class TestStripRefusesALinkedConfig(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.managed = root / "ClaudeCode"
        self.managed.mkdir()
        self.script = self.managed / "hooks" / "unbound.py"
        self.config = json.dumps({
            "forceLoginOrgUUID": "org-uuid",
            "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": f'"{self.script}"'}]}]}})

    def tearDown(self):
        self._tmp.cleanup()

    def _strip(self):
        return mdm._strip_unbound_hooks_from_settings(self.managed, self.script)

    def test_a_link_is_refused_and_its_target_untouched(self):
        target = Path(self._tmp.name) / "org-managed-settings.json"
        target.write_text(self.config)
        link = self.managed / "managed-settings.json"
        link.symlink_to(target)

        self.assertEqual(self._strip(), (False, True), "a refusal must surface as an error")
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(), self.config)

    def test_a_link_with_nothing_of_ours_is_not_an_error(self):
        target = Path(self._tmp.name) / "org-managed-settings.json"
        target.write_text(json.dumps({"forceLoginOrgUUID": "org-uuid"}))
        (self.managed / "managed-settings.json").symlink_to(target)

        self.assertEqual(self._strip(), (False, False), "nothing to strip is not a failure")

    def test_a_plain_file_is_still_stripped(self):
        settings = self.managed / "managed-settings.json"
        settings.write_text(self.config)

        self.assertEqual(self._strip(), (True, False))
        left = json.loads(settings.read_text())
        self.assertNotIn("hooks", left)
        self.assertEqual(left["forceLoginOrgUUID"], "org-uuid")


if __name__ == "__main__":
    unittest.main()
