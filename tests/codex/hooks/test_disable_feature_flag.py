"""Regression tests for clearing the Codex hooks feature flag from ~/.codex/config.toml.

`sudo unbound nuke` reported `Codex (Failed to clear hooks feature flag)` on machines whose
python3 is older than 3.11: with no tomllib to validate the edit, the clear refused to touch
any config holding a multi-line value, so the flag could never reach disk. These cover the
clear on both Pythons and both spellings.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.conftest import tool_module

setup = tool_module("codex/hooks", kind="setup")


# A config that carries a multi-line array — the shape that made the parser-less safety check
# refuse to write, so the flag could never be cleared.
MULTILINE_CONFIG = """\
model = "gpt-5-codex"

[model_providers.unbound]
name = "Unbound"
env_key = "UNBOUND_CODEX_API_KEY"
extra_headers = [
    "x-one",
    "x-two",
]

[features]
hooks = true
"""


class _FlagClearBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # Path.home() reads $HOME via expanduser on POSIX, so this scopes the clear to tmp.
        patcher = mock.patch.dict(os.environ, {"HOME": self.tmp})
        patcher.start()
        self.addCleanup(patcher.stop)
        (Path(self.tmp) / ".codex").mkdir(parents=True)
        self.config = Path(self.tmp) / ".codex" / "config.toml"

    def _write(self, text):
        self.config.write_text(text, encoding="utf-8")

    def _read(self):
        return self.config.read_text(encoding="utf-8")


class TestDisableStatus(_FlagClearBase):
    def test_section_form_multiline_without_tomllib(self):
        # The exact regression: old python (no tomllib) + a multi-line array in the config.
        self._write(MULTILINE_CONFIG)
        with mock.patch.object(setup, "tomllib", None):
            status = setup.disable_codex_hooks_feature_status()
        self.assertEqual(status, "cleared")
        out = self._read()
        self.assertNotIn("hooks = true", out)   # flag gone
        self.assertIn("[features]", out)          # section preserved
        self.assertIn("extra_headers", out)       # multi-line array untouched

    def test_section_form_multiline_with_tomllib(self):
        if setup.tomllib is None:
            self.skipTest("tomllib unavailable on this interpreter")
        self._write(MULTILINE_CONFIG)
        self.assertEqual(setup.disable_codex_hooks_feature_status(), "cleared")
        self.assertNotIn("hooks = true", self._read())

    def test_old_spelling_codex_hooks(self):
        self._write("[features]\ncodex_hooks = true\n")
        with mock.patch.object(setup, "tomllib", None):
            self.assertEqual(setup.disable_codex_hooks_feature_status(), "cleared")
        self.assertNotIn("codex_hooks", self._read())

    def test_no_flag_is_not_found(self):
        self._write("[features]\nother = true\n")
        self.assertEqual(setup.disable_codex_hooks_feature_status(), "not_found")

    def test_hooks_key_in_other_table_is_left_alone(self):
        # `hooks = true` under some other table is an unrelated setting, not this flag.
        self._write("[hooks.state]\nhooks = true\n")
        self.assertEqual(setup.disable_codex_hooks_feature_status(), "not_found")
        self.assertIn("hooks = true", self._read())


class TestDisableVoid(_FlagClearBase):
    """disable_codex_hooks_feature() is the void twin used off the nuke path; same fix."""

    def test_section_form_multiline_without_tomllib(self):
        self._write(MULTILINE_CONFIG)
        with mock.patch.object(setup, "tomllib", None):
            setup.disable_codex_hooks_feature()
        self.assertNotIn("hooks = true", self._read())


if __name__ == "__main__":
    unittest.main()
