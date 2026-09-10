"""Copilot OTLP export settings, written into VS Code's user settings.

Runs against both setup modules, because the user-level and MDM paths carry
independent copies of this code and a fix applied to one has silently missed
the other before.
"""

import importlib.util
import json
import shutil
import tempfile
import time
import platform
import unittest
from unittest.mock import patch
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]

MODULES = {
    "user": (_REPO_ROOT / "copilot" / "hooks" / "setup.py", "configure_otel_export", "clear_otel_export"),
    "mdm": (_REPO_ROOT / "copilot" / "hooks" / "mdm" / "setup.py", "configure_otel_export_for_user", "clear_otel_export_for_user"),
}

# A settings file as they actually look: comments, a trailing comma, a nested
# language block. A json.load/json.dump round-trip destroys all three.
REAL_WORLD = """{
  // Editor look and feel
  "editor.fontSize": 13,
  "editor.rulers": [80, 100],  // soft guides
  /* block comment
     across lines */
  "[python]": {
    "editor.tabSize": 4
  },
  "workbench.colorTheme": "Default Dark+",
}"""

OTEL_PREFIX = "github.copilot.chat.otel."


def _load(name, path):
    spec = importlib.util.spec_from_file_location(f"copilot_setup_{name}", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _OtelHelpers:
    def _home_with(self, contents=None):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        user_dir = home / "Library" / "Application Support" / "Code" / "User"
        user_dir.mkdir(parents=True)
        if contents is not None:
            (user_dir / "settings.json").write_text(contents, encoding="utf-8")
        return home, user_dir / "settings.json"

    @staticmethod
    def _passthrough(mod):
        """MDM writers drop privileges; the fork needs root, so run fn inline."""
        return patch.object(mod, "_run_as_user",
                            lambda username, fn, *a, **kw: fn(*a, **kw), create=True)

    def _configure(self, mod, name, api_key, home, gateway="https://api.getunbound.ai"):
        fn = getattr(mod, MODULES[name][1])
        if name == "mdm":
            with self._passthrough(mod):
                return fn("someuser", home, api_key, gateway_url=gateway)
        return fn(api_key, gateway_url=gateway, home=home)

    def _clear(self, mod, name, home):
        fn = getattr(mod, MODULES[name][2])
        if name == "mdm":
            with self._passthrough(mod):
                return fn("someuser", home)
        return fn(home)

    def _each(self):
        for name, (path, _, _) in MODULES.items():
            with self.subTest(module=name):
                yield name, _load(name, path)


class OtelSettingsTests(_OtelHelpers, unittest.TestCase):
    # ── writing ──────────────────────────────────────────────────────────

    def test_writes_the_five_settings_with_the_key_as_a_header(self):
        for name, mod in self._each():
            home, path = self._home_with("{}")
            self.assertTrue(self._configure(mod, name, "sk-live-abc", home))
            got = json.loads(path.read_text())
            self.assertTrue(got["github.copilot.chat.otel.enabled"])
            self.assertEqual(got["github.copilot.chat.otel.exporterType"], "otlp-http")
            self.assertEqual(got["github.copilot.chat.otel.headers"], {"x-api-key": "sk-live-abc"})
            self.assertFalse(got["github.copilot.chat.otel.captureContent"])

    def test_the_endpoint_is_a_base_the_exporter_appends_to(self):
        """The exporter adds /v1/traces itself, so writing the full path would
        produce /otel/v1/traces/v1/traces."""
        for name, mod in self._each():
            home, path = self._home_with("{}")
            self._configure(mod, name, "k", home, gateway="https://api.getunbound.ai/")
            endpoint = json.loads(path.read_text())["github.copilot.chat.otel.otlpEndpoint"]
            self.assertEqual(endpoint, "https://api.getunbound.ai/otel")

    def test_a_users_comments_and_settings_survive(self):
        for name, mod in self._each():
            home, path = self._home_with(REAL_WORLD)
            self.assertTrue(self._configure(mod, name, "k", home))
            text = path.read_text()
            self.assertIn("// Editor look and feel", text)
            self.assertIn("/* block comment", text)
            got = mod._parse_jsonc_or_none(text)
            self.assertEqual(got["editor.fontSize"], 13)
            self.assertEqual(got["[python]"], {"editor.tabSize": 4})
            self.assertEqual(got["workbench.colorTheme"], "Default Dark+")

    def test_running_setup_twice_changes_nothing(self):
        for name, mod in self._each():
            home, path = self._home_with(REAL_WORLD)
            self._configure(mod, name, "k", home)
            once = path.read_text()
            self._configure(mod, name, "k", home)
            self.assertEqual(path.read_text(), once)
            self.assertEqual(once.count('"github.copilot.chat.otel.enabled"'), 1)

    def test_a_rotated_key_replaces_rather_than_appends(self):
        for name, mod in self._each():
            home, path = self._home_with(REAL_WORLD)
            self._configure(mod, name, "sk-old", home)
            self._configure(mod, name, "sk-new", home)
            text = path.read_text()
            self.assertEqual(text.count('"github.copilot.chat.otel.headers"'), 1)
            self.assertEqual(
                mod._parse_jsonc_or_none(text)["github.copilot.chat.otel.headers"],
                {"x-api-key": "sk-new"})

    def test_the_original_is_backed_up_before_the_first_write(self):
        for name, mod in self._each():
            home, path = self._home_with(REAL_WORLD)
            self._configure(mod, name, "k", home)
            backup = path.with_suffix(".json.unbound-bak")
            self.assertTrue(backup.exists())
            self.assertEqual(backup.read_text(), REAL_WORLD)

    def test_a_settings_file_that_does_not_parse_is_left_alone(self):
        for name, mod in self._each():
            home, path = self._home_with("{ this is not json at all ")
            self.assertFalse(self._configure(mod, name, "k", home))
            self.assertEqual(path.read_text(), "{ this is not json at all ")

    def test_no_vscode_directory_is_not_a_failure(self):
        """A device without VS Code must not fail setup, and must not have a
        settings directory conjured for an editor it does not run."""
        for name, mod in self._each():
            home = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, home, ignore_errors=True)
            if name == "user":
                self.assertTrue(self._configure(mod, name, "k", home))
            else:
                self.assertTrue(self._configure(mod, name, "k", home))
            self.assertFalse((home / "Library").exists())

    # ── clearing ─────────────────────────────────────────────────────────

    def test_clear_removes_only_our_keys(self):
        for name, mod in self._each():
            home, path = self._home_with(REAL_WORLD)
            self._configure(mod, name, "k", home)
            self.assertEqual(self._clear(mod, name, home), "cleared")
            text = path.read_text()
            got = mod._parse_jsonc_or_none(text)
            self.assertEqual([k for k in got if k.startswith(OTEL_PREFIX)], [])
            self.assertEqual(got["editor.fontSize"], 13)
            self.assertEqual(got["workbench.colorTheme"], "Default Dark+")
            self.assertIn("// Editor look and feel", text)

    def test_clear_reports_not_found_when_we_never_wrote_anything(self):
        for name, mod in self._each():
            home, _ = self._home_with(REAL_WORLD)
            self.assertEqual(self._clear(mod, name, home), "not_found")

    def test_clear_is_safe_to_run_twice(self):
        for name, mod in self._each():
            home, path = self._home_with(REAL_WORLD)
            self._configure(mod, name, "k", home)
            self.assertEqual(self._clear(mod, name, home), "cleared")
            after = path.read_text()
            self.assertEqual(self._clear(mod, name, home), "not_found")
            self.assertEqual(path.read_text(), after)




class OtelSettingsRegressionTests(_OtelHelpers, unittest.TestCase):
    def test_a_commented_out_copy_of_a_key_does_not_absorb_the_write(self):
        original = (
            '{\n'
            '  // tried this last week:\n'
            '  // "github.copilot.chat.otel.otlpEndpoint": "http://localhost:4318",\n'
            '  "editor.fontSize": 12\n'
            '}'
        )
        for name, mod in self._each():
            home, settings = self._home_with(original)
            self.assertTrue(self._configure(mod, name, "KEY", home))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["github.copilot.chat.otel.otlpEndpoint"],
                             "https://api.getunbound.ai/otel")
            self.assertIn("// tried this last week:", settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["editor.fontSize"], 12)

    def test_one_unparsable_editor_does_not_skip_the_others(self):
        for name, mod in self._each():
            home, stable = self._home_with('{ "editor.fontSize": 12,, }')
            insiders = home / "Library" / "Application Support" / "Code - Insiders" / "User"
            insiders.mkdir(parents=True)
            (insiders / "settings.json").write_text('{ "editor.fontSize": 14 }', encoding="utf-8")
            self._configure(mod, name, "KEY", home)
            parsed = mod._parse_jsonc_or_none((insiders / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(parsed["github.copilot.chat.otel.otlpEndpoint"],
                             "https://api.getunbound.ai/otel")

    def test_mdm_writers_drop_privileges_before_touching_a_user_home(self):
        mod = _load("mdm", MODULES["mdm"][0])
        home, _ = self._home_with('{ "editor.fontSize": 12 }')
        seen = []

        def _record(username, fn, *a, **kw):
            seen.append(username)
            return fn(*a, **kw)

        with patch.object(mod, "_run_as_user", _record):
            mod.configure_otel_export_for_user("someuser", home, "KEY",
                                               gateway_url="https://api.getunbound.ai")
            mod.clear_otel_export_for_user("someuser", home)
        self.assertEqual(seen, ["someuser", "someuser"])


if __name__ == "__main__":
    unittest.main()


class OtelSettingsHostileInputTests(_OtelHelpers, unittest.TestCase):
    def test_a_settings_file_that_is_not_utf8_does_not_abort_the_install(self):
        for name, mod in self._each():
            home, settings = self._home_with("")
            settings.write_bytes(b"\xff\xfe{\x00}\x00")
            self.assertFalse(self._configure(mod, name, "KEY", home))
            self.assertEqual(self._clear(mod, name, home), "not_found")

    def test_a_byte_order_mark_is_accepted(self):
        for name, mod in self._each():
            home, settings = self._home_with("")
            settings.write_bytes(b'\xef\xbb\xbf{"editor.fontSize": 12}')
            self.assertTrue(self._configure(mod, name, "KEY", home))

    def test_a_leading_block_comment_holding_a_brace_does_not_swallow_the_key(self):
        original = '/* settings { see wiki } */\n{\n  "editor.fontSize": 12\n}'
        for name, mod in self._each():
            home, settings = self._home_with(original)
            self.assertTrue(self._configure(mod, name, "SECRETKEY", home))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["github.copilot.chat.otel.otlpEndpoint"],
                             "https://api.getunbound.ai/otel")
            self.assertEqual(self._clear(mod, name, home), "cleared")
            self.assertNotIn("SECRETKEY", settings.read_text(encoding="utf-8"))

    def test_a_duplicated_key_is_edited_where_the_parser_reads_it(self):
        original = ('{"github.copilot.chat.otel.enabled": false, "a": 1,'
                    ' "github.copilot.chat.otel.enabled": false}')
        for name, mod in self._each():
            home, settings = self._home_with(original)
            self._configure(mod, name, "KEY", home)
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertTrue(parsed["github.copilot.chat.otel.enabled"])

    def test_clear_removes_the_backup_that_holds_the_key(self):
        for name, mod in self._each():
            home, settings = self._home_with('{"editor.fontSize": 12}')
            self._configure(mod, name, "SECRETKEY", home)
            self._configure(mod, name, "SECRETKEY", home)
            backup = settings.with_suffix(".json.unbound-bak")
            self.assertIn("SECRETKEY", backup.read_text(encoding="utf-8"))
            self.assertEqual(self._clear(mod, name, home), "cleared")
            self.assertFalse(backup.exists())

    def test_a_run_of_unterminated_block_comments_is_scanned_in_linear_time(self):
        for name, mod in self._each():
            home, _ = self._home_with('{"a": 1}\n' + '/* ' * 40000)
            started = time.monotonic()
            self._configure(mod, name, "KEY", home)
            self.assertLess(time.monotonic() - started, 2.0)

    def test_a_settings_file_that_is_a_symlink_is_never_written_through(self):
        if platform.system() == "Windows":
            self.skipTest("POSIX symlink semantics")
        for name, mod in self._each():
            home, settings = self._home_with('{"a": 1}')
            victim = Path(tempfile.mkdtemp()) / "victim.txt"
            self.addCleanup(shutil.rmtree, victim.parent, ignore_errors=True)
            victim.write_text("SAFE", encoding="utf-8")
            settings.unlink()
            settings.symlink_to(victim)
            self.assertFalse(self._configure(mod, name, "KEY", home))
            self.assertEqual(victim.read_text(encoding="utf-8"), "SAFE")

    def test_comment_characters_inside_a_string_value_are_not_treated_as_comments(self):
        original = '{"weird": "a // not a comment /* nor this */", "b": 1}'
        for name, mod in self._each():
            home, settings = self._home_with(original)
            self.assertTrue(self._configure(mod, name, "KEY", home))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["weird"], "a // not a comment /* nor this */")

    def test_a_top_level_array_is_left_alone(self):
        for name, mod in self._each():
            home, settings = self._home_with('[1, 2, 3]')
            self.assertFalse(self._configure(mod, name, "KEY", home))
            self.assertEqual(settings.read_text(encoding="utf-8"), '[1, 2, 3]')
