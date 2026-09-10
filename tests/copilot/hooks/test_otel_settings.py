"""Copilot OTLP export settings, written into VS Code's user settings.

Runs against both setup modules, because the user-level and MDM paths carry
independent copies of this code and a fix applied to one has silently missed
the other before.
"""

import importlib.util
import json
import shutil
import stat
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
    # Every platform's base, so the module's own choice of directory is what the test
    # follows. Hardcoding one makes the suite pass on that OS and nowhere else.
    _VSCODE_BASES = (
        ("Library", "Application Support"),
        ("AppData", "Roaming"),
        (".config",),
    )

    def _make_user_dirs(self, home, editor="Code"):
        for parts in self._VSCODE_BASES:
            home.joinpath(*parts, editor, "User").mkdir(parents=True, exist_ok=True)

    def _user_dir(self, mod, home, editor="Code"):
        """The directory this module will actually write to on this platform."""
        dirs = [d for d in mod.vscode_user_dirs(home) if d.parent.name == editor]
        self.assertEqual(len(dirs), 1, f"expected one {editor} dir, got {dirs}")
        return dirs[0]

    def _home_with(self, mod, contents=None):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        self._make_user_dirs(home)
        settings = self._user_dir(mod, home) / "settings.json"
        if contents is not None:
            settings.write_text(contents, encoding="utf-8")
        return home, settings

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
            home, path = self._home_with(mod, "{}")
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
            home, path = self._home_with(mod, "{}")
            self._configure(mod, name, "k", home, gateway="https://api.getunbound.ai/")
            endpoint = json.loads(path.read_text())["github.copilot.chat.otel.otlpEndpoint"]
            self.assertEqual(endpoint, "https://api.getunbound.ai/otel")

    def test_a_users_comments_and_settings_survive(self):
        for name, mod in self._each():
            home, path = self._home_with(mod, REAL_WORLD)
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
            home, path = self._home_with(mod, REAL_WORLD)
            self._configure(mod, name, "k", home)
            once = path.read_text()
            self._configure(mod, name, "k", home)
            self.assertEqual(path.read_text(), once)
            self.assertEqual(once.count('"github.copilot.chat.otel.enabled"'), 1)

    def test_a_rotated_key_replaces_rather_than_appends(self):
        for name, mod in self._each():
            home, path = self._home_with(mod, REAL_WORLD)
            self._configure(mod, name, "sk-old", home)
            self._configure(mod, name, "sk-new", home)
            text = path.read_text()
            # As a setting key, not as the string inside settingsSync.ignoredSettings.
            self.assertEqual(text.count('"github.copilot.chat.otel.headers":'), 1)
            self.assertEqual(
                mod._parse_jsonc_or_none(text)["github.copilot.chat.otel.headers"],
                {"x-api-key": "sk-new"})

    def test_the_original_is_backed_up_before_the_first_write(self):
        for name, mod in self._each():
            home, path = self._home_with(mod, REAL_WORLD)
            self._configure(mod, name, "k", home)
            backup = path.with_suffix(".json.unbound-bak")
            self.assertTrue(backup.exists())
            self.assertEqual(backup.read_text(), REAL_WORLD)

    def test_a_settings_file_that_does_not_parse_is_left_alone(self):
        for name, mod in self._each():
            home, path = self._home_with(mod, "{ this is not json at all ")
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
            home, path = self._home_with(mod, REAL_WORLD)
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
            home, _ = self._home_with(mod, REAL_WORLD)
            self.assertEqual(self._clear(mod, name, home), "not_found")

    def test_clear_is_safe_to_run_twice(self):
        for name, mod in self._each():
            home, path = self._home_with(mod, REAL_WORLD)
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
            home, settings = self._home_with(mod, original)
            self.assertTrue(self._configure(mod, name, "KEY", home))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["github.copilot.chat.otel.otlpEndpoint"],
                             "https://api.getunbound.ai/otel")
            self.assertIn("// tried this last week:", settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["editor.fontSize"], 12)

    def test_one_unparsable_editor_does_not_skip_the_others(self):
        for name, mod in self._each():
            home, stable = self._home_with(mod, '{ "editor.fontSize": 12,, }')
            self._make_user_dirs(home, editor="Code - Insiders")
            insiders = self._user_dir(mod, home, editor="Code - Insiders")
            (insiders / "settings.json").write_text('{ "editor.fontSize": 14 }', encoding="utf-8")
            self._configure(mod, name, "KEY", home)
            parsed = mod._parse_jsonc_or_none((insiders / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(parsed["github.copilot.chat.otel.otlpEndpoint"],
                             "https://api.getunbound.ai/otel")

    def test_mdm_writers_drop_privileges_before_touching_a_user_home(self):
        mod = _load("mdm", MODULES["mdm"][0])
        home, _ = self._home_with(mod, '{ "editor.fontSize": 12 }')
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
            home, settings = self._home_with(mod, "")
            settings.write_bytes(b"\xff\xfe{\x00}\x00")
            self.assertFalse(self._configure(mod, name, "KEY", home))
            self.assertEqual(self._clear(mod, name, home), "not_found")

    def test_a_byte_order_mark_is_accepted(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, "")
            settings.write_bytes(b'\xef\xbb\xbf{"editor.fontSize": 12}')
            self.assertTrue(self._configure(mod, name, "KEY", home))

    def test_a_leading_block_comment_holding_a_brace_does_not_swallow_the_key(self):
        original = '/* settings { see wiki } */\n{\n  "editor.fontSize": 12\n}'
        for name, mod in self._each():
            home, settings = self._home_with(mod, original)
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
            home, settings = self._home_with(mod, original)
            self._configure(mod, name, "KEY", home)
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertTrue(parsed["github.copilot.chat.otel.enabled"])

    def test_clear_removes_the_backup(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"editor.fontSize": 12}')
            self._configure(mod, name, "SECRETKEY", home)
            self._configure(mod, name, "SECRETKEY", home)
            backup = settings.with_suffix(".json.unbound-bak")
            # Taken from the file as it was before the first write, so it holds the
            # user's original settings and never a key of ours.
            self.assertNotIn("SECRETKEY", backup.read_text(encoding="utf-8"))
            self.assertIn("editor.fontSize", backup.read_text(encoding="utf-8"))
            self.assertEqual(self._clear(mod, name, home), "cleared")
            self.assertFalse(backup.exists())

    def test_a_run_of_unterminated_block_comments_is_scanned_in_linear_time(self):
        for name, mod in self._each():
            home, _ = self._home_with(mod, '{"a": 1}\n' + '/* ' * 40000)
            started = time.monotonic()
            self._configure(mod, name, "KEY", home)
            self.assertLess(time.monotonic() - started, 2.0)

    def test_a_settings_file_that_is_a_symlink_is_never_written_through(self):
        if platform.system() == "Windows":
            self.skipTest("POSIX symlink semantics")
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"a": 1}')
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
            home, settings = self._home_with(mod, original)
            self.assertTrue(self._configure(mod, name, "KEY", home))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["weird"], "a // not a comment /* nor this */")

    def test_a_top_level_array_is_left_alone(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, '[1, 2, 3]')
            self.assertFalse(self._configure(mod, name, "KEY", home))
            self.assertEqual(settings.read_text(encoding="utf-8"), '[1, 2, 3]')


class OtelSettingsCredentialHandlingTests(_OtelHelpers, unittest.TestCase):
    def test_a_file_holding_the_key_is_owner_only_even_if_the_editor_made_it(self):
        if platform.system() == "Windows":
            self.skipTest("POSIX modes")
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"editor.fontSize": 12}')
            settings.chmod(0o644)
            self.assertTrue(self._configure(mod, name, "SECRETKEY", home))
            self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o600)
            backup = settings.with_suffix(".json.unbound-bak")
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_clear_removes_every_duplicate_of_a_key_not_just_the_effective_one(self):
        original = ('{"github.copilot.chat.otel.enabled": true,'
                    ' "github.copilot.chat.otel.headers": {"x-api-key": "OLDKEY"},'
                    ' "a": 1,'
                    ' "github.copilot.chat.otel.enabled": true,'
                    ' "github.copilot.chat.otel.headers": {"x-api-key": "SECRETKEY"}}')
        for name, mod in self._each():
            home, settings = self._home_with(mod, original)
            self.assertEqual(self._clear(mod, name, home), "cleared")
            text = settings.read_text(encoding="utf-8")
            self.assertNotIn("OLDKEY", text)
            self.assertNotIn("SECRETKEY", text)
            parsed = mod._parse_jsonc_or_none(text)
            self.assertEqual([k for k in parsed if k.startswith(OTEL_PREFIX)], [])

    def test_the_write_leaves_no_staging_file_behind(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, REAL_WORLD)
            self._configure(mod, name, "KEY", home)
            self.assertEqual(list(settings.parent.glob(".unbound-*")), [])

    def test_a_redirected_settings_directory_is_refused(self):
        if platform.system() == "Windows":
            self.skipTest("POSIX symlink semantics")
        for name, mod in self._each():
            home = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, home, ignore_errors=True)
            outside = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
            (outside / "User").mkdir()
            self._make_user_dirs(home)
            hijacked = self._user_dir(mod, home)
            hijacked.rmdir()
            hijacked.symlink_to(outside / "User")
            self.assertEqual(mod.vscode_user_dirs(home), [])
            self._configure(mod, name, "SECRETKEY", home)
            self.assertFalse((outside / "User" / "settings.json").exists())


class OtelSettingsEndpointAndBackupTests(_OtelHelpers, unittest.TestCase):
    def test_rotating_the_key_never_leaves_the_old_one_in_the_backup(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"editor.fontSize": 12}')
            self._configure(mod, name, "OLDKEY", home)
            self._configure(mod, name, "NEWKEY", home)
            backup = settings.with_suffix(".json.unbound-bak")
            text = backup.read_text(encoding="utf-8")
            self.assertNotIn("OLDKEY", text)
            self.assertNotIn("NEWKEY", text)
            self.assertIn("NEWKEY", settings.read_text(encoding="utf-8"))

    def test_a_plaintext_gateway_never_receives_the_key(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod)
            self.assertFalse(
                self._configure(mod, name, "SECRETKEY", home, gateway="http://internal-gw.local"))
            self.assertFalse(settings.exists())

    def test_a_bare_host_is_treated_as_https_and_still_configured(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod)
            self.assertTrue(self._configure(mod, name, "KEY", home, gateway="internal-gw.local"))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["github.copilot.chat.otel.otlpEndpoint"],
                             "https://internal-gw.local/otel")

    def test_a_loopback_collector_is_allowed_for_local_testing(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod)
            self.assertTrue(
                self._configure(mod, name, "KEY", home, gateway="http://localhost:4318"))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["github.copilot.chat.otel.otlpEndpoint"],
                             "http://localhost:4318/otel")


class OtelSettingsSyncAndLegacyBackupTests(_OtelHelpers, unittest.TestCase):
    def test_a_legacy_backup_holding_a_key_is_stripped_on_the_next_run(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"editor.fontSize": 12}')
            backup = settings.with_suffix(".json.unbound-bak")
            backup.write_text(
                '{"editor.fontSize": 12,'
                ' "github.copilot.chat.otel.headers": {"x-api-key": "LEGACYKEY"}}',
                encoding="utf-8")
            self._configure(mod, name, "NEWKEY", home)
            text = backup.read_text(encoding="utf-8")
            self.assertNotIn("LEGACYKEY", text)
            self.assertIn("editor.fontSize", text)
            if platform.system() != "Windows":
                self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_the_header_is_excluded_from_settings_sync(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"editor.fontSize": 12}')
            self._configure(mod, name, "KEY", home)
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertIn("github.copilot.chat.otel.headers",
                          parsed["settingsSync.ignoredSettings"])

    def test_the_users_own_ignored_settings_are_kept(self):
        original = '{"settingsSync.ignoredSettings": ["editor.fontSize"]}'
        for name, mod in self._each():
            home, settings = self._home_with(mod, original)
            self._configure(mod, name, "KEY", home)
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["settingsSync.ignoredSettings"],
                             ["editor.fontSize", "github.copilot.chat.otel.headers"])
            self.assertEqual(self._clear(mod, name, home), "cleared")
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["settingsSync.ignoredSettings"], ["editor.fontSize"])

    def test_the_ignore_list_is_removed_when_only_our_entry_was_in_it(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"editor.fontSize": 12}')
            self._configure(mod, name, "KEY", home)
            self.assertEqual(self._clear(mod, name, home), "cleared")
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertNotIn("settingsSync.ignoredSettings", parsed)
            self.assertEqual(parsed["editor.fontSize"], 12)

    def test_running_setup_twice_still_leaves_one_ignore_entry(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"editor.fontSize": 12}')
            self._configure(mod, name, "KEY", home)
            self._configure(mod, name, "KEY", home)
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["settingsSync.ignoredSettings"].count(
                "github.copilot.chat.otel.headers"), 1)


class OtelSettingsTopLevelOnlyTests(_OtelHelpers, unittest.TestCase):
    NESTED = ('{"unbound.backup": {"github.copilot.chat.otel.headers": {"x-api-key": "OLDKEY"}},'
              ' "editor.fontSize": 12}')

    def test_a_nested_copy_of_a_key_does_not_absorb_the_write(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, self.NESTED)
            self.assertTrue(self._configure(mod, name, "NEWKEY", home))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["github.copilot.chat.otel.headers"], {"x-api-key": "NEWKEY"})
            self.assertEqual(parsed["github.copilot.chat.otel.otlpEndpoint"],
                             "https://api.getunbound.ai/otel")
            self.assertEqual(parsed["unbound.backup"],
                             {"github.copilot.chat.otel.headers": {"x-api-key": "OLDKEY"}})

    def test_clear_leaves_a_nested_copy_alone(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, self.NESTED)
            self._configure(mod, name, "NEWKEY", home)
            self.assertEqual(self._clear(mod, name, home), "cleared")
            text = settings.read_text(encoding="utf-8")
            self.assertNotIn("NEWKEY", text)
            parsed = mod._parse_jsonc_or_none(text)
            self.assertEqual(parsed["unbound.backup"],
                             {"github.copilot.chat.otel.headers": {"x-api-key": "OLDKEY"}})
            self.assertEqual(parsed["editor.fontSize"], 12)

    def test_a_string_value_naming_one_of_our_keys_is_left_alone(self):
        original = json.dumps({"note": 'see "github.copilot.chat.otel.headers": x', "a": 1})
        for name, mod in self._each():
            home, settings = self._home_with(mod, original)
            self.assertTrue(self._configure(mod, name, "KEY", home))
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertEqual(parsed["note"], 'see "github.copilot.chat.otel.headers": x')
            self.assertEqual(parsed["github.copilot.chat.otel.headers"], {"x-api-key": "KEY"})

    def test_a_key_inside_a_language_block_is_not_touched(self):
        original = ('{"[python]": {"github.copilot.chat.otel.enabled": false},'
                    ' "editor.fontSize": 12}')
        for name, mod in self._each():
            home, settings = self._home_with(mod, original)
            self._configure(mod, name, "KEY", home)
            parsed = mod._parse_jsonc_or_none(settings.read_text(encoding="utf-8"))
            self.assertTrue(parsed["github.copilot.chat.otel.enabled"])
            self.assertFalse(parsed["[python]"]["github.copilot.chat.otel.enabled"])
