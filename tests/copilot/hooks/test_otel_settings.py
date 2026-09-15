"""Copilot OTLP export settings.

The exporter is configured through Copilot's managed settings, which only the MDM
installer can write, so this is MDM-only: the user-level installer no longer touches
telemetry at all. The MDM path still takes the VS Code keys earlier versions wrote
back out, so the seeding helper here stands in for that older install and the clear
tests run against real settings files.
"""

import importlib.util
import json
import os
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
    "mdm": (_REPO_ROOT / "copilot" / "hooks" / "mdm" / "setup.py", "clear_otel_export_for_user"),
}

# What an install from before the move to managed settings left on the machine.
LEGACY_SETTINGS = {
    "github.copilot.chat.otel.enabled": True,
    "github.copilot.chat.otel.exporterType": "otlp-http",
    "github.copilot.chat.otel.otlpEndpoint": "https://api.getunbound.ai/otel",
    "github.copilot.chat.otel.headers": {"x-api-key": "sk-live-abc"},
    "github.copilot.chat.otel.captureContent": False,
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
        """Seed the keys an older install wrote, through the module's own writer.

        Not a call into a writer any more: nothing writes these now. Going through
        _write_settings keeps the JSONC round-trip under test, which is what every
        hostile-input case below is actually about.
        """
        dirs = mod.vscode_user_dirs(home)
        if not dirs:
            return True
        results = []
        for directory in dirs:
            settings_path = directory / "settings.json"
            existing = mod._parse_jsonc_or_none(
                mod._read_settings_text(settings_path) or "") if settings_path.exists() else None
            ignored = existing.get("settingsSync.ignoredSettings") if isinstance(
                existing, dict) else None
            ignored = [i for i in ignored if isinstance(i, str)] if isinstance(ignored, list) else []
            if mod.OTEL_HEADERS_KEY not in ignored:
                ignored = ignored + [mod.OTEL_HEADERS_KEY]
            updates = dict(
                LEGACY_SETTINGS,
                **{"github.copilot.chat.otel.headers": {"x-api-key": api_key},
                   "settingsSync.ignoredSettings": ignored})
            results.append(mod._write_settings(settings_path, updates, home))
        return all(results)

    def _clear(self, mod, name, home):
        fn = getattr(mod, MODULES[name][1])
        with self._passthrough(mod):
            return fn("someuser", home)

    def _each(self):
        for name, (path, _) in MODULES.items():
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


    def test_a_settings_file_that_does_not_parse_is_left_alone(self):
        for name, mod in self._each():
            home, path = self._home_with(mod, "{ this is not json at all ")
            self.assertFalse(self._configure(mod, name, "k", home))
            self.assertEqual(path.read_text(), "{ this is not json at all ")

    def test_no_vscode_directory_is_not_a_failure(self):
        """A device without VS Code must not fail the clear, and must not have a
        settings directory conjured for an editor it does not run."""
        for name, mod in self._each():
            home = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, home, ignore_errors=True)
            self.assertEqual(self._clear(mod, name, home), "not_found")
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
            self.assertEqual(got["[python]"], {"editor.tabSize": 4})

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

    def test_the_mdm_clear_drops_privileges_before_touching_a_user_home(self):
        mod = _load("mdm", MODULES["mdm"][0])
        home, _ = self._home_with(mod, '{ "editor.fontSize": 12 }')
        seen = []

        def _record(username, fn, *a, **kw):
            seen.append(username)
            return fn(*a, **kw)

        with patch.object(mod, "_run_as_user", _record):
            mod.clear_otel_export_for_user("someuser", home)
        self.assertEqual(seen, ["someuser"])


if __name__ == "__main__":
    unittest.main()


class OtelSettingsHostileInputTests(_OtelHelpers, unittest.TestCase):
    def test_a_settings_file_that_is_not_utf8_does_not_abort_the_install(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, "")
            settings.write_bytes(b"\xff\xfe{\x00}\x00")
            self.assertFalse(self._configure(mod, name, "KEY", home))
            # The file exists and we cannot read it, so clear must not report it clean.
            self.assertEqual(self._clear(mod, name, home), "failed")

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


class OtelSettingsSyncAndLegacyBackupTests(_OtelHelpers, unittest.TestCase):

    def test_the_users_own_ignored_settings_are_kept(self):
        original = '{"settingsSync.ignoredSettings": ["editor.fontSize"]}'
        for name, mod in self._each():
            home, settings = self._home_with(mod, original)
            self._configure(mod, name, "KEY", home)
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


class OtelSettingsHostileFileTypeTests(_OtelHelpers, unittest.TestCase):
    """A settings path the installer does not control: it runs as root over every home."""

    def _replace_with(self, mod, home, make):
        settings = self._user_dir(mod, home) / "settings.json"
        if settings.exists() or settings.is_symlink():
            settings.unlink()
        make(settings)
        return settings

    def test_a_fifo_does_not_block_the_install(self):
        if platform.system() == "Windows":
            self.skipTest("POSIX FIFO")
        for name, mod in self._each():
            home, _ = self._home_with(mod, '{"a": 1}')
            self._replace_with(mod, home, lambda p: os.mkfifo(str(p)))
            started = time.monotonic()
            self.assertFalse(self._configure(mod, name, "KEY", home))
            self.assertLess(time.monotonic() - started, 5.0)

    def test_a_symlink_to_a_character_device_is_refused(self):
        if platform.system() == "Windows":
            self.skipTest("POSIX device nodes")
        for name, mod in self._each():
            home, _ = self._home_with(mod, '{"a": 1}')
            self._replace_with(mod, home, lambda p: p.symlink_to("/dev/zero"))
            started = time.monotonic()
            self.assertFalse(self._configure(mod, name, "KEY", home))
            self.assertLess(time.monotonic() - started, 5.0)

    def test_a_directory_in_place_of_the_file_is_refused(self):
        for name, mod in self._each():
            home, _ = self._home_with(mod, '{"a": 1}')
            self._replace_with(mod, home, lambda p: p.mkdir())
            self.assertFalse(self._configure(mod, name, "KEY", home))

    def test_clear_reports_failure_when_a_configured_file_becomes_unreadable(self):
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"a": 1}')
            self._configure(mod, name, "SECRETKEY", home)
            settings.write_bytes(b"\xff\xfe{\x00}\x00")
            # not_found would tell the caller the device is clean while the key is on disk
            self.assertEqual(self._clear(mod, name, home), "failed")


class OtelSettingsWriteBindingTests(_OtelHelpers, unittest.TestCase):
    def test_a_directory_swapped_after_discovery_is_refused_at_the_write(self):
        if platform.system() == "Windows":
            self.skipTest("POSIX symlink stands in for a junction")
        for name, mod in self._each():
            home, settings = self._home_with(mod, '{"a": 1}')
            user_dir = settings.parent
            outside = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
            # Accepted at discovery, then swapped before the write lands.
            self.assertEqual(mod.vscode_user_dirs(home), [user_dir])
            shutil.rmtree(user_dir)
            user_dir.symlink_to(outside)
            self.assertFalse(mod._write_settings(
                user_dir / "settings.json", {"github.copilot.chat.otel.enabled": True}, home))
            self.assertFalse((outside / "settings.json").exists())
            self.assertEqual(list(outside.glob(".unbound-*")), [])


class ManagedTelemetrySettingsTests(unittest.TestCase):
    """The managed settings file, which is where the exporter is configured now.

    MDM only: the path is root-owned and the user-level installer cannot write it.
    """

    def setUp(self):
        self.mod = _load("mdm", MODULES["mdm"][0])
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.path = self.root / "GitHubCopilot" / "managed-settings.json"

    def _configure(self, api_key="sk-live-abc", gateway="https://api.getunbound.ai"):
        return self.mod.configure_managed_telemetry(api_key, gateway_url=gateway,
                                                    path=self.path)

    def _read(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def test_the_path_matches_what_copilot_reads_on_this_os(self):
        system = platform.system().lower()
        expected = {
            "darwin": "/Library/Application Support/GitHubCopilot/managed-settings.json",
            "linux": "/etc/github-copilot/managed-settings.json",
        }.get(system)
        got = self.mod.managed_settings_path()
        if expected is not None:
            self.assertEqual(str(got), expected)
        elif system == "windows":
            self.assertEqual(got.name, "managed-settings.json")
            self.assertEqual(got.parent.name, "GitHubCopilot")
        else:
            self.assertIsNone(got)

    def test_writes_the_telemetry_block_with_the_key_as_a_header(self):
        self.assertTrue(self._configure())
        telemetry = self._read()["telemetry"]
        self.assertTrue(telemetry["enabled"])
        self.assertEqual(telemetry["headers"], {"x-api-key": "sk-live-abc"})
        self.assertFalse(telemetry["captureContent"])

    def test_the_protocol_is_json_because_that_is_all_the_collector_parses(self):
        # The OTel default is protobuf, which the gateway rejects with nothing
        # surfaced to the device, so an omitted protocol is silent data loss.
        self._configure()
        self.assertEqual(self._read()["telemetry"]["protocol"], "http/json")

    def test_the_endpoint_is_a_base_the_exporter_appends_to(self):
        """The exporter adds /v1/traces itself, so writing the full path would
        produce /otel/v1/traces/v1/traces."""
        self._configure(gateway="https://api.getunbound.ai/")
        self.assertEqual(self._read()["telemetry"]["endpoint"],
                         "https://api.getunbound.ai/otel")

    def test_a_plaintext_gateway_never_receives_the_key(self):
        self.assertFalse(self._configure(gateway="http://internal-gw.local"))
        self.assertFalse(self.path.exists())

    def test_a_loopback_collector_is_allowed_for_local_testing(self):
        self.assertTrue(self._configure(gateway="http://localhost:4318"))
        self.assertEqual(self._read()["telemetry"]["endpoint"],
                         "http://localhost:4318/otel")

    def test_an_administrators_own_settings_are_preserved(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({
            "sandbox": {"enabled": True},
            "telemetry": {"endpoint": "https://someone-elses-collector"},
        }), encoding="utf-8")
        self.assertTrue(self._configure())
        got = self._read()
        self.assertEqual(got["sandbox"], {"enabled": True})
        self.assertEqual(got["telemetry"]["endpoint"], "https://api.getunbound.ai/otel")

    def test_a_file_that_does_not_parse_is_left_alone(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("{ not json", encoding="utf-8")
        self.assertFalse(self._configure())
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{ not json")

    def test_a_top_level_array_is_left_alone(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("[1, 2, 3]", encoding="utf-8")
        self.assertFalse(self._configure())
        self.assertEqual(self.path.read_text(encoding="utf-8"), "[1, 2, 3]")

    def test_a_symlinked_file_is_never_written_through(self):
        # Copilot refuses a symlinked managed file, and following one as root would
        # write wherever it points.
        self.path.parent.mkdir(parents=True)
        target = self.root / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        self.path.symlink_to(target)
        self.assertFalse(self._configure())
        self.assertEqual(target.read_text(encoding="utf-8"), "{}")

    def test_the_file_is_readable_by_the_user_copilot_runs_as(self):
        # Not 0600: Copilot runs as the signed-in user and has to read it. 0644 also
        # satisfies the not-group-or-world-writable rule the loader enforces.
        self._configure()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)

    def test_the_write_leaves_no_staging_file_behind(self):
        self._configure()
        self.assertEqual([p.name for p in self.path.parent.iterdir()],
                         ["managed-settings.json"])

    def test_a_rotated_key_replaces_rather_than_appends(self):
        self._configure(api_key="sk-old")
        self._configure(api_key="sk-new")
        self.assertEqual(self._read()["telemetry"]["headers"], {"x-api-key": "sk-new"})

    def test_clear_removes_our_block_and_keeps_the_rest(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({"sandbox": {"enabled": True}}), encoding="utf-8")
        self._configure()
        self.assertEqual(self.mod.clear_managed_telemetry(path=self.path), "cleared")
        self.assertEqual(self._read(), {"sandbox": {"enabled": True}})

    def test_clear_removes_the_file_when_nothing_else_was_in_it(self):
        self._configure()
        self.assertEqual(self.mod.clear_managed_telemetry(path=self.path), "cleared")
        self.assertFalse(self.path.exists())

    def test_clear_reports_not_found_when_we_never_wrote_anything(self):
        self.assertEqual(self.mod.clear_managed_telemetry(path=self.path), "not_found")
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({"sandbox": {"enabled": True}}), encoding="utf-8")
        self.assertEqual(self.mod.clear_managed_telemetry(path=self.path), "not_found")
        self.assertEqual(self._read(), {"sandbox": {"enabled": True}})

    def test_clear_leaves_a_block_an_administrator_replaced(self):
        # Ours is recognised by its endpoint and header. A block someone else put there
        # after us is theirs, and teardown must not take it.
        self._configure()
        theirs = {"endpoint": "https://collector.corp.internal/v1/traces",
                  "enabled": True}
        self.path.write_text(json.dumps({"telemetry": theirs}), encoding="utf-8")
        self.assertEqual(self.mod.clear_managed_telemetry(path=self.path), "not_found")
        self.assertEqual(self._read()["telemetry"], theirs)

    def test_clear_still_removes_a_block_we_wrote(self):
        # The guard above must not be so tight that our own key survives teardown.
        self._configure()
        self.assertTrue(self.mod._is_our_telemetry(self._read()["telemetry"]))
        self.assertEqual(self.mod.clear_managed_telemetry(path=self.path), "cleared")
        self.assertFalse(self.path.exists())

    def test_clear_removes_what_we_wrote_against_any_gateway(self):
        # Self-hosted tenants get a different host; the mark is the /otel path and the
        # header, not the domain, so their teardown works too.
        self._configure(gateway="https://gw.customer.example")
        self.assertEqual(self.mod.clear_managed_telemetry(path=self.path), "cleared")
        self.assertFalse(self.path.exists())
