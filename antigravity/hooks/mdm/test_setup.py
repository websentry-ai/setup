"""Integration tests for antigravity/hooks/mdm/setup.py.

Run from this directory:

    cd antigravity/hooks/mdm && python3 -m unittest test_setup.py -v

These tests drive the privilege-dropped install payload against a tmpdir-rooted
fake home so the real ``/Users/<you>/.antigravity`` is never touched.

What they cover (and why):

1. ``_write_unbound_config_payload`` actually writes ``~/.unbound/config.json``
   with the API key, mode 0o600, and the gateway/backend URLs. CRITICAL: the
   runtime hook scripts read this file via ``_common.py::load_credentials`` —
   without it every PreToolUse silently fail-opens and the org policy is
   never enforced.

2. ``install_for_user_payload`` (called from inside the fork) drops the
   config file BEFORE the settings.json merge, so a settings.json failure
   never strands a half-installed device with a hook entry pointing at a
   config that doesn't exist.

3. The matcher shape uses the catch-all ``"*"``, not the regex allowlist
   that hardcoded the tool list. Any future tool (WebFetch, WebSearch,
   MultiEdit, NotebookEdit, TodoWrite, ...) still hits our gate.

4. ``notify_setup_complete`` + ``fetch_api_key_from_mdm`` do NOT shell out
   to ``curl`` — passing the API key via curl's argv leaks it to any other
   user on the device through ``ps auxe``.
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path


# Make ``setup`` (this directory's module) importable when tests run from here.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import setup as mdm_setup  # noqa: E402


class TestWriteUnboundConfig(unittest.TestCase):
    """``_write_unbound_config_payload`` is the fix for CRITICAL #1: MDM was
    installing scripts + settings.json but never the credentials file the
    hook scripts read at runtime."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_writes_config_with_api_key(self):
        ok = mdm_setup._write_unbound_config_payload(
            self.home,
            api_key="dev-key",
            gateway_url="https://gw.example.test",
            backend_url="https://be.example.test",
        )
        self.assertTrue(ok)

        config_file = self.home / ".unbound" / "config.json"
        self.assertTrue(config_file.exists())
        with open(config_file, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertEqual(cfg["api_key"], "dev-key")
        self.assertEqual(cfg["gateway_url"], "https://gw.example.test")
        self.assertEqual(cfg["backend_url"], "https://be.example.test")

    @unittest.skipIf(os.name == "nt", "POSIX modes only")
    def test_config_file_mode_is_0600(self):
        mdm_setup._write_unbound_config_payload(
            self.home, api_key="x", gateway_url="https://g.test", backend_url="https://b.test",
        )
        config_file = self.home / ".unbound" / "config.json"
        mode = stat.S_IMODE(config_file.stat().st_mode)
        self.assertEqual(mode, 0o600, f"expected 0o600, got {oct(mode)}")

    @unittest.skipIf(os.name == "nt", "POSIX modes only")
    def test_config_dir_mode_is_0700(self):
        mdm_setup._write_unbound_config_payload(
            self.home, api_key="x", gateway_url="https://g.test", backend_url="https://b.test",
        )
        config_dir = self.home / ".unbound"
        mode = stat.S_IMODE(config_dir.stat().st_mode)
        self.assertEqual(mode, 0o700, f"expected 0o700, got {oct(mode)}")

    def test_preserves_unrelated_existing_fields(self):
        """If a previous tool's setup wrote sibling fields into the same
        config (e.g. claude-code), we must not clobber them."""
        config_dir = self.home / ".unbound"
        config_dir.mkdir()
        existing = config_dir / "config.json"
        existing.write_text(json.dumps({
            "api_key": "old-key",
            "claude_code_specific": "preserve-me",
        }))

        mdm_setup._write_unbound_config_payload(
            self.home, api_key="new-key",
            gateway_url="https://g.test", backend_url="https://b.test",
        )

        with open(existing, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertEqual(cfg["api_key"], "new-key")
        self.assertEqual(cfg["claude_code_specific"], "preserve-me")


class TestInstallForUserPayload(unittest.TestCase):
    """The full per-user install body. Drives it directly (without the fork)
    against a tmpdir home and asserts the credentials file, scripts, and
    settings.json all land."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        # Read script templates the same way run_install does.
        self.templates = {}
        for filename in ["_common.py"] + [
            name.replace("unbound_", "", 1)
            for _e, name in mdm_setup.HOOK_EVENT_SCRIPTS
        ]:
            data = mdm_setup._read_script_template(filename)
            assert data is not None, f"failed to read template {filename}"
            self.templates[filename] = data

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_install_writes_config_scripts_and_settings(self):
        ok = mdm_setup.install_for_user_payload(
            self.home,
            gateway_url="https://gw.example.test",
            backend_url="https://be.example.test",
            api_key="install-key",
            script_templates=self.templates,
        )
        self.assertTrue(ok)

        # 1. Credentials file landed (CRITICAL #1).
        config_file = self.home / ".unbound" / "config.json"
        self.assertTrue(config_file.exists())
        with open(config_file, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertEqual(cfg["api_key"], "install-key")

        # 2. All four hook scripts + _common.py exist.
        hooks_dir = self.home / ".antigravity" / "hooks"
        for _event, installed_name in mdm_setup.HOOK_EVENT_SCRIPTS:
            self.assertTrue((hooks_dir / installed_name).exists())
        self.assertTrue((hooks_dir / "_common.py").exists())

        # 3. settings.json lists every event.
        settings_path = self.home / ".antigravity" / "settings.json"
        self.assertTrue(settings_path.exists())
        with open(settings_path, "r", encoding="utf-8") as f:
            settings = json.load(f)
        for event in ("PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"):
            self.assertIn(event, settings["hooks"])

    def test_matchers_are_catch_all(self):
        """CRITICAL #3 regression: PreToolUse and PostToolUse matchers must
        be ``"*"``, not a tool-name allowlist. Any tool not in the list
        would silently bypass the gate."""
        ok = mdm_setup.install_for_user_payload(
            self.home,
            gateway_url="https://gw.test",
            backend_url="https://be.test",
            api_key="k",
            script_templates=self.templates,
        )
        self.assertTrue(ok)

        with open(self.home / ".antigravity" / "settings.json", "r", encoding="utf-8") as f:
            settings = json.load(f)

        for event in ("PreToolUse", "PostToolUse"):
            ours = None
            for item in settings["hooks"][event]:
                for h in item.get("hooks", []):
                    if "unbound_" in h.get("command", ""):
                        ours = item
                        break
                if ours:
                    break
            self.assertIsNotNone(ours, f"no Unbound entry in {event}")
            self.assertEqual(ours.get("matcher"), "*", f"{event} matcher not catch-all")
            # Hard regression assertion: no allowlist alternation.
            self.assertNotIn("|", ours.get("matcher", ""))

    def test_config_written_before_settings(self):
        """Ordering invariant: if settings.json write fails we MUST still
        have written the credentials file. (If the order were reversed, a
        crash between steps could leave settings.json pointing at scripts
        that have no creds to read.)"""
        original = mdm_setup._atomic_write_json
        seen_config_first = {"value": False}

        def boom(*a, **kw):
            # By the time we try to write settings.json, the config file must
            # already exist.
            cfg = self.home / ".unbound" / "config.json"
            seen_config_first["value"] = cfg.exists()
            raise OSError("simulated settings.json failure")

        try:
            mdm_setup._atomic_write_json = boom
            ok = mdm_setup.install_for_user_payload(
                self.home,
                gateway_url="https://gw.test",
                backend_url="https://be.test",
                api_key="k",
                script_templates=self.templates,
            )
        finally:
            mdm_setup._atomic_write_json = original

        # The install should have failed (settings write raised), but the
        # config file should have landed first.
        self.assertFalse(ok)
        self.assertTrue(
            seen_config_first["value"],
            "config.json was not written before settings.json — ordering bug",
        )


class TestUnknownToolHitsHook(unittest.TestCase):
    """CRITICAL #3: an unfamiliar tool_name like ``WebFetch`` must still
    match the entry we install. With the old allowlist
    ``Bash|bash|Write|Edit|Read|Glob|Grep|Task`` it would not. With ``*``
    it does."""

    def test_webfetch_matches_catch_all(self):
        entry = mdm_setup._build_event_entry(
            "PreToolUse", Path("/tmp/unbound_pre_tool_use.py"),
        )
        # The catch-all matcher means: anything matches.
        self.assertEqual(entry.get("matcher"), "*")


class TestNotifySetupCompleteNoCurl(unittest.TestCase):
    """CRITICAL #2: ``notify_setup_complete`` MUST NOT shell out to ``curl``.
    ``X-API-KEY: <key>`` on argv is visible to every other user on the
    device via ``ps auxe``. We assert the move to urllib by ensuring the
    curl-shim on PATH never gets invoked."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        bin_dir = self.home / "bin"
        bin_dir.mkdir()
        self.curl_log = self.home / "curl.log"
        fake = bin_dir / "curl"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"with open({repr(str(self.curl_log))}, 'a') as f:\n"
            "    f.write(' '.join(sys.argv) + '\\n')\n"
            "sys.exit(0)\n"
        )
        os.chmod(fake, fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self._old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{self._old_path}"

    def tearDown(self):
        os.environ["PATH"] = self._old_path
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_notify_setup_complete_does_not_invoke_curl(self):
        # Closed port → urllib raises URLError, which notify_setup_complete
        # swallows (fail-soft). The relevant assertion is that no curl process
        # ever ran with our secret on argv.
        mdm_setup.notify_setup_complete(
            api_key="super-secret-mdm-key",
            backend_url="http://127.0.0.1:1",
            device_id="DEVICE-1",
        )
        self.assertFalse(
            self.curl_log.exists(),
            "curl was invoked from notify_setup_complete — API key leaked via argv",
        )

    def test_fetch_api_key_does_not_invoke_curl(self):
        # Same shim, but exercise the MDM-key fetch path. URL points at a
        # closed port so urllib raises URLError; fetch returns None. Again,
        # the assertion is that no curl process ran.
        result = mdm_setup.fetch_api_key_from_mdm(
            base_url="http://127.0.0.1:1",
            app_name=None,
            auth_api_key="super-secret-admin-key",
            device_id="DEVICE-1",
        )
        self.assertIsNone(result)
        self.assertFalse(
            self.curl_log.exists(),
            "curl was invoked from fetch_api_key_from_mdm — bearer token leaked via argv",
        )


if __name__ == "__main__":
    unittest.main()
