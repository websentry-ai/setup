import unittest
from unittest.mock import patch
import json
import os
import shutil
import socket
import tempfile
import threading
import urllib.request
import urllib.error
import urllib.parse
import time
from pathlib import Path


class TestCallbackHandler(unittest.TestCase):
    """Tests for the CallbackHandler inside run_callback_server.

    These tests exercise the real run_callback_server function by mocking
    webbrowser.open to intercept the URL, then sending an HTTP request
    to the actual server it spins up.
    """

    def _run_server_with_query(self, query_string):
        """Call run_callback_server, intercept its URL, hit it with query_string.

        Returns (http_status, response_body, result_dict).
        """
        from setup import run_callback_server

        captured_url = {}
        http_response = {}

        def fake_browser_open(url):
            """Instead of opening a browser, parse the callback_url and hit it."""
            captured_url["browser_url"] = url
            parsed = urllib.parse.urlparse(url)
            qs = dict(urllib.parse.parse_qsl(parsed.query))
            callback_url = qs.get("callback_url", "")
            target = f"{callback_url}?{query_string}"
            captured_url["target"] = target

            # Small delay to let the server finish binding
            time.sleep(0.05)

            try:
                resp = urllib.request.urlopen(target)
                http_response["code"] = resp.getcode()
                http_response["body"] = resp.read().decode()
            except urllib.error.HTTPError as e:
                http_response["code"] = e.code
                http_response["body"] = e.read().decode()

        with patch("webbrowser.open", side_effect=fake_browser_open):
            result = run_callback_server("https://example.com")

        self._last_browser_url = captured_url.get("browser_url", "")
        return http_response.get("code"), http_response.get("body", ""), result

    def test_success_returns_200(self):
        """CallbackHandler returns 200 on success (no error param)."""
        code, body, result = self._run_server_with_query("api_key=abc123")
        self.assertEqual(code, 200)
        self.assertIn("Logged in successfully", body)
        self.assertEqual(result["query"]["api_key"], "abc123")

    def test_app_type_is_augment(self):
        """The callback target URL declares app_type=augment."""
        self._run_server_with_query("api_key=abc123")
        self.assertIn("app_type=augment", self._last_browser_url)

    def test_error_returns_400(self):
        """CallbackHandler returns 400 with error message when error param present."""
        code, body, result = self._run_server_with_query("error=something+went+wrong")
        self.assertEqual(code, 400)
        self.assertIn("Setup failed: something went wrong", body)

    def test_error_truncated_to_200_chars(self):
        """Error message in HTTP response is truncated to 200 characters."""
        long_error = "x" * 300
        code, body, _ = self._run_server_with_query(f"error={long_error}")
        self.assertEqual(code, 400)
        self.assertIn("x" * 200, body)
        self.assertNotIn("x" * 201, body)


class TestMainErrorHandling(unittest.TestCase):
    """Tests for error display in main()."""

    def _run_main_with_callback(self, query):
        """Run main() with a mocked callback response and capture stdout."""
        import setup
        import sys
        from io import StringIO

        with patch("setup.run_callback_server") as mock_server, \
             patch("setup.install_macos_certificates"), \
             patch("setup.check_enterprise_hooks_conflict", return_value=False):
            mock_server.return_value = {
                "method": "GET",
                "path": "/callback",
                "query": query,
                "headers": {},
                "body": None,
            }

            old_argv = sys.argv
            sys.argv = ["setup.py", "--domain", "example.com"]
            captured = StringIO()
            old_stdout = sys.stdout
            sys.stdout = captured
            try:
                setup.main()
            finally:
                sys.stdout = old_stdout
                sys.argv = old_argv

        return captured.getvalue()

    def test_main_prints_specific_error(self):
        """main() prints specific error when callback has error param."""
        output = self._run_main_with_callback({"error": "token expired"})
        self.assertIn("Setup failed: token expired", output)

    def test_ansi_stripped_from_terminal_output(self):
        """ANSI escape sequences are stripped from terminal error output."""
        output = self._run_main_with_callback({"error": "\x1b[31mred error\x1b[0m"})
        self.assertNotIn("\x1b", output)
        self.assertIn("red error", output)

    def test_error_truncated_in_terminal(self):
        """Error message displayed in terminal is truncated to 200 chars."""
        long_error = "A" * 300
        output = self._run_main_with_callback({"error": long_error})
        self.assertIn("A" * 200, output)
        self.assertNotIn("A" * 201, output)


class TestMdmWriteConfigReportsSuccess(unittest.TestCase):
    """A successful per-user config write must NOT be logged as a failure.

    Regression for the missing ``return True`` in the privilege-dropped
    ``_write`` closure of ``write_unbound_config_for_user``: without it the
    closure returned None on success, ``_run_as_user`` relayed that None, and
    the caller misreported every successful write as
    ``Could not write config for <user>``.
    """

    _REPO_ROOT = Path(__file__).resolve().parents[2]
    TOOLS = {
        "augment": _REPO_ROOT / "augment" / "hooks" / "mdm" / "setup.py",
    }

    @staticmethod
    def _load(name, path):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            f"mdm_setup_{name.replace('-', '_')}", str(path)
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_successful_write_is_not_reported_as_failure(self):
        for name, path in self.TOOLS.items():
            with self.subTest(tool=name):
                mdm = self._load(name, path)
                logs = []
                home = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, home, ignore_errors=True)

                # Mimic a successful privilege drop: _run_as_user runs the
                # callback in-process and relays its return value verbatim.
                def fake_run_as_user(username, fn, *args, **kwargs):
                    return fn(*args, **kwargs)

                with patch.object(mdm, "_run_as_user", side_effect=fake_run_as_user), \
                     patch.object(mdm, "_repair_user_ownership", lambda *a, **k: None), \
                     patch.object(mdm, "debug_print", side_effect=logs.append):
                    mdm.write_unbound_config_for_user(
                        "tester", home, "sk-test-key",
                        urls={"base_url": "https://backend", "gateway_url": "https://gw"},
                    )

                config_file = home / ".unbound" / "config.json"
                self.assertTrue(config_file.exists(), f"{name}: config.json was not written")
                data = json.loads(config_file.read_text())
                self.assertEqual(data["api_key"], "sk-test-key")
                self.assertEqual(data["base_url"], "https://backend")
                self.assertFalse(
                    any("Could not write config" in m for m in logs),
                    f"{name}: success path falsely logged a failure: {logs}",
                )


class TestConversationDataFlag(unittest.TestCase):
    """The augment Stop hook must request conversation data so the end-of-turn
    exchange has the user prompt — otherwise every tool-bearing turn is dropped
    and the hook floods the gateway/Sentry with `dropped_turn`."""

    _REPO_ROOT = Path(__file__).resolve().parents[2]
    _MDM = _REPO_ROOT / "augment" / "hooks" / "mdm" / "setup.py"

    @classmethod
    def _load_mdm(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("mdm_setup_augment_conv", str(cls._MDM))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_build_hooks_block_stop_requests_conversation_data(self):
        import setup
        for name, mod in (("user", setup), ("mdm", self._load_mdm())):
            with self.subTest(variant=name):
                stop = mod.build_hooks_block("/x/unbound.py")["Stop"]
                self.assertIs(stop[0]["metadata"]["includeConversationData"], True)

    def test_configure_writes_conversation_flag_on_fresh_install(self):
        import setup
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        (home / ".augment" / "hooks").mkdir(parents=True)
        with patch("pathlib.Path.home", return_value=home):
            self.assertTrue(setup.configure_augment_settings())
        settings = json.loads((home / ".augment" / "settings.json").read_text())
        stop = settings["hooks"]["Stop"]
        self.assertIs(stop[0]["metadata"]["includeConversationData"], True)

    def test_configure_upgrades_existing_stop_block_missing_flag(self):
        """A device installed before the fix has our Stop hook but no metadata.
        Re-running setup must inject includeConversationData in place, without
        duplicating the hook or the block."""
        import setup
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        (home / ".augment" / "hooks").mkdir(parents=True)
        our_cmd = str(home / ".augment" / "hooks" / "unbound.py")
        (home / ".augment" / "settings.json").write_text(json.dumps(
            {"hooks": {"Stop": [{"hooks": [
                {"type": "command", "command": our_cmd, "timeout": 10000}]}]}}
        ))
        with patch("pathlib.Path.home", return_value=home):
            self.assertTrue(setup.configure_augment_settings())
        settings = json.loads((home / ".augment" / "settings.json").read_text())
        stop = settings["hooks"]["Stop"]
        self.assertEqual(len(stop), 1)              # no duplicate block
        self.assertEqual(len(stop[0]["hooks"]), 1)  # no duplicate hook entry
        self.assertIs(stop[0]["metadata"]["includeConversationData"], True)

    def test_clear_drops_conversation_flag_from_surviving_shared_block(self):
        """Uninstall symmetry: when our hook shared a Stop block with a foreign
        hook, removing our hook must also drop the includeConversationData flag we
        set — the foreign hook and block stay intact."""
        import setup
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        (home / ".augment" / "hooks").mkdir(parents=True)
        our_cmd = str(home / ".augment" / "hooks" / "unbound.py")
        (home / ".augment" / "settings.json").write_text(json.dumps(
            {"hooks": {"Stop": [{
                "hooks": [
                    {"type": "command", "command": our_cmd, "timeout": 10000},
                    {"type": "command", "command": "/foreign/hook", "timeout": 5000},
                ],
                "metadata": {"includeConversationData": True},
            }]}}
        ))
        with patch("pathlib.Path.home", return_value=home):
            self.assertEqual(setup.remove_hooks_from_settings(), "cleared")
        block = json.loads((home / ".augment" / "settings.json").read_text())["hooks"]["Stop"][0]
        self.assertEqual([h["command"] for h in block["hooks"]], ["/foreign/hook"])
        self.assertNotIn("includeConversationData", block.get("metadata", {}))

    def test_mdm_user_level_clear_drops_conversation_flag(self):
        """MDM per-user cleanup (remove_user_level_hooks_for_user) must also drop
        the flag from a surviving shared Stop block — parity with the user-level
        and managed clear paths."""
        mdm = self._load_mdm()
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        (home / ".augment" / "hooks").mkdir(parents=True)
        our_cmd = str(home / ".augment" / "hooks" / "unbound.py")
        (home / ".augment" / "settings.json").write_text(json.dumps(
            {"hooks": {"Stop": [{
                "hooks": [
                    {"type": "command", "command": our_cmd, "timeout": 10000},
                    {"type": "command", "command": "/foreign/hook", "timeout": 5000},
                ],
                "metadata": {"includeConversationData": True},
            }]}}
        ))

        def fake_run_as_user(username, fn, *args, **kwargs):
            return fn(*args, **kwargs)

        with patch.object(mdm, "_run_as_user", side_effect=fake_run_as_user), \
             patch.object(mdm, "debug_print", lambda *a, **k: None):
            mdm.remove_user_level_hooks_for_user("tester", home)
        block = json.loads((home / ".augment" / "settings.json").read_text())["hooks"]["Stop"][0]
        self.assertEqual([h["command"] for h in block["hooks"]], ["/foreign/hook"])
        self.assertNotIn("includeConversationData", block.get("metadata", {}))


if __name__ == "__main__":
    unittest.main()
