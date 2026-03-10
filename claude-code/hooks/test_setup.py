import unittest
from unittest.mock import patch
import socket
import threading
import urllib.request
import urllib.error
import urllib.parse
import time


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

        return http_response.get("code"), http_response.get("body", ""), result

    def test_success_returns_200(self):
        """CallbackHandler returns 200 on success (no error param)."""
        code, body, result = self._run_server_with_query("api_key=abc123")
        self.assertEqual(code, 200)
        self.assertIn("Logged in successfully", body)
        self.assertEqual(result["query"]["api_key"], "abc123")

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
             patch("setup.install_macos_certificates"):
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

    def test_cb_response_error_without_guard(self):
        """Error path works when cb_response is non-None with no api_key.

        Validates that removing the redundant 'if cb_response else None'
        guard does not break error extraction -- cb_response is guaranteed
        non-None at that point because line 543-545 returns early if None.
        """
        output = self._run_main_with_callback({"error": "access denied"})
        self.assertIn("Setup failed: access denied", output)
        self.assertNotIn("No API key received", output)


if __name__ == "__main__":
    unittest.main()
