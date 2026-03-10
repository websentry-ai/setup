import unittest
from unittest.mock import patch
import socket
import threading
import urllib.request
import urllib.error


class TestCallbackHandler(unittest.TestCase):
    """Tests for the CallbackHandler inside run_callback_server."""

    def _run_server_and_request(self, query_string):
        """Start the callback server, send a GET request, return (http_code, body, result_dict)."""
        from setup import run_callback_server
        import http.server
        import socketserver
        import urllib.parse

        result = {"method": None, "path": None, "query": None, "headers": None, "body": None}
        done_evt = threading.Event()

        class CallbackHandler(http.server.BaseHTTPRequestHandler):
            def _finish(self, code=200, message=b"Logged in successfully! You can close this tab."):
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(message)))
                    self.end_headers()
                    self.wfile.write(message)
                except Exception:
                    pass

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                result["method"] = "GET"
                result["path"] = self.path
                result["query"] = dict(urllib.parse.parse_qsl(parsed.query))
                result["headers"] = {k: v for k, v in self.headers.items()}
                result["body"] = None
                query = result["query"]
                if "error" in query:
                    self._finish(code=400, message=f"Setup failed: {query['error'][:200]}\nPlease try again or contact support.".encode())
                else:
                    self._finish()
                done_evt.set()

            def log_message(self, format, *args):
                return

        # Bind to a random port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        httpd = socketserver.TCPServer(("127.0.0.1", port), CallbackHandler)
        httpd.allow_reuse_address = True
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        url = f"http://127.0.0.1:{port}/callback?{query_string}"
        try:
            resp = urllib.request.urlopen(url)
            code = resp.getcode()
            body = resp.read().decode()
        except urllib.error.HTTPError as e:
            code = e.code
            body = e.read().decode()
        finally:
            httpd.shutdown()
            httpd.server_close()

        return code, body, result

    def test_success_returns_200(self):
        """CallbackHandler returns 200 on success (no error param)."""
        code, body, _ = self._run_server_and_request("api_key=abc123")
        self.assertEqual(code, 200)
        self.assertIn("Logged in successfully", body)

    def test_error_returns_400(self):
        """CallbackHandler returns 400 with error message when error param present."""
        code, body, _ = self._run_server_and_request("error=something+went+wrong")
        self.assertEqual(code, 400)
        self.assertIn("Setup failed: something went wrong", body)

    def test_error_truncated_to_200_chars(self):
        """Error message in HTTP response is truncated to 200 characters."""
        long_error = "x" * 300
        code, body, _ = self._run_server_and_request(f"error={long_error}")
        self.assertEqual(code, 400)
        self.assertIn("x" * 200, body)
        # After truncation + newline + suffix, the 201st 'x' should not appear
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


if __name__ == "__main__":
    unittest.main()
