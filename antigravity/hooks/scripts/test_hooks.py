"""Integration tests for the Antigravity hook scripts.

Run with:

    cd antigravity/hooks/scripts && python3 -m unittest test_hooks.py -v

Tests drive ``pre_tool_use.py``, ``post_tool_use.py``,
``user_prompt_submit.py``, and ``session_start.py`` end-to-end by
spawning a subprocess, piping the chop-verified golden Antigravity
stdin payload in, and asserting on stdout / exit code. The gateway POST
is intercepted by a local HTTP server bound on 127.0.0.1:<random> that
records each request the hook makes — no real network calls.

Golden payloads are lifted verbatim from ``AgusRdz/chop:hooks/antigravity_test.go``.
"""

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent


# --- Golden payloads (verbatim from AgusRdz/chop:hooks/antigravity_test.go) ---

GOLDEN_PRE_TOOL_USE_BASH = {
    "session_id": "test",
    "cwd": "/tmp",
    "hook_event_name": "PreToolUse",
    "tool_name": "bash",
    "tool_input": {"command": "git status"},
}

GOLDEN_PRE_TOOL_USE_BASH_PASCAL = {
    "session_id": "test",
    "cwd": "/tmp",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "git status"},
}

GOLDEN_PRE_TOOL_USE_NON_BASH = {
    "session_id": "test",
    "cwd": "/tmp",
    "hook_event_name": "PreToolUse",
    "tool_name": "FileRead",
    "tool_input": {"path": "test.txt"},
}

GOLDEN_USER_PROMPT_SUBMIT = {
    "session_id": "test",
    "cwd": "/tmp",
    "hook_event_name": "UserPromptSubmit",
    "prompt": "hello",
}

GOLDEN_SESSION_START = {
    "session_id": "test",
    "cwd": "/tmp",
    "hook_event_name": "SessionStart",
}


class _FakeGateway:
    """Local HTTP server stand-in for the Unbound gateway.

    Records every incoming request (path/method/headers/body) into
    ``requests`` and replies with the configured ``response_body`` +
    ``status``. Bind on ``127.0.0.1:0`` so tests can run in parallel.
    """

    def __init__(self, response_body: dict = None, status: int = 200):
        self.response_body = response_body if response_body is not None else {}
        self.status = status
        self.requests = []  # list of dicts: {path, method, headers, body}
        self._server = None
        self._thread = None

    def __enter__(self):
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def _read_and_record(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length > 0 else b""
                outer.requests.append({
                    "path": self.path,
                    "method": method,
                    "headers": {k: v for k, v in self.headers.items()},
                    "body": body.decode("utf-8", errors="replace"),
                })

            def do_POST(self):  # noqa: N802
                self._read_and_record("POST")
                payload = json.dumps(outer.response_body).encode("utf-8")
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):  # noqa: A002
                return  # silence default stderr logging

        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"


def _closed_port_url() -> str:
    """Bind a socket to 127.0.0.1:0, read the port, close the socket.
    The returned URL points at a port nothing is listening on — connections
    will fail fast with ECONNREFUSED."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def _run_hook_script(
    script_name: str,
    stdin_payload: dict,
    gateway_url: str,
    api_key: str = "test-api-key",
    home: Path = None,
    extra_path_dir: Path = None,
):
    """Invoke ``scripts/<script_name>`` as a child Python process with a
    sandboxed HOME. The gateway URL is injected via env so the hook posts
    to our local test server. Returns the completed subprocess."""
    tmp = home if home else Path(tempfile.mkdtemp())
    cfg_dir = tmp / ".unbound"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config.json").write_text(
        json.dumps({"api_key": api_key, "gateway_url": gateway_url})
    )

    env = os.environ.copy()
    env["HOME"] = str(tmp)
    env["USERPROFILE"] = str(tmp)
    if extra_path_dir is not None:
        env["PATH"] = f"{extra_path_dir}{os.pathsep}{env.get('PATH', '')}"
    # Don't let real env vars override the config-file values during tests.
    env.pop("UNBOUND_API_KEY", None)
    env.pop("UNBOUND_GATEWAY_URL", None)

    proc = subprocess.run(
        [sys.executable, str(SCRIPT_DIR / script_name)],
        input=json.dumps(stdin_payload).encode("utf-8"),
        capture_output=True,
        env=env,
        timeout=10,
    )
    return proc


class TestPreToolUseDecisions(unittest.TestCase):
    """The only hook that emits a non-empty stdout: pre_tool_use.py."""

    def test_allow_emits_silent_stdout(self):
        """Gateway returns ``allow`` → we print NOTHING and exit 0."""
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
                gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_deny_emits_hook_specific_output(self):
        """Gateway returns ``deny`` → we emit camelCase hookSpecificOutput."""
        with _FakeGateway(response_body={
            "decision": "deny",
            "reason": "Blocked by org policy.",
        }) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
                gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout.decode())
        self.assertIn("hookSpecificOutput", out)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertEqual(hso["permissionDecisionReason"], "Blocked by org policy.")

    def test_ask_emits_hook_specific_output(self):
        with _FakeGateway(response_body={"decision": "ask"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
                gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout.decode())
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_pascal_case_bash_works_too(self):
        """The chop fixtures show Antigravity emits both 'bash' and 'Bash' —
        our hook must handle either casing."""
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH_PASCAL,
                gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            # We should still have POSTed to the gateway.
            self.assertEqual(len(gw.requests), 1)
            body = json.loads(gw.requests[0]["body"])
        # tool_name in the request body must be canonicalised to "Bash".
        self.assertEqual(body["pre_tool_use_data"]["tool_name"], "Bash")

    def test_non_bash_tool_still_calls_gateway(self):
        """Non-bash tools (FileRead, Write, etc.) are checked too — gateway
        decides whether they're policy-relevant, not the hook script."""
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_NON_BASH,
                gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(len(gw.requests), 1)


class TestPreToolUseFailOpen(unittest.TestCase):
    """Iron law: never block the agent on our infra. Any infra failure
    (HTTP non-2xx, malformed JSON, unreachable gateway) must result in
    silent exit 0 (== allow)."""

    def test_gateway_5xx_is_silent_allow(self):
        with _FakeGateway(response_body={}, status=500) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
                gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_gateway_unreachable_is_silent_allow(self):
        """Connection refused → fail open, exit 0, no stdout."""
        proc = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
            gateway_url=_closed_port_url(),
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_gateway_returns_garbage_is_silent_allow(self):
        """Even with HTTP 200, non-JSON body → fail open."""

        class _GarbageHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                payload = b"not json at all"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):  # noqa: A002
                return

        server = HTTPServer(("127.0.0.1", 0), _GarbageHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
                gateway_url=f"http://{host}:{port}",
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
        finally:
            server.shutdown()
            server.server_close()

    def test_no_api_key_is_silent_allow(self):
        """If ~/.unbound/config.json is absent and no env override is set,
        we silently allow — never crash, never block."""
        tmp = Path(tempfile.mkdtemp())
        env = os.environ.copy()
        env["HOME"] = str(tmp)
        env["USERPROFILE"] = str(tmp)
        env.pop("UNBOUND_API_KEY", None)
        env.pop("UNBOUND_GATEWAY_URL", None)
        try:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT_DIR / "pre_tool_use.py")],
                input=json.dumps(GOLDEN_PRE_TOOL_USE_BASH).encode(),
                capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_malformed_stdin_is_silent_allow(self):
        """Garbage on stdin → exit 0 silently. Never raise."""
        tmp = Path(tempfile.mkdtemp())
        env = os.environ.copy()
        env["HOME"] = str(tmp)
        env["USERPROFILE"] = str(tmp)
        try:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT_DIR / "pre_tool_use.py")],
                input=b"not json at all",
                capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestTelemetryHooks(unittest.TestCase):
    """post_tool_use, user_prompt_submit, session_start: telemetry only.
    Exit 0, no stdout, regardless of gateway response."""

    def test_post_tool_use_is_silent_and_posts(self):
        with _FakeGateway(response_body={
            "decision": "deny", "reason": "should be ignored",
        }) as gw:
            proc = _run_hook_script(
                "post_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
                gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(len(gw.requests), 1, "post_tool_use must POST telemetry")

    def test_user_prompt_submit_is_silent_and_posts(self):
        with _FakeGateway(response_body={"decision": "deny"}) as gw:
            proc = _run_hook_script(
                "user_prompt_submit.py", GOLDEN_USER_PROMPT_SUBMIT,
                gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(len(gw.requests), 1)

    def test_session_start_is_silent_and_posts(self):
        with _FakeGateway(response_body={"decision": "deny"}) as gw:
            proc = _run_hook_script(
                "session_start.py", GOLDEN_SESSION_START,
                gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(len(gw.requests), 1)


class TestRequestBody(unittest.TestCase):
    """Verify the POSTed body matches PretoolRequestBody shape from
    ai-gateway/src/handlers/preToolUseHandler.ts:86-100."""

    def test_request_body_shape_for_bash_command(self):
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
                gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(len(gw.requests), 1)
            body = json.loads(gw.requests[0]["body"])

        # PretoolRequestBody required fields:
        self.assertEqual(body["conversation_id"], "test")
        self.assertEqual(body["event_name"], "PreToolUse")
        self.assertEqual(body["unbound_app_label"], "antigravity")
        self.assertIn("model", body)
        # pre_tool_use_data
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["tool_name"], "Bash")
        self.assertEqual(ptud["command"], "git status")
        self.assertIn("metadata", ptud)
        # The original snake_case payload is preserved in metadata.
        self.assertEqual(ptud["metadata"]["cwd"], "/tmp")

    def test_authorization_header_is_set(self):
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
                gateway_url=gw.url,
                api_key="my-secret-key",
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(len(gw.requests), 1)
            req = gw.requests[0]
        # Authorization header is set (case-insensitive lookup) and the
        # request lands on /hooks/antigravity.
        headers_lower = {k.lower(): v for k, v in req["headers"].items()}
        self.assertEqual(headers_lower.get("authorization"), "Bearer my-secret-key")
        self.assertEqual(headers_lower.get("content-type"), "application/json")
        self.assertEqual(req["path"], "/hooks/antigravity")
        self.assertEqual(req["method"], "POST")


class TestNoCurlAtRuntime(unittest.TestCase):
    """Regression lock-in: ``post_to_gateway`` MUST NOT shell out to ``curl``.

    Passing ``Authorization: Bearer <key>`` on curl's argv leaks the bearer
    token to any other user on the device via ``ps auxe`` /
    ``/proc/<pid>/cmdline``. The fix is to use stdlib urllib (headers stay
    inside the process). We assert that by putting a fake ``curl`` shim
    first on PATH and verifying it never gets invoked end-to-end across
    pre_tool_use and the telemetry hooks. Mirrors
    ``TestNotifySetupCompleteNoCurl`` in ``antigravity/hooks/test_setup.py``.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # Fake curl shim that logs every invocation.
        self.bin_dir = self.tmp / "bin"
        self.bin_dir.mkdir()
        self.curl_log = self.tmp / "curl.log"
        fake = self.bin_dir / "curl"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"with open({repr(str(self.curl_log))}, 'a') as f:\n"
            "    f.write(' '.join(sys.argv) + '\\n')\n"
            "sys.exit(0)\n"
        )
        os.chmod(fake, fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _assert_no_curl(self, script_name: str, payload: dict) -> None:
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                script_name, payload,
                gateway_url=gw.url,
                home=self.tmp,
                extra_path_dir=self.bin_dir,
            )
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(
            self.curl_log.exists(),
            f"curl was invoked from {script_name} — bearer token leaked via argv",
        )

    def test_pre_tool_use_does_not_invoke_curl(self):
        self._assert_no_curl("pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH)

    def test_post_tool_use_does_not_invoke_curl(self):
        self._assert_no_curl("post_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH)

    def test_user_prompt_submit_does_not_invoke_curl(self):
        self._assert_no_curl("user_prompt_submit.py", GOLDEN_USER_PROMPT_SUBMIT)

    def test_session_start_does_not_invoke_curl(self):
        self._assert_no_curl("session_start.py", GOLDEN_SESSION_START)


if __name__ == "__main__":
    unittest.main()
