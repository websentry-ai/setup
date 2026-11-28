"""Integration tests for the Antigravity hook scripts.

Run with:

    cd antigravity/hooks/scripts && python3 -m unittest test_hooks.py -v

Tests drive ``pre_tool_use.py`` and ``post_tool_use.py`` end-to-end by
spawning a subprocess, piping the agy-actual camelCase stdin payload in,
and asserting on stdout / exit code. The gateway POST is intercepted by
a local HTTP server bound on 127.0.0.1:<random> that records each request
the hook makes — no real network calls.

Stdin shapes come from AGY-EMPIRICAL-FINDINGS.md (verified against agy 1.0.5).
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


# --- agy-verified stdin payloads (camelCase, PascalCase arg keys) -------------

GOLDEN_PRE_TOOL_USE_RUN_COMMAND = {
    "artifactDirectoryPath": "/Users/me/.gemini/antigravity-cli/brain/conv-123",
    "conversationId": "conv-123",
    "stepIdx": 1,
    "toolCall": {
        "name": "run_command",
        "args": {
            "CommandLine": "git status",
            "Cwd": "/tmp",
            "Blocking": True,
            "WaitMsBeforeAsync": 1000,
        },
    },
    "transcriptPath": "/Users/me/.gemini/antigravity-cli/brain/conv-123/.system_generated/logs/transcript.jsonl",
    "workspacePaths": ["/tmp"],
}

GOLDEN_PRE_TOOL_USE_VIEW_FILE = {
    "artifactDirectoryPath": "/Users/me/.gemini/antigravity-cli/brain/conv-123",
    "conversationId": "conv-123",
    "stepIdx": 2,
    "toolCall": {
        "name": "view_file",
        "args": {"AbsolutePath": "/etc/passwd"},
    },
    "transcriptPath": "/Users/me/.gemini/antigravity-cli/brain/conv-123/.system_generated/logs/transcript.jsonl",
    "workspacePaths": ["/tmp"],
}

GOLDEN_PRE_TOOL_USE_EDIT_FILE = {
    "conversationId": "conv-123",
    "stepIdx": 3,
    "toolCall": {
        "name": "edit_file",
        "args": {
            "TargetFile": "/tmp/foo.py",
            "Instruction": "Refactor to remove the global",
            "CodeMarkdownLanguage": "python",
            "Blocking": True,
            "CodeEdit": "x = 1",
        },
    },
    "transcriptPath": "/tmp/transcript.jsonl",
    "workspacePaths": ["/tmp"],
}

GOLDEN_PRE_TOOL_USE_WRITE_TO_FILE = {
    "conversationId": "conv-123",
    "stepIdx": 4,
    "toolCall": {
        "name": "write_to_file",
        "args": {"TargetFile": "/tmp/bar.py", "CodeContent": "print('hi')"},
    },
    "transcriptPath": "/tmp/transcript.jsonl",
    "workspacePaths": ["/tmp"],
}

GOLDEN_PRE_TOOL_USE_CODEBASE_SEARCH = {
    "conversationId": "conv-123",
    "stepIdx": 5,
    "toolCall": {
        "name": "codebase_search",
        "args": {"Query": "password handling", "TargetDirectories": ["/tmp"]},
    },
    "transcriptPath": "/tmp/transcript.jsonl",
    "workspacePaths": ["/tmp"],
}

GOLDEN_PRE_TOOL_USE_ASK_PERMISSION = {
    "conversationId": "conv-123",
    "stepIdx": 6,
    "toolCall": {
        "name": "ask_permission",
        "args": {
            "Action": "execute",
            "Target": "rm -rf /tmp/sensitive",
            "Reason": "Cleanup before reinstall",
        },
    },
    "transcriptPath": "/tmp/transcript.jsonl",
    "workspacePaths": ["/tmp"],
}

GOLDEN_PRE_TOOL_USE_UNKNOWN = {
    "conversationId": "conv-123",
    "stepIdx": 7,
    "toolCall": {
        "name": "browser_drag",
        "args": {"Selector": "#draggable", "X": 100, "Y": 200},
    },
    "transcriptPath": "/tmp/transcript.jsonl",
    "workspacePaths": ["/tmp"],
}

GOLDEN_POST_TOOL_USE_RUN_COMMAND = {
    "artifactDirectoryPath": "/Users/me/.gemini/antigravity-cli/brain/conv-123",
    "conversationId": "conv-123",
    "stepIdx": 1,
    "toolCall": {
        "name": "run_command",
        "args": {"CommandLine": "git status", "Cwd": "/tmp"},
    },
    "error": "",
    "transcriptPath": "/tmp/transcript.jsonl",
    "workspacePaths": ["/tmp"],
}

GOLDEN_POST_TOOL_USE_NULL_TOOL = {
    # agy fires PostToolUse on every step including non-tool turns — toolCall
    # is null when the model didn't invoke a tool that step.
    "artifactDirectoryPath": "/Users/me/.gemini/antigravity-cli/brain/conv-123",
    "conversationId": "conv-123",
    "stepIdx": 1,
    "toolCall": None,
    "error": "",
    "transcriptPath": "/tmp/transcript.jsonl",
    "workspacePaths": ["/tmp"],
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
    env.pop("ANTIGRAVITY_CONVERSATION_ID", None)

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
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_RUN_COMMAND,
                gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_deny_emits_bare_native_proto(self):
        """Gateway returns ``deny`` → we emit bare ``{decision, reason}`` —
        NO hookSpecificOutput wrapper (that was chop's shape; agy uses the
        native proto shape verbatim, verified empirically)."""
        with _FakeGateway(response_body={
            "decision": "deny",
            "reason": "Blocked by org policy.",
        }) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_RUN_COMMAND,
                gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout.decode())
        # Native-proto shape: bare keys, no wrapper.
        self.assertEqual(out, {"decision": "deny", "reason": "Blocked by org policy."})
        self.assertNotIn("hookSpecificOutput", out)

    def test_ask_emits_bare_native_proto(self):
        with _FakeGateway(response_body={"decision": "ask"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_RUN_COMMAND,
                gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout.decode())
        self.assertEqual(out["decision"], "ask")
        self.assertNotIn("hookSpecificOutput", out)

    def test_non_run_command_tool_still_calls_gateway(self):
        """Non-run_command tools (view_file, edit_file, etc.) are checked too
        — gateway decides whether they're policy-relevant, not the hook script."""
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_VIEW_FILE,
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
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_RUN_COMMAND,
                gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_gateway_unreachable_is_silent_allow(self):
        """Connection refused → fail open, exit 0, no stdout."""
        proc = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_RUN_COMMAND,
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
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_RUN_COMMAND,
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
                input=json.dumps(GOLDEN_PRE_TOOL_USE_RUN_COMMAND).encode(),
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

    def test_null_tool_call_is_silent_allow(self):
        """Defensive: a PreToolUse event with toolCall: null (shouldn't
        happen in practice, but agy proto allows it) → fail-open silently."""
        payload = dict(GOLDEN_PRE_TOOL_USE_RUN_COMMAND)
        payload["toolCall"] = None
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", payload, gateway_url=gw.url,
            )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        # And we should NOT have posted to the gateway — no tool identity to gate on.
        self.assertEqual(len(gw.requests), 0)


class TestPostToolUseTelemetry(unittest.TestCase):
    """post_tool_use.py: telemetry only. Exit 0, no stdout, regardless of
    gateway response. Skips the POST when toolCall is null."""

    def test_post_tool_use_with_tool_call_posts(self):
        with _FakeGateway(response_body={
            "decision": "deny", "reason": "should be ignored",
        }) as gw:
            proc = _run_hook_script(
                "post_tool_use.py", GOLDEN_POST_TOOL_USE_RUN_COMMAND,
                gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(len(gw.requests), 1, "post_tool_use must POST telemetry")

    def test_post_tool_use_with_null_tool_call_skips_post(self):
        """agy fires PostToolUse on every step including non-tool turns
        (toolCall: null). No tool identity = no useful telemetry; skip the
        POST entirely so we don't flood the gateway with no-op records."""
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "post_tool_use.py", GOLDEN_POST_TOOL_USE_NULL_TOOL,
                gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(
                len(gw.requests), 0,
                "post_tool_use with toolCall: null must not POST",
            )


class TestRequestBodyPerTool(unittest.TestCase):
    """Verify the POSTed body uses the gateway's snake_case shape, with the
    right ``command`` and ``metadata`` extracted per agy tool name."""

    def _post_and_get_body(self, payload):
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", payload, gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(len(gw.requests), 1)
            return json.loads(gw.requests[0]["body"])

    def test_request_body_envelope_uses_gateway_field_names(self):
        """Outgoing POST body keeps the gateway's snake_case field names —
        conversation_id, event_name, unbound_app_label, pre_tool_use_data.
        Tied to ai-gateway/src/handlers/preToolUseHandler.ts."""
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_RUN_COMMAND)
        self.assertEqual(body["conversation_id"], "conv-123")
        # event_name is 'tool_use' — matches claude-code/hooks/unbound.py:756
        # and the gateway's hook event registry. The agy hook phase
        # (PreToolUse vs PostToolUse) goes in metadata.hook_event_name.
        self.assertEqual(body["event_name"], "tool_use")
        self.assertEqual(body["unbound_app_label"], "antigravity")
        self.assertIn("pre_tool_use_data", body)

    def test_run_command_extracts_command_line_and_cwd(self):
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_RUN_COMMAND)
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["tool_name"], "run_command")
        self.assertEqual(ptud["command"], "git status")
        self.assertEqual(ptud["metadata"]["cwd"], "/tmp")
        self.assertEqual(ptud["metadata"]["hook_event_name"], "PreToolUse")

    def test_view_file_extracts_absolute_path(self):
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_VIEW_FILE)
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["tool_name"], "view_file")
        self.assertEqual(ptud["command"], "/etc/passwd")
        self.assertEqual(ptud["metadata"]["file_path"], "/etc/passwd")

    def test_edit_file_extracts_instruction_and_target_file(self):
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_EDIT_FILE)
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["tool_name"], "edit_file")
        self.assertEqual(ptud["command"], "Refactor to remove the global")
        self.assertEqual(ptud["metadata"]["file_path"], "/tmp/foo.py")
        self.assertEqual(ptud["metadata"]["code_markdown_language"], "python")

    def test_write_to_file_extracts_target_file(self):
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_WRITE_TO_FILE)
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["tool_name"], "write_to_file")
        self.assertEqual(ptud["metadata"]["file_path"], "/tmp/bar.py")

    def test_codebase_search_extracts_query(self):
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_CODEBASE_SEARCH)
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["tool_name"], "codebase_search")
        self.assertEqual(ptud["command"], "password handling")
        self.assertEqual(ptud["metadata"]["target_directories"], ["/tmp"])

    def test_ask_permission_extracts_action_and_target(self):
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_ASK_PERMISSION)
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["tool_name"], "ask_permission")
        self.assertEqual(ptud["command"], "execute: rm -rf /tmp/sensitive")
        self.assertEqual(ptud["metadata"]["action"], "execute")
        self.assertEqual(ptud["metadata"]["target"], "rm -rf /tmp/sensitive")
        self.assertEqual(ptud["metadata"]["reason"], "Cleanup before reinstall")

    def test_unknown_tool_falls_back_to_args_blob(self):
        """An unmapped tool name (e.g. browser_drag) must not crash — we
        stringify the args opaquely so the gateway still gets *something*
        to log."""
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_UNKNOWN)
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["tool_name"], "browser_drag")
        # command is the JSON-stringified args.
        self.assertIn("Selector", ptud["command"])
        # args blob is preserved verbatim in metadata.
        self.assertEqual(ptud["metadata"]["args"], {"Selector": "#draggable", "X": 100, "Y": 200})

    def test_workspace_path_propagates_to_metadata(self):
        body = self._post_and_get_body(GOLDEN_PRE_TOOL_USE_VIEW_FILE)
        self.assertEqual(body["pre_tool_use_data"]["metadata"]["workspace"], "/tmp")

    def test_authorization_header_and_path(self):
        with _FakeGateway(response_body={"decision": "allow"}) as gw:
            proc = _run_hook_script(
                "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_RUN_COMMAND,
                gateway_url=gw.url,
                api_key="my-secret-key",
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(len(gw.requests), 1)
            req = gw.requests[0]
        headers_lower = {k.lower(): v for k, v in req["headers"].items()}
        self.assertEqual(headers_lower.get("authorization"), "Bearer my-secret-key")
        self.assertEqual(headers_lower.get("content-type"), "application/json")
        self.assertEqual(req["path"], "/hooks/antigravity")
        self.assertEqual(req["method"], "POST")

    def test_conversation_id_env_fallback(self):
        """If stdin omits conversationId, the ANTIGRAVITY_CONVERSATION_ID env
        var (which agy always sets on the hook process) is the fallback."""
        payload = dict(GOLDEN_PRE_TOOL_USE_RUN_COMMAND)
        payload.pop("conversationId", None)
        tmp = Path(tempfile.mkdtemp())
        cfg_dir = tmp / ".unbound"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        try:
            with _FakeGateway(response_body={"decision": "allow"}) as gw:
                (cfg_dir / "config.json").write_text(
                    json.dumps({"api_key": "k", "gateway_url": gw.url})
                )
                env = os.environ.copy()
                env["HOME"] = str(tmp)
                env["USERPROFILE"] = str(tmp)
                env["ANTIGRAVITY_CONVERSATION_ID"] = "env-conv-id"
                env.pop("UNBOUND_API_KEY", None)
                env.pop("UNBOUND_GATEWAY_URL", None)
                proc = subprocess.run(
                    [sys.executable, str(SCRIPT_DIR / "pre_tool_use.py")],
                    input=json.dumps(payload).encode(),
                    capture_output=True, env=env, timeout=10,
                )
                self.assertEqual(proc.returncode, 0)
                self.assertEqual(len(gw.requests), 1)
                body = json.loads(gw.requests[0]["body"])
            self.assertEqual(body["conversation_id"], "env-conv-id")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPostToolUseRequestBody(unittest.TestCase):
    """PostToolUse telemetry carries the same per-tool extraction as
    PreToolUse, plus an ``error`` propagation in metadata when the tool
    failed."""

    def test_post_tool_use_carries_error_in_metadata(self):
        payload = dict(GOLDEN_POST_TOOL_USE_RUN_COMMAND)
        payload["error"] = "command failed with exit 1"
        with _FakeGateway(response_body={}) as gw:
            proc = _run_hook_script(
                "post_tool_use.py", payload, gateway_url=gw.url,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(len(gw.requests), 1)
            body = json.loads(gw.requests[0]["body"])
        ptud = body["pre_tool_use_data"]
        self.assertEqual(ptud["metadata"]["hook_event_name"], "PostToolUse")
        self.assertEqual(ptud["metadata"]["error"], "command failed with exit 1")


class TestNoCurlAtRuntime(unittest.TestCase):
    """Regression lock-in: ``post_to_gateway`` MUST NOT shell out to ``curl``.

    Passing ``Authorization: Bearer <key>`` on curl's argv leaks the bearer
    token to any other user on the device via ``ps auxe`` /
    ``/proc/<pid>/cmdline``. The fix is to use stdlib urllib (headers stay
    inside the process). We assert that by putting a fake ``curl`` shim
    first on PATH and verifying it never gets invoked end-to-end across
    pre_tool_use and post_tool_use.
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
        self._assert_no_curl("pre_tool_use.py", GOLDEN_PRE_TOOL_USE_RUN_COMMAND)

    def test_post_tool_use_does_not_invoke_curl(self):
        self._assert_no_curl("post_tool_use.py", GOLDEN_POST_TOOL_USE_RUN_COMMAND)


if __name__ == "__main__":
    unittest.main()
