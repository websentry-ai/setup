"""Integration tests for the Antigravity hook scripts.

Run with:

    cd antigravity/hooks/scripts && python3 -m unittest test_hooks.py -v

Tests drive ``pre_tool_use.py``, ``post_tool_use.py``,
``user_prompt_submit.py``, and ``session_start.py`` end-to-end by
spawning a subprocess, piping the chop-verified golden Antigravity
stdin payload in, and asserting on stdout / exit code. The gateway POST
is intercepted at the subprocess.run-of-curl layer via a fake ``curl``
shim on PATH so we never make real network calls.

Golden payloads are lifted verbatim from ``AgusRdz/chop:hooks/antigravity_test.go``.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
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


def _make_fake_curl(tmpdir: Path, gateway_response: dict, log_path: Path, exit_code: int = 0) -> Path:
    """Create an executable ``curl`` shim in tmpdir/bin that:
    - Reads its stdin (the POST body).
    - Writes the request body + argv to ``log_path`` for assertions.
    - Prints ``gateway_response`` (as JSON) on stdout.
    - Exits with ``exit_code``.

    Returns the directory to prepend to PATH so child processes pick it up.
    """
    bin_dir = tmpdir / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "curl"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, json, os\n"
        f"log_path = {repr(str(log_path))}\n"
        "body = sys.stdin.read()\n"
        "with open(log_path, 'a', encoding='utf-8') as f:\n"
        "    f.write(json.dumps({'argv': sys.argv[1:], 'body': body}) + '\\n')\n"
        f"sys.stdout.write({repr(json.dumps(gateway_response))})\n"
        f"sys.exit({int(exit_code)})\n"
    )
    os.chmod(fake, fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir


def _run_hook_script(
    script_name: str,
    stdin_payload: dict,
    fake_curl_response: dict = None,
    curl_exit_code: int = 0,
    api_key: str = "test-api-key",
    home: Path = None,
):
    """Invoke ``scripts/<script_name>`` as a child Python process with a
    sandboxed HOME and a fake ``curl`` on PATH. Returns (proc, curl_log)."""
    tmp = home if home else Path(tempfile.mkdtemp())
    # Write the unbound config so the hook script reads the API key.
    cfg_dir = tmp / ".unbound"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config.json").write_text(
        json.dumps({"api_key": api_key, "gateway_url": "https://api.example.test"})
    )

    curl_log = tmp / "curl.log"
    bin_dir = _make_fake_curl(tmp, fake_curl_response or {}, curl_log, exit_code=curl_exit_code)

    env = os.environ.copy()
    env["HOME"] = str(tmp)
    env["USERPROFILE"] = str(tmp)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    # Don't let real env vars override the config-file API key during tests.
    env.pop("UNBOUND_API_KEY", None)
    env.pop("UNBOUND_GATEWAY_URL", None)

    proc = subprocess.run(
        [sys.executable, str(SCRIPT_DIR / script_name)],
        input=json.dumps(stdin_payload).encode("utf-8"),
        capture_output=True,
        env=env,
        timeout=10,
    )
    return proc, curl_log


class TestPreToolUseDecisions(unittest.TestCase):
    """The only hook that emits a non-empty stdout: pre_tool_use.py."""

    def test_allow_emits_silent_stdout(self):
        """Gateway returns ``allow`` → we print NOTHING and exit 0."""
        proc, _log = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
            fake_curl_response={"decision": "allow"},
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_deny_emits_hook_specific_output(self):
        """Gateway returns ``deny`` → we emit camelCase hookSpecificOutput."""
        proc, _log = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
            fake_curl_response={
                "decision": "deny",
                "reason": "Blocked by org policy.",
            },
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout.decode())
        self.assertIn("hookSpecificOutput", out)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertEqual(hso["permissionDecisionReason"], "Blocked by org policy.")

    def test_ask_emits_hook_specific_output(self):
        proc, _log = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
            fake_curl_response={"decision": "ask"},
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout.decode())
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_pascal_case_bash_works_too(self):
        """The chop fixtures show Antigravity emits both 'bash' and 'Bash' —
        our hook must handle either casing."""
        proc, log = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH_PASCAL,
            fake_curl_response={"decision": "allow"},
        )
        self.assertEqual(proc.returncode, 0)
        # We should still have POSTed to the gateway.
        entries = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(entries), 1)
        body = json.loads(entries[0]["body"])
        # tool_name in the request body must be canonicalised to "Bash".
        self.assertEqual(body["pre_tool_use_data"]["tool_name"], "Bash")

    def test_non_bash_tool_still_calls_gateway(self):
        """Non-bash tools (FileRead, Write, etc.) are checked too — gateway
        decides whether they're policy-relevant, not the hook script."""
        proc, log = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_NON_BASH,
            fake_curl_response={"decision": "allow"},
        )
        self.assertEqual(proc.returncode, 0)
        entries = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(entries), 1)


class TestPreToolUseFailOpen(unittest.TestCase):
    """Iron law: never block the agent on our infra. Any infra failure
    (curl exit non-zero, malformed JSON, unreachable gateway) must result
    in silent exit 0 (== allow)."""

    def test_curl_failure_is_silent_allow(self):
        proc, _log = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
            fake_curl_response={}, curl_exit_code=22,  # 22 = HTTP error from curl -f
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_gateway_returns_garbage_is_silent_allow(self):
        """Even if curl exits 0 with non-JSON, we fail open."""
        # Build the script manually to emit raw garbage on stdout.
        tmp = Path(tempfile.mkdtemp())
        cfg_dir = tmp / ".unbound"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.json").write_text(
            json.dumps({"api_key": "k", "gateway_url": "https://x.test"})
        )
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "curl"
        fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\nprint('not json at all')\nsys.exit(0)\n")
        os.chmod(fake, fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        env = os.environ.copy()
        env["HOME"] = str(tmp)
        env["USERPROFILE"] = str(tmp)
        env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
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
        proc, log = _run_hook_script(
            "post_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
            fake_curl_response={"decision": "deny", "reason": "should be ignored"},
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        entries = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(entries), 1, "post_tool_use must POST telemetry")

    def test_user_prompt_submit_is_silent_and_posts(self):
        proc, log = _run_hook_script(
            "user_prompt_submit.py", GOLDEN_USER_PROMPT_SUBMIT,
            fake_curl_response={"decision": "deny"},
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        entries = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(entries), 1)

    def test_session_start_is_silent_and_posts(self):
        proc, log = _run_hook_script(
            "session_start.py", GOLDEN_SESSION_START,
            fake_curl_response={"decision": "deny"},
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        entries = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(entries), 1)


class TestRequestBody(unittest.TestCase):
    """Verify the POSTed body matches PretoolRequestBody shape from
    ai-gateway/src/handlers/preToolUseHandler.ts:86-100."""

    def test_request_body_shape_for_bash_command(self):
        proc, log = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
            fake_curl_response={"decision": "allow"},
        )
        self.assertEqual(proc.returncode, 0)
        entries = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(entries), 1)
        body = json.loads(entries[0]["body"])

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
        proc, log = _run_hook_script(
            "pre_tool_use.py", GOLDEN_PRE_TOOL_USE_BASH,
            fake_curl_response={"decision": "allow"},
            api_key="my-secret-key",
        )
        self.assertEqual(proc.returncode, 0)
        entries = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        argv = entries[0]["argv"]
        self.assertIn("Authorization: Bearer my-secret-key", argv)
        # And the URL ends in /hooks/antigravity.
        url = argv[-1]
        self.assertTrue(url.endswith("/hooks/antigravity"), f"unexpected URL: {url}")


if __name__ == "__main__":
    unittest.main()
