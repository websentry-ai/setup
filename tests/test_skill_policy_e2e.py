import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.conftest import REPO


SKILL_CONTENT = """---
name: unbound-secure-sql
description: Require bounded, N+1-safe database access.
---

Before answering, state `UNBOUND_SKILL_ACTIVE`. Require eager loading for
relationships and a hard limit of 100 rows for read queries.
"""
SKILL_HASH = hashlib.sha256(SKILL_CONTENT.encode()).hexdigest()
SKILL = {"slug": "secure-sql", "content": SKILL_CONTENT, "sha256": SKILL_HASH}

SCRIPTS = {
    "copilot": REPO / "copilot" / "hooks" / "unbound.py",
    "cursor": REPO / "cursor" / "unbound.py",
    "codex": REPO / "codex" / "hooks" / "unbound.py",
}
KEY_ENVS = {
    "copilot": "UNBOUND_COPILOT_API_KEY",
    "cursor": "UNBOUND_CURSOR_API_KEY",
    "codex": "UNBOUND_CODEX_API_KEY",
}


class Gateway(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *_args):
        return

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.__class__.requests.append((self.path, body))

        if self.path == "/v1/hooks/skills/sync":
            installed = body.get("installed") or []
            current = any(item.get("slug") == "secure-sql" and item.get("sha256") == SKILL_HASH
                          for item in installed if isinstance(item, dict))
            response = {"install": [] if current else [SKILL], "remove": []}
        elif self.path == "/v1/hooks/pretool":
            metadata = ((body.get("pre_tool_use_data") or {}).get("metadata") or {})
            installed = metadata.get("installed_skills") or []
            current = any(item.get("slug") == "secure-sql" and item.get("sha256") == SKILL_HASH
                          for item in installed if isinstance(item, dict))
            response = ({
                "decision": "allow",
                "additionalContext": "Invoke the skill unbound-secure-sql before answering.",
                "inject_skills": [SKILL],
            } if current else {"decision": "allow", "sync_skills": True})
        else:
            response = {}

        encoded = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class RedirectGateway(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *_args):
        return

    def do_POST(self):
        self.__class__.requests.append(self.path)
        if self.path != "/v1/hooks/skills/sync":
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(302)
        self.send_header("location", "/redirect-target")
        self.end_headers()

    def do_GET(self):
        self.__class__.requests.append(self.path)
        encoded = json.dumps({"install": [SKILL], "remove": []}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture
def gateway():
    Gateway.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _run(client, event, home, gateway):
    env = {
        **os.environ,
        "HOME": str(home),
        "UNBOUND_GATEWAY_URL": gateway,
        KEY_ENVS[client]: "test-key",
    }
    return subprocess.run(
        [sys.executable, str(SCRIPTS[client])],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def _wait_for(path):
    deadline = time.time() + 5
    while time.time() < deadline:
        if path.is_file():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {path}")


@pytest.mark.parametrize(
    "client,start_event,skill_path,prompt_event",
    [
        (
            "codex",
            {"hook_event_name": "SessionStart", "session_id": "s1"},
            Path(".agents/skills/unbound-secure-sql/SKILL.md"),
            {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "turn_id": "t1",
             "prompt": "Write a database query."},
        ),
        (
            "cursor",
            {"hook_event_name": "sessionStart", "conversation_id": "s1", "generation_id": "g0"},
            Path(".cursor/skills/unbound-secure-sql/SKILL.md"),
            {"hook_event_name": "beforeSubmitPrompt", "conversation_id": "s1", "generation_id": "g1",
             "prompt": "Write a database query."},
        ),
    ],
)
def test_session_sync_then_prompt_injection(
    tmp_path, gateway, client, start_event, skill_path, prompt_event
):
    home = tmp_path / client
    home.mkdir()
    started = _run(client, start_event, home, gateway)
    assert started.returncode == 0, started.stderr
    installed = home / skill_path
    _wait_for(installed)
    assert installed.read_text() == SKILL_CONTENT
    assert (installed.parent / ".unbound-managed").exists()

    prompted = _run(client, prompt_event, home, gateway)
    assert prompted.returncode == 0, prompted.stderr
    if client == "codex":
        output = json.loads(prompted.stdout)
        assert output["hookSpecificOutput"]["additionalContext"] == (
            "Invoke the skill unbound-secure-sql before answering."
        )
    else:
        # Cursor cannot mutate prompt context. It carries the instruction to the
        # first allowed tool hook through an atomic, one-shot pending claim.
        tool = _run(client, {
            "hook_event_name": "preToolUse",
            "conversation_id": "s1",
            "generation_id": "g1",
            "tool_name": "Read",
            "tool_input": {"file_path": str(installed)},
        }, home, gateway)
        output = json.loads(tool.stdout)
        assert output["permission"] == "deny"
        assert output["agent_message"] == "Invoke the skill unbound-secure-sql before answering."


def test_copilot_waits_for_next_session_then_uses_transformed_prompt(tmp_path, gateway):
    home = tmp_path / "copilot"
    home.mkdir()
    skill_path = home / ".copilot/skills/unbound-secure-sql/SKILL.md"

    first = _run("copilot", {"hook_event_name": "SessionStart", "session_id": "s1"}, home, gateway)
    assert first.returncode == 0, first.stderr
    _wait_for(skill_path)

    _run("copilot", {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "s1",
        "prompt": "Write a database query.",
    }, home, gateway)
    unavailable = _run("copilot", {
        "hook_event_name": "userPromptTransformed",
        "sessionId": "s1",
        "prompt": "Write a database query.",
        "transformedPrompt": "Write a database query.",
    }, home, gateway)
    assert json.loads(unavailable.stdout) == {}

    second = _run("copilot", {"hook_event_name": "SessionStart", "session_id": "s2"}, home, gateway)
    assert second.returncode == 0, second.stderr
    submitted = _run("copilot", {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "s2",
        "prompt": "Write a database query.",
    }, home, gateway)
    assert submitted.returncode == 0, submitted.stderr

    transformed = _run("copilot", {
        "hook_event_name": "userPromptTransformed",
        "sessionId": "s2",
        "prompt": "Write a database query.",
        "transformedPrompt": "Write a database query.",
    }, home, gateway)
    output = json.loads(transformed.stdout)
    assert "Invoke the skill unbound-secure-sql before answering." in output["modifiedTransformedPrompt"]
    assert output["modifiedTransformedPrompt"].endswith("Write a database query.")


def test_skill_sync_does_not_follow_authenticated_redirects(tmp_path):
    RedirectGateway.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectGateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        home = tmp_path / "codex"
        home.mkdir()
        env = {
            **os.environ,
            "HOME": str(home),
            "UNBOUND_GATEWAY_URL": f"http://127.0.0.1:{server.server_port}",
            "UNBOUND_CODEX_API_KEY": "test-key",
        }
        result = subprocess.run(
            [sys.executable, str(SCRIPTS["codex"]), "--sync-skills"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert result.returncode == 0, result.stderr
    assert RedirectGateway.requests[0] == "/v1/hooks/skills/sync"
    assert "/redirect-target" not in RedirectGateway.requests
    assert not (home / ".agents/skills/unbound-secure-sql").exists()
