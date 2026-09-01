"""The skill-injection loop, driven through the real hook process.

The unit tests cover each piece; this covers the wiring between them, which is
where a port goes wrong. Every tool runs as the editor runs it — a subprocess fed
one event on stdin — against a gateway that records what it was told.

The transcript fixtures are the shapes real sessions produced: `skill.invoked` for
Copilot, a `Read` tool call for Cursor, an `exec` that opens the SKILL.md for Codex.
"""

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tests.conftest import REPO

BODY = "# secure sql\n"
SHA = hashlib.sha256(BODY.encode()).hexdigest()
PLAN = {"install": [{"slug": "secure-sql", "content": BODY, "sha256": SHA}], "remove": []}
DENY = {
    "decision": "deny",
    "reason": "Load the unbound-secure-sql skill first.",
    "additionalContext": "Read the skill, then retry.",
    "inject_skills": [{"slug": "secure-sql", "sha256": SHA}],
}


def _copilot_transcript(home, skills):
    directory = home / ".copilot" / "session-state" / "s1"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "events.jsonl").write_text(
        json.dumps({"type": "skill.invoked", "data": {"name": "unbound-secure-sql"}}) + "\n")
    return None  # Copilot's PreToolUse carries no path; the hook derives it.


def _cursor_transcript(home, skills):
    path = home / "transcript.jsonl"
    path.write_text(json.dumps({"role": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "Read",
         "input": {"path": str(skills / "unbound-secure-sql" / "SKILL.md")}}]}}) + "\n")
    return str(path)


def _codex_transcript(home, skills):
    path = home / "rollout.jsonl"
    path.write_text(json.dumps({"type": "response_item", "payload": {
        "type": "custom_tool_call", "status": "completed", "name": "exec",
        "input": "await tools.exec_command({cmd:\"sed -n '1,240p' %s\"});"
                 % (skills / "unbound-secure-sql" / "SKILL.md")}}) + "\n")
    return str(path)


TOOLS = {
    "copilot": {
        "hook": REPO / "copilot" / "hooks" / "unbound.py",
        "env_key": "UNBOUND_COPILOT_API_KEY",
        "home_var": "COPILOT_HOME",
        "home_rel": ".copilot",
        "skills_rel": ".copilot/skills",
        "session_start": {"hook_event_name": "SessionStart", "session_id": "s1"},
        "call": lambda tp: {"hook_event_name": "PreToolUse", "session_id": "s1",
                            "tool_name": "Bash", "tool_input": {"command": "psql"}},
        "transcript": _copilot_transcript,
        "deny_marker": '"permissionDecision": "deny"',
    },
    "cursor": {
        "hook": REPO / "cursor" / "unbound.py",
        "env_key": "UNBOUND_CURSOR_API_KEY",
        "home_var": None,
        "home_rel": ".cursor",
        "skills_rel": ".cursor/skills",
        "session_start": {"hook_event_name": "sessionStart", "conversation_id": "s1"},
        "call": lambda tp: {"hook_event_name": "beforeShellExecution", "conversation_id": "s1",
                            "generation_id": "g1", "command": "psql", "transcript_path": tp},
        "transcript": _cursor_transcript,
        "deny_marker": '"permission": "deny"',
    },
    "codex": {
        "hook": REPO / "codex" / "hooks" / "unbound.py",
        "env_key": "UNBOUND_CODEX_API_KEY",
        "home_var": "CODEX_HOME",
        "home_rel": ".codex",
        "skills_rel": ".codex/skills",
        "session_start": {"hook_event_name": "SessionStart", "session_id": "s1"},
        "call": lambda tp: {"hook_event_name": "PreToolUse", "session_id": "s1", "turn_id": "t1",
                            "tool_name": "Bash", "tool_input": {"command": "psql"},
                            "transcript_path": tp},
        "transcript": _codex_transcript,
        "deny_marker": '"permissionDecision": "deny"',
    },
}


class _Gateway:
    """Answers the reconcile with a fixed plan and every policy call with `response`."""

    def __init__(self):
        self.requests = []
        self.response = {"decision": "allow"}
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = {}
                gateway.requests.append({"path": self.path, "body": body})
                out = PLAN if self.path.endswith("/skills/sync") else gateway.response
                data = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    def last_metadata(self, since):
        for request in reversed(self.requests[since:]):
            if request["path"].endswith("/skills/sync"):
                continue
            return (request["body"].get("pre_tool_use_data") or {}).get("metadata") or {}
        return {}


@pytest.fixture
def gateway():
    server = _Gateway()
    yield server
    server.close()


@pytest.fixture(params=sorted(TOOLS), ids=sorted(TOOLS))
def tool(request):
    return TOOLS[request.param]


def _run(tool, payload, home, gateway_url):
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "UNBOUND_GATEWAY_URL": gateway_url, tool["env_key"]: "test-key"}
    if tool["home_var"]:
        env[tool["home_var"]] = str(home / tool["home_rel"])
    return subprocess.run([sys.executable, str(tool["hook"])], input=json.dumps(payload),
                          capture_output=True, text=True, timeout=90, env=env)


def _reconcile(tool, home, gateway_url):
    _run(tool, tool["session_start"], home, gateway_url)
    skills = home / tool["skills_rel"]
    body = skills / "unbound-secure-sql" / "SKILL.md"
    deadline = time.time() + 30
    while time.time() < deadline and not body.exists():
        time.sleep(0.1)
    return skills, body


@pytest.fixture
def home(tmp_path):
    directory = tmp_path / "home"
    directory.mkdir()
    return directory


def test_session_start_installs_the_org_skill(tool, home, gateway):
    skills, body = _reconcile(tool, home, gateway.url)
    assert body.read_text() == BODY
    assert (skills / "unbound-secure-sql" / ".unbound-managed").exists()


def test_a_tool_call_reports_what_is_installed(tool, home, gateway):
    _reconcile(tool, home, gateway.url)
    since = len(gateway.requests)
    _run(tool, tool["call"](None), home, gateway.url)
    metadata = gateway.last_metadata(since)
    assert metadata["installed_skills"] == [{"slug": "secure-sql", "sha256": SHA}]
    assert "loaded_skills" not in metadata


def test_a_deny_reaches_the_editor(tool, home, gateway):
    _reconcile(tool, home, gateway.url)
    gateway.response = DENY
    result = _run(tool, tool["call"](None), home, gateway.url)
    assert tool["deny_marker"] in result.stdout
    assert "unbound-secure-sql" in result.stdout


def test_a_loaded_skill_is_reported_back(tool, home, gateway):
    skills, _ = _reconcile(tool, home, gateway.url)
    transcript = tool["transcript"](home, skills)
    since = len(gateway.requests)
    _run(tool, tool["call"](transcript), home, gateway.url)
    metadata = gateway.last_metadata(since)
    assert metadata["loaded_skills"] == ["secure-sql"]
    assert metadata["skills_loaded_this_session"] == 1


def test_the_reconcile_prunes_what_the_org_dropped(tool, home, gateway):
    skills, body = _reconcile(tool, home, gateway.url)
    assert body.exists()
    PLAN["install"], PLAN["remove"] = [], ["secure-sql"]
    try:
        _run(tool, tool["session_start"], home, gateway.url)
        deadline = time.time() + 30
        while time.time() < deadline and body.exists():
            time.sleep(0.1)
        assert not body.exists()
    finally:
        PLAN["install"] = [{"slug": "secure-sql", "content": BODY, "sha256": SHA}]
        PLAN["remove"] = []


def test_an_unreachable_gateway_never_blocks_the_editor(tool, home):
    result = _run(tool, tool["call"](None), home, "http://127.0.0.1:9")
    assert result.returncode == 0
    assert "deny" not in result.stdout
