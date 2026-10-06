"""The real hook, run as Claude Desktop runs it, sends a Cowork skill run's path and
content hash upstream.

Each case pipes real hook events into ``claude-code/hooks/unbound.py`` in a fresh
process, with HOME pointing at a fake Cowork tree and the gateway at a local stub
that records what the hook sends.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOOK = Path(__file__).resolve().parents[3] / "claude-code" / "hooks" / "unbound.py"


class _Gateway(BaseHTTPRequestHandler):
    sent = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.startswith("/v1/hooks/claude"):
            type(self).sent.append(json.loads(body))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = do_POST

    def log_message(self, *args):
        pass


def _support_dir(home):
    """Where the hook looks for Claude Desktop on this OS (APPDATA is redirected on Windows)."""
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude"
    if sys.platform == "win32":
        return home / "AppData" / "Roaming" / "Claude"
    return home / ".config" / "Claude"


class CoworkHookE2E(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Gateway)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        _Gateway.sent = []
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name).resolve()
        self.org = _support_dir(self.home) / "local-agent-mode-sessions" / "acct" / "org"
        self.session = self.org / "local_e2e"
        self.outputs = self.session / "outputs"
        self.outputs.mkdir(parents=True)
        self.env = dict(
            os.environ,
            HOME=str(self.home), USERPROFILE=str(self.home),
            APPDATA=str(self.home / "AppData" / "Roaming"),
            UNBOUND_GATEWAY_URL="http://127.0.0.1:%d" % self.server.server_address[1],
            UNBOUND_CLAUDE_API_KEY="test-key",
        )
        for key in ("CLAUDE_CONFIG_DIR", "UNBOUND_HOOK_TOOL"):
            self.env.pop(key, None)

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def bundle_skill(self, name, text):
        root = self.org.parent.parent / "skills-plugin" / "b1" / "b1" / "skills"
        return self.write(root / name / "SKILL.md", text)

    def run_turn(self, *, skill=None, prompt="make it", cwd=None, transcript=None):
        cwd = str(cwd or self.outputs)
        transcript = str(transcript or self.write(self.home / "t" / "s.jsonl", ""))
        base = {"session_id": "s-e2e", "cwd": cwd, "transcript_path": transcript}
        events = [dict(base, hook_event_name="UserPromptSubmit", prompt=prompt)]
        if skill is not None:
            events.append(dict(base, hook_event_name="PostToolUse", tool_name="Skill",
                               tool_input={"skill": skill}, tool_response={},
                               tool_use_id="tu-1"))
        events.append(dict(base, hook_event_name="Stop", stop_hook_active=False))
        for event in events:
            result = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event).encode(),
                                    env=self.env, cwd=cwd, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(_Gateway.sent, "the hook sent nothing upstream")
        return [use for exchange in _Gateway.sent for message in exchange.get("messages", [])
                for use in message.get("tool_use", []) if use.get("tool_name") == "Skill"]

    @staticmethod
    def scanner_hash(text):
        return hashlib.sha256(("SKILL.md:" + text).encode("utf-8")).hexdigest()

    def test_cowork_skill_run_carries_path_and_scanner_hash(self):
        text = "---\nname: xlsx\n---\nSheets.\n"
        skill = self.bundle_skill("xlsx", text)
        (use,) = self.run_turn(skill="anthropic-skills:xlsx")
        self.assertEqual(use["skill_path"], str(skill))
        self.assertEqual(use["content_hash"], self.scanner_hash(text))

    def test_claude_code_run_still_resolves_its_own_skills_dir(self):
        text = "---\nname: review\n---\nReview.\n"
        skill = self.write(self.home / ".claude" / "skills" / "review" / "SKILL.md", text)
        repo = self.home / "repo"
        repo.mkdir()
        (use,) = self.run_turn(skill="review", cwd=repo)
        self.assertEqual(use["skill_path"], str(skill))
        self.assertEqual(use["content_hash"], self.scanner_hash(text))

    def test_run_in_a_picked_folder_resolves_through_the_temp_transcript(self):
        skill = self.bundle_skill("docx", "# docx")
        picked = self.home / "Documents" / "Q3"
        picked.mkdir(parents=True)
        slug = re.sub(r"[^A-Za-z0-9]", "-", str(self.outputs))
        transcript = self.write(Path(self._tmp.name) / "claude-hostloop-plugins" / "h" / "projects" / slug / "s.jsonl", "")
        (use,) = self.run_turn(skill="anthropic-skills:docx", cwd=picked, transcript=transcript)
        self.assertEqual(use["skill_path"], str(skill))

    def test_hostile_skill_names_resolve_nothing_and_never_escape(self):
        self.write(self.home / "secret" / "SKILL.md", "# not a skill")
        for name in ("../../../secret", "anthropic-skills:../x", "x*", "C:evil", "a/b:..\\c"):
            with self.subTest(name=name):
                _Gateway.sent = []
                (use,) = self.run_turn(skill=name)
                self.assertNotIn("skill_path", use)
                self.assertNotIn("content_hash", use)

    def test_a_broken_or_huge_plugin_manifest_does_not_break_the_turn(self):
        plugin = self.org / "rpm" / "plugin_01"
        self.write(plugin / ".claude-plugin" / "plugin.json", "{not json" + "x" * 2_000_000)
        self.write(plugin / "skills" / "review" / "SKILL.md", "# review")
        (use,) = self.run_turn(skill="gtm-skills:review")
        self.assertNotIn("skill_path", use)


if __name__ == "__main__":
    unittest.main()
