"""
Tests for get_api_key in codex/hooks/unbound.py (WEB-4812).

The hook must fall back to ~/.unbound/config.json when UNBOUND_CODEX_API_KEY
is not in the environment — codex launched from VS Code, GUI launchers, or
terminals opened before setup ran never sees shell-profile env vars, and
without the fallback every exchange is silently dropped (send_to_api no-ops,
policy checks fail open, and error reporting itself needs the key).

Mirrors the WEB-4145 fix that gave Claude Code (then cursor and copilot)
the same two-tier lookup.
"""

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unbound


class TestGetApiKey(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_path = Path(self._tmp.name) / "config.json"
        patcher = patch.object(unbound, "UNBOUND_CONFIG_PATH", self.config_path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_env_var_wins_over_config(self):
        self.config_path.write_text(json.dumps({"api_key": "from-config"}))
        with patch.dict(os.environ, {"UNBOUND_CODEX_API_KEY": "from-env"}):
            self.assertEqual(unbound.get_api_key(), "from-env")

    def test_falls_back_to_unbound_config(self):
        self.config_path.write_text(json.dumps({"api_key": "from-config"}))
        with patch.dict(os.environ):
            os.environ.pop("UNBOUND_CODEX_API_KEY", None)
            self.assertEqual(unbound.get_api_key(), "from-config")

    def test_no_env_no_config_returns_none(self):
        with patch.dict(os.environ):
            os.environ.pop("UNBOUND_CODEX_API_KEY", None)
            self.assertIsNone(unbound.get_api_key())

    def test_invalid_config_json_returns_none(self):
        self.config_path.write_text("{not json")
        with patch.dict(os.environ), \
                patch.object(unbound, "log_error") as mock_log:
            os.environ.pop("UNBOUND_CODEX_API_KEY", None)
            self.assertIsNone(unbound.get_api_key())
        mock_log.assert_called_once()
        self.assertEqual(mock_log.call_args[0][1], "config")

    def test_config_without_api_key_returns_none(self):
        self.config_path.write_text(json.dumps({"base_url": "https://x"}))
        with patch.dict(os.environ):
            os.environ.pop("UNBOUND_CODEX_API_KEY", None)
            self.assertIsNone(unbound.get_api_key())


class TestStopEventUsesConfigKey(unittest.TestCase):
    """Regression for the WEB-4812 silent drop: with no env var, a Stop
    exchange must still be sent using the ~/.unbound/config.json key."""

    def test_stop_event_sends_with_config_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(json.dumps({"api_key": "cfg-key"}))
            prompt_log = [{
                "timestamp": "2026-06-12T00:00:00Z",
                "session_id": "sess-1",
                "event": {
                    "hook_event_name": "UserPromptSubmit",
                    "session_id": "sess-1",
                    "prompt": "hi",
                },
            }]
            stop_event = json.dumps({
                "hook_event_name": "Stop",
                "session_id": "sess-1",
                "last_assistant_message": "answer",
            })
            sent = {}

            def fake_send(exchange, api_key):
                sent["exchange"] = exchange
                sent["api_key"] = api_key
                return True

            with patch.dict(os.environ), \
                    patch.object(unbound, "UNBOUND_CONFIG_PATH", config_path), \
                    patch.object(unbound, "send_to_api", fake_send), \
                    patch.object(unbound, "load_existing_logs", return_value=prompt_log), \
                    patch.object(unbound, "append_to_audit_log"), \
                    patch.object(unbound, "cleanup_old_logs"), \
                    patch.object(unbound.sys, "stdin", io.StringIO(stop_event)):
                os.environ.pop("UNBOUND_CODEX_API_KEY", None)
                unbound.main()

            self.assertEqual(sent.get("api_key"), "cfg-key")
            self.assertEqual(sent["exchange"]["conversation_id"], "sess-1")
            self.assertEqual(
                sent["exchange"]["messages"][0]["content"], "hi")


if __name__ == "__main__":
    unittest.main()
