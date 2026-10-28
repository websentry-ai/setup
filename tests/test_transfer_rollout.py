"""The Copilot usage backfill replays past turns without resolving their transfers again."""
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import REPO, load_module

FAKE_SSH = """#!/bin/sh
echo "$@" >> "$SSH_LOG"
echo "hostname 10.0.4.12"
"""


class TestCopilotBackfillLooksNothingUp(unittest.TestCase):
    """Replaying past turns reads MCP provenance only, so a past scp is never resolved again."""

    def test_a_past_shell_transfer_runs_no_ssh_and_no_dns(self):
        for module in ("copilot/hooks/setup.py", "copilot/hooks/mdm/setup.py"):
            with self.subTest(module=module), tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                home, copilot_home, bin_dir = tmp / "home", tmp / "copilot", tmp / "bin"
                (home / ".ssh").mkdir(parents=True)
                (home / ".ssh" / "config").write_text("Host backup\n  HostName 10.0.4.12\n")
                (copilot_home / "hooks").mkdir(parents=True)
                shutil.copy(REPO / "copilot" / "hooks" / "unbound.py", copilot_home / "hooks" / "unbound.py")
                bin_dir.mkdir()
                ssh = bin_dir / "ssh"
                ssh.write_text(FAKE_SSH)
                ssh.chmod(ssh.stat().st_mode | stat.S_IEXEC)
                log = tmp / "ssh.log"
                entries = [{"type": "tool.execution_start", "cwd": str(tmp), "data": {
                    "toolCallId": "c1", "toolName": "bash", "arguments": {"command": "scp customers.sql backup:/srv"}}}]
                env = {"HOME": str(home), "COPILOT_HOME": str(copilot_home), "SSH_LOG": str(log),
                       "PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin"}
                setup = load_module(module)
                setup._BACKFILL_HOOK_MODULE = None
                with patch.dict(os.environ, env), patch("socket.getaddrinfo") as lookup:
                    setup._backfill_mcp_tool_provenance(entries)
                self.assertFalse(log.exists(), log.read_text() if log.exists() else "")
                lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
