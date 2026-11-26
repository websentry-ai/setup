"""Which MCP server the Codex hook reports when servers live in project config.

Codex reads a project's .codex/config.toml only once the project's git root is
trusted in $CODEX_HOME/config.toml; the file nearest the cwd wins, and project
servers win over user ones. Drives the real PreToolUse path.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.conftest import tool_module

unbound = tool_module("codex/hooks")

FS_TOML = 'command = "npx"\nargs = ["-y", "@modelcontextprotocol/server-filesystem", "/data"]\n'
OTHER_TOML = 'command = "python3"\nargs = ["/opt/other_server.py"]\n'
FS = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]}
OTHER = {"command": "python3", "args": ["/opt/other_server.py"]}


class CodexProjectMcpConfig(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.user_config = root / "codex_home" / "config.toml"
        self.user_config.parent.mkdir()
        self.user_config.write_text("")
        self.repo = root / "repo"
        (self.repo / ".git").mkdir(parents=True)
        self.cwd = self.repo
        self._patchers = [
            patch.object(unbound, "CODEX_CONFIG_PATH", self.user_config),
            patch.object(unbound, "load_policy_cache", lambda: {"tools_to_check": [], "ts": 0}),
            patch.object(unbound, "is_cache_stale", lambda c: False),
            patch.object(unbound, "get_recent_user_prompts_for_session", lambda *a, **k: []),
            patch.object(unbound, "_is_approval_retry", lambda *a, **k: False),
            patch.object(unbound, "build_account_identity", lambda *a, **k: {}),
            patch.object(unbound, "report_error_to_gateway", lambda *a, **k: None),
            patch.object(unbound, "_dispatch_mcp_server_scan", lambda *a, **k: None),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        self._tmp.cleanup()

    def _user(self, *, server=None, trust=None):
        text = f"[mcp_servers.fsx]\n{server}" if server else ""
        if trust:
            text += f'\n[projects."{trust}"]\ntrust_level = "trusted"\n'
        self.user_config.write_text(text)

    def _project(self, folder, server):
        (folder / ".codex").mkdir(parents=True, exist_ok=True)
        (folder / ".codex" / "config.toml").write_text(f"[mcp_servers.fsx]\n{server}")

    def forwarded(self):
        sent = {}

        def fake_send(body, api_key):
            sent["md"] = body["pre_tool_use_data"]["metadata"]
            return {"decision": "allow"}

        event = {"hook_event_name": "PreToolUse", "tool_name": "mcp__fsx__write_file",
                 "tool_input": {}, "cwd": str(self.cwd), "session_id": "s"}
        with patch.object(unbound, "send_to_hook_api", fake_send):
            unbound.process_pre_tool_use(event, "API_KEY")
        return sent.get("md", {}).get("mcp_server_config")

    def test_trusted_project_server_is_forwarded(self):
        self._user(trust=self.repo)
        self._project(self.repo, FS_TOML)
        self.assertEqual(self.forwarded(), FS)

    def test_untrusted_project_is_ignored_like_codex_does(self):
        self._project(self.repo, FS_TOML)
        self.assertIsNone(self.forwarded())

    def test_trust_is_keyed_to_the_git_root_not_the_subfolder(self):
        sub = self.repo / "pkg"
        sub.mkdir()
        self._user(trust=sub)
        self._project(self.repo, FS_TOML)
        self.cwd = sub
        self.assertIsNone(self.forwarded())

    def test_root_file_is_read_from_a_subfolder(self):
        sub = self.repo / "pkg"
        sub.mkdir()
        self._user(trust=self.repo)
        self._project(self.repo, FS_TOML)
        self.cwd = sub
        self.assertEqual(self.forwarded(), FS)

    def test_nearest_project_file_wins(self):
        sub = self.repo / "pkg"
        self._user(trust=self.repo)
        self._project(self.repo, OTHER_TOML)
        self._project(sub, FS_TOML)
        self.cwd = sub
        self.assertEqual(self.forwarded(), FS)

    def _real_worktree(self):
        import shutil
        import subprocess
        shutil.rmtree(self.repo / ".git")
        git = lambda *a: subprocess.run(["git", *a], check=True, capture_output=True)
        git("-C", str(self.repo), "init", "-q")
        git("-C", str(self.repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "i")
        wt = self.repo.parent / "wt"
        git("-C", str(self.repo), "worktree", "add", "-q", str(wt))
        return wt

    def test_linked_worktree_inherits_the_main_checkouts_trust(self):
        wt = self._real_worktree()
        self._user(trust=self.repo)
        self._project(wt, FS_TOML)
        self.cwd = wt
        self.assertEqual(self.forwarded(), FS)

    def test_forged_git_file_does_not_borrow_another_repos_trust(self):
        # A hand-written .git pointer with no backlink from the trusted repo's admin dir.
        gitdir = self.repo / ".git" / "worktrees" / "wt"
        gitdir.mkdir(parents=True)
        (gitdir / "commondir").write_text("../..\n")
        wt = self.repo.parent / "wt"
        wt.mkdir()
        (wt / ".git").write_text(f"gitdir: {gitdir}\n")
        self._user(trust=self.repo)
        self._project(wt, FS_TOML)
        self.cwd = wt
        self.assertIsNone(self.forwarded())

    def test_symlinked_git_file_does_not_borrow_a_worktrees_trust(self):
        wt = self._real_worktree()
        link = self.repo.parent / "link"
        link.mkdir()
        (link / ".git").symlink_to(wt / ".git")
        self._user(trust=self.repo)
        self._project(link, FS_TOML)
        self.cwd = link
        self.assertIsNone(self.forwarded())

    def test_worktrees_folder_outside_git_does_not_vouch_for_another_checkout(self):
        # Ordinary files a trusted repo could commit, laid out like worktree metadata.
        evil = self.repo.parent / "evil"
        evil.mkdir()
        admin = self.repo / "decoy" / "worktrees" / "x"
        admin.mkdir(parents=True)
        (admin / "commondir").write_text("../..\n")
        (admin / "gitdir").write_text(f"{evil / '.git'}\n")
        (evil / ".git").write_text(f"gitdir: {admin}\n")
        self._user(trust=self.repo)
        self._project(evil, FS_TOML)
        self.cwd = evil
        self.assertIsNone(self.forwarded())

    def test_project_fields_merge_over_the_user_definition(self):
        self._user(server=FS_TOML, trust=self.repo)
        (self.repo / ".codex").mkdir()
        (self.repo / ".codex" / "config.toml").write_text('[mcp_servers.fsx]\nargs = ["/opt/other_server.py"]\n')
        self.assertEqual(self.forwarded(), {"command": "npx", "args": ["/opt/other_server.py"]})

    def test_project_can_clear_the_user_args(self):
        self._user(server=FS_TOML, trust=self.repo)
        self._project(self.repo, "args = []\n")
        self.assertEqual(self.forwarded(), {"command": "npx"})

    def test_project_beats_user_with_the_same_name(self):
        self._user(server=OTHER_TOML, trust=self.repo)
        self._project(self.repo, FS_TOML)
        self.assertEqual(self.forwarded(), FS)

    def test_user_config_still_used_without_a_project_entry(self):
        self._user(server=FS_TOML, trust=self.repo)
        self.assertEqual(self.forwarded(), FS)

    def test_files_above_the_git_root_are_not_project_config(self):
        self._user(trust=self.repo)
        self._project(self.repo.parent, FS_TOML)
        self.assertIsNone(self.forwarded())

    def test_without_tomllib_the_fallback_parser_agrees(self):
        self._user(server=OTHER_TOML, trust=self.repo)
        self._project(self.repo, FS_TOML)
        with patch.dict(sys.modules, {"tomllib": None}):
            self.assertEqual(self.forwarded(), FS)

    def test_without_tomllib_an_untrusted_project_is_ignored(self):
        self.user_config.write_text(f'[projects."{self.repo}"]\ntrust_level = "untrusted"\n')
        self._project(self.repo, FS_TOML)
        with patch.dict(sys.modules, {"tomllib": None}):
            self.assertIsNone(self.forwarded())


if __name__ == "__main__":
    unittest.main()
