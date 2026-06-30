"""Repo Allowlist client-hook tests: _get_git_context behavior and
git_remote_url payload parity across claude-code and copilot."""

import contextlib
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cc = _load("cc_unbound", "claude-code/hooks/unbound.py")
co = _load("co_unbound", "copilot/hooks/unbound.py")
cur = _load("cur_unbound", "cursor/unbound.py")

ALL_HOOKS = [("claude-code", cc), ("copilot", co), ("cursor", cur)]

# (label, module, native file-tool name, session-id key, file_path key)
HOOK_TOOL_CASES = [
    ("claude-code", cc, "Edit", "session_id", "file_path"),
    ("claude-code-multiedit", cc, "MultiEdit", "session_id", "file_path"),
    ("claude-code-notebookedit", cc, "NotebookEdit", "session_id", "notebook_path"),
    ("copilot", co, "Edit", "session_id", "filePath"),
    ("cursor", cur, "Write", "conversation_id", "file_path"),
]


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _make_repo(remote_url):
    d = tempfile.mkdtemp()
    _git(["init", "-q"], d)
    _git(["remote", "add", "origin", remote_url], d)
    return d


class TestGetGitContext(unittest.TestCase):
    def setUp(self):
        for _, mod in ALL_HOOKS:
            mod._GIT_CONTEXT_CACHE.clear()

    def _both(self):
        return ALL_HOOKS

    def test_returns_origin_url(self):
        repo = _make_repo("https://github.com/org/repo.git")
        for label, mod in self._both():
            with self.subTest(hook=label):
                self.assertEqual(
                    mod._get_git_context("s1", repo),
                    "https://github.com/org/repo.git",
                )

    def test_strips_credentials(self):
        repo = _make_repo("https://user:token@github.com/org/repo.git")
        for label, mod in self._both():
            with self.subTest(hook=label):
                result = mod._get_git_context("s1", repo)
                self.assertNotIn("user:token@", result)
                self.assertNotIn("@", result)
                self.assertEqual(result, "https://github.com/org/repo.git")

    def test_no_git_repo(self):
        plain = tempfile.mkdtemp()
        for label, mod in self._both():
            with self.subTest(hook=label):
                self.assertIsNone(mod._get_git_context("s1", plain))

    def test_no_cwd(self):
        for label, mod in self._both():
            with self.subTest(hook=label):
                self.assertIsNone(mod._get_git_context("s1", None))

    def test_git_missing_no_raise(self):
        for label, mod in self._both():
            with self.subTest(hook=label):
                with patch("subprocess.run", side_effect=FileNotFoundError()):
                    self.assertIsNone(mod._get_git_context("s_missing", "/x"))

    def test_timeout_no_raise(self):
        for label, mod in self._both():
            with self.subTest(hook=label):
                with patch("subprocess.run",
                           side_effect=subprocess.TimeoutExpired("git", 2)):
                    self.assertIsNone(mod._get_git_context("s_timeout", "/x"))

    def test_caches_per_session_cwd(self):
        repo = _make_repo("https://github.com/org/repo.git")
        for label, mod in self._both():
            with self.subTest(hook=label):
                mod._GIT_CONTEXT_CACHE.clear()
                real = subprocess.run
                with patch("subprocess.run", side_effect=real) as spy:
                    mod._get_git_context("s_cache", repo)
                    mod._get_git_context("s_cache", repo)
                    self.assertEqual(spy.call_count, 1)


def _capture(mod, fn, event):
    with contextlib.ExitStack() as stack:
        send = stack.enter_context(
            patch.object(mod, "send_to_hook_api", return_value={"decision": "allow"}))
        if hasattr(mod, "build_account_identity"):
            stack.enter_context(
                patch.object(mod, "build_account_identity", return_value={}))
        if hasattr(mod, "load_policy_cache"):
            stack.enter_context(patch.object(mod, "load_policy_cache", return_value=None))
        fn(event, "key")
        return send.call_args.args[0]


class TestRepoContextDir(unittest.TestCase):
    """The repo identity follows the operation target: the nearest existing
    ancestor of the edited/read file for file tools, the session cwd otherwise."""

    def test_uses_existing_target_directory(self):
        parent = tempfile.mkdtemp()
        sub = os.path.join(parent, "src")
        os.makedirs(sub)
        target = os.path.join(sub, "x.py")
        for mod in (cc, co, cur):
            with self.subTest(mod=mod.__name__):
                self.assertEqual(mod._repo_context_dir(parent, target), sub)

    def test_walks_up_to_nearest_existing_dir(self):
        parent = tempfile.mkdtemp()
        target = os.path.join(parent, "brand", "new", "deep", "file.py")
        for mod in (cc, co, cur):
            with self.subTest(mod=mod.__name__):
                self.assertEqual(mod._repo_context_dir(parent, target), parent)

    def test_falls_back_to_cwd_without_file_path(self):
        parent = tempfile.mkdtemp()
        for mod in (cc, co, cur):
            with self.subTest(mod=mod.__name__):
                self.assertEqual(mod._repo_context_dir(parent, None), parent)


class TestTargetDirResolution(unittest.TestCase):
    """A file tool launched from a non-git parent resolves to the subdir-repo
    it actually edits; a file outside any repo resolves to nothing."""

    def setUp(self):
        for _, mod in ALL_HOOKS:
            mod._GIT_CONTEXT_CACHE.clear()

    def test_file_in_subdir_repo_resolves_from_parent_cwd(self):
        parent = tempfile.mkdtemp()
        repo = Path(parent) / "service"
        (repo / "src").mkdir(parents=True)
        _git(["init", "-q"], str(repo))
        _git(["remote", "add", "origin", "https://github.com/org/service.git"], str(repo))
        target = str(repo / "src" / "x.py")

        for label, mod, tool, idk, pathk in HOOK_TOOL_CASES:
            with self.subTest(hook=label):
                body = _capture(mod, mod.process_pre_tool_use, {
                    idk: "t", "tool_name": tool, "cwd": parent,
                    "tool_input": {pathk: target}})
                self.assertEqual(
                    body["git_remote_url"], "https://github.com/org/service.git")

    def test_file_outside_any_repo_resolves_null(self):
        parent = tempfile.mkdtemp()
        target = str(Path(parent) / "notes.py")

        for label, mod, tool, idk, pathk in HOOK_TOOL_CASES:
            with self.subTest(hook=label):
                body = _capture(mod, mod.process_pre_tool_use, {
                    idk: "t2", "tool_name": tool, "cwd": parent,
                    "tool_input": {pathk: target}})
                self.assertIsNone(body["git_remote_url"])

    def test_warm_cache_still_sends_file_tool_when_listed(self):
        repo = _make_repo("https://github.com/org/repo.git")
        target = os.path.join(repo, "x.py")
        for label, mod, tool, idk, pathk in HOOK_TOOL_CASES:
            with self.subTest(hook=label), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(
                    mod, "load_policy_cache", return_value={"tools_to_check": [tool]}))
                stack.enter_context(patch.object(mod, "is_cache_stale", return_value=False))
                send = stack.enter_context(patch.object(
                    mod, "send_to_hook_api", return_value={"decision": "allow"}))
                if hasattr(mod, "build_account_identity"):
                    stack.enter_context(patch.object(mod, "build_account_identity", return_value={}))
                mod.process_pre_tool_use({
                    idk: "w", "tool_name": tool, "cwd": repo,
                    "tool_input": {pathk: target}}, "k")
                self.assertTrue(send.called)


class TestPayloadParity(unittest.TestCase):
    """The prompt path is no longer gated, so its body omits git_remote_url;
    the tool path carries it for both hooks."""

    def setUp(self):
        for _, mod in ALL_HOOKS:
            mod._GIT_CONTEXT_CACHE.clear()
        self.repo = _make_repo("https://github.com/org/repo.git")

    def test_tool_bodies_carry_git_remote_url(self):
        tool_event = {"session_id": "t", "tool_name": "Bash",
                      "tool_input": {"command": "ls"}, "cwd": self.repo}
        for label, mod in (("claude-code", cc), ("copilot", co)):
            body = _capture(mod, mod.process_pre_tool_use, dict(tool_event))
            with self.subTest(hook=label):
                self.assertEqual(
                    body["git_remote_url"], "https://github.com/org/repo.git")

    def test_prompt_bodies_omit_git_remote_url(self):
        prompt_event = {"session_id": "p", "prompt": "hi", "cwd": self.repo}
        for label, mod in (("claude-code", cc), ("copilot", co)):
            body = _capture(mod, mod.process_user_prompt_submit, dict(prompt_event))
            with self.subTest(hook=label):
                self.assertNotIn("git_remote_url", body)


class TestStripGitCredentials(unittest.TestCase):
    def _both(self):
        return ALL_HOOKS

    def _check(self, url, expected):
        for label, mod in self._both():
            with self.subTest(hook=label, url=url):
                out = mod._strip_git_credentials(url)
                self.assertEqual(out, expected)
                self.assertNotIn("@", out)

    def test_scheme_with_token(self):
        self._check("https://user:token@github.com/org/repo.git",
                    "https://github.com/org/repo.git")

    def test_scp_form_with_token(self):
        self._check("user:token@github.com:org/repo.git",
                    "github.com:org/repo.git")

    def test_scp_form_plain_user(self):
        self._check("git@github.com:org/repo.git",
                    "github.com:org/repo.git")

    def test_password_with_at_scheme(self):
        self._check("https://user:p@ss@w@rd@github.com/org/repo",
                    "https://github.com/org/repo")

    def test_password_with_at_scp(self):
        self._check("user:p@ss@github.com:org/repo",
                    "github.com:org/repo")

    def test_ssh_scheme_with_port(self):
        self._check("ssh://git@github.com:22/org/repo",
                    "ssh://github.com:22/org/repo")

    def test_no_userinfo_unchanged(self):
        for url in ("https://github.com/org/repo.git",
                    "github.com:org/repo.git", "", "/local/path/repo"):
            for label, mod in self._both():
                with self.subTest(hook=label, url=url):
                    self.assertEqual(mod._strip_git_credentials(url), url)


if __name__ == "__main__":
    unittest.main()
