"""Repo Allowlist client-hook tests: _get_git_context behavior and
git_remote_url payload parity across claude-code and copilot."""

import contextlib
import importlib.util
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
        cc._GIT_CONTEXT_CACHE.clear()
        co._GIT_CONTEXT_CACHE.clear()

    def _both(self):
        return [("claude-code", cc), ("copilot", co)]

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


class TestPayloadParity(unittest.TestCase):
    """git_remote_url must appear with the same key/shape in both the
    user_prompt and pre_tool_use bodies for claude-code and copilot.

    Copilot's UserPromptSubmit cwd is UNVERIFIED in-repo; the hook reads
    event.get('cwd') defensively, so the field is present and null when cwd
    is absent (contract-compatible) and populated when cwd is supplied."""

    def setUp(self):
        cc._GIT_CONTEXT_CACHE.clear()
        co._GIT_CONTEXT_CACHE.clear()
        self.repo = _make_repo("https://github.com/org/repo.git")
        self.expected = "https://github.com/org/repo.git"

    def _capture(self, mod, fn, event):
        with contextlib.ExitStack() as stack:
            send = stack.enter_context(
                patch.object(mod, "send_to_hook_api", return_value={"decision": "allow"}))
            if hasattr(mod, "build_account_identity"):
                stack.enter_context(
                    patch.object(mod, "build_account_identity", return_value={}))
            fn(event, "key")
            return send.call_args.args[0]

    def test_all_four_bodies_carry_git_remote_url(self):
        prompt_event = {"session_id": "p", "prompt": "hi", "cwd": self.repo}
        tool_event = {"session_id": "t", "tool_name": "Bash",
                      "tool_input": {"command": "ls"}, "cwd": self.repo}

        bodies = {
            "cc_prompt": self._capture(cc, cc.process_user_prompt_submit, dict(prompt_event)),
            "cc_tool": self._capture(cc, cc.process_pre_tool_use, dict(tool_event)),
            "co_prompt": self._capture(co, co.process_user_prompt_submit, dict(prompt_event)),
            "co_tool": self._capture(co, co.process_pre_tool_use, dict(tool_event)),
        }

        for name, body in bodies.items():
            with self.subTest(body=name):
                self.assertIn("git_remote_url", body)
                self.assertEqual(body["git_remote_url"], self.expected)

    def test_field_is_null_when_no_cwd(self):
        prompt_event = {"session_id": "n", "prompt": "hi"}
        for mod in (cc, co):
            body = self._capture(mod, mod.process_user_prompt_submit, dict(prompt_event))
            with self.subTest(mod=mod.__name__):
                self.assertIn("git_remote_url", body)
                self.assertIsNone(body["git_remote_url"])


class TestStripGitCredentials(unittest.TestCase):
    def _both(self):
        return [("claude-code", cc), ("copilot", co)]

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
