"""Where the pi installer decides to put the extension, and the preflight around it.

This is the one calculation that can report success while installing nowhere pi
looks (RESEARCH E2), so every branch of hooks-ts/packages/core/src/cache.ts:68-95
is pinned here rather than assumed.
"""

from pathlib import Path

import pytest


class TestResolveAgentDir:
    def test_it_matches_the_extension_for_all_four_env_states(self, pi_setup, pi_home, agent_dir_cases):
        """unset / absolute / ~ / relative -- the four states cache.ts distinguishes."""
        for case in agent_dir_cases:
            env = case.env(pi_home.env)
            got = pi_setup.resolve_agent_dir(pi_home.home, env)
            assert Path(got) == case.expected_base, case.name

    def test_unset_is_the_home_default(self, pi_setup, pi_home):
        got = pi_setup.resolve_agent_dir(pi_home.home, {})
        assert Path(got) == pi_home.home / ".pi" / "agent"

    def test_a_blank_value_is_the_home_default(self, pi_setup, pi_home):
        """An exported-but-empty var is how a shell profile leaves it; not a base."""
        for blank in ("", "   ", "\t\n"):
            got = pi_setup.resolve_agent_dir(pi_home.home, {"PI_CODING_AGENT_DIR": blank})
            assert Path(got) == pi_home.home / ".pi" / "agent", repr(blank)

    def test_an_absolute_value_is_returned_as_is(self, pi_setup, pi_home):
        target = pi_home.home / "elsewhere"
        got = pi_setup.resolve_agent_dir(pi_home.home, {"PI_CODING_AGENT_DIR": str(target)})
        assert Path(got) == target

    def test_a_bare_tilde_is_home_itself(self, pi_setup, pi_home):
        got = pi_setup.resolve_agent_dir(pi_home.home, {"PI_CODING_AGENT_DIR": "~"})
        assert Path(got) == pi_home.home

    def test_tilde_expands_against_the_passed_home_not_the_process_env(self, pi_setup, pi_home, monkeypatch):
        """cache.ts expands against an explicit homeDir; a developer's real HOME
        leaking in here would put the file on their own machine under test."""
        monkeypatch.setenv("HOME", "/nonexistent-real-home")
        got = pi_setup.resolve_agent_dir(pi_home.home, {"PI_CODING_AGENT_DIR": "~/tilde-agent"})
        assert Path(got) == pi_home.home / "tilde-agent"

    @pytest.mark.parametrize("value", ["relative-agent", "./relative-agent", "../relative-agent", "a/b"])
    def test_a_relative_value_falls_back_to_the_home_default(self, pi_setup, pi_home, monkeypatch, tmp_path, value):
        """The failure mode this test exists for: resolving against cwd would write
        the extension into whatever directory the CLI happened to be run from."""
        cwd = tmp_path / "cwd"
        (cwd / "relative-agent").mkdir(parents=True)
        monkeypatch.chdir(cwd)
        got = pi_setup.resolve_agent_dir(pi_home.home, {"PI_CODING_AGENT_DIR": value})
        assert Path(got) == pi_home.home / ".pi" / "agent"
        assert str(cwd) not in str(got)

    def test_no_safe_base_means_none_rather_than_a_guess(self, pi_setup):
        """cache.ts returns undefined when homeDir is missing or relative; joining
        from "" would put the extension inside the repo pi was started in."""
        assert pi_setup.resolve_agent_dir("", {}) is None
        assert pi_setup.resolve_agent_dir("not/absolute", {}) is None
        assert pi_setup.resolve_agent_dir(None, {}) is None


class TestPaths:
    def test_extension_dir_and_artifact_path(self, pi_setup, pi_home):
        extdir = pi_setup.extension_dir(pi_home.agent_dir)
        assert Path(extdir) == pi_home.extension_dir()
        assert Path(extdir).name == "unbound"
        assert Path(pi_setup.artifact_path(pi_home.agent_dir)) == pi_home.extension_dir() / "index.js"

    def test_the_artifact_is_index_js_not_index_ts(self, pi_setup, pi_home):
        """The built extension is JavaScript; .ts would be the file that shadows it."""
        assert str(pi_setup.artifact_path(pi_home.agent_dir)).endswith("index.js")


class _FakeRun:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class TestPreflight:
    def test_a_missing_pi_warns_and_never_blocks(self, pi_setup, monkeypatch, capsys):
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: None)
        assert pi_setup.preflight() is True
        out = capsys.readouterr().out
        assert "pi" in out and "PATH" in out

    def test_an_older_pi_warns_and_never_blocks(self, pi_setup, monkeypatch, capsys):
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: "/somewhere/bin/pi")
        monkeypatch.setattr(pi_setup.subprocess, "run", lambda *a, **k: _FakeRun("0.50.0\n"))
        assert pi_setup.preflight() is True
        out = capsys.readouterr().out
        assert pi_setup.TESTED_PI_VERSION in out

    def test_the_tested_version_is_accepted_quietly_enough(self, pi_setup, monkeypatch, capsys):
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: "/somewhere/bin/pi")
        monkeypatch.setattr(pi_setup.subprocess, "run",
                            lambda *a, **k: _FakeRun(pi_setup.TESTED_PI_VERSION + "\n"))
        assert pi_setup.preflight() is True
        assert "older" not in capsys.readouterr().out

    def test_an_unparseable_version_is_not_an_error(self, pi_setup, monkeypatch):
        """A pre-release or a reworded --version must not turn into a traceback."""
        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: "/somewhere/bin/pi")
        monkeypatch.setattr(pi_setup.subprocess, "run", lambda *a, **k: _FakeRun("pi version next\n"))
        assert pi_setup.preflight() is True

    def test_a_crashing_pi_is_not_an_error(self, pi_setup, monkeypatch):
        def boom(*a, **k):
            raise OSError("cannot exec")

        monkeypatch.setattr(pi_setup.shutil, "which", lambda name: "/somewhere/bin/pi")
        monkeypatch.setattr(pi_setup.subprocess, "run", boom)
        assert pi_setup.preflight() is True


class TestArgParsing:
    def test_every_flag_the_cli_passes_is_understood(self, pi_setup):
        argv = ["setup.py", "--api-key", "k-123", "--backend-url", "backend.example.com",
                "--gateway-url", "https://gw.example.com/", "--domain", "app.example.com", "--debug"]
        args = pi_setup.parse_args(argv)
        assert args["api_key"] == "k-123"
        assert args["backend_url"] == "https://backend.example.com"
        assert args["gateway_url"] == "https://gw.example.com"
        assert args["domain"] == "app.example.com"
        assert args["debug"] is True
        assert args["clear"] is False

    def test_defaults_when_only_a_key_is_passed(self, pi_setup):
        args = pi_setup.parse_args(["setup.py", "--api-key", "k"])
        assert args["backend_url"] == pi_setup.DEFAULT_BACKEND_URL
        assert args["gateway_url"] == pi_setup.DEFAULT_GATEWAY_URL
        assert args["domain"] is None
        assert args["clear"] is False

    def test_clear_is_recognised_without_a_key(self, pi_setup):
        args = pi_setup.parse_args(["setup.py", "--clear"])
        assert args["clear"] is True
        assert args["api_key"] is None

    def test_a_flag_with_no_value_does_not_crash(self, pi_setup):
        """`--api-key` as the last token is a CLI bug, not an installer traceback."""
        args = pi_setup.parse_args(["setup.py", "--api-key"])
        assert args["api_key"] is None
