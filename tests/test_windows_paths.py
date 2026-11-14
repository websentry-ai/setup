"""WEB-6740: Windows paths (C:\\x, C:/x, Git Bash /c/x) resolve to a repo and branch like /x does."""

import os
import subprocess

import pytest

from tests.conftest import tool_module

HOOKS = {
    "claude-code": "claude-code/hooks",
    "cursor": "cursor",
    "copilot": "copilot/hooks",
    "codex": "codex/hooks",
    "augment": "augment/hooks",
}
TOOL_HOOKS = ["claude-code", "augment"]
BRANCH = "feat/windows"

windows_only = pytest.mark.skipif(os.name != "nt", reason="needs a real Windows filesystem")


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _git_bash_path(path):
    """C:\\Users\\x -> /c/Users/x, the way Git Bash prints it."""
    drive, rest = os.path.splitdrive(str(path))
    return "/" + drive[0].lower() + rest.replace("\\", "/")


def _make_repo(r):
    r.mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    _git(r, "remote", "add", "origin", "https://github.com/acme/web.git")
    _git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init")
    _git(r, "switch", "-q", "-c", BRANCH)
    (r / "src").mkdir()
    return r


@pytest.fixture
def repo(tmp_path):
    return _make_repo(tmp_path / "web")


@pytest.mark.parametrize("tool", sorted(HOOKS))
class TestPathHelpers:
    """String-only checks, so they run on every OS."""

    def test_drive_paths_are_absolute_only_on_windows(self, tool, monkeypatch):
        m = tool_module(HOOKS[tool])
        monkeypatch.setattr(m, "_WINDOWS_PATHS", True)
        assert m._is_abs_path("C:\\repo\\a.py")
        assert m._is_abs_path("c:/repo/a.py")
        assert m._is_abs_path("/repo/a.py")
        assert m._is_abs_path("\\\\server\\share\\repo\\a.py")
        assert not m._is_abs_path("C:repo")
        assert not m._is_abs_path("src\\a.py")
        monkeypatch.setattr(m, "_WINDOWS_PATHS", False)
        assert not m._is_abs_path("C:\\repo\\a.py")
        assert not m._is_abs_path("\\\\server\\share\\repo\\a.py")
        assert m._is_abs_path("/repo/a.py")

    def test_git_bash_drive_becomes_a_windows_drive(self, tool, monkeypatch):
        m = tool_module(HOOKS[tool])
        monkeypatch.setattr(m, "_WINDOWS_PATHS", True)
        assert m._native_path("/c/Users/me/web") == "C:/Users/me/web"
        assert m._native_path("\\d\\work\\web") == "D:\\work\\web"
        assert m._native_path("/c") == "C:\\"
        assert m._native_path("/tmp/web") == "/tmp/web"
        assert m._native_path("C:\\Users\\me") == "C:\\Users\\me"

    def test_other_systems_leave_paths_alone(self, tool, monkeypatch):
        m = tool_module(HOOKS[tool])
        monkeypatch.setattr(m, "_WINDOWS_PATHS", False)
        assert m._native_path("/c/Users/me/web") == "/c/Users/me/web"


@windows_only
@pytest.mark.parametrize("tool", sorted(HOOKS))
class TestWindowsResolution:
    def test_a_git_bash_path_finds_the_repo_root(self, tool, repo):
        m = tool_module(HOOKS[tool])
        assert os.path.normcase(m._find_git_root(_git_bash_path(repo / "src"))) == os.path.normcase(str(repo))

    def test_a_forward_slash_drive_path_in_a_command_is_found(self, tool, repo):
        m = tool_module(HOOKS[tool])
        target = str(repo / "src").replace("\\", "/")
        assert target in m._ABS_PATH_RE.findall("ls %s" % target)


@windows_only
@pytest.mark.parametrize("tool", TOOL_HOOKS)
class TestWindowsShellTracking:
    def test_a_git_bash_cd_resolves_project_and_branch(self, tool, repo):
        m = tool_module(HOOKS[tool])
        command = "cd %s && git status" % _git_bash_path(repo)
        project, branch, _ = m._repo_for_tool_use("Bash", {"command": command}, None, {})
        assert (project, branch) == ("acme/web", BRANCH)

    def test_a_quoted_forward_slash_cd_resolves_project_and_branch(self, tool, repo):
        m = tool_module(HOOKS[tool])
        command = 'cd "%s" && git status' % str(repo).replace("\\", "/")
        project, branch, _ = m._repo_for_tool_use("Bash", {"command": command}, None, {})
        assert (project, branch) == ("acme/web", BRANCH)

    def test_a_relative_write_after_a_git_bash_cd_resolves_project_and_branch(self, tool, repo):
        m = tool_module(HOOKS[tool])
        _, _, shell_dir = m._repo_for_tool_use("Bash", {"command": "cd %s" % _git_bash_path(repo)}, None, {})
        project, branch, _ = m._repo_for_tool_use("Write", {"file_path": "src/a.py"}, shell_dir, {})
        assert (project, branch) == ("acme/web", BRANCH)

    def test_a_backslash_file_path_resolves_project_and_branch(self, tool, repo):
        m = tool_module(HOOKS[tool])
        path = str(repo / "src" / "a.py")
        project, branch, _ = m._repo_for_tool_use("Write", {"file_path": path}, None, {})
        assert (project, branch) == ("acme/web", BRANCH)


ALLOWED_ONLY = [{"github_org": "allowed"}]


def _gate_candidates(tool, m, cwd, command=None, file_path=None):
    """Paths the repo-scope gate judges for one shell command or one file write."""
    if tool == "claude-code":
        tool_name, tool_input = ("Bash", {"command": command}) if command else ("Write", {"file_path": file_path})
        return m._tool_use_path_candidates(tool_name, tool_input, cwd)[0]
    if tool == "cursor":
        if command:
            return m._repo_gate_candidates({"cwd": cwd}, m._REPO_GATE_SHELL_TOOL, command)
        return m._repo_gate_candidates({"cwd": cwd, "file_path": file_path}, "Write", None)
    shell_tool = next(iter(m._REPO_GATE_SHELL_TOOLS))
    if command:
        return m._repo_gate_candidates(shell_tool, {"command": command}, cwd)
    return m._repo_gate_candidates("Write", {"file_path": file_path}, cwd)


@windows_only
@pytest.mark.parametrize("tool", sorted(HOOKS))
class TestWindowsRepoGate:
    """A write into a repo outside the allowed org is caught, not let through."""

    def test_a_backslash_write_path_is_judged(self, tool, repo, tmp_path):
        m = tool_module(HOOKS[tool])
        candidates = _gate_candidates(tool, m, str(tmp_path), file_path=str(repo / "src" / "a.py"))
        assert m._repo_gate_violating_repo(candidates, ALLOWED_ONLY, {}) == "acme/web"

    def test_a_git_bash_path_in_a_command_is_judged(self, tool, repo, tmp_path):
        m = tool_module(HOOKS[tool])
        command = "touch %s/a.txt" % _git_bash_path(repo)
        candidates = _gate_candidates(tool, m, str(tmp_path), command=command)
        assert m._repo_gate_violating_repo(candidates, ALLOWED_ONLY, {}) == "acme/web"

    @pytest.mark.parametrize("quote", ['"', "'"])
    @pytest.mark.parametrize("spelling", ["drive", "git-bash"])
    def test_a_quoted_path_with_a_space_is_judged(self, tool, tmp_path, quote, spelling):
        m = tool_module(HOOKS[tool])
        spaced = _make_repo(tmp_path / "John Smith" / "web")
        target = str(spaced / "a.txt") if spelling == "drive" else _git_bash_path(spaced / "a.txt")
        command = "touch %s%s%s" % (quote, target, quote)
        candidates = _gate_candidates(tool, m, str(tmp_path), command=command)
        assert m._repo_gate_violating_repo(candidates, ALLOWED_ONLY, {}) == "acme/web"
