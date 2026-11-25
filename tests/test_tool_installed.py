"""WEB-6392: whether a tool is installed, for the setup/complete status (skipped "<Tool> is not installed").

Every tool's MDM script is fetched and run on its own, so each carries the same check with its own
footprints; the unbound-hook binary calls the same function. These tests pin the footprints per OS, the
shared CLI folders, and that the five copies stay identical."""

import inspect
from pathlib import Path

import pytest

from tests.conftest import load_module

MODULES = {
    "claude-code": "claude-code/hooks/mdm/setup.py",
    "cursor": "cursor/mdm/setup.py",
    "codex": "codex/hooks/mdm/setup.py",
    "copilot": "copilot/hooks/mdm/setup.py",
    "augment": "augment/hooks/mdm/setup.py",
}
NAMES = {"claude-code": "Claude Code", "cursor": "Cursor", "codex": "Codex", "copilot": "GitHub Copilot",
         "augment": "Augment"}


def _mod(tool):
    return load_module(MODULES[tool])


@pytest.fixture
def box(tmp_path):
    """A machine root and one user home, both empty."""
    root, home = tmp_path / "root", tmp_path / "home"
    root.mkdir()
    home.mkdir()
    return root, home


def _plant(base: Path, relpath: str):
    """A file at relpath: the check only asks whether something is there."""
    path = base / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")


def _installed(tool, system, box):
    root, home = box
    return _mod(tool).tool_installed([("u", home)], system=system, machine_root=root)


FOOTPRINTS = [
    # (tool, system, "machine" or "home", path)
    ("claude-code", "darwin", "machine", "Applications/Claude.app"),
    ("claude-code", "darwin", "home", ".claude.json"),
    ("claude-code", "linux", "home", ".claude/local/claude"),
    ("claude-code", "windows", "home", ".local/bin/claude.exe"),
    ("claude-code", "windows", "home", "AppData/Local/AnthropicClaude"),
    ("cursor", "darwin", "machine", "Applications/Cursor.app"),
    ("cursor", "darwin", "home", ".local/bin/cursor-agent"),
    ("cursor", "linux", "machine", "usr/share/cursor"),
    ("cursor", "linux", "machine", "usr/bin/cursor"),
    ("cursor", "linux", "home", "Applications/Cursor-1.2.3-x86_64.AppImage"),
    ("cursor", "windows", "home", "AppData/Local/Programs/cursor"),
    ("cursor", "windows", "machine", "Program Files/Cursor"),
    ("codex", "darwin", "machine", "usr/local/bin/codex"),
    ("codex", "linux", "home", ".codex/auth.json"),
    ("codex", "windows", "home", "AppData/Roaming/npm/codex.cmd"),
    ("codex", "windows", "home", ".codex/sessions"),
    ("copilot", "darwin", "machine", "Applications/Visual Studio Code.app"),
    ("copilot", "darwin", "home", ".vscode/extensions/github.copilot-chat-0.30.0"),
    ("copilot", "linux", "machine", "usr/share/code"),
    ("copilot", "linux", "machine", "snap/bin/code"),
    ("copilot", "linux", "home", ".local/share/flatpak/app/com.visualstudio.code"),
    ("copilot", "windows", "home", "AppData/Local/Programs/Microsoft VS Code"),
    ("copilot", "windows", "machine", "Program Files/Microsoft VS Code"),
    # Visual Studio: the installer's instance registry (what the hook's _vs_installed reads) and the
    # Copilot chat log the hook's sweep reads.
    ("copilot", "windows", "machine", "ProgramData/Microsoft/VisualStudio/Packages/_Instances/3f1e2d4c"),
    ("copilot", "windows", "home", "AppData/Local/Temp/VSGitHubCopilotLogs/20261124_VSGitHubCopilot.chat.log"),
    # JetBrains: the Copilot plugin's own config (read by the hook and by discovery), and the plugin
    # folder in an IDE's per-user config (JetBrains and Google, as discovery scans them).
    ("copilot", "darwin", "home", ".config/github-copilot/intellij/mcp.json"),
    ("copilot", "linux", "home", ".config/github-copilot/intellij/global-copilot-instructions.md"),
    ("copilot", "windows", "home", "AppData/Local/github-copilot/intellij/mcp.json"),
    ("copilot", "darwin", "home", "Library/Application Support/JetBrains/IntelliJIdea2025.2/plugins/github-copilot-intellij/lib/x.jar"),
    ("copilot", "linux", "home", ".config/JetBrains/PyCharm2025.1/plugins/github-copilot-intellij/lib/x.jar"),
    ("copilot", "linux", "home", ".config/Google/AndroidStudio2025.1/plugins/github-copilot-intellij/lib/x.jar"),
    ("copilot", "windows", "home", "AppData/Roaming/JetBrains/Rider2025.2/plugins/github-copilot-intellij/lib/x.jar"),
    ("augment", "darwin", "home", ".vscode/extensions/augment.vscode-augment-0.512.0"),
    ("augment", "linux", "home", ".local/bin/auggie"),
    ("augment", "linux", "machine", "usr/bin/auggie"),
    ("augment", "windows", "home", ".cursor/extensions/augment.vscode-augment-0.512.0"),
    ("augment", "windows", "home", "AppData/Roaming/npm/auggie.ps1"),
]


@pytest.mark.parametrize("tool,system,where,relpath", FOOTPRINTS)
def test_each_footprint_counts_as_installed(box, tool, system, where, relpath):
    _plant(box[0] if where == "machine" else box[1], relpath)
    assert _installed(tool, system, box) is True


@pytest.mark.parametrize("system", ["darwin", "linux", "windows"])
@pytest.mark.parametrize("tool", sorted(MODULES))
def test_nothing_on_disk_is_not_installed(box, tool, system):
    assert _installed(tool, system, box) is False


@pytest.mark.parametrize("system,where,folder", [
    ("darwin", "machine", "opt/homebrew/bin"), ("darwin", "machine", "opt/local/bin"),
    ("darwin", "home", "Library/pnpm"), ("darwin", "home", ".volta/bin"),
    ("linux", "machine", "usr/local/bin"), ("linux", "machine", "var/lib/flatpak/exports/bin"),
    ("linux", "home", ".local/share/pnpm"), ("linux", "home", ".nvm/versions/node/v22.1.0/bin"),
    ("linux", "home", ".local/share/mise/installs/node/22.1.0/bin"), ("linux", "home", ".asdf/shims"),
    ("windows", "machine", "ProgramData/chocolatey/bin"), ("windows", "home", "scoop/shims"),
    ("windows", "home", "AppData/Local/Volta/bin"), ("windows", "home", "AppData/Roaming/nvm/v22.1.0"),
])
def test_every_tool_finds_its_cli_in_the_shared_folders(box, system, where, folder):
    for tool, module in MODULES.items():
        cli = _mod(tool).TOOL_CLI + (".cmd" if system == "windows" else "")
        _plant(box[0] if where == "machine" else box[1], f"{folder}/{cli}")
        assert _installed(tool, system, box) is True, tool


def test_a_tool_is_not_found_by_another_tools_footprint(box):
    _plant(box[0], "Applications/Cursor.app")
    assert _installed("copilot", "darwin", box) is False


@pytest.mark.parametrize("prefix", ["~/.npm-packages", "$HOME/.npm-packages", "${HOME}/.npm-packages"])
def test_an_npm_prefix_from_npmrc_counts_on_unix(box, prefix):
    _, home = box
    (home / ".npmrc").write_text(f"; comment\nprefix = {prefix}\n")
    _plant(home, ".npm-packages/bin/codex")
    assert _installed("codex", "linux", box) is True


def test_a_linked_npmrc_is_not_followed(box, tmp_path):
    _, home = box
    elsewhere = tmp_path / "elsewhere.npmrc"
    elsewhere.write_text(f"prefix={home}/.npm-packages\n")
    (home / ".npmrc").symlink_to(elsewhere)
    _plant(home, ".npm-packages/bin/codex")
    assert _installed("codex", "linux", box) is False


def test_a_check_that_fails_counts_as_installed(box, monkeypatch):
    def broken():
        raise RuntimeError("no account database")
        yield  # noqa: unreachable, makes this a generator
    root, _ = box
    assert _mod("cursor").tool_installed(broken(), system="linux", machine_root=root) is True
    # A place that can't be looked at says nothing about the tool, so it counts too.
    monkeypatch.setattr(Path, "exists", lambda self, *a, **k: (_ for _ in ()).throw(PermissionError(13, "denied")))
    assert _installed("cursor", "linux", box) is True


def test_each_module_names_its_tool():
    assert {tool: _mod(tool).TOOL_NAME for tool in MODULES} == NAMES


SHARED_FUNCTIONS = ("_install_root", "_found", "_npmrc_cli_dir", "tool_installed")
SHARED_DATA = ("_UNIX_HOME_CLI_DIRS", "_CLI_DIRS", "_CLI_SUFFIXES")


@pytest.mark.parametrize("name", SHARED_FUNCTIONS + SHARED_DATA)
def test_the_five_copies_are_identical(name):
    def value(tool):
        obj = getattr(_mod(tool), name)
        return inspect.getsource(obj) if callable(obj) else obj
    first = value("claude-code")
    assert all(value(tool) == first for tool in MODULES), name
