"""Whether a coding tool is on this machine, reported beside its install state.

Setup hooks every tool on every profile, so a machine that never had a tool still
reports an install state for it. This lets the backend leave those out. It leans to
"present": a wrong "absent" would hide a real tamper, a wrong "present" only keeps
today's count. Paths are only stat'ed, never opened or run, and nothing setup itself
writes (~/.unbound, ~/.codex/hooks*, ~/.codex/config.toml, ~/.copilot/hooks) counts.
"""

import itertools
from pathlib import Path

_MACHINE_BIN_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin")
_USER_BIN_DIRS = (
    ".local/bin", ".bun/bin", ".npm-global/bin", ".volta/bin", ".cargo/bin", ".yarn/bin",
    "Library/pnpm", ".local/share/pnpm", ".config/yarn/global/node_modules/.bin",
    ".nvm/versions/node/*/bin", ".local/share/fnm/node-versions/*/installation/bin",
    ".fnm/node-versions/*/installation/bin", ".asdf/installs/nodejs/*/bin",
    ".local/share/mise/installs/node/*/bin",
)
_EDITOR_DIRS = (".vscode", ".vscode-insiders", ".vscode-oss", ".cursor", ".windsurf")
_APP_DIRS = ("/Applications",)
# Bounds the work per pattern: a session folder can hold thousands of files.
_MAX_MATCHES = 64

# binaries: names on a bin dir; paths: other per-home locations; extensions: editor
# extension folders; apps: macOS app bundles; activity: files only the tool writes.
_TOOLS = {
    "claude-code": {
        "binaries": ("claude",),
        "paths": (".claude/local/claude", ".local/share/claude/versions/*"),
        "extensions": ("anthropic.claude-code-*",),
        "apps": ("Claude.app",),
        "activity": (".claude/projects/*/*.jsonl",),
    },
    "codex": {
        "binaries": ("codex",),
        "extensions": ("openai.chatgpt-*",),
        "apps": ("Codex.app",),
        "activity": (".codex/sessions/*", ".codex/history.jsonl"),
    },
    "cursor": {
        "binaries": ("cursor-agent", "cursor"),
        "paths": (".local/share/cursor-agent/versions/*",),
        "apps": ("Cursor.app",),
    },
    "copilot": {
        "binaries": ("copilot",),
        "extensions": ("github.copilot-*",),
        "activity": (".copilot/session-state/*",),
    },
    "augment": {
        "binaries": ("auggie",),
        "extensions": ("augment.vscode-augment-*",),
        "paths": ("Library/Application Support/JetBrains/*/plugins/*ugment*",
                  ".local/share/JetBrains/*/*ugment*"),
    },
}


def tool_present(tool, user_homes):
    """True if any sign of ``tool`` is on the machine or in any of ``user_homes``,
    False if none is, None if a place couldn't be checked (the report then omits it)."""
    signs = _TOOLS.get(tool)
    if signs is None:
        return None
    try:
        machine = [str(Path(d) / name) for d in _MACHINE_BIN_DIRS for name in signs["binaries"]]
        machine += [str(Path(d) / app) for d in _APP_DIRS for app in signs.get("apps", ())]
        results = [_matches(Path("/"), p) for p in machine]
        results += [_matches(Path(home), p) for _, home in user_homes for p in _home_patterns(signs)]
    except Exception:  # never fail the setup report over this
        return None
    if True in results:
        return True
    return None if None in results else False


def _home_patterns(signs):
    patterns = [f"{d}/{name}" for d in _USER_BIN_DIRS for name in signs["binaries"]]
    patterns += list(signs.get("paths", ()))
    patterns += [f"{d}/extensions/{ext}" for d in _EDITOR_DIRS for ext in signs.get("extensions", ())]
    patterns += [f"Applications/{app}" for app in signs.get("apps", ())]
    return patterns + list(signs.get("activity", ()))


def _matches(base, pattern):
    """Whether ``pattern`` under ``base`` exists; None if that couldn't be checked."""
    try:
        if "*" not in pattern:
            return (base / pattern.lstrip("/")).exists()
        return any(p.exists() for p in itertools.islice(base.glob(pattern), _MAX_MATCHES))
    except OSError:
        return None
