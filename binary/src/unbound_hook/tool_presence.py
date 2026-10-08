"""Whether a coding tool is on this machine, reported beside its install state.

Setup hooks every tool on every profile, so a machine that never had a tool still
reports an install state for it. This lets the backend tell those apart. It leans to
"present": a wrong "absent" would hide a real tamper, a wrong "present" only keeps
today's count, and a place that can't be checked makes the answer unknown. Paths are
only stat'ed and listed, never opened or run, and nothing setup itself writes
(~/.unbound, ~/.codex/hooks*, ~/.codex/config.toml, ~/.copilot/hooks) counts.

The signs live in user-writable homes, so a user can remove them: "absent" is a hint
for sorting reports, not proof that a tamper can be ignored.
"""

import fnmatch
import os
import sys
import time
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
# Users control their homes: a folder too big to list, or a slow one, is unknown.
_MAX_ENTRIES = 2000
_BUDGET_SECONDS = 5.0

# binaries: names on a bin dir; paths: other per-home locations; extensions: editor
# extension folders; apps: macOS app bundles; activity: files only the tool writes
# (the desktop apps that bundle these tools write the same sessions).
_TOOLS = {
    "claude-code": {
        "binaries": ("claude",),
        "paths": (".claude/local/claude", ".local/share/claude/versions/*"),
        "extensions": ("anthropic.claude-code-*",),
        "activity": (".claude/projects/*/*.jsonl",),
    },
    "codex": {
        "binaries": ("codex",),
        "extensions": ("openai.chatgpt-*",),
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


class _Unknown(Exception):
    """A folder couldn't be listed, was too big, or the time budget ran out."""


def tool_present(tool, user_homes):
    """True if any sign of ``tool`` is on the machine or in any of ``user_homes``,
    False if none is, None if a place couldn't be checked (the report then omits it)."""
    signs = _TOOLS.get(tool)
    if signs is None:
        return None
    try:
        deadline = time.monotonic() + _BUDGET_SECONDS
        homes = {str(home) for _, home in user_homes} | {str(home) for home in _account_homes()}
        if not homes:
            return None  # no account to look in: that isn't evidence of absence
        checks = [(Path("/"), f"{d}/{name}") for d in _MACHINE_BIN_DIRS for name in signs["binaries"]]
        checks += [(Path("/"), f"{d}/{app}") for d in _APP_DIRS for app in signs.get("apps", ())]
        checks += [(Path(home), p) for home in sorted(homes) for p in _home_patterns(signs)]
        unknown = False
        for base, pattern in checks:
            try:
                if _find(base, [p for p in pattern.split("/") if p], deadline):
                    return True
            except _Unknown:
                unknown = True
        return None if unknown else False
    except Exception:  # never fail the setup report over this
        return None


def _account_homes():
    """Every login account's home, wherever it lives. Setup's own list keeps only
    readable homes under /Users, and is empty when any home can't be read."""
    try:
        import pwd
    except ImportError:
        return []
    floor = 500 if sys.platform == "darwin" else 1000
    return [Path(u.pw_dir) for u in pwd.getpwall() if u.pw_uid >= floor and u.pw_dir not in ("", "/")]


def _home_patterns(signs):
    patterns = [f"{d}/{name}" for d in _USER_BIN_DIRS for name in signs["binaries"]]
    patterns += list(signs.get("paths", ()))
    patterns += [f"{d}/extensions/{ext}" for d in _EDITOR_DIRS for ext in signs.get("extensions", ())]
    patterns += [f"Applications/{app}" for app in signs.get("apps", ())]
    return patterns + list(signs.get("activity", ()))


def _find(base, parts, deadline):
    """Whether a path matching ``parts`` exists under ``base``, stopping at the first
    match. Raises _Unknown when that can't be told, rather than answering no."""
    if time.monotonic() > deadline:
        raise _Unknown
    if not parts:
        return True
    head, rest = parts[0], parts[1:]
    if "*" not in head:
        try:
            os.stat(base / head)
        except (FileNotFoundError, NotADirectoryError):
            return False
        except OSError:
            raise _Unknown
        return _find(base / head, rest, deadline)
    unknown = False
    try:
        with os.scandir(base) as entries:
            for count, entry in enumerate(entries):
                if count >= _MAX_ENTRIES:
                    raise _Unknown
                if not fnmatch.fnmatchcase(entry.name, head):
                    continue
                try:
                    if _find(Path(entry.path), rest, deadline):
                        return True
                except _Unknown:
                    unknown = True
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        raise _Unknown
    if unknown:
        raise _Unknown
    return False
