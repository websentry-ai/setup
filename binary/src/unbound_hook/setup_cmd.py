"""`unbound-hook setup` — in-binary port of mdm/onboard.py + per-tool MDM setup.

Orchestrates, in onboard.py's order: migration sweep (WEB-4788), then
claude-code, cursor, codex, copilot, then the discovery scan. All heavy
lifting reuses the vendored MDM setup modules' own functions (privilege
drop, env vars, config writes, user-hook strips, backfill, completion
notify); only two things differ from the python path by design:

  1. nothing is downloaded — no SCRIPT_URL fetches, no install.sh; the hook
     IS this binary and discovery is the locally installed binary
  2. managed hook settings point at
     /opt/unbound/current/unbound-hook/unbound-hook hook <tool> <event>
     with the per-event timeouts copied verbatim from the python writers
     (including PreToolUse's historical `15000` vs `60` elsewhere — units
     intentionally NOT normalized)

Fail-open: a component failure is reported in the summary and the exit code,
but never aborts the remaining components.
"""

import hashlib
import json
import math
import os
import platform
import re
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

from ._loader import load_mdm_setup_module
from ._resources import (
    DISCOVERY_BINARY,
    HOOK_BINARY,
    hook_command_for_event,
    hook_source_path,
)
from . import migration
from ._codex_python_era_hashes import CODEX_PYTHON_ERA_HOOK_SHA256

# Mirrors mdm/onboard.py's discovery timeout contract.
DISCOVERY_TIMEOUT_SECONDS = 5400
DISCOVERY_KILL_GRACE_SECONDS = 120

SETUP_TOOLS = ("claude-code", "cursor", "codex", "copilot", "augment")

USAGE = (
    "Usage: unbound-hook setup --api-key <admin_key>\n"
    "           [--backend-url <url>] [--gateway-url <url>] [--frontend-url <url>]\n"
    "           [--app_name <name>] [--backfill] [--tools t1,t2,...]\n"
    "           [--skip-managed-settings]   # claude-code only\n"
)


def _parse_args(argv):
    opts = {
        "api_key": None,
        "backend_url": "https://backend.getunbound.ai",
        "gateway_url": "https://api.getunbound.ai",
        "frontend_url": None,
        "app_name": None,
        "backfill": False,
        "skip_managed_settings": False,
        "tools": list(SETUP_TOOLS),
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--api-key" and i + 1 < len(argv):
            opts["api_key"] = argv[i + 1]; i += 2
        elif a == "--discovery-key":
            # Accepted and ignored so older callers keep working. A valueless
            # flag must not swallow the flag that follows it.
            i += 2 if i + 1 < len(argv) and not argv[i + 1].startswith("--") else 1
        elif a == "--backend-url" and i + 1 < len(argv):
            opts["backend_url"] = argv[i + 1]; i += 2
        elif a == "--gateway-url" and i + 1 < len(argv):
            opts["gateway_url"] = argv[i + 1]; i += 2
        elif a == "--frontend-url" and i + 1 < len(argv):
            opts["frontend_url"] = argv[i + 1]; i += 2
        elif a == "--app_name" and i + 1 < len(argv):
            opts["app_name"] = argv[i + 1]; i += 2
        elif a == "--backfill":
            opts["backfill"] = True; i += 1
        elif a == "--skip-managed-settings":
            # Read by the claude-code adapter alone; the other tools' managed
            # configs are unrelated to the Claude Code remote policy.
            opts["skip_managed_settings"] = True; i += 1
        elif a == "--tools" and i + 1 < len(argv):
            opts["tools"] = [t.strip() for t in argv[i + 1].split(",") if t.strip()]
            i += 2
        elif a == "--debug":
            i += 1
        else:
            print(f"Unknown argument: {a}", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return None
    return opts


def _module(tool):
    m = load_mdm_setup_module(tool)
    m.DEBUG = True  # MDM runs always log diagnostics (parity with python path)
    return m


def _normalized_urls(m, opts):
    base = m.normalize_url(opts["backend_url"])
    gateway = m.normalize_url(opts["gateway_url"])
    return base, gateway


def _detect_state(settings_path: Path):
    """Binary-era analog of the python detect_install_state(): the python
    version checked managed unbound.py existence, which no longer exists.
    'persisted' = settings present and pointing at this binary OR at the
    python-era unbound.py (a legitimate install being migrated — reporting
    those as 'tampered' would flood the backend with false tamper signals on
    rollout day); 'tampered' = settings present referencing neither. Callers that
    do not own the settings file must not call this at all."""
    try:
        if not settings_path.exists():
            return "fresh"
        text = settings_path.read_text(encoding="utf-8")
        if str(HOOK_BINARY) in text or "unbound.py" in text:
            return "persisted"
        return "tampered"
    except Exception as e:
        # None = "unknown" — notify_setup_complete omits the field entirely,
        # which is more honest than guessing 'fresh' over an unreadable but
        # real install. Loud so fleet logs show WHY the state was unknown.
        print(f"[setup] install_state detection failed for {settings_path}: {e}",
              file=sys.stderr)
        return None


def _remove_stale_managed_script(managed_dir: Path) -> None:
    """Delete the python-era managed hook script — called ONLY after the
    settings rewrite succeeded, so hook registrations are never left
    pointing at a deleted script (a failed setup must leave the python
    serving path intact)."""
    script = managed_dir / "hooks" / "unbound.py"
    try:
        if script.is_file():
            script.unlink()
            print(f"[migration] removed {script}")
        hooks_dir = script.parent
        if hooks_dir.is_dir() and not any(hooks_dir.iterdir()):
            hooks_dir.rmdir()
    except OSError as e:
        print(f"[migration] could not remove {script}: {e}")


# ---------------------------------------------------------------------------
# Managed hook settings writers (binary command variants of the python
# setup_managed_hooks / setup_hooks / _copilot_hooks_config writers; JSON
# structure and timeouts copied verbatim, command strings swapped).
# ---------------------------------------------------------------------------

def _atomic_write_text(path: Path, text: str) -> None:
    """tmp + os.replace so a crash mid-write never leaves the editor reading
    a truncated managed-settings file. A link is refused, not resolved: this runs as
    root, so following one writes wherever it points."""
    if path.is_symlink():
        raise OSError(f"{path} is a link; refusing to write through it as root")
    tmp = path.parent / f"{path.name}.{os.getpid()}.tmp"
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)

def _claude_hooks_config():
    cmd = lambda ev: hook_command_for_event("claude-code", ev)
    return {
        "PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("PreToolUse"), "timeout": 15000}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("PostToolUse"), "async": True, "timeout": 60}]}],
        "UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": cmd("UserPromptSubmit"), "timeout": 60}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": cmd("Stop"), "timeout": 60}]}],
        "SessionStart": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("SessionStart"), "async": True, "timeout": 60}]}],
        "SessionEnd": [{"hooks": [
            {"type": "command", "command": cmd("SessionEnd"), "async": True, "timeout": 60}]}],
    }


def _codex_hooks_config(hook_command):
    # Codex runs the command as a single on-disk python program (its python
    # path registers a bare script, not a shell line), so every event shares
    # one wrapper command; the event is read from stdin.
    cmd = lambda ev: hook_command
    return {
        "PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("PreToolUse"), "timeout": 15000}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("PostToolUse"), "timeout": 60}]}],
        "UserPromptSubmit": [{"hooks": [
            {"type": "command", "command": cmd("UserPromptSubmit"), "timeout": 60}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": cmd("Stop"), "timeout": 60}]}],
        "SessionStart": [{"matcher": "*", "hooks": [
            {"type": "command", "command": cmd("SessionStart"), "timeout": 60}]}],
    }


def _cursor_hooks_json():
    """cursor/hooks.json with binary commands; events/timeouts verbatim."""
    cmd = lambda ev: hook_command_for_event("cursor", ev)
    hooks = {
        "preToolUse": [{"command": cmd("preToolUse"), "timeout": 15000}],
        "postToolUse": [{"command": cmd("postToolUse")}],
        "beforeShellExecution": [{"command": cmd("beforeShellExecution"), "timeout": 15000}],
        "beforeMCPExecution": [{"command": cmd("beforeMCPExecution"), "timeout": 15000}],
        "afterShellExecution": [{"command": cmd("afterShellExecution")}],
        "afterMCPExecution": [{"command": cmd("afterMCPExecution")}],
        "afterFileEdit": [{"command": cmd("afterFileEdit")}],
        "beforeReadFile": [{"command": cmd("beforeReadFile")}],
        "beforeSubmitPrompt": [{"command": cmd("beforeSubmitPrompt")}],
        "afterAgentResponse": [{"command": cmd("afterAgentResponse")}],
        "stop": [{"command": cmd("stop")}],
        "sessionStart": [{"command": cmd("sessionStart")}],
    }
    return {"version": 1, "hooks": hooks}


def _augment_hooks_config():
    """The Augment hooks block with binary commands. Structure + per-event
    timeouts (ms) copied verbatim from augment build_hooks_block; block-level
    metadata is set by the writer and no UserPromptSubmit (Augment has no such
    event). No Windows `shell` key — the binary path is macOS-only."""
    cmd = lambda ev: hook_command_for_event("augment", ev)
    return {
        "PreToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": cmd("PreToolUse"), "timeout": 15000}]}],
        "PostToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": cmd("PostToolUse"), "timeout": 10000}]}],
        "Stop": [{"hooks": [
            {"type": "command", "command": cmd("Stop"), "timeout": 10000}]}],
        "SessionStart": [{"hooks": [
            {"type": "command", "command": cmd("SessionStart"), "timeout": 60000}]}],
        "SessionEnd": [{"hooks": [
            {"type": "command", "command": cmd("SessionEnd"), "timeout": 10000}]}],
    }


def _copilot_hooks_config():
    """Port of _copilot_hooks_config with the binary command. Copilot is
    invoked per-user; field pairs (command/bash/powershell, timeout/
    timeoutSec) preserved verbatim."""
    event_timeouts = {
        "SessionStart": 30,
        "UserPromptSubmit": 60,
        "PreToolUse": 600,
        "PostToolUse": 30,
        "Stop": 60,
    }
    hooks = {}
    for event_name, timeout_sec in event_timeouts.items():
        cmd = hook_command_for_event("copilot", event_name)
        hooks[event_name] = [{
            "type": "command",
            "command": cmd,
            "bash": cmd,
            "powershell": cmd,
            "timeout": timeout_sec,
            "timeoutSec": timeout_sec,
        }]
    return {"version": 1, "hooks": hooks}


def _print_remote_policy_hooks() -> None:
    """One command per event, unlike the python path's single script path —
    an admin authoring the remote policy needs every one of them."""
    print("Add these to your remote Claude Code policy:")
    for event, entries in _claude_hooks_config().items():
        for entry in entries:
            for hook in entry.get("hooks", []):
                print(f"  {event}: {hook['command']}")


def _write_claude_managed_settings(m, skip_settings: bool = False) -> bool:
    """Binary variant of claude-code setup_managed_hooks(): same settings
    file, same gateway-leftover cleanup, no script download. With
    skip_settings it writes no hook config and leaves the file alone entirely."""
    try:
        managed_dir = m.get_managed_settings_dir()
        managed_dir.mkdir(parents=True, exist_ok=True)
        settings_path = managed_dir / "managed-settings.json"

        # No hook config of our own: the remote policy owns it. managed-settings.json
        # belongs to the admin in this mode and is neither read nor written.
        if skip_settings:
            if platform.system().lower() in ("darwin", "linux"):
                os.chmod(managed_dir, 0o755)
            return True

        settings = {}
        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    settings = json.load(f) or {}
            except Exception:
                settings = {}

        # Same gateway-era cleanup as the python writer.
        if "apiKeyHelper" in settings:
            del settings["apiKeyHelper"]
        env = settings.get("env") if isinstance(settings.get("env"), dict) else None
        if env:
            for k in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
                env.pop(k, None)
            if not env:
                del settings["env"]

        settings["hooks"] = _claude_hooks_config()
        _atomic_write_text(settings_path, json.dumps(settings, indent=2))

        gateway_key_helper = managed_dir / "anthropic_key.sh"
        if gateway_key_helper.exists():
            try:
                gateway_key_helper.unlink()
            except Exception:
                pass

        if platform.system().lower() in ("darwin", "linux"):
            os.chmod(managed_dir, 0o755)
            os.chmod(settings_path, 0o644)
        return True
    except Exception as e:
        print(f"Failed to write managed settings: {e}")
        return False


def _write_augment_managed_settings(m) -> bool:
    """Binary variant of augment setup_managed_hooks(): same /etc/augment/
    settings.json, no script download. /etc/augment/settings.json is SHARED
    with the org's own Augment config, so this MERGES per-event (append our
    hook entry only if our command isn't already present) and merges
    toolPermissions on identity, preserving every foreign entry, rule, and
    other top-level key — never clobbering the org's config."""
    try:
        managed_dir = m.get_managed_settings_dir()
        managed_dir.mkdir(parents=True, exist_ok=True)
        settings_path = managed_dir / "settings.json"

        settings = {}
        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    settings = json.load(f) or {}
            except Exception:
                settings = {}
        if not isinstance(settings, dict):
            settings = {}

        # MERGE per-event (settings.json is shared with the org's own config):
        # append our hook entry per event only if our command isn't already
        # present; preserve every foreign entry and other top-level key.
        hooks_config = _augment_hooks_config()
        if not isinstance(settings.get("hooks"), dict):
            settings["hooks"] = {}
        for event, new_config in hooks_config.items():
            our_command = new_config[0]["hooks"][0]["command"]
            existing_config = settings["hooks"].get(event)
            if isinstance(existing_config, list):
                our_hook_exists = any(
                    hook.get("command", "") == our_command
                    for item in existing_config if isinstance(item, dict)
                    # .get's default only covers a missing key, so a scalar
                    # would be iterated and raise, aborting the write.
                    for hook in (item.get("hooks") if isinstance(item.get("hooks"), list) else [])
                    if isinstance(hook, dict)
                )
                if not our_hook_exists:
                    existing_config.extend(new_config)
            elif existing_config is None:
                settings["hooks"][event] = new_config
            # A foreign non-list hooks[event] is left untouched.

        # Without these Auggie sends no context, so no account email. Set on
        # existing blocks too, so installed devices pick them up on re-run.
        for event, flags in m._HOOK_METADATA.items():
            blocks = settings["hooks"].get(event)
            if not isinstance(blocks, list):
                continue
            our_command = hooks_config[event][0]["hooks"][0]["command"]
            for item in blocks:
                if isinstance(item, dict) and any(
                        isinstance(hook, dict) and hook.get("command", "") == our_command
                        # .get's default only covers a missing key, so a scalar
                        # would be iterated and raise, aborting the write.
                        for hook in (item.get("hooks")
                                     if isinstance(item.get("hooks"), list) else [])):
                    if not isinstance(item.get("metadata"), dict):
                        item["metadata"] = {}
                    item["metadata"].update(flags)

        # Merge toolPermissions, preserving foreign rules. Match on our identity
        # (toolName + shellInputRegex) so re-running never duplicates.
        existing_perms = settings.get("toolPermissions")
        if not isinstance(existing_perms, list):
            existing_perms = []
        existing_identities = {
            m._tool_permission_identity(r) for r in existing_perms if isinstance(r, dict)
        }
        for rule in m.build_tool_permissions_block():
            if m._tool_permission_identity(rule) not in existing_identities:
                existing_perms.append(rule)
                existing_identities.add(m._tool_permission_identity(rule))
        settings["toolPermissions"] = existing_perms

        _atomic_write_text(settings_path, json.dumps(settings, indent=2))

        if platform.system().lower() in ("darwin", "linux"):
            os.chmod(managed_dir, 0o755)
            os.chmod(settings_path, 0o644)
        return True
    except Exception as e:
        print(f"Failed to write augment managed settings: {e}")
        return False


# Files in a user's home: never follow a link we write through, and never wait
# on a FIFO planted in place of one.
_USER_FILE_WRITE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                          | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
_USER_FILE_MAX_BYTES = 4 * 1024 * 1024


def _read_user_file(path: Path, follow: bool) -> bytes:
    """A user-owned file's bytes, read non-blocking and capped. Raises OSError for
    anything but a regular file within the cap."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"{path} is not a regular file")
    with os.fdopen(fd, "rb") as f:
        data = f.read(_USER_FILE_MAX_BYTES + 1)
    if len(data) > _USER_FILE_MAX_BYTES:
        raise OSError(f"{path} is larger than {_USER_FILE_MAX_BYTES} bytes")
    return data


class _JsonObject(dict):
    """A parsed JSON object that remembers which keys appeared more than once."""
    dups = frozenset()


def _json_object(pairs):
    obj = _JsonObject(pairs)
    if len(obj) != len(pairs):
        seen, dups = set(), set()
        for key, _ in pairs:
            (dups if key in seen else seen).add(key)
        obj.dups = frozenset(dups)
    return obj


def _load_codex_json(data: bytes):
    """Parse the way codex's serde_json would see it: no byte-order mark,
    NaN/Infinity or lone surrogates. Duplicate keys are kept for the schema check."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("byte-order mark")

    def _constant(name):
        raise ValueError(name)

    config = json.loads(data.decode("utf-8"), object_pairs_hook=_json_object, parse_constant=_constant)
    json.dumps(config, ensure_ascii=False).encode("utf-8")  # raises on a lone surrogate
    if _json_depth(config) >= _SERDE_MAX_DEPTH:
        raise ValueError("nested deeper than serde_json allows")
    return config


_SERDE_MAX_DEPTH = 128  # serde_json fails on the 128th nested [ or {


def _json_depth(value) -> int:
    """Deepest array/object nesting, counted iteratively."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        node, depth = stack.pop()
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else None
        if children is None:
            continue
        deepest = max(deepest, depth)
        stack.extend((child, depth + 1) for child in children)
    return deepest


# Codex's hooks.json schema (codex-rs/config/src/hook_config.rs). It rejects the
# whole file if any of this fails to deserialize, and no hook in it runs.
_CODEX_FILE_FIELDS = ("description", "hooks")
_CODEX_EVENT_FIELDS = (
    "PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact",
    "SessionStart", "SessionEnd", "UserPromptSubmit", "SubagentStart", "SubagentStop",
    "Stop", "Interrupt")
_CODEX_HANDLER_FIELDS = {
    "command": {"type": None, "command": str, "commandWindows": "str?", "command_windows": "str?",
                "timeout": "u64?", "async": bool, "statusMessage": "str?",
                "additionalContextLimit": "u64?"},
    "mcp_tool": {"type": None, "server": str, "tool": str, "input": "toml_map",
                 "timeout": "u64?", "statusMessage": "str?"},
    "prompt": {"type": None},
    "agent": {"type": None},
}
_U64_MAX = 2 ** 64 - 1


def _struct_ok(obj, fields) -> bool:
    """A serde-derived struct: a JSON object with no known field repeated."""
    return isinstance(obj, dict) and not (getattr(obj, "dups", frozenset()) & set(fields))


def _toml_ok(value) -> bool:
    if value is None:
        return False
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return -2 ** 63 <= value < 2 ** 63
    if isinstance(value, list):
        return all(_toml_ok(v) for v in value)
    return isinstance(value, dict) and all(_toml_ok(v) for v in value.values())


def _field_ok(value, kind) -> bool:
    if kind is str:
        return isinstance(value, str)
    if kind is bool:
        return isinstance(value, bool)
    if kind == "str?":
        return value is None or isinstance(value, str)
    if kind == "u64?":
        return value is None or (isinstance(value, int) and not isinstance(value, bool)
                                 and 0 <= value <= _U64_MAX)
    if kind == "toml_map":
        return isinstance(value, dict) and _toml_ok(value)
    return True


def _codex_handler_loads(handler) -> bool:
    kind = handler.get("type") if isinstance(handler, dict) else None
    fields = _CODEX_HANDLER_FIELDS.get(kind) if isinstance(kind, str) else None
    if fields is None or not _struct_ok(handler, fields):
        return False
    if "commandWindows" in handler and "command_windows" in handler:
        return False  # one field under two names
    required = [k for k, kind in fields.items() if kind in (str,)]
    return (all(k in handler for k in required)
            and all(_field_ok(handler[k], kind) for k, kind in fields.items() if k in handler))


def _codex_group_loads(group) -> bool:
    if not _struct_ok(group, ("matcher", "hooks")):
        return False
    if not _field_ok(group.get("matcher"), "str?"):
        return False
    hooks = group.get("hooks", [])
    return isinstance(hooks, list) and all(_codex_handler_loads(h) for h in hooks)


def _codex_can_load(config) -> bool:
    """Whether codex would load this hooks.json at all."""
    if not _struct_ok(config, _CODEX_FILE_FIELDS) or set(config) - set(_CODEX_FILE_FIELDS):
        return False
    if not _field_ok(config.get("description"), "str?"):
        return False
    events = config.get("hooks", {})
    if not _struct_ok(events, _CODEX_EVENT_FIELDS):
        return False
    return all(isinstance(events[e], list) and all(_codex_group_loads(g) for g in events[e])
               for e in _CODEX_EVENT_FIELDS if e in events)


def _codex_make_loadable(config) -> dict:
    """Drop only content that breaks codex's known schema (wrong types, malformed
    groups or handlers), so the hooks it can load run again. Keys and handler types
    this check doesn't know are kept: a newer codex may define them."""
    if not isinstance(config, dict):
        return {}
    clean = dict(config)
    if not _field_ok(clean.get("description"), "str?"):
        clean.pop("description")
    events = clean.get("hooks")
    clean["hooks"] = events = dict(events) if isinstance(events, dict) else {}
    for event in _CODEX_EVENT_FIELDS:
        if event not in events:
            continue
        groups = events[event] if isinstance(events[event], list) else []
        kept = []
        for group in groups:
            if not isinstance(group, dict) or not _field_ok(group.get("matcher"), "str?"):
                continue
            group = dict(group)
            hooks = group.get("hooks", [])
            group["hooks"] = ([h for h in hooks if _codex_handler_kept(h)]
                              if isinstance(hooks, list) else [])
            if group["hooks"] or not hooks:
                kept.append(group)
        events[event] = kept
    return _drop_non_finite(clean)


def _drop_non_finite(value):
    """Drop NaN/Infinity wherever they sit: codex's JSON parser rejects the whole file."""
    if isinstance(value, dict):
        return {k: _drop_non_finite(v) for k, v in value.items()
                if not (isinstance(v, float) and not math.isfinite(v))}
    if isinstance(value, list):
        return [_drop_non_finite(v) for v in value if not (isinstance(v, float) and not math.isfinite(v))]
    return value


def _codex_handler_kept(handler) -> bool:
    """Keep a handler unless it breaks the schema of a type we know."""
    kind = handler.get("type") if isinstance(handler, dict) else None
    if isinstance(kind, str) and kind not in _CODEX_HANDLER_FIELDS:
        return True
    return _codex_handler_loads(handler)


def _install_codex_hooks_for_user(m, username, home_dir) -> bool:
    """Register codex hooks per-user in ~/.codex/hooks.json (the layer codex
    actually discovers them from), mirroring the python user-level
    configure_codex_hooks exactly. Codex runs the registered ~/.codex/hooks/
    unbound.py as a PYTHON program (its native hook contract — the real
    python-era file is `#!/usr/bin/env python3`, and the python installer's
    Windows branch invokes it as `py -3 "<path>"`). A `#!/bin/sh` wrapper at a
    `.py` path is therefore NOT valid python and codex silently drops it (the
    bug this replaces). So the wrapper is a tiny python shim that execs the
    binary (the event is read from stdin) — valid whether codex honors the
    shebang OR runs it through a python interpreter by extension. The registered
    command is that bare wrapper PATH. Privilege-dropped; merge is idempotent
    (match-by-command) and preserves other tools' hooks."""
    hooks_dir = home_dir / ".codex" / "hooks"
    wrapper = hooks_dir / "unbound.py"
    hooks_path = home_dir / ".codex" / "hooks.json"
    hook_command = str(wrapper)

    def _install():
        hooks_dir.mkdir(parents=True, exist_ok=True)
        # Replace a symlink at our own path rather than write through it
        # (O_NOFOLLOW below would otherwise defer codex on every run).
        if wrapper.is_symlink():
            wrapper.unlink()
        fd = os.open(str(wrapper), _USER_FILE_WRITE_FLAGS, 0o755)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_codex_wrapper_source())
        os.chmod(wrapper, 0o755)
        _merge_codex_hooks_json(hooks_path, hook_command)
        return True

    return bool(m._run_as_user(username, _install))


def _command_targets_hook(command: str, target: Path) -> bool:
    if not isinstance(command, str) or not command:
        # A non-string command is not ours; the checks below would raise on it.
        return False
    try:
        tokens = shlex.split(command, posix=(os.name != "nt"))
    except ValueError:
        return False
    tokens = [t.strip().strip('"').strip("'") for t in tokens]
    tokens = [t for t in tokens if t]
    if not tokens:
        return False
    launcher = os.path.basename(tokens[0]).lower()
    if launcher.endswith(".exe"):
        launcher = launcher[:-4]
    if launcher in ("py", "python", "python2", "python3"):
        tokens = tokens[1:]
        while tokens and tokens[0].startswith("-"):
            tokens = tokens[1:]
    if not tokens:
        return False
    normalized_target = os.path.normcase(os.path.normpath(str(target)))
    return os.path.normcase(os.path.normpath(tokens[0])) == normalized_target


def _codex_wrapper_source() -> str:
    """Python shim written to ~/.codex/hooks/unbound.py. Must be valid python
    (codex runs it as a python program) AND exec the binary with no python
    dependency beyond the interpreter that launches it. os.execv replaces the
    process so stdin/stdout/stderr (the hook payload + response) pass straight
    through. repr() safely embeds the binary path as a python string literal."""
    return (
        "#!/usr/bin/env python3\n"
        "import os\n"
        'os.execv(%s, ["unbound-hook", "hook", "codex"])\n' % repr(str(HOOK_BINARY))
    )


def _merge_codex_hooks_json(hooks_path: Path, wrapper_path: str) -> None:
    """Idempotent merge of the codex hook events into hooks.json, preserving other
    tools' hooks. Writes only when something changed, so a file that already has
    our hook is left alone even when it's a symlink we would refuse to write."""
    wrapper = Path(wrapper_path)
    command = shlex.quote(wrapper_path)  # codex runs it via `$SHELL -lc`
    try:
        raw = _read_user_file(hooks_path, follow=True)
    except FileNotFoundError:
        raw = b"{}"
    try:
        config = _load_codex_json(raw)
        loadable = _codex_can_load(config)
    except ValueError:
        # Codex rejects it (byte-order mark, NaN, lone surrogate, too deep), so nothing
        # in it runs; recover what Python can and rewrite only if that loads.
        config = json.loads(raw.removeprefix(b"\xef\xbb\xbf").decode("utf-8"),
                            object_pairs_hook=_json_object)
        loadable = False
    before = json.dumps(config, sort_keys=True)
    config = _codex_make_loadable(config)

    hooks_config = _codex_hooks_config(command)
    if "hooks" not in config:
        config["hooks"] = {}

    for event, new_config in hooks_config.items():
        if event not in config["hooks"]:
            config["hooks"][event] = new_config
            continue
        existing_config = config["hooks"][event]
        if any(_codex_group_runs_wrapper(item, wrapper, event) for item in existing_config):
            continue
        # Drop our own entries that don't work (unquoted path the shell splits,
        # async, short timeout, narrowed matcher) so the real group isn't doubled.
        for existing_item in list(existing_config):
            existing_hooks = existing_item.get("hooks") if isinstance(existing_item, dict) else None
            if not isinstance(existing_hooks, list):
                continue
            kept = [h for h in existing_hooks if not (isinstance(h, dict) and (
                h.get("command") == wrapper_path or _codex_runs_wrapper(h.get("command"), wrapper)))]
            if len(kept) != len(existing_hooks):
                existing_item["hooks"] = kept
                if not kept:
                    existing_config.remove(existing_item)
        existing_config.extend(new_config)

    text = json.dumps(config, indent=2, ensure_ascii=False, allow_nan=False)
    try:
        rewritten_loads = _codex_can_load(_load_codex_json(text.encode("utf-8")))
    except ValueError:
        rewritten_loads = False
    # Unchanged content is still rewritten when that alone makes it loadable
    # (a repeated key collapses on rewrite); otherwise the file is left alone.
    if json.dumps(config, sort_keys=True) == before and (loadable or not rewritten_loads):
        return
    data = text.encode("utf-8")  # before the truncating open: a failure must leave the file intact
    if len(data) > _USER_FILE_MAX_BYTES:
        raise ValueError("hooks.json would outgrow what detection reads back")
    fd = os.open(str(hooks_path), _USER_FILE_WRITE_FLAGS, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _write_cursor_enterprise_hooks(m) -> tuple:
    """Binary variant of cursor setup_hooks(). Returns (ok, hooks_changed)."""
    try:
        enterprise_dir = m.get_enterprise_hooks_dir()
        hooks_json = enterprise_dir / "hooks.json"
        new_content = json.dumps(_cursor_hooks_json(), indent=2)
        hooks_changed = m.compare_hooks_json(hooks_json, new_content)
        enterprise_dir.mkdir(parents=True, exist_ok=True)
        tmp = enterprise_dir / "hooks.json.tmp"
        tmp.write_text(new_content, encoding="utf-8")
        tmp.replace(hooks_json)
        if platform.system().lower() in ("darwin", "linux"):
            os.chmod(hooks_json, 0o644)
        return True, hooks_changed
    except Exception as e:
        print(f"Failed to write cursor hooks.json: {e}")
        return False, False


def _install_copilot_hooks_for_user(m, username, home_dir) -> bool:
    """Binary variant of copilot install_hooks_for_user(): writes only
    unbound.json (no unbound.py copy), privilege-dropped like the original.
    The python-era unbound.py is removed AFTER the new registration is
    written — a failed install leaves python-era coverage fully intact
    (same delete-after-replace rule as the managed-settings tools)."""
    hooks_dir = home_dir / ".copilot" / "hooks"
    hooks_json = hooks_dir / "unbound.json"
    stale_script = hooks_dir / "unbound.py"
    config = _copilot_hooks_config()

    def _install():
        hooks_dir.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(hooks_json), flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        try:
            if stale_script.is_file():
                stale_script.unlink()
        except OSError:
            pass  # stale script is inert once unbound.json points at the binary
        return True

    return bool(m._run_as_user(username, _install))


# ---------------------------------------------------------------------------
# Per-tool adapters — each mirrors its python main() flow step-for-step,
# minus downloads, returning a status instead of exiting.
# ---------------------------------------------------------------------------

def _setup_claude_code(opts):
    m = _module("claude-code")
    base, gateway = _normalized_urls(m, opts)
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")

    for username, home_dir in m.get_all_user_homes():
        m.remove_env_var_from_user(username, home_dir, "UNBOUND_API_KEY")
        m.remove_env_var_from_user(username, home_dir, "ANTHROPIC_BASE_URL")

    success, _ = m.set_env_var_system_wide("UNBOUND_CLAUDE_API_KEY", api_key)
    if not success:
        return ("deferred", "failed to set UNBOUND_CLAUDE_API_KEY")

    for username, home_dir in m.get_all_user_homes():
        m.remove_gateway_artifacts_for_user(username, home_dir)
        m.remove_user_level_hooks_for_user(username, home_dir)
        m.write_unbound_config_for_user(
            username, home_dir, api_key,
            urls={"base_url": base, "gateway_url": gateway, "frontend_url": opts["frontend_url"]})

    skip_settings = opts["skip_managed_settings"]
    # None (unknown) without looking: in skip mode managed-settings.json is the
    # admin's file, and unknown leaves the backend's tamper state untouched.
    state = None if skip_settings else _detect_state(
        m.get_managed_settings_dir() / "managed-settings.json")
    if not _write_claude_managed_settings(m, skip_settings=skip_settings):
        return ("deferred", "managed settings update failed")
    if skip_settings:
        # A remote policy may name the python script; deleting it here would
        # strand that policy on a missing file with no local error.
        _print_remote_policy_hooks()
    else:
        _remove_stale_managed_script(m.get_managed_settings_dir())

    m.notify_setup_complete(api_key, "claude-code", backend_url=base,
                            install_state=state, serial_number=device_id,
                            hook_hash=m.hook_script_hash(hook_source_path("claude-code")),
                            install_mode="binary-skip" if skip_settings else "binary")
    if opts["backfill"]:
        # Bounded like the MDM script: a heavy history must not hold setup open. The
        # deadline origin is this tool's turn, not module import in the shared process.
        m._SCRIPT_START = time.time()
        m._run_backfill_bounded(api_key, base, m.get_all_user_homes())
    return ("configured", None)


def _setup_augment(opts):
    """Mirrors augment mdm/setup.py main() step-for-step, minus downloads.
    Augment uses system-managed /etc/augment (get_managed_settings_dir), like
    claude-code; the notify tool_type is 'augment_code' and the env var is
    UNBOUND_AUGMENT_API_KEY (both verbatim from augment's setup.py). Augment
    does NOT support backfill. One substitution from main(): user-level hook
    removal is gated on the managed write returning True rather than on
    verify_managed_hooks_installed() — the latter checks for the downloaded
    /etc/augment/hooks/unbound.py the binary path never writes."""
    m = _module("augment")
    base, gateway = _normalized_urls(m, opts)
    if opts["backfill"]:
        print("[backfill] Augment backfill is not supported.")
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")

    success, _ = m.set_env_var_system_wide("UNBOUND_AUGMENT_API_KEY", api_key)
    if not success:
        return ("deferred", "failed to set UNBOUND_AUGMENT_API_KEY")

    # Write the per-user unbound config now (needed by the managed hook). User
    # hook removal is deferred until the managed write succeeds (parity with
    # augment main()'s ordering).
    user_homes = m.get_all_user_homes()
    for username, home_dir in user_homes:
        m.write_unbound_config_for_user(
            username, home_dir, api_key,
            urls={"base_url": base, "gateway_url": gateway, "frontend_url": opts["frontend_url"]})

    state = _detect_state(m.get_managed_settings_dir() / "settings.json")
    if not _write_augment_managed_settings(m):
        return ("deferred", "managed settings write failed")
    _remove_stale_managed_script(m.get_managed_settings_dir())

    # Strip leftover user-level Unbound hooks only after the managed write
    # succeeded, so managed hooks don't fire twice.
    for username, home_dir in user_homes:
        m.remove_user_level_hooks_for_user(username, home_dir)

    m.notify_setup_complete(api_key, "augment_code", backend_url=base,
                            install_state=state, serial_number=device_id,
                            hook_hash=m.hook_script_hash(hook_source_path("augment")),
                            install_mode="binary")
    return ("configured", None)


def _setup_codex(opts):
    m = _module("codex")
    base, gateway = _normalized_urls(m, opts)
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")

    for username, home_dir in m.get_all_user_homes():
        m.remove_env_var_from_user(username, home_dir, "OPENAI_API_KEY")

    success, _ = m.set_env_var_system_wide("UNBOUND_CODEX_API_KEY", api_key)
    if not success:
        return ("deferred", "failed to set UNBOUND_CODEX_API_KEY")

    # codex 0.125 discovers hooks from ~/.codex/hooks.json (user layer), not the
    # managed dir — so register per-user there, mirroring the python user-level
    # setup. No managed write and no user-level strip (the install IS the user
    # registration).
    user_homes = m.get_all_user_homes()
    state = _codex_detect_state(m, user_homes, gateway)
    installed = 0
    for username, home_dir in user_homes:
        m.remove_gateway_artifacts_for_user(username, home_dir)
        m.write_unbound_config_for_user(
            username, home_dir, api_key,
            urls={"base_url": base, "gateway_url": gateway, "frontend_url": opts["frontend_url"]})
        m.enable_codex_hooks_feature_for_user(username, home_dir)
        if _install_codex_hooks_for_user(m, username, home_dir):
            installed += 1

    if user_homes and installed == 0:
        # A user can make every install fail (a symlinked or FIFO hooks.json), so
        # a detected tamper is still reported rather than lost with the deferral.
        if state == "tampered":
            m.notify_setup_complete(api_key, "codex", backend_url=base,
                                    install_state=state, serial_number=device_id,
                                    install_mode="binary")
        return ("deferred", "hook install failed for all users")

    m.notify_setup_complete(api_key, "codex", backend_url=base,
                            install_state=state, serial_number=device_id,
                            hook_hash=m.hook_script_hash(hook_source_path("codex")),
                            install_mode="binary")
    if opts["backfill"]:
        m.run_backfill(api_key, base, m.get_all_user_homes())
    return ("configured", None)


# Characters the shell acts on in an unquoted word.
_SHELL_SPECIAL = set(" \t\n\"'\\$`;&|<>()*?[]{}~#!")
# Events where an async hook can't block, so codex wouldn't enforce our answer.
# Older installs wrote async only on PostToolUse and SessionStart.
_CODEX_BLOCKING_EVENTS = ("PreToolUse", "UserPromptSubmit", "Stop")
# Codex ignores the matcher on these (matcher_pattern_for_event).
_CODEX_UNMATCHED_EVENTS = ("UserPromptSubmit", "Stop", "Interrupt")


def _codex_runs_wrapper(command, wrapper: Path) -> bool:
    """The command is literally a way our installers write the wrapper: shell-
    quoted, or single/double-quoted or bare where the shell expands nothing.
    Anything else can expand, redirect or skip it."""
    if not isinstance(command, str):
        return False
    path = str(wrapper)
    forms = {shlex.quote(path)}
    if "'" not in path:
        forms.add(f"'{path}'")
    if not any(c in path for c in '"$`\\'):
        forms.add(f'"{path}"')
    if not any(c in _SHELL_SPECIAL for c in path):
        forms.add(path)
    return command in forms


def _codex_group_runs_wrapper(group, wrapper: Path, event: str) -> bool:
    """A hooks.json group that fires our wrapper for every tool and lets it act: a
    match-all matcher (codex treats absent, "" and "*" alike), the exact command,
    synchronous where it blocks, and no shorter timeout than any we've written."""
    if not isinstance(group, dict):
        return False
    if event not in _CODEX_UNMATCHED_EVENTS and group.get("matcher") not in (None, "", "*"):
        return False
    floor = 10 if event == "PreToolUse" else 60
    hooks = group.get("hooks")
    for h in hooks if isinstance(hooks, list) else []:
        if not (isinstance(h, dict) and h.get("type") == "command"
                and _codex_runs_wrapper(h.get("command"), wrapper)):
            continue
        if h.get("async") and event in _CODEX_BLOCKING_EVENTS:
            continue
        timeout = h.get("timeout", floor)  # codex reads a u64: no float, no bool
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < floor:
            continue
        return True
    return False


try:
    import tomllib
except ImportError:  # python older than 3.11; the shipped binary bundles it
    tomllib = None


def _codex_hooks_disabled(config_path: Path) -> bool:
    """Whether config.toml turns codex's hooks feature off (on by default; the legacy
    key codex_hooks is an alias). A config codex can't parse isn't read as either."""
    if tomllib is None:
        return False
    try:
        features = tomllib.loads(_read_user_file(config_path, follow=True).decode("utf-8")).get("features")
    except (OSError, ValueError, RecursionError):
        return False
    return isinstance(features, dict) and any(features.get(k) is False for k in ("hooks", "codex_hooks"))


def _codex_hook_registered(hooks_path: Path, wrapper: Path) -> bool:
    """Whether this hooks.json registers our wrapper for every event. Runs as the
    profile's user and reads the file as codex does, following a symlink.
    Anything codex couldn't load counts as not registered."""
    try:
        config = _load_codex_json(_read_user_file(hooks_path, follow=True))
    except Exception:
        return False
    if not _codex_can_load(config) or _codex_hooks_disabled(hooks_path.parent / "config.toml"):
        return False
    events = config.get("hooks", {})
    # Every event setup installs, or a dropped PreToolUse would still read healthy.
    return all(any(_codex_group_runs_wrapper(group, wrapper, event)
                   for group in (events.get(event) if isinstance(events.get(event), list) else []))
               for event in _codex_hooks_config(None))


def _codex_wrapper_runnable(wrapper: Path) -> bool:
    """A regular file (not followed) its owner can read and execute: the shell needs
    the execute bit, then python has to open the file after the shebang."""
    try:
        mode = wrapper.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and mode & (stat.S_IRUSR | stat.S_IXUSR) == stat.S_IRUSR | stat.S_IXUSR


# The python installers patch the tenant gateway into the hook's one gateway literal;
# resetting it gives the shipped script back, to compare against the shipped hashes.
_PYTHON_ERA_GATEWAY = re.compile(r'(UNBOUND_GATEWAY_URL", |UNBOUND_GATEWAY_URL = )"([^"\n]*)"')
_PYTHON_ERA_DEFAULT_GATEWAY = "https://api.getunbound.ai"


def _python_era_hook_sha256(text: str, gateway=_PYTHON_ERA_DEFAULT_GATEWAY):
    """The hash with the gateway reset to the default; None if the hook points anywhere
    but this device's gateway, the only URL the installers wrote there."""
    match = _PYTHON_ERA_GATEWAY.search(text)
    if match:
        if match.group(2) != gateway:
            return None
        text = text[:match.start()] + match.group(1) + f'"{_PYTHON_ERA_DEFAULT_GATEWAY}"' + text[match.end():]
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _known_python_era_hashes() -> frozenset:
    """Every shipped version, plus the one bundled with this binary (newer than the list)."""
    try:
        bundled = _python_era_hook_sha256(hook_source_path("codex").read_text(encoding="utf-8"))
    except OSError:
        return CODEX_PYTHON_ERA_HOOK_SHA256
    return CODEX_PYTHON_ERA_HOOK_SHA256 | {bundled}


def _codex_wrapper_is_ours(wrapper: Path, python_era_hashes: frozenset, gateway: str) -> bool:
    """Runs as the profile's user: the script is the binary's wrapper or a python-era
    hook we shipped, not a no-op kept at our path with the right mode."""
    if not os.access(wrapper, os.R_OK | os.X_OK):
        return False  # e.g. another account's file: its owner bits don't make it runnable here
    try:
        text = _read_user_file(wrapper, follow=False).decode("utf-8")
    except (OSError, ValueError):
        return False
    return text == _codex_wrapper_source() or _python_era_hook_sha256(text, gateway) in python_era_hashes


def _codex_detect_state(m, user_homes, gateway=_PYTHON_ERA_DEFAULT_GATEWAY):
    """Install state before this run reasserts it, per profile, on the pair setup
    installs: the wrapper script and our hooks.json entry. Either alone leaves codex
    unenforced for that user. 'fresh' (no profile has either), 'persisted' (one has
    both), 'tampered' (any has one without the other; wins), None if a check failed."""
    try:
        any_complete = False
        indeterminate = False
        python_era_hashes = _known_python_era_hashes()
        for username, home_dir in user_homes:
            wrapper = home_dir / ".codex" / "hooks" / "unbound.py"
            hooks_path = home_dir / ".codex" / "hooks.json"
            script = _codex_wrapper_runnable(wrapper)
            if not script and os.path.lexists(wrapper):
                return "tampered"  # something other than our file holds the script path
            if script:
                script = m._run_as_user(username, _codex_wrapper_is_ours, wrapper, python_era_hashes, gateway)
                if script is False:
                    return "tampered"  # a runnable script at our path that isn't ours
            registered = False
            if os.path.lexists(hooks_path):
                registered = m._run_as_user(username, _codex_hook_registered, hooks_path, wrapper)
            if registered is None or script is None:
                indeterminate = True
            elif script and registered:
                any_complete = True
            elif script or registered:
                return "tampered"
        if indeterminate:
            return None
        return "persisted" if any_complete else "fresh"
    except Exception as e:
        print(f"[setup] codex install_state detection failed: {e}", file=sys.stderr)
        return None


def _setup_cursor(opts):
    m = _module("cursor")
    base, gateway = _normalized_urls(m, opts)
    if opts["backfill"]:
        print("[backfill] Cursor backfill is not supported — no historical transcript data is available on disk.")
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")

    success, env_changed, message = m.set_env_var("UNBOUND_CURSOR_API_KEY", api_key)
    if not success:
        return ("deferred", f"failed to set UNBOUND_CURSOR_API_KEY: {message}")

    for username, home_dir in m.get_all_user_homes():
        if m.write_unbound_config_for_user(
                username, home_dir, api_key,
                urls={"base_url": base, "gateway_url": gateway, "frontend_url": opts["frontend_url"]}):
            m.remove_user_level_hooks(username, home_dir)

    state = _detect_state(m.get_enterprise_hooks_dir() / "hooks.json")
    hooks_ok, hooks_changed = _write_cursor_enterprise_hooks(m)
    if not hooks_ok:
        return ("deferred", "enterprise hooks.json write failed")
    _remove_stale_managed_script(m.get_enterprise_hooks_dir())

    m.notify_setup_complete(api_key, "cursor", backend_url=base,
                            install_state=state, serial_number=device_id,
                            hook_hash=m.hook_script_hash(hook_source_path("cursor")),
                            install_mode="binary")
    if env_changed or hooks_changed:
        m.restart_cursor()
    return ("configured", None)


def _copilot_detect_state(user_homes) -> str:
    """Binary-era analog of copilot detect_install_state(): per-user files.
    'fresh' = no user has an unbound.json; 'persisted' = at least one user's
    unbound.json already points at the binary; 'tampered' otherwise."""
    saw_json = False
    saw_known_ref = False
    try:
        for _username, home_dir in user_homes:
            p = home_dir / ".copilot" / "hooks" / "unbound.json"
            if p.exists():
                saw_json = True
                try:
                    text = p.read_text(encoding="utf-8")
                    if str(HOOK_BINARY) in text or "unbound.py" in text:
                        saw_known_ref = True
                except OSError:
                    pass
        if not saw_json:
            return "fresh"
        return "persisted" if saw_known_ref else "tampered"
    except Exception as e:
        print(f"[setup] copilot install_state detection failed: {e}", file=sys.stderr)
        return None


def _setup_copilot(opts):
    m = _module("copilot")
    base, gateway = _normalized_urls(m, opts)
    device_id = m.get_device_identifier()
    if not device_id:
        return ("deferred", "could not read device identifier")
    api_key = m.fetch_api_key_from_mdm(base, opts["app_name"], opts["api_key"], device_id)
    if not api_key:
        return ("deferred", "MDM api key fetch failed")

    success, _ = m.set_env_var_system_wide("UNBOUND_COPILOT_API_KEY", api_key)
    if not success:
        return ("deferred", "failed to set UNBOUND_COPILOT_API_KEY")

    user_homes = m.get_all_user_homes()
    state = _copilot_detect_state(user_homes)
    installed = 0
    for username, home_dir in user_homes:
        m.write_unbound_config_for_user(
            username, home_dir, api_key,
            urls={"base_url": base, "gateway_url": gateway, "frontend_url": opts["frontend_url"]})
        # Earlier versions configured the exporter here, per user, in VS Code
        # settings. The managed file written below outranks those, so they are only
        # taken back out.
        if home_dir is not None:
            m.clear_otel_export_for_user(username, home_dir)
        if _install_copilot_hooks_for_user(m, username, home_dir):
            installed += 1

    # Machine-wide, so once for the device rather than once per user. Called
    # explicitly: this command drives the vendored module's named functions rather
    # than its main(), so a writer added there is dead code here until it is invoked.
    m.configure_managed_telemetry(api_key, gateway_url=gateway)

    if user_homes and installed == 0:
        return ("deferred", "hook install failed for all users")

    m.notify_setup_complete(api_key, "copilot", backend_url=base,
                            install_state=state, serial_number=device_id,
                            hook_hash=m.hook_script_hash(hook_source_path("copilot")),
                            install_mode="binary")
    if opts["backfill"]:
        hook_source = hook_source_path("copilot").read_text(encoding="utf-8")
        m.run_backfill(api_key, base, user_homes, hook_source)
    return ("configured", None)


def _fetch_device_owner_key(opts):
    """Resolve the API key of the user this device belongs to, from its hardware
    serial. Replaces the org discovery key: the scan authenticates as the owner,
    so the device is attributed to them. Returns None when it can't be resolved."""
    m = _module("claude-code")
    device_id = m.get_device_identifier()
    if not device_id:
        return None
    return m.fetch_api_key_from_mdm(
        opts["backend_url"], opts["app_name"], opts["api_key"], device_id,
        app_type="default",
    )


def _run_discovery(opts):
    """Run the locally installed discovery binary (no install.sh download).
    Mirrors onboard.py's process-group + backstop-kill discipline."""
    if not DISCOVERY_BINARY.is_file():
        return ("deferred", f"discovery binary not installed at {DISCOVERY_BINARY}")
    scan_key = _fetch_device_owner_key(opts)
    if not scan_key:
        return ("skipped", "could not resolve the device owner's key from the serial")
    # Key via env, never argv — the scan runs up to 90 min and argv is
    # visible to every local user via ps (same contract the hook modules'
    # frozen discovery dispatch uses).
    cmd = [str(DISCOVERY_BINARY), "--domain", opts["backend_url"]]
    env = {**os.environ, "UNBOUND_API_KEY": scan_key}
    backstop = DISCOVERY_TIMEOUT_SECONDS + DISCOVERY_KILL_GRACE_SECONDS
    try:
        proc = subprocess.Popen(cmd, start_new_session=True, env=env)
        try:
            rc = proc.wait(timeout=backstop)
        except subprocess.TimeoutExpired:
            import signal
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=15)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
            return ("deferred", f"discovery exceeded {backstop}s and was terminated")
        if rc != 0:
            return ("deferred", f"discovery exited with code {rc}")
        return ("configured", None)
    except Exception as e:
        return ("deferred", f"discovery launch failed: {e}")


_ADAPTERS = {
    "claude-code": _setup_claude_code,
    "cursor": _setup_cursor,
    "codex": _setup_codex,
    "copilot": _setup_copilot,
    "augment": _setup_augment,
}


def run(argv) -> int:
    opts = _parse_args(argv)
    if opts is None:
        return 2
    if not opts["api_key"]:
        print("Error: --api-key is required (the MDM admin key).", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    try:
        m0 = load_mdm_setup_module("claude-code")
        admin = m0.check_admin_privileges()
    except Exception:
        admin = False
    if not admin:
        print("unbound-hook setup requires administrator/root privileges. Re-run with sudo.",
              file=sys.stderr)
        return 1

    # Normalize once at the boundary so every consumer (adapters, discovery
    # --domain) sees a schemed, trailing-slash-free URL.
    opts["backend_url"] = m0.normalize_url(opts["backend_url"])
    opts["gateway_url"] = m0.normalize_url(opts["gateway_url"])
    # Optional: only when given, so an absent value stays None and the config
    # writer keeps skipping it.
    if opts["frontend_url"]:
        opts["frontend_url"] = m0.normalize_url(opts["frontend_url"])

    statuses = {}

    print(f"\n{'=' * 60}\n[migration] python->binary sweep\n{'=' * 60}")
    statuses["migration"] = migration.run_sweep(tools=opts["tools"])

    for tool in opts["tools"]:
        adapter = _ADAPTERS.get(tool)
        if adapter is None:
            statuses[tool] = ("skipped", f"unknown tool {tool!r}")
            continue
        print(f"\n{'=' * 60}\n[{tool}] MDM setup\n{'=' * 60}")
        try:
            statuses[tool] = adapter(opts)
        except SystemExit as e:
            statuses[tool] = ("deferred", f"component exited early: {e}")
        except Exception as e:
            statuses[tool] = ("deferred", f"error: {e}")

    print(f"\n{'=' * 60}\n[discovery] coding-tool scan\n{'=' * 60}")
    try:
        statuses["discovery"] = _run_discovery(opts)
    except Exception as e:
        statuses["discovery"] = ("deferred", f"error: {e}")

    print(f"\n{'=' * 60}\nunbound-hook setup summary\n{'=' * 60}")
    any_deferred = False
    for component, (status, reason) in statuses.items():
        line = f"  {component:12s} {status}"
        if reason:
            line += f" ({reason})"
        print(line)
        if status == "deferred":
            any_deferred = True
    return 1 if any_deferred else 0
