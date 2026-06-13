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

import json
import os
import platform
import subprocess
import sys
from pathlib import Path

from ._loader import load_mdm_setup_module
from ._resources import DISCOVERY_BINARY, HOOK_BINARY, hook_command_for_event
from . import migration

# Mirrors mdm/onboard.py's discovery timeout contract.
DISCOVERY_TIMEOUT_SECONDS = 5400
DISCOVERY_KILL_GRACE_SECONDS = 120

SETUP_TOOLS = ("claude-code", "cursor", "codex", "copilot")

USAGE = (
    "Usage: unbound-hook setup --api-key <admin_key> [--discovery-key <key>]\n"
    "           [--backend-url <url>] [--gateway-url <url>] [--frontend-url <url>]\n"
    "           [--app_name <name>] [--backfill] [--tools t1,t2,...]\n"
)


def _parse_args(argv):
    opts = {
        "api_key": None,
        "discovery_key": None,
        "backend_url": "https://backend.getunbound.ai",
        "gateway_url": "https://api.getunbound.ai",
        "frontend_url": None,
        "app_name": None,
        "backfill": False,
        "tools": list(SETUP_TOOLS),
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--api-key" and i + 1 < len(argv):
            opts["api_key"] = argv[i + 1]; i += 2
        elif a == "--discovery-key" and i + 1 < len(argv):
            opts["discovery_key"] = argv[i + 1]; i += 2
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
    rollout day); 'tampered' = settings present referencing neither."""
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
    a truncated managed-settings file."""
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


def _codex_hooks_config():
    cmd = lambda ev: hook_command_for_event("codex", ev)
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


def _write_claude_managed_settings(m) -> bool:
    """Binary variant of claude-code setup_managed_hooks(): same settings
    file, same gateway-leftover cleanup, no script download."""
    try:
        managed_dir = m.get_managed_settings_dir()
        managed_dir.mkdir(parents=True, exist_ok=True)
        settings_path = managed_dir / "managed-settings.json"

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


def _write_codex_managed_settings(m) -> bool:
    try:
        managed_dir = m.get_managed_settings_dir()
        managed_dir.mkdir(parents=True, exist_ok=True)
        settings_path = managed_dir / "hooks.json"

        settings = {}
        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    settings = json.load(f) or {}
            except Exception:
                settings = {}

        settings["hooks"] = _codex_hooks_config()
        _atomic_write_text(settings_path, json.dumps(settings, indent=2))

        if platform.system().lower() in ("darwin", "linux"):
            os.chmod(managed_dir, 0o755)
            os.chmod(settings_path, 0o644)
        return True
    except Exception as e:
        print(f"Failed to write managed settings: {e}")
        return False


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

    state = _detect_state(m.get_managed_settings_dir() / "managed-settings.json")
    if not _write_claude_managed_settings(m):
        return ("deferred", "managed settings write failed")
    _remove_stale_managed_script(m.get_managed_settings_dir())

    m.notify_setup_complete(api_key, "claude-code", backend_url=base,
                            install_state=state, serial_number=device_id)
    if opts["backfill"]:
        m.run_backfill(api_key, base, m.get_all_user_homes())
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

    for username, home_dir in m.get_all_user_homes():
        m.remove_gateway_artifacts_for_user(username, home_dir)
        m.remove_user_level_hooks_for_user(username, home_dir)
        m.write_unbound_config_for_user(
            username, home_dir, api_key,
            urls={"base_url": base, "gateway_url": gateway, "frontend_url": opts["frontend_url"]})
        m.enable_codex_hooks_feature_for_user(username, home_dir)

    state = _detect_state(m.get_managed_settings_dir() / "hooks.json")
    if not _write_codex_managed_settings(m):
        return ("deferred", "managed settings write failed")
    _remove_stale_managed_script(m.get_managed_settings_dir())

    m.notify_setup_complete(api_key, "codex", backend_url=base,
                            install_state=state, serial_number=device_id)
    if opts["backfill"]:
        m.run_backfill(api_key, base, m.get_all_user_homes())
    return ("configured", None)


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
                            install_state=state, serial_number=device_id)
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
        if _install_copilot_hooks_for_user(m, username, home_dir):
            installed += 1

    if user_homes and installed == 0:
        return ("deferred", "hook install failed for all users")

    m.notify_setup_complete(api_key, "copilot", backend_url=base,
                            install_state=state, serial_number=device_id)
    if opts["backfill"]:
        m.run_backfill(api_key, base, user_homes)
    return ("configured", None)


# Root-only credential file the scheduled discovery LaunchDaemon reads to find
# its api key + domain (WEB-4808). Lives in the pkg-provisioned config dir
# (postinstall: install -d -m 0750 root:wheel /opt/unbound/etc). The recurring
# daemon runs as root with no shell env and a world-readable plist that
# deliberately carries no secrets, so this file is its only credential channel.
# The entry point (packaging/unbound_discovery_entry.py:DISCOVERY_CONFIG_PATH)
# reads it as an OPTIONAL fallback; keep the two paths in sync.
DISCOVERY_CONFIG_PATH = Path("/opt/unbound/etc/discovery.json")


def _write_discovery_config(opts):
    """Persist the discovery key + domain for the scheduled daemon.

    Writes /opt/unbound/etc/discovery.json atomically as 0600 root:wheel (it
    holds a credential). The `etc` dir itself is created/enforced as 0750
    root-owned (not the umask-default 0755) so it is not world-traversable.
    Best-effort: a failure here is reported but never aborts onboarding — the
    one-shot scan below still runs, and a daemon with no config simply idles
    fail-open. Returns None on success or a short reason string on failure.
    """
    import tempfile

    payload = json.dumps(
        {"api_key": opts["discovery_key"], "domain": opts["backend_url"]},
        indent=2,
    ) + "\n"
    parent = DISCOVERY_CONFIG_PATH.parent
    try:
        # Create ONLY the leaf `etc` dir, not the whole tree: /opt/unbound is
        # provisioned (and owned) by the pkg postinstall, so its absence means
        # something is wrong — building the tree here would risk leaving an
        # ancestor world-readable. Refuse rather than mask that.
        if not parent.parent.is_dir():
            return (f"could not persist discovery config: parent "
                    f"{parent.parent} missing (expected pkg-provisioned)")
        # 0750 (not the umask default 0755) so the dir is not world-traversable
        # — it reinforces the directory-level symlink/TOCTOU barrier the 0600
        # credential file relies on. When root (the production path), enforce
        # mode + root:root ownership even if the dir already existed; tolerate
        # non-root/dev contexts where chmod/chown would be denied.
        os.makedirs(parent, mode=0o750, exist_ok=True)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            try:
                os.chmod(parent, 0o750)
                os.chown(parent, 0, 0)
            except OSError:
                pass  # best-effort hardening; never block the credential write
        # Write to a temp file in the same dir (mkstemp is already 0600 by
        # default), set explicit perms + owner, then atomically rename so a
        # reader never observes a partial or wrong-permission file.
        fd, tmp = tempfile.mkstemp(dir=str(parent), prefix=".discovery.", suffix=".json")
        try:
            os.fchmod(fd, 0o600)
            try:
                os.fchown(fd, 0, 0)  # root:wheel; no-op-equivalent if already root
            except (PermissionError, OSError):
                pass  # not root (shouldn't happen — setup requires sudo); keep going
            with os.fdopen(fd, "w") as f:
                f.write(payload)
            os.replace(tmp, str(DISCOVERY_CONFIG_PATH))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        return f"could not persist discovery config: {e}"
    return None


def _run_discovery(opts):
    """Run the locally installed discovery binary (no install.sh download).
    Mirrors onboard.py's process-group + backstop-kill discipline."""
    if not opts["discovery_key"]:
        return ("skipped", "no --discovery-key provided")
    if not DISCOVERY_BINARY.is_file():
        return ("deferred", f"discovery binary not installed at {DISCOVERY_BINARY}")
    # Persist creds so the scheduled LaunchDaemon (which has no shell env and a
    # secret-free plist) can run the recurring 12h scan, not just this one-shot
    # (WEB-4808). Fail-open: a persist failure is logged, not fatal.
    config_err = _write_discovery_config(opts)
    if config_err:
        print(f"[setup] discovery: {config_err}", file=sys.stderr)
    # Key via env, never argv — the scan runs up to 90 min and argv is
    # visible to every local user via ps (same contract the hook modules'
    # frozen discovery dispatch uses).
    cmd = [str(DISCOVERY_BINARY), "--domain", opts["backend_url"]]
    env = {**os.environ, "UNBOUND_API_KEY": opts["discovery_key"]}
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

    statuses = {}

    print(f"\n{'=' * 60}\n[migration] python→binary sweep\n{'=' * 60}")
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
