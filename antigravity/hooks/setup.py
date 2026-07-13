#!/usr/bin/env python3
"""User-level Unbound hooks installer for Antigravity (agy 1.0.5+).

Mirrors the flag surface and idioms of ``claude-code/hooks/setup.py``:

  --api-key <key>          Skip OAuth callback and use this key directly.
  --domain <url>           Frontend host that hands off an API key via a
                           localhost callback (mirrors Claude Code).
  --backend-url <url>      Backend host for setup-complete notifications.
  --gateway-url <url>      Unbound gateway base URL (baked into hook scripts).
  --clear                  Surgically remove only our entries from
                           ~/.gemini/config/hooks.json + delete our scripts.
  --backfill               No-op for Antigravity (no transcript store yet) —
                           accepted for CLI compatibility with other tools.
  --debug                  Verbose logging.

Wire format (verified empirically against agy 1.0.5, see
``AGY-EMPIRICAL-FINDINGS.md``):
  Hooks file:    ~/.gemini/config/hooks.json
  Hooks file keys: hooks.{PreToolUse,PostToolUse}
  Stdin payload: camelCase  {conversationId,stepIdx,toolCall:{name,args},...}
  Stdout payload: bare native-proto  {decision,reason}
  Tool names:    agy-native lowercase (run_command, view_file, edit_file, ...)
"""

import http.server
import json
import os
import platform
import re
import shutil
import socketserver
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional, Tuple


DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"
DEFAULT_BACKEND_URL = "https://backend.getunbound.ai"
UNBOUND_APP_LABEL = "antigravity"

# agy auto-loads hooks from ~/.gemini/config/hooks.json. Verified empirically;
# the older chop-derived path (~/.antigravity/settings.json) is not read.
GEMINI_CONFIG_DIR = Path.home() / ".gemini" / "config"
HOOKS_JSON_PATH = GEMINI_CONFIG_DIR / "hooks.json"

# Hook scripts live under our own namespace, not inside agy's config tree —
# keeps Unbound artifacts together with ~/.unbound/config.json so --clear has
# one place to look and so agy upgrades can't surprise-delete our scripts.
UNBOUND_DIR = Path.home() / ".unbound"
HOOKS_INSTALL_DIR = UNBOUND_DIR / "antigravity-hooks"
SENTINEL_PATH = HOOKS_INSTALL_DIR / ".unbound-installed.json"

# Only PreToolUse and PostToolUse actually wire through to user-supplied
# commands in agy 1.0.5. UserPromptSubmit/SessionStart are silently dropped at
# parse time; PreInvocation/PostInvocation/Stop register and log "executing
# command" but never spawn the process. Don't install hooks we know won't fire.
HOOK_EVENT_SCRIPTS: List[Tuple[str, str]] = [
    ("PreToolUse", "unbound_pre_tool_use.py"),
    ("PostToolUse", "unbound_post_tool_use.py"),
]

# Catch-all matcher for both events. ``""`` (empty string) is verified to fire
# on every tool. Server-side filtering (gateway's APP_NATIVE_FILE_TOOLS /
# tools_to_check) is where we defang; the matcher is the wrong place to
# allowlist — any tool not in the regex would silently bypass our hook.
HOOK_EVENT_MATCHERS: Dict[str, Optional[str]] = {
    "PreToolUse": "",
    "PostToolUse": "",
}

HOOK_TIMEOUT_SECONDS = 15
TELEMETRY_TIMEOUT_SECONDS = 60

DEBUG = False


def debug_print(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}")


def normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return value
    if not (value.startswith("http://") or value.startswith("https://")):
        value = f"https://{value}"
    return value.rstrip("/")


def install_macos_certificates() -> None:
    if platform.system().lower() != "darwin":
        return
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    cert_path = f"/Applications/Python {py_version}/Install Certificates.command"
    if os.path.exists(cert_path):
        subprocess.run([cert_path], capture_output=True)


# -----------------------------------------------------------------------------
# OAuth callback (mirrors claude-code/hooks/setup.py:run_callback_server)
# -----------------------------------------------------------------------------

def run_callback_server(frontend_url: str) -> Optional[Dict]:
    result: Dict = {"method": None, "path": None, "query": None, "headers": None, "body": None}
    done_evt = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def _finish(self, code: int = 200, message: bytes = b"Logged in successfully! You can close this tab.") -> None:
            try:
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(message)))
                self.end_headers()
                self.wfile.write(message)
            except Exception:
                pass

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            result["method"] = "GET"
            result["path"] = self.path
            result["query"] = dict(urllib.parse.parse_qsl(parsed.query))
            result["headers"] = {k: v for k, v in self.headers.items()}
            result["body"] = None
            query = result["query"]
            if "error" in query:
                self._finish(code=400, message=f"Setup failed: {query['error'][:200]}\nPlease try again or contact support.".encode())
            else:
                self._finish()
            done_evt.set()

        def log_message(self, format: str, *args) -> None:
            return

    class _CallbackServer(socketserver.TCPServer):
        allow_reuse_address = True

    try:
        httpd = _CallbackServer(("127.0.0.1", 0), CallbackHandler)
        port = httpd.server_address[1]
        callback_url = f"http://127.0.0.1:{port}/callback"

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        encoded_callback = urllib.parse.quote(callback_url, safe="")
        target_url = (
            f"{frontend_url.rstrip('/')}/automations/api-key-callback"
            f"?callback_url={encoded_callback}&app_type={UNBOUND_APP_LABEL}"
        )
        webbrowser.open(target_url)
        print("Opening browser...")
        print("If browser doesn't open automatically, open this link:")
        print(target_url)
        print("Waiting for authentication...")

        try:
            if not done_evt.wait(timeout=300):
                print("Timed out waiting for authentication (5 minutes). Please re-run setup.")
                return None
        finally:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass

        return result
    except Exception as e:
        print(f"Failed to run callback server: {e}")
        return None


# -----------------------------------------------------------------------------
# Unbound config (~/.unbound/config.json) — shared with unbound-cli + hooks
# -----------------------------------------------------------------------------

def write_unbound_config(api_key: str, gateway_url: str) -> bool:
    config_dir = Path.home() / ".unbound"
    config_file = config_dir / "config.json"
    try:
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if platform.system().lower() != "windows":
            os.chmod(config_dir, 0o700)
        config: Dict = {}
        if config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    config = json.loads(f.read())
            except (json.JSONDecodeError, OSError):
                config = {}
        config["api_key"] = api_key
        if gateway_url:
            config["gateway_url"] = gateway_url
        fd = os.open(str(config_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(config, indent=2))
        return True
    except Exception as e:
        print(f"Could not write config: {e}")
        return False


# -----------------------------------------------------------------------------
# Hook script installation
# -----------------------------------------------------------------------------

def _script_source_dir() -> Path:
    """The directory holding our packaged hook script templates.

    When ``setup.py`` is run from a checkout of websentry-ai/setup, the
    scripts live in ``./scripts/`` next to this file. When the curl-piped
    install pulls just ``setup.py``, the user runs with ``--domain`` and the
    scripts get fetched from GitHub on demand (see ``download_script``).
    """
    return Path(__file__).resolve().parent / "scripts"


SCRIPT_BASE_URL = (
    "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/"
    "antigravity/hooks/scripts"
)


def download_script(filename: str, dest_path: Path) -> bool:
    url = f"{SCRIPT_BASE_URL}/{filename}"
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        debug_print(f"Downloading {url} to {dest_path}")
        result = subprocess.run(
            ["curl", "-fsSL", "-o", str(dest_path), url],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Failed to download {url}: {e}")
        return False


def _install_one_script(src_filename: str, dest_path: Path) -> bool:
    """Copy from local checkout if present, otherwise fetch from GitHub."""
    src = _script_source_dir() / src_filename
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if src.exists():
        try:
            shutil.copyfile(src, dest_path)
            debug_print(f"Installed {dest_path} from local checkout")
            return True
        except OSError as e:
            print(f"Failed to copy {src} → {dest_path}: {e}")
            return False
    return download_script(src_filename, dest_path)


def install_hook_scripts(gateway_url: str) -> bool:
    """Install the two hook scripts plus the _common helper into
    ``~/.unbound/antigravity-hooks/``. Bake the gateway_url into _common.py so
    tenant deployments don't depend on env vars at runtime."""
    HOOKS_INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. The shared helper.
    common_dest = HOOKS_INSTALL_DIR / "_common.py"
    if not _install_one_script("_common.py", common_dest):
        return False
    rewrite_gateway_url_in_file(common_dest, gateway_url)

    # 2. The two event scripts. Each gets a stable name so --clear can find them.
    for _event, installed_name in HOOK_EVENT_SCRIPTS:
        # Source filename mirrors event name without the unbound_ prefix.
        src = installed_name.replace("unbound_", "", 1)
        dest = HOOKS_INSTALL_DIR / installed_name
        if not _install_one_script(src, dest):
            return False
        # Make executable on Unix.
        if platform.system().lower() != "windows":
            try:
                current_mode = dest.stat().st_mode
                os.chmod(dest, current_mode | 0o111)
            except OSError:
                pass

    return True


def rewrite_gateway_url_in_file(path: Path, gateway_url: str) -> None:
    """Replace the default gateway URL inside _common.py at install time so
    tenant deployments don't depend on UNBOUND_GATEWAY_URL being set."""
    if not gateway_url or gateway_url == DEFAULT_GATEWAY_URL:
        return
    try:
        text = path.read_text(encoding="utf-8")
        new_text = text.replace(f'"{DEFAULT_GATEWAY_URL}"', f'"{gateway_url}"')
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    except Exception as e:
        debug_print(f"Could not rewrite gateway URL in {path}: {e}")


# -----------------------------------------------------------------------------
# hooks.json merge / unmerge
# -----------------------------------------------------------------------------

def _build_hook_command(script_filename: str) -> Tuple[str, bool]:
    """Return (command_string, is_windows). On Windows we wrap with the
    Python launcher and quote for spaces. Same trick as
    claude-code/hooks/setup.py."""
    script_path = HOOKS_INSTALL_DIR / script_filename
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        launcher = "py -3" if shutil.which("py") else "python"
        return f'{launcher} "{script_path}"', True
    return str(script_path), False


def _build_event_entry(event: str, script_filename: str) -> Dict:
    """Construct the matcher+hooks block for a single event.

    Both PreToolUse and PostToolUse use the catch-all ``""`` (verified to
    fire on every tool). Server-side filtering, not the matcher, is where
    we defang.
    """
    command, is_windows = _build_hook_command(script_filename)
    matcher = HOOK_EVENT_MATCHERS.get(event, "")

    inner: Dict = {
        "type": "command",
        "command": command,
        "timeout": TELEMETRY_TIMEOUT_SECONDS if event != "PreToolUse" else HOOK_TIMEOUT_SECONDS,
    }
    # PostToolUse is telemetry — let it run async.
    if event == "PostToolUse":
        inner["async"] = True
    if is_windows:
        inner["shell"] = "powershell"

    # Place "matcher" first to mirror the layout chop and Claude Code use.
    return {"matcher": matcher if matcher is not None else "", "hooks": [inner]}


def _is_our_hook_command(command: str, is_windows: bool) -> bool:
    """Identify a hook entry we wrote. On Unix that's an exact match against
    ``~/.unbound/antigravity-hooks/unbound_*.py``; on Windows we look for the
    install dir substring because the command is wrapped in ``py -3 "..."``."""
    if not command:
        return False
    install_prefix = str(HOOKS_INSTALL_DIR)
    if is_windows:
        return install_prefix in command and "unbound_" in command
    # Exact path match: our installed file lives inside HOOKS_INSTALL_DIR and
    # starts with "unbound_".
    try:
        path = Path(command)
        return (
            str(path.parent) == install_prefix
            and path.name.startswith("unbound_")
            and path.name.endswith(".py")
        )
    except (ValueError, OSError):
        return False


def _atomic_write_json(path: Path, data: Dict) -> None:
    """Write JSON atomically: tmp file + rename. Never leaves a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def configure_antigravity_settings() -> bool:
    """Non-destructively merge our hook entries into ~/.gemini/config/hooks.json.

    - Creates the file with ``{}`` if absent.
    - Preserves every existing hook entry that we did not write.
    - Idempotent: re-running install is a no-op if our entries are already present.
    """
    try:
        if HOOKS_JSON_PATH.exists():
            try:
                with open(HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
                    settings = json.load(f)
            except json.JSONDecodeError as e:
                print(f"Failed to parse existing hooks.json: {e}")
                print("   Please check your hooks.json file for syntax errors")
                return False
        else:
            settings = {}

        if not isinstance(settings, dict):
            print(f"Existing hooks.json is not a JSON object; refusing to overwrite.")
            return False

        if "hooks" not in settings or not isinstance(settings["hooks"], dict):
            settings["hooks"] = {}

        is_windows = platform.system().lower() == "windows"
        sentinel_entries: List[Dict[str, str]] = []

        for event, script_filename in HOOK_EVENT_SCRIPTS:
            our_entry = _build_event_entry(event, script_filename)
            our_command = our_entry["hooks"][0]["command"]
            sentinel_entries.append({"event": event, "script": script_filename})

            existing = settings["hooks"].get(event)
            if not isinstance(existing, list):
                settings["hooks"][event] = [our_entry]
                continue

            # Is there already an entry pointing at our installed script?
            already_present = False
            for item in existing:
                if not isinstance(item, dict):
                    continue
                hooks_list = item.get("hooks", [])
                if not isinstance(hooks_list, list):
                    continue
                for h in hooks_list:
                    if not isinstance(h, dict):
                        continue
                    if h.get("command") == our_command:
                        already_present = True
                        break
                if already_present:
                    break

            if not already_present:
                existing.append(our_entry)

        _atomic_write_json(HOOKS_JSON_PATH, settings)

        sentinel = {"version": 1, "entries": sentinel_entries}
        _atomic_write_json(SENTINEL_PATH, sentinel)

        # Best-effort: tighten perms on the sentinel.
        if not is_windows:
            try:
                os.chmod(SENTINEL_PATH, 0o600)
            except OSError:
                pass
        return True
    except Exception as e:
        print(f"Failed to configure settings: {e}")
        return False


def remove_hooks_from_settings() -> str:
    """Surgically remove our entries from hooks.json. Returns
    "cleared" | "not_found" | "failed".

    Pattern mirrors ``AgusRdz/chop:hooks/antigravity_install.go::antigravityUninstallFrom``:
    walk each event's list, drop any hook whose command points at our install
    dir, drop the wrapping matcher entry if its hooks list ends empty, drop
    the event key if no entries remain, drop ``hooks`` if it ends empty.
    """
    if not HOOKS_JSON_PATH.exists():
        return "not_found"

    is_windows = platform.system().lower() == "windows"

    try:
        with open(HOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Failed to read hooks.json: {e}")
        return "failed"

    if not isinstance(settings, dict) or not isinstance(settings.get("hooks"), dict):
        return "not_found"

    modified = False
    hooks_block = settings["hooks"]

    for event in list(hooks_block.keys()):
        event_config = hooks_block[event]
        if not isinstance(event_config, list):
            continue
        new_event_config: List[Dict] = []
        for item in event_config:
            if not isinstance(item, dict):
                new_event_config.append(item)
                continue
            hooks_list = item.get("hooks")
            if not isinstance(hooks_list, list):
                new_event_config.append(item)
                continue
            new_hooks = [
                h for h in hooks_list
                if not (
                    isinstance(h, dict)
                    and _is_our_hook_command(h.get("command", ""), is_windows)
                )
            ]
            if len(new_hooks) == len(hooks_list):
                new_event_config.append(item)
                continue
            modified = True
            if new_hooks:
                item["hooks"] = new_hooks
                new_event_config.append(item)
            # else: drop this matcher entry entirely.
        if new_event_config:
            hooks_block[event] = new_event_config
        else:
            del hooks_block[event]
            modified = True

    if not hooks_block:
        del settings["hooks"]
        modified = True

    if not modified:
        return "not_found"

    try:
        _atomic_write_json(HOOKS_JSON_PATH, settings)
    except OSError as e:
        print(f"Failed to write hooks.json: {e}")
        return "failed"
    return "cleared"


# -----------------------------------------------------------------------------
# Clear path
# -----------------------------------------------------------------------------

def _delete_path(path: Path, label: str) -> str:
    if not path.exists():
        return "not_found"
    try:
        path.unlink()
        debug_print(f"Removed {path}")
        return "cleared"
    except Exception as e:
        print(f"Failed to clear {label}: {e}")
        return "failed"


def clear_setup() -> None:
    print("=" * 60)
    print("Antigravity Hooks - Clearing Setup")
    print("=" * 60)

    any_cleared = False
    any_failed = False

    # 1. Surgically remove our entries from hooks.json.
    settings_status = remove_hooks_from_settings()
    if settings_status == "cleared":
        any_cleared = True
    elif settings_status == "failed":
        any_failed = True

    # 2. Delete each ~/.unbound/antigravity-hooks/unbound_*.py.
    if HOOKS_INSTALL_DIR.exists():
        for _event, installed_name in HOOK_EVENT_SCRIPTS:
            status = _delete_path(HOOKS_INSTALL_DIR / installed_name, installed_name)
            if status == "cleared":
                any_cleared = True
            elif status == "failed":
                any_failed = True
        # And the shared helper.
        status = _delete_path(HOOKS_INSTALL_DIR / "_common.py", "_common.py")
        if status == "cleared":
            any_cleared = True
        elif status == "failed":
            any_failed = True
        # 3. Drop the sentinel (lives inside HOOKS_INSTALL_DIR).
        sentinel_status = _delete_path(SENTINEL_PATH, "install sentinel")
        if sentinel_status == "cleared":
            any_cleared = True
        elif sentinel_status == "failed":
            any_failed = True
        # Drop the hooks dir if empty.
        try:
            if not any(HOOKS_INSTALL_DIR.iterdir()):
                HOOKS_INSTALL_DIR.rmdir()
                debug_print(f"Removed empty {HOOKS_INSTALL_DIR}")
        except OSError:
            pass

    if any_cleared:
        print("Cleared")
    elif not any_failed:
        print("Nothing to clear (Unbound hooks were not installed for Antigravity)")
    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


# -----------------------------------------------------------------------------
# Backend notification (best-effort)
# -----------------------------------------------------------------------------

def notify_setup_complete(api_key: str, backend_url: str) -> None:
    # Use stdlib urllib instead of shelling out to curl: passing the API key
    # via curl's argv leaks it through ``ps auxe`` / ``/proc/<pid>/cmdline``
    # to any other user on the device. urllib sets the header inside the
    # process — argv stays secret-free.
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        body = json.dumps({"tool_type": UNBOUND_APP_LABEL}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "X-API-KEY": api_key,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except urllib.error.HTTPError as e:
            debug_print(f"Setup-complete returned HTTP {e.code}")
        debug_print("Setup completion notification sent")
    except Exception as e:
        debug_print(f"Could not notify backend: {e}")


# -----------------------------------------------------------------------------
# Argument parsing + main
# -----------------------------------------------------------------------------

def _arg_value(name: str, argv: List[str]) -> Optional[str]:
    for i, arg in enumerate(argv):
        if arg == name and i + 1 < len(argv):
            return argv[i + 1]
    return None


def main() -> None:
    global DEBUG

    argv = sys.argv[1:]
    clear_mode = "--clear" in argv
    DEBUG = "--debug" in argv
    backfill_mode = "--backfill" in argv

    if clear_mode:
        clear_setup()
        return

    install_macos_certificates()

    print("=" * 60)
    print("Antigravity Hooks Setup for Unbound Gateway")
    print("=" * 60)

    domain = _arg_value("--domain", argv)
    backend_url = normalize_url(_arg_value("--backend-url", argv) or DEFAULT_BACKEND_URL)
    gateway_url = normalize_url(_arg_value("--gateway-url", argv) or DEFAULT_GATEWAY_URL)
    api_key = _arg_value("--api-key", argv)

    if not api_key:
        if not domain:
            print("Missing required argument: --domain or --api-key")
            sys.exit(1)
        cb_response = run_callback_server(normalize_url(domain))
        if cb_response is None:
            print("Failed to receive callback. Exiting.")
            sys.exit(1)
        try:
            api_key = (cb_response.get("query") or {}).get("api_key")
        except Exception:
            api_key = None
        if not api_key:
            error_msg = (cb_response.get("query") or {}).get("error")
            if error_msg:
                safe_error = re.sub(r"[\x00-\x1f\x7f]", "", error_msg)[:200]
                print(f"Setup failed: {safe_error}")
            else:
                print("No API key received. Exiting.")
            sys.exit(1)

    debug_print("API key resolved")

    write_unbound_config(api_key, gateway_url)

    debug_print("Installing hook scripts...")
    if not install_hook_scripts(gateway_url):
        print("Failed to install hook scripts")
        sys.exit(1)

    debug_print("Configuring Antigravity hooks.json...")
    if not configure_antigravity_settings():
        print("Failed to configure Antigravity hooks.json")
        sys.exit(1)

    print("API key verified and added")
    print("Setup complete")
    print("=" * 60)

    notify_setup_complete(api_key, backend_url)

    if backfill_mode:
        # Antigravity has no on-disk transcript store equivalent to
        # ~/.claude/projects yet — accept the flag for CLI parity but no-op.
        debug_print("--backfill: no-op for Antigravity (no transcript store)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
