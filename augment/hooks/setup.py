
#!/usr/bin/env python3

import os
import re
import shutil
import sys
import platform
import subprocess
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Tuple, Optional, Dict, List
import threading
import http.server
import socketserver
import socket
import json
import tempfile


SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/augment/hooks/unbound.py"

DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"

DEBUG = False


# --- Augment settings blocks ------------------------------------------------
#
# These two constants are the single source of truth for what we write into a
# user's ~/.augment/settings.json (the MDM script reuses them with a different
# <CMD>). They are kept as builder functions so the per-hook command can be
# swapped for the MDM path / Windows launcher without duplicating the schema.

# No per-hook `metadata` is seeded. Auggie rejects a `metadata` property on a
# hook entry ("Unknown property metadata ... will be ignored") and shows a
# "Some plugin hooks use unsupported configuration" warning on every run. It is
# also unnecessary: Auggie delivers the turn conversation by DEFAULT on the Stop
# event (event._exchange.exchange.{request_message, response_text}) — which is
# what the end-of-turn analytics read.


def build_hooks_block(hook_command: str, extra: Optional[Dict] = None) -> Dict:
    """The Augment `hooks` block. Augment has no UserPromptSubmit event, so it is
    absent. Timeouts are in milliseconds. `extra` (e.g. {"shell": "powershell"})
    is merged into every hook entry for the Windows launcher. No per-hook
    metadata is emitted — Auggie rejects it and the turn conversation arrives by
    default on Stop (see the note above)."""
    def _hook(timeout: int) -> Dict:
        entry = {"type": "command", "command": hook_command, "timeout": timeout}
        if extra:
            entry = {**entry, **extra}
        return entry

    return {
        "PreToolUse": [{"matcher": ".*", "hooks": [_hook(15000)]}],
        "PostToolUse": [{"matcher": ".*", "hooks": [_hook(10000)]}],
        "Stop": [{"hooks": [_hook(10000)]}],
        "SessionStart": [{"hooks": [_hook(60000)]}],
        "SessionEnd": [{"hooks": [_hook(10000)]}],
    }


# Conservative seed set of native toolPermissions ask-user rules (Option 1).
# Augment's hook output can only DENY today, so WARN-class policy outcomes are
# delegated to Augment's native toolPermissions interactive prompt
# ([A]llow / [D]eny, defaults to deny in --print). These rules pause on the
# highest-risk shell invocations and on any MCP tool call so an operator
# confirms before they run. Kept intentionally small and clearly commented;
# the gateway remains the authoritative policy surface.
#
# shellInputRegex matches: rm -rf, piping a remote fetch into a shell
# (curl|wget ... | sh/bash), sudo, world-writable chmod, force-push, and reads
# of common credential files.
_HIGH_RISK_SHELL_REGEX = (
    r"(rm\s+-rf|"
    r"(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba)?sh|"
    r"\bsudo\b|"
    r"chmod\s+(-[A-Za-z]*\s+)*777|"
    r"git\s+push\b[^\n]*(--force|-f)\b|"
    r"cat\b[^\n]*(/etc/shadow|\.aws/credentials|\.ssh/id_|\.netrc|\.env))"
)


def build_tool_permissions_block() -> List[Dict]:
    """Seeded ask-user rules. Each rule is matched on (toolName, shellInputRegex)
    for idempotent merge so re-running setup never duplicates them and foreign
    rules are preserved."""
    return [
        {
            "toolName": "launch-process",
            "shellInputRegex": _HIGH_RISK_SHELL_REGEX,
            "eventType": "tool-call",
            "permission": {"type": "ask-user"},
        },
        {
            # DEFER (schema TBC): the "mcp:.*" toolName pattern is unverified
            # against a live Augment instance — confirm before relying on it.
            # Gateway deny remains authoritative regardless.
            "toolName": "mcp:.*",
            "eventType": "tool-call",
            "permission": {"type": "ask-user"},
        },
    ]


def _tool_permission_identity(rule: Dict) -> Tuple:
    """Identity tuple used to dedupe / match our rules on merge and clear."""
    if not isinstance(rule, dict):
        return (None, None)
    return (rule.get("toolName"), rule.get("shellInputRegex"))


_OUR_TOOL_PERMISSION_IDENTITIES = {
    _tool_permission_identity(r) for r in build_tool_permissions_block()
}


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def curl_with_auth(auth_headers: List[str], curl_args: List[str], *,
                   input=None, timeout: int = 10):
    """Run curl with secret auth header(s) kept OFF the argv.

    The curl argv is world-readable via /proc/<pid>/cmdline and `ps`, so passing
    `X-API-KEY: <key>` / `Authorization: Bearer <key>` as `-H "<header>"` would
    leak the secret on a shared host. Write the auth header line(s) to a 0600
    temp file and pass `-H @<tmpfile>` instead; delete it in a finally.
    `curl_args` is everything except the auth header (flags + URL). Returns the
    CompletedProcess, or None if the header file could not be written."""
    fd, tmp_path = tempfile.mkstemp(prefix=".curlhdr.", suffix=".txt")
    try:
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(auth_headers) + "\n")
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return None
        cmd = ["curl", *curl_args, "-H", f"@{tmp_path}"]
        return subprocess.run(cmd, input=input, capture_output=True, timeout=timeout)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def install_macos_certificates():
    """Run Python certificate installation command on macOS."""
    if platform.system().lower() != "darwin":
        return
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    cert_path = f"/Applications/Python {py_version}/Install Certificates.command"
    if os.path.exists(cert_path):
        subprocess.run([cert_path], capture_output=True)


def normalize_url(domain: str) -> str:
    domain = domain.strip()

    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain
    else:
        url = f"https://{domain}"

    return url.rstrip('/')


def get_shell_rc_file() -> Path:
    system = platform.system().lower()
    shell = os.environ.get("SHELL", "").lower()

    if system == "darwin":
        return Path.home() / ".zprofile" if "zsh" in shell else Path.home() / ".bash_profile"
    elif system == "linux":
        return Path.home() / ".zshrc" if "zsh" in shell else Path.home() / ".bashrc"
    elif system == "windows":
        return None
    else:
        raise OSError(f"Unsupported operating system: {system}")


def append_to_file(file_path: Path, line: str, var_name: str = None) -> bool:
    try:
        file_path.touch(exist_ok=True)

        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if var_name:
            export_prefix = f"export {var_name}="
            lines = [l for l in lines if not l.strip().startswith(export_prefix)]

        if line + "\n" not in lines and line not in [l.rstrip() for l in lines]:
            lines.append(f"{line}\n")

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        if var_name and line not in [l.rstrip() for l in lines]:
            lines.append(f"{line}\n")
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        return True
    except Exception as e:
        print(f"❌ Failed to modify {file_path}: {e}")
        return False


def set_env_var_windows(var_name: str, value: str) -> bool:
    debug_print(f"Writing to user environment registry (Windows)")
    try:
        subprocess.run(["setx", var_name, value], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"❌ Failed to set {var_name} on Windows: {e}")
        return False


def set_env_var_unix(var_name: str, value: str) -> bool:
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False

    debug_print(f"Writing to shell file: {rc_file}")
    export_line = f'export {var_name}="{value}"'
    return append_to_file(rc_file, export_line, var_name)


def set_env_var(var_name: str, value: str) -> Tuple[bool, str]:
    system = platform.system().lower()

    if system == "windows":
        success = set_env_var_windows(var_name, value)
        return (True, "Set for new terminals") if success else (False, "Failed")
    elif system in ["darwin", "linux"]:
        success = set_env_var_unix(var_name, value)
        if success:
            shell_name = "zsh" if "zsh" in os.environ.get("SHELL", "") else "bash"
            return True, f"Run 'source ~/.{shell_name}rc' or restart terminal"
        return False, "Failed"
    else:
        return False, f"Unsupported OS: {system}"


def remove_env_var_on_unix(var_name: str) -> str:
    """Remove an environment variable export line from the user's shell rc file.

    Returns "cleared", "not_found", or "failed".
    """
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return "failed"
    try:
        if not rc_file.exists():
            return "not_found"
        with open(rc_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = []
        removed = False
        export_prefix = f"export {var_name}="
        for line in lines:
            if line.strip().startswith(export_prefix):
                removed = True
                debug_print(f"Removing {var_name} from {rc_file}")
                continue
            new_lines.append(line)
        if removed:
            with open(rc_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            return "cleared"
        return "not_found"
    except Exception as e:
        print(f"Failed to modify {rc_file}: {e}")
        return "failed"


def remove_env_var_on_windows(var_name: str) -> str:
    """Remove a user environment variable on Windows.

    Returns "cleared", "not_found", or "failed".
    """
    try:
        query = subprocess.run(
            ["reg", "query", "HKCU\\Environment", "/V", var_name],
            capture_output=True,
        )
        if query.returncode != 0:
            return "not_found"
        subprocess.run(
            ["reg", "delete", "HKCU\\Environment", "/F", "/V", var_name],
            check=True,
            capture_output=True,
        )
        debug_print(f"Removed {var_name} from Windows registry")
        return "cleared"
    except subprocess.CalledProcessError:
        return "failed"
    except FileNotFoundError:
        print("'reg' command not found. Please remove the variable manually.")
        return "failed"


def remove_env_var(var_name: str) -> Tuple[str, str]:
    """Remove an environment variable permanently across OS platforms.

    Returns (status, message) where status is "cleared", "not_found", "failed",
    or "unsupported".
    """
    system = platform.system().lower()
    if system == "windows":
        return remove_env_var_on_windows(var_name), ""
    elif system in ["darwin", "linux"]:
        return remove_env_var_on_unix(var_name), ""
    else:
        return "unsupported", f"Unsupported OS: {system}"


def run_callback_server(frontend_url: str) -> Optional[Dict[str, any]]:
    result: Dict[str, any] = {"method": None, "path": None, "query": None, "headers": None, "body": None}
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
        target_url = f"{frontend_url.rstrip('/')}/automations/api-key-callback?callback_url={encoded_callback}&app_type=augment_code"
        webbrowser.open(target_url)
        print("🌐 Opening browser...")
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
        print(f"❌ Failed to run callback server: {e}")
        return None


def write_unbound_config(api_key: str, urls: dict = None) -> bool:
    """Write API key to ~/.unbound/config.json (shared with unbound-cli)."""
    config_dir = Path.home() / ".unbound"
    config_file = config_dir / "config.json"
    try:
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(config_dir, 0o700)
        config = {}
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.loads(f.read())
            except (json.JSONDecodeError, OSError):
                config = {}
        config['api_key'] = api_key
        if urls:
            config.update({k: v for k, v in urls.items() if v})
        fd = os.open(str(config_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(config, indent=2))
        return True
    except Exception as e:
        print(f"⚠️  Could not write config: {e}")
        return False


def download_file(url: str, dest_path: Path) -> bool:
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        debug_print(f"Downloading {url} to {dest_path}")
        result = subprocess.run(
            ["curl", "-fsSL", "-o", str(dest_path), url],
            capture_output=True,
            timeout=30
        )
        if result.returncode == 0:
            debug_print(f"File downloaded successfully: {dest_path}")
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"❌ Failed to download {url}: {e}")
        return False


def rewrite_gateway_url_in_file(path: Path, gateway_url: str) -> None:
    """Replace the hardcoded default gateway URL inside a downloaded unbound.py
    so tenant deployments don't depend on the env var being set at runtime."""
    if not gateway_url or gateway_url == DEFAULT_GATEWAY_URL:
        return
    try:
        text = path.read_text(encoding="utf-8")
        new_text = text.replace(f'"{DEFAULT_GATEWAY_URL}"', f'"{gateway_url}"')
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    except Exception as e:
        debug_print(f"Could not rewrite gateway URL in {path}: {e}")


def setup_hooks(gateway_url: str = DEFAULT_GATEWAY_URL):
    hooks_dir = Path.home() / ".augment" / "hooks"
    script_path = hooks_dir / "unbound.py"

    if not download_file(SCRIPT_URL, script_path):
        return False
    rewrite_gateway_url_in_file(script_path, gateway_url)

    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
    except Exception as e:
        pass

    return True


def _hook_command_matches(existing_cmd: str, hook_command: str, script_path: Path, is_windows: bool) -> bool:
    """An existing hook entry is ours if its command matches exactly, or (on
    Windows, where it's wrapped in a `py -3 "..."` launcher) references our
    script path."""
    return existing_cmd == hook_command or (is_windows and bool(existing_cmd) and str(script_path) in existing_cmd)


def configure_augment_settings() -> bool:
    settings_path = Path.home() / ".augment" / "settings.json"

    try:
        if settings_path.exists():
            with open(settings_path, 'r', encoding='utf-8') as f:
                settings = json.load(f)
        else:
            settings = {}
            settings_path.parent.mkdir(parents=True, exist_ok=True)

        if not isinstance(settings, dict):
            settings = {}

        script_path = Path.home() / ".augment" / "hooks" / "unbound.py"

        # On Windows, invoke via the launcher and quote the path (handles spaces
        # like C:\Users\Jane Doe\ or C:\Program Files\). Use `py -3` if present,
        # falling back to `python`. Set "shell": "powershell" so the quoted
        # command parses right.
        is_windows = platform.system().lower() == "windows"
        if is_windows:
            launcher = "py -3" if shutil.which("py") else "python"
            hook_command = f'{launcher} "{script_path}"'
            extra = {"shell": "powershell"}
        else:
            hook_command = str(script_path)
            extra = None

        hooks_config = build_hooks_block(hook_command, extra=extra)

        if "hooks" not in settings or not isinstance(settings.get("hooks"), dict):
            settings["hooks"] = {}

        for event, new_config in hooks_config.items():
            if event in settings["hooks"] and isinstance(settings["hooks"][event], list):
                existing_config = settings["hooks"][event]

                our_hook_exists = False
                for existing_item in existing_config:
                    if isinstance(existing_item, dict):
                        for hook in existing_item.get("hooks", []):
                            if _hook_command_matches(hook.get("command", ""), hook_command, script_path, is_windows):
                                our_hook_exists = True
                                break

                if not our_hook_exists:
                    settings["hooks"][event].extend(new_config)
            elif event not in settings["hooks"]:
                settings["hooks"][event] = new_config
            # A foreign non-list hooks[event] is left untouched — never clobber an
            # org's own Augment config in the shared settings file.

        # Merge toolPermissions, preserving any foreign rules. Match on our rule
        # identity (toolName + shellInputRegex) so re-running never duplicates.
        existing_perms = settings.get("toolPermissions")
        if not isinstance(existing_perms, list):
            existing_perms = []
        existing_identities = {_tool_permission_identity(r) for r in existing_perms if isinstance(r, dict)}
        for rule in build_tool_permissions_block():
            if _tool_permission_identity(rule) not in existing_identities:
                existing_perms.append(rule)
                existing_identities.add(_tool_permission_identity(rule))
        settings["toolPermissions"] = existing_perms

        with open(settings_path, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)

        return True

    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse existing settings.json: {e}")
        print("   Please check your settings.json file for syntax errors")
        return False
    except Exception as e:
        print(f"❌ Failed to configure settings: {e}")
        return False


def remove_hooks_from_settings() -> str:
    """Remove our hook entries AND our toolPermissions rules from
    ~/.augment/settings.json, preserving foreign hooks and foreign rules.

    Returns "cleared", "not_found", or "failed".
    """
    settings_path = Path.home() / ".augment" / "settings.json"
    script_path = Path.home() / ".augment" / "hooks" / "unbound.py"
    hook_command = str(script_path)
    is_windows = platform.system().lower() == "windows"

    if not settings_path.exists():
        return "not_found"

    def _is_unbound(cmd: str) -> bool:
        return _hook_command_matches(cmd, hook_command, script_path, is_windows)

    try:
        with open(settings_path, 'r', encoding='utf-8') as f:
            settings = json.load(f)
        if not isinstance(settings, dict):
            return "not_found"

        modified = False

        hooks_block = settings.get("hooks")
        if isinstance(hooks_block, dict):
            for event in list(hooks_block.keys()):
                event_config = hooks_block[event]
                if not isinstance(event_config, list):
                    continue
                new_config = []
                for item in event_config:
                    if isinstance(item, dict):
                        hooks = item.get("hooks", [])
                        new_hooks = [h for h in hooks if not _is_unbound(h.get("command", ""))]
                        if new_hooks != hooks:
                            modified = True
                            debug_print(f"Removed unbound hook from {event}")
                        if new_hooks:
                            item["hooks"] = new_hooks
                            new_config.append(item)
                    else:
                        new_config.append(item)
                if new_config:
                    hooks_block[event] = new_config
                else:
                    del hooks_block[event]
                    modified = True
            if not hooks_block:
                del settings["hooks"]

        # Strip our toolPermissions rules, preserving foreign ones.
        perms = settings.get("toolPermissions")
        if isinstance(perms, list):
            new_perms = [
                r for r in perms
                if not (isinstance(r, dict) and _tool_permission_identity(r) in _OUR_TOOL_PERMISSION_IDENTITIES)
            ]
            if len(new_perms) != len(perms):
                modified = True
                debug_print("Removed unbound toolPermissions rules")
            if new_perms:
                settings["toolPermissions"] = new_perms
            else:
                del settings["toolPermissions"]

        if modified:
            with open(settings_path, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2)
            return "cleared"
        return "not_found"
    except Exception as e:
        print(f"Failed to update settings.json: {e}")
        return "failed"


def _clear_path(path: Path, label: str) -> str:
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
    """Undo all changes made by the setup script."""
    print("=" * 60)
    print("Augment Code Hooks - Clearing Setup")
    print("=" * 60)

    any_cleared = False
    any_failed = False

    status, _ = remove_env_var("UNBOUND_AUGMENT_API_KEY")
    if status == "cleared":
        any_cleared = True
    elif status not in ("cleared", "not_found"):
        print("Failed to clear API_KEY")
        any_failed = True

    _r = _clear_path(Path.home() / ".augment" / "hooks" / "unbound.py", "Augment unbound.py hook")
    if _r == "cleared":
        any_cleared = True
    elif _r == "failed":
        any_failed = True

    for extra in (
        Path.home() / ".augment" / "hooks" / "unbound-setup.py",
        Path.home() / ".augment" / "hooks" / ".last_updated",
    ):
        _r = _clear_path(extra, str(extra))
        if _r == "cleared":
            any_cleared = True
        elif _r == "failed":
            any_failed = True

    settings_status = remove_hooks_from_settings()
    if settings_status == "cleared":
        any_cleared = True
    elif settings_status == "failed":
        print("Failed to clear Unbound hooks in settings.json")
        any_failed = True

    if any_cleared:
        print("Cleared")
    elif not any_failed:
        print("API_KEY not set, nothing to clear")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def get_device_identifier() -> Optional[str]:
    system = platform.system().lower()
    try:
        if system == "darwin":
            # ioreg's IOPlatformSerialNumber key is locale-stable; system_profiler's
            # "Serial Number" label is localized and fails on non-English macOS.
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'IOPlatformSerialNumber' in line:
                        parts = line.split('=')
                        if len(parts) >= 2:
                            serial = parts[1].strip().strip('"').strip()
                            if serial:
                                return serial
            return None

        elif system == "linux":
            try:
                result = subprocess.run(
                    ["dmidecode", "-s", "system-serial-number"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    stderr=subprocess.DEVNULL
                )
                if result.returncode == 0:
                    device_id = result.stdout.strip()
                    if device_id:
                        return device_id
            except Exception:
                debug_print("dmidecode failed, trying machine-id")

            for machine_id_path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
                try:
                    with open(machine_id_path, 'r', encoding='utf-8') as f:
                        device_id = f.read().strip()
                        if device_id:
                            return device_id
                except Exception:
                    continue

            try:
                result = subprocess.run(
                    ["hostname"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    hostname = result.stdout.strip()
                    if hostname:
                        return hostname
            except Exception:
                pass

            return None

        elif system == "windows":
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    serial = result.stdout.strip()
                    if serial:
                        return serial
            except Exception:
                debug_print("PowerShell BIOS query failed, trying registry MachineGuid")

            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Cryptography") as key:
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if value:
                        return str(value).strip()
            except Exception:
                debug_print("MachineGuid registry read failed, falling back to hostname")

            try:
                import socket
                return socket.gethostname()
            except Exception:
                return None

    except Exception as e:
        debug_print(f"Failed to get device identifier: {e}")
        return None


def detect_install_state() -> str:
    """User-level install state (informational): 'persisted' if this tool's
    Unbound setup already exists on this device, else 'fresh'. User-level setups
    are never tamper-eligible, so 'tampered' is never reported."""
    try:
        return "persisted" if (Path.home() / ".augment" / "hooks" / "unbound.py").exists() else "fresh"
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return "fresh"


def get_managed_settings_dir() -> Path:
    """System-wide managed (MDM) settings directory for Augment. Mirrors the path
    the MDM setup writes to; keep this in sync with mdm/setup.py."""
    system = platform.system().lower()
    if system in ("darwin", "linux"):
        return Path("/etc/augment")
    elif system == "windows":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "Augment"
    raise OSError(f"Unsupported operating system: {system}")


def _managed_settings_has_our_hook(managed_dir: Path) -> bool:
    """True if /etc/augment/settings.json contains a hook command pointing at OUR
    managed script (managed_dir/hooks/unbound.py). Distinguishes an Unbound MDM
    install from the org's OWN Augment managed config (a foreign settings.json
    without our marker). Raises on read/parse failure so the caller fails closed."""
    settings_path = managed_dir / "settings.json"
    if not settings_path.exists():
        return False
    our_script = str(managed_dir / "hooks" / "unbound.py")
    # Our managed hook command always embeds the managed script path (bare or
    # launcher-wrapped). A substring check over the serialized hooks block is
    # marker-specific and immune to the exact command form. Let exceptions
    # (read/JSON errors) propagate so check_enterprise_hooks_conflict fails closed.
    with open(settings_path, "r", encoding="utf-8") as f:
        settings = json.load(f)
    hooks_block = settings.get("hooks") if isinstance(settings, dict) else None
    if not isinstance(hooks_block, dict):
        return False
    return our_script in json.dumps(hooks_block)


def check_enterprise_hooks_conflict() -> bool:
    """True if an Unbound MDM (managed) setup already exists for Augment on this
    device. User-level setup must not run alongside it — the managed config
    already enforces Unbound for every user, so a second user-level install would
    make every hook fire twice. Read-only.

    Detects OUR marker specifically: the managed hook script
    /etc/augment/hooks/unbound.py exists, OR our hook command appears in
    /etc/augment/settings.json's hooks. A FOREIGN /etc/augment/settings.json (the
    org's own Augment managed config, without our marker) is NOT a conflict — the
    user-level install must proceed there.

    Fails CLOSED: on a stat/read/parse exception we cannot prove the box is
    unmanaged, so we assume managed (return True). On a shared host a false
    'unmanaged' would let managed + user hooks both fire (double-deny /
    double-audit); the per-user main() then raises SystemExit(3) and skips, which
    is the safe outcome."""
    try:
        managed_dir = get_managed_settings_dir()
        if (managed_dir / "hooks" / "unbound.py").exists():
            return True
        return _managed_settings_has_our_hook(managed_dir)
    except Exception as e:
        print(f"Warning: could not check for an MDM install ({e!r}); assuming managed and skipping user-level setup.")
        return True


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = "https://backend.getunbound.ai", install_state: Optional[str] = None, serial_number: Optional[str] = None):
    """Notify backend that tool setup completed. Never fails the setup."""
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        body = {"tool_type": tool_type}
        if install_state is not None:
            body["install_state"] = install_state
        if serial_number is not None:
            body["serial_number"] = serial_number
        data = json.dumps(body)
        # X-API-KEY off-argv via 0600 temp header file; body off-argv via stdin.
        curl_with_auth(
            [f"X-API-KEY: {api_key}"],
            ["-fsSL", "-X", "POST",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-", url],
            input=data.encode(),
            timeout=10,
        )
        debug_print("Setup completion notification sent")
    except Exception as e:
        debug_print(f"Could not notify backend: {e}")


def main():
    global DEBUG

    # Parse arguments
    clear_mode = "--clear" in sys.argv
    debug_mode = "--debug" in sys.argv

    if debug_mode:
        DEBUG = True
        debug_print("Debug mode enabled")

    if "--backfill" in sys.argv:
        print("[backfill] Augment backfill is not supported.")

    if clear_mode:
        clear_setup()
        return True

    if check_enterprise_hooks_conflict():
        print("\n❌ Skipped — Augment is managed by your organization (MDM).")
        raise SystemExit(3)

    install_macos_certificates()

    print("=" * 60)
    print("Augment Code Setup for Unbound Gateway")
    print("=" * 60)

    domain = None
    for i, arg in enumerate(sys.argv):
        if arg == "--domain" and i + 1 < len(sys.argv):
            domain = sys.argv[i + 1]
            break

    backend_url = "https://backend.getunbound.ai"
    for i, arg in enumerate(sys.argv):
        if arg == "--backend-url" and i + 1 < len(sys.argv):
            backend_url = normalize_url(sys.argv[i + 1])
            break

    gateway_url = DEFAULT_GATEWAY_URL
    for i, arg in enumerate(sys.argv):
        if arg == "--gateway-url" and i + 1 < len(sys.argv):
            gateway_url = normalize_url(sys.argv[i + 1])
            break

    api_key_arg = None
    for i, arg in enumerate(sys.argv):
        if arg == "--api-key" and i + 1 < len(sys.argv):
            api_key_arg = sys.argv[i + 1]
            break

    api_key = api_key_arg
    if not api_key:
        if not domain:
            print("❌ Missing required argument: --domain or --api-key")
            return False

        auth_url = normalize_url(domain)

        cb_response = run_callback_server(auth_url)
        if cb_response is None:
            print("❌ Failed to receive callback. Exiting.")
            return False

        try:
            api_key = (cb_response.get("query") or {}).get("api_key")
        except Exception:
            pass

        if not api_key:
            error_msg = (cb_response.get("query") or {}).get("error")
            if error_msg:
                safe_error = re.sub(r'[\x00-\x1f\x7f]', '', error_msg)[:200]
                print(f"❌ Setup failed: {safe_error}")
            else:
                print("❌ No API key received. Exiting.")
            return False

    debug_print("API key received from callback")

    debug_print("Setting UNBOUND_AUGMENT_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_AUGMENT_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return False
    debug_print("UNBOUND_AUGMENT_API_KEY set successfully")

    _install_state = detect_install_state()
    _device_id = get_device_identifier()

    write_unbound_config(api_key, urls={"base_url": backend_url, "gateway_url": gateway_url, "frontend_url": normalize_url(domain) if domain else None})

    debug_print("Setting up hooks...")
    if not setup_hooks(gateway_url=gateway_url):
        print("❌ Failed to setup hooks")
        return False
    debug_print("Hooks downloaded successfully")

    debug_print("Configuring Augment settings...")
    if not configure_augment_settings():
        print("❌ Failed to configure Augment settings")
        return False
    debug_print("Augment settings configured successfully")

    print("✅ API key verified and added")
    print("✅ Setup complete")
    print("=" * 60)

    notify_setup_complete(api_key, "augment_code", backend_url=backend_url, install_state=_install_state, serial_number=_device_id)

    rc_path = get_shell_rc_file()
    if rc_path is not None:
        print(f"\nTo apply changes in your current terminal, run:\n  source {rc_path}\n\nOr open a new terminal.")

    return True


if __name__ == "__main__":
    try:
        ok = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    sys.exit(0 if ok else 1)
