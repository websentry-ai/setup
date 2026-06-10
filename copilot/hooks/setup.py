#!/usr/bin/env python3

import os
import sys
import platform
import shutil
import subprocess
import urllib.parse
import urllib.request
import urllib.error
import time
import webbrowser
from pathlib import Path
from typing import Tuple, Optional, Dict, List
import threading
import http.server
import socketserver
import socket
import json

SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/copilot/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"

BACKFILL_CHUNK_BYTES = 14 * 1024 * 1024
BACKFILL_TOOL_TYPE = "copilot"
BACKFILL_MAX_FILE_BYTES = 50 * 1024 * 1024
BACKFILL_MAX_LINES_PER_FILE = 50000
BACKFILL_MAX_SESSIONS_PER_RUN = 5000
BACKFILL_MAX_AGE_DAYS = 30
BACKFILL_STATE_FILE = '.unbound_last_backfill'

DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def install_macos_certificates():
    """Run Python certificate installation command on macOS."""
    if platform.system().lower() != "darwin":
        return
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    cert_path = f"/Applications/Python {py_version}/Install Certificates.command"
    if os.path.exists(cert_path):
        subprocess.run([cert_path], capture_output=True)


def normalize_url(domain: str) -> str:
    """Normalize domain to proper URL format."""
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

        # Remove existing export for this variable if var_name is provided
        if var_name:
            export_prefix = f"export {var_name}="
            lines = [l for l in lines if not l.strip().startswith(export_prefix)]

        # Check if line already exists
        if line + "\n" not in lines and line not in [l.rstrip() for l in lines]:
            lines.append(f"{line}\n")

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        # If we removed an old export and need to add new one
        if var_name:
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
        if success:
            debug_print(f"Environment variable {var_name} set on Windows")
        return (True, "Set for new terminals") if success else (False, "Failed")
    elif system in ["darwin", "linux"]:
        success = set_env_var_unix(var_name, value)
        if success:
            debug_print(f"Environment variable {var_name} added to shell rc file")
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
        target_url = f"{frontend_url.rstrip('/')}/automations/api-key-callback?callback_url={encoded_callback}&app_type=copilot"
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
        # Create with 0o600 atomically so the API key is never briefly world-readable.
        fd = os.open(str(config_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(config, indent=2))
        return True
    except Exception as e:
        print(f"⚠️  Could not write config: {e}")
        return False


def rewrite_gateway_url_in_file(path: Path, gateway_url: str) -> None:
    """Replace the hardcoded default gateway URL inside a downloaded unbound.py."""
    if not gateway_url or gateway_url == DEFAULT_GATEWAY_URL:
        return
    try:
        text = path.read_text(encoding="utf-8")
        new_text = text.replace(f'"{DEFAULT_GATEWAY_URL}"', f'"{gateway_url}"')
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    except Exception as e:
        print(f"⚠️  Could not rewrite gateway URL in {path}: {e}")


def setup_hooks(gateway_url: str = DEFAULT_GATEWAY_URL):
    hooks_dir = Path.home() / ".copilot" / "hooks"
    script_path = hooks_dir / "unbound.py"

    print("\n📥 Downloading unbound.py script...")
    if not download_file(SCRIPT_URL, script_path):
        return False
    print("✅ unbound.py downloaded")
    rewrite_gateway_url_in_file(script_path, gateway_url)

    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
        print("✅ Made unbound.py executable")
    except Exception as e:
        print(f"⚠️  Could not make script executable: {e}")

    return True


def _copilot_hooks_config(script_path: Path) -> dict:
    """Build the ~/.copilot/hooks/unbound.json config for the 5 Copilot events.
    Copilot delivers hook_event_name in the payload, so no per-event env is needed."""
    # Copilot reads `bash` on Unix, `powershell` on Windows. The Unix script is
    # chmod +x with a python3 shebang, so bash executes it directly. On Windows
    # invoke via `py -3` (falling back to `python`), quoting the path so spaces
    # in C:\Users\<name>\ paths don't break parsing.
    bash_cmd = f'"{script_path}"'
    launcher = "py -3" if shutil.which("py") else "python"
    powershell_cmd = f'{launcher} "{script_path}"'

    # Per-event timeout (seconds): PreToolUse is generous for approval polling.
    event_timeouts = {
        "SessionStart": 30,
        "UserPromptSubmit": 60,
        "PreToolUse": 600,
        "PostToolUse": 30,
        "Stop": 60,
    }

    hooks = {}
    for event_name, timeout_sec in event_timeouts.items():
        hooks[event_name] = [
            {
                "type": "command",
                "command": bash_cmd,
                "bash": bash_cmd,
                "powershell": powershell_cmd,
                "timeout": timeout_sec,
                "timeoutSec": timeout_sec,
            }
        ]

    return {"version": 1, "hooks": hooks}


def configure_copilot_hooks() -> bool:
    """Write ~/.copilot/hooks/unbound.json. Unbound owns this file and overwrites
    it wholesale; other *.json files in the directory are left untouched."""
    hooks_path = Path.home() / ".copilot" / "hooks" / "unbound.json"
    script_path = Path.home() / ".copilot" / "hooks" / "unbound.py"

    try:
        hooks_path.parent.mkdir(parents=True, exist_ok=True)
        config = _copilot_hooks_config(script_path)
        with open(hooks_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        print("✅ Copilot hooks configured")
        return True
    except Exception as e:
        print(f"❌ Failed to configure Copilot hooks: {e}")
        return False



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
    print("Unbound Copilot Hooks - Clearing Setup")
    print("=" * 60)

    any_cleared = False
    any_failed = False

    status, _ = remove_env_var("UNBOUND_COPILOT_API_KEY")
    if status == "cleared":
        any_cleared = True
    elif status not in ("cleared", "not_found"):
        print("Failed to clear API_KEY")
        any_failed = True

    _r = _clear_path(Path.home() / ".copilot" / "hooks" / "unbound.py", "Copilot unbound.py hook")
    if _r == "cleared":
        any_cleared = True
    elif _r == "failed":
        any_failed = True
    _r = _clear_path(Path.home() / ".copilot" / "hooks" / "unbound.json", "Copilot unbound.json hooks config")
    if _r == "cleared":
        any_cleared = True
    elif _r == "failed":
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
        return "persisted" if (Path.home() / ".copilot" / "hooks" / "unbound.py").exists() else "fresh"
    except Exception as e:
        debug_print(f"detect_install_state failed: {e}")
        return "fresh"


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
        subprocess.run(
            ["curl", "-fsSL", "-X", "POST",
             "-H", f"X-API-KEY: {api_key}",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-", url],
            input=data.encode(),
            capture_output=True,
            timeout=10,
        )
        debug_print("Setup completion notification sent")
    except Exception as e:
        debug_print(f"Could not notify backend: {e}")


def _backfill_session_id_from_path(transcript_path: Path) -> Optional[str]:
    # CLI: ~/.copilot/session-state/<id>/events.jsonl → parent dir name.
    # VS Code: .../GitHub.copilot-chat/transcripts/<id>.jsonl → file stem.
    name = transcript_path.parent.name if transcript_path.stem == 'events' else transcript_path.stem
    return name or None


def _backfill_collect_session(transcript_path: Path) -> Optional[Dict]:
    """Read a transcript and return {session_id, entries} for server-side parsing.
    The client only JSON-decodes lines and resolves a session id (preferring the
    session.start payload, falling back to the path). All semantic parsing
    happens server-side in webapp.services.coding_tools_backfill_service."""
    entries = []
    session_id = None
    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for lineno, line in enumerate(f):
                if lineno >= BACKFILL_MAX_LINES_PER_FILE:
                    break
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                entries.append(entry)
                if not session_id and isinstance(entry, dict):
                    if entry.get('type') == 'session.start':
                        sid = (entry.get('data') or {}).get('sessionId')
                        if sid:
                            session_id = sid
    except (OSError, UnicodeDecodeError):
        return None
    except Exception:
        return None

    if not session_id:
        session_id = _backfill_session_id_from_path(transcript_path)

    if not session_id or not entries:
        return None
    return {'session_id': session_id, 'entries': entries}


def _backfill_edr_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    # Stable, identifiable UA + ops headers so SOC tooling can whitelist by signature.
    headers = {
        'User-Agent': f'Unbound-Setup/{BACKFILL_TOOL_TYPE}-backfill ({platform.platform()})',
        'X-Unbound-Operation': 'backfill',
        'X-Unbound-Tool': BACKFILL_TOOL_TYPE,
    }
    if extra:
        headers.update(extra)
    return headers


def _backfill_http_request(url: str, method: str, headers: Dict[str, str], body: Optional[bytes] = None, timeout: int = 30) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        try:
            error_body = e.read()
        except Exception:
            error_body = b''
        return e.code, error_body
    except (urllib.error.URLError, OSError) as e:
        debug_print(f"HTTP request failed: {e}")
        return 0, b''


def _backfill_upload_chunk(api_key: str, backend_url: str, sessions: List[Dict]) -> bool:
    payload_bytes = json.dumps({'tool_type': BACKFILL_TOOL_TYPE, 'sessions': sessions}).encode('utf-8')

    auth_headers = _backfill_edr_headers({
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
    })

    code, body = _backfill_http_request(
        f"{backend_url.rstrip('/')}/api/v1/coding-tools/backfill/upload-url/",
        method='POST',
        headers=auth_headers,
        body=json.dumps({'tool_type': BACKFILL_TOOL_TYPE}).encode('utf-8'),
        timeout=30,
    )
    if code < 200 or code >= 300:
        debug_print(f"upload-url request failed: HTTP {code}")
        return False
    try:
        url_resp = json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        debug_print("upload-url response was not JSON")
        return False

    upload_url = url_resp.get('upload_url')
    object_key = url_resp.get('object_key')
    if not upload_url or not object_key:
        debug_print("upload-url response missing fields")
        return False

    code, _ = _backfill_http_request(
        upload_url,
        method='PUT',
        headers=_backfill_edr_headers({'Content-Type': 'application/json'}),
        body=payload_bytes,
        timeout=30,
    )
    if code < 200 or code >= 300:
        debug_print(f"S3 PUT failed: HTTP {code}")
        return False

    code, _ = _backfill_http_request(
        f"{backend_url.rstrip('/')}/api/v1/coding-tools/backfill/from-s3/",
        method='POST',
        headers=auth_headers,
        body=json.dumps({'tool_type': BACKFILL_TOOL_TYPE, 'object_key': object_key}).encode('utf-8'),
        timeout=30,
    )
    if code < 200 or code >= 300:
        debug_print(f"from-s3 request failed: HTTP {code}")
        return False

    return True


def _backfill_vscode_workspace_roots() -> List[Path]:
    # VS Code stores Copilot transcripts under workspaceStorage; the base differs
    # by OS and by stable/Insiders build.
    home = Path.home()
    system = platform.system().lower()
    bases: List[Path] = []
    editors = ('Code', 'Code - Insiders')
    if system == 'darwin':
        for editor in editors:
            bases.append(home / 'Library' / 'Application Support' / editor / 'User' / 'workspaceStorage')
    elif system == 'windows':
        # Fall back to the conventional Roaming path when APPDATA is unset
        # (service accounts / stripped environments) so VS Code transcripts
        # aren't silently skipped.
        appdata = os.environ.get('APPDATA')
        appdata_dir = Path(appdata) if appdata else (home / 'AppData' / 'Roaming')
        for editor in editors:
            bases.append(appdata_dir / editor / 'User' / 'workspaceStorage')
    else:
        for editor in editors:
            bases.append(home / '.config' / editor / 'User' / 'workspaceStorage')
    return bases


def _backfill_state_path(home: Path) -> Path:
    return home / '.copilot' / 'hooks' / BACKFILL_STATE_FILE


def _backfill_read_cutoff(home: Path) -> float:
    """mtime cutoff for transcript selection: the last successful backfill when
    cached (so cron reruns only seed sessions touched since), else 30 days ago."""
    default_cutoff = time.time() - (BACKFILL_MAX_AGE_DAYS * 86400)
    try:
        last = float(_backfill_state_path(home).read_text().strip())
    except (OSError, ValueError):
        return default_cutoff
    # Ignore corrupt or future timestamps (clock skew).
    if last <= 0 or last > time.time():
        return default_cutoff
    return last


def _backfill_write_cutoff(home: Path, ts: float) -> None:
    # Write via temp + atomic replace so an overlapping cron run never reads a
    # half-written timestamp.
    try:
        path = _backfill_state_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / f'{path.name}.{os.getpid()}.tmp'
        tmp.write_text(str(ts))
        os.replace(tmp, path)
    except OSError as e:
        debug_print(f"failed to persist backfill timestamp: {e}")


def _backfill_should_include(p: Path, cutoff_mtime: float) -> bool:
    # Skip hidden, symlinked, oversized (50MB cap), or stale (>30 day) files.
    if p.name.startswith('.'):
        return False
    if not p.is_file() or p.is_symlink():
        return False
    try:
        st = p.stat()
        if st.st_size > BACKFILL_MAX_FILE_BYTES:
            return False
        if st.st_mtime < cutoff_mtime:
            return False
    except OSError:
        return False
    return True


def _backfill_iter_transcripts(cutoff_mtime: float):
    cli_root = Path.home() / '.copilot' / 'session-state'
    if cli_root.exists():
        for p in cli_root.glob('*/events.jsonl'):
            if _backfill_should_include(p, cutoff_mtime):
                yield p
    for base in _backfill_vscode_workspace_roots():
        if not base.exists():
            continue
        for p in base.glob('*/GitHub.copilot-chat/transcripts/*.jsonl'):
            if _backfill_should_include(p, cutoff_mtime):
                yield p


def _backfill_is_user_message(entry) -> bool:
    # Mirror server-side parse_copilot_session: a new exchange starts on a
    # user.message with non-empty data.content.
    if not isinstance(entry, dict) or entry.get('type') != 'user.message':
        return False
    content = (entry.get('data') or {}).get('content')
    return bool(content and str(content).strip())


def _backfill_exchange_boundaries(entries: List[Dict]) -> List[int]:
    return [i for i, entry in enumerate(entries) if _backfill_is_user_message(entry)]


def _backfill_slice_session(session: Dict, max_chunk_bytes: int):
    """Yield session payloads ≤ max_chunk_bytes. Sessions that already fit are
    yielded as-is. Oversized sessions are split at server-side exchange
    boundaries; each slice carries record_index_base = cumulative exchange
    count of all earlier slices so the server's per-record UUID5 seed stays
    globally stable per (org, tool, session, record_index)."""
    session_id = session.get('session_id')
    entries = session.get('entries') or []
    try:
        if len(json.dumps(session).encode('utf-8')) <= max_chunk_bytes:
            yield session
            return
        # +2 for the `, ` separator json.dumps puts between array elements.
        entry_sizes = [len(json.dumps(e).encode('utf-8')) + 2 for e in entries]
    except (TypeError, ValueError):
        debug_print(f"skipping unserializable session {session_id}")
        return

    boundaries = _backfill_exchange_boundaries(entries)
    n = len(entries)
    record_index_base = 0
    start_idx = 0
    while start_idx < n:
        ends = [b for b in boundaries if b > start_idx]
        if not ends or ends[-1] < n:
            ends.append(n)

        wrap = len(json.dumps({
            'session_id': session_id,
            'record_index_base': record_index_base,
            'entries': [],
        }).encode('utf-8'))
        cum = wrap
        cursor = start_idx
        last_fit_end = None
        last_fit_base_count = 0
        for end_idx in ends:
            cum += sum(entry_sizes[cursor:end_idx])
            cursor = end_idx
            # -2: last entry has no trailing `, ` and `[]` was counted in wrap.
            if cum - 2 > max_chunk_bytes:
                break
            last_fit_end = end_idx
            last_fit_base_count = sum(1 for b in boundaries if start_idx <= b < end_idx)

        if last_fit_end is None:
            debug_print(f"skipped session {session_id}: smallest exchange slice exceeds {max_chunk_bytes} bytes")
            return

        yield {
            'session_id': session_id,
            'record_index_base': record_index_base,
            'entries': entries[start_idx:last_fit_end],
        }
        record_index_base += last_fit_base_count
        start_idx = last_fit_end


def run_backfill(api_key: str, backend_url: str) -> None:
    """Walk Copilot CLI + VS Code transcripts and seed historical sessions. Never raises."""
    if os.environ.get('UNBOUND_BACKFILL_DISABLED') == '1':
        debug_print("UNBOUND_BACKFILL_DISABLED=1 — skipping backfill")
        return

    try:
        home = Path.home()
        started_at = time.time()
        cutoff_mtime = _backfill_read_cutoff(home)
        sessions: List[Dict] = []
        capped = False
        for transcript_path in sorted(_backfill_iter_transcripts(cutoff_mtime)):
            if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
                # Hit the per-run cap with files still unprocessed — don't advance
                # the cutoff, or those older files would be skipped permanently.
                capped = True
                debug_print(f"reached session cap {BACKFILL_MAX_SESSIONS_PER_RUN}; remaining skipped")
                break
            session = _backfill_collect_session(transcript_path)
            if session:
                sessions.append(session)
        if not sessions:
            _backfill_write_cutoff(home, started_at)
            print("[backfill] No past sessions found.")
            return

        print(f"[backfill] Found {len(sessions)} past sessions. Uploading (this may take a few minutes)...")

        chunks_total = 0
        chunks_sent = 0
        sessions_sent_ids: set = set()
        current_chunk: List[Dict] = []
        current_size = 2  # outer `[]`

        def _flush():
            nonlocal current_chunk, current_size, chunks_total, chunks_sent
            if not current_chunk:
                return
            chunks_total += 1
            if _backfill_upload_chunk(api_key, backend_url, current_chunk):
                chunks_sent += 1
                for s in current_chunk:
                    sessions_sent_ids.add(s.get('session_id'))
            current_chunk = []
            current_size = 2

        for session in sessions:
            for slice_session in _backfill_slice_session(session, BACKFILL_CHUNK_BYTES):
                try:
                    slice_bytes = len(json.dumps(slice_session).encode('utf-8'))
                except (TypeError, ValueError):
                    continue
                if slice_bytes > BACKFILL_CHUNK_BYTES:
                    continue
                if current_chunk and current_size + slice_bytes + 1 > BACKFILL_CHUNK_BYTES:
                    _flush()
                current_chunk.append(slice_session)
                current_size += slice_bytes + 1

        _flush()

        failed = chunks_total - chunks_sent
        sessions_sent = len(sessions_sent_ids)
        if sessions_sent == 0:
            print(f"[backfill] No sessions queued (all {chunks_total} uploads failed).")
        elif failed:
            print(f"[backfill] Done — queued {sessions_sent} past sessions ({failed} chunks failed).")
        else:
            if not capped:
                _backfill_write_cutoff(home, started_at)
            print(f"[backfill] Done — queued {sessions_sent} past sessions for processing.")
    except Exception as e:
        print(f"[backfill] Skipped due to error: {e}", file=sys.stderr)


def main():
    global DEBUG

    # Parse arguments
    clear_mode = "--clear" in sys.argv
    debug_mode = "--debug" in sys.argv
    backfill_mode = "--backfill" in sys.argv

    if debug_mode:
        DEBUG = True
        debug_print("Debug mode enabled")

    if clear_mode:
        clear_setup()
        return

    install_macos_certificates()

    print("=" * 60)
    print("Unbound Copilot Hooks - Setup")
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
            print("\n❌ Missing required argument: --domain or --api-key")
            return

        auth_url = normalize_url(domain)

        cb_response = run_callback_server(auth_url)
        if cb_response is None:
            print("\n❌ Failed to receive callback. Exiting.")
            return

        try:
            api_key = (cb_response.get("query") or {}).get("api_key")
        except Exception:
            pass

        if not api_key:
            print("\n❌ No API key received. Exiting.")
            return

    print("✅ API key received")
    debug_print("API key received from callback")

    _install_state = detect_install_state()
    _device_id = get_device_identifier()

    if not write_unbound_config(api_key, urls={"base_url": backend_url, "gateway_url": gateway_url, "frontend_url": normalize_url(domain) if domain else None}):
        print("⚠️  Could not write ~/.unbound/config.json — hooks may not work when Copilot is launched from Dock/Spotlight")

    debug_print("Setting UNBOUND_COPILOT_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_COPILOT_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return

    print(f"✅ Environment variable set")
    debug_print("UNBOUND_COPILOT_API_KEY set successfully")

    debug_print("Setting up hooks...")
    if not setup_hooks(gateway_url=gateway_url):
        print("\n❌ Failed to setup hooks")
        return
    debug_print("Hooks setup complete")

    debug_print("Configuring Copilot hooks...")
    if not configure_copilot_hooks():
        print("\n❌ Failed to configure Copilot hooks")
        return
    debug_print("Copilot hooks configured")

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(api_key, "copilot", backend_url=backend_url, install_state=_install_state, serial_number=_device_id)

    if backfill_mode:
        run_backfill(api_key, backend_url)

    rc_path = get_shell_rc_file()
    if rc_path is not None:
        print(f"\nTo apply changes in your current terminal, run:\n  source {rc_path}\n\nOr open a new terminal.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        exit(1)
