
#!/usr/bin/env python3

import os
import re
import shutil
import sys
import time
import platform
import subprocess
import urllib.parse
import urllib.request
import urllib.error
import webbrowser
from pathlib import Path
from typing import Tuple, Optional, Dict, List
import threading
import http.server
import socketserver
import socket
import json


SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/unbound.py"
DEFAULT_GATEWAY_URL = "https://api.getunbound.ai"


AUTO_UPDATE_SH_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/unbound-auto-update.sh"
SETUP_SELF_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/setup.py"
AUTO_UPDATE_TTL_SECONDS = 2 * 60 * 60
BACKFILL_CHUNK_BYTES = 14 * 1024 * 1024
BACKFILL_TOOL_TYPE = "codex"
BACKFILL_MAX_FILE_BYTES = 50 * 1024 * 1024
BACKFILL_MAX_LINES_PER_FILE = 50000
BACKFILL_MAX_SESSIONS_PER_RUN = 5000
BACKFILL_MAX_AGE_DAYS = 30
ROLLOUT_FILENAME_RE = re.compile(
    r'^rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$'
)

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
        print(f"Failed to modify {file_path}: {e}")
        return False


def set_env_var_windows(var_name: str, value: str) -> bool:
    debug_print(f"Writing to user environment registry (Windows)")
    try:
        subprocess.run(["setx", var_name, value], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Failed to set {var_name} on Windows: {e}")
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


def remove_env_var_on_unix(var_name: str) -> bool:
    """
    Remove an environment variable export line from the user's shell rc file.
    """
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False
    try:
        rc_file.touch(exist_ok=True)
        with open(rc_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = []
        removed = False
        export_prefix = f"export {var_name}="
        for line in lines:
            if line.strip().startswith(export_prefix):
                removed = True
                continue
            new_lines.append(line)
        if removed:
            with open(rc_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        return True
    except Exception as e:
        print(f"Failed to modify {rc_file}: {e}")
        return False


def remove_env_var_on_windows(var_name: str) -> bool:
    """
    Remove a user environment variable on Windows by deleting it from HKCU\\Environment.
    """
    try:
        subprocess.run(["reg", "delete", "HKCU\\Environment", "/F", "/V", var_name], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        # If it doesn't exist, treat as success
        return True
    except FileNotFoundError:
        print("'reg' command not found. Please remove the variable manually.")
        return False


def remove_env_var(var_name: str) -> Tuple[bool, str]:
    """
    Remove an environment variable permanently across OS platforms.
    """
    system = platform.system().lower()
    if system == "windows":
        success = remove_env_var_on_windows(var_name)
        if success:
            debug_print(f"Removed {var_name} from Windows registry")
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    elif system in ["darwin", "linux"]:
        success = remove_env_var_on_unix(var_name)
        if success:
            debug_print(f"Removed {var_name} from shell rc file")
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    else:
        return False, f"Unsupported OS: {system}"


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
        target_url = f"{frontend_url.rstrip('/')}/automations/api-key-callback?callback_url={encoded_callback}&app_type=codex"
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


def write_unbound_config(api_key: str) -> bool:
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
        fd = os.open(str(config_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(config, indent=2))
        return True
    except Exception as e:
        print(f"Could not write config: {e}")
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
        print(f"Failed to download {url}: {e}")
        return False


def remove_gateway_artifacts() -> None:
    """Remove OPENAI_API_KEY env var and openai_base_url from ~/.codex/config.toml (leftover from gateway setup)."""
    # Remove OPENAI_API_KEY env var
    try:
        remove_env_var("OPENAI_API_KEY")
        debug_print("Removed OPENAI_API_KEY env var")
    except Exception as e:
        debug_print(f"Failed to remove OPENAI_API_KEY: {e}")

    # Remove openai_base_url from config.toml
    config_path = Path.home() / ".codex" / "config.toml"
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            new_lines = [l for l in lines if not l.strip().startswith('openai_base_url')]
            if len(new_lines) != len(lines):
                with open(config_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                debug_print(f"Removed openai_base_url from {config_path}")
        except Exception as e:
            debug_print(f"Failed to update {config_path}: {e}")


def rewrite_gateway_url_in_file(path: Path, gateway_url: str) -> None:
    """Replace the hardcoded default gateway URL inside a downloaded unbound.py."""
    if not gateway_url or gateway_url == DEFAULT_GATEWAY_URL:
        return
    try:
        text = path.read_text(encoding="utf-8")
        new_text = text.replace(f'"{DEFAULT_GATEWAY_URL}"', f'"{gateway_url}"')
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    except Exception:
        pass


def setup_hooks(gateway_url: str = DEFAULT_GATEWAY_URL):
    hooks_dir = Path.home() / ".codex" / "hooks"
    script_path = hooks_dir / "unbound.py"

    if not download_file(SCRIPT_URL, script_path):
        return False
    rewrite_gateway_url_in_file(script_path, gateway_url)

    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
    except Exception:
        pass

    install_auto_update_assets(hooks_dir)
    return True


def configure_codex_hooks() -> bool:
    hooks_path = Path.home() / ".codex" / "hooks.json"

    try:
        if hooks_path.exists():
            with open(hooks_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            config = {}
            hooks_path.parent.mkdir(parents=True, exist_ok=True)

        script_path = Path.home() / ".codex" / "hooks" / "unbound.py"
        is_windows = platform.system().lower() == "windows"

        # On Windows, invoke via `py -3` (falling back to `python`) and quote
        # the path so spaces in C:\Users\<name>\ paths don't break parsing.
        if is_windows:
            launcher = "py -3" if shutil.which("py") else "python"
            hook_command = f'{launcher} "{script_path}"'
        else:
            hook_command = str(script_path)

        hooks_config = {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 15000
                        }
                    ]
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "UserPromptSubmit": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                },
            {
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "command": str(Path.home() / ".codex/hooks" / "unbound-auto-update.sh")
                    }
                ]
            }
            ]
        }

        if "hooks" not in config:
            config["hooks"] = {}

        for event, new_config in hooks_config.items():
            if event in config["hooks"]:
                existing_config = config["hooks"][event]

                our_hook_exists = False
                for existing_item in existing_config:
                    if isinstance(existing_item, dict):
                        existing_hooks = existing_item.get("hooks", [])
                        for hook in existing_hooks:
                            existing_cmd = hook.get("command", "")
                            # Exact match handles every OS; on Windows also
                            # match the "py -3 ..." launcher form.
                            if existing_cmd == hook_command or (is_windows and str(script_path) in existing_cmd):
                                our_hook_exists = True
                                break

                if not our_hook_exists:
                    config["hooks"][event].extend(new_config)
            else:
                config["hooks"][event] = new_config
        # Ensure auto-update SessionStart entry is present (idempotent).
        # The dedup-by-unbound.py merge above can skip adding new sibling
        # entries when the runtime hook is already registered.
        _auto_path = str(Path.home() / ".codex/hooks" / "unbound-auto-update.sh")
        _ss = config.setdefault("hooks", {}).setdefault("SessionStart", [])
        _has_auto = any(
            any(h.get("command") == _auto_path for h in (e.get("hooks", []) if isinstance(e, dict) else []))
            for e in _ss
        )
        if not _has_auto:
            _ss.append({"matcher": "", "hooks": [{"type": "command", "command": _auto_path}]})


        with open(hooks_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        return True

    except json.JSONDecodeError as e:
        print(f"Failed to parse existing hooks.json: {e}")
        print("   Please check your hooks.json file for syntax errors")
        return False
    except Exception as e:
        print(f"Failed to configure hooks: {e}")
        return False


def remove_hooks_from_config() -> None:
    """Remove the unbound hooks from hooks.json."""
    hooks_path = Path.home() / ".codex" / "hooks.json"
    hook_command = str(Path.home() / ".codex" / "hooks" / "unbound.py")
    is_windows = platform.system().lower() == "windows"

    if not hooks_path.exists():
        return

    def _is_unbound(cmd: str) -> bool:
        # Exact match on every OS; on Windows also match the "py -3 ..." form.
        return cmd == hook_command or (is_windows and bool(cmd) and hook_command in cmd)

    try:
        with open(hooks_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        if "hooks" not in config:
            return

        modified = False
        for event in list(config["hooks"].keys()):
            event_config = config["hooks"][event]
            new_config = []
            for item in event_config:
                if isinstance(item, dict):
                    hooks = item.get("hooks", [])
                    new_hooks = [h for h in hooks if not _is_unbound(h.get("command", ""))]
                    if new_hooks:
                        item["hooks"] = new_hooks
                        new_config.append(item)
                    elif hooks != new_hooks:
                        modified = True
                        debug_print(f"Removed unbound hook from {event}")
                else:
                    new_config.append(item)
            if new_config:
                config["hooks"][event] = new_config
            else:
                del config["hooks"][event]
                modified = True

        if not config["hooks"]:
            del config["hooks"]
            modified = True

        if modified:
            with open(hooks_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            print("Removed hooks from hooks.json")
    except Exception as e:
        print(f"Failed to update hooks.json: {e}")


def clear_setup() -> None:
    """Undo all changes made by the setup script."""
    print("=" * 60)
    print("Codex Hooks - Clearing Setup")
    print("=" * 60)

    # Remove environment variable
    success, _ = remove_env_var("UNBOUND_CODEX_API_KEY")
    if success:
        print("Removed UNBOUND_CODEX_API_KEY")
    else:
        print("Failed to remove UNBOUND_CODEX_API_KEY")

    # Remove the unbound.py script
    script_path = Path.home() / ".codex" / "hooks" / "unbound.py"
    if script_path.exists():
        try:
            script_path.unlink()
            debug_print(f"Removed {script_path}")
            print(f"Removed {script_path}")
        except Exception as e:
            print(f"Failed to remove {script_path}: {e}")

    # Remove hooks from hooks.json
    remove_hooks_from_config()

    # Remove codex_hooks feature flag
    disable_codex_hooks_feature()

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def enable_codex_hooks_feature() -> bool:
    """Enable the codex_hooks feature flag in ~/.codex/config.toml.
    If [features] section exists, adds the key under it.
    Otherwise appends a new [features] section at the end of the file."""
    config_path = Path.home() / ".codex" / "config.toml"
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

        # Check if already enabled
        content = ''.join(lines)
        if 'codex_hooks = true' in content:
            debug_print("codex_hooks feature flag already enabled")
            return True

        # Check if [features] section already exists
        features_idx = None
        for i, line in enumerate(lines):
            if line.strip() == '[features]':
                features_idx = i
                break

        if features_idx is not None:
            # Insert codex_hooks = true right after [features] header
            lines.insert(features_idx + 1, 'codex_hooks = true\n')
        else:
            # Append new [features] section at the end
            if lines and not lines[-1].endswith('\n'):
                lines.append('\n')
            lines.append('\n[features]\ncodex_hooks = true\n')

        with open(config_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)

        debug_print("Enabled codex_hooks feature flag in config.toml")
        return True
    except Exception as e:
        debug_print(f"Failed to enable codex_hooks feature: {e}")
        return False


def disable_codex_hooks_feature() -> None:
    """Remove only the codex_hooks line from ~/.codex/config.toml.
    Preserves the [features] section and any other flags within it."""
    config_path = Path.home() / ".codex" / "config.toml"
    if not config_path.exists():
        return
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        new_lines = [line for line in lines if not line.strip().startswith('codex_hooks')]
        if len(new_lines) != len(lines):
            with open(config_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            debug_print("Removed codex_hooks feature flag from config.toml")
    except Exception as e:
        debug_print(f"Failed to remove codex_hooks feature: {e}")


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = "https://backend.getunbound.ai"):
    """Notify backend that tool setup completed. Never fails the setup."""
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        data = json.dumps({"tool_type": tool_type})
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


def _backfill_session_id_from_filename(transcript_path: Path) -> Optional[str]:
    # Only `rollout-<isots>-<uuid>.jsonl` — never a generic stem fallback.
    m = ROLLOUT_FILENAME_RE.match(transcript_path.stem)
    return m.group(1) if m else None


def _backfill_collect_session(transcript_path: Path) -> Optional[Dict]:
    """Read a transcript and return {session_id, entries} for server-side parsing.
    The client only JSON-decodes lines and resolves a session id (preferring
    the session_meta payload, falling back to the rollout filename UUID). All
    semantic parsing happens server-side in
    webapp.services.coding_tools_backfill_service."""
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
                if not session_id:
                    sid = entry.get('sessionId') or entry.get('session_id')
                    payload = entry.get('payload')
                    if not sid and isinstance(payload, dict):
                        sid = payload.get('id') or payload.get('session_id')
                    if sid:
                        session_id = sid
    except (OSError, UnicodeDecodeError):
        return None
    except Exception:
        return None

    # session_meta absent → recover from rollout-<ts>-<uuid>.jsonl filename only;
    # never fall back to a generic stem.
    if not session_id:
        session_id = _backfill_session_id_from_filename(transcript_path)

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


def _backfill_iter_transcripts(root: Path):
    # Skip hidden, symlinked, oversized (50MB cap), or stale (>30 day) files.
    cutoff_mtime = time.time() - (BACKFILL_MAX_AGE_DAYS * 86400)
    for p in root.rglob('rollout-*.jsonl'):
        if p.name.startswith('.'):
            continue
        if not p.is_file() or p.is_symlink():
            continue
        try:
            st = p.stat()
            if st.st_size > BACKFILL_MAX_FILE_BYTES:
                continue
            if st.st_mtime < cutoff_mtime:
                continue
        except OSError:
            continue
        yield p


def _backfill_is_user_message_payload(payload) -> bool:
    # Mirror server-side parse_codex_session's user-message-start gate:
    # response_item with payload.type='message' role='user', non-empty joined
    # text, and not a Codex prelude (AGENTS.md / environment_context wrapper).
    if not isinstance(payload, dict):
        return False
    if payload.get('type') != 'message' or payload.get('role') != 'user':
        return False
    text_parts = []
    for c in payload.get('content') or []:
        if isinstance(c, dict):
            text = c.get('text') or c.get('content') or ''
            if isinstance(text, str) and text:
                text_parts.append(text)
    joined = '\n\n'.join(text_parts)
    if not joined:
        return False
    stripped = joined.lstrip()
    if stripped.startswith('# AGENTS.md') or stripped.startswith('<environment_context>'):
        return False
    return True


def _backfill_exchange_boundaries(entries: List[Dict]) -> List[int]:
    boundaries = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        if entry.get('type') != 'response_item':
            continue
        if _backfill_is_user_message_payload(entry.get('payload')):
            boundaries.append(i)
    return boundaries


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
    """Walk ~/.codex/sessions and seed historical sessions. Never raises."""
    if os.environ.get('UNBOUND_BACKFILL_DISABLED') == '1':
        debug_print("UNBOUND_BACKFILL_DISABLED=1 — skipping backfill")
        return

    try:
        sessions_root = Path.home() / '.codex' / 'sessions'
        sessions: List[Dict] = []
        if sessions_root.exists():
            for transcript_path in sorted(_backfill_iter_transcripts(sessions_root)):
                if len(sessions) >= BACKFILL_MAX_SESSIONS_PER_RUN:
                    debug_print(f"reached session cap {BACKFILL_MAX_SESSIONS_PER_RUN}; remaining skipped")
                    break
                session = _backfill_collect_session(transcript_path)
                if session:
                    sessions.append(session)
        if not sessions:
            print("[backfill] No past sessions found.")
            return

        print(f"[backfill] Found {len(sessions)} past sessions. Uploading (this may take a few minutes)...")

        chunks_total = 0
        chunks_sent = 0
        sessions_sent_ids: set = set()
        current_chunk: List[Dict] = []
        current_size = 2

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
            print(f"[backfill] Done — queued {sessions_sent} past sessions for processing.")
    except Exception as e:
        print(f"[backfill] Skipped due to error: {e}", file=sys.stderr)



def install_auto_update_assets(hooks_dir):
    """Drop the SessionStart shim + a local setup.py copy so the hook can
    re-run install on a 2h TTL without a fresh curl|python3.
    Prefers local sibling files (this checkout) over network download."""
    import shutil as _sh
    try:
        hooks_dir.mkdir(parents=True, exist_ok=True)
        shim_dest = hooks_dir / "unbound-auto-update.sh"
        setup_dest = hooks_dir / "unbound-setup.py"
        here = Path(__file__).resolve().parent
        shim_local = here / "unbound-auto-update.sh"
        setup_local = here / "setup.py"
        # When we run as the local copy (auto-update re-run), source == dest.
        # Skip the self-copy; the file is already in place.
        if shim_local.exists() and shim_local.resolve() != shim_dest.resolve():
            _sh.copyfile(shim_local, shim_dest)
        elif not shim_local.exists():
            download_file(AUTO_UPDATE_SH_URL, shim_dest)
        if shim_dest.exists():
            os.chmod(shim_dest, 0o755)
        if setup_local.exists() and setup_local.resolve() != setup_dest.resolve():
            _sh.copyfile(setup_local, setup_dest)
        elif not setup_local.exists():
            download_file(SETUP_SELF_URL, setup_dest)
        if setup_dest.exists():
            os.chmod(setup_dest, 0o755)
        cache = hooks_dir / ".unbound-auto-update"
        cache.touch()  # always stamp; this IS the success signal for the TTL gate
    except Exception as _e:
        try: debug_print(f"auto-update install skipped: {_e}")
        except Exception: pass

def auto_update_is_fresh(hooks_dir):
    import time as _t
    cache = hooks_dir / ".unbound-auto-update"
    try:
        return (_t.time() - cache.stat().st_mtime) < AUTO_UPDATE_TTL_SECONDS
    except Exception:
        return False


def touch_auto_update_cache(hooks_dir):
    try:
        hooks_dir.mkdir(parents=True, exist_ok=True)
        (hooks_dir / ".unbound-auto-update").touch()
    except Exception as _e:
        try: debug_print(f"auto-update touch failed: {_e}")
        except Exception: pass


def detach_to_background():
    """POSIX double-fork. Parent exits; child orphaned from host-app."""
    if os.environ.get("UNBOUND_DETACHED") == "1":
        return
    try:
        if os.fork() != 0:
            os._exit(0)
        os.setsid()
        if os.fork() != 0:
            os._exit(0)
        os.environ["UNBOUND_DETACHED"] = "1"
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            try: os.dup2(devnull, fd)
            except OSError: pass
    except Exception:
        pass


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


    if_stale = "--if-stale" in sys.argv
    background = "--background" in sys.argv

    # Auto-update entrypoint (SessionStart shim invokes us with both flags).
    # TTL gate exits cheapest; detach so the host-app hook returns fast.
    hooks_dir = Path.home() / ".codex/hooks"
    if if_stale and auto_update_is_fresh(hooks_dir):
        return
    if background:
        detach_to_background()
    install_macos_certificates()

    print("=" * 60)
    print("Codex Setup for Unbound Gateway")
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
            print("Missing required argument: --domain or --api-key")
            return

        auth_url = normalize_url(domain)

        cb_response = run_callback_server(auth_url)
        if cb_response is None:
            print("Failed to receive callback. Exiting.")
            return

        try:
            api_key = (cb_response.get("query") or {}).get("api_key")
        except Exception:
            pass

        if not api_key:
            error_msg = (cb_response.get("query") or {}).get("error")
            if error_msg:
                safe_error = re.sub(r'[\x00-\x1f\x7f]', '', error_msg)[:200]
                print(f"Setup failed: {safe_error}")
            else:
                print("No API key received. Exiting.")
            return

    debug_print("API key received from callback")

    # Remove gateway setup env vars and artifacts
    remove_gateway_artifacts()

    debug_print("Setting UNBOUND_CODEX_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_CODEX_API_KEY", api_key)
    if not success:
        print(f"Failed to set environment variable: {message}")
        return
    debug_print("UNBOUND_CODEX_API_KEY set successfully")

    write_unbound_config(api_key)

    debug_print("Setting up hooks...")
    if not setup_hooks(gateway_url=gateway_url):
        print("Failed to setup hooks")
        return
    debug_print("Hooks downloaded successfully")

    debug_print("Configuring Codex hooks...")
    if not configure_codex_hooks():
        print("Failed to configure Codex hooks")
        return
    debug_print("Codex hooks configured successfully")

    debug_print("Enabling codex_hooks feature flag...")
    enable_codex_hooks_feature()

    print("API key verified and added")
    print("Setup complete")
    print("=" * 60)

    notify_setup_complete(api_key, "codex", backend_url=backend_url)

    if backfill_mode:
        run_backfill(api_key, backend_url)

    rc_path = get_shell_rc_file()
    if rc_path is not None:
        print(f"\nTo apply changes in your current terminal, run:\n  source {rc_path}\n\nOr open a new terminal.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
    except Exception as e:
        print(f"\nError: {e}")
        exit(1)
