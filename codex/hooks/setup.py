
#!/usr/bin/env python3

import os
import re
import sys
import platform
import subprocess
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Tuple, Optional, Dict
import threading
import http.server
import socketserver
import socket
import json


SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/unbound.py"

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

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            host, port = s.getsockname()
        callback_url = f"http://127.0.0.1:{port}/callback"

        httpd = socketserver.TCPServer(("127.0.0.1", port), CallbackHandler)
        httpd.allow_reuse_address = True

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
            done_evt.wait()
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


def setup_hooks():
    hooks_dir = Path.home() / ".codex" / "hooks"
    script_path = hooks_dir / "unbound.py"

    if not download_file(SCRIPT_URL, script_path):
        return False

    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
    except Exception as e:
        pass

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

        hook_command = str(Path.home() / ".codex" / "hooks" / "unbound.py")

        hooks_config = {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 10
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
                            "async": True,
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
                            "async": True,
                            "timeout": 60
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
                            if hook.get("command") == hook_command:
                                our_hook_exists = True
                                break

                if not our_hook_exists:
                    config["hooks"][event].extend(new_config)
            else:
                config["hooks"][event] = new_config

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

    if not hooks_path.exists():
        return

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
                    new_hooks = [h for h in hooks if h.get("command") != hook_command]
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
        result = subprocess.run(
            ["curl", "-fsSL", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-H", f"X-API-KEY: {api_key}",
             "-d", data, url],
            capture_output=True,
            text=True,
            timeout=10
        )
        debug_print(f"Setup completion reported (exit code {result.returncode})")
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

    if clear_mode:
        clear_setup()
        return

    install_macos_certificates()

    print("=" * 60)
    print("Codex Setup for Unbound Gateway")
    print("=" * 60)

    domain = None
    for i, arg in enumerate(sys.argv):
        if arg == "--domain" and i + 1 < len(sys.argv):
            domain = sys.argv[i + 1]
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
    if not setup_hooks():
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

    notify_setup_complete(api_key, "codex")

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
