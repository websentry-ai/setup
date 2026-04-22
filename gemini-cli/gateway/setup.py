#!/usr/bin/env python3
"""
Gemini CLI - Environment Setup Script
"""

import os
import platform
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import json
from pathlib import Path
from typing import Tuple, Optional, Dict
import argparse
import threading
import http.server
import socketserver
import socket
import webbrowser


DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def normalize_url(domain: str) -> str:
    """Normalize domain to proper URL format."""
    domain = domain.strip()

    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain
    else:
        url = f"https://{domain}"

    return url.rstrip('/')

def get_shell_rc_file() -> Path:
    """
    Determine the appropriate shell configuration file based on the OS and shell.
    
    Returns:
        Path: Path to the shell configuration file
    """
    system = platform.system().lower()
    shell = os.environ.get("SHELL", "").lower()
    
    if system == "darwin":
        # macOS - default shell is zsh
        if "zsh" in shell:
            return Path.home() / ".zprofile"
        else:
            return Path.home() / ".bash_profile"
    
    elif system == "linux":
        # Linux
        if "zsh" in shell:
            return Path.home() / ".zshrc"
        else:
            return Path.home() / ".bashrc"
    
    elif system == "windows":
        # Windows - uses registry, no rc file
        return None
    
    else:
        raise OSError(f"Unsupported operating system: {system}")


def append_to_file(file_path: Path, line: str) -> bool:
    """
    Append a line to a file only if it's not already present.
    
    Args:
        file_path: Path to the file to append to
        line: Line to append (without newline)
    
    Returns:
        bool: True if line was added, False if it already existed
    """
    try:
        file_path.touch(exist_ok=True)
        
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        if line not in content:
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(f"{line}\n")
            return True
        else:
            return False
    except Exception as e:
        print(f"❌ Failed to modify {file_path}: {e}")
        return False


def set_env_var_on_windows(var_name: str, value: str) -> bool:
    """
    Set environment variable permanently on Windows using setx.

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        bool: True if successful, False otherwise
    """
    debug_print(f"Writing to user environment registry (Windows)")
    try:
        subprocess.run(["setx", var_name, value], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to set {var_name} on Windows: {e}")
        if e.stderr:
            print(f"   Error details: {e.stderr.decode()}")
        return False
    except FileNotFoundError:
        print(f"❌ 'setx' command not found. Please set {var_name} manually.")
        return False


def set_env_var_on_unix(var_name: str, value: str) -> bool:
    """
    Set environment variable permanently on Unix-like systems (macOS, Linux).

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        bool: True if successful, False otherwise
    """
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False

    debug_print(f"Writing to shell file: {rc_file}")
    export_line = f'export {var_name}="{value}"'
    
    was_added = append_to_file(rc_file, export_line)
    
    if was_added:
        return True
    else:
        return True


def set_env_var(var_name: str, value: str) -> Tuple[bool, str]:
    """
    Set an environment variable permanently across all OS platforms.

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        Tuple[bool, str]: (success, message)
    """
    system = platform.system().lower()

    if system == "windows":
        success = set_env_var_on_windows(var_name, value)
        if success:
            debug_print(f"Environment variable {var_name} set on Windows")
            return True, "Environment variable set for new terminals"
        else:
            return False, "Failed to set environment variable"

    elif system in ["darwin", "linux"]:
        success = set_env_var_on_unix(var_name, value)
        if success:
            debug_print(f"Environment variable {var_name} added to shell rc file")
            shell_name = "zsh" if "zsh" in os.environ.get("SHELL", "") else "bash"
            return True, f"Run 'source ~/.{shell_name}rc' or restart terminal"
        else:
            return False, "Failed to set environment variable"

    else:
        return False, f"Unsupported OS: {system}"


def remove_env_var_on_unix(var_name: str) -> bool:
    """Remove an environment variable export line from the user's shell rc file."""
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False
    try:
        if not rc_file.exists():
            return True
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
        return True
    except Exception as e:
        print(f"❌ Failed to modify {rc_file}: {e}")
        return False


def remove_env_var_on_windows(var_name: str) -> bool:
    """Remove a user environment variable on Windows."""
    try:
        subprocess.run(["reg", "delete", "HKCU\\Environment", "/F", "/V", var_name], check=True, capture_output=True)
        debug_print(f"Removed {var_name} from Windows registry")
        return True
    except subprocess.CalledProcessError:
        return True
    except FileNotFoundError:
        print("❌ 'reg' command not found. Please remove the variable manually.")
        return False


def remove_env_var(var_name: str) -> Tuple[bool, str]:
    """Remove an environment variable permanently across OS platforms."""
    system = platform.system().lower()
    if system == "windows":
        success = remove_env_var_on_windows(var_name)
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    elif system in ["darwin", "linux"]:
        success = remove_env_var_on_unix(var_name)
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    else:
        return False, f"Unsupported OS: {system}"


def run_one_shot_callback_server(frontend_url: str) -> Optional[Dict[str, any]]:
    """
    Start a local HTTP server that waits for a single callback request and returns its contents.
    Returns a dict with method, path, query, headers, and body; or None on failure.
    """
    result: Dict[str, any] = {"method": None, "path": None, "query": None, "headers": None, "body": None}
    done_evt = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def _finish(self, code: int = 200, message: bytes = b"Logged in successfully! You can close this tab and return to the terminal.") -> None:
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

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(length) if length > 0 else b""
            parsed = urllib.parse.urlparse(self.path)
            result["method"] = "POST"
            result["path"] = self.path
            result["query"] = dict(urllib.parse.parse_qsl(parsed.query))
            result["headers"] = {k: v for k, v in self.headers.items()}
            result["body"] = body.decode("utf-8", errors="replace") if body else None
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
        target_url = f"{frontend_url.rstrip('/')}/automations/api-key-callback?callback_url={encoded_callback}&app_type=default"
        webbrowser.open(target_url)
        print("🌐 Opening browser...")
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
        print(f"❌ Failed to run callback server: {e}")
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
        print(f"⚠️  Could not write config: {e}")
        return False


def clear_setup() -> None:
    """Undo all changes made by the setup script."""
    print("=" * 60)
    print("Gemini CLI - Clearing Setup")
    print("=" * 60)

    # Remove environment variables
    env_vars = ["GEMINI_API_KEY", "GOOGLE_GEMINI_BASE_URL"]
    for var in env_vars:
        success, _ = remove_env_var(var)
        if success:
            print(f"✅ Removed {var}")
        else:
            print(f"❌ Failed to remove {var}")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def notify_setup_complete(api_key: str, tool_type: str, backend_url: str = "https://backend.getunbound.ai"):
    """Notify backend that tool setup completed. Never fails the setup."""
    try:
        url = f"{backend_url.rstrip('/')}/api/v1/setup/complete/"
        data = json.dumps({"tool_type": tool_type})
        subprocess.run(
            ["curl", "-fsSL", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", data, "--config", "-", url],
            input=f'header = "X-API-KEY: {api_key}"\n'.encode(),
            capture_output=True,
            timeout=10,
        )
        debug_print("Setup completion notification sent")
    except Exception as e:
        debug_print(f"Could not notify backend: {e}")


def main():
    """Main setup function."""
    global DEBUG

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--domain", dest="domain", help="Base frontend URL (e.g., gateway.getunbound.ai)")
    parser.add_argument("--backend-url", dest="backend_url", default="https://backend.getunbound.ai", help="Override backend URL for local/staging testing (default: https://backend.getunbound.ai)")
    parser.add_argument("--gateway-url", dest="gateway_url", default="https://api.getunbound.ai", help="Override AI gateway URL written to GOOGLE_GEMINI_BASE_URL (default: https://api.getunbound.ai)")
    parser.add_argument("--clear", action="store_true", help="Undo all changes made by the setup script")
    parser.add_argument("--debug", action="store_true", help="Show detailed debug information")
    parser.add_argument("--api-key", dest="api_key", help="API key (skip browser auth)")
    args, _ = parser.parse_known_args()
    args.gateway_url = normalize_url(args.gateway_url)

    if args.debug:
        DEBUG = True
        debug_print("Debug mode enabled")

    if args.clear:
        clear_setup()
        return

    print("=" * 60)
    print("Gemini CLI - Environment Setup")
    print("=" * 60)

    api_key = args.api_key
    if not api_key:
        if not args.domain:
            print("\n❌ Missing required argument: --domain or --api-key")
            return

        auth_url = normalize_url(args.domain)
        cb_response = run_one_shot_callback_server(auth_url)
        if cb_response is None:
            print("\n❌ Failed to receive callback response. Exiting.")
            return

        try:
            api_key = (cb_response.get("query") or {}).get("api_key")
        except Exception:
            api_key = None

        if not api_key:
            print("\n❌ No api_key found in callback. Exiting.")
            return

    print("API Key Verified ✅")
    debug_print("API key verification successful")

    debug_print("Setting GEMINI_API_KEY environment variable...")
    success, message = set_env_var("GEMINI_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to configure GEMINI_API_KEY: {message}")
        return
    debug_print("GEMINI_API_KEY set successfully")

    debug_print("Setting GOOGLE_GEMINI_BASE_URL environment variable...")
    success, message = set_env_var("GOOGLE_GEMINI_BASE_URL", f"{args.gateway_url.rstrip('/')}/v1")
    debug_print("GOOGLE_GEMINI_BASE_URL set successfully")

    write_unbound_config(api_key)

    # Final instructions
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(api_key, "gemini-cli", backend_url=args.backend_url)

    rc_path = get_shell_rc_file()
    if rc_path is not None:
        print(f"\nTo apply changes in your current terminal, run:\n  source {rc_path}\n\nOr open a new terminal.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled by user.")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        exit(1)
