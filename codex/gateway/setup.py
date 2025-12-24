#!/usr/bin/env python3
"""
Codex CLI - Environment Setup Script
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


def verify_api_key(api_key: str) -> bool:
    """
    Verify the API key by making a request to the /models endpoint.
    
    Args:
        api_key: The API key to verify
    
    Returns:
        True if valid, False otherwise
    """
    if not api_key or len(api_key) == 0:
        print("❌ API key is empty")
        return False
    
    try:
        url = "https://api.getunbound.ai/v1/models"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Unbound CLI"
        }
        
        request = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                
                # Check if response has data (models)
                if data and isinstance(data, dict) and "data" in data:
                    if isinstance(data["data"], list) and len(data["data"]) > 0:
                        return True
                # Also check if data is a list directly
                elif data and isinstance(data, list) and len(data) > 0:
                    return True
                # Or if it's an object
                elif data and isinstance(data, dict):
                    return True
                
                return False
            else:
                print(f"❌ API key verification failed: {response.status}")
                return False
                
    except urllib.error.HTTPError as e:
        print(f"❌ API key verification failed: {e.code} {e.reason}")
        try:
            error_data = json.loads(e.read().decode())
            if "error" in error_data and "message" in error_data["error"]:
                print(f"   Error: {error_data['error']['message']}")
        except:
            pass
        return False
    except Exception as e:
        print(f"❌ API key verification failed: {e}")
        return False


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


def clear_setup() -> None:
    """Undo all changes made by the setup script."""
    global DEBUG
    print("=" * 60)
    print("Codex CLI - Clearing Setup")
    print("=" * 60)

    # Remove environment variables
    env_vars = ["OPENAI_API_KEY", "OPENAI_BASE_URL"]
    for var in env_vars:
        success, _ = remove_env_var(var)
        if success:
            print(f"✅ Removed {var}")
        else:
            print(f"❌ Failed to remove {var}")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def main():
    """Main setup function."""
    global DEBUG

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--domain", dest="domain", help="Base frontend URL (e.g., gateway.getunbound.ai)")
    parser.add_argument("--clear", action="store_true", help="Undo all changes made by the setup script")
    parser.add_argument("--debug", action="store_true", help="Show detailed debug information")
    args, _ = parser.parse_known_args()

    if args.debug:
        DEBUG = True
        debug_print("Debug mode enabled")

    if args.clear:
        clear_setup()
        return

    print("=" * 60)
    print("Codex CLI - Environment Setup")
    print("=" * 60)

    if not args.domain:
        print("\n❌ Missing required argument: --domain (e.g., --domain gateway.getunbound.ai)")
        return

    auth_url = normalize_url(args.domain)
    cb_response = run_one_shot_callback_server(auth_url)
    if cb_response is None:
        print("\n❌ Failed to receive callback response. Exiting.")
        return

    api_key = None
    try:
        api_key = (cb_response.get("query") or {}).get("api_key")
    except Exception:
        api_key = None

    if not api_key:
        print("\n❌ No api_key found in callback. Exiting.")
        return

    debug_print("Verifying API key...")
    if not verify_api_key(api_key):
        print("❌ API key verification failed. Exiting.")
        return

    print("API Key Verified ✅")
    debug_print("API key verification successful")

    debug_print("Setting OPENAI_API_KEY environment variable...")
    success, message = set_env_var("OPENAI_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to configure OPENAI_API_KEY: {message}")
        return
    debug_print("OPENAI_API_KEY set successfully")

    debug_print("Setting OPENAI_BASE_URL environment variable...")
    success, message = set_env_var("OPENAI_BASE_URL", "https://api.getunbound.ai/v1")
    debug_print("OPENAI_BASE_URL set successfully")
    
    # Final instructions
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    
    system = platform.system().lower()
    if system in ["darwin", "linux"]:
        try:
            rc_path = get_shell_rc_file()
            if rc_path is not None:
                shell_path = os.environ.get("SHELL", "/bin/bash") or "/bin/bash"
                subprocess.run([shell_path, "-lc", f"source '{rc_path}'"], check=False, capture_output=True)
        except Exception:
            pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled by user.")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        exit(1)
