#!/usr/bin/env python3

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from setup_utils import (
    debug_print, normalize_url, get_shell_rc_file,
    set_env_var, remove_env_var
)
import setup_utils

import platform
import subprocess
import urllib.parse
import time
import webbrowser
from typing import Optional, Dict
import threading
import http.server
import socketserver
import socket

HOOKS_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/hooks.json"
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/unbound.py"

DEBUG = False


def install_macos_certificates():
    """Run Python certificate installation command on macOS."""
    if platform.system().lower() != "darwin":
        return
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    cert_path = f"/Applications/Python {py_version}/Install Certificates.command"
    if os.path.exists(cert_path):
        subprocess.run([cert_path], capture_output=True)


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
        target_url = f"{frontend_url.rstrip('/')}/automations/api-key-callback?callback_url={encoded_callback}&app_type=cursor"
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

def setup_hooks():
    hooks_dir = Path.home() / ".cursor" / "hooks"
    hooks_json = Path.home() / ".cursor" / "hooks.json"
    script_path = hooks_dir / "unbound.py"
    
    print("\n📥 Downloading hooks configuration...")
    if not download_file(HOOKS_URL, hooks_json):
        return False
    print("✅ hooks.json downloaded")
    
    print("📥 Downloading unbound.py script...")
    if not download_file(SCRIPT_URL, script_path):
        return False
    print("✅ unbound.py downloaded")
    
    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
        print("✅ Made unbound.py executable")
    except Exception as e:
        print(f"⚠️  Could not make script executable: {e}")
    
    return True


def restart_cursor() -> bool:
    """Attempt to restart Cursor IDE."""
    system = platform.system().lower()

    try:
        if system == "darwin":
            # macOS: Gracefully quit using AppleScript, then relaunch
            print("\n🔄 Restarting Cursor IDE...")
            result = subprocess.run(["osascript", "-e", 'tell application "Cursor" to quit'], 
                                  capture_output=True, timeout=5)
            if result.returncode != 0:
                # Fallback to killall if osascript fails
                subprocess.run(["killall", "Cursor"], capture_output=True, timeout=5)
            time.sleep(2)
            # Launch Cursor and check if it succeeds
            result = subprocess.run(["open", "-a", "Cursor"],
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                print("✅ Cursor restarted")
                return True
            else:
                print("Restart Cursor")
                return False

        elif system == "linux":
            # Linux: Kill and relaunch cursor
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["pkill", "-9", "cursor"], capture_output=True, timeout=5)
            time.sleep(1)
            proc = subprocess.Popen(["cursor"],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            # Give it a moment to start
            time.sleep(0.5)
            # If process is still running (poll returns None) or started successfully, it's good
            if proc.poll() is None:
                print("✅ Cursor restarted")
                return True
            else:
                print("Restart Cursor")
                return False

        elif system == "windows":
            # Windows: Use taskkill and start
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["taskkill", "/F", "/IM", "Cursor.exe"],
                         capture_output=True, timeout=5)
            time.sleep(1)
            proc = subprocess.Popen(["start", "cursor"],
                                  shell=True,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            # Give it a moment to start
            time.sleep(0.5)
            # start command returns immediately, so check if process started
            if proc.poll() is None or proc.returncode == 0:
                print("✅ Cursor restarted")
                return True
            else:
                print("Restart Cursor")
                return False

        return False

    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        print("Restart Cursor")
        return False


def clear_setup() -> None:
    """Undo all changes made by the setup script."""
    print("=" * 60)
    print("Unbound Cursor Hooks - Clearing Setup")
    print("=" * 60)

    # Remove environment variable
    success, _ = remove_env_var("UNBOUND_CURSOR_API_KEY")
    if success:
        print("✅ Removed UNBOUND_CURSOR_API_KEY")
    else:
        print("❌ Failed to remove UNBOUND_CURSOR_API_KEY")

    # Remove the hooks.json file
    hooks_json = Path.home() / ".cursor" / "hooks.json"
    if hooks_json.exists():
        try:
            hooks_json.unlink()
            debug_print(f"Removed {hooks_json}")
            print(f"✅ Removed {hooks_json}")
        except Exception as e:
            print(f"❌ Failed to remove {hooks_json}: {e}")

    # Remove the unbound.py script
    script_path = Path.home() / ".cursor" / "hooks" / "unbound.py"
    if script_path.exists():
        try:
            script_path.unlink()
            debug_print(f"Removed {script_path}")
            print(f"✅ Removed {script_path}")
        except Exception as e:
            print(f"❌ Failed to remove {script_path}: {e}")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def main():
    global DEBUG

    # Parse arguments
    clear_mode = "--clear" in sys.argv
    debug_mode = "--debug" in sys.argv

    if debug_mode:
        DEBUG = True
        setup_utils.DEBUG = True
        debug_print("Debug mode enabled")

    if clear_mode:
        clear_setup()
        return

    install_macos_certificates()

    print("=" * 60)
    print("Unbound Cursor Hooks - Setup")
    print("=" * 60)

    domain = None
    for i, arg in enumerate(sys.argv):
        if arg == "--domain" and i + 1 < len(sys.argv):
            domain = sys.argv[i + 1]
            break

    if not domain:
        print("\n❌ Missing required argument: --domain")
        print("Usage: python3 setup.py --domain gateway.getunbound.ai")
        return
    
    auth_url = normalize_url(domain)
    
    cb_response = run_callback_server(auth_url)
    if cb_response is None:
        print("\n❌ Failed to receive callback. Exiting.")
        return
    
    api_key = None
    try:
        api_key = (cb_response.get("query") or {}).get("api_key")
    except Exception:
        pass
    
    if not api_key:
        print("\n❌ No API key received. Exiting.")
        return

    print("✅ API key received")
    debug_print("API key received from callback")

    debug_print("Setting UNBOUND_CURSOR_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_CURSOR_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return

    print(f"✅ Environment variable set")
    debug_print("UNBOUND_CURSOR_API_KEY set successfully")

    debug_print("Setting up hooks...")
    if not setup_hooks():
        print("\n❌ Failed to setup hooks")
        return
    debug_print("Hooks setup complete")
    
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    
    restart_cursor()

    print("=" * 60)
    print("\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        exit(1)