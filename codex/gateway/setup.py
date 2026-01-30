#!/usr/bin/env python3
"""
Codex CLI - Environment Setup Script
"""

import os
import sys
import platform
import subprocess
import urllib.parse
import json
from pathlib import Path
from typing import Optional, Dict
import argparse
import threading
import http.server
import socketserver
import socket
import webbrowser

# Add parent directory to path to import shared utilities
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from setup_utils import (
    debug_print, normalize_url, get_shell_rc_file, 
    set_env_var, remove_env_var, verify_api_key
)
import setup_utils

DEBUG = False


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
        setup_utils.DEBUG = True
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
