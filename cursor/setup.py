#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import urllib.request
import urllib.parse
import time
import webbrowser
from pathlib import Path
from typing import Tuple, Optional, Dict
import threading
import http.server
import socketserver
import socket
import ssl

try:
    import certifi
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--user", "certifi"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import certifi

HOOKS_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/hooks.json"
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/unbound.py"


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
        # Create SSL context with certifi certificates
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        with urllib.request.urlopen(url, timeout=30, context=ssl_context) as response:
            if response.status == 200:
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                dest_path.write_bytes(response.read())
                return True
        return False
    except Exception as e:
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


def main():
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
    
    success, message = set_env_var("UNBOUND_CURSOR_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return
    
    print(f"✅ Environment variable set")
    
    if not setup_hooks():
        print("\n❌ Failed to setup hooks")
        return
    
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