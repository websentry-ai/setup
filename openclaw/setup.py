#!/usr/bin/env python3

import os
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
import json


DEBUG = False


def debug_print(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}")


def install_macos_certificates():
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
    return url.rstrip("/")


def get_shell_rc_file() -> Optional[Path]:
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
    export_line = f"export {var_name}='{value}'"
    return append_to_file(rc_file, export_line, var_name)


def set_env_var(var_name: str, value: str) -> Tuple[bool, str]:
    system = platform.system().lower()

    if system == "windows":
        success = set_env_var_windows(var_name, value)
        return (True, "Set for new terminals") if success else (False, "Failed")
    elif system in ["darwin", "linux"]:
        success = set_env_var_unix(var_name, value)
        if success:
            return True, "Set successfully"
        return False, "Failed"
    else:
        return False, f"Unsupported OS: {system}"


def remove_env_var_unix(var_name: str) -> bool:
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False
    try:
        rc_file.touch(exist_ok=True)
        with open(rc_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        export_prefix = f"export {var_name}="
        new_lines = [l for l in lines if not l.strip().startswith(export_prefix)]
        if len(new_lines) != len(lines):
            with open(rc_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        return True
    except Exception as e:
        print(f"❌ Failed to modify {rc_file}: {e}")
        return False


def remove_env_var_windows(var_name: str) -> bool:
    try:
        subprocess.run(
            ["reg", "delete", "HKCU\\Environment", "/F", "/V", var_name],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError:
        return True
    except FileNotFoundError:
        print("❌ 'reg' command not found. Please remove the variable manually.")
        return False


def remove_env_var(var_name: str) -> Tuple[bool, str]:
    system = platform.system().lower()
    if system == "windows":
        success = remove_env_var_windows(var_name)
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    elif system in ["darwin", "linux"]:
        success = remove_env_var_unix(var_name)
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    else:
        return False, f"Unsupported OS: {system}"


def run_callback_server(frontend_url: str) -> Optional[Dict]:
    result = {"method": None, "path": None, "query": None, "headers": None, "body": None}
    done_evt = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def _finish(self, code=200, message=b"Logged in successfully! You can close this tab."):
            try:
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(message)))
                self.end_headers()
                self.wfile.write(message)
            except Exception:
                pass

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            query = dict(urllib.parse.parse_qsl(parsed.query))

            if parsed.path != "/callback" or "api_key" not in query:
                self._finish(code=400, message=b"Unexpected request. Please complete the OAuth flow in your browser.")
                return

            result["method"] = "GET"
            result["path"] = self.path
            result["query"] = query
            result["headers"] = {k: v for k, v in self.headers.items()}
            result["body"] = None
            self._finish()
            done_evt.set()

        def log_message(self, format, *args):
            return

    try:
        httpd = socketserver.TCPServer(("127.0.0.1", 0), CallbackHandler)
        _, port = httpd.server_address
        callback_url = f"http://127.0.0.1:{port}/callback"

        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        encoded_callback = urllib.parse.quote(callback_url, safe="")
        target_url = f"{frontend_url.rstrip('/')}/automations/api-key-callback?callback_url={encoded_callback}&app_type=openclaw"
        webbrowser.open(target_url)
        print("🌐 Opening browser...")
        print("If browser doesn't open automatically, open this link:")
        print(target_url)
        print("Waiting for authentication (5 minute timeout)...")

        try:
            timed_out = not done_evt.wait(timeout=300)
        finally:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass

        if timed_out:
            print("❌ Timed out waiting for authentication (5 minutes). Please try again.")
            return None

        return result
    except Exception as e:
        print(f"❌ Failed to run callback server: {e}")
        return None


def configure_openclaw(gateway_url: str) -> bool:
    """Configure OpenClaw with the Unbound plugin and provider."""
    config_dir = Path.home() / ".openclaw"
    config_path = config_dir / "openclaw.json"

    try:
        config_dir.mkdir(parents=True, exist_ok=True)

        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        else:
            config = {}

        # Configure the plugin
        if "plugins" not in config:
            config["plugins"] = {}
        if "entries" not in config["plugins"]:
            config["plugins"]["entries"] = {}

        config["plugins"]["entries"]["unbound-gateway"] = {
            "enabled": True,
            "config": {
                "gatewayUrl": gateway_url,
                "failOpen": True,
            },
        }

        # Configure the LLM provider
        if "models" not in config:
            config["models"] = {}
        if "providers" not in config["models"]:
            config["models"]["providers"] = {}

        config["models"]["providers"]["unbound"] = {
            "baseUrl": f"{gateway_url}/v1",
            "apiKey": "${UNBOUND_API_KEY}",
            "api": "openai-completions",
            "models": [
                {
                    "id": "claude-sonnet-4-20250514",
                    "name": "Claude Sonnet 4",
                    "contextWindow": 200000,
                    "maxTokens": 8192,
                }
            ],
        }

        # Set default model to use Unbound provider
        if "agents" not in config:
            config["agents"] = {}
        if "defaults" not in config["agents"]:
            config["agents"]["defaults"] = {}
        if "model" not in config["agents"]["defaults"]:
            config["agents"]["defaults"]["model"] = {}

        if "primary" not in config["agents"]["defaults"]["model"]:
            config["agents"]["defaults"]["model"]["primary"] = "unbound/claude-sonnet-4-20250514"
        else:
            print(f"ℹ️  Keeping existing default model: {config['agents']['defaults']['model']['primary']}")

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        debug_print(f"OpenClaw config written to {config_path}")
        return True

    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse existing openclaw.json: {e}")
        return False
    except Exception as e:
        print(f"❌ Failed to configure OpenClaw: {e}")
        return False


def clear_setup() -> None:
    """Undo all changes made by the setup script."""
    print("=" * 60)
    print("OpenClaw Unbound Plugin - Clearing Setup")
    print("=" * 60)

    # Remove environment variable
    success, _ = remove_env_var("UNBOUND_API_KEY")
    if success:
        print("✅ Removed UNBOUND_API_KEY")
    else:
        print("❌ Failed to remove UNBOUND_API_KEY")

    # Remove plugin config from openclaw.json
    config_path = Path.home() / ".openclaw" / "openclaw.json"
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            modified = False

            # Remove plugin entry
            if "plugins" in config and "entries" in config["plugins"]:
                if "unbound-gateway" in config["plugins"]["entries"]:
                    del config["plugins"]["entries"]["unbound-gateway"]
                    modified = True
                    print("✅ Removed unbound-gateway plugin entry")

            # Remove provider
            if "models" in config and "providers" in config["models"]:
                if "unbound" in config["models"]["providers"]:
                    del config["models"]["providers"]["unbound"]
                    modified = True
                    print("✅ Removed unbound provider")

            # Remove default model if it points to the unbound provider
            try:
                primary = config.get("agents", {}).get("defaults", {}).get("model", {}).get("primary", "")
                if primary.startswith("unbound/"):
                    del config["agents"]["defaults"]["model"]["primary"]
                    modified = True
                    print(f"✅ Removed default model ({primary})")
            except (KeyError, TypeError):
                pass

            if modified:
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2)

        except Exception as e:
            print(f"❌ Failed to update openclaw.json: {e}")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def main():
    global DEBUG

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
    print("OpenClaw Setup for Unbound Gateway")
    print("=" * 60)

    domain = None
    for i, arg in enumerate(sys.argv):
        if arg == "--domain" and i + 1 < len(sys.argv):
            domain = sys.argv[i + 1]
            break

    if not domain:
        print("❌ Missing required argument: --domain")
        print("Usage: python3 setup.py --domain gateway.getunbound.ai")
        return

    auth_url = normalize_url(domain)
    # Always derive the API gateway URL from the bare domain.
    # Input is always a bare domain (e.g., gateway.getunbound.ai).
    # The API endpoint is at api.<domain>.
    bare_domain = domain
    for prefix in ("https://", "http://"):
        if bare_domain.startswith(prefix):
            bare_domain = bare_domain[len(prefix):]
            break
    bare_domain = bare_domain.rstrip("/")
    gateway_url = f"https://api.{bare_domain}"

    cb_response = run_callback_server(auth_url)
    if cb_response is None:
        print("❌ Failed to receive callback. Exiting.")
        return

    api_key = None
    try:
        api_key = (cb_response.get("query") or {}).get("api_key")
    except Exception:
        pass

    if not api_key:
        print("❌ No API key received. Exiting.")
        return

    debug_print("API key received from callback")

    # Set environment variable
    debug_print("Setting UNBOUND_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return

    # Configure OpenClaw
    debug_print("Configuring OpenClaw...")
    if not configure_openclaw(gateway_url):
        print("❌ Failed to configure OpenClaw")
        return

    print("✅ API key verified and added")
    print("✅ OpenClaw plugin configured")
    print("✅ Unbound LLM provider configured")

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    print("\nYou can now use OpenClaw with Unbound tool policies:")
    print("  openclaw agent --local --message 'hello world'")

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
