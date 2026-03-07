#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Tuple, Optional
import threading
import http.server
import socketserver
import json


DEBUG = False

ENV_VAR_NAME = "UNBOUND_OPENCLAW_API_KEY"
PLUGIN_NAME = "unbound-openclaw-plugin"
PROVIDER_NAME = "unbound"
DEFAULT_MODEL = "unbound/claude-sonnet-4-20250514"


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

        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"

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


def run_callback_server(frontend_url: str) -> Optional[str]:
    """Run a local HTTP server to receive the OAuth callback. Returns the API key or None."""
    api_key_holder = [None]
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

            api_key_holder[0] = query["api_key"]
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
        target_url = f"{frontend_url}/automations/api-key-callback?callback_url={encoded_callback}&app_type=openclaw"
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

        return api_key_holder[0]
    except Exception as e:
        print(f"❌ Failed to run callback server: {e}")
        return None


def configure_openclaw(gateway_url: str, setup_plugin: bool = True, setup_provider: bool = True, model: str = None) -> bool:
    """Configure OpenClaw with the Unbound plugin and/or provider."""
    config_dir = Path.home() / ".openclaw"
    config_path = config_dir / "openclaw.json"

    try:
        config_dir.mkdir(parents=True, exist_ok=True)

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except FileNotFoundError:
            config = {}

        if setup_plugin:
            entries = config.setdefault("plugins", {}).setdefault("entries", {})

            if PLUGIN_NAME not in entries:
                entries[PLUGIN_NAME] = {
                    "enabled": True,
                    "config": {
                        "gatewayUrl": gateway_url,
                        "failOpen": True,
                    },
                }
            else:
                entries[PLUGIN_NAME]["config"]["gatewayUrl"] = gateway_url
                print("ℹ️  Updating gatewayUrl in existing plugin entry")

        if setup_provider:
            providers = config.setdefault("models", {}).setdefault("providers", {})
            model_id = model or "claude-sonnet-4-20250514"

            if PROVIDER_NAME not in providers:
                providers[PROVIDER_NAME] = {
                    "baseUrl": f"{gateway_url}/v1",
                    "apiKey": "${UNBOUND_OPENCLAW_API_KEY}",
                    "api": "openai-completions",
                    "models": [
                        {
                            "id": model_id,
                            "name": model_id,
                            "contextWindow": 200000,
                            "maxTokens": 8192,
                        }
                    ],
                }
            else:
                providers[PROVIDER_NAME]["baseUrl"] = f"{gateway_url}/v1"
                print("ℹ️  Updating baseUrl in existing unbound provider")

            model_config = config.setdefault("agents", {}).setdefault("defaults", {}).setdefault("model", {})
            default_model = f"unbound/{model_id}"

            if "primary" not in model_config:
                model_config["primary"] = default_model
            else:
                print(f"ℹ️  Keeping existing default model: {model_config['primary']}")

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
    success, _ = remove_env_var(ENV_VAR_NAME)
    if success:
        print(f"✅ Removed {ENV_VAR_NAME}")
    else:
        print(f"❌ Failed to remove {ENV_VAR_NAME}")

    # Remove plugin config from openclaw.json
    config_path = Path.home() / ".openclaw" / "openclaw.json"
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            modified = False

            # Remove plugin entry
            entries = config.get("plugins", {}).get("entries", {})
            if entries.pop(PLUGIN_NAME, None) is not None:
                modified = True
                print("✅ Removed plugin entry")

            # Remove plugin from installs
            installs = config.get("plugins", {}).get("installs", {})
            unbound_keywords = (PLUGIN_NAME, "unbound-gateway", "openclaw-unbound")
            for key in list(installs.keys()):
                install_path = installs[key].get("installPath", "")
                if any(kw in key or kw in install_path for kw in unbound_keywords):
                    installs.pop(key)
                    modified = True
                    print(f"✅ Removed plugin install ({key})")

            # Remove plugin from load paths
            load_paths = config.get("plugins", {}).get("load", {}).get("paths", [])
            original_len = len(load_paths)
            load_paths[:] = [p for p in load_paths if PLUGIN_NAME not in p and "openclaw-unbound" not in p]
            if len(load_paths) < original_len:
                modified = True
                print("✅ Removed plugin load path")

            # Remove provider
            providers = config.get("models", {}).get("providers", {})
            if providers.pop(PROVIDER_NAME, None) is not None:
                modified = True
                print("✅ Removed unbound provider")

            # Remove default model if it points to the unbound provider
            model_config = config.get("agents", {}).get("defaults", {}).get("model", {})
            primary = model_config.get("primary", "")
            if primary.startswith("unbound/"):
                model_config.pop("primary")
                modified = True
                print(f"✅ Removed default model ({primary})")

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
    model = None
    for i, arg in enumerate(sys.argv):
        if arg == "--domain" and i + 1 < len(sys.argv):
            domain = sys.argv[i + 1]
        elif arg == "--model" and i + 1 < len(sys.argv):
            model = sys.argv[i + 1]

    setup_plugin = "--plugin" in sys.argv
    setup_provider = "--provider" in sys.argv
    # If neither flag is given, set up both
    if not setup_plugin and not setup_provider:
        setup_plugin = True
        setup_provider = True

    if not domain:
        print("❌ Missing required argument: --domain")
        print("Usage: python3 setup.py --domain gateway.getunbound.ai [--plugin] [--provider] [--model MODEL_ID]")
        return

    auth_url = normalize_url(domain)
    # The API gateway is always api.getunbound.ai regardless of the UI domain.
    # --domain only controls where the browser opens for OAuth.
    gateway_url = "https://api.getunbound.ai"

    api_key = run_callback_server(auth_url)
    if not api_key:
        print("❌ No API key received. Exiting.")
        return

    debug_print("API key received from callback")

    # Set environment variable
    debug_print(f"Setting {ENV_VAR_NAME} environment variable...")
    success, message = set_env_var(ENV_VAR_NAME, api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return

    # Configure OpenClaw
    debug_print("Configuring OpenClaw...")
    if not configure_openclaw(gateway_url, setup_plugin=setup_plugin, setup_provider=setup_provider, model=model):
        print("❌ Failed to configure OpenClaw")
        return

    print("✅ API key verified and added")
    if setup_plugin:
        print("✅ OpenClaw plugin configured")
    if setup_provider:
        print("✅ Unbound LLM provider configured")

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    print("\nYou can now use OpenClaw with Unbound tool policies:")
    print("  openclaw agent --local --agent main --message 'hello world'")

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
