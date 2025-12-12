#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import json
import time
from pathlib import Path
from typing import Tuple

HOOKS_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/hooks.json"
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/unbound.py"

DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def get_enterprise_hooks_dir() -> Path:
    """Get the enterprise-managed hooks directory based on OS."""
    system = platform.system().lower()

    if system == "darwin":
        return Path("/Library/Application Support/Cursor")
    elif system == "linux":
        return Path("/etc/cursor")
    elif system == "windows":
        return Path("C:/ProgramData/Cursor")
    else:
        raise OSError(f"Unsupported operating system: {system}")


def check_admin_privileges() -> bool:
    """Check if the script is running with admin/root privileges."""
    system = platform.system().lower()

    try:
        if system in ["darwin", "linux"]:
            # Check if running as root (UID 0)
            return os.geteuid() == 0
        elif system == "windows":
            # Check if running as admin
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return False
    except Exception as e:
        debug_print(f"Failed to check privileges: {e}")
        return False


def get_mac_serial_number() -> str:
    """Get the Mac serial number using system_profiler."""
    try:
        result = subprocess.run(
            ["system_profiler", "SPHardwareDataType"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.split('\n'):
            if 'Serial Number' in line:
                parts = line.split(': ')
                if len(parts) >= 2:
                    return parts[1].strip()
        return None
    except Exception as e:
        debug_print(f"Failed to get serial number: {e}")
        return None


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
    enterprise_dir = get_enterprise_hooks_dir()
    hooks_dir = enterprise_dir / "hooks"
    hooks_json = enterprise_dir / "hooks.json"
    script_path = hooks_dir / "unbound.py"

    debug_print(f"Enterprise hooks directory: {enterprise_dir}")
    debug_print(f"Hooks JSON path: {hooks_json}")
    debug_print(f"Script path: {script_path}")

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
            print("\n🔄 Restarting Cursor IDE...")
            result = subprocess.run(["osascript", "-e", 'tell application "Cursor" to quit'],
                                    capture_output=True, timeout=5)
            if result.returncode != 0:
                subprocess.run(["killall", "Cursor"], capture_output=True, timeout=5)
            time.sleep(2)
            result = subprocess.run(["open", "-a", "Cursor"],
                                    capture_output=True, timeout=5)
            if result.returncode == 0:
                print("✅ Cursor restarted")
                return True
            else:
                print("Restart Cursor")
                return False

        elif system == "linux":
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["pkill", "-9", "cursor"], capture_output=True, timeout=5)
            time.sleep(1)
            proc = subprocess.Popen(["cursor"],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            if proc.poll() is None:
                print("✅ Cursor restarted")
                return True
            else:
                print("Restart Cursor")
                return False

        elif system == "windows":
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["taskkill", "/F", "/IM", "Cursor.exe"],
                           capture_output=True, timeout=5)
            time.sleep(1)
            proc = subprocess.Popen(["start", "cursor"],
                                    shell=True,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            time.sleep(0.5)
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


def fetch_api_key_from_mdm(base_url: str, app_name: str, auth_api_key: str, serial_number: str) -> str:
    """Fetch API key from MDM endpoint."""
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?app_name={app_name}&serial_number={serial_number}&app_type=cursor"

    debug_print(f"Fetching API key from: {url}")

    try:
        result = subprocess.run(
            ["curl", "-fsSL", "-w", "\n%{http_code}", "-H", f"Authorization: Bearer {auth_api_key}", url],
            capture_output=True,
            text=True,
            timeout=30
        )

        output_lines = result.stdout.strip().split('\n')
        if len(output_lines) < 2:
            print("❌ Invalid response from server")
            return None

        http_code = output_lines[-1]
        response_body = '\n'.join(output_lines[:-1])

        debug_print(f"HTTP status: {http_code}")
        debug_print(f"Response: {response_body}")

        if http_code != "200":
            print(f"❌ API request failed with status {http_code}")
            return None

        try:
            data = json.loads(response_body)
            api_key = data.get("api_key")
            if not api_key:
                print("❌ No api_key in response")
                return None
            user_email = data.get("email")
            first_name = data.get("first_name")
            last_name = data.get("last_name")
            print(f"User email: {user_email}")
            print(f"Name: {first_name} {last_name}")
            return api_key
        except json.JSONDecodeError:
            print("❌ Invalid JSON response from server")
            return None

    except subprocess.TimeoutExpired:
        print("❌ Request timed out")
        return None
    except Exception as e:
        debug_print(f"Request failed: {e}")
        print("❌ Failed to fetch API key")
        return None


def main():
    global DEBUG

    debug_mode = "--debug" in sys.argv
    if debug_mode:
        DEBUG = True
        debug_print("Debug mode enabled")

    print("=" * 60)
    print("Unbound Cursor Hooks - MDM Setup")
    print("=" * 60)

    # Check platform
    if platform.system().lower() != "darwin":
        print("❌ This script only supports macOS")
        return

    # Check admin privileges
    if not check_admin_privileges():
        print("❌ This script requires administrator/root privileges")
        print("   Please run with: sudo python3 setup.py ...")
        return

    # Parse arguments
    base_url = None
    app_name = None
    auth_api_key = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--url" and i + 1 < len(args):
            base_url = args[i + 1]
            i += 2
        elif args[i] == "--app_name" and i + 1 < len(args):
            app_name = args[i + 1]
            i += 2
        elif args[i] == "--api_key" and i + 1 < len(args):
            auth_api_key = args[i + 1]
            i += 2
        elif args[i] == "--debug":
            i += 1
        else:
            i += 1

    if not base_url or not app_name or not auth_api_key:
        print("\n❌ Missing required arguments")
        print("Usage: python setup.py --url <base_url> --app_name <app_name> --api_key <api_key> [--debug]")
        return

    # Get serial number
    print("\n🔍 Getting device serial number...")
    serial_number = get_mac_serial_number()
    if not serial_number:
        print("❌ Failed to get device serial number")
        return
    debug_print(f"Serial number: {serial_number}")
    print("✅ Serial number retrieved")

    # Fetch API key from MDM endpoint
    print("\n🔑 Fetching API key from MDM...")
    cursor_api_key = fetch_api_key_from_mdm(base_url, app_name, auth_api_key, serial_number)
    if not cursor_api_key:
        return
    print("✅ API key received")

    # Set environment variable
    debug_print("Setting UNBOUND_CURSOR_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_CURSOR_API_KEY", cursor_api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return
    print("✅ Environment variable set")

    # Setup hooks
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
