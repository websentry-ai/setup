#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import json
import time
import pwd
from pathlib import Path
from typing import Tuple, List

HOOKS_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/hooks.json"
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/unbound.py"

DEBUG = True


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


def check_env_var_exists(rc_file: Path, var_name: str, value: str) -> bool:
    if not rc_file.exists():
        return False
    try:
        with open(rc_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        export_line = f'export {var_name}="{value}"'
        return any(l.rstrip() == export_line for l in lines)
    except Exception:
        return False


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


def get_all_user_homes() -> List[Tuple[str, Path]]:
    """Get all real user home directories on the system (excluding system accounts)."""
    user_homes = []

    try:
        # Iterate through all users in the password database
        for user in pwd.getpwall():
            uid = user.pw_uid
            username = user.pw_name
            home_dir = Path(user.pw_dir)

            # Filter out system accounts (UID < 500 on macOS)
            # Real users typically have UID >= 501 on macOS
            if uid >= 500 and home_dir.exists() and home_dir.is_dir():
                # Additional checks to ensure it's a real user home
                if str(home_dir).startswith('/Users/') and username not in ['Shared', 'Guest']:
                    user_homes.append((username, home_dir))
                    debug_print(f"Found user: {username} -> {home_dir}")

        return user_homes
    except Exception as e:
        debug_print(f"Error enumerating users: {e}")
        return []


def set_env_var_system_wide_macos(var_name: str, value: str) -> Tuple[bool, bool]:
    """Set environment variable for all users on macOS by updating each user's shell rc file.
    Returns: (success, changed)"""
    try:
        user_homes = get_all_user_homes()

        if not user_homes:
            print("⚠️  No user home directories found")
            return False, False

        success_count = 0
        changed_count = 0
        export_line = f'export {var_name}="{value}"'

        # Set environment variable for each user
        for username, home_dir in user_homes:
            debug_print(f"Setting env var for user: {username}")

            # Get user's UID and GID for proper file ownership
            try:
                user_info = pwd.getpwnam(username)
                uid = user_info.pw_uid
                gid = user_info.pw_gid
            except KeyError:
                debug_print(f"Could not get UID/GID for {username}")
                continue

            # Try both zsh and bash profiles
            rc_files = [
                home_dir / ".zprofile",
                home_dir / ".bash_profile"
            ]

            user_success = False
            user_changed = False
            for rc_file in rc_files:
                try:
                    exists_already = check_env_var_exists(rc_file, var_name, value)
                    if append_to_file(rc_file, export_line, var_name):
                        # Set correct ownership (important when running as root)
                        os.chown(rc_file, uid, gid)
                        debug_print(f"Updated {rc_file} for {username}")
                        user_success = True
                        if not exists_already:
                            user_changed = True
                except Exception as e:
                    debug_print(f"Failed to update {rc_file}: {e}")

            if user_success:
                success_count += 1
            if user_changed:
                changed_count += 1

        if success_count > 0:
            print(f"   Set for {success_count} user(s)")
            return True, changed_count > 0
        else:
            print("⚠️  Failed to set environment variable for any users")
            return False, False

    except Exception as e:
        print(f"❌ Failed to set system-wide environment variable: {e}")
        return False, False


def remove_env_var_from_user(username: str, home_dir: Path, var_name: str) -> bool:
    """Remove environment variable from a user's shell rc files."""
    try:
        rc_files = [
            home_dir / ".zprofile",
            home_dir / ".bash_profile"
        ]

        success = False
        export_prefix = f"export {var_name}="

        for rc_file in rc_files:
            if not rc_file.exists():
                continue

            try:
                with open(rc_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                new_lines = [l for l in lines if not l.strip().startswith(export_prefix)]

                if len(new_lines) < len(lines):
                    with open(rc_file, 'w', encoding='utf-8') as f:
                        f.writelines(new_lines)

                    # Set correct ownership
                    user_info = pwd.getpwnam(username)
                    os.chown(rc_file, user_info.pw_uid, user_info.pw_gid)

                    debug_print(f"Removed {var_name} from {rc_file}")
                    success = True
            except Exception as e:
                debug_print(f"Failed to update {rc_file}: {e}")

        return success
    except Exception as e:
        debug_print(f"Error removing env var for {username}: {e}")
        return False


def set_env_var_unix(var_name: str, value: str) -> Tuple[bool, bool]:
    if platform.system().lower() == "darwin" and os.geteuid() == 0:
        return set_env_var_system_wide_macos(var_name, value)

    # For other cases, use the per-user approach
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False, False

    exists_already = check_env_var_exists(rc_file, var_name, value)
    export_line = f'export {var_name}="{value}"'
    success = append_to_file(rc_file, export_line, var_name)
    return success, success and not exists_already


def set_env_var(var_name: str, value: str) -> Tuple[bool, bool, str]:
    system = platform.system().lower()

    if system == "windows":
        success = set_env_var_windows(var_name, value)
        if success:
            debug_print(f"Environment variable {var_name} set on Windows")
        msg = "Set for new terminals" if success else "Failed"
        return (success, True, msg)
    elif system in ["darwin", "linux"]:
        success, changed = set_env_var_unix(var_name, value)
        if success:
            # Check if we're running as root on macOS (system-wide setup)
            if system == "darwin" and os.geteuid() == 0:
                debug_print(f"Environment variable {var_name} set system-wide")
                return True, changed, "Set system-wide for all users"
            else:
                debug_print(f"Environment variable {var_name} added to shell rc file")
                shell_name = "zsh" if "zsh" in os.environ.get("SHELL", "") else "bash"
                return True, changed, f"Run 'source ~/.{shell_name}rc' or restart terminal"
        return False, False, "Failed"
    else:
        return False, False, f"Unsupported OS: {system}"


def compare_hooks_json(hooks_json_path: Path, new_content: str) -> bool:
    if not hooks_json_path.exists():
        return True
    try:
        with open(hooks_json_path, 'r', encoding='utf-8') as f:
            existing_content = f.read()
        existing = json.loads(existing_content)
        new = json.loads(new_content)
        return existing != new
    except Exception:
        return True


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


def setup_hooks() -> Tuple[bool, bool]:
    enterprise_dir = get_enterprise_hooks_dir()
    hooks_dir = enterprise_dir / "hooks"
    hooks_json = enterprise_dir / "hooks.json"
    script_path = hooks_dir / "unbound.py"
    temp_hooks_json = enterprise_dir / "hooks.json.tmp"

    debug_print(f"Enterprise hooks directory: {enterprise_dir}")
    debug_print(f"Hooks JSON path: {hooks_json}")
    debug_print(f"Script path: {script_path}")

    print("\n📥 Downloading hooks configuration...")
    if not download_file(HOOKS_URL, temp_hooks_json):
        return False, False

    hooks_changed = False
    try:
        with open(temp_hooks_json, 'r', encoding='utf-8') as f:
            new_hooks_content = f.read()
        hooks_changed = compare_hooks_json(hooks_json, new_hooks_content)
        hooks_json.parent.mkdir(parents=True, exist_ok=True)
        temp_hooks_json.replace(hooks_json)
    except Exception as e:
        debug_print(f"Failed to handle hooks.json: {e}")
        return False, False
    print("✅ hooks.json downloaded")

    print("📥 Downloading unbound.py script...")
    if not download_file(SCRIPT_URL, script_path):
        return False, hooks_changed
    print("✅ unbound.py downloaded")

    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
        print("✅ Made unbound.py executable")
    except Exception as e:
        print(f"⚠️  Could not make script executable: {e}")

    # Set proper permissions for hooks directory (allow users to write logs)
    try:
        os.chmod(hooks_dir, 0o775)
        debug_print(f"Set hooks directory permissions to 775")
        print("✅ Set hooks directory permissions")
    except Exception as e:
        print(f"⚠️  Could not set directory permissions: {e}")

    return True, hooks_changed


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


def clear_setup():
    """Remove hooks and environment variables set by the setup script."""
    print("=" * 60)
    print("Unbound Cursor Hooks - Clearing Setup")
    print("=" * 60)

    # Check admin privileges
    if not check_admin_privileges():
        print("❌ This script requires administrator/root privileges")
        print("   Please run with: sudo python3 setup.py --clear")
        return

    # Remove enterprise hooks files (NOT the entire Cursor directory)
    print("\n🗑️  Removing enterprise hooks...")
    enterprise_dir = get_enterprise_hooks_dir()
    hooks_json = enterprise_dir / "hooks.json"
    hooks_dir = enterprise_dir / "hooks"

    # Remove hooks.json
    if hooks_json.exists():
        try:
            hooks_json.unlink()
            print(f"✅ Removed {hooks_json}")
        except Exception as e:
            print(f"❌ Failed to remove {hooks_json}: {e}")
    else:
        print(f"   {hooks_json} does not exist")

    # Remove hooks directory
    if hooks_dir.exists():
        try:
            import shutil
            shutil.rmtree(hooks_dir)
            print(f"✅ Removed {hooks_dir}")
        except Exception as e:
            print(f"❌ Failed to remove {hooks_dir}: {e}")
    else:
        print(f"   {hooks_dir} does not exist")

    # Remove environment variable from all users
    print("\n🗑️  Removing environment variables...")
    user_homes = get_all_user_homes()

    if not user_homes:
        print("   No user home directories found")
    else:
        removed_count = 0
        for username, home_dir in user_homes:
            if remove_env_var_from_user(username, home_dir, "UNBOUND_CURSOR_API_KEY"):
                removed_count += 1

        if removed_count > 0:
            print(f"✅ Removed environment variable from {removed_count} user(s)")
        else:
            print("   No environment variables found to remove")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)

    # Restart Cursor
    restart_cursor()

    print("=" * 60)
    print("\nNote: Restart your terminal or log out/in for env var changes to take effect")
    print("=" * 60)


def fetch_api_key_from_mdm(base_url: str, app_name: str, auth_api_key: str, serial_number: str) -> str:
    """Fetch API key from MDM endpoint."""
    params = f"serial_number={serial_number}&app_type=cursor"
    if app_name:
        params = f"app_name={app_name}&{params}"
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"

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

    # Check for --clear flag first
    clear_mode = "--clear" in sys.argv

    debug_mode = "--debug" in sys.argv
    if debug_mode:
        DEBUG = True
        debug_print("Debug mode enabled")

    # If clear mode, run cleanup and exit
    if clear_mode:
        clear_setup()
        return

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

    if not base_url or not auth_api_key:
        print("\n❌ Missing required arguments")
        print("Usage: sudo python3 setup.py --url <base_url> --api_key <api_key> [--app_name <app_name>] [--debug]")
        print("   Or: sudo python3 setup.py --clear [--debug]")
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
    success, env_changed, message = set_env_var("UNBOUND_CURSOR_API_KEY", cursor_api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return
    print(f"✅ Environment variable set ({message})")

    # Setup hooks
    debug_print("Setting up hooks...")
    hooks_success, hooks_changed = setup_hooks()
    if not hooks_success:
        print("\n❌ Failed to setup hooks")
        return
    debug_print("Hooks setup complete")

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    if env_changed or hooks_changed:
        debug_print(f"Restart needed: env_changed={env_changed}, hooks_changed={hooks_changed}")
        restart_cursor()
    else:
        debug_print("No changes detected, skipping restart")

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
