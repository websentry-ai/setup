#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import json
import pwd
from pathlib import Path
from typing import Tuple, List, Optional

DEBUG = True


def debug_print(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}")


def check_admin_privileges() -> bool:
    try:
        if platform.system().lower() in ["darwin", "linux"]:
            return os.geteuid() == 0
        return False
    except Exception as e:
        debug_print(f"Failed to check privileges: {e}")
        return False


def get_device_identifier() -> Optional[str]:
    system = platform.system().lower()
    try:
        if system == "darwin":
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Serial Number' in line:
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            serial = parts[1].strip()
                            if serial:
                                return serial
            return None

        elif system == "linux":
            try:
                result = subprocess.run(
                    ["dmidecode", "-s", "system-serial-number"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    stderr=subprocess.DEVNULL
                )
                if result.returncode == 0:
                    device_id = result.stdout.strip()
                    if device_id:
                        return device_id
            except Exception:
                debug_print("dmidecode failed, trying machine-id")

            for machine_id_path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
                try:
                    with open(machine_id_path, 'r', encoding='utf-8') as f:
                        device_id = f.read().strip()
                        if device_id:
                            return device_id
                except Exception:
                    continue

            try:
                result = subprocess.run(
                    ["hostname"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    hostname = result.stdout.strip()
                    if hostname:
                        return hostname
            except Exception:
                pass

            return None

        elif system == "windows":
            try:
                result = subprocess.run(
                    ["powershell", "-Command",
                     "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    serial = result.stdout.strip()
                    if serial:
                        return serial
            except Exception:
                debug_print("PowerShell BIOS query failed, trying registry")

            try:
                result = subprocess.run(
                    ["reg", "query", "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "/v", "ProcessorNameString"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception:
                pass

            return None

    except Exception as e:
        debug_print(f"Failed to get device identifier: {e}")
        return None


def get_all_user_homes() -> List[Tuple[str, Path]]:
    user_homes = []
    system = platform.system().lower()

    try:
        if system == "darwin":
            for user in pwd.getwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)

                if uid >= 500 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith('/Users/') and username not in ['Shared', 'Guest']:
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "linux":
            for user in pwd.getwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)

                if uid >= 1000 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith('/home/'):
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "windows":
            users_dir = Path("C:/Users")
            if users_dir.exists():
                try:
                    for user_dir in users_dir.iterdir():
                        if user_dir.is_dir() and user_dir.name not in ['Public', 'Default', 'Default User', 'Administrator']:
                            user_homes.append((user_dir.name, user_dir))
                            debug_print(f"Found user: {user_dir.name} -> {user_dir}")
                except Exception as e:
                    debug_print(f"Error scanning Windows users directory: {e}")

        return user_homes
    except Exception as e:
        debug_print(f"Error enumerating users: {e}")
        return []


def append_to_file(file_path: Path, line: str, var_name: str = None) -> bool:
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                lines = []

        if var_name:
            export_prefix = f"export {var_name}="
            lines = [l for l in lines if not l.strip().startswith(export_prefix)]

        normalized_line = line.rstrip()
        line_exists = any(l.rstrip() == normalized_line for l in lines)

        if not line_exists:
            lines.append(f"{line}\n")
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True
        elif var_name:
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True

        return True
    except Exception as e:
        print(f"❌ Failed to modify {file_path}: {e}")
        return False


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


def set_env_var_for_user(username: str, home_dir: Path, var_name: str, value: str) -> Tuple[bool, bool]:
    system = platform.system().lower()
    try:
        if system == "darwin":
            rc_files = [home_dir / ".zprofile", home_dir / ".bash_profile"]
            debug_print(f"Writing to shell files: {[str(f) for f in rc_files]}")
            user_success = False
            user_changed = False
            export_line = f'export {var_name}="{value}"'

            for rc_file in rc_files:
                try:
                    exists_already = check_env_var_exists(rc_file, var_name, value)
                    if append_to_file(rc_file, export_line, var_name):
                        try:
                            user_info = pwd.getpwnam(username)
                            os.chown(rc_file, user_info.pw_uid, user_info.pw_gid)
                            os.chmod(rc_file, 0o644)
                        except Exception as e:
                            debug_print(f"Failed to set ownership on {rc_file}: {e}")

                        debug_print(f"Updated {rc_file} for {username}")
                        user_success = True
                        if not exists_already:
                            user_changed = True
                except Exception as e:
                    debug_print(f"Failed to update {rc_file}: {e}")

            return user_success, user_changed

        elif system == "linux":
            rc_files = [home_dir / ".zshrc", home_dir / ".bashrc"]
            debug_print(f"Writing to shell files: {[str(f) for f in rc_files]}")
            user_success = False
            user_changed = False
            export_line = f'export {var_name}="{value}"'

            for rc_file in rc_files:
                try:
                    exists_already = check_env_var_exists(rc_file, var_name, value)
                    if append_to_file(rc_file, export_line, var_name):
                        try:
                            user_info = pwd.getpwnam(username)
                            os.chown(rc_file, user_info.pw_uid, user_info.pw_gid)
                            os.chmod(rc_file, 0o644)
                        except Exception as e:
                            debug_print(f"Failed to set ownership on {rc_file}: {e}")

                        debug_print(f"Updated {rc_file} for {username}")
                        user_success = True
                        if not exists_already:
                            user_changed = True
                except Exception as e:
                    debug_print(f"Failed to update {rc_file}: {e}")

            return user_success, user_changed

        elif system == "windows":
            debug_print(f"Writing to system registry (Windows)")
            try:
                subprocess.run(
                    ["setx", var_name, value, "/M"],
                    check=False,
                    capture_output=True,
                    timeout=10
                )
                debug_print(f"Set {var_name} system-wide on Windows")
                return True, True
            except Exception as e:
                debug_print(f"Failed to set {var_name} on Windows: {e}")
                return False, False

    except Exception as e:
        debug_print(f"Error setting env var for {username}: {e}")
        return False, False


def set_env_var_system_wide(var_name: str, value: str) -> Tuple[bool, bool]:
    try:
        user_homes = get_all_user_homes()

        if not user_homes:
            print("⚠️  No user home directories found")
            return False, False

        success_count = 0
        changed_count = 0

        for username, home_dir in user_homes:
            debug_print(f"Setting {var_name} for user: {username}")
            success, changed = set_env_var_for_user(username, home_dir, var_name, value)
            if success:
                success_count += 1
            if changed:
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


def fetch_api_key_from_mdm(base_url: str, app_name: str, auth_api_key: str, device_id: str) -> Optional[str]:
    params = f"serial_number={device_id}&app_type=default"
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


def remove_env_var_from_user(username: str, home_dir: Path, var_name: str) -> bool:
    system = platform.system().lower()
    try:
        if system == "darwin":
            rc_files = [home_dir / ".zprofile", home_dir / ".bash_profile"]
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

                        try:
                            user_info = pwd.getpwnam(username)
                            os.chown(rc_file, user_info.pw_uid, user_info.pw_gid)
                        except Exception:
                            pass

                        debug_print(f"Removed {var_name} from {rc_file}")
                        success = True
                except Exception as e:
                    debug_print(f"Failed to update {rc_file}: {e}")

            return success

        elif system == "linux":
            rc_files = [home_dir / ".zshrc", home_dir / ".bashrc"]
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

                        try:
                            user_info = pwd.getpwnam(username)
                            os.chown(rc_file, user_info.pw_uid, user_info.pw_gid)
                        except Exception:
                            pass

                        debug_print(f"Removed {var_name} from {rc_file}")
                        success = True
                except Exception as e:
                    debug_print(f"Failed to update {rc_file}: {e}")

            return success

        elif system == "windows":
            try:
                subprocess.run(
                    ["reg", "delete", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "/F", "/V", var_name],
                    check=False,
                    capture_output=True,
                    timeout=10
                )
                debug_print(f"Removed {var_name} from system environment")
                return True
            except Exception as e:
                debug_print(f"Failed to remove {var_name}: {e}")
                return False

    except Exception as e:
        debug_print(f"Error removing env var for {username}: {e}")
        return False


def clear_setup():
    print("=" * 60)
    print("Gemini CLI - Clearing MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        print("❌ This script requires administrator/root privileges")
        print("   Please run with: sudo python3 setup.py --clear")
        return

    print("\n🗑️  Removing environment variables...")
    user_homes = get_all_user_homes()

    if not user_homes:
        print("   No user home directories found")
    else:
        removed_count = 0
        for username, home_dir in user_homes:
            if remove_env_var_from_user(username, home_dir, "GEMINI_API_KEY"):
                removed_count += 1
            remove_env_var_from_user(username, home_dir, "GOOGLE_GEMINI_BASE_URL")

        if removed_count > 0:
            print(f"✅ Removed environment variables from {removed_count} user(s)")
        else:
            print("   No environment variables found to remove")

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

    print("=" * 60)
    print("Gemini CLI - MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        system = platform.system().lower()
        if system in ["darwin", "linux"]:
            print("❌ This script requires administrator/root privileges")
            print("   Please run with: sudo python3 setup.py ...")
        else:
            print("❌ This script requires administrator privileges")
            print("   Please run as Administrator")
        return

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

    print("\n🔍 Getting device identifier...")
    device_id = get_device_identifier()
    if not device_id:
        print("❌ Failed to get device identifier")
        return
    debug_print(f"Device identifier: {device_id}")
    print("✅ Device identifier retrieved")

    print("\n🔑 Fetching API key from MDM...")
    gemini_api_key = fetch_api_key_from_mdm(base_url, app_name, auth_api_key, device_id)
    if not gemini_api_key:
        return
    print("✅ API key received")

    print("\n📝 Setting environment variables system-wide...")
    success, env_changed = set_env_var_system_wide("GEMINI_API_KEY", gemini_api_key)
    if not success:
        print(f"❌ Failed to set GEMINI_API_KEY")
        return
    debug_print("GEMINI_API_KEY set successfully")

    success, url_changed = set_env_var_system_wide("GOOGLE_GEMINI_BASE_URL", "https://api.getunbound.ai/v1")
    if not success:
        print(f"❌ Failed to set GOOGLE_GEMINI_BASE_URL")
        return
    debug_print("GOOGLE_GEMINI_BASE_URL set successfully")

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled by user.")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        exit(1)
