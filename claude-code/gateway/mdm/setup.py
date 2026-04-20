#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import json
from pathlib import Path
from typing import Tuple, List, Optional
try:
    import pwd
except ImportError:
    pwd = None

DEBUG = False


def debug_print(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}")


def check_admin_privileges() -> bool:
    try:
        system = platform.system().lower()
        if system in ["darwin", "linux"]:
            return os.geteuid() == 0
        if system == "windows":
            import ctypes
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
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
                    ["powershell", "-NoProfile", "-Command",
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
                debug_print("PowerShell BIOS query failed, trying registry MachineGuid")

            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Cryptography") as key:
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if value:
                        return str(value).strip()
            except Exception:
                debug_print("MachineGuid registry read failed, falling back to hostname")

            try:
                import socket
                return socket.gethostname()
            except Exception:
                return None

    except Exception as e:
        debug_print(f"Failed to get device identifier: {e}")
        return None


def get_all_user_homes() -> List[Tuple[str, Path]]:
    user_homes = []
    system = platform.system().lower()

    try:
        if system == "darwin":
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)

                if uid >= 500 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith('/Users/') and username not in ['Shared', 'Guest']:
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "linux":
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)

                if uid >= 1000 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith('/home/'):
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "windows":
            system_drive = os.environ.get("SystemDrive", "C:")
            users_dir = Path(system_drive + r"\Users")
            if users_dir.exists():
                try:
                    for user_dir in users_dir.iterdir():
                        if user_dir.is_dir() and user_dir.name not in ['Public', 'Default', 'Default User', 'Administrator', 'All Users']:
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
        # On Windows, `setx /M` writes machine-wide in one call — no per-user iteration.
        if platform.system().lower() == "windows":
            return set_env_var_for_user(None, None, var_name, value)

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
            ["curl", "-fsSL", "-K", "-", "-w", "\n%{http_code}", url],
            input=f'header = "Authorization: Bearer {auth_api_key}"\n',
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
        debug_print(f"Response length: {len(response_body)}")

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


def write_unbound_config_for_user(username: str, home_dir: Path, api_key: str) -> None:
    """Write API key to ~/.unbound/config.json for a given user."""
    config_dir = home_dir / ".unbound"
    config_file = config_dir / "config.json"
    try:
        if platform.system().lower() == "windows":
            config_dir.mkdir(parents=True, exist_ok=True)
            config = {}
            if config_file.exists():
                try:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config = json.loads(f.read())
                except (json.JSONDecodeError, OSError):
                    config = {}
            config['api_key'] = api_key
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(json.dumps(config, indent=2))
            return

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
        try:
            user_info = pwd.getpwnam(username)
            os.chown(config_dir, user_info.pw_uid, user_info.pw_gid)
            os.chown(config_file, user_info.pw_uid, user_info.pw_gid)
        except Exception as e:
            debug_print(f"Could not chown config files for {username}: {e}")
    except Exception as e:
        debug_print(f"Could not write config for {username}: {e}")


def remove_hooks_unbound_script_for_user(username: str, home_dir: Path) -> None:
    """Remove ~/.claude/hooks/unbound.py for a given user (leftover from hooks setup)."""
    script_path = home_dir / ".claude" / "hooks" / "unbound.py"
    if script_path.exists():
        try:
            script_path.unlink()
            debug_print(f"Removed {script_path} for {username}")
        except Exception as e:
            debug_print(f"Failed to remove {script_path}: {e}")


def get_managed_settings_dir() -> Path:
    """Get the system-wide managed settings directory for Claude Code."""
    system = platform.system().lower()
    if system == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    elif system == "linux":
        return Path("/etc/claude-code")
    elif system == "windows":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        return Path(program_files) / "ClaudeCode"
    else:
        raise OSError(f"Unsupported operating system: {system}")


def setup_managed_settings() -> bool:
    """
    Set up system-wide managed settings for Claude Code.
    Creates managed-settings.json and anthropic_key.sh in the system location.
    """
    system = platform.system().lower()
    try:
        managed_dir = get_managed_settings_dir()
        key_helper_path = managed_dir / "anthropic_key.sh"

        # Pick settings path: on Windows prefer the drop-in dir so we don't
        # clobber an existing managed-settings.json; fall back to the flat
        # file only if the drop-in dir can't be created.
        if system == "windows":
            dropin_dir = managed_dir / "managed-settings.d"
            try:
                dropin_dir.mkdir(parents=True, exist_ok=True)
                settings_path = dropin_dir / "unbound.json"
            except Exception as e:
                debug_print(f"Could not create drop-in dir, falling back: {e}")
                managed_dir.mkdir(parents=True, exist_ok=True)
                settings_path = managed_dir / "managed-settings.json"
        else:
            managed_dir.mkdir(parents=True, exist_ok=True)
            settings_path = managed_dir / "managed-settings.json"
        debug_print(f"Created managed settings directory: {managed_dir}")

        # Create anthropic_key.sh script
        key_helper_path.parent.mkdir(parents=True, exist_ok=True)
        key_helper_path.write_text("echo $UNBOUND_API_KEY", encoding="utf-8")
        debug_print(f"Created key helper script: {key_helper_path}")

        # Make script executable on Unix systems
        if system in ["darwin", "linux"]:
            os.chmod(key_helper_path, 0o755)
            debug_print("Set script as executable")

        # Create managed-settings.json
        settings = {
            "apiKeyHelper": str(key_helper_path)
        }
        settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        debug_print(f"Created managed settings: {settings_path}")

        # Set permissions - readable by all users
        if system in ["darwin", "linux"]:
            os.chmod(managed_dir, 0o755)
            os.chmod(settings_path, 0o644)
            os.chmod(key_helper_path, 0o755)

        return True

    except Exception as e:
        print(f"❌ Failed to setup managed settings: {e}")
        debug_print(f"Error details: {e}")
        return False


def clear_managed_settings() -> bool:
    """Remove the apiKeyHelper script and setting from managed Claude config."""
    try:
        managed_dir = get_managed_settings_dir()
        key_helper_path = managed_dir / "anthropic_key.sh"

        # Potential settings files: drop-in (Windows) and the flat file.
        settings_candidates = [
            managed_dir / "managed-settings.d" / "unbound.json",
            managed_dir / "managed-settings.json",
        ]

        removed_any = False

        # Remove the key helper script
        if key_helper_path.exists():
            try:
                key_helper_path.unlink()
                debug_print(f"Removed {key_helper_path}")
                removed_any = True
            except Exception as e:
                debug_print(f"Failed to remove {key_helper_path}: {e}")

        for settings_path in settings_candidates:
            if not settings_path.exists():
                continue
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    settings = json.load(f)
                if "apiKeyHelper" in settings:
                    del settings["apiKeyHelper"]
                    # If this is our drop-in file and nothing else is left,
                    # remove it to avoid leaving an empty config file around.
                    if (settings_path.name == "unbound.json"
                            and settings_path.parent.name == "managed-settings.d"
                            and not settings):
                        settings_path.unlink()
                        debug_print(f"Removed empty drop-in {settings_path}")
                    else:
                        with open(settings_path, "w", encoding="utf-8") as f:
                            json.dump(settings, f, indent=2)
                        debug_print(f"Removed apiKeyHelper from {settings_path}")
                    removed_any = True
            except Exception as e:
                debug_print(f"Failed to update {settings_path}: {e}")

        return removed_any

    except Exception as e:
        debug_print(f"Error clearing managed settings: {e}")
        return False


def clear_setup():
    print("=" * 60)
    print("Claude Code - Clearing MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        print("❌ This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return

    print("\n🗑️  Removing environment variables...")
    user_homes = get_all_user_homes()

    if not user_homes:
        print("   No user home directories found")
    else:
        removed_count = 0
        for username, home_dir in user_homes:
            if remove_env_var_from_user(username, home_dir, "UNBOUND_API_KEY"):
                removed_count += 1
            remove_env_var_from_user(username, home_dir, "ANTHROPIC_BASE_URL")

        if removed_count > 0:
            print(f"✅ Removed environment variables from {removed_count} user(s)")
        else:
            print("   No environment variables found to remove")

    # Remove managed settings
    print("\n🗑️  Removing managed settings...")
    if clear_managed_settings():
        managed_dir = get_managed_settings_dir()
        print(f"✅ Removed managed settings from {managed_dir}")
    else:
        print("   No managed settings found to remove")

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
    print("Claude Code - MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        if platform.system().lower() == "windows":
            sys.exit(
                "Error: MDM setup requires an elevated shell on Windows. "
                "Right-click PowerShell \u2192 Run as Administrator, then rerun."
            )
        print("❌ This script requires administrator/root privileges")
        print("   Please re-run with sudo.")
        return

    base_url = "https://backend.getunbound.ai"
    app_name = None
    auth_api_key = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--backend-url" and i + 1 < len(args):
            base_url = args[i + 1]
            i += 2
        elif args[i] == "--app_name" and i + 1 < len(args):
            app_name = args[i + 1]
            i += 2
        elif args[i] == "--api-key" and i + 1 < len(args):
            auth_api_key = args[i + 1]
            i += 2
        elif args[i] == "--debug":
            i += 1
        else:
            i += 1

    if not auth_api_key:
        print("\n❌ Missing required argument: --api-key")
        print("Usage: sudo python3 setup.py --api-key <api_key> [--backend-url <url>] [--app_name <app_name>] [--debug]")
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
    claude_api_key = fetch_api_key_from_mdm(base_url, app_name, auth_api_key, device_id)
    if not claude_api_key:
        return
    print("✅ API key received")

    print("\n📝 Setting environment variables system-wide...")
    # Remove leftover hooks setup env var
    for username, home_dir in get_all_user_homes():
        remove_env_var_from_user(username, home_dir, "UNBOUND_CLAUDE_API_KEY")

    success, env_changed = set_env_var_system_wide("UNBOUND_API_KEY", claude_api_key)
    if not success:
        print(f"❌ Failed to set UNBOUND_API_KEY")
        return
    debug_print("UNBOUND_API_KEY set successfully")

    success, url_changed = set_env_var_system_wide("ANTHROPIC_BASE_URL", "https://api.getunbound.ai")
    if not success:
        print(f"❌ Failed to set ANTHROPIC_BASE_URL")
        return
    debug_print("ANTHROPIC_BASE_URL set successfully")

    # Remove leftover hooks scripts and write unbound config for all users
    for username, home_dir in get_all_user_homes():
        remove_hooks_unbound_script_for_user(username, home_dir)
        write_unbound_config_for_user(username, home_dir, claude_api_key)

    print("\n🔧 Configuring Claude managed settings...")
    if setup_managed_settings():
        managed_dir = get_managed_settings_dir()
        print(f"✅ Created managed settings in {managed_dir}")
    else:
        print("❌ Failed to configure managed settings")
        return

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    notify_setup_complete(claude_api_key, "unbound-claude-code", backend_url=base_url)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        exit(1)
