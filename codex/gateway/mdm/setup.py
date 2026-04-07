#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import json
import pwd
from pathlib import Path
from typing import Tuple, List, Optional

DEBUG = False


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


def _update_toml_root_key(lines, key_name, key_line):
    """Update or insert a root-level key in TOML lines.
    Only matches keys in the root section (before any [table] headers).
    Returns the modified lines list."""
    in_section = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = True
        if not in_section and stripped.startswith(key_name):
            lines[i] = key_line + "\n"
            return lines

    # Key not found in root — insert before the first [table] header
    insert_idx = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("["):
            insert_idx = i
            break
    else:
        insert_idx = len(lines)
    lines.insert(insert_idx, key_line + "\n")
    return lines


def _remove_toml_root_key(lines, key_name):
    """Remove a root-level key from TOML lines.
    Only removes keys in the root section (before any [table] headers).
    Returns (new_lines, was_removed)."""
    new_lines = []
    removed = False
    in_section = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = True
        if not in_section and stripped.startswith(key_name):
            removed = True
            continue
        new_lines.append(line)
    return new_lines, removed


def write_codex_config_for_user(username: str, home_dir: Path, base_url: str) -> bool:
    """Write openai_base_url to {home_dir}/.codex/config.toml for a specific user."""
    config_dir = home_dir / ".codex"
    config_file = config_dir / "config.toml"
    key_line = f'openai_base_url = "{base_url}"'
    try:
        config_dir.mkdir(mode=0o755, parents=True, exist_ok=True)

        if config_file.exists():
            with open(config_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            lines = _update_toml_root_key(lines, "openai_base_url", key_line)
            with open(config_file, "w", encoding="utf-8") as f:
                f.writelines(lines)
        else:
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(key_line + "\n")

        os.chmod(config_file, 0o644)

        try:
            user_info = pwd.getpwnam(username)
            os.chown(config_dir, user_info.pw_uid, user_info.pw_gid)
            os.chown(config_file, user_info.pw_uid, user_info.pw_gid)
        except Exception as e:
            debug_print(f"Could not chown codex config for {username}: {e}")

        debug_print(f"Wrote openai_base_url to {config_file} for {username}")
        return True
    except Exception as e:
        debug_print(f"Failed to write codex config for {username}: {e}")
        return False


def remove_codex_config_base_url_for_user(username: str, home_dir: Path) -> bool:
    """Remove openai_base_url from {home_dir}/.codex/config.toml.
    Returns True if the key was found and removed, False otherwise."""
    config_file = home_dir / ".codex" / "config.toml"
    try:
        if not config_file.exists():
            return False
        with open(config_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines, removed = _remove_toml_root_key(lines, "openai_base_url")
        if removed:
            with open(config_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            try:
                user_info = pwd.getpwnam(username)
                os.chown(config_file, user_info.pw_uid, user_info.pw_gid)
            except Exception:
                pass
            debug_print(f"Removed openai_base_url from {config_file} for {username}")
        return removed
    except Exception as e:
        debug_print(f"Failed to update codex config for {username}: {e}")
        return False


def clear_setup():
    print("=" * 60)
    print("Codex - Clearing MDM Setup")
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
            if remove_env_var_from_user(username, home_dir, "OPENAI_API_KEY"):
                removed_count += 1
            # Remove OPENAI_BASE_URL env var for backwards compatibility (old setups)
            remove_env_var_from_user(username, home_dir, "OPENAI_BASE_URL")
            # Remove openai_base_url from codex config.toml
            remove_codex_config_base_url_for_user(username, home_dir)

        if removed_count > 0:
            print(f"✅ Removed environment variables from {removed_count} user(s)")
        else:
            print("   No environment variables found to remove")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def remove_hooks_unbound_script_for_user(username: str, home_dir: Path) -> None:
    """Remove ~/.codex/hooks/unbound.py for a given user (leftover from hooks setup)."""
    script_path = home_dir / ".codex" / "hooks" / "unbound.py"
    if script_path.exists():
        try:
            script_path.unlink()
            debug_print(f"Removed {script_path} for {username}")
        except Exception as e:
            debug_print(f"Failed to remove {script_path}: {e}")


def get_managed_settings_dir() -> Path:
    """Get the system-wide managed settings directory for Codex."""
    system = platform.system().lower()
    if system == "darwin":
        return Path("/Library/Application Support/Codex")
    elif system == "linux":
        return Path("/etc/codex")
    elif system == "windows":
        return Path("C:/Program Files/Codex")
    else:
        raise OSError(f"Unsupported operating system: {system}")


def clear_managed_hooks() -> bool:
    """Remove the hooks script and hooks setting from managed Codex config."""
    try:
        managed_dir = get_managed_settings_dir()
        settings_path = managed_dir / "hooks.json"
        hooks_dir = managed_dir / "hooks"
        script_path = hooks_dir / "unbound.py"

        removed_any = False

        # Remove the hook script
        if script_path.exists():
            try:
                script_path.unlink()
                debug_print(f"Removed {script_path}")
                removed_any = True
            except Exception as e:
                debug_print(f"Failed to remove {script_path}: {e}")

        # Try to remove hooks directory if empty
        if hooks_dir.exists():
            try:
                if not any(hooks_dir.iterdir()):
                    hooks_dir.rmdir()
                    debug_print(f"Removed empty directory {hooks_dir}")
            except Exception as e:
                debug_print(f"Could not remove directory {hooks_dir}: {e}")

        # Remove hooks from hooks.json (keep the file)
        if settings_path.exists():
            try:
                with open(settings_path, "r", encoding="utf-8") as f:
                    settings = json.load(f)
                changed = False
                if "hooks" in settings:
                    del settings["hooks"]
                    changed = True
                if changed:
                    with open(settings_path, "w", encoding="utf-8") as f:
                        json.dump(settings, f, indent=2)
                    debug_print("Removed hooks from hooks.json")
                    removed_any = True
            except Exception as e:
                debug_print(f"Failed to update hooks.json: {e}")

        return removed_any

    except Exception as e:
        debug_print(f"Error clearing managed hooks: {e}")
        return False


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
    print("Codex - MDM Setup")
    print("=" * 60)

    if not check_admin_privileges():
        system = platform.system().lower()
        if system in ["darwin", "linux"]:
            print("❌ This script requires administrator/root privileges")
            print("   Please re-run with sudo.")
        else:
            print("❌ This script requires administrator privileges")
            print("   Please run as Administrator")
        return

    base_url = "https://backend.getunbound.ai"
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

    if not auth_api_key:
        print("\n❌ Missing required arguments")
        print("Usage: sudo python3 setup.py --api_key <api_key> [--url <base_url>] [--app_name <app_name>] [--debug]")
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
    codex_api_key = fetch_api_key_from_mdm(base_url, app_name, auth_api_key, device_id)
    if not codex_api_key:
        return
    print("✅ API key received")

    # Remove leftover hooks setup env var
    for username, home_dir in get_all_user_homes():
        remove_env_var_from_user(username, home_dir, "UNBOUND_CODEX_API_KEY")

    print("\n📝 Setting environment variables system-wide...")
    success, env_changed = set_env_var_system_wide("OPENAI_API_KEY", codex_api_key)
    if not success:
        print(f"❌ Failed to set OPENAI_API_KEY")
        return
    debug_print("OPENAI_API_KEY set successfully")

    print("\n📝 Configuring all users...")
    user_homes = get_all_user_homes()
    if not user_homes:
        print("❌ No user home directories found")
        return
    config_count = 0
    for username, home_dir in user_homes:
        if write_codex_config_for_user(username, home_dir, "https://api.getunbound.ai/v1"):
            config_count += 1
        remove_hooks_unbound_script_for_user(username, home_dir)
        write_unbound_config_for_user(username, home_dir, codex_api_key)

    if config_count == 0:
        print("❌ Failed to configure codex for any users")
        return

    print(f"✅ Configured {config_count} user(s)")

    # Remove managed hooks if present (leftover from hooks MDM setup)
    clear_managed_hooks()

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
