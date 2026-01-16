#!/usr/bin/env python3
"""
Claude Code - Environment Setup Script (with API Key)
"""

import os
import platform
import subprocess
import json
from pathlib import Path
from typing import Tuple
import argparse


DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def get_shell_rc_file() -> Path:
    """
    Determine the appropriate shell configuration file based on the OS and shell.

    Returns:
        Path: Path to the shell configuration file
    """
    system = platform.system().lower()
    shell = os.environ.get("SHELL", "").lower()

    if system == "darwin":
        # macOS - default shell is zsh
        if "zsh" in shell:
            return Path.home() / ".zprofile"
        else:
            return Path.home() / ".bash_profile"

    elif system == "linux":
        # Linux
        if "zsh" in shell:
            return Path.home() / ".zshrc"
        else:
            return Path.home() / ".bashrc"

    elif system == "windows":
        # Windows - uses registry, no rc file
        return None

    else:
        raise OSError(f"Unsupported operating system: {system}")


def append_to_file(file_path: Path, line: str) -> bool:
    """
    Append a line to a file only if it's not already present.

    Args:
        file_path: Path to the file to append to
        line: Line to append (without newline)

    Returns:
        bool: True if line was added, False if it already existed
    """
    try:
        file_path.touch(exist_ok=True)

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if line not in content:
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(f"{line}\n")
            return True
        else:
            return False
    except Exception as e:
        print(f"❌ Failed to modify {file_path}: {e}")
        return False


def set_env_var_on_windows(var_name: str, value: str) -> bool:
    """
    Set environment variable permanently on Windows using setx.

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        subprocess.run(["setx", var_name, value], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to set {var_name} on Windows: {e}")
        if e.stderr:
            print(f"   Error details: {e.stderr.decode()}")
        return False
    except FileNotFoundError:
        print(f"❌ 'setx' command not found. Please set {var_name} manually.")
        return False


def set_env_var_on_unix(var_name: str, value: str) -> bool:
    """
    Set environment variable permanently on Unix-like systems (macOS, Linux).

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        bool: True if successful, False otherwise
    """
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False

    export_line = f'export {var_name}="{value}"'

    was_added = append_to_file(rc_file, export_line)

    if was_added:
        return True
    else:
        return True


def set_env_var(var_name: str, value: str) -> Tuple[bool, str]:
    """
    Set an environment variable permanently across all OS platforms.

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        Tuple[bool, str]: (success, message)
    """
    system = platform.system().lower()

    if system == "windows":
        success = set_env_var_on_windows(var_name, value)
        if success:
            return True, "Environment variable set for new terminals"
        else:
            return False, "Failed to set environment variable"

    elif system in ["darwin", "linux"]:
        success = set_env_var_on_unix(var_name, value)
        if success:
            shell_name = "zsh" if "zsh" in os.environ.get("SHELL", "") else "bash"
            return True, f"Run 'source ~/.{shell_name}rc' or restart terminal"
        else:
            return False, "Failed to set environment variable"

    else:
        return False, f"Unsupported OS: {system}"


def remove_env_var_on_unix(var_name: str) -> bool:
    """
    Remove an environment variable export line from the user's shell rc file.
    """
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False
    try:
        rc_file.touch(exist_ok=True)
        with open(rc_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = []
        removed = False
        export_prefix = f"export {var_name}="
        for line in lines:
            if line.strip().startswith(export_prefix):
                removed = True
                continue
            new_lines.append(line)
        if removed:
            with open(rc_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        return True
    except Exception as e:
        print(f"❌ Failed to modify {rc_file}: {e}")
        return False


def remove_env_var_on_windows(var_name: str) -> bool:
    """
    Remove a user environment variable on Windows by deleting it from HKCU\\Environment.
    """
    try:
        subprocess.run(["reg", "delete", "HKCU\\Environment", "/F", "/V", var_name], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        # If it doesn't exist, treat as success
        return True
    except FileNotFoundError:
        print("❌ 'reg' command not found. Please remove the variable manually.")
        return False


def remove_env_var(var_name: str) -> Tuple[bool, str]:
    """
    Remove an environment variable permanently across OS platforms.
    """
    system = platform.system().lower()
    if system == "windows":
        success = remove_env_var_on_windows(var_name)
        if success:
            debug_print(f"Removed {var_name} from Windows registry")
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    elif system in ["darwin", "linux"]:
        success = remove_env_var_on_unix(var_name)
        if success:
            debug_print(f"Removed {var_name} from shell rc file")
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    else:
        return False, f"Unsupported OS: {system}"


def verify_api_key(api_key: str) -> bool:
    """
    Verify the API key by making a request to the /models endpoint.

    Args:
        api_key: The API key to verify

    Returns:
        True if valid, False otherwise
    """
    import urllib.request
    import urllib.error

    if not api_key or len(api_key) == 0:
        print("❌ API key is empty")
        return False

    try:
        url = "https://api.getunbound.ai/v1/models"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Unbound CLI"
        }

        request = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())

                # Check if response has data (models)
                if data and isinstance(data, dict) and "data" in data:
                    if isinstance(data["data"], list) and len(data["data"]) > 0:
                        return True
                # Also check if data is a list directly
                elif data and isinstance(data, list) and len(data) > 0:
                    return True
                # Or if it's an object
                elif data and isinstance(data, dict):
                    return True

                return False
            else:
                print(f"❌ API key verification failed: {response.status}")
                return False

    except urllib.error.HTTPError as e:
        print(f"❌ API key verification failed: {e.code} {e.reason}")
        try:
            error_data = json.loads(e.read().decode())
            if "error" in error_data and "message" in error_data["error"]:
                print(f"   Error: {error_data['error']['message']}")
        except:
            pass
        return False
    except Exception as e:
        print(f"❌ API key verification failed: {e}")
        return False


def setup_claude_key_helper() -> None:
    """
    Create ~/.claude/anthropic_key.sh that echoes UNBOUND_API_KEY and
    update ~/.claude/settings.json with apiKeyHelper pointing to that script.
    """
    claude_dir = Path.home() / ".claude"
    settings_path = claude_dir / "settings.json"
    key_helper_path = claude_dir / "anthropic_key.sh"

    try:
        claude_dir.mkdir(parents=True, exist_ok=True)

        # Write anthropic_key.sh
        key_helper_path.write_text("echo $UNBOUND_API_KEY", encoding="utf-8")
        try:
            current_mode = key_helper_path.stat().st_mode
            os.chmod(key_helper_path, current_mode | 0o111)
        except Exception:
            pass

        # Read existing settings.json if present
        settings = {}
        if settings_path.exists():
            try:
                settings = json.loads(settings_path.read_text(encoding="utf-8")) or {}
            except Exception:
                settings = {}

        # Remove hooks if present before adding apiKeyHelper
        if "hooks" in settings:
            del settings["hooks"]

        # Update apiKeyHelper
        settings["apiKeyHelper"] = "~/.claude/anthropic_key.sh"

        settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"⚠️  Failed to configure Claude Code key helper: {e}")


def remove_claude_key_helper() -> None:
    """Remove the apiKeyHelper script and setting from Claude config."""
    claude_dir = Path.home() / ".claude"
    key_helper_path = claude_dir / "anthropic_key.sh"
    settings_path = claude_dir / "settings.json"

    # Remove the key helper script
    if key_helper_path.exists():
        try:
            key_helper_path.unlink()
            debug_print(f"Removed {key_helper_path}")
            print(f"✅ Removed {key_helper_path}")
        except Exception as e:
            print(f"❌ Failed to remove {key_helper_path}: {e}")

    # Remove apiKeyHelper from settings.json
    if settings_path.exists():
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
            if "apiKeyHelper" in settings:
                del settings["apiKeyHelper"]
                with open(settings_path, "w", encoding="utf-8") as f:
                    json.dump(settings, f, indent=2)
                debug_print("Removed apiKeyHelper from settings.json")
                print("✅ Removed apiKeyHelper from settings.json")
        except Exception as e:
            print(f"❌ Failed to update settings.json: {e}")


def clear_setup() -> None:
    """Undo all changes made by the setup script."""
    print("=" * 60)
    print("Claude Code - Clearing Setup")
    print("=" * 60)

    # Remove environment variables
    env_vars = ["UNBOUND_API_KEY", "ANTHROPIC_BASE_URL"]
    for var in env_vars:
        success, _ = remove_env_var(var)
        if success:
            print(f"✅ Removed {var}")
        else:
            print(f"❌ Failed to remove {var}")

    # Remove Claude key helper files
    remove_claude_key_helper()

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def main():
    """Main setup function."""
    global DEBUG

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--api-key", dest="api_key", help="API key for authentication")
    parser.add_argument("--clear", action="store_true", help="Undo all changes made by the setup script")
    parser.add_argument("--debug", action="store_true", help="Show detailed debug information")
    args, _ = parser.parse_known_args()

    if args.debug:
        DEBUG = True
        debug_print("Debug mode enabled")

    if args.clear:
        clear_setup()
        return

    print("=" * 60)
    print("Claude Code - Environment Setup (with API Key)")
    print("=" * 60)

    # Flush previously set environment variables at start
    for var_name in [
        "ANTHROPIC_BASE_URL",
        "UNBOUND_API_KEY"
    ]:
        try:
            remove_env_var(var_name)
        except Exception:
            pass

    if not args.api_key:
        print("\n❌ Missing required argument: --api-key")
        print("Usage: python3 setup_with_api_key.py --api-key YOUR_API_KEY")
        print("\nTo get your API key:")
        print("  1. Go to https://gateway.getunbound.ai")
        print("  2. Navigate to Settings → API Keys")
        print("  3. Create or copy an existing API key")
        return

    print("\n✅ API key provided")

    debug_print("Verifying API key...")
    if not verify_api_key(args.api_key):
        print("❌ API key verification failed. Exiting.")
        return

    print("API Key Verified ✅")
    debug_print("API key verification successful")

    debug_print("Setting UNBOUND_API_KEY environment variable...")
    success, message = set_env_var("UNBOUND_API_KEY", args.api_key)
    if not success:
        print(f"❌ Failed to configure UNBOUND_API_KEY: {message}")
        return
    debug_print("UNBOUND_API_KEY set successfully")

    debug_print("Setting ANTHROPIC_BASE_URL environment variable...")
    success, message = set_env_var("ANTHROPIC_BASE_URL", "https://api.getunbound.ai")
    debug_print("ANTHROPIC_BASE_URL set successfully")

    # Configure Claude Code helper files
    debug_print("Setting up Claude key helper...")
    setup_claude_key_helper()
    debug_print("Claude key helper configured")

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
