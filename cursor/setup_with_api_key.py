#!/usr/bin/env python3

import os
import sys
import platform
import urllib.request
import subprocess
import time
from pathlib import Path
from typing import Tuple

HOOKS_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/hooks.json"
SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/unbound.py"


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
        import subprocess
        subprocess.run(["setx", var_name, value], check=True, capture_output=True)
        return True
    except Exception as e:
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


def download_file(url: str, dest_path: Path) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
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
        print(f"⚠️ Could not make script executable: {e}")

    return True


def restart_cursor() -> bool:
    """Attempt to restart Cursor IDE."""
    system = platform.system().lower()

    try:
        if system == "darwin":
            # macOS: Gracefully quit using AppleScript, then relaunch
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["osascript", "-e", 'tell application "Cursor" to quit'], 
                         capture_output=True)
            time.sleep(2)
            subprocess.run(["open", "-a", "Cursor"])
            print("✅ Cursor restarted")
            return True

        elif system == "linux":
            # Linux: Kill and relaunch cursor
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["pkill", "-9", "cursor"], capture_output=True)
            time.sleep(1)
            subprocess.Popen(["cursor"],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            print("✅ Cursor restarted")
            return True

        elif system == "windows":
            # Windows: Use taskkill and start
            print("\n🔄 Restarting Cursor IDE...")
            subprocess.run(["taskkill", "/F", "/IM", "Cursor.exe"],
                         capture_output=True)
            time.sleep(1)
            subprocess.Popen(["start", "cursor"],
                           shell=True,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            print("✅ Cursor restarted")
            return True

        return False

    except Exception as e:
        print(f"⚠️ Could not automatically restart Cursor: {e}")
        print("Please restart Cursor manually")
        return False


def main():
    print("=" * 60)
    print("Unbound Cursor Hooks - Setup with API Key")
    print("=" * 60)

    api_key = None
    for i, arg in enumerate(sys.argv):
        if arg == "--api-key" and i + 1 < len(sys.argv):
            api_key = sys.argv[i + 1]
            break

    if not api_key:
        print("\n❌ Missing required argument: --api-key")
        print("Usage: python3 setup_with_api_key.py --api-key YOUR_API_KEY")
        print("\nTo get your API key:")
        print("  1. Go to https://gateway.getunbound.ai")
        print("  2. Navigate to Settings → API Keys")
        print("  3. Create or copy an existing API key")
        return

    print("\n✅ API key provided")

    success, message = set_env_var("UNBOUND_CURSOR_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return

    print(f"✅ Environment variable set ({message})")

    if not setup_hooks():
        print("\n❌ Failed to setup hooks")
        return

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    # Attempt to restart Cursor automatically
    restart_cursor()

    print("\n" + "=" * 60)
    print("All Done!")
    print("=" * 60)
    print("Note: You may need to restart your terminal")
    print("      (or run source command shown above)")
    print("=" * 60)
    print("\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Setup cancelled.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        exit(1)
