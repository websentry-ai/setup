
#!/usr/bin/env python3

import os
import sys
import platform
import urllib.request
from pathlib import Path
from typing import Tuple
import json
import subprocess
import ssl

try:
    import certifi
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--user", "certifi"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import certifi

SCRIPT_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/unbound.py"


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
        
        if var_name and line not in [l.rstrip() for l in lines]:
            lines.append(f"{line}\n")
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
        import subprocess
        subprocess.run(["reg", "delete", "HKCU\\Environment", "/F", "/V", var_name], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
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
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    elif system in ["darwin", "linux"]:
        success = remove_env_var_on_unix(var_name)
        return (True, "Removed") if success else (False, f"Failed to remove {var_name}")
    else:
        return False, f"Unsupported OS: {system}"


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
    hooks_dir = Path.home() / ".claude" / "hooks"
    script_path = hooks_dir / "unbound.py"
    
    # print("\n📥 Downloading unbound.py script...")
    
    if not download_file(SCRIPT_URL, script_path):
        return False
    # print("✅ unbound.py downloaded")
    
    try:
        current_mode = script_path.stat().st_mode
        os.chmod(script_path, current_mode | 0o111)
        # print("✅ Made unbound.py executable")
    except Exception as e:
        # print(f"⚠️  Could not make script executable: {e}")
        pass
    
    return True


def configure_claude_settings() -> bool:
    settings_path = Path.home() / ".claude" / "settings.json"
    
    try:
        if settings_path.exists():
            with open(settings_path, 'r', encoding='utf-8') as f:
                settings = json.load(f)
        else:
            settings = {}
            settings_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove apiKeyHelper if present before adding hooks
        if "apiKeyHelper" in settings:
            del settings["apiKeyHelper"]
        
        hook_command = str(Path.home() / ".claude" / "hooks" / "unbound.py")
        
        hooks_config = {
            "PostToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "UserPromptSubmit": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ],
            "SessionEnd": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 60
                        }
                    ]
                }
            ]
        }
        
        if "hooks" not in settings:
            settings["hooks"] = {}
        
        for event, new_config in hooks_config.items():
            if event in settings["hooks"]:
                existing_config = settings["hooks"][event]
                
                our_hook_exists = False
                for existing_item in existing_config:
                    if isinstance(existing_item, dict):
                        existing_hooks = existing_item.get("hooks", [])
                        for hook in existing_hooks:
                            if hook.get("command") == hook_command:
                                our_hook_exists = True
                                break
                
                if not our_hook_exists:
                    settings["hooks"][event].extend(new_config)
                # else:
                #     print(f"  ✓ Unbound hook already configured for {event}")
            else:
                settings["hooks"][event] = new_config
        
        with open(settings_path, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)
        
        # print("✅ Claude settings configured successfully")
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse existing settings.json: {e}")
        print("   Please check your settings.json file for syntax errors")
        return False
    except Exception as e:
        print(f"❌ Failed to configure settings: {e}")
        return False


def main():
    print("Claude code setup")
    
    api_key = None
    for i, arg in enumerate(sys.argv):
        if arg == "--api-key" and i + 1 < len(sys.argv):
            api_key = sys.argv[i + 1]
            break
    
    if not api_key:
        print("❌ Missing required argument: --api-key")
        print("Usage: python3 setup_with_api_key.py --api-key YOUR_API_KEY")
        return
    
    success, message = set_env_var("UNBOUND_CLAUDE_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to set environment variable: {message}")
        return
    
    # Remove ANTHROPIC_BASE_URL if it exists
    try:
        remove_env_var("ANTHROPIC_BASE_URL")
    except Exception:
        pass
    
    if not setup_hooks():
        print("❌ Failed to setup hooks")
        return
    
    import json
    if not configure_claude_settings():
        print("❌ Failed to configure Claude settings")
        return
    
    print("API key added")
    print("Setup complete")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        exit(1)