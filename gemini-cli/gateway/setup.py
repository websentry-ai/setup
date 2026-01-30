#!/usr/bin/env python3
"""
Gemini CLI - Environment Setup Script
"""

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from setup_utils import (
    debug_print, normalize_url, get_shell_rc_file,
    set_env_var, remove_env_var, verify_api_key,
    run_one_shot_callback_server
)
import setup_utils

import platform
import subprocess
from typing import Optional, Dict
import argparse


DEBUG = False


def clear_setup() -> None:
    """Undo all changes made by the setup script."""
    print("=" * 60)
    print("Gemini CLI - Clearing Setup")
    print("=" * 60)

    # Remove environment variables
    env_vars = ["GEMINI_API_KEY", "GOOGLE_GEMINI_BASE_URL"]
    for var in env_vars:
        success, _ = remove_env_var(var)
        if success:
            print(f"✅ Removed {var}")
        else:
            print(f"❌ Failed to remove {var}")

    print("\n" + "=" * 60)
    print("Clear Complete!")
    print("=" * 60)


def main():
    """Main setup function."""
    global DEBUG

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--domain", dest="domain", help="Base frontend URL (e.g., gateway.getunbound.ai)")
    parser.add_argument("--clear", action="store_true", help="Undo all changes made by the setup script")
    parser.add_argument("--debug", action="store_true", help="Show detailed debug information")
    args, _ = parser.parse_known_args()

    if args.debug:
        DEBUG = True
        setup_utils.DEBUG = True
        debug_print("Debug mode enabled")

    if args.clear:
        clear_setup()
        return

    print("=" * 60)
    print("Gemini CLI - Environment Setup")
    print("=" * 60)

    if not args.domain:
        print("\n❌ Missing required argument: --domain (e.g., --domain gateway.getunbound.ai)")
        return

    auth_url = normalize_url(args.domain)
    cb_response = run_one_shot_callback_server(auth_url)
    if cb_response is None:
        print("\n❌ Failed to receive callback response. Exiting.")
        return

    api_key = None
    try:
        api_key = (cb_response.get("query") or {}).get("api_key")
    except Exception:
        api_key = None

    if not api_key:
        print("\n❌ No api_key found in callback. Exiting.")
        return

    debug_print("Verifying API key...")
    if not verify_api_key(api_key):
        print("❌ API key verification failed. Exiting.")
        return

    print("API Key Verified ✅")
    debug_print("API key verification successful")

    debug_print("Setting GEMINI_API_KEY environment variable...")
    success, message = set_env_var("GEMINI_API_KEY", api_key)
    if not success:
        print(f"❌ Failed to configure GEMINI_API_KEY: {message}")
        return
    debug_print("GEMINI_API_KEY set successfully")

    debug_print("Setting GOOGLE_GEMINI_BASE_URL environment variable...")
    success, message = set_env_var("GOOGLE_GEMINI_BASE_URL", "https://api.getunbound.ai/v1")
    debug_print("GOOGLE_GEMINI_BASE_URL set successfully")
    
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
