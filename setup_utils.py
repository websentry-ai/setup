#!/usr/bin/env python3
"""
Shared utility functions for setup scripts across different AI coding assistants.
This module provides common functionality for environment variable management,
URL normalization, and API key verification.
"""

import os
import platform
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import json
from pathlib import Path
from typing import Tuple, Optional, Dict
import threading
import http.server
import socketserver
import socket
import webbrowser


DEBUG = False


def debug_print(message: str) -> None:
    """Print message only if DEBUG mode is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}")


def normalize_url(domain: str) -> str:
    """Normalize domain to proper URL format."""
    domain = domain.strip()

    if domain.startswith("http://") or domain.startswith("https://"):
        url = domain
    else:
        url = f"https://{domain}"

    return url.rstrip('/')


def get_shell_rc_file() -> Optional[Path]:
    """
    Determine the appropriate shell configuration file based on the OS and shell.
    
    Returns:
        Path: Path to the shell configuration file, or None for Windows
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


def append_to_file(file_path: Path, line: str, var_name: Optional[str] = None) -> bool:
    """
    Append a line to a file only if it's not already present.
    
    Args:
        file_path: Path to the file to append to
        line: Line to append (without newline)
        var_name: Optional variable name to remove old exports before adding new one
    
    Returns:
        bool: True if line was added or already existed, False on error
    """
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


def set_env_var_on_windows(var_name: str, value: str) -> bool:
    """
    Set environment variable permanently on Windows using setx.

    Args:
        var_name: Name of the environment variable
        value: Value to set

    Returns:
        bool: True if successful, False otherwise
    """
    debug_print(f"Writing to user environment registry (Windows)")
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

    debug_print(f"Writing to shell file: {rc_file}")
    export_line = f'export {var_name}="{value}"'
    
    was_added = append_to_file(rc_file, export_line)
    
    return True if was_added else True


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
            debug_print(f"Environment variable {var_name} set on Windows")
            return True, "Environment variable set for new terminals"
        else:
            return False, "Failed to set environment variable"
    
    elif system in ["darwin", "linux"]:
        success = set_env_var_on_unix(var_name, value)
        if success:
            debug_print(f"Environment variable {var_name} added to shell rc file")
            shell_name = "zsh" if "zsh" in os.environ.get("SHELL", "") else "bash"
            return True, f"Run 'source ~/.{shell_name}rc' or restart terminal"
        else:
            return False, "Failed to set environment variable"
    
    else:
        return False, f"Unsupported OS: {system}"


def remove_env_var_on_unix(var_name: str) -> bool:
    """
    Remove an environment variable export line from the user's shell rc file.
    
    Args:
        var_name: Name of the environment variable to remove
        
    Returns:
        bool: True if successful, False otherwise
    """
    rc_file = get_shell_rc_file()
    if rc_file is None:
        return False
    try:
        if not rc_file.exists():
            return True
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
    
    Args:
        var_name: Name of the environment variable to remove
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        subprocess.run(["reg", "delete", "HKCU\\Environment", "/F", "/V", var_name], 
                      check=True, capture_output=True)
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
    
    Args:
        var_name: Name of the environment variable to remove
        
    Returns:
        Tuple[bool, str]: (success, message)
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


def verify_api_key(api_key: str, api_url: str = "https://api.getunbound.ai/v1/models") -> bool:
    """
    Verify the API key by making a request to the models endpoint.
    
    Args:
        api_key: The API key to verify
        api_url: The API endpoint URL to verify against (default: Unbound AI)
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not api_key or len(api_key) == 0:
        print("❌ API key is empty")
        return False
    
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Unbound CLI"
        }
        
        request = urllib.request.Request(api_url, headers=headers)
        
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


def run_one_shot_callback_server(frontend_url: str) -> Optional[Dict[str, any]]:
    """
    Start a local HTTP server that waits for a single callback request and returns its contents.
    
    Args:
        frontend_url: The URL to open in the browser
    
    Returns:
        Dict with method, path, query, headers, and body; or None on failure
    """
    result = {"received": False, "data": None}
    server_ready = threading.Event()

    class CallbackHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            result["data"] = {
                "method": "GET",
                "path": parsed.path,
                "query": query_params,
                "headers": dict(self.headers),
                "body": None
            }
            result["received"] = True
            
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Success!</h1><p>You can close this window now.</p></body></html>")
        
        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else None
            
            parsed = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            result["data"] = {
                "method": "POST",
                "path": parsed.path,
                "query": query_params,
                "headers": dict(self.headers),
                "body": body
            }
            result["received"] = True
            
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Success!</h1><p>You can close this window now.</p></body></html>")
        
        def log_message(self, format, *args):
            pass

    def find_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def run_server(port: int):
        with socketserver.TCPServer(("", port), CallbackHandler) as httpd:
            server_ready.set()
            while not result["received"]:
                httpd.handle_request()

    try:
        port = find_free_port()
        callback_url = f"http://localhost:{port}/callback"
        full_url = f"{frontend_url}?callback_url={urllib.parse.quote(callback_url)}"
        
        server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
        server_thread.start()
        
        server_ready.wait(timeout=2)
        
        print(f"Opening browser to: {full_url}")
        webbrowser.open(full_url)
        
        timeout = 300
        server_thread.join(timeout=timeout)
        
        if result["received"]:
            return result["data"]
        else:
            print("❌ Timeout waiting for callback")
            return None
            
    except Exception as e:
        print(f"❌ Failed to run callback server: {e}")
        return None
