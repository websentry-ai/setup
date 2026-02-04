#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import json
import re
import glob
from datetime import datetime, timezone, timedelta
from pathlib import Path

DEBUG = True
ENV_VAR_NAME = "UNBOUND_COPILOT_API_KEY"
GATEWAY_ENDPOINT = "https://api.getunbound.ai/v1/hooks/copilot"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def debug_print(message):
    if DEBUG:
        print(f"[DEBUG] {message}")


def check_admin_privileges():
    try:
        system = platform.system().lower()
        if system in ("darwin", "linux"):
            return os.geteuid() == 0
        elif system == "windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return False
    except Exception as e:
        debug_print(f"Failed to check privileges: {e}")
        return False


# ---------------------------------------------------------------------------
# Device identification (from claude-code/hooks/mdm/setup.py)
# ---------------------------------------------------------------------------

def get_device_identifier():
    system = platform.system().lower()
    try:
        if system == "darwin":
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "Serial Number" in line:
                        parts = line.split(": ")
                        if len(parts) >= 2:
                            serial = parts[1].strip()
                            if serial:
                                return serial
            return None

        elif system == "linux":
            try:
                result = subprocess.run(
                    ["dmidecode", "-s", "system-serial-number"],
                    capture_output=True, text=True, timeout=10,
                    stderr=subprocess.DEVNULL,
                )
                if result.returncode == 0:
                    device_id = result.stdout.strip()
                    if device_id:
                        return device_id
            except Exception:
                debug_print("dmidecode failed, trying machine-id")

            for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        device_id = f.read().strip()
                        if device_id:
                            return device_id
                except Exception:
                    continue

            try:
                result = subprocess.run(
                    ["hostname"], capture_output=True, text=True, timeout=10,
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
                    ["wmic", "os", "get", "SerialNumber"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
                    if len(lines) > 1:
                        return lines[1]
            except Exception:
                debug_print("WMI query failed, trying registry")

            try:
                result = subprocess.run(
                    ["reg", "query",
                     "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
                     "/v", "MachineGuid"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "MachineGuid" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                return parts[-1]
            except Exception:
                pass
            return None

    except Exception as e:
        debug_print(f"Failed to get device identifier: {e}")
        return None


# ---------------------------------------------------------------------------
# Environment variable management (from claude-code/hooks/mdm/setup.py)
# ---------------------------------------------------------------------------

def get_all_user_homes():
    user_homes = []
    system = platform.system().lower()
    try:
        if system == "darwin":
            import pwd
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)
                if uid >= 500 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith("/Users/") and username not in ("Shared", "Guest"):
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "linux":
            import pwd
            for user in pwd.getpwall():
                uid = user.pw_uid
                username = user.pw_name
                home_dir = Path(user.pw_dir)
                if uid >= 1000 and home_dir.exists() and home_dir.is_dir():
                    if str(home_dir).startswith("/home/"):
                        user_homes.append((username, home_dir))
                        debug_print(f"Found user: {username} -> {home_dir}")

        elif system == "windows":
            users_dir = Path("C:/Users")
            if users_dir.exists():
                try:
                    for user_dir in users_dir.iterdir():
                        if user_dir.is_dir() and user_dir.name not in ("Public", "Default", "Default User", "Administrator"):
                            user_homes.append((user_dir.name, user_dir))
                            debug_print(f"Found user: {user_dir.name} -> {user_dir}")
                except Exception as e:
                    debug_print(f"Error scanning Windows users directory: {e}")

        return user_homes
    except Exception as e:
        debug_print(f"Error enumerating users: {e}")
        return []


def append_to_file(file_path, line, var_name=None):
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
        print(f"Failed to modify {file_path}: {e}")
        return False


def check_env_var_exists(rc_file, var_name, value):
    if not rc_file.exists():
        return False
    try:
        with open(rc_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        export_line = f'export {var_name}="{value}"'
        return any(l.rstrip() == export_line for l in lines)
    except Exception:
        return False


def set_env_var_for_user(username, home_dir, var_name, value):
    system = platform.system().lower()
    try:
        if system == "darwin":
            rc_files = [home_dir / ".zprofile", home_dir / ".bash_profile"]
        elif system == "linux":
            rc_files = [home_dir / ".zshrc", home_dir / ".bashrc"]
        elif system == "windows":
            try:
                subprocess.run(
                    ["setx", var_name, value, "/M"],
                    check=False, capture_output=True, timeout=10,
                )
                debug_print(f"Set {var_name} system-wide on Windows")
                return True, True
            except Exception as e:
                debug_print(f"Failed to set {var_name} on Windows: {e}")
                return False, False
        else:
            return False, False

        export_line = f'export {var_name}="{value}"'
        user_success = False
        user_changed = False

        for rc_file in rc_files:
            try:
                exists_already = check_env_var_exists(rc_file, var_name, value)
                if append_to_file(rc_file, export_line, var_name):
                    if system in ("darwin", "linux"):
                        try:
                            import pwd
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
    except Exception as e:
        debug_print(f"Error setting env var for {username}: {e}")
        return False, False


def set_env_var_system_wide(var_name, value):
    try:
        user_homes = get_all_user_homes()
        if not user_homes:
            print("No user home directories found")
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
            print("Failed to set environment variable for any users")
            return False, False
    except Exception as e:
        print(f"Failed to set system-wide environment variable: {e}")
        return False, False


def fetch_api_key_from_mdm(base_url, app_name, auth_api_key, device_id):
    params = f"serial_number={device_id}&app_type=copilot"
    if app_name:
        params = f"app_name={app_name}&{params}"
    url = f"{base_url.rstrip('/')}/api/v1/automations/mdm/get_application_api_key/?{params}"

    debug_print(f"Fetching API key from: {url}")

    try:
        result = subprocess.run(
            ["curl", "-fsSL", "-w", "\n%{http_code}",
             "-H", f"Authorization: Bearer {auth_api_key}", url],
            capture_output=True, text=True, timeout=30,
        )

        output_lines = result.stdout.strip().split("\n")
        if len(output_lines) < 2:
            print("Invalid response from server")
            return None

        http_code = output_lines[-1]
        response_body = "\n".join(output_lines[:-1])

        debug_print(f"HTTP status: {http_code}")
        debug_print(f"Response: {response_body}")

        if http_code != "200":
            print(f"API request failed with status {http_code}")
            return None

        try:
            data = json.loads(response_body)
            api_key = data.get("api_key")
            if not api_key:
                print("No api_key in response")
                return None
            user_email = data.get("email")
            first_name = data.get("first_name")
            last_name = data.get("last_name")
            print(f"User email: {user_email}")
            print(f"Name: {first_name} {last_name}")
            return api_key
        except json.JSONDecodeError:
            print("Invalid JSON response from server")
            return None

    except subprocess.TimeoutExpired:
        print("Request timed out")
        return None
    except Exception as e:
        debug_print(f"Request failed: {e}")
        print("Failed to fetch API key")
        return None


# ---------------------------------------------------------------------------
# Copilot session parser (inlined from copilot/parse_sessions.py)
# ---------------------------------------------------------------------------

def _epoch_ms_to_utc(epoch_ms):
    if not epoch_ms:
        return None
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).isoformat()


def _clean(d):
    """Remove keys with empty string values from a dict."""
    return {k: v for k, v in d.items() if v}


def _read_file_from_disk(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception:
        return ""


def extract_response_text(response_parts):
    chunks = []
    skip_next_text = False
    for part in response_parts:
        kind = part.get("kind")

        if kind in ("mcpServersStarting", "thinking", "textEditGroup",
                     "undoStop", "prepareToolInvocation",
                     "toolInvocationSerialized"):
            continue

        if kind == "codeblockUri":
            if chunks:
                stripped = re.sub(r'\n?`{3,}\w*\n?$', '', chunks[-1])
                if stripped:
                    chunks[-1] = stripped
                else:
                    chunks.pop()
            skip_next_text = True
            continue

        if kind == "inlineReference":
            ref = part.get("inlineReference", {})
            path = ref.get("path") or ref.get("fsPath", "")
            if path:
                chunks.append(f"`{path}`")
            skip_next_text = False
            continue

        value = part.get("value")
        if isinstance(value, str) and value:
            if skip_next_text:
                skip_next_text = False
                continue
            chunks.append(value)
        else:
            skip_next_text = False

    return "".join(chunks)


def extract_file_writes(response_parts):
    writes = []
    i = 0
    while i < len(response_parts):
        part = response_parts[i]
        if part.get("kind") == "codeblockUri":
            uri = part.get("uri", {})
            path = uri.get("path") or uri.get("fsPath", "")
            content = ""
            for j in range(i + 1, len(response_parts)):
                nxt = response_parts[j]
                if nxt.get("kind") in ("thinking", "mcpServersStarting"):
                    continue
                if nxt.get("kind") == "textEditGroup":
                    edits = nxt.get("edits", [])
                    if edits and edits[0]:
                        content = edits[0][0].get("text", "")
                    break
                val = nxt.get("value")
                if isinstance(val, str):
                    content = re.sub(r'\n?`{3,}\s*$', '', val)
                break
            if path:
                writes.append(_clean({
                    "type": "afterFileEdit",
                    "file_path": path,
                    "content": content,
                }))
        i += 1
    return writes


def extract_file_reads(variable_data, content_refs, file_state):
    seen = set()
    tool_uses = []

    for var in variable_data.get("variables", []):
        val = var.get("value", {})
        path = val.get("path") or val.get("fsPath")
        if path and path not in seen:
            seen.add(path)
            content = file_state.get(path) if path in file_state else _read_file_from_disk(path)
            tool_uses.append(_clean({
                "type": "beforeReadFile",
                "file_path": path,
                "content": content,
            }))

    for ref_obj in content_refs:
        ref = ref_obj.get("reference", {})
        path = ref.get("path") or ref.get("fsPath")
        if path and path not in seen:
            seen.add(path)
            content = file_state.get(path) if path in file_state else _read_file_from_disk(path)
            tool_uses.append(_clean({
                "type": "beforeReadFile",
                "file_path": path,
                "content": content,
            }))

    return tool_uses


def _resolve_tool_result(call_id, tool_call_results):
    entry = tool_call_results.get(call_id, {})
    parts = entry.get("content", [])
    texts = []
    for p in parts:
        val = p.get("value")
        if isinstance(val, str) and val:
            texts.append(val)
    return "\n".join(texts)


def extract_tool_calls(result_metadata):
    tool_call_results = result_metadata.get("toolCallResults", {})
    tool_uses = []
    rounds = result_metadata.get("toolCallRounds", [])

    for rnd in rounds:
        for tc in rnd.get("toolCalls", []):
            name = tc.get("name", tc.get("toolCallId", "unknown"))
            call_id = tc.get("id", "")

            args_raw = tc.get("arguments", "{}")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else (args_raw or {})
            except (json.JSONDecodeError, TypeError):
                args = {"raw": args_raw}

            result_text = _resolve_tool_result(call_id, tool_call_results)

            if name == "run_in_terminal":
                tool_uses.append(_clean({
                    "type": "afterShellExecution",
                    "command": args.get("command", ""),
                    "output": result_text,
                }))
            elif name in ("readFile", "read_file"):
                tool_uses.append(_clean({
                    "type": "beforeReadFile",
                    "file_path": args.get("filePath", args.get("file_path", "")),
                    "content": result_text,
                }))
            elif name in ("editFile", "edit_file", "insert_edit"):
                tool_uses.append(_clean({
                    "type": "afterFileEdit",
                    "file_path": args.get("filePath", args.get("file_path", "")),
                    "content": result_text,
                }))
            else:
                tool_uses.append(_clean({
                    "type": "afterMCPExecution",
                    "tool_name": name,
                    "tool_input": args,
                    "result_json": result_text,
                }))

    return tool_uses


def parse_session_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        session = json.load(f)

    session_id = session.get("sessionId", Path(filepath).stem)
    requests = session.get("requests", [])
    file_state = {}
    exchanges = []

    for req in requests:
        user_text = req.get("message", {}).get("text", "")
        if not user_text:
            continue

        raw_model = req.get("modelId", "")
        model_id = raw_model.split("/")[-1] if raw_model else "auto"
        timestamp = req.get("timestamp")
        timings = req.get("result", {}).get("timings", {})
        total_elapsed = timings.get("totalElapsed", 0)

        response_parts = req.get("response", [])
        assistant_text = extract_response_text(response_parts)

        file_reads = extract_file_reads(
            req.get("variableData", {}),
            req.get("contentReferences", []),
            file_state,
        )
        file_writes = extract_file_writes(response_parts)
        result_meta = req.get("result", {}).get("metadata", {})
        explicit_tools = extract_tool_calls(result_meta)
        all_tool_uses = file_reads + file_writes + explicit_tools

        for tu in file_writes + explicit_tools:
            if tu["type"] == "afterFileEdit" and tu.get("content"):
                file_state[tu["file_path"]] = tu["content"]

        messages = [{"role": "user", "content": user_text}]

        if assistant_text or all_tool_uses:
            assistant_msg = {"role": "assistant", "content": assistant_text or ""}
            if all_tool_uses:
                assistant_msg["tool_use"] = all_tool_uses
            messages.append(assistant_msg)

        if len(messages) < 2:
            continue

        exchanges.append({
            "conversation_id": session_id,
            "model": model_id,
            "requestInitialized": _epoch_ms_to_utc(timestamp),
            "requestCompleted": _epoch_ms_to_utc(timestamp + total_elapsed) if timestamp and total_elapsed else _epoch_ms_to_utc(timestamp),
            "messages": messages,
        })

    return exchanges


# ---------------------------------------------------------------------------
# Cross-platform VS Code paths & session discovery
# ---------------------------------------------------------------------------

def get_workspace_storage_root():
    system = platform.system().lower()
    if system == "darwin":
        return Path.home() / "Library" / "Application Support" / "Code" / "User" / "workspaceStorage"
    elif system == "linux":
        return Path.home() / ".config" / "Code" / "User" / "workspaceStorage"
    elif system == "windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            return Path(appdata) / "Code" / "User" / "workspaceStorage"
        return Path.home() / "AppData" / "Roaming" / "Code" / "User" / "workspaceStorage"
    else:
        return Path.home() / ".config" / "Code" / "User" / "workspaceStorage"


def get_user_workspace_root(home_dir):
    """Get workspace storage root for a specific user's home directory."""
    system = platform.system().lower()
    if system == "darwin":
        return home_dir / "Library" / "Application Support" / "Code" / "User" / "workspaceStorage"
    elif system == "linux":
        return home_dir / ".config" / "Code" / "User" / "workspaceStorage"
    elif system == "windows":
        return home_dir / "AppData" / "Roaming" / "Code" / "User" / "workspaceStorage"
    return home_dir / ".config" / "Code" / "User" / "workspaceStorage"


def get_unbound_dir():
    """
    Return the .unbound/ directory inside workspace storage for state files.
    When running as root, uses the first real user's workspace storage.
    """
    if check_admin_privileges():
        for _username, home_dir in get_all_user_homes():
            root = get_user_workspace_root(home_dir)
            if root.exists():
                d = root / ".unbound"
                d.mkdir(exist_ok=True)
                return d
    # Fallback: current user
    root = get_workspace_storage_root()
    d = root / ".unbound"
    d.mkdir(parents=True, exist_ok=True)
    return d


def find_recent_session_files(root, cutoff_ts):
    """Find session JSON files with mtime >= cutoff_ts (epoch seconds)."""
    pattern = str(root / "*" / "chatSessions" / "*.json")
    files = []
    for f in glob.glob(pattern):
        try:
            if os.path.getmtime(f) >= cutoff_ts:
                files.append(f)
        except OSError:
            continue
    return sorted(files)


def filter_exchanges_by_time(exchanges, cutoff_iso):
    """Keep only exchanges where requestInitialized >= cutoff_iso."""
    filtered = []
    for ex in exchanges:
        ts = ex.get("requestInitialized")
        if ts and ts >= cutoff_iso:
            filtered.append(ex)
    return filtered


# ---------------------------------------------------------------------------
# Last-run timestamp & temp JSON persistence
# ---------------------------------------------------------------------------

def get_last_run_path():
    return get_unbound_dir() / "last_run"


def get_temp_json_path():
    return get_unbound_dir() / "sync.json"


def read_last_run_timestamp():
    """Read last-run UTC ISO timestamp. Returns None if not found."""
    path = get_last_run_path()
    try:
        if path.exists():
            ts = path.read_text(encoding="utf-8").strip()
            if ts:
                return ts
    except Exception as e:
        debug_print(f"Could not read last-run timestamp: {e}")
    return None


def write_last_run_timestamp(iso_ts):
    path = get_last_run_path()
    try:
        path.write_text(iso_ts, encoding="utf-8")
    except Exception as e:
        debug_print(f"Could not write last-run timestamp: {e}")


def save_temp_json(data):
    """Atomic write: write to .tmp then rename."""
    path = get_temp_json_path()
    tmp_path = path.with_suffix(".tmp")
    try:
        tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(path)
    except Exception as e:
        debug_print(f"Could not save temp JSON: {e}")


def load_or_create_temp_json(exchanges):
    """
    If temp JSON exists (crash recovery), load it and return.
    Otherwise create fresh from exchanges.
    """
    path = get_temp_json_path()

    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            pending = [e for e in data.get("entries", []) if e.get("status") != "processed"]
            if pending:
                debug_print(f"Resuming: {len(pending)} entries pending/failed from previous run")
                return data
        except Exception as e:
            debug_print(f"Could not load temp JSON, rebuilding: {e}")

    data = {
        "entries": [{"exchange": ex, "status": "pending"} for ex in exchanges]
    }
    save_temp_json(data)
    return data


# ---------------------------------------------------------------------------
# Gateway send
# ---------------------------------------------------------------------------

def send_exchange(exchange, api_key):
    """POST a single exchange to the gateway. Returns True on success."""
    body = json.dumps(exchange, ensure_ascii=False)
    try:
        result = subprocess.run(
            ["curl", "-fsSL", "-w", "\n%{http_code}",
             "-X", "POST",
             "-H", f"Authorization: Bearer {api_key}",
             "-H", "Content-Type: application/json",
             "-d", body,
             GATEWAY_ENDPOINT],
            capture_output=True, text=True, timeout=30,
        )
        output_lines = result.stdout.strip().split("\n")
        http_code = output_lines[-1] if output_lines else ""
        return http_code == "200"
    except Exception as e:
        debug_print(f"Send failed: {e}")
        return False


def sync_entries(data, api_key):
    """Send all pending/failed entries. Returns (sent_count, failed_count)."""
    entries = data.get("entries", [])
    total = len([e for e in entries if e.get("status") != "processed"])
    sent = 0
    failed = 0
    idx = 0

    for entry in entries:
        if entry.get("status") == "processed":
            continue
        idx += 1
        debug_print(f"Sending: {idx}/{total}")

        success = send_exchange(entry["exchange"], api_key)
        if not success:
            # Retry once
            debug_print(f"Retrying {idx}/{total}")
            success = send_exchange(entry["exchange"], api_key)

        if success:
            entry["status"] = "processed"
            sent += 1
        else:
            entry["status"] = "failed"
            failed += 1

        save_temp_json(data)

    return sent, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global DEBUG
    DEBUG = True

    print("=" * 60)
    print("Copilot Hooks - MDM Setup & Sync")
    print("=" * 60)

    # Parse args
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
        print("\nMissing required arguments")
        print("Usage: sudo python3 setup.py --url <base_url> --api_key <api_key> [--app_name <name>]")
        return

    # --- Step 1: Resolve API key ---
    api_key = os.environ.get(ENV_VAR_NAME)
    if api_key:
        debug_print(f"{ENV_VAR_NAME} found in environment")
    else:
        debug_print(f"{ENV_VAR_NAME} not found, fetching from backend")

        if not check_admin_privileges():
            system = platform.system().lower()
            if system in ("darwin", "linux"):
                print("This script requires administrator/root privileges to set env vars")
                print("   Please run with: sudo python3 setup.py ...")
            else:
                print("This script requires administrator privileges")
            return

        print("\nGetting device identifier...")
        device_id = get_device_identifier()
        if not device_id:
            print("Failed to get device identifier")
            return
        debug_print(f"Device identifier: {device_id}")

        print("Fetching API key from backend...")
        api_key = fetch_api_key_from_mdm(base_url, app_name, auth_api_key, device_id)
        if not api_key:
            return
        print("API key received")

        print("Setting environment variable system-wide...")
        success, _ = set_env_var_system_wide(ENV_VAR_NAME, api_key)
        if not success:
            print(f"Failed to set {ENV_VAR_NAME}")
            return
        debug_print(f"{ENV_VAR_NAME} set successfully")

    # --- Step 2: Determine time window ---
    now_utc = datetime.now(timezone.utc)
    last_run = read_last_run_timestamp()
    if last_run:
        debug_print(f"Last run: {last_run}")
        cutoff_iso = last_run
    else:
        cutoff_iso = (now_utc - timedelta(hours=24)).isoformat()
        debug_print(f"First run, defaulting to last 24h: {cutoff_iso}")

    # Convert cutoff to epoch seconds for mtime filtering
    cutoff_dt = datetime.fromisoformat(cutoff_iso)
    cutoff_epoch = cutoff_dt.timestamp()

    # --- Step 3: Find session files ---
    root = get_workspace_storage_root()
    debug_print(f"Looking for sessions in {root}")

    # When running as root, scan all user homes
    if check_admin_privileges():
        all_files = []
        for _username, home_dir in get_all_user_homes():
            user_root = get_user_workspace_root(home_dir)
            if user_root.exists():
                all_files.extend(find_recent_session_files(user_root, cutoff_epoch))
        session_files = sorted(set(all_files))
    else:
        session_files = find_recent_session_files(root, cutoff_epoch)

    print(f"Found {len(session_files)} session files since last run")
    if not session_files:
        print("Nothing to sync")
        return

    # --- Step 4: Parse & filter exchanges ---
    all_exchanges = []
    for sf in session_files:
        try:
            exs = parse_session_file(sf)
            all_exchanges.extend(exs)
        except Exception as e:
            debug_print(f"Error parsing {sf}: {e}")

    exchanges = filter_exchanges_by_time(all_exchanges, cutoff_iso)
    print(f"Found {len(exchanges)} exchanges to sync")
    if not exchanges:
        print("Nothing to sync")
        return

    # --- Step 5: Build / resume temp JSON ---
    data = load_or_create_temp_json(exchanges)

    # --- Step 6: Send to gateway ---
    sent, failed = sync_entries(data, api_key)
    print(f"Sync complete: {sent} sent, {failed} failed")

    # Clean up temp file if all processed
    remaining = [e for e in data.get("entries", []) if e.get("status") != "processed"]
    if not remaining:
        try:
            get_temp_json_path().unlink(missing_ok=True)
        except Exception:
            pass

    # --- Step 7: Update last-run timestamp (max requestInitialized from processed exchanges) ---
    max_ts = max(
        (ex["requestInitialized"] for ex in exchanges if ex.get("requestInitialized")),
        default=None,
    )
    if max_ts:
        write_last_run_timestamp(max_ts)

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCancelled.")
    except Exception as e:
        print(f"\nError: {e}")
        exit(1)
