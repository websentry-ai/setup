#!/usr/bin/env python3
"""
Real-time Cursor hook event processor with smart garbage collection.
Reads JSON events from stdin, appends to agent-audit.log, and processes them on stop events.
"""

import sys
import json
import os
import subprocess
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
import tempfile
import time
import hashlib
import re
import sqlite3
import platform
from urllib.parse import quote

UNBOUND_GATEWAY_URL = os.environ.get(
    "UNBOUND_GATEWAY_URL", "https://api.getunbound.ai"
).rstrip("/")
APPROVAL_TIMEOUT = 4 * 60 * 60

DISCOVERY_DEBOUNCE_SECONDS = 24 * 3600
DISCOVERY_STALE_LOCK_SECONDS = 15 * 60
DISCOVERY_CACHE_PATH = Path.home() / ".unbound" / "discovery-cache.json"
DISCOVERY_LOCK_PATH = Path.home() / ".unbound" / "discovery.lock"
DISCOVERY_DISPATCH_PATH = Path.home() / ".unbound" / "discovery.dispatch.lock"
DISCOVERY_DISPATCH_TTL_SECONDS = 10
DISCOVERY_INSTALL_DIR = Path.home() / ".local" / "share" / "unbound"
DISCOVERY_INSTALL_SH = DISCOVERY_INSTALL_DIR / "install.sh"
DISCOVERY_INSTALL_URL = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main/install.sh"

DISCOVERY_INSTALL_SH_TTL_SECONDS = 24 * 3600
UNBOUND_CONFIG_PATH = Path.home() / ".unbound" / "config.json"
IDENTITY_CACHE_PATH = Path.home() / ".unbound" / "identity.json"

APPROVAL_POLL_PHASES = (
    (5 * 60,        3),    # 0-5 min: 3s
    (30 * 60,       15),   # 5-30 min: 15s
    (2 * 60 * 60,   60),   # 30 min - 2h: 1min
    (4 * 60 * 60,   120),  # 2h - 4h: 2min
)

# Use user's home directory for logs
LOG_DIR = Path.home() / ".cursor" / "hooks"
AUDIT_LOG = LOG_DIR / "agent-audit.log"
ERROR_LOG = LOG_DIR / "error.log"
LAST_REPORT_FILE = LOG_DIR / ".last_error_report"

SELF_UPDATE_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/cursor/unbound.py"
SELF_UPDATE_INTERVAL_SECONDS = 2 * 3600
SELF_UPDATE_LOCK_TTL_SECONDS = 30
SELF_UPDATE_CURL_TIMEOUT = 10
SELF_SCRIPT_PATH = LOG_DIR / "unbound.py"
SELF_UPDATE_STATE_PATH = LOG_DIR / ".self_update_check"
SELF_UPDATE_LOCK_PATH = LOG_DIR / ".self_update.lock"

# Frozen-binary mode (the PyInstaller-packaged `unbound-hook` CLI). The frozen
# binary must make ZERO network calls other than the backend/gateway APIs:
# self-update is owned by the MDM package (never in-place), and discovery runs
# from the locally installed binary instead of a GitHub-fetched install.sh.
# UNBOUND_HOOK_FROZEN=1 lets tests exercise these gates without freezing.
RUNNING_FROZEN = bool(getattr(sys, "frozen", False)) or os.environ.get("UNBOUND_HOOK_FROZEN") == "1"
FROZEN_DISCOVERY_BIN = "/opt/unbound/current/unbound-discovery/unbound-discovery"

PRETOOL_NATIVE_TOOLS = {'Delete', 'Write', 'Read'}   # preToolUse → policy check
EXCHANGE_NATIVE_TOOLS = {'Delete'}            # postToolUse → included in exchange
# INVARIANT: every skill entry below carries a tool_use_id - the native one
# when the tool reports it, otherwise a deterministic synthetic one. The backend
# relies on this: two id-less invocations of one skill with the same arguments
# are byte-identical, so nothing can tell a replay from a genuine repeat.
SKILL_SEARCH_DIRS = (('.cursor', 'skills'), ('.agents', 'skills'),
                     ('.claude', 'skills'), ('.codex', 'skills'))
POLICY_CACHE_FILE = LOG_DIR / ".policy_cache.json"
CURSOR_MCP_CONFIG_PATH = Path.home() / ".cursor" / "mcp.json"
CACHE_TTL_SECONDS = 300
# Repo-scope gate. Grace is session-scoped: an advisory nudge, not an audit trail.
REPO_GATE_STATE_FILE = LOG_DIR / ".repo_gate_state.json"
REPO_GATE_TURN_MEMORY = 20
# _repo_gate_turn_id's unknown-turn answer, not an identity: never memoize it.
REPO_GATE_UNKNOWN_TURN = '_session_turn'
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'
PRETOOL_USER_MESSAGES_LIMIT = 5
AUDIT_LOG_TOTAL_LIMIT = 100

# Ensure log directory exists
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    # Fallback to temp directory if home directory is not writable
    LOG_DIR = Path(tempfile.gettempdir()) / "cursor-hooks"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_LOG = LOG_DIR / "agent-audit.log"
    ERROR_LOG = LOG_DIR / "error.log"
    LAST_REPORT_FILE = LOG_DIR / ".last_error_report"
    POLICY_CACHE_FILE = LOG_DIR / ".policy_cache.json"


_cached_api_key = None
_reporting_error = False


def _should_report():
    """Rate limit: max 1 remote error report per 60 seconds. Fails closed."""
    try:
        if LAST_REPORT_FILE.exists():
            mtime = LAST_REPORT_FILE.stat().st_mtime
            if (datetime.now().timestamp() - mtime) < 60:
                return False
        LAST_REPORT_FILE.touch()
        return True
    except Exception:
        return False


def redact_secrets(text, key=None):
    text = re.sub(r'(?i)\bBearer\s+\S+', 'Bearer [REDACTED]', str(text))
    if key and len(key) >= 8:
        text = text.replace(key, '[REDACTED]')
    return text


def report_error_to_gateway(message, category='general', api_key=None):
    """Fire-and-forget error report to gateway. Never blocks, never raises."""
    global _reporting_error
    if _reporting_error or not api_key or not _should_report():
        return
    _reporting_error = True
    message = redact_secrets(message, api_key)
    try:
        payload = json.dumps({
            'errors': [{'message': message, 'timestamp': datetime.utcnow().isoformat() + 'Z', 'category': category}],
            'hook_source': 'cursor',
        })
        proc = subprocess.Popen(
            ["curl", "-fsSL", "-X", "POST",
             "-H", f"Authorization: Bearer {api_key}",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-",
             f"{UNBOUND_GATEWAY_URL}/v1/hooks/errors"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.stdin.write(payload.encode())
        proc.stdin.close()
    except Exception:
        pass
    finally:
        _reporting_error = False


def log_error(message, category='general'):
    """Log error with timestamp to error.log, keeping only last 25 errors."""
    message = redact_secrets(message, _cached_api_key)
    timestamp = datetime.now().astimezone().isoformat().replace('+00:00', 'Z')
    error_entry = f"{timestamp}: {message}\n"

    try:
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(error_entry)

        # Keep only last 25 errors
        if ERROR_LOG.exists():
            with open(ERROR_LOG, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            if len(lines) > 25:
                with open(ERROR_LOG, 'w', encoding='utf-8') as f:
                    f.writelines(lines[-25:])
    except Exception:
        pass

    # Report to gateway (fire-and-forget)
    report_error_to_gateway(message, category, _cached_api_key)


def _read_policy_cache_raw():
    """Read and JSON-parse the policy cache file. Returns None on missing/corrupt."""
    try:
        if not POLICY_CACHE_FILE.exists():
            return None
        with open(POLICY_CACHE_FILE, 'r', encoding='utf-8') as f:
            cache = json.loads(f.read())
        return cache if isinstance(cache, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def load_policy_cache():
    """Load policy cache from disk. Returns None if missing, corrupt, or expired."""
    cache = _read_policy_cache_raw()
    if cache is None or 'last_synced' not in cache or 'tools_to_check' not in cache:
        return None
    if not isinstance(cache['tools_to_check'], list):
        return None
    return cache


def get_policy_check_failure_action():
    """Read failure-action from cache, defaulting to 'allow'. Ignores TTL."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return POLICY_CHECK_FAILURE_DEFAULT
    value = cache.get('policy_check_failure_action')
    return value if value in ('allow', 'block') else POLICY_CHECK_FAILURE_DEFAULT


def get_repo_policies():
    """Repo-scope policies from cache, [] if absent; a stale cache still applies."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return []
    policies = cache.get('repo_policies')
    return policies if isinstance(policies, list) else []


def save_policy_cache(tools_to_check=None, policy_check_failure_action=None, repo_policies=None):
    """Write policy cache to disk. None for any field preserves the prior value."""
    try:
        POLICY_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        prior = _read_policy_cache_raw() or {}
        if tools_to_check is None:
            tools_to_check = prior.get('tools_to_check', [])
        if policy_check_failure_action not in ('allow', 'block'):
            policy_check_failure_action = get_policy_check_failure_action()
        if not isinstance(repo_policies, list):
            repo_policies = get_repo_policies()
        cache = {
            'last_synced': datetime.utcnow().isoformat() + 'Z',
            'tools_to_check': tools_to_check,
            'policy_check_failure_action': policy_check_failure_action,
            'repo_policies': repo_policies,
        }
        with open(POLICY_CACHE_FILE, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cache))
    except (OSError, TypeError):
        pass


def _gateway_unreachable_response():
    """Cursor deny shape for gateway-unreachable when failure mode is 'block'."""
    return {
        'permission': 'deny',
        'user_message': POLICY_CHECK_FAILURE_BLOCK_REASON,
        'agent_message': 'The organization policy engine could not be reached. This is a transient infrastructure failure. Tell the user the policy engine is unavailable and ask them to retry.',
    }


def _cache_policies_from_response(api_response):
    """Without this a session never loads policies and the gate cannot fire."""
    if not isinstance(api_response, dict):
        return
    if (
        'tools_to_check' in api_response
        or 'policy_check_failure_action' in api_response
        or 'repo_policies' in api_response
    ):
        save_policy_cache(
            tools_to_check=api_response.get('tools_to_check'),
            policy_check_failure_action=api_response.get('policy_check_failure_action'),
            repo_policies=api_response.get('repo_policies'),
        )


def is_cache_stale(cache):
    """Check if cached data is older than CACHE_TTL_SECONDS."""
    try:
        synced = datetime.fromisoformat(cache['last_synced'].rstrip('Z'))
        age = (datetime.utcnow() - synced).total_seconds()
        return age > CACHE_TTL_SECONDS
    except (ValueError, KeyError):
        return True


def load_existing_logs():
    """Load existing logs from agent-audit.log into memory."""
    logs = []
    if AUDIT_LOG.exists():
        with open(AUDIT_LOG, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError: 
                        continue
    return logs


def save_logs(logs):
    """Save logs back to agent-audit.log."""
    with open(AUDIT_LOG, 'w', encoding='utf-8') as f:
        for log in logs:
            f.write(json.dumps(log) + '\n')


def append_to_audit_log(event_data):
    """Append event to agent-audit.log."""
    with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
        f.write(json.dumps(event_data) + '\n')


def handle_deny_and_exit():
    """Terminate with Cursor's block exit code."""
    sys.exit(2)


def group_events_by_generation(logs):
    """Group events by conversation_id and generation_id."""
    grouped = defaultdict(lambda: defaultdict(list))
    
    for log in logs:
        event = log.get('event', {})
        conversation_id = event.get('conversation_id')
        generation_id = event.get('generation_id')
        
        if conversation_id and generation_id:
            grouped[conversation_id][generation_id].append(log)
    
    return grouped

def get_recent_user_prompts_for_session(conversation_id, n):
    if not conversation_id or n <= 0:
        return []

    logs = load_existing_logs()
    prompts = []
    for log in logs:
        event = log.get('event', {})
        if event.get('hook_event_name') != 'beforeSubmitPrompt':
            continue
        if event.get('conversation_id') != conversation_id:
            continue
        prompt = event.get('prompt')
        if prompt:
            prompts.append(prompt)
    return prompts[-n:]


def _build_user_prompt_payload(recent_user_prompts):
    last = recent_user_prompts[-1] if recent_user_prompts else None
    return {
        'messages': [{'role': 'user', 'content': last}] if last else [],
        'user_prompts': recent_user_prompts,
    }


def send_to_hook_api(request_body, api_key):
    """Send request to /v1/hooks/pretool endpoint."""
    if not api_key:
        return {}

    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/pretool"
    data = json.dumps(request_body)

    for attempt in range(3):
        try:
            result = subprocess.run(
                ["curl", "-fsSL", "-X", "POST",
                 "-H", f"Authorization: Bearer {api_key}",
                 "-H", "Content-Type: application/json",
                 "--data-binary", "@-", url],
                input=data.encode(),
                capture_output=True,
                timeout=20
            )

            # rc==0 means curl got an HTTP 2xx (-f fails on 4xx/5xx), so the
            # server accepted the request. Do NOT retry on success — a retry
            # would re-deliver the same pre-tool event (duplicate). Parse the
            # body if present, otherwise return {} (an empty 2xx is still a
            # successful, non-blocking allow).
            if result.returncode == 0:
                if result.stdout:
                    try:
                        return json.loads(result.stdout.decode('utf-8'))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return {}
                return {}
        except Exception as e:
            log_error(f"Hook API error: {str(e)}", 'api_call')

        if attempt < 2:
            time.sleep(0.5)

    return {}


_APPROVAL_MARKER_FILE = LOG_DIR / ".approval_pending"


def _is_approval_retry(command):
    """True if a marker exists for this exact command and is fresh."""
    try:
        if not _APPROVAL_MARKER_FILE.exists():
            return False
        data = json.loads(_APPROVAL_MARKER_FILE.read_text())
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        return data.get('cmd') == cmd_hash and (time.time() - data.get('ts', 0)) < APPROVAL_TIMEOUT
    except (OSError, json.JSONDecodeError):
        return False


def _set_approval_marker(command, policy_ids, application_id, request_id='', escalated_admin_contact=''):
    _APPROVAL_MARKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        'cmd': hashlib.sha256(command.encode()).hexdigest()[:16],
        'ts': time.time(),
        'policyIds': policy_ids,
        'applicationId': application_id,
        'requestId': request_id,
        'escalatedAdminContact': escalated_admin_contact,
    }
    _APPROVAL_MARKER_FILE.write_text(json.dumps(data))


def _get_approval_marker_data():
    try:
        if _APPROVAL_MARKER_FILE.exists():
            return json.loads(_APPROVAL_MARKER_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _clear_approval_marker():
    try:
        _APPROVAL_MARKER_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _next_poll_interval(elapsed):
    """Pick the polling interval for the current elapsed time using APPROVAL_POLL_PHASES."""
    for upto, interval in APPROVAL_POLL_PHASES:
        if elapsed < upto:
            return interval
    return APPROVAL_POLL_PHASES[-1][1]

def poll_approval_status(api_key, policy_ids, application_id, request_id='', timeout=APPROVAL_TIMEOUT):
    """Poll the approval-status endpoint until approved, denied, or timeout.
    Returns 'approved', 'deny', or 'timeout'."""

    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/pretool/approval-status"
    payload = {"policyIds": policy_ids, "applicationId": application_id}
    if request_id:
        payload["requestId"] = request_id
    body = json.dumps(payload)
    
    start = time.monotonic()
    deadline = start + timeout

    while time.monotonic() < deadline:
        time.sleep(_next_poll_interval(time.monotonic() - start))
        for attempt in range(3):
            try:
                result = subprocess.run(
                    ["curl", "-fsSL", "-X", "POST",
                     "-H", f"Authorization: Bearer {api_key}",
                     "-H", "Content-Type: application/json",
                     "--data-binary", "@-", url],
                    input=body.encode(),
                    capture_output=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout:
                    resp = json.loads(result.stdout.decode('utf-8'))
                    decision = resp.get('decision', 'pending')
                    if decision == 'allow':
                        return 'approved'
                    if decision == 'deny':
                        return 'deny'
                    break
            except Exception as e:
                log_error(f"Approval poll error: {str(e)}", 'api_call')

            if attempt < 2:
                time.sleep(0.5)

    return 'timeout'


def format_hook_response(api_response):
    """Convert API response to Cursor hook output format (permission/user_message/agent_message)."""
    if not api_response:
        return {}
    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')
    additional_context = api_response.get('additionalContext', '')
    # On 'allow', emit no permission so Cursor uses its normal flow instead of the hook force-approving (keep any advisory context).
    if decision not in ('deny', 'block'):
        return {'agent_message': additional_context} if additional_context else {}
    response = {'permission': 'deny'}
    if reason:
        response['user_message'] = reason
    if additional_context:
        response['agent_message'] = additional_context
    return response

def _email_domain(email):
    try:
        if email and '@' in email:
            domain = email.rsplit('@', 1)[1].strip().lower()
            return domain or None
    except Exception:
        pass
    return None


def _cursor_state_db_path():
    if sys.platform == 'darwin':
        return Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    if os.name == 'nt':
        appdata = os.environ.get('APPDATA')
        if not appdata:
            return None
        return Path(appdata) / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    return Path.home() / ".config" / "Cursor" / "User" / "globalStorage" / "state.vscdb"


def _read_cursor_item_table(db_path, keys):
    if not keys:
        return {}
    values = {}
    conn = None
    try:
        uri = f"file:{quote(str(db_path))}?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True)
        placeholders = ','.join('?' for _ in keys)
        cursor = conn.execute(
            f"SELECT key, value FROM ItemTable WHERE key IN ({placeholders})", keys
        )
        for key, value in cursor.fetchall():
            values[key] = value
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return values


def read_account_identity():
    plan = None
    email = None
    try:
        db_path = _cursor_state_db_path()
        if db_path and db_path.exists():
            values = _read_cursor_item_table(
                db_path, ['cursorAuth/cachedEmail', 'cursorAuth/stripeMembershipType']
            )
            email = (values.get('cursorAuth/cachedEmail') or '').strip() or None
            plan = values.get('cursorAuth/stripeMembershipType') or None
    except Exception:
        pass
    return {
        'org_id': None,
        'plan': plan,
        'auth_mode': None,
        'user_email': email,
        'email_domain': _email_domain(email),
    }


# DMI/BIOS serial fields are often unset on VMs and OEM boards and come back as a
# shared sentinel string (with a zero exit code), which would map many machines
# onto one fake serial. Treat these as "no serial" and fall through.
_PLACEHOLDER_SERIALS = {
    '', '0', '00000000', '000000000', '0000000000', 'none', 'na', 'n/a',
    'unknown', 'default', 'default string', 'to be filled by o.e.m.',
    'to be filled by oem', 'system serial number', 'serial number',
    'not applicable', 'not specified', 'not available', 'oem', 'o.e.m.',
    'invalid', '123456789', 'xxxxxxxx',
}


def _valid_serial(value):
    return bool(value) and value.strip().lower() not in _PLACEHOLDER_SERIALS


def _get_device_serial():
    """Best-effort hardware serial, mirroring the MDM setup scripts. Filters known
    OEM/VM placeholder values so two machines never collide on the same fake serial,
    falling through to a stable per-install id (machine-id / MachineGuid) instead."""
    try:
        system = platform.system().lower()
        if system == 'darwin':
            out = subprocess.run(['system_profiler', 'SPHardwareDataType'],
                                 capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                for line in out.stdout.split('\n'):
                    if 'Serial Number' in line:
                        parts = line.split(': ', 1)
                        if len(parts) >= 2 and _valid_serial(parts[1]):
                            return parts[1].strip()
        elif system == 'linux':
            try:
                out = subprocess.run(['dmidecode', '-s', 'system-serial-number'],
                                     capture_output=True, text=True, timeout=10)
                if out.returncode == 0 and _valid_serial(out.stdout):
                    return out.stdout.strip()
            except Exception:
                pass
            for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
                try:
                    value = Path(path).read_text(encoding='utf-8').strip()
                    if _valid_serial(value):
                        return value
                except Exception:
                    continue
        elif system == 'windows':
            try:
                out = subprocess.run(['powershell', '-NoProfile', '-Command',
                                      '(Get-CimInstance -ClassName Win32_BIOS).SerialNumber'],
                                     capture_output=True, text=True, timeout=10)
                if out.returncode == 0 and _valid_serial(out.stdout):
                    return out.stdout.strip()
            except Exception:
                pass
            try:
                out = subprocess.run(['powershell', '-NoProfile', '-Command',
                                      "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid"],
                                     capture_output=True, text=True, timeout=10)
                if out.returncode == 0 and _valid_serial(out.stdout):
                    return out.stdout.strip()
            except Exception:
                pass
    except Exception:
        pass
    return None


def _device_serial(probe=True):
    """Hardware serial, computed once and cached. Never raises and never blocks the
    hook. On the latency-critical pre-tool path callers pass probe=False to read the
    cache only (no subprocess); sessionStart and the end-of-turn exchange probe and
    persist. A missing / corrupt / unreadable cache falls back to a fresh probe (when
    allowed), an unwritable cache is ignored (the probed value is still returned), and
    an unavailable serial returns None so the caller proceeds without it. The cache is
    shared with the claude-code hook, so we merge and write atomically (no torn file)."""
    data = {}
    try:
        loaded = json.loads(IDENTITY_CACHE_PATH.read_text(encoding='utf-8'))
        if isinstance(loaded, dict):
            data = loaded
            cached = data.get('device_serial')
            if isinstance(cached, str) and cached.strip():
                return cached.strip()
    except Exception:
        data = {}
    if not probe:
        return None
    try:
        serial = _get_device_serial()
    except Exception:
        serial = None
    if serial:
        try:
            data['device_serial'] = serial
            IDENTITY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = IDENTITY_CACHE_PATH.parent / (".identity.%d.tmp" % os.getpid())
            tmp.write_text(json.dumps(data), encoding='utf-8')
            os.replace(str(tmp), str(IDENTITY_CACHE_PATH))
        except Exception:
            pass
    return serial


def build_account_identity(event=None, probe=False):
    """Cursor reports user_email on every hook (common schema); read it off the event
    and add the cached device serial. probe defaults False so the latency-critical
    pre-tool path only reads the cache; the end-of-turn exchange passes probe=True.
    Never raises — on any failure the hook proceeds with whatever identity it has."""
    try:
        identity = read_account_identity()
        if not isinstance(identity, dict):
            identity = {}
    except Exception:
        identity = {}
    try:
        if isinstance(event, dict):
            email = (event.get('user_email') or '').strip() or None
            if email:
                identity['user_email'] = email
                if not identity.get('email_domain'):
                    identity['email_domain'] = _email_domain(email)
        serial = _device_serial(probe=probe)
        if serial:
            identity['device_serial'] = serial
    except Exception:
        pass
    return identity


# Cursor surfaces file ops through several event shapes; map each to a normalized
# operation so a pre event (preToolUse Write/Read/Delete) and its completion
# (afterFileEdit / beforeReadFile) for the same path hash to the same synthetic id.
_CURSOR_FILE_OP = {
    'Write': 'write', 'Edit': 'write', 'Delete': 'delete', 'Read': 'read',
    'afterFileEdit': 'write', 'beforeReadFile': 'read',
}


def _resolve_tool_use_id(event):
    """Stable per-call id: the native tool_use_id when Cursor supplies one, else a
    deterministic synthetic id. The key uses ONLY fields byte-identical across the
    before* (pre) and after* (completion) event for the same call — conversation_id,
    generation_id, raw tool_name, and canonical content — so pre and post compute the
    same id. MCP after* events drop the server 'command', so MCP is keyed on
    tool_input only. Fail-open: never raises, falls back to native-or-None."""
    try:
        if not isinstance(event, dict):
            return None
        native = event.get('tool_use_id')
        if native:
            return native
        hook_name = event.get('hook_event_name') or ''
        tool_name = event.get('tool_name') or ''
        ti = event.get('tool_input') if isinstance(event.get('tool_input'), dict) else {}
        # File ops arrive in several shapes (preToolUse Write/Read/Delete, afterFileEdit,
        # beforeReadFile). Normalize them to (operation, path) so a pre event and its
        # completion for the SAME file hash to the same id -- the differing tool_name /
        # tool_input / edits shapes would otherwise fork the id.
        file_op = _CURSOR_FILE_OP.get(tool_name) or _CURSOR_FILE_OP.get(hook_name)
        file_path = event.get('file_path') or ti.get('file_path') or ti.get('path')
        if file_op and file_path:
            tool_disc, content = 'file', file_op + ':' + str(file_path)
        elif 'MCP' in hook_name:
            tool_disc, content = tool_name, json.dumps(ti, sort_keys=True)
        elif event.get('command') is not None:
            tool_disc, content = tool_name, str(event.get('command'))
        elif ti:
            tool_disc, content = tool_name, json.dumps(ti, sort_keys=True)
        else:
            tool_disc, content = tool_name, ''
        key = '\x1f'.join((
            str(event.get('conversation_id') or ''),
            str(event.get('generation_id') or ''),
            tool_disc,
            content,
        ))
        return 'unb-' + hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:24]
    except Exception:
        return event.get('tool_use_id') if isinstance(event, dict) else None


def process_pre_tool_use(event, api_key):
    """preToolUse entry point. The repo gate runs FIRST because _evaluate_pre_tool_use_policies short-circuits for file tools when no policy covers them."""
    gate = _repo_gate_evaluate(event, event.get('tool_name', ''))
    if gate and gate['decision'] == 'deny':
        return _repo_gate_deny_response(gate['repo'])
    response = _evaluate_pre_tool_use_policies(event, api_key)
    if gate:
        return _with_repo_gate_context(
            response, _repo_gate_warning(gate['repo'], gate['remaining'])
        )
    return response


def _evaluate_pre_tool_use_policies(event, api_key):
    """Run the gateway policy check for a preToolUse event."""
    tool_name = event.get('tool_name', '')

    if tool_name not in PRETOOL_NATIVE_TOOLS:
        return {}

    cache = load_policy_cache()
    tools_to_check = cache.get('tools_to_check', []) if cache else []
    need_pull_policies = cache is None or is_cache_stale(cache)

    if tool_name not in tools_to_check and not need_pull_policies:
        return {}

    generation_id = event.get('generation_id')
    conversation_id = event.get('conversation_id')
    model = event.get('model') or 'auto'
    tool_input = event.get('tool_input') or {}

    recent_user_prompts = get_recent_user_prompts_for_session(
        conversation_id, PRETOOL_USER_MESSAGES_LIMIT
    )
    metadata = dict(event)
    file_path = tool_input.get('file_path', '')
    if file_path:
        metadata['file_path'] = file_path

    approval_key = f"{tool_name}:{file_path}" if file_path else tool_name
    is_retry = _is_approval_retry(approval_key)

    request_body = {
        'conversation_id': conversation_id,
        'unbound_app_label': 'cursor',
        'model': model,
        'event_name': 'tool_use',
        'pre_tool_use_data': {
            'tool_name': tool_name,
            'command': '',
            'metadata': metadata
        },
        'account_identity': build_account_identity(event),
        **_build_user_prompt_payload(recent_user_prompts),
    }

    _tuid = _resolve_tool_use_id(event)
    if _tuid:
        request_body['pre_tool_use_data']['tool_use_id'] = _tuid

    if not is_retry:
        request_body['first_approval_check'] = True

    if is_retry:
        marker_data = _get_approval_marker_data()
        if marker_data:
            policy_ids = marker_data.get('policyIds', [])
            application_id = marker_data.get('applicationId', '')
            request_id = marker_data.get('requestId', '')
            _clear_approval_marker()
            result = poll_approval_status(api_key, policy_ids, application_id, request_id=request_id)

            if result == 'approved':
                return {}
            elif result == 'deny':
                return {
                    'permission': 'deny',
                    'user_message': 'Blocked by organization policy. This action was denied via Slack.',
                    'agent_message': 'This action was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                }
            else:
                admin_contact = marker_data.get('escalatedAdminContact', '') or ''
                if admin_contact:
                    timeout_user_message = f'Blocked by organization policy. Approval request timed out — ask {admin_contact} to check Slack and retry.'
                else:
                    timeout_user_message = 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry.'
                return {
                    'permission': 'deny',
                    'user_message': timeout_user_message,
                    'agent_message': 'This action was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                }

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        if get_policy_check_failure_action() == 'block':
            return _gateway_unreachable_response()
        report_error_to_gateway(
            f'Hook bypassed_due_to_failure: gateway unreachable for tool={tool_name}',
            category='bypassed_due_to_failure',
            api_key=api_key,
        )
        return {}

    _cache_policies_from_response(api_response)

    if api_response.get('decision') == 'approval_required':
        approval_check = api_response.get('approvalCheck', {})
        policy_ids = approval_check.get('policyIds', [])
        application_id = approval_check.get('applicationId', '')
        request_id = approval_check.get('requestId', '')
        admin_contact = approval_check.get('escalatedAdminContact', '') or ''

        if admin_contact:
            user_message = (
                f'We could not find your Slack account, so an approval request was sent to {admin_contact}. '
                'Please ask them to approve it in Slack.'
            )
        else:
            user_message = 'An approval request has been sent to your Slack DMs. Please approve it there.'

        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id, escalated_admin_contact=admin_contact)
        return {
            'permission': 'deny',
            'user_message': user_message,
            'agent_message': (
                'This is NOT a permanent block — it is a temporary hold pending Slack approval. '
                f'Tell the user: "{user_message}" '
                'Then immediately retry the exact same tool call with the exact same arguments — '
                'do not modify them in any way, do not add sleep or any prefix. '
                'Retry exactly once — the second attempt will wait for the approval.'
            ),
        }

    return format_hook_response(api_response)


_HOOK_SCRIPT_RUNTIMES = {
    'node', 'nodejs', 'bun', 'deno', 'python', 'python2', 'python3', 'py',
    'ruby', 'dart', 'php', 'perl', 'rscript',
}
_HOOK_SCRIPT_EXT_RE = re.compile(r'\.(sh|py|js|cjs|mjs|ts|tsx|rb|php|dart)$', re.IGNORECASE)
_HOOK_RUNNER_SUBTOKENS = {'run', 'tsx', 'ts-node'}


def _hook_command_basename(command):
    base = re.split(r'[\\/]', (command or '').strip())[-1]
    return re.sub(r'\.(exe|cmd|bat|com)$', '', base.lower())


def _hook_looks_like_path(value):
    v = (value or '').strip().strip('"\'')
    if v.startswith(('http://', 'https://', '@', 'git+')):
        return False
    # Only treat an arg as a local script if it has a recognised script
    # extension. Previously any '/'-containing arg matched, which let a crafted
    # runtime config (e.g. `python3 /etc/passwd`) read arbitrary non-script files.
    return bool(_HOOK_SCRIPT_EXT_RE.search(v))


def _hook_candidate_script(command, args):
    """The local script this config runs: the file arg under a runtime, or the
    command itself when it's a script file. None for packages/urls/binaries."""
    base = _hook_command_basename(command or '')
    if base in _HOOK_SCRIPT_RUNTIMES:
        for a in (args or []):
            if not isinstance(a, str) or a.startswith('-'):
                continue
            t = a.strip().strip('"\'')
            if t in _HOOK_RUNNER_SUBTOKENS:
                continue
            if _hook_looks_like_path(t):
                return t
        return None
    if command and _HOOK_SCRIPT_EXT_RE.search(base):
        return command
    return None


_HOOK_MAX_SCRIPT_BYTES = 256 * 1024


def _compute_script_hash(command, args, cwd):
    """sha256 of the local script's contents, or None when it isn't a resolvable
    local script. Matches what the backend recomputes from the uploaded body, so
    the gateway's `script:<hash>` lookup lines up with the stored fingerprint.
    Capped so all clients agree on the hash for large scripts."""
    try:
        cand = _hook_candidate_script(command, args)
        if not cand:
            return None
        path = os.path.expanduser(os.path.expandvars(cand.strip().strip('"\'')))
        if '${' in path:  # an env var we couldn't expand -> can't resolve
            return None
        if not os.path.isabs(path) and cwd:
            path = os.path.join(cwd, path)
        if not os.path.isfile(path):
            return None
        h = hashlib.sha256()
        remaining = _HOOK_MAX_SCRIPT_BYTES
        with open(path, 'rb') as f:
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _augment_script_hash(result, cwd):
    """Add scriptHash to an MCP server config when it runs a local script, so the
    gateway can fingerprint it as `script:<hash>`."""
    if result and result.get('command'):
        script_hash = _compute_script_hash(result.get('command'), result.get('args'), cwd)
        if script_hash:
            result['scriptHash'] = script_hash
    return result


def _read_mcp_server_config(server_name, config_path):
    """
    Read an MCP server's config (url, command, args) from a config file.
    Returns a dict with only the fields needed for fingerprinting, or None.
    Never includes env or headers (secrets).
    """
    try:
        if not config_path.exists():
            return None
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.loads(f.read())
        servers = config.get('mcpServers', {})
        if not isinstance(servers, dict):
            return None
        server = servers.get(server_name)
        if not isinstance(server, dict):
            return None
        result = {}
        if server.get('url'):
            result['url'] = server['url']
        if server.get('command'):
            result['command'] = server['command']
        if server.get('args'):
            result['args'] = server['args']
        if server.get('type'):
            result['type'] = server['type']
        return result if result else None
    except Exception:
        return None


def process_pre_tool_use_execution(event, api_key, tool_name, command, mcp_server=None, mcp_tool=None):
    """beforeShellExecution / beforeMCPExecution entry point; the gate runs first and applies to the shell event only, an MCP call names no local path to resolve."""
    gate = _repo_gate_evaluate(event, tool_name, command)
    if gate and gate['decision'] == 'deny':
        return _repo_gate_deny_response(gate['repo'])
    response = _evaluate_pre_tool_use_execution_policies(
        event, api_key, tool_name, command, mcp_server=mcp_server, mcp_tool=mcp_tool)
    if gate:
        return _with_repo_gate_context(
            response, _repo_gate_warning(gate['repo'], gate['remaining'])
        )
    return response


def _evaluate_pre_tool_use_execution_policies(event, api_key, tool_name, command, mcp_server=None, mcp_tool=None):
    """Run the gateway policy check for a shell/MCP execution event."""
    generation_id = event.get('generation_id')
    conversation_id = event.get('conversation_id')
    model = event.get('model') or 'auto'

    cache = load_policy_cache()
    need_pull_policies = cache is None or is_cache_stale(cache)

    recent_user_prompts = get_recent_user_prompts_for_session(
        conversation_id, PRETOOL_USER_MESSAGES_LIMIT
    )

    # Build metadata with the raw event, inject mcp fields if present
    metadata = dict(event)
    if mcp_server is not None:
        metadata['mcp_server'] = mcp_server

        server_cfg = _read_mcp_server_config(mcp_server, CURSOR_MCP_CONFIG_PATH)
        if server_cfg:
            metadata['mcp_server_config'] = _augment_script_hash(server_cfg, metadata.get('cwd'))

    if mcp_tool is not None:
        metadata['mcp_tool'] = mcp_tool

    approval_key = f"{tool_name}:{command}"
    is_retry = _is_approval_retry(approval_key)

    request_body = {
        'conversation_id': conversation_id,
        'unbound_app_label': 'cursor',
        'model': model,
        'event_name': 'tool_use',
        'pre_tool_use_data': {
            'tool_name': tool_name,
            'command': command,
            'metadata': metadata
        },
        'account_identity': build_account_identity(event),
        **_build_user_prompt_payload(recent_user_prompts),
    }

    _tuid = _resolve_tool_use_id(event)
    if _tuid:
        request_body['pre_tool_use_data']['tool_use_id'] = _tuid

    if not is_retry:
        request_body['first_approval_check'] = True

    # On retry, skip the gateway call — use cached IDs from the marker and poll.
    if is_retry:
        marker_data = _get_approval_marker_data()
        if marker_data:
            policy_ids = marker_data.get('policyIds', [])
            application_id = marker_data.get('applicationId', '')
            request_id = marker_data.get('requestId', '')
            _clear_approval_marker()
            result = poll_approval_status(api_key, policy_ids, application_id, request_id=request_id)

            if result == 'approved':
                return {}
            elif result == 'deny':
                return {
                    'permission': 'deny',
                    'user_message': 'Blocked by organization policy. This command was denied via Slack.',
                    'agent_message': 'This command was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                }
            else:
                admin_contact = marker_data.get('escalatedAdminContact', '') or ''
                if admin_contact:
                    timeout_user_message = f'Blocked by organization policy. Approval request timed out — ask {admin_contact} to check Slack and retry the command.'
                else:
                    timeout_user_message = 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry the command.'
                return {
                    'permission': 'deny',
                    'user_message': timeout_user_message,
                    'agent_message': 'This command was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                }

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        if get_policy_check_failure_action() == 'block':
            return _gateway_unreachable_response()
        report_error_to_gateway(
            f'Hook bypassed_due_to_failure: gateway unreachable for tool={tool_name}',
            category='bypassed_due_to_failure',
            api_key=api_key,
        )
        return {}

    _cache_policies_from_response(api_response)

    if api_response.get('decision') == 'approval_required':
        approval_check = api_response.get('approvalCheck', {})
        policy_ids = approval_check.get('policyIds', [])
        application_id = approval_check.get('applicationId', '')
        request_id = approval_check.get('requestId', '')
        admin_contact = approval_check.get('escalatedAdminContact', '') or ''

        if admin_contact:
            user_message = (
                f'We could not find your Slack account, so an approval request was sent to {admin_contact}. '
                'Please ask them to approve it in Slack.'
            )
        else:
            user_message = 'An approval request has been sent to your Slack DMs. Please approve it there.'

        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id, escalated_admin_contact=admin_contact)
        return {
            'permission': 'deny',
            'user_message': user_message,
            'agent_message': (
                'This is NOT a permanent block — it is a temporary hold pending Slack approval. '
                f'Tell the user: "{user_message}" '
                'Then immediately retry the exact same tool call with the exact same command — '
                'do not modify the command in any way, do not add sleep or any prefix. '
                'Retry exactly once — the second attempt will wait for the approval.'
            ),
        }

    
    if mcp_server is not None and api_response.get('unknown_mcp_server'):
        server_cfg = metadata.get('mcp_server_config')
        if server_cfg:
            _dispatch_mcp_server_scan(mcp_server, server_cfg)

    return format_hook_response(api_response)


def process_user_prompt_submit(event, api_key):
    """Process beforeSubmitPrompt event for policy checking. Also refreshes the policy cache, which is what makes the session's FIRST gated tool call enforceable: the gate never calls the network."""
    conversation_id = event.get('conversation_id')
    model = event.get('model') or 'auto'
    prompt = event.get('prompt', '')

    cache = load_policy_cache()
    need_pull_policies = cache is None or is_cache_stale(cache)

    request_body = {
        'conversation_id': conversation_id,
        'unbound_app_label': 'cursor',
        'model': model,
        'event_name': 'user_prompt',
        'account_identity': build_account_identity(event),
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }
    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)
    _cache_policies_from_response(api_response)
    return api_response if api_response else {}


def _cursor_usage_from_event(event):
    """Map Cursor stop/afterAgentResponse token fields to the gateway usage shape."""
    if not isinstance(event, dict):
        return None
    if not any(k in event for k in ('input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_write_tokens')):
        return None

    def _i(key):
        try:
            return max(int(event.get(key) or 0), 0)
        except (TypeError, ValueError):
            return 0

    input_tokens = _i('input_tokens')
    output_tokens = _i('output_tokens')
    cache_read = _i('cache_read_tokens')
    cache_write = _i('cache_write_tokens')
    base_input = max(input_tokens - cache_read, 0)

    if not (base_input or output_tokens or cache_read or cache_write):
        return None

    return {
        'input_tokens': base_input,
        'output_tokens': output_tokens,
        'cache_read_input_tokens': cache_read,
        'cache_creation_input_tokens': cache_write,
        'total_tokens': base_input + output_tokens + cache_read + cache_write,
    }


def _strip_git_suffix(segment):
    return segment[:-4] if segment.endswith('.git') else segment


def _github_remote_path(remote_url):
    """Path portion ("org/repo[.git]") of an SSH or HTTPS git remote URL.
    None when the URL is empty or has no recognizable path."""
    if not remote_url:
        return None
    url = remote_url.strip()
    if '://' in url:
        rest = url.split('://', 1)[1]
        parts = rest.split('/', 1)
        return parts[1] if len(parts) == 2 and parts[1] else None
    if ':' in url:
        rest = url.split(':', 1)[1]
        return rest if rest else None
    return None


def _git_origin_url(cwd):
    """Origin's URL, else None; raises only if git cannot run, so callers fail open."""
    result = subprocess.run(
        ['git', '-C', cwd, 'remote', 'get-url', 'origin'],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()



def _remote_host(remote_url):
    """Reject a host-less remote URL, so file:///srv/git/x is not org 'srv'."""
    url = (remote_url or '').strip()
    if '://' in url:
        host = url.split('://', 1)[1].split('/', 1)[0]
    elif ':' in url:
        host = url.split(':', 1)[0]
    else:
        return None
    host = host.rsplit('@', 1)[-1].split('?', 1)[0]
    return host.lower() or None


def _get_git_origin_org_repo(cwd):
    """Lowercased (org, repo) of `cwd`'s origin; git failure propagates upward."""
    url = _git_origin_url(cwd)
    if not url or not _remote_host(url):
        return (None, None)
    path = _github_remote_path(url)
    if not path:
        return (None, None)
    parts = path.split('/')
    if len(parts) < 2:
        return (None, None)
    org = _strip_git_suffix(parts[0]).lower()
    repo = _strip_git_suffix(parts[1]).lower()
    return (org or None, repo or None)

def _get_project(cwd):
    """Lowercased "<org>/<repo>" for `cwd`'s origin, for analytics; never raises."""
    try:
        if not cwd:
            return None
        org, repo = _get_git_origin_org_repo(cwd)
        return f"{org}/{repo}" if org and repo else None
    except Exception:
        return None


def _find_git_root(path):
    """Nearest ancestor of `path` holding a `.git`; None on any error."""
    try:
        p = Path(path)
        for parent in [p] + list(p.parents):
            if (parent / '.git').exists():
                return str(parent)
    except Exception:
        pass
    return None


# Any absolute path inside a shell command; left boundary required so the
# slash inside a relative token (tests/webapp/) doesn't read as absolute.
_ABS_PATH_RE = re.compile(r'(?:^|[\s"\'=(])(/[^\s"\';|&<>()]+)')
# Real git clones that are never the engineer's project: a path under
# /opt/homebrew must not attribute the call to "homebrew/brew" (WEB-5433).
_SYSTEM_CHECKOUT_ROOTS = (
    '/opt/homebrew',
    '/home/linuxbrew',
    '/nix',
    '/usr',
    '/Library',
    '/System',
)


def _is_system_checkout_path(path):
    try:
        normalized = os.path.normpath(path)
        return any(
            normalized == root or normalized.startswith(root + '/')
            for root in _SYSTEM_CHECKOUT_ROOTS
        )
    except Exception:
        return False


# --- Bash calls in scope for the repo gate: a segment's command word invokes git or writes the working tree; anything unclassifiable is not gated ---
_QUOTED_RUN_RE = re.compile(r'"[^"]*"|\'[^\']*\'')
_SHELL_SEGMENT_SEP_RE = re.compile(r'\|\||&&|[;|&\n]')
_ENV_ASSIGNMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
# Wrappers that stand in front of the real command word.
_COMMAND_PREFIX_WORDS = frozenset({'sudo', 'env', 'command'})
# Creating or appending redirect; the lookahead drops `2>&1`, the lookbehind keeps `>>` from counting twice.
_REDIRECT_RE = re.compile(r'(?<!>)>>?(?![&>])')

# Shell commands that mutate the working tree, always a write whatever the flags:
_SHELL_WRITE_COMMANDS = frozenset({
    'rm', 'rmdir', 'unlink', 'shred',       # delete
    'mv', 'cp', 'ln', 'install',            # create or relocate
    'touch', 'mkdir',                       # create
    'tee', 'truncate', 'patch',             # rewrite contents
})
# A write only with the right flag: `sed 's/a/b/' f` and `dd if=f` only read.
_SHELL_INPLACE_COMMANDS = frozenset({'sed', 'perl'})
_INPLACE_FLAG_RE = re.compile(r'^(?:--in-place|-[A-Za-z]*i)')
# DELIBERATELY NOT WRITES: chmod and chown change metadata, not repository content.


def _mask_quoted_runs(command):
    """Blank the inside of quoted runs, preserving length; an unbalanced quote leaves its tail untouched."""
    return _QUOTED_RUN_RE.sub(
        lambda m: m.group(0)[0] + ' ' * (len(m.group(0)) - 2) + m.group(0)[0],
        command)


def _segment_words(segment):
    """A segment's words from its command word on, dropping env assignments and any sudo/env/command wrapper."""
    words = []
    for word in segment.split():
        word = word.strip('()`{}"\'')
        if not words and (not word or word.startswith('-')
                          or _ENV_ASSIGNMENT_RE.match(word)
                          or word in _COMMAND_PREFIX_WORDS):
            continue
        words.append(word)
    return words


def _segment_writes(words):
    """Whether a segment's command word plus its flags mutate the working tree."""
    name = os.path.basename(words[0])
    if name in _SHELL_WRITE_COMMANDS:
        return True
    if name in _SHELL_INPLACE_COMMANDS:
        return any(_INPLACE_FLAG_RE.match(w) for w in words[1:])
    if name == 'dd':
        return any(w.startswith('of=') for w in words[1:])
    return False


def _is_git_command(command):
    """Whether any segment of `command` directly invokes git; False on any error."""
    try:
        if not isinstance(command, str) or 'git' not in command:
            return False
        for segment in _SHELL_SEGMENT_SEP_RE.split(_mask_quoted_runs(command)):
            words = _segment_words(segment)
            if words and os.path.basename(words[0]) == 'git':
                return True
        return False
    except Exception:
        return False


def _is_shell_write_command(command):
    """Whether `command` mutates the working tree: a write command word in any segment, or a creating/appending redirect. False on any error."""
    try:
        if not isinstance(command, str) or not command:
            return False
        masked = _mask_quoted_runs(command)
        if _REDIRECT_RE.search(masked):
            return True
        for segment in _SHELL_SEGMENT_SEP_RE.split(masked):
            words = _segment_words(segment)
            if words and _segment_writes(words):
                return True
        return False
    except Exception:
        return False


# --- Repository-scope gate: blocks writes, git commands and shell writes in repos outside the org's allowed scope; Cursor consults it from both preToolUse and beforeShellExecution ---

# Write tools, git commands and shell writes only; reads, conversation and every other shell command (ls, cat, npm test) are ungated.
_REPO_GATE_SHELL_TOOL = 'Shell'
_REPO_GATE_SHELL_TOOLS = frozenset({_REPO_GATE_SHELL_TOOL})
_REPO_GATE_WRITE_TOOLS = frozenset({'Write', 'Delete'})
_REPO_GATE_TOOLS = _REPO_GATE_WRITE_TOOLS | _REPO_GATE_SHELL_TOOLS
REPO_GATE_BLOCK_CONTEXT = (
    'This action was blocked by an organization repository-scope policy. Do not '
    'attempt to achieve the same result using alternative tools, file operations, '
    'or workarounds. Inform the user and stop.'
)






def _repo_gate_applies(tool_name, command):
    """Whether this call is in the gate's scope: a write tool always, a shell call only when it invokes git or writes."""
    if tool_name in _REPO_GATE_SHELL_TOOLS:
        return _is_git_command(command) or _is_shell_write_command(command)
    return tool_name in _REPO_GATE_WRITE_TOOLS


def _repo_gate_block_policies(policies):
    """Enforceable subset; a policy this hook cannot read is dropped, not guessed."""
    enforceable = []
    for policy in policies or []:
        if not isinstance(policy, dict):
            continue
        grace = policy.get('grace_turns')
        if isinstance(grace, bool) or not isinstance(grace, int) or grace < 0:
            continue
        org = policy.get('github_org')
        if not isinstance(org, str) or not org.strip():
            continue
        enforceable.append(policy)
    return enforceable


def _repo_gate_scope_allows(policy, org, repo):
    """Whether `org` matches this policy's allowed organization; both lowercased."""
    return org == policy['github_org'].strip().lower()


def _repo_gate_violating_repo(candidates, block_policies, root_projects):
    """First candidate outside every scope; a git failure propagates to fail open."""
    for candidate in candidates:
        root = _find_git_root(candidate)
        if not root:
            continue
        if root not in root_projects:
            root_projects[root] = _get_git_origin_org_repo(root)
        org, repo = root_projects[root]
        if not org or not repo:
            continue
        if not any(_repo_gate_scope_allows(p, org, repo) for p in block_policies):
            return '%s/%s' % (org, repo)
    return None


def _repo_gate_workspace_dir(event):
    """The event's cwd when Cursor sends one, else the first workspace root."""
    cwd = event.get('cwd')
    if isinstance(cwd, str) and cwd:
        return cwd
    roots = event.get('workspace_roots')
    if isinstance(roots, list) and roots and isinstance(roots[0], str):
        return roots[0]
    return None


def _repo_gate_candidates(event, tool_name, command):
    """Paths a Cursor call works in, backstopped by the workspace root."""
    if tool_name == _REPO_GATE_SHELL_TOOL:
        candidates = []
        if isinstance(command, str) and command:
            candidates.extend(
                p for p in _ABS_PATH_RE.findall(command)
                if not _is_system_checkout_path(p)
            )
        if not candidates:
            workspace = _repo_gate_workspace_dir(event)
            if workspace:
                candidates.append(workspace)
        return candidates
    tool_input = event.get('tool_input') or {}
    path = (event.get('file_path') or tool_input.get('file_path')
            or tool_input.get('path'))
    if not isinstance(path, str) or not path:
        return []
    # A relative path resolves against the workspace dir, or nothing is judged.
    if not path.startswith('/'):
        workspace = _repo_gate_workspace_dir(event)
        if workspace:
            path = os.path.normpath(os.path.join(workspace, path))
    if path.startswith('/') and not _is_system_checkout_path(path):
        return [os.path.dirname(path)]
    return []


def _repo_gate_turn_id(event):
    """Turn identity so one turn burns one grace; `generation_id`, else per call."""
    generation_id = event.get('generation_id')
    if generation_id:
        return str(generation_id)
    return REPO_GATE_UNKNOWN_TURN


def _load_repo_gate_state(session_id):
    """Grace state, keyed on session; anything unreadable reads as unused grace."""
    fresh = {'used': 0, 'turns': []}
    try:
        with open(REPO_GATE_STATE_FILE, 'r', encoding='utf-8') as f:
            state = json.loads(f.read())
        if not isinstance(state, dict) or state.get('session_id') != session_id:
            return fresh
        used = state.get('used')
        turns = state.get('turns')
        if isinstance(used, bool) or not isinstance(used, int) or used < 0:
            return fresh
        if not isinstance(turns, list):
            return fresh
        return {'used': used, 'turns': [t for t in turns if isinstance(t, str)]}
    except (OSError, ValueError):
        return fresh


def _save_repo_gate_state(session_id, state):
    """Atomic replace, so parallel calls in one turn cannot leave a torn file."""
    try:
        REPO_GATE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({
            'session_id': session_id,
            'used': state['used'],
            'turns': state['turns'][-REPO_GATE_TURN_MEMORY:],
        })
        tmp = REPO_GATE_STATE_FILE.parent / ('.repo_gate.%d.tmp' % os.getpid())
        tmp.write_text(payload, encoding='utf-8')
        os.replace(str(tmp), str(REPO_GATE_STATE_FILE))
    except Exception:
        pass


def _repo_gate_warning(repo, remaining):
    if remaining <= 0:
        tail = 'This is the final warning — the next turn touching an out-of-scope repository will be blocked.'
    elif remaining == 1:
        tail = '1 warning left before out-of-scope repositories are blocked.'
    else:
        tail = '%d warnings left before out-of-scope repositories are blocked.' % remaining
    return (
        'Unbound repository policy: this action works in "%s", which is outside '
        'your organization\'s allowed repository scope. %s' % (repo, tail)
    )


def _repo_gate_block_reason(repo):
    return (
        'Blocked by organization policy. "%s" is outside your organization\'s '
        'allowed repository scope.' % repo
    )


# --- incident reporting: telemetry only, dispatched after the verdict and never waited on; `surface` is always "tool" ---

REPO_GATE_AGENT = 'cursor'
REPO_GATE_REPORT_MAX_CHARS = 2000
_REPO_GATE_INPUT_KEYS = ('command', 'commandLine', 'file_path', 'filePath',
                         'path', 'notebook_path')


def _repo_gate_clip(text):
    """Cap one reported string, keeping the body inside curl's pipe buffer."""
    if not isinstance(text, str) or not text:
        return None
    return text[:REPO_GATE_REPORT_MAX_CHARS]


def _repo_gate_binding_policy(block_policies):
    """The denying policy whose grace decided warn-vs-block."""
    return min(block_policies, key=lambda p: p['grace_turns'])


def _repo_gate_post(body, api_key):
    """Never waited on, so the blocking path stays free of synchronous work."""
    proc = subprocess.Popen(
        ['curl', '-fsSL', '--max-time', '10', '-X', 'POST',
         '-H', 'Authorization: Bearer %s' % api_key,
         '-H', 'Content-Type: application/json',
         '--data-binary', '@-',
         '%s/v1/hooks/repo-gate' % UNBOUND_GATEWAY_URL],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.stdin.write(body.encode())
    proc.stdin.close()


def _repo_gate_report(gate, block_policies, context):
    """Report one WARN or BLOCK, fire and forget; never raises, never blocks."""
    try:
        decision = (gate or {}).get('decision')
        if decision not in ('warn', 'deny'):
            return
        # main() already resolved the key; the fallback covers entry points that skip it.
        api_key = _cached_api_key or get_api_key()
        if not api_key:
            return
        policy = _repo_gate_binding_policy(block_policies)
        # WARN reports how far into the grace it got; BLOCK reports the whole grace.
        grace = policy.get('grace_turns')
        remaining = gate.get('remaining')
        if isinstance(grace, bool) or not isinstance(grace, int):
            turn = None
        elif isinstance(remaining, int) and not isinstance(remaining, bool):
            turn = grace - remaining
        else:
            turn = grace
        # What the call was about: its shell command, or the path it names.
        tool_input = context.get('tool_input')
        if isinstance(tool_input, dict):
            named = [tool_input.get(k) for k in _REPO_GATE_INPUT_KEYS]
            tool_input = next((v for v in named if isinstance(v, str) and v), None)
        _repo_gate_post(json.dumps({
            'policy_id': policy.get('id'),
            'policy_name': policy.get('name'),
            'repository': gate.get('repo'),
            'decision': 'BLOCK' if decision == 'deny' else 'WARN',
            'agent': REPO_GATE_AGENT,
            'surface': context.get('surface'),
            'tool_name': context.get('tool_name'),
            'session_id': context.get('session_id'),
            'turn': turn,
            'prompt_text': _repo_gate_clip(context.get('prompt_text')),
            'tool_input': _repo_gate_clip(tool_input),
        }), api_key)
    except Exception:
        pass


def _repo_gate_evaluate(event, tool_name, command=''):
    """Verdict for one tool call: None allows, else deny or warn. Never raises."""
    try:
        if not _repo_gate_applies(tool_name, command):
            return None
        block_policies = _repo_gate_block_policies(get_repo_policies())
        if not block_policies:
            return None

        candidates = _repo_gate_candidates(event, tool_name, command)
        repo = _repo_gate_violating_repo(candidates, block_policies, {})
        gate = _repo_gate_decide(event, block_policies, repo)
        _repo_gate_report(gate, block_policies, {
            'surface': 'tool',
            'session_id': event.get('conversation_id'),
            'tool_name': tool_name,
            # The shell event carries its command as an argument; file events name their path on the event itself.
            'tool_input': command or event.get('tool_input') or event,
        })
        return gate
    except Exception:
        return None


def _repo_gate_decide(event, block_policies, repo):
    """One grace per turn; memoizing the unknown-turn sentinel freezes grace."""
    if not repo:
        return None
    grace = min(p['grace_turns'] for p in block_policies)
    conversation_id = event.get('conversation_id')
    state = _load_repo_gate_state(conversation_id)
    turn_id = _repo_gate_turn_id(event)
    known_turn = turn_id != REPO_GATE_UNKNOWN_TURN
    if not known_turn or turn_id not in state['turns']:
        if state['used'] >= grace:
            return {'decision': 'deny', 'repo': repo}
        state['used'] += 1
        if known_turn:
            state['turns'].append(turn_id)
        _save_repo_gate_state(conversation_id, state)
    return {
        'decision': 'warn',
        'repo': repo,
        'remaining': max(0, grace - state['used']),
    }


def _repo_gate_deny_response(repo):
    return format_hook_response({
        'decision': 'deny',
        'reason': _repo_gate_block_reason(repo),
        'additionalContext': REPO_GATE_BLOCK_CONTEXT,
    })


def _with_repo_gate_context(response, context):
    """Append via `agent_message`; additive, so a real block is never downgraded."""
    if not context:
        return response
    merged = dict(response or {})
    existing = merged.get('agent_message') or ''
    merged['agent_message'] = (
        existing + '\n\n' + context if existing else context
    )
    return merged


def _trusted_ancestors(start):
    """Ancestors of `start`, stopping before the first directory another local
    user could write to. Without this the walk reaches shared dirs like /tmp,
    where anyone can plant a SKILL.md and spoof skill telemetry."""
    out = []
    try:
        uid = os.getuid()
    except AttributeError:
        uid = None  # Windows: no uid model, fall back to the plain walk
    for path in [start] + list(start.parents):
        if uid is not None:
            try:
                info = path.stat()
            except OSError:
                break
            # 0o022: group- or world-writable, both plantable by another user.
            if info.st_uid not in (uid, 0) or (info.st_mode & 0o022):
                break
        out.append(path)
    return out


def _skill_roots(cwd):
    """Directories a skill root may hang off: every given root's ancestors,
    plus home. Accepts one path or several."""
    starts = [cwd] if isinstance(cwd, str) else list(cwd or [])
    roots = []
    for start in starts:
        if start:
            roots += _trusted_ancestors(Path(start))
    roots.append(Path.home())
    return {str(r).replace('\\', '/') for r in roots}


def _skill_path_key(path):
    """Separator-normalised path, so a read (which keeps the payload's '/')
    and a body match (which uses str(Path), '\\' on Windows) compare equal."""
    return path.replace('\\', '/') if isinstance(path, str) else path


def _skill_name_from_path(file_path, cwd=None):
    """Skill name when a path sits under a real skill root, else None. The root
    must hang off cwd's ancestry or home, so a lookalike such as
    <project>/fixtures/.cursor/skills/x/SKILL.md is not counted. Separators are
    normalised because hook payloads use '/' even on Windows."""
    try:
        if not isinstance(file_path, str):
            return None
        parts = file_path.replace('\\', '/').split('/')
        if len(parts) < 4 or parts[-1] != 'SKILL.md':
            return None
        allowed = _skill_roots(cwd)
        for root in SKILL_SEARCH_DIRS:
            span = len(root)
            for i in range(len(parts) - span - 1):
                if tuple(parts[i:i + span]) != tuple(root):
                    continue
                if '/'.join(parts[:i]) in allowed:
                    return parts[-2]
        return None
    except Exception:
        return None

def _project_for_paths(candidates, root_projects):
    """First project ("<org>/<repo>") resolved from `candidates` paths.
    `root_projects` caches origin lookups so `git remote get-url` runs at
    most once per distinct repo. None when nothing resolves (fail-open)."""
    try:
        for candidate in candidates:
            if not candidate:
                continue
            root = _find_git_root(candidate)
            if not root:
                continue
            if root not in root_projects:
                root_projects[root] = _get_project(root)
            if root_projects[root]:
                return root_projects[root]
    except Exception:
        pass
    return None


def build_llm_exchange(events, api_key=None):
    """Build standard LLM exchange format from events."""
    messages = []
    assistant_tool_uses = []
    
    user_prompt = None
    assistant_response = None
    conversation_id = None
    generation_id = None
    model = None
    user_email = None
    request_initialized = None
    request_completed = None
    usage = None
    # Working-dir context for per-entry project attribution: every Cursor
    # event carries workspace_roots; shell events carry an explicit cwd.
    workspace_cwd = None
    workspace_roots = []
    read_skills = set()
    root_projects = {}

    for log_entry in events:
        event = log_entry.get('event', {})
        hook_event_name = event.get('hook_event_name')

        if not workspace_cwd:
            roots = event.get('workspace_roots')
            if isinstance(roots, list) and roots and isinstance(roots[0], str):
                workspace_cwd = roots[0]
                workspace_roots = list(roots)

        if not conversation_id:
            conversation_id = event.get('conversation_id')

        if not generation_id:
            generation_id = event.get('generation_id')

        if not model:
            model = event.get('model')

        if not user_email:
            user_email = event.get('user_email')

        if hook_event_name == 'beforeSubmitPrompt':
            user_prompt = event.get('prompt')
            request_initialized = log_entry.get('timestamp')

        elif hook_event_name == 'stop':
            request_completed = log_entry.get('timestamp')
            usage = _cursor_usage_from_event(event) or usage

        elif hook_event_name == 'beforeReadFile':
            file_path = event.get('file_path')
            read_entry = {
                'type': hook_event_name,
                'file_path': file_path,
                'content': event.get('content', ''),
                'attachments': event.get('attachments', []),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(
                    [os.path.dirname(file_path)]
                    if isinstance(file_path, str) and file_path.startswith('/') and not _is_system_checkout_path(file_path)
                    else [],
                    root_projects)
            }
            # Cursor loads a skill by reading its SKILL.md, so this read is the
            # only skill-invocation signal it emits.
            # Prefer the read event's own roots: the first logged event may
            # have carried an incomplete list.
            event_roots = [r for r in (event.get('workspace_roots') or [])
                           if isinstance(r, str) and r]
            skill_name = _skill_name_from_path(
                file_path,
                (event_roots + workspace_roots) or workspace_cwd)
            # Re-reading one SKILL.md in a turn is still a single invocation.
            # Keyed by path, not name: two skills can share a name under
            # different roots and are different skills.
            if skill_name and _skill_path_key(file_path) not in read_skills:
                read_skills.add(_skill_path_key(file_path))
                read_entry['skill_name'] = skill_name
                read_entry['skill_path'] = file_path
            assistant_tool_uses.append(read_entry)

        elif hook_event_name == 'postToolUse':
            tool_name = event.get('tool_name', '')

            if tool_name not in EXCHANGE_NATIVE_TOOLS:
                continue

            tool_output = event.get('tool_output', '')

            # Attribute the call to the repo it worked in: the event's own
            # cwd when present, else absolute paths inside tool_input.
            candidates = []
            if isinstance(event.get('cwd'), str):
                candidates.append(event['cwd'])
            tool_input = event.get('tool_input')
            if isinstance(tool_input, dict):
                for value in tool_input.values():
                    if isinstance(value, str) and value.startswith('/') and not _is_system_checkout_path(value):
                        candidates.append(os.path.dirname(value))

            assistant_tool_uses.append({
                'type': hook_event_name,
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_output': tool_output,
                'duration': event.get('duration'),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(candidates or [workspace_cwd], root_projects)
            })

        elif hook_event_name == 'afterFileEdit':
            file_path = event.get('file_path')
            assistant_tool_uses.append({
                'type': hook_event_name,
                'file_path': file_path,
                'edits': event.get('edits', []),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(
                    [os.path.dirname(file_path)]
                    if isinstance(file_path, str) and file_path.startswith('/') and not _is_system_checkout_path(file_path)
                    else [],
                    root_projects)
            })

        elif hook_event_name == 'afterShellExecution':
            command = event.get('command')
            # The event's cwd is where the command actually ran; absolute
            # paths in the command and the workspace root are fallbacks.
            candidates = []
            if isinstance(event.get('cwd'), str):
                candidates.append(event['cwd'])
            if isinstance(command, str):
                candidates.extend(
                    p for p in _ABS_PATH_RE.findall(command) if not _is_system_checkout_path(p)
                )
            if not candidates and workspace_cwd:
                candidates.append(workspace_cwd)
            assistant_tool_uses.append({
                'type': hook_event_name,
                'command': command,
                'output': event.get('output', ''),
                'tool_use_id': _resolve_tool_use_id(event),
                'project': _project_for_paths(candidates, root_projects)
            })

        elif hook_event_name == 'afterMCPExecution':
            assistant_tool_uses.append({
                'type': hook_event_name,
                'tool_name': event.get('tool_name'),
                'tool_input': event.get('tool_input'),
                'result_json': event.get('result_json'),
                'tool_use_id': _resolve_tool_use_id(event)
            })
        
        elif hook_event_name == 'afterAgentResponse':
            assistant_response = event.get('text')
            usage = _cursor_usage_from_event(event) or usage
    
    if user_prompt:
        messages.append({'role': 'user', 'content': user_prompt})
    
    if assistant_response:
        assistant_msg = {'role': 'assistant', 'content': assistant_response}
        if assistant_tool_uses:
            assistant_msg['tool_use'] = assistant_tool_uses
        messages.append(assistant_msg)
    
    if not messages:
        return None
    
    if not model or model == 'default' or model == 'unknown':
        model = 'auto'

    exchange = {
        'conversation_id': conversation_id,
        'model': model,
        'messages': messages,
        'cwd': workspace_cwd,
        # Turn-level fallback: rows without a per-call project (the user
        # prompt row, or tool-less turns) inherit the workspace repo.
        'project': _project_for_paths([workspace_cwd], root_projects),
        'account_identity': build_account_identity({'user_email': user_email}, probe=True)
    }

    # Omit when unknown; gateway falls back
    if request_initialized:
        exchange['requestInitialized'] = request_initialized
    if request_completed:
        exchange['requestCompleted'] = request_completed

    if usage:
        exchange['usage'] = usage

    # Exact per-turn id for deterministic idempotency (vs a content hash).
    if generation_id:
        exchange['turn_request_id'] = generation_id

    return exchange


def send_to_api(exchange, api_key):
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False
    
    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/cursor"
    data = json.dumps(exchange)

    for attempt in range(3):
        try:
            result = subprocess.run(
                ["curl", "-fsSL", "-X", "POST",
                 "-H", f"Authorization: Bearer {api_key}",
                 "-H", "Content-Type: application/json",
                 "--data-binary", "@-", url],
                input=data.encode(),
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                return True
            error_msg = result.stderr.decode('utf-8', errors='ignore').strip() if result.stderr else "Unknown error"
            log_error(f"API request failed: {error_msg}", 'api_call')
        except Exception as e:
            log_error(f"Exception in send_to_api: {str(e)}", 'api_call')

        if attempt < 2:
            time.sleep(0.5)

    return False


def cleanup_interrupted_requests(logs, current_conversation_id, current_generation_id):
    """
    Remove incomplete generation logs when a new generation starts in the same conversation.
    This handles interrupted requests (user stopped and started a new request).
    """
    cleaned_logs = []
    conversation_generations = defaultdict(set)
    
    # First pass: identify all generation_ids per conversation
    for log in logs:
        event = log.get('event', {})
        conv_id = event.get('conversation_id')
        gen_id = event.get('generation_id')
        if conv_id and gen_id:
            conversation_generations[conv_id].add(gen_id)
    
    # Check if current generation is new in this conversation
    if current_conversation_id in conversation_generations:
        existing_gens = conversation_generations[current_conversation_id]
        
        # If this is a new generation in the same conversation, remove incomplete ones
        if current_generation_id not in existing_gens:
            # Find incomplete generations (no stop event)
            for log in logs:
                event = log.get('event', {})
                conv_id = event.get('conversation_id')
                gen_id = event.get('generation_id')
                
                # Keep logs from other conversations or completed generations
                if conv_id != current_conversation_id:
                    cleaned_logs.append(log)
                elif conv_id == current_conversation_id and gen_id in existing_gens:
                    # Check if this generation has a stop event
                    has_stop = any(
                        l.get('event', {}).get('generation_id') == gen_id and
                        l.get('event', {}).get('hook_event_name') == 'stop'
                        for l in logs
                    )
                    if has_stop:
                        cleaned_logs.append(log)
                    # else: skip incomplete generation logs
            
            return cleaned_logs
    
    return logs


def cleanup_old_logs():
    """
    Manage log file size by removing old generation_ids when log count exceeds 50.
    Keeps only the most recent generation_id's entries to ensure current request is safe.
    """
    
    logs = load_existing_logs()

    if len(logs) <= AUDIT_LOG_TOTAL_LIMIT:
        return

    conversation_order = []
    seen_conversations = set()

    for log in logs:
        event = log.get('event', {})
        conv_id = event.get('conversation_id')
        if conv_id and conv_id not in seen_conversations:
            conversation_order.append(conv_id)
            seen_conversations.add(conv_id)

    if len(conversation_order) > 1:
        most_recent_conv_id = conversation_order[-1]
        kept_logs = [
            log for log in logs
            if log.get('event', {}).get('conversation_id') == most_recent_conv_id
        ]
        save_logs(kept_logs)
    elif len(logs) > AUDIT_LOG_TOTAL_LIMIT:
        save_logs(logs[-AUDIT_LOG_TOTAL_LIMIT:])


def process_stop_event(generation_id, api_key=None):
    """Process stop event: convert to LLM format and send to API."""
    logs = load_existing_logs()
    
    # Group events
    grouped = group_events_by_generation(logs)
    
    # Find and process the generation with stop event
    for conversation_id, generations in grouped.items():
        if generation_id in generations:
            events = generations[generation_id]
            
            # Check if this generation has a stop event
            has_stop = any(
                log.get('event', {}).get('hook_event_name') == 'stop'
                for log in events
            )
            
            if has_stop:
                exchange = build_llm_exchange(events, api_key)
                if exchange:
                    send_to_api(exchange, api_key)
                break


def get_api_key():
    """Get API key from env var or ~/.unbound/config.json."""
    key = os.getenv('UNBOUND_CURSOR_API_KEY')
    if key:
        return key
    try:
        config_file = Path.home() / ".unbound" / "config.json"
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.loads(f.read()).get('api_key')
    except FileNotFoundError:
        return None
    except Exception as e:
        log_error(f"Failed to read config file: {e}", 'config')
        return None


_GATEWAY_URL_RE = re.compile(r'^https?://[A-Za-z0-9._\-]+(:\d+)?(/[A-Za-z0-9._/\-]*)?$')
_BAKED_GATEWAY_RE = re.compile(r'os\.environ\.get\(\s*"UNBOUND_GATEWAY_URL"\s*,\s*"([^"]*)"')


def _is_valid_gateway_url(url: str) -> bool:
    if not url or any(c in url for c in '"\\\n\r\x00'):
        return False
    return bool(_GATEWAY_URL_RE.fullmatch(url))


def _baked_gateway_url(text: str) -> str:
    # read baked url, not env
    match = _BAKED_GATEWAY_RE.search(text)
    return match.group(1) if match else ""


def _rebake_gateway_url(text: str, gateway_url: str) -> str:
    # rewrite only the env-var default, nothing else
    return _BAKED_GATEWAY_RE.sub(
        lambda m: m.group(0).replace(f'"{m.group(1)}"', f'"{gateway_url}"'),
        text,
        count=1,
    )


def _self_update_due() -> bool:
    try:
        return (time.time() - SELF_UPDATE_STATE_PATH.stat().st_mtime) >= SELF_UPDATE_INTERVAL_SECONDS
    except OSError:
        return True


def _acquire_self_update_lock() -> bool:
    try:
        if SELF_UPDATE_LOCK_PATH.exists():
            if (time.time() - SELF_UPDATE_LOCK_PATH.stat().st_mtime) < SELF_UPDATE_LOCK_TTL_SECONDS:
                return False
            SELF_UPDATE_LOCK_PATH.unlink(missing_ok=True)
        fd = os.open(str(SELF_UPDATE_LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        return True
    except (FileExistsError, OSError):
        return False


def _download_latest_hook():
    try:
        result = subprocess.run(
            ["curl", "-fsSL", "--max-time", str(SELF_UPDATE_CURL_TIMEOUT), SELF_UPDATE_URL],
            capture_output=True, timeout=SELF_UPDATE_CURL_TIMEOUT + 5,
        )
        if result.returncode != 0 or not result.stdout:
            return None
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return None


def _replace_self(new_bytes: bytes) -> None:
    try:
        mode = SELF_SCRIPT_PATH.stat().st_mode
    except OSError:
        mode = 0o755
    fd, tmp_path = tempfile.mkstemp(dir=str(SELF_SCRIPT_PATH.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(new_bytes)
        os.replace(tmp_path, SELF_SCRIPT_PATH)
        os.chmod(SELF_SCRIPT_PATH, mode | 0o111)
    except OSError as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        log_error(f"self_update replace failed: {e}", 'self_update')


def _check_self_update() -> None:
    if RUNNING_FROZEN:
        # Binary deployments are updated by the MDM package, never in place.
        return
    # Under MDM the hook runs from an admin-managed (enterprise) location we
    # can't write to, so SELF_SCRIPT_PATH (user-level) is not the file executing
    # — updating it would only write a dead copy the enterprise hooks never run.
    # The daily MDM cron refreshes the enterprise script instead. Only
    # self-update when we are actually running the user-level script.
    try:
        running = os.path.normcase(str(Path(__file__).resolve()))
        target = os.path.normcase(str(SELF_SCRIPT_PATH.resolve()))
    except Exception as e:
        log_error(f"self_update skipped: could not resolve script path: {e}", 'self_update')
        return
    if running != target:
        # Running from a managed/enterprise location (MDM) — the daily cron owns
        # updates there; skipping is expected, not an error.
        return
    # refresh hook from main, throttled per interval
    try:
        if not _self_update_due():
            return
        try:
            SELF_SCRIPT_PATH.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        if not _acquire_self_update_lock():
            return
        try:
            SELF_UPDATE_STATE_PATH.touch()  # one attempt per interval
            try:
                local_bytes = SELF_SCRIPT_PATH.read_bytes()
                gateway_url = _baked_gateway_url(local_bytes.decode("utf-8", errors="replace"))
            except OSError:
                # self file gone — heal by re-pulling; recover tenant url
                # from the running instance, no local file to read it from
                local_bytes = None
                gateway_url = UNBOUND_GATEWAY_URL
            if not _is_valid_gateway_url(gateway_url):
                log_error("self_update skipped: invalid gateway url", 'self_update')
                return

            payload = _download_latest_hook()
            if not payload:
                return
            remote_text = payload.decode("utf-8", errors="replace")
            if "UNBOUND_GATEWAY_URL" not in remote_text:
                log_error("self_update skipped: bad download", 'self_update')
                return

            new_text = _rebake_gateway_url(remote_text, gateway_url)
            if _baked_gateway_url(new_text) != gateway_url:
                log_error("self_update skipped: gateway url not preserved", 'self_update')
                return
            new_bytes = new_text.encode("utf-8")
            if local_bytes is None or hashlib.sha256(new_bytes).digest() != hashlib.sha256(local_bytes).digest():
                _replace_self(new_bytes)
        finally:
            SELF_UPDATE_LOCK_PATH.unlink(missing_ok=True)
    except Exception as e:
        log_error(f"self_update error: {e}", 'self_update')


def _install_sh_is_stale():
    try:
        return (time.time() - DISCOVERY_INSTALL_SH.stat().st_mtime) > DISCOVERY_INSTALL_SH_TTL_SECONDS
    except OSError:
        return True


def _dispatch_mcp_server_scan(server_name, server_config):
    """Report ONE unknown MCP server out-of-band.

    Detached so the blocking PreToolUse hook returns immediately. Secrets
    (server_config args, api key) go via env, never argv or the shell string.
    """
    if not server_name:
        log_error("mcp scan dispatch: empty server name, skipping", 'mcp_server')
        return
    try:
        try:
            with UNBOUND_CONFIG_PATH.open("r", encoding="utf-8") as f:
                unbound_config = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log_error(f"mcp scan dispatch: cannot read config: {e}", 'mcp_server')
            return
        api_key = unbound_config.get("api_key")
        backend_url = unbound_config.get("base_url")
        if not api_key or not backend_url:
            log_error("mcp scan dispatch: api_key/base_url missing in config", 'mcp_server')
            return

        if RUNNING_FROZEN:
            # Frozen binary: never fetch install.sh — run the locally
            # installed discovery binary, or skip if it isn't there.
            if not os.path.isfile(FROZEN_DISCOVERY_BIN):
                log_error(f"mcp scan dispatch: discovery binary missing at {FROZEN_DISCOVERY_BIN}", 'mcp_server')
                return
            scan_cmd = [FROZEN_DISCOVERY_BIN, "mcp-scan",
                        "--name", server_name, "--domain", backend_url]
        else:
            DISCOVERY_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
            bootstrap = (
                'set -e; '
                f'SH="{DISCOVERY_INSTALL_SH.as_posix()}"; '
                f'if [ ! -f "$SH" ] || [ -n "$(find "$SH" -mmin +{DISCOVERY_INSTALL_SH_TTL_SECONDS // 60} 2>/dev/null)" ]; then '
                f'T="$(mktemp)"; curl -fsSL -o "$T" "{DISCOVERY_INSTALL_URL}" '
                '&& chmod 755 "$T" && mv -f "$T" "$SH" || rm -f "$T"; fi; '
                'exec bash "$SH" mcp-scan --name "$UNBOUND_MCP_SERVER_NAME" --domain "$UNBOUND_MCP_DOMAIN"'
            )
            scan_cmd = ["bash", "-c", bootstrap]
        popen_kwargs = {
            "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
            "stdin": subprocess.DEVNULL, "close_fds": True,
            "env": {**os.environ,
                    "UNBOUND_API_KEY": api_key,
                    "UNBOUND_MCP_SERVER_JSON": json.dumps(server_config),
                    "UNBOUND_MCP_SERVER_NAME": server_name,
                    "UNBOUND_MCP_DOMAIN": backend_url},
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        subprocess.Popen(scan_cmd, **popen_kwargs)
    except Exception as e:
        log_error(f"mcp scan dispatch failed for {server_name}: {e}", 'mcp_server')
        return


def _dispatch_discovery() -> None:
    try:
        cache = {}
        if DISCOVERY_CACHE_PATH.exists():
            try:
                with DISCOVERY_CACHE_PATH.open("r", encoding="utf-8") as f:
                    cache = json.load(f) or {}
            except (OSError, json.JSONDecodeError):
                cache = {}
        if not isinstance(cache, dict):
            cache = {}

        last = cache.get("last_run_at")
        if isinstance(last, str):
            try:
                ts = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
                if (time.time() - ts) < DISCOVERY_DEBOUNCE_SECONDS:
                    return
            except ValueError:
                pass

        if DISCOVERY_LOCK_PATH.exists():
            try:
                age = time.time() - DISCOVERY_LOCK_PATH.stat().st_mtime
            except OSError:
                age = DISCOVERY_STALE_LOCK_SECONDS + 1
            if age < DISCOVERY_STALE_LOCK_SECONDS:
                return

        # Atomic dispatch claim — first hook to create the marker wins;
        # concurrent peers bail to avoid duplicate fork-detached Popens.
        try:
            _dispatch_fd = os.open(str(DISCOVERY_DISPATCH_PATH),
                                   os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(_dispatch_fd)
        except FileExistsError:
            try:
                age = time.time() - DISCOVERY_DISPATCH_PATH.stat().st_mtime
            except OSError:
                age = DISCOVERY_DISPATCH_TTL_SECONDS + 1
            if age < DISCOVERY_DISPATCH_TTL_SECONDS:
                return
            try:
                DISCOVERY_DISPATCH_PATH.unlink()
                _dispatch_fd = os.open(str(DISCOVERY_DISPATCH_PATH),
                                       os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(_dispatch_fd)
            except (FileExistsError, OSError):
                return

        try:
            try:
                with UNBOUND_CONFIG_PATH.open("r", encoding="utf-8") as f:
                    unbound_config = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                log_error(f"discovery gate: could not read {UNBOUND_CONFIG_PATH}: {e}", 'discovery_gate')
                return
            api_key = unbound_config.get("api_key")
            backend_url = unbound_config.get("base_url")
            if not api_key:
                log_error("discovery gate: api_key missing in ~/.unbound/config.json", 'discovery_gate')
                return
            if not backend_url:
                log_error("discovery gate: base_url missing in ~/.unbound/config.json", 'discovery_gate')
                return

            if RUNNING_FROZEN:
                # Frozen binary: never fetch install.sh — run the locally
                # installed discovery binary, or skip if it isn't there.
                if not os.path.isfile(FROZEN_DISCOVERY_BIN):
                    log_error(f"discovery gate: discovery binary missing at {FROZEN_DISCOVERY_BIN}", 'discovery_gate')
                    return
                discovery_cmd = [FROZEN_DISCOVERY_BIN, "--domain", backend_url]
            else:
                DISCOVERY_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
                if _install_sh_is_stale():
                    fd, _tmp = tempfile.mkstemp(dir=DISCOVERY_INSTALL_DIR, prefix="install.", suffix=".tmp")
                    os.close(fd)
                    tmp = Path(_tmp)
                    r = subprocess.run(
                        ["curl", "-fsSL", "-o", str(tmp), DISCOVERY_INSTALL_URL],
                        capture_output=True, timeout=30,
                    )
                    if r.returncode == 0:
                        os.chmod(tmp, 0o755)
                        os.replace(tmp, DISCOVERY_INSTALL_SH)
                    else:
                        tmp.unlink(missing_ok=True)
                        if not DISCOVERY_INSTALL_SH.exists():
                            log_error(f"discovery install.sh download failed: {r.stderr.decode(errors='replace')[:200]}", 'discovery_gate')
                            return
                        log_error(f"discovery install.sh refresh failed; using cached copy: {r.stderr.decode(errors='replace')[:200]}", 'discovery_gate')
                discovery_cmd = ["bash", str(DISCOVERY_INSTALL_SH), "--domain", backend_url]

            # api_key goes via env so it never appears in argv / /proc/<pid>/cmdline.
            popen_kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                            "stdin": subprocess.DEVNULL, "close_fds": True,
                            "env": {**os.environ, "UNBOUND_API_KEY": api_key}}
            if os.name == "nt":
                popen_kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_kwargs["start_new_session"] = True
            try:
                subprocess.Popen(discovery_cmd, **popen_kwargs)
            except OSError as e:
                log_error(f"discovery gate: Popen failed: {e}", 'discovery_gate')
                return

            # Stamp last_run_at only after Popen succeeds so a launch failure
            # (missing bash, EPERM, ENOMEM, etc.) doesn't burn the 24h window.
            cache["last_run_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            tmp = DISCOVERY_CACHE_PATH.with_suffix(".tmp")
            DISCOVERY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2, sort_keys=True)
            os.replace(tmp, DISCOVERY_CACHE_PATH)
        finally:
            try:
                DISCOVERY_DISPATCH_PATH.unlink(missing_ok=True)
            except OSError:
                pass
    except Exception as e:
        log_error(f"discovery gate failed: {e}", 'discovery_gate')


def main():
    """Main entry point - read from stdin and process events."""
    global _cached_api_key
    # Get API key (will be None if not set)
    api_key = get_api_key()
    _cached_api_key = api_key
    
    try:
        # Read JSON from stdin
        input_data = sys.stdin.read().strip()
        
        if not input_data:
            print("{}")
            return
        
        # Parse the event
        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            print("{}")
            return

        # Get event details
        hook_event_name = event.get('hook_event_name')

        # sessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if hook_event_name == "sessionStart":
            _device_serial()  # warm the (slow) serial probe + cache once per session
            _check_self_update()
            _dispatch_discovery()
            print("{}")
            return
        generation_id = event.get('generation_id')
        conversation_id = event.get('conversation_id')

        if hook_event_name == 'preToolUse':
            response = process_pre_tool_use(event, api_key)
            print(json.dumps(response), flush=True)
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        # Handle beforeShellExecution / beforeMCPExecution - check policy before execution
        if hook_event_name == 'beforeShellExecution':
            response = process_pre_tool_use_execution(event, api_key, 'Shell', event.get('command', ''))
            print(json.dumps(response), flush=True)
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        if hook_event_name == 'beforeMCPExecution':
            mcp_server = event.get('command', '')
            mcp_tool_name = event.get('tool_name', '')

            response = process_pre_tool_use_execution(
                event, api_key, f'MCP:{mcp_tool_name}', json.dumps(event.get('tool_input') or {}),
                mcp_server=mcp_server, mcp_tool=mcp_tool_name
            )
            print(json.dumps(response), flush=True)
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        # Handle beforeSubmitPrompt - check policy before processing
        if hook_event_name == 'beforeSubmitPrompt':
            # No repo gate here: conversation is never gated, but this call refreshes the policy cache so the session's first gated TOOL call is enforceable.
            response = process_user_prompt_submit(event, api_key)

            # If denied, log the event, transform response for Cursor format and exit
            if response.get('decision') == 'deny':
                append_to_audit_log({
                    'timestamp': datetime.now().astimezone().isoformat().replace('+00:00', 'Z'),
                    'event': event
                })
                cursor_response = {
                    'continue': False,
                    'user_message': response.get('reason', 'Prompt blocked by policy')
                }
                print(json.dumps(cursor_response), flush=True)
                sys.exit(2)

        # Create log entry with timestamp
        timestamp = datetime.now().astimezone().isoformat().replace('+00:00', 'Z')
        log_entry = {
            'timestamp': timestamp,
            'event': event
        }
        
        # Append to audit log
        append_to_audit_log(log_entry)
        
        # Handle interrupted requests (new generation in same conversation)
        if hook_event_name == 'beforeSubmitPrompt' and conversation_id and generation_id:
            logs = load_existing_logs()
            cleaned_logs = cleanup_interrupted_requests(logs, conversation_id, generation_id)
            if len(cleaned_logs) < len(logs):
                save_logs(cleaned_logs)
        
        # Process stop event
        if hook_event_name == 'stop' and generation_id:
            process_stop_event(generation_id, api_key)
            # Only cleanup after processing stop event to avoid race conditions
            cleanup_old_logs()
        
        # Output required by Cursor hooks
        print("{}")

    except Exception as e:
        # Log errors but still output {} to not break Cursor
        log_error(f"Exception in main: {str(e)}", 'general')
        print("{}", file=sys.stderr)
        print(f"Error: {redact_secrets(str(e), _cached_api_key)}", file=sys.stderr)
        print("{}")


if __name__ == '__main__':
    main()