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
DISCOVERY_HOOK_FLAG_TTL_SECONDS = 24 * 3600
DISCOVERY_HOOK_FLAG_PATH = "/v1/hooks/discovery-enabled"
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
POLICY_CACHE_FILE = LOG_DIR / ".policy_cache.json"
CURSOR_MCP_CONFIG_PATH = Path.home() / ".cursor" / "mcp.json"
CACHE_TTL_SECONDS = 300
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


def _emit(text):
    """Write a hook response line to stdout, treating a closed reader pipe as
    a benign no-op. The host may close the read end (timeout, cancel, session
    end, blocked approval-poll) before we flush — that is not a hook error."""
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except (BrokenPipeError, OSError):
        try:
            sys.stdout = open(os.devnull, "w")
        except Exception:
            pass


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


def save_policy_cache(tools_to_check=None, policy_check_failure_action=None):
    """Write policy cache to disk. None for any field preserves the prior value."""
    try:
        POLICY_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        prior = _read_policy_cache_raw() or {}
        if tools_to_check is None:
            tools_to_check = prior.get('tools_to_check', [])
        if policy_check_failure_action not in ('allow', 'block'):
            policy_check_failure_action = get_policy_check_failure_action()
        cache = {
            'last_synced': datetime.utcnow().isoformat() + 'Z',
            'tools_to_check': tools_to_check,
            'policy_check_failure_action': policy_check_failure_action,
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


def process_pre_tool_use(event, api_key):
    """Process preToolUse event - check policy before tool execution."""
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

    _tuid = event.get('tool_use_id')
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

    if 'tools_to_check' in api_response or 'policy_check_failure_action' in api_response:
        save_policy_cache(
            tools_to_check=api_response.get('tools_to_check'),
            policy_check_failure_action=api_response.get('policy_check_failure_action'),
        )

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
    """Process beforeShellExecution or beforeMCPExecution event."""
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

    if 'tools_to_check' in api_response or 'policy_check_failure_action' in api_response:
        save_policy_cache(
            tools_to_check=api_response.get('tools_to_check'),
            policy_check_failure_action=api_response.get('policy_check_failure_action'),
        )

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
    """Process beforeSubmitPrompt event for policy checking"""
    conversation_id = event.get('conversation_id')
    model = event.get('model') or 'auto'
    prompt = event.get('prompt', '')

    request_body = {
        'conversation_id': conversation_id,
        'unbound_app_label': 'cursor',
        'model': model,
        'event_name': 'user_prompt',
        'account_identity': build_account_identity(event),
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }

    api_response = send_to_hook_api(request_body, api_key)
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


def build_llm_exchange(events, api_key=None):
    """Build standard LLM exchange format from events."""
    messages = []
    assistant_tool_uses = []
    
    user_prompt = None
    assistant_response = None
    conversation_id = None
    model = None
    user_email = None
    request_initialized = None
    request_completed = None
    usage = None

    for log_entry in events:
        event = log_entry.get('event', {})
        hook_event_name = event.get('hook_event_name')

        if not conversation_id:
            conversation_id = event.get('conversation_id')

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
            assistant_tool_uses.append({
                'type': hook_event_name,
                'file_path': event.get('file_path'),
                'content': event.get('content', ''),
                'attachments': event.get('attachments', [])
            })

        elif hook_event_name == 'postToolUse':
            tool_name = event.get('tool_name', '')

            if tool_name not in EXCHANGE_NATIVE_TOOLS:
                continue
            
            tool_output = event.get('tool_output', '')

            assistant_tool_uses.append({
                'type': hook_event_name,
                'tool_name': tool_name,
                'tool_input': event.get('tool_input'),
                'tool_output': tool_output,
                'duration': event.get('duration'),
                'tool_use_id': event.get('tool_use_id')
            })
        
        elif hook_event_name == 'afterFileEdit':
            assistant_tool_uses.append({
                'type': hook_event_name,
                'file_path': event.get('file_path'),
                'edits': event.get('edits', [])
            })
        
        elif hook_event_name == 'afterShellExecution':
            assistant_tool_uses.append({
                'type': hook_event_name,
                'command': event.get('command'),
                'output': event.get('output', '')
            })
        
        elif hook_event_name == 'afterMCPExecution':
            assistant_tool_uses.append({
                'type': hook_event_name,
                'tool_name': event.get('tool_name'),
                'tool_input': event.get('tool_input'),
                'result_json': event.get('result_json')
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
    
    if not model or model == 'default':
        model = 'auto'

    exchange = {
        'conversation_id': conversation_id,
        'model': model,
        'messages': messages,
        'account_identity': build_account_identity({'user_email': user_email}, probe=True)
    }

    # Omit when unknown; gateway falls back
    if request_initialized:
        exchange['requestInitialized'] = request_initialized
    if request_completed:
        exchange['requestCompleted'] = request_completed

    if usage:
        exchange['usage'] = usage

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


def _hook_discovery_enabled_for_org() -> bool:
    """Return whether SessionStart-triggered discovery is enabled for this
    user's org. Reads ~/.unbound/discovery-cache.json first; refetches from
    the gateway only when the cached value is missing or older than
    DISCOVERY_HOOK_FLAG_TTL_SECONDS. Fail-closed: any error and no usable
    cached value means False."""
    cache = {}
    if DISCOVERY_CACHE_PATH.exists():
        try:
            with DISCOVERY_CACHE_PATH.open("r", encoding="utf-8") as f:
                cache = json.load(f) or {}
        except (OSError, json.JSONDecodeError):
            cache = {}
    if not isinstance(cache, dict):
        cache = {}
    _hd = cache.get("hook_discovery")
    flag = _hd if isinstance(_hd, dict) else {}
    last_fetched = flag.get("fetched_at")
    if isinstance(last_fetched, str):
        try:
            ts = datetime.strptime(last_fetched, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            if (time.time() - ts) < DISCOVERY_HOOK_FLAG_TTL_SECONDS:
                return bool(flag.get("enabled", False))
        except ValueError:
            pass

    try:
        with UNBOUND_CONFIG_PATH.open("r", encoding="utf-8") as f:
            cfg = json.load(f) or {}
    except (OSError, json.JSONDecodeError):
        return bool(flag.get("enabled", False))
    api_key = cfg.get("api_key")
    if not api_key:
        return bool(flag.get("enabled", False))
    try:
        r = subprocess.run(
            ["curl", "-fsSL",
             "-H", f"Authorization: Bearer {api_key}",
             "--max-time", "5",
             f"{UNBOUND_GATEWAY_URL}{DISCOVERY_HOOK_FLAG_PATH}"],
            capture_output=True, timeout=8,
        )
        if r.returncode != 0:
            return bool(flag.get("enabled", False))
        enabled = bool(json.loads(r.stdout.decode("utf-8", errors="replace")).get("enabled", False))
    except Exception:
        return bool(flag.get("enabled", False))

    cache["hook_discovery"] = {
        "enabled": enabled,
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        DISCOVERY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = DISCOVERY_CACHE_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
        os.replace(tmp, DISCOVERY_CACHE_PATH)
    except OSError:
        pass
    return enabled


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
    if not _hook_discovery_enabled_for_org():
        return
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
            _emit("{}")
            return

        # Parse the event
        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            _emit("{}")
            return

        # Get event details
        hook_event_name = event.get('hook_event_name')

        # sessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if hook_event_name == "sessionStart":
            _device_serial()  # warm the (slow) serial probe + cache once per session
            _check_self_update()
            _dispatch_discovery()
            _emit("{}")
            return
        generation_id = event.get('generation_id')
        conversation_id = event.get('conversation_id')

        if hook_event_name == 'preToolUse':
            response = process_pre_tool_use(event, api_key)
            _emit(json.dumps(response))
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        # Handle beforeShellExecution / beforeMCPExecution - check policy before execution
        if hook_event_name == 'beforeShellExecution':
            response = process_pre_tool_use_execution(event, api_key, 'Shell', event.get('command', ''))
            _emit(json.dumps(response))
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
            _emit(json.dumps(response))
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        # Handle beforeSubmitPrompt - check policy before processing
        if hook_event_name == 'beforeSubmitPrompt':
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
                _emit(json.dumps(cursor_response))
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
        _emit("{}")

    except BrokenPipeError:
        # Host closed the read end of our stdout pipe (timeout / cancel /
        # session end / blocked approval-poll). Benign — do not self-report.
        try:
            sys.stdout = open(os.devnull, "w")
        except Exception:
            pass
    except Exception as e:
        # Log errors but still output {} to not break Cursor
        log_error(f"Exception in main: {str(e)}", 'general')
        try:
            print("{}", file=sys.stderr)
            print(f"Error: {redact_secrets(str(e), _cached_api_key)}", file=sys.stderr)
        except (BrokenPipeError, OSError):
            pass
        _emit("{}")


if __name__ == '__main__':
    main()