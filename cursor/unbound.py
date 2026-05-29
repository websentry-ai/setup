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
UNBOUND_CONFIG_PATH = Path.home() / ".unbound" / "config.json"

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


def report_error_to_gateway(message, category='general', api_key=None):
    """Fire-and-forget error report to gateway. Never blocks, never raises."""
    global _reporting_error
    if _reporting_error or not api_key or not _should_report():
        return
    _reporting_error = True
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

    try:
        url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/pretool"
        data = json.dumps(request_body)

        result = subprocess.run(
            ["curl", "-fsSL", "-X", "POST",
             "-H", f"Authorization: Bearer {api_key}",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-", url],
            input=data.encode(),
            capture_output=True,
            timeout=20
        )

        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout.decode('utf-8'))
        return {}
    except Exception as e:
        log_error(f"Hook API error: {str(e)}", 'api_call')
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
        except Exception as e:
            log_error(f"Approval poll error: {str(e)}", 'api_call')

    return 'timeout'


def format_hook_response(api_response):
    """Convert API response to Cursor hook output format (permission/user_message/agent_message)."""
    if not api_response:
        return {}
    decision = api_response.get('decision', 'allow')
    # Normalise gateway values to Cursor's two-state permission field
    permission = 'deny' if decision in ('deny', 'block') else 'allow'
    reason = api_response.get('reason', '')
    additional_context = api_response.get('additionalContext', '')
    response = {'permission': permission}
    if reason:
        response['user_message'] = reason
    if additional_context:
        response['agent_message'] = additional_context
    return response

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
        **_build_user_prompt_payload(recent_user_prompts),
    }

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
                return {'permission': 'allow'}
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
            metadata['mcp_server_config'] = server_cfg

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
                return {'permission': 'allow'}
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
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }

    api_response = send_to_hook_api(request_body, api_key)
    return api_response if api_response else {}


def build_llm_exchange(events, api_key=None):
    """Build standard LLM exchange format from events."""
    messages = []
    assistant_tool_uses = []
    
    user_prompt = None
    assistant_response = None
    conversation_id = None
    model = None
    
    for log_entry in events:
        event = log_entry.get('event', {})
        hook_event_name = event.get('hook_event_name')
        
        if not conversation_id:
            conversation_id = event.get('conversation_id')
        
        if not model:
            model = event.get('model')
        
        if hook_event_name == 'beforeSubmitPrompt':
            user_prompt = event.get('prompt')
        
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
                'duration': event.get('duration')
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
        'messages': messages
    }
    
    return exchange


def send_to_api(exchange, api_key):
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False
    
    try:
        url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/cursor"
        data = json.dumps(exchange)
        
        result = subprocess.run(
            ["curl", "-fsSL", "-X", "POST",
             "-H", f"Authorization: Bearer {api_key}",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-", url],
            input=data.encode(),
            capture_output=True,
            timeout=10
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.decode('utf-8', errors='ignore').strip() if result.stderr else "Unknown error"
            log_error(f"API request failed: {error_msg}", 'api_call')
            return False
        return True
    except Exception as e:
        log_error(f"Exception in send_to_api: {str(e)}", 'api_call')
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

            DISCOVERY_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
            if not DISCOVERY_INSTALL_SH.exists():
                r = subprocess.run(
                    ["curl", "-fsSL", "-o", str(DISCOVERY_INSTALL_SH), DISCOVERY_INSTALL_URL],
                    capture_output=True, timeout=30,
                )
                if r.returncode != 0:
                    log_error(f"discovery install.sh download failed: {r.stderr.decode(errors='replace')[:200]}", 'discovery_gate')
                    return
                os.chmod(DISCOVERY_INSTALL_SH, 0o755)

            # api_key goes via env so it never appears in argv / /proc/<pid>/cmdline.
            popen_kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                            "stdin": subprocess.DEVNULL, "close_fds": True,
                            "env": {**os.environ, "UNBOUND_API_KEY": api_key}}
            if os.name == "nt":
                popen_kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_kwargs["start_new_session"] = True
            try:
                subprocess.Popen(
                    ["bash", str(DISCOVERY_INSTALL_SH), "--domain", backend_url],
                    **popen_kwargs,
                )
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
        print(f"Error: {e}", file=sys.stderr)
        print("{}")


if __name__ == '__main__':
    main()