#!/usr/bin/env python3
"""
Real-time GitHub Copilot hook event processor.
Reads JSON events from stdin, appends to agent-audit.log, and processes them on stop events.
"""

import sys
import json
import os
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import tempfile
import time
import hashlib
import re

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
LOG_DIR = Path.home() / ".copilot" / "hooks"
AUDIT_LOG = LOG_DIR / "agent-audit.log"
ERROR_LOG = LOG_DIR / "error.log"
LAST_REPORT_FILE = LOG_DIR / ".last_error_report"

SELF_UPDATE_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/copilot/hooks/unbound.py"
SELF_UPDATE_INTERVAL_SECONDS = 2 * 3600
SELF_UPDATE_LOCK_TTL_SECONDS = 30
SELF_UPDATE_CURL_TIMEOUT = 10
SELF_SCRIPT_PATH = LOG_DIR / "unbound.py"
SELF_UPDATE_STATE_PATH = LOG_DIR / ".self_update_check"
SELF_UPDATE_LOCK_PATH = LOG_DIR / ".self_update.lock"

# Copilot tool names (VS Code + CLI) translated to the canonical gateway vocabulary.
SHELL_TOOLS = {'bash', 'shell', 'run_in_terminal', 'runInTerminal', 'terminal'}
READ_TOOLS = {'read_file', 'readFile', 'view', 'list_dir', 'listDirectory', 'cat'}
WRITE_TOOLS = {'create_file', 'create', 'createFile', 'write', 'write_file', 'new_file'}
EDIT_TOOLS = {'str_replace', 'edit_file', 'editFile', 'apply_patch', 'insert_edit', 'replace_string_in_file'}
ALLOWED_NON_MCP_HOOK_NAMES = {'Bash', 'Read', 'Write', 'Edit'}  # MCP tools (mcp*) are always checked separately
NATIVE_FILE_TOOLS = {'Read', 'Write', 'Edit'}
POLICY_CACHE_FILE = LOG_DIR / ".policy_cache.json"
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
    LOG_DIR = Path(tempfile.gettempdir()) / "copilot-hooks"
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
            'hook_source': 'copilot',
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
        try:
            with open(AUDIT_LOG, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            logs.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception:
            pass
    return logs


def save_logs(logs):
    """Save logs back to agent-audit.log."""
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, 'w', encoding='utf-8') as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
    except Exception:
        pass


def append_to_audit_log(event_data):
    """Append event to agent-audit.log."""
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event_data) + '\n')
    except Exception:
        pass


def cleanup_old_logs():
    """Manage log file size by keeping only the most recent session's entries
    once the audit log exceeds AUDIT_LOG_TOTAL_LIMIT."""
    logs = load_existing_logs()

    if len(logs) <= AUDIT_LOG_TOTAL_LIMIT:
        return

    session_order = []
    seen_sessions = set()

    for log in logs:
        event = log.get('event', {})
        session_id = event.get('session_id')
        if session_id and session_id not in seen_sessions:
            session_order.append(session_id)
            seen_sessions.add(session_id)

    if len(session_order) > 1:
        most_recent_session = session_order[-1]
        kept_logs = [
            log for log in logs
            if log.get('event', {}).get('session_id') == most_recent_session
        ]
        save_logs(kept_logs)
    elif len(logs) > AUDIT_LOG_TOTAL_LIMIT:
        save_logs(logs[-AUDIT_LOG_TOTAL_LIMIT:])


def get_recent_user_prompts_for_session(session_id, n):
    if not session_id or n <= 0:
        return []

    logs = load_existing_logs()
    prompts = []
    for log in logs:
        event = log.get('event', {})
        if event.get('hook_event_name') != 'UserPromptSubmit':
            continue
        if event.get('session_id') != session_id:
            continue
        prompt = event.get('prompt')
        if prompt:
            prompts.append(prompt)
    return prompts[-n:]


def get_session_start_model(session_id):
    """Return the model from the audit-logged SessionStart event for a session.
    VS Code's SessionStart payload carries `model`; latest entry wins."""
    if not session_id:
        return None
    found = None
    for log in load_existing_logs():
        event = log.get('event', {})
        if event.get('hook_event_name') != 'SessionStart':
            continue
        if event.get('session_id') != session_id:
            continue
        model = event.get('model')
        if model:
            found = model
    return found


def _build_user_prompt_payload(recent_user_prompts):
    last = recent_user_prompts[-1] if recent_user_prompts else None
    return {
        'messages': [{'role': 'user', 'content': last}] if last else [],
        'user_prompts': recent_user_prompts,
    }


def canonical_tool_name(raw):
    """Translate a Copilot tool name to the canonical gateway vocabulary.
    Returns '' when the tool is not security-relevant."""
    if raw in SHELL_TOOLS:
        return 'Bash'
    if raw in READ_TOOLS:
        return 'Read'
    if raw in WRITE_TOOLS:
        return 'Write'
    if raw in EDIT_TOOLS:
        return 'Edit'
    if raw.startswith('mcp'):
        # MCP tools pass through unchanged — the gateway matches on the raw name.
        return raw
    return ''


def extract_command_for_pretool(canonical, tool_input):
    """Extract the policy-check command from tool_input keyed by canonical tool type."""
    if canonical == 'Bash':
        return tool_input.get('command', '')
    if canonical in ('Read', 'Write', 'Edit'):
        return tool_input.get('filePath') or tool_input.get('path') or tool_input.get('file_path') or ''
    if canonical.startswith('mcp'):
        return json.dumps(tool_input)
    return ''


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


def _set_approval_marker(command, policy_ids, application_id, request_id=''):
    _APPROVAL_MARKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        'cmd': hashlib.sha256(command.encode()).hexdigest()[:16],
        'ts': time.time(),
        'policyIds': policy_ids,
        'applicationId': application_id,
        'requestId': request_id,
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


def transform_response_for_copilot(api_response):
    """Transform a gateway response to Copilot PreToolUse output format."""
    if not api_response:
        return {}

    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')
    additional_context = api_response.get('additionalContext', '')

    return {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': decision,
            'permissionDecisionReason': reason,
            'additionalContext': additional_context
        }
    }


def transform_response_for_copilot_prompt(api_response):
    """Transform a gateway response to Copilot UserPromptSubmit output format."""
    if not api_response:
        return {}

    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')

    # For UserPromptSubmit, 'deny' maps to 'block'
    if decision == 'deny':
        return {
            'decision': 'block',
            'reason': reason
        }

    return {}


def process_pre_tool_use(event, api_key):
    """Process PreToolUse event - check policy before tool execution."""
    raw_tool = event.get('tool_name', '')
    tool_input = event.get('tool_input') or {}
    session_id = event.get('session_id')

    # Translate the Copilot tool name to the canonical gateway vocabulary.
    canonical = canonical_tool_name(raw_tool)
    is_mcp = canonical.startswith('mcp')
    if not is_mcp and canonical not in ALLOWED_NON_MCP_HOOK_NAMES:
        return {}

    cache = load_policy_cache()
    tools_to_check = cache.get('tools_to_check', []) if cache else []
    need_pull_policies = cache is None or is_cache_stale(cache)

    if (
        canonical in NATIVE_FILE_TOOLS
        and canonical not in tools_to_check
        and not need_pull_policies
    ):
        return {}

    model = get_session_start_model(session_id) or 'auto'
    command = extract_command_for_pretool(canonical, tool_input)

    recent_user_prompts = get_recent_user_prompts_for_session(
        session_id, PRETOOL_USER_MESSAGES_LIMIT
    )

    # Preserve the raw event (raw tool_name + tool_input) inside metadata.
    metadata = dict(event)
    file_path = tool_input.get('filePath') or tool_input.get('path') or tool_input.get('file_path')
    if file_path:
        metadata['file_path'] = file_path

    approval_key = f"{canonical}:{command}"
    is_retry = _is_approval_retry(approval_key)

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'copilot',
        'model': model,
        'event_name': 'tool_use',
        'pre_tool_use_data': {
            'tool_name': canonical,
            'command': command,
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
                return {}
            elif result == 'deny':
                return transform_response_for_copilot({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. This action was denied via Slack.',
                    'additionalContext': 'This action was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                })
            else:
                return transform_response_for_copilot({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry.',
                    'additionalContext': 'This action was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                })

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        if get_policy_check_failure_action() == 'block':
            return transform_response_for_copilot({
                'decision': 'deny',
                'reason': POLICY_CHECK_FAILURE_BLOCK_REASON,
                'additionalContext': 'The organization policy engine could not be reached. This is a transient infrastructure failure. Tell the user the policy engine is unavailable and ask them to retry.',
            })
        report_error_to_gateway(
            f'Hook bypassed_due_to_failure: gateway unreachable for tool={raw_tool}',
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

        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id)
        return transform_response_for_copilot({
            'decision': 'deny',
            'reason': 'An approval request has been sent to your Slack DMs. Please approve it there.',
            'additionalContext': (
                'This is NOT a permanent block — it is a temporary hold pending Slack approval. '
                'Tell the user: "An approval request has been sent to your Slack DMs. '
                'Please approve it and I will retry automatically." '
                'Then immediately retry the exact same tool call with the exact same arguments — '
                'do not modify them in any way. Retry exactly once — the second attempt will wait for the approval.'
            ),
        })

    return transform_response_for_copilot(api_response)


def process_user_prompt_submit(event, api_key):
    """Process UserPromptSubmit event for policy checking."""
    session_id = event.get('session_id')
    model = get_session_start_model(session_id) or 'auto'
    prompt = event.get('prompt', '')

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'copilot',
        'model': model,
        'event_name': 'user_prompt',
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }

    api_response = send_to_hook_api(request_body, api_key)
    return transform_response_for_copilot_prompt(api_response)


def _normalize_arguments(arguments):
    """Copilot tool arguments may be a dict or a JSON string. Always return a dict."""
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
            return parsed if isinstance(parsed, dict) else {'value': arguments}
        except json.JSONDecodeError:
            return {'value': arguments}
    return {}


def map_copilot_tool(name, args, result_content):
    """Map a Copilot tool call to a cursor-style tool_use entry."""
    if name in SHELL_TOOLS:
        entry = {
            'type': 'afterShellExecution',
            'command': args.get('command', ''),
            'output': result_content or '',
        }
    elif name in READ_TOOLS:
        entry = {
            'type': 'beforeReadFile',
            'file_path': args.get('filePath') or args.get('path') or args.get('file_path', ''),
            'content': result_content or '',
        }
    elif name in WRITE_TOOLS or name in EDIT_TOOLS:
        entry = {
            'type': 'afterFileEdit',
            'file_path': args.get('filePath') or args.get('path') or args.get('file_path', ''),
            'content': args.get('content') or args.get('file_text') or result_content or '',
        }
    else:
        entry = {
            'type': 'afterMCPExecution',
            'tool_name': name,
            'tool_input': args,
            'result_json': result_content or '',
        }
    # Drop empty-string values.
    return {k: v for k, v in entry.items() if v != ''}


def build_exchange_from_transcript(transcript_path, fallback_session_id, session_start_model=None):
    """Parse a Copilot JSONL transcript into a cursor-style LLM exchange.

    Reads defensively — blank or unparseable lines are skipped, never raised."""
    if not transcript_path or not os.path.exists(transcript_path):
        return None

    entries = []
    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return None

    # CLI stores transcripts at ~/.copilot/session-state/<conversation_id>/events.jsonl;
    # VS Code at .../transcripts/<sessionId>.jsonl. Recover the id from the path
    # when the payload carries none.
    conversation_id = fallback_session_id
    if not conversation_id:
        p = Path(transcript_path)
        conversation_id = p.parent.name if p.stem == 'events' else p.stem
    model = None
    last_user_index = -1

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get('type')
        data = entry.get('data') or {}
        if entry_type == 'session.start':
            sid = data.get('sessionId')
            if sid and conversation_id == fallback_session_id:
                conversation_id = sid
        elif entry_type == 'session.model_change':
            new_model = data.get('newModel')
            if new_model:
                model = new_model
        elif entry_type == 'user.message':
            last_user_index = i

    if last_user_index < 0:
        return None

    user_prompt = (entries[last_user_index].get('data') or {}).get('content')

    text_parts = []
    tool_calls = []          # ordered list of call ids
    tool_data = {}           # call_id -> {name, arguments, result, success}

    def _register(call_id):
        if call_id not in tool_data:
            tool_data[call_id] = {'name': '', 'arguments': {}, 'result': None, 'success': None}
            tool_calls.append(call_id)
        return tool_data[call_id]

    for entry in entries[last_user_index + 1:]:
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get('type')
        data = entry.get('data') or {}

        if entry_type == 'assistant.message':
            content = data.get('content')
            if content:
                text_parts.append(content)
            for req in data.get('toolRequests') or []:
                if not isinstance(req, dict):
                    continue
                call_id = req.get('toolCallId')
                if not call_id:
                    continue
                call = _register(call_id)
                call['name'] = req.get('name') or call['name']
                call['arguments'] = _normalize_arguments(req.get('arguments'))

        elif entry_type == 'tool.execution_start':
            call_id = data.get('toolCallId')
            if not call_id:
                continue
            call = _register(call_id)
            if data.get('toolName'):
                call['name'] = data['toolName']
            if data.get('arguments') is not None:
                call['arguments'] = _normalize_arguments(data.get('arguments'))

        elif entry_type == 'tool.execution_complete':
            call_id = data.get('toolCallId')
            if not call_id:
                continue
            call = _register(call_id)
            call['success'] = data.get('success')
            result = data.get('result') or {}
            if isinstance(result, dict):
                call['result'] = result.get('content')

    tool_use = []
    for call_id in tool_calls:
        call = tool_data[call_id]
        tool_use.append(map_copilot_tool(call['name'], call['arguments'], call['result']))

    messages = []
    if user_prompt:
        messages.append({'role': 'user', 'content': user_prompt})

    assistant_msg = {'role': 'assistant', 'content': '\n\n'.join(text_parts)}
    if tool_use:
        assistant_msg['tool_use'] = tool_use
    messages.append(assistant_msg)

    if not messages:
        return None

    return {
        'conversation_id': conversation_id,
        'model': model or session_start_model or 'auto',
        'messages': messages,
    }


def send_to_api(exchange, api_key):
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False

    try:
        url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/copilot"
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


def get_api_key():
    """Get API key from env var or ~/.unbound/config.json."""
    key = os.getenv('UNBOUND_COPILOT_API_KEY')
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
    api_key = get_api_key()
    _cached_api_key = api_key

    try:
        input_data = sys.stdin.read().strip()

        if not input_data:
            print("{}")
            return

        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            print("{}")
            return

        event_name = event.get('hook_event_name')

        # SessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if event_name == 'SessionStart':
            _check_self_update()
            # _dispatch_discovery()
            print("{}")
            return

        if event_name == 'PreToolUse':
            response = process_pre_tool_use(event, api_key)
            print(json.dumps(response), flush=True)
            return

        if event_name == 'UserPromptSubmit':
            response = process_user_prompt_submit(event, api_key)
            if response.get('decision') == 'block':
                append_to_audit_log({
                    'timestamp': datetime.now().astimezone().isoformat().replace('+00:00', 'Z'),
                    'event': event,
                })
                print(json.dumps(response), flush=True)
                return

        # Create log entry with timestamp; the event already carries hook_event_name
        timestamp = datetime.now().astimezone().isoformat().replace('+00:00', 'Z')
        log_entry = {
            'timestamp': timestamp,
            'event': event,
        }
        append_to_audit_log(log_entry)

        if event_name == 'Stop':
            session_id = event.get('session_id')
            exchange = build_exchange_from_transcript(
                event.get('transcript_path'), session_id,
                session_start_model=get_session_start_model(session_id),
            )
            if exchange:
                send_to_api(exchange, api_key)
            cleanup_old_logs()

        # Output required by Copilot hooks
        print("{}")

    except Exception as e:
        # Log errors but still output {} to not break Copilot
        log_error(f"Exception in main: {str(e)}", 'general')
        print("{}")


if __name__ == '__main__':
    main()
