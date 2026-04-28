#!/usr/bin/env python3

import sys
import json
import os
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import time
import hashlib


UNBOUND_GATEWAY_URL = os.environ.get(
    "UNBOUND_GATEWAY_URL", "https://api.getunbound.ai"
).rstrip("/")
AUDIT_LOG = Path.home() / ".codex" / "hooks" / "agent-audit.log"
ERROR_LOG = Path.home() / ".codex" / "hooks" / "error.log"
LAST_REPORT_FILE = Path.home() / ".codex" / "hooks" / ".last_error_report"
ALLOWED_NON_MCP_HOOK_NAMES = ['Bash', 'apply_patch']  # MCP tools (mcp__*) are always checked separately
NATIVE_FILE_TOOLS = {'apply_patch'}
MCP_TOOL_PREFIX = 'mcp__'
POLICY_CACHE_FILE = Path.home() / ".codex" / "hooks" / ".policy_cache.json"
CACHE_TTL_SECONDS = 300
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'

APPROVAL_TIMEOUT = 4 * 60 * 60

APPROVAL_POLL_PHASES = (
    (5 * 60,        3),    # 0-5 min: 3s
    (30 * 60,       15),   # 5-30 min: 15s
    (2 * 60 * 60,   60),   # 30 min - 2h: 1min
    (4 * 60 * 60,   120),  # 2h - 4h: 2min
)

_APPROVAL_MARKER_FILE = Path.home() / ".codex" / "hooks" / ".approval_pending"


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
            'hook_source': 'codex',
        })
        proc = subprocess.Popen(
            ["curl", "-fsSL", "-K", "-", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", payload,
             f"{UNBOUND_GATEWAY_URL}/v1/hooks/errors"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        proc.stdin.write(f'header = "Authorization: Bearer {api_key}"\n'.encode())
        proc.stdin.close()
    except Exception:
        pass
    finally:
        _reporting_error = False


def log_error(message: str, category: str = 'general'):
    """Log error with timestamp to error.log, keeping only last 25 errors."""
    timestamp = datetime.utcnow().isoformat() + 'Z'
    error_entry = f"{timestamp}: {message}\n"

    try:
        ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
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


def _read_policy_cache_raw() -> Optional[Dict]:
    """Read and JSON-parse the policy cache file. Returns None on missing/corrupt."""
    try:
        if not POLICY_CACHE_FILE.exists():
            return None
        with open(POLICY_CACHE_FILE, 'r', encoding='utf-8') as f:
            cache = json.loads(f.read())
        return cache if isinstance(cache, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def load_policy_cache() -> Optional[Dict]:
    """Load policy cache from disk. Returns None if missing, corrupt, or expired."""
    cache = _read_policy_cache_raw()
    if cache is None or 'last_synced' not in cache or 'tools_to_check' not in cache:
        return None
    if not isinstance(cache['tools_to_check'], list):
        return None
    return cache


def get_policy_check_failure_action() -> str:
    """Read failure-action from cache, defaulting to 'allow'. Ignores TTL."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return POLICY_CHECK_FAILURE_DEFAULT
    value = cache.get('policy_check_failure_action')
    return value if value in ('allow', 'block') else POLICY_CHECK_FAILURE_DEFAULT


def save_policy_cache(tools_to_check: Optional[List[str]] = None, policy_check_failure_action: Optional[str] = None):
    """Merge supplied fields into the cache. Fields passed as None are left untouched.
    last_synced is refreshed only when tools_to_check is being updated."""
    try:
        POLICY_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        cache = _read_policy_cache_raw() or {}
        if tools_to_check is not None:
            cache['tools_to_check'] = tools_to_check
            cache['last_synced'] = datetime.utcnow().isoformat() + 'Z'
        if policy_check_failure_action in ('allow', 'block'):
            cache['policy_check_failure_action'] = policy_check_failure_action
        with open(POLICY_CACHE_FILE, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cache))
    except (OSError, TypeError):
        pass


def is_cache_stale(cache: Dict) -> bool:
    """Check if cached data is older than CACHE_TTL_SECONDS."""
    try:
        synced = datetime.fromisoformat(cache['last_synced'].rstrip('Z'))
        age = (datetime.utcnow() - synced).total_seconds()
        return age > CACHE_TTL_SECONDS
    except (ValueError, KeyError):
        return True


def _is_approval_retry(command: str) -> bool:
    """True if a marker exists for this exact command and is fresh (< APPROVAL_TIMEOUT)."""
    try:
        if not _APPROVAL_MARKER_FILE.exists():
            return False
        data = json.loads(_APPROVAL_MARKER_FILE.read_text())
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        return data.get('cmd') == cmd_hash and (time.time() - data.get('ts', 0)) < APPROVAL_TIMEOUT
    except (OSError, json.JSONDecodeError):
        return False


def _set_approval_marker(command: str, policy_ids: list, application_id: str, request_id: str = '') -> None:
    _APPROVAL_MARKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        'cmd': hashlib.sha256(command.encode()).hexdigest()[:16],
        'ts': time.time(),
        'policyIds': policy_ids,
        'applicationId': application_id,
        'requestId': request_id,
    }
    _APPROVAL_MARKER_FILE.write_text(json.dumps(data))


def _get_approval_marker_data() -> Optional[Dict]:
    try:
        if not _APPROVAL_MARKER_FILE.exists():
            return None
        return json.loads(_APPROVAL_MARKER_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _clear_approval_marker() -> None:
    try:
        if _APPROVAL_MARKER_FILE.exists():
            _APPROVAL_MARKER_FILE.unlink()
    except OSError:
        pass


def _next_poll_interval(elapsed: float) -> int:
    """Pick the polling interval for the current elapsed time using APPROVAL_POLL_PHASES."""
    for upto, interval in APPROVAL_POLL_PHASES:
        if elapsed < upto:
            return interval
    return APPROVAL_POLL_PHASES[-1][1]


def poll_approval_status(api_key: str, policy_ids: list, application_id: str, request_id: str = '', timeout: int = APPROVAL_TIMEOUT) -> str:
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
                 "-d", body, url],
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
            log_error(f"Approval poll error: {str(e)}")

    return 'timeout'


def load_existing_logs() -> List[Dict]:
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


def save_logs(logs: List[Dict]):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, 'w', encoding='utf-8') as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
    except Exception:
        pass


def append_to_audit_log(event_data: Dict):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event_data) + '\n')
    except Exception:
        pass


def parse_transcript_file(transcript_path: str, user_prompt_timestamp: Optional[str] = None) -> Dict:
    conversation_data = {
        'user_messages': [],
        'assistant_messages': [],
        'tool_uses': []
    }

    if not transcript_path or not os.path.exists(transcript_path):
        return conversation_data

    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)
                    entry_type = entry.get('type', '')
                    entry_timestamp = entry.get('timestamp')

                    if entry_type == 'user':
                        message = entry.get('message', {})
                        if message.get('role') == 'user':
                            content = message.get('content', '')
                            if content:
                                conversation_data['user_messages'].append({
                                    'content': content,
                                    'timestamp': entry_timestamp
                                })

                    elif entry_type == 'assistant':
                        if user_prompt_timestamp and entry_timestamp:
                            if entry_timestamp <= user_prompt_timestamp:
                                continue

                        message = entry.get('message', {})
                        if message.get('role') == 'assistant':
                            content_array = message.get('content', [])
                            text_content = ''
                            for content_item in content_array:
                                if isinstance(content_item, dict) and content_item.get('type') == 'text':
                                    text_content = content_item.get('text', '')
                                    if text_content:
                                        conversation_data['assistant_messages'].append({
                                            'content': text_content,
                                            'timestamp': entry_timestamp
                                        })

                except json.JSONDecodeError:
                    continue

    except Exception:
        pass

    return conversation_data


def get_latest_user_prompt_for_session(session_id: str, transcript_path: Optional[str] = None) -> Optional[str]:
    """Get the most recent user prompt for this session."""
    logs = load_existing_logs()
    latest_prompt = None

    for log in logs:
        log_session = log.get('session_id') or log.get('event', {}).get('session_id')
        if log_session == session_id:
            event = log.get('event', {})
            if event.get('hook_event_name') == 'UserPromptSubmit':
                latest_prompt = event.get('prompt')

    if latest_prompt:
        return latest_prompt

    # Fallback: parse transcript file
    if transcript_path and transcript_path != 'undefined' and os.path.exists(transcript_path):
        data = parse_transcript_file(transcript_path)
        if data.get('user_messages'):
            return data['user_messages'][-1].get('content')

    return None


def extract_command_for_pretool(event: Dict) -> str:
    """Extract command from tool_input based on tool type."""
    tool_input = event.get('tool_input') or {}
    tool_name = event.get('tool_name', '')

    # Bash: command field
    if tool_name == 'Bash' and 'command' in tool_input:
        return tool_input['command']
    # MCP tools: stringify the input
    if tool_name.startswith(MCP_TOOL_PREFIX):
        return json.dumps(tool_input)
    # File tools: file_path
    if tool_name in ['Write', 'Edit', 'Read'] and 'file_path' in tool_input:
        return tool_input['file_path']
    # Grep: pattern
    if tool_name == 'Grep' and 'pattern' in tool_input:
        return tool_input['pattern']
    # Glob: pattern
    if tool_name == 'Glob' and 'pattern' in tool_input:
        return tool_input['pattern']
    # WebFetch: url
    if tool_name == 'WebFetch' and 'url' in tool_input:
        return tool_input['url']
    # WebSearch: query
    if tool_name == 'WebSearch' and 'query' in tool_input:
        return tool_input['query']
    # Task: prompt
    if tool_name == 'Task' and 'prompt' in tool_input:
        return tool_input['prompt']
    # Default: tool name
    return tool_name


def send_to_hook_api(request_body: Dict, api_key: str) -> Dict:
    """Send request to /v1/hooks/pretool endpoint."""
    if not api_key:
        return {}

    try:
        url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/pretool"
        data = json.dumps(request_body)

        result = subprocess.run(
            ["curl", "-fsSL", "-K", "-", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", data, url],
            input=f'header = "Authorization: Bearer {api_key}"\n'.encode(),
            capture_output=True,
            timeout=20
        )

        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout.decode('utf-8'))
        return {}
    except Exception as e:
        log_error(f"Hook API error: {str(e)}", 'api_call')
        return {}


def transform_response_for_codex(api_response: Dict) -> Dict:
    """Transform API response to Codex format for PreToolUse.

    Codex PreToolUse hooks:
    - allow: return empty {}
    - deny: return hookSpecificOutput with permissionDecision:deny
    - ask: return hookSpecificOutput with permissionDecision:deny + reason
           (ask is parsed but not yet supported by Codex, so we deny with reason)
    """
    if not api_response:
        return {}

    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')
    additional_context = api_response.get('additionalContext', '')

    # Allow: return empty response
    if decision == 'allow':
        return {}

    # Deny or Ask: use hookSpecificOutput with deny
    return {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny',
            'permissionDecisionReason': reason,
            'additionalContext': additional_context
        }
    }


def transform_response_for_codex_prompt(api_response: Dict) -> Dict:
    """Transform API response to Codex format for UserPromptSubmit."""
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


def process_pre_tool_use(event: Dict, api_key: str) -> Dict:
    """Process PreToolUse event - DO NOT LOG."""
    session_id = event.get('session_id')
    model = event.get('model') or 'auto'
    transcript_path = event.get('transcript_path')
    tool_name = event.get('tool_name', '')

    is_mcp = tool_name.startswith(MCP_TOOL_PREFIX)
    if not is_mcp and tool_name not in ALLOWED_NON_MCP_HOOK_NAMES:
        return {}

    cache = load_policy_cache()
    tools_to_check = cache.get('tools_to_check', []) if cache else []
    need_pull_policies = cache is None or is_cache_stale(cache)

    if (
        tool_name in NATIVE_FILE_TOOLS
        and tool_name not in tools_to_check
        and not need_pull_policies
    ):
        return {}

    user_prompt = get_latest_user_prompt_for_session(session_id, transcript_path)
    command = extract_command_for_pretool(event)

    # Build metadata with the raw event
    metadata = dict(event)

    if is_mcp:
        # Parse mcp__<server>__<tool> to extract server and tool for gateway matching
        parts = tool_name[len(MCP_TOOL_PREFIX):].split('__', 1)
        metadata['mcp_server'] = parts[0] if len(parts) >= 1 else ''
        metadata['mcp_tool'] = parts[1] if len(parts) >= 2 else ''

    approval_key = f"{tool_name}:{command}"
    is_retry = _is_approval_retry(approval_key)

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'codex',
        'model': model,
        'event_name': 'tool_use',
        'pre_tool_use_data': {
            'command': command,
            'tool_name': tool_name,
            'metadata': metadata
        },
        'messages': [{'role': 'user', 'content': user_prompt}] if user_prompt else []
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
                return transform_response_for_codex({'decision': 'allow'})
            elif result == 'deny':
                return transform_response_for_codex({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. This command was denied via Slack.',
                    'additionalContext': 'This command was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                })
            else:
                return transform_response_for_codex({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry the command.',
                    'additionalContext': 'This command was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                })

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        if get_policy_check_failure_action() == 'block':
            return transform_response_for_codex({
                'decision': 'deny',
                'reason': POLICY_CHECK_FAILURE_BLOCK_REASON,
                'additionalContext': 'The organization policy engine could not be reached. This is a transient infrastructure failure. Tell the user the policy engine is unavailable and ask them to retry.',
            })
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

        _set_approval_marker(approval_key, policy_ids, application_id, request_id=request_id)
        return transform_response_for_codex({
            'decision': 'deny',
            'reason': 'An approval request has been sent to your Slack DMs. Please approve it there.',
            'additionalContext': (
                'This is NOT a permanent block — it is a temporary hold pending Slack approval. '
                'Tell the user: "An approval request has been sent to your Slack DMs. '
                'Please approve it and I will retry automatically." '
                'Then immediately retry the exact same tool call with the exact same command — '
                'do not modify the command in any way, do not add sleep or any prefix. '
                'Retry exactly once — the second attempt will wait for the approval.'
            ),
        })

    return transform_response_for_codex(api_response)


def process_user_prompt_submit(event: Dict, api_key: str) -> Dict:
    """Process UserPromptSubmit event for policy checking."""
    session_id = event.get('session_id')
    model = event.get('model') or 'auto'
    prompt = event.get('prompt', '')

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'codex',
        'model': model,
        'event_name': 'user_prompt',
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }

    api_response = send_to_hook_api(request_body, api_key)
    return transform_response_for_codex_prompt(api_response)





def send_to_api(exchange: Dict, api_key: str) -> bool:
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False

    try:
        url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/codex"
        data = json.dumps(exchange)

        result = subprocess.run(
            ["curl", "-fsSL", "-K", "-", "-X", "POST",
             "-H", "Content-Type: application/json", "-d", data, url],
            input=f'header = "Authorization: Bearer {api_key}"\n'.encode(),
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


def cleanup_old_logs():
    logs = load_existing_logs()

    if len(logs) <= 50:
        return

    session_order = []
    seen_sessions = set()

    for log in logs:
        session_id = log.get('session_id')
        if session_id and session_id not in seen_sessions:
            session_order.append(session_id)
            seen_sessions.add(session_id)

    if len(session_order) > 1:
        most_recent_session = session_order[-1]
        kept_logs = [
            log for log in logs
            if log.get('session_id') == most_recent_session
        ]
        save_logs(kept_logs)


def parse_codex_transcript_for_tools(transcript_path: str, user_prompt_timestamp: Optional[str] = None) -> List[Dict]:
    """Parse Codex transcript for function_call/function_call_output pairs.

    Codex transcripts use response_item entries with:
    - type: 'function_call' (contains name, arguments with cmd)
    - type: 'function_call_output' (contains output)

    Converts to PostToolUse format matching Claude Code hooks for backend compatibility.
    """
    tool_uses = []
    if not transcript_path or not os.path.exists(transcript_path):
        return tool_uses

    try:
        # Collect all function calls and outputs, keyed by call_id
        function_calls = {}
        function_outputs = {}

        with open(transcript_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    entry_type = entry.get('type')
                    entry_timestamp = entry.get('timestamp', '')
                    payload = entry.get('payload', {})

                    # Skip entries before user prompt if timestamp provided
                    if user_prompt_timestamp and entry_timestamp and entry_timestamp <= user_prompt_timestamp:
                        continue

                    if entry_type == 'response_item':
                        item_type = payload.get('type', '')
                        call_id = payload.get('call_id', '')

                        if item_type == 'function_call' and call_id:
                            arguments = payload.get('arguments', '')
                            if isinstance(arguments, str):
                                try:
                                    arguments = json.loads(arguments)
                                except json.JSONDecodeError:
                                    arguments = {'command': arguments}
                            function_calls[call_id] = {
                                'name': payload.get('name', ''),
                                'arguments': arguments
                            }

                        elif item_type == 'function_call_output' and call_id:
                            function_outputs[call_id] = payload.get('output', '')

                except json.JSONDecodeError:
                    continue

        # Match calls with outputs and convert to PostToolUse format
        for call_id, call_data in function_calls.items():
            name = call_data.get('name', '')
            args = call_data.get('arguments', {})
            output = function_outputs.get(call_id, '')

            # Map Codex function names to tool names
            # Codex currently only has exec_command (Bash). Other function names
            # are handled generically as fallback for future Codex tool support.
            if name == 'exec_command':
                tool_name = 'Bash'
                tool_input = {'command': args.get('cmd', '')}
                # Parse exec_command output format to extract clean stdout and exit_code
                stdout = output
                exit_code = 0
                if 'Output:\n' in output:
                    stdout = output.split('Output:\n', 1)[1].rstrip()
                if 'Process exited with code ' in output:
                    try:
                        code_str = output.split('Process exited with code ')[1].split('\n')[0].strip()
                        exit_code = int(code_str)
                    except (ValueError, IndexError):
                        pass
                tool_response = {'stdout': stdout, 'exitCode': exit_code}
            else:
                # Generic fallback for any future Codex tools
                tool_name = name
                tool_input = args if isinstance(args, dict) else {'command': str(args)}
                tool_response = {'stdout': output}

            tool_uses.append({
                'type': 'PostToolUse',
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_response': tool_response
            })

    except Exception:
        pass

    return tool_uses


def parse_codex_transcript_for_usage(transcript_path: str, user_prompt_timestamp: Optional[str] = None) -> Optional[Dict]:
    """Per-turn token usage via total_token_usage deltas (last_token_usage re-emits across turns; openai/codex#14489)."""
    if not transcript_path or not os.path.exists(transcript_path) or not user_prompt_timestamp:
        return None

    before, after = {}, {}
    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                payload = entry.get('payload') or {}
                if entry.get('type') != 'event_msg' or payload.get('type') != 'token_count':
                    continue
                total = (payload.get('info') or {}).get('total_token_usage')
                if not total:
                    continue
                if entry.get('timestamp', '') < user_prompt_timestamp:
                    before = total
                else:
                    after = total

        if not after:
            return None

        delta = lambda k: max(int(after.get(k) or 0) - int(before.get(k) or 0), 0)
        # Codex input_tokens includes cached_input_tokens; subtract so cache isn't billed at the base rate too.
        prompt = max(delta('input_tokens') - delta('cached_input_tokens'), 0)
        completion = delta('output_tokens') + delta('reasoning_output_tokens')
        cache_read = delta('cached_input_tokens')
    except Exception:
        return None

    if not (prompt or completion or cache_read):
        return None

    return {
        'prompt_tokens': prompt,
        'completion_tokens': completion,
        'cache_read_input_tokens': cache_read,
        'cache_creation_input_tokens': 0,
        'total_tokens': prompt + completion + cache_read,
    }


def process_stop_event(event: Dict, api_key: str):
    session_id = event.get('session_id')
    transcript_path = event.get('transcript_path')
    last_assistant_message = event.get('last_assistant_message', '')

    logs = load_existing_logs()

    # Find the UserPromptSubmit for this session
    user_prompt = None
    user_prompt_timestamp = None
    permission_mode = None

    for log in logs:
        log_session_id = log.get('session_id') or log.get('event', {}).get('session_id')

        if log_session_id == session_id:
            log_event = log.get('event', {}) if 'event' in log else log
            event_name = log_event.get('hook_event_name')

            if event_name == 'UserPromptSubmit':
                user_prompt = log_event.get('prompt')
                user_prompt_timestamp = log.get('timestamp')
                permission_mode = log_event.get('permission_mode', 'default')

    if not user_prompt:
        return

    messages = [{'role': 'user', 'content': user_prompt}]

    # Parse tool uses from Codex transcript (function_call/function_call_output pairs)
    assistant_tool_uses = parse_codex_transcript_for_tools(transcript_path, user_prompt_timestamp)

    assistant_msg = {
        'role': 'assistant',
        'content': last_assistant_message or ''
    }
    if assistant_tool_uses:
        assistant_msg['tool_use'] = assistant_tool_uses
    messages.append(assistant_msg)

    exchange = {
        'conversation_id': session_id or 'unknown',
        'model': event.get('model', 'auto'),
        'messages': messages,
        'permission_mode': permission_mode or 'default'
    }

    usage = parse_codex_transcript_for_usage(transcript_path, user_prompt_timestamp)
    if usage:
        exchange['usage'] = usage

    success = send_to_api(exchange, api_key)

    if success:
        remaining_logs = [
            log for log in logs
            if log.get('session_id') != session_id and
            (not log.get('event') or log.get('event', {}).get('session_id') != session_id)
        ]
        save_logs(remaining_logs)


def main():
    global _cached_api_key
    api_key = os.getenv('UNBOUND_CODEX_API_KEY')
    _cached_api_key = api_key

    try:
        input_data = sys.stdin.read().strip()

        if not input_data:
            print('{"suppressOutput": true}', flush=True)
            return

        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            print('{"suppressOutput": true}', flush=True)
            return

        hook_event_name = event.get('hook_event_name')
        session_id = event.get('session_id')

        # Handle PreToolUse - return immediately after decision is made
        # Note: Codex PreToolUse does not support suppressOutput
        if hook_event_name == 'PreToolUse':
            response = process_pre_tool_use(event, api_key)
            print(json.dumps(response), flush=True)
            return

        # Handle UserPromptSubmit - check policy before processing
        if hook_event_name == 'UserPromptSubmit':
            response = process_user_prompt_submit(event, api_key)

            # If denied (response has decision: block), return and don't log
            if response.get('decision') == 'block':
                response["suppressOutput"] = True
                print(json.dumps(response), flush=True)
                return

            # If allowed, continue to log the event (output printed at end)

        timestamp = datetime.utcnow().isoformat() + 'Z'
        log_entry = {
            'timestamp': timestamp,
            'session_id': event.get('session_id'),
            'event': event
        }

        append_to_audit_log(log_entry)

        if hook_event_name == 'Stop' and session_id:
            process_stop_event(event, api_key)

        cleanup_old_logs()

        print('{"suppressOutput": true}', flush=True)

    except Exception as e:
        # Still return empty JSON object to Codex to indicate completion
        log_error(f"Exception in main: {str(e)}", 'general')
        print('{"suppressOutput": true}', flush=True)


if __name__ == '__main__':
    main()
