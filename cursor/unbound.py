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
from datetime import datetime
import tempfile
import time
import hashlib

UNBOUND_GATEWAY_URL = "https://api.getunbound.ai"

# Max time (seconds) to wait for Slack approval before timing out.
# Buffer of 20s ensures poll_approval_status finishes before Claude Code's hook timeout
APPROVAL_TIMEOUT = 600
APPROVAL_POLL_TIMEOUT = APPROVAL_TIMEOUT - 20

# Use user's home directory for logs
LOG_DIR = Path.home() / ".cursor" / "hooks"
AUDIT_LOG = LOG_DIR / "agent-audit.log"
ERROR_LOG = LOG_DIR / "error.log"
LAST_REPORT_FILE = LOG_DIR / ".last_error_report"


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


def get_latest_user_prompt(generation_id):
    """Get the most recent user prompt for this generation from logs."""
    logs = load_existing_logs()
    latest_prompt = None

    for log in logs:
        event = log.get('event', {})
        if (event.get('hook_event_name') == 'beforeSubmitPrompt' and
            event.get('generation_id') == generation_id):
            latest_prompt = event.get('prompt')

    return latest_prompt


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
             "-d", data, url],
            capture_output=True,
            timeout=10
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


def _set_approval_marker(command, policy_ids, application_id):
    _APPROVAL_MARKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        'cmd': hashlib.sha256(command.encode()).hexdigest()[:16],
        'ts': time.time(),
        'policyIds': policy_ids,
        'applicationId': application_id,
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


def poll_approval_status(api_key, policy_ids, application_id, poll_interval=5, timeout=APPROVAL_POLL_TIMEOUT):
    """Poll the approval-status endpoint until approved, denied, or timeout.
    Returns 'approved', 'denied', or 'timeout'."""

    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/pretool/approval-status"
    body = json.dumps({"policyIds": policy_ids, "applicationId": application_id})
    deadline = time.time() + timeout

    while time.time() < deadline:
        time.sleep(poll_interval)
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
                if decision == 'denied':
                    return 'denied'
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


def process_pre_tool_use_execution(event, api_key, tool_name, command, mcp_server=None, mcp_tool=None):
    """Process beforeShellExecution or beforeMCPExecution event."""
    generation_id = event.get('generation_id')
    conversation_id = event.get('conversation_id')
    model = event.get('model') or 'auto'

    user_prompt = get_latest_user_prompt(generation_id)

    # Build metadata with the raw event, inject mcp fields if present
    metadata = dict(event)
    if mcp_server is not None:
        metadata['mcp_server'] = mcp_server
    if mcp_tool is not None:
        metadata['mcp_tool'] = mcp_tool

    is_retry = _is_approval_retry(command)

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
        'messages': [{'role': 'user', 'content': user_prompt}] if user_prompt else []
    }

    if not is_retry:
        request_body['first_approval_check'] = True

    # On retry, skip the gateway call — use cached IDs from the marker and poll.
    if is_retry:
        marker_data = _get_approval_marker_data()
        if marker_data:
            policy_ids = marker_data.get('policyIds', [])
            application_id = marker_data.get('applicationId', '')
            _clear_approval_marker()
            result = poll_approval_status(api_key, policy_ids, application_id)

            if result == 'approved':
                return {'permission': 'allow'}
            elif result == 'denied':
                return {
                    'permission': 'deny',
                    'user_message': 'Blocked by organization policy. This command was denied via Slack.',
                    'agent_message': 'This command was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                }
            else:
                return {
                    'permission': 'deny',
                    'user_message': 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry the command.',
                    'agent_message': 'This command was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                }

    api_response = send_to_hook_api(request_body, api_key)

    if api_response.get('decision') == 'approval_required':
        approval_check = api_response.get('approvalCheck', {})
        policy_ids = approval_check.get('policyIds', [])
        application_id = approval_check.get('applicationId', '')

        _set_approval_marker(command, policy_ids, application_id)
        return {
            'permission': 'deny',
            'user_message': 'An approval request has been sent to your Slack DMs. Please approve it there.',
            'agent_message': (
                'This is NOT a permanent block — it is a temporary hold pending Slack approval. '
                'Tell the user: "An approval request has been sent to your Slack DMs. '
                'Please approve it and I will retry automatically." '
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
            ["curl", "-fsSL", "-X", "POST", "-H", f"Authorization: Bearer {api_key}",
             "-H", "Content-Type: application/json", "-d", data, url],
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
    
    # If we have 50 or fewer entries, no cleanup needed
    if len(logs) <= 50:
        return
    
    # Track generation_ids in order of first appearance
    generation_order = []
    seen_generations = set()
    
    for log in logs:
        event = log.get('event', {})
        gen_id = event.get('generation_id')
        
        if gen_id and gen_id not in seen_generations:
            generation_order.append(gen_id)
            seen_generations.add(gen_id)
    
    # If we have multiple generation_ids and log count > 50,
    # keep only the most recent generation_id's entries
    if len(generation_order) > 1:
        # Keep only the most recent generation_id
        most_recent_gen_id = generation_order[-1]
        
        # Filter logs to keep only the most recent generation
        kept_logs = [
            log for log in logs
            if log.get('event', {}).get('generation_id') == most_recent_gen_id
        ]
        
        # Save the filtered logs
        save_logs(kept_logs)


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
                # Build LLM exchange
                exchange = build_llm_exchange(events, api_key)
                
                if exchange:
                    # Send to API
                    send_to_api(exchange, api_key)
                
                # Remove this generation's logs from agent-audit.log
                remaining_logs = [
                    log for log in logs
                    if log.get('event', {}).get('generation_id') != generation_id
                ]
                
                save_logs(remaining_logs)
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
        generation_id = event.get('generation_id')
        conversation_id = event.get('conversation_id')

        # Handle beforeShellExecution / beforeMCPExecution - check policy before execution
        if hook_event_name == 'beforeShellExecution':
            response = process_pre_tool_use_execution(event, api_key, 'Shell', event.get('command', ''))
            print(json.dumps(response), flush=True)
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        if hook_event_name == 'beforeMCPExecution':
            mcp_tool_name = event.get('tool_name', '')
            # Cursor doesn't provide mcp_server directly; pass tool_name as mcp_tool
            response = process_pre_tool_use_execution(
                event, api_key, f'MCP:{mcp_tool_name}', json.dumps(event.get('tool_input') or {}),
                mcp_server=None, mcp_tool=mcp_tool_name
            )
            print(json.dumps(response), flush=True)
            if response.get('permission') == 'deny':
                handle_deny_and_exit()
            return

        # Handle beforeSubmitPrompt - check policy before processing
        if hook_event_name == 'beforeSubmitPrompt':
            response = process_user_prompt_submit(event, api_key)

            # If denied, transform response for Cursor format and exit
            if response.get('decision') == 'deny':
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