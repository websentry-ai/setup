#!/usr/bin/env python3

import sys
import json
import os
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional
import time
import hashlib
import re
import tempfile
import platform


UNBOUND_GATEWAY_URL = os.environ.get(
    "UNBOUND_GATEWAY_URL", "https://api.getunbound.ai"
).rstrip("/")
AUDIT_LOG = Path.home() / ".claude" / "hooks" / "agent-audit.log"
ERROR_LOG = Path.home() / ".claude" / "hooks" / "error.log"
LAST_REPORT_FILE = Path.home() / ".claude" / "hooks" / ".last_error_report"
ALLOWED_NON_MCP_HOOK_NAMES = ['Bash', 'Read', 'Write', 'Edit']  # MCP tools (mcp__*) are always checked separately
NATIVE_FILE_TOOLS = {'Read', 'Write', 'Edit'}
MCP_TOOL_PREFIX = 'mcp__'
CLAUDE_MCP_CONFIG_PATH = Path.home() / ".claude.json"
CLAUDE_PLUGIN_CACHE_DIR = Path.home() / ".claude" / "plugins" / "cache"
POLICY_CACHE_FILE = Path.home() / ".claude" / "hooks" / ".policy_cache.json"
CACHE_TTL_SECONDS = 300
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'
PRETOOL_USER_MESSAGES_LIMIT = 5
AUDIT_LOG_TOTAL_LIMIT = 100

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

SELF_UPDATE_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/claude-code/hooks/unbound.py"
SELF_UPDATE_INTERVAL_SECONDS = 2 * 3600
SELF_UPDATE_LOCK_TTL_SECONDS = 30
SELF_UPDATE_CURL_TIMEOUT = 10
SELF_SCRIPT_PATH = Path.home() / ".claude" / "hooks" / "unbound.py"
SELF_UPDATE_STATE_PATH = SELF_SCRIPT_PATH.parent / ".self_update_check"
SELF_UPDATE_LOCK_PATH = SELF_SCRIPT_PATH.parent / ".self_update.lock"

# Frozen-binary mode (the PyInstaller-packaged `unbound-hook` CLI). The frozen
# binary must make ZERO network calls other than the backend/gateway APIs:
# self-update is owned by the MDM package (never in-place), and discovery runs
# from the locally installed binary instead of a GitHub-fetched install.sh.
# UNBOUND_HOOK_FROZEN=1 lets tests exercise these gates without freezing.
RUNNING_FROZEN = bool(getattr(sys, "frozen", False)) or os.environ.get("UNBOUND_HOOK_FROZEN") == "1"
FROZEN_DISCOVERY_BIN = "/opt/unbound/current/unbound-discovery/unbound-discovery"

APPROVAL_POLL_PHASES = (
    (5 * 60,        3),    # 0-5 min: 3s
    (30 * 60,       15),   # 5-30 min: 15s
    (2 * 60 * 60,   60),   # 30 min - 2h: 1min
    (4 * 60 * 60,   120),  # 2h - 4h: 2min
)

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
            'hook_source': 'claude-code',
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


def log_error(message: str, category: str = 'general'):
    """Log error with timestamp to error.log, keeping only last 25 errors."""
    message = redact_secrets(message, _cached_api_key)
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


def is_cache_stale(cache: Dict) -> bool:
    """Check if cached data is older than CACHE_TTL_SECONDS."""
    try:
        synced = datetime.fromisoformat(cache['last_synced'].rstrip('Z'))
        age = (datetime.utcnow() - synced).total_seconds()
        return age > CACHE_TTL_SECONDS
    except (ValueError, KeyError):
        return True


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


_APPROVAL_MARKER_FILE = Path.home() / ".claude" / "hooks" / ".approval_pending"


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


def _set_approval_marker(
    command: str,
    policy_ids: list,
    application_id: str,
    request_id: str = '',
    escalated_admin_contact: str = '',
) -> None:
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


def _get_approval_marker_data() -> Optional[Dict]:
    try:
        if _APPROVAL_MARKER_FILE.exists():
            return json.loads(_APPROVAL_MARKER_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _clear_approval_marker() -> None:
    try:
        _APPROVAL_MARKER_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _handle_approval_required_response(api_response: Dict, approval_key: str) -> Dict:
    approval_check = api_response.get('approvalCheck', {})
    policy_ids = approval_check.get('policyIds', [])
    application_id = approval_check.get('applicationId', '')
    request_id = approval_check.get('requestId', '')
    admin_contact = approval_check.get('escalatedAdminContact', '') or ''

    if admin_contact:
        reason = (
            f'We could not find your Slack account, so an approval request was sent to {admin_contact}. '
            'Please ask them to approve it in Slack.'
        )
        tell_user = f'Tell the user: "{reason}" '
    else:
        reason = 'An approval request has been sent to your Slack DMs. Please approve it there.'
        tell_user = (
            'Tell the user: "An approval request has been sent to your Slack DMs. '
            'Please approve it and I will retry automatically." '
        )

    _set_approval_marker(
        approval_key,
        policy_ids,
        application_id,
        request_id=request_id,
        escalated_admin_contact=admin_contact,
    )
    return transform_response_for_claude({
        'decision': 'deny',
        'reason': reason,
        'additionalContext': (
            'This is NOT a permanent block — it is a temporary hold pending Slack approval. '
            + tell_user +
            'Then immediately retry the exact same tool call with the exact same command — '
            'do not modify the command in any way, do not add sleep or any prefix. '
            'Retry exactly once — the second attempt will wait for the approval.'
        ),
    })


def _extract_session_model(logs: List[Dict], session_id: str) -> Optional[str]:
    """Return the model for `session_id` from the most recent SessionStart
    entry in `logs`. Forward scan with 'latest wins' — SessionStart is the
    oldest entry for a session, so scanning forward finds it in O(k) instead
    of O(n) (n includes every PostToolUse accumulated since). Returns None
    if no SessionStart has been logged for this session."""
    if not session_id or not logs:
        return None
    found = None
    try:
        for log in logs:
            log_session = log.get('session_id') or log.get('event', {}).get('session_id')
            if log_session != session_id:
                continue
            event = log.get('event', {}) if 'event' in log else log
            if event.get('hook_event_name') == 'SessionStart':
                model = event.get('model')
                if model:
                    found = model  # keep scanning — latest SessionStart wins
    except Exception:
        pass
    return found


def _get_session_model(session_id: str) -> Optional[str]:
    """Convenience wrapper for callers that don't already hold the logs in
    memory (PreToolUse / UserPromptSubmit handlers). Loads the audit log and
    delegates to `_extract_session_model`."""
    if not session_id:
        return None
    try:
        return _extract_session_model(load_existing_logs(), session_id)
    except Exception:
        return None


def parse_transcript_file(transcript_path: str, user_prompt_timestamp: Optional[str] = None) -> Dict:
    conversation_data = {
        'user_messages': [],
        'assistant_messages': [],
        'tool_uses': [],
        'usage': None,
        'model': None,
    }

    if not transcript_path or not os.path.exists(transcript_path):
        return conversation_data

    usage = {'input_tokens': 0, 'output_tokens': 0, 'cache_read_input_tokens': 0, 'cache_creation_input_tokens': 0}
    turn_model = None  # model that handled this turn; user_prompt_timestamp filter guarantees only this turn's lines are scanned

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
                            for content_item in message.get('content', []):
                                if isinstance(content_item, dict) and content_item.get('type') == 'text':
                                    text_content = content_item.get('text', '')
                                    if text_content:
                                        conversation_data['assistant_messages'].append({
                                            'content': text_content,
                                            'timestamp': entry_timestamp
                                        })

                            # Model is captured unconditionally so it survives even on usage-less assistant entries.
                            turn_model = turn_model or message.get('model')

                            msg_usage = message.get('usage') or {}
                            if msg_usage:
                                for k in usage:
                                    usage[k] += int(msg_usage.get(k) or 0)

                except json.JSONDecodeError:
                    continue

    except Exception:
        pass

    if any(usage.values()):
        conversation_data['usage'] = {**usage, 'total_tokens': sum(usage.values())}
    if turn_model:
        conversation_data['model'] = turn_model

    return conversation_data


def get_recent_user_prompts_for_session(
    session_id: str,
    n: int,
    transcript_path: Optional[str] = None,
) -> List[str]:
    if n <= 0:
        return []

    prompts: List[str] = []
    logs = load_existing_logs()
    for log in logs:
        log_session = log.get('session_id') or log.get('event', {}).get('session_id')
        if log_session != session_id:
            continue
        event = log.get('event', {})
        if event.get('hook_event_name') != 'UserPromptSubmit':
            continue
        prompt = event.get('prompt')
        if prompt:
            prompts.append(prompt)

    if prompts:
        return prompts[-n:]

    if transcript_path and transcript_path != 'undefined' and os.path.exists(transcript_path):
        data = parse_transcript_file(transcript_path)
        user_messages = data.get('user_messages') or []
        return [m.get('content') for m in user_messages[-n:] if m.get('content')]

    return []


def _build_user_prompt_payload(recent_user_prompts: List[str]) -> Dict:
    last = recent_user_prompts[-1] if recent_user_prompts else None
    return {
        'messages': [{'role': 'user', 'content': last}] if last else [],
        'user_prompts': recent_user_prompts,
    }


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
                log_error(f"Approval poll error: {str(e)}")

            if attempt < 2:
                time.sleep(0.5)

    return 'timeout'


def transform_response_for_claude(api_response: Dict) -> Dict:
    """Transform API response to Claude Code format for PreToolUse."""
    if not api_response:
        return {}

    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')
    additional_context = api_response.get('additionalContext', '')

    # On 'allow', emit no permissionDecision so Claude runs its normal permission flow (e.g. default-mode ask for un-allowlisted commands) instead of the hook force-approving.
    if decision == 'allow':
        if additional_context:
            return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'additionalContext': additional_context}}
        return {}

    return {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': decision,
            'permissionDecisionReason': reason,
            'additionalContext': additional_context
        }
    }


def transform_response_for_claude_prompt(api_response: Dict) -> Dict:
    """Transform API response to Claude Code format for UserPromptSubmit."""
    if not api_response:
        return {}

    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')

    # For UserPromptSubmit, 'deny' maps to 'block'
    if decision == 'deny':
        return {
            'decision': 'block',
            'reason': reason,
            'suppressOriginalPrompt': True,
        }

    return {}


def _extract_mcp_server_fields(server: Dict) -> Optional[Dict]:
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


def _mangle_mcp_token(s: Optional[str]) -> str:
    return re.sub(r'[^A-Za-z0-9_-]', '_', s or '')


def _plugin_mcp_server_map(version_dir: Path) -> Dict:
    servers = {}
    sources = [version_dir / ".mcp.json", version_dir / ".claude-plugin" / "plugin.json"]
    for source in sources:
        if not source.is_file():
            continue
        try:
            with open(source, 'r', encoding='utf-8') as f:
                data = json.loads(f.read())
        except Exception as exc:
            log_error(f"mcp plugin source unreadable: {source}: {exc}", 'mcp_plugin')
            continue
        if not isinstance(data, dict):
            continue
        mcp_servers = data.get('mcpServers')
        if isinstance(mcp_servers, str):
            # Contain the path to the version dir: reject absolute paths and
            # ../ traversal (and symlink escapes via resolve()).
            candidate = (version_dir / mcp_servers).resolve()
            try:
                candidate.relative_to(version_dir.resolve())
            except ValueError:
                continue
            if candidate.is_file():
                try:
                    with open(candidate, 'r', encoding='utf-8') as f:
                        rel_data = json.loads(f.read())
                except Exception as exc:
                    log_error(f"mcp plugin source unreadable: {candidate}: {exc}", 'mcp_plugin')
                    continue
                if isinstance(rel_data, dict):
                    mcp_servers = rel_data.get('mcpServers')
        if isinstance(mcp_servers, dict):
            for key, entry in mcp_servers.items():
                servers.setdefault(key, entry)
    return servers


def _select_plugin_version_dir(plugin_dir: Path) -> Optional[Path]:
    version_dirs = [d for d in plugin_dir.iterdir() if d.is_dir()]
    if not version_dirs:
        return None
    in_use = [d for d in version_dirs if (d / ".in_use").exists()]
    candidates = in_use or version_dirs
    return max(candidates, key=lambda d: (d.stat().st_mtime, d.name))


def _resolve_plugin_mcp_config(server_name: str, cache_dir: Path = CLAUDE_PLUGIN_CACHE_DIR) -> Optional[Dict]:
    if not server_name.startswith('plugin_'):
        return None
    try:
        if not cache_dir.is_dir():
            log_error(f"mcp plugin resolve miss: {server_name}", 'mcp_plugin')
            return None
        matches = []
        for marketplace in cache_dir.iterdir():
            if not marketplace.is_dir():
                continue
            for plugin_dir in marketplace.iterdir():
                if not plugin_dir.is_dir():
                    continue
                try:
                    version_dir = _select_plugin_version_dir(plugin_dir)
                    if version_dir is None:
                        continue
                    server_map = _plugin_mcp_server_map(version_dir)
                    for server_key, entry in server_map.items():
                        candidate = "plugin_%s_%s" % (
                            _mangle_mcp_token(plugin_dir.name),
                            _mangle_mcp_token(server_key),
                        )
                        if candidate == server_name:
                            fields = _extract_mcp_server_fields(entry)
                            if fields is not None:
                                matches.append(fields)
                except Exception as exc:
                    log_error(f"mcp plugin dir error: {plugin_dir.name}: {exc}", 'mcp_plugin')
                    continue
        distinct = []
        for cfg in matches:
            if cfg not in distinct:
                distinct.append(cfg)
        if len(distinct) == 1:
            return distinct[0]
        if not distinct:
            log_error(f"mcp plugin resolve miss: {server_name}", 'mcp_plugin')
            return None
        log_error(f"mcp plugin resolve ambiguous: {server_name}", 'mcp_plugin')
        return None
    except Exception as exc:
        log_error(f"mcp plugin resolve error: {server_name}: {exc}", 'mcp_plugin')
        return None


def _resolve_claude_ai_connector(server_name: str, config_path: Path = CLAUDE_MCP_CONFIG_PATH) -> Optional[tuple]:
    if not server_name.startswith('claude_ai_'):
        return None
    try:
        if not config_path.exists():
            log_error(f"mcp connector resolve miss: {server_name}", 'mcp_connector')
            return None
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.loads(f.read())
        ever_connected = config.get('claudeAiMcpEverConnected', [])
        distinct = []
        if isinstance(ever_connected, list):
            for display in ever_connected:
                if isinstance(display, str) and _mangle_mcp_token(display) == server_name:
                    if display not in distinct:
                        distinct.append(display)
        if len(distinct) == 1:
            return (distinct[0], {"additional_data": {"scope": "claudeai"}})
        if not distinct:
            log_error(f"mcp connector resolve miss: {server_name}", 'mcp_connector')
            return None
        log_error(f"mcp connector resolve ambiguous: {server_name}", 'mcp_connector')
        return None
    except Exception as exc:
        log_error(f"mcp connector resolve error: {server_name}: {exc}", 'mcp_connector')
        return None


_MCP_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
)


def _is_uuid(name: str) -> bool:
    return bool(name) and bool(_MCP_UUID_RE.match(name))


def _claude_code_sessions_dir() -> Optional[Path]:
    try:
        home = Path.home()
        if sys.platform == 'darwin':
            return home / 'Library' / 'Application Support' / 'Claude' / 'claude-code-sessions'
        if sys.platform.startswith('win'):
            appdata = os.environ.get('APPDATA')
            return Path(appdata) / 'Claude' / 'claude-code-sessions' if appdata else None
        return home / '.config' / 'Claude' / 'claude-code-sessions'
    except Exception:
        return None


def _resolve_claude_code_session_connector(server_uuid: str) -> Optional[tuple]:
    if not _is_uuid(server_uuid):
        return None
    try:
        base = _claude_code_sessions_dir()
        if not base or not base.exists():
            return None
        try:
            files = sorted(
                base.glob('**/local_*.json'),
                key=lambda p: p.stat().st_mtime, reverse=True,
            )[:20]
        except Exception:
            files = list(base.glob('**/local_*.json'))[:20]
        for f in files:
            try:
                data = json.loads(f.read_text(encoding='utf-8'))
            except Exception:
                continue
            for entry in (data.get('remoteMcpServersConfig') or []):
                if isinstance(entry, dict) and entry.get('uuid') == server_uuid:
                    name = entry.get('name')
                    if not name:
                        return None
                    cfg = {"additional_data": {"scope": "claude-connector"}}
                    url = entry.get('url')
                    if url:
                        cfg["url"] = url
                        cfg["type"] = "http"
                    return (name, cfg)
        return None
    except Exception as exc:
        log_error(f"mcp cc-session resolve error: {server_uuid}: {exc}", 'mcp_connector')
        return None


def _read_mcp_server_config(server_name: str, config_path: Path, cwd: Optional[str] = None) -> Optional[Dict]:
    try:
        if not config_path.exists():
            return None

        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.loads(f.read())

        if cwd:
            projects = config.get('projects', {})
            if isinstance(projects, dict):
                cwd_path = cwd.replace('\\', '/').rstrip('/')
                while cwd_path:
                    proj_data = projects.get(cwd_path)
                    if isinstance(proj_data, dict):
                        proj_servers = proj_data.get('mcpServers', {})
                        if isinstance(proj_servers, dict) and server_name in proj_servers:
                            result = _extract_mcp_server_fields(proj_servers[server_name])
                            if result:
                                return result
                    parent = os.path.dirname(cwd_path)
                    if parent == cwd_path:
                        break
                    cwd_path = parent

        top_servers = config.get('mcpServers', {})
        if isinstance(top_servers, dict) and server_name in top_servers:
            result = _extract_mcp_server_fields(top_servers[server_name])
            if result:
                return result

        return None
    except Exception:
        return None


def _email_domain(email: Optional[str]) -> Optional[str]:
    try:
        if email and '@' in email:
            domain = email.rsplit('@', 1)[1].strip().lower()
            return domain or None
    except Exception:
        pass
    return None


def read_account_identity() -> Dict:
    org_id = None
    plan = None
    auth_mode = None
    email = None
    try:
        config = json.loads(CLAUDE_MCP_CONFIG_PATH.read_text(encoding='utf-8'))
        oauth = config.get('oauthAccount')
        if isinstance(oauth, dict):
            org_id = oauth.get('organizationUuid') or None
            plan = oauth.get('organizationType') or None
            email = oauth.get('emailAddress') or None
            auth_mode = 'subscription'
        elif os.getenv('ANTHROPIC_API_KEY') or (config.get('customApiKeyResponses') or {}).get('approved'):
            auth_mode = 'api_key'
    except Exception:
        pass
    return {
        'org_id': org_id,
        'plan': plan,
        'auth_mode': auth_mode,
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


def _valid_serial(value: Optional[str]) -> bool:
    return bool(value) and value.strip().lower() not in _PLACEHOLDER_SERIALS


def _get_device_serial() -> Optional[str]:
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


def _device_serial(probe: bool = True) -> Optional[str]:
    """Hardware serial, computed once and cached. Never raises and never blocks the
    hook. On the latency-critical pre-tool path callers pass probe=False to read the
    cache only (no subprocess); SessionStart and the end-of-turn exchange probe and
    persist. A missing / corrupt / unreadable cache falls back to a fresh probe (when
    allowed), an unwritable cache is ignored (the probed value is still returned), and
    an unavailable serial returns None so the caller proceeds without it. The cache is
    shared with the cursor hook, so we merge and write atomically (no torn file)."""
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


def build_account_identity(probe: bool = False) -> Dict:
    """read_account_identity pulls the full user_email from ~/.claude.json; just add
    the device serial. probe defaults False so the latency-critical pre-tool path only
    reads the cache; the end-of-turn exchange passes probe=True. Never raises — on any
    failure the hook proceeds with whatever identity it has (possibly none)."""
    try:
        identity = read_account_identity()
        if not isinstance(identity, dict):
            identity = {}
    except Exception:
        identity = {}
    try:
        serial = _device_serial(probe=probe)
        if serial:
            identity['device_serial'] = serial
    except Exception:
        pass
    return identity


def process_pre_tool_use(event: Dict, api_key: str) -> Dict:
    """Process PreToolUse event - DO NOT LOG."""
    session_id = event.get('session_id')
    model = event.get('model') or _get_session_model(session_id) or 'auto'
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

    recent_user_prompts = get_recent_user_prompts_for_session(
        session_id, PRETOOL_USER_MESSAGES_LIMIT, transcript_path
    )
    command = extract_command_for_pretool(event)

    # Build metadata with the raw event
    metadata = dict(event)
    tool_input = event.get('tool_input') or {}
    if 'file_path' in tool_input:
        metadata['file_path'] = tool_input['file_path']

    if is_mcp:
        # Parse mcp__<server>__<tool> to extract server and tool for gateway matching
        parts = tool_name[len(MCP_TOOL_PREFIX):].split('__', 1)
        mcp_server_name = parts[0] if len(parts) >= 1 else ''
        metadata['mcp_server'] = mcp_server_name
        metadata['mcp_tool'] = parts[1] if len(parts) >= 2 else ''

        if mcp_server_name:
            cwd = event.get('cwd')
            server_cfg = _read_mcp_server_config(
                mcp_server_name, CLAUDE_MCP_CONFIG_PATH, cwd=cwd
            )
            if server_cfg:
                metadata['mcp_server_config'] = server_cfg

            if not server_cfg:
                connector = _resolve_claude_ai_connector(mcp_server_name)
                if connector:
                    display_name, connector_cfg = connector
                    metadata['mcp_server'] = display_name
                    metadata['mcp_server_config'] = connector_cfg
                else:
                    plugin_cfg = _resolve_plugin_mcp_config(mcp_server_name)
                    if plugin_cfg:
                        metadata['mcp_server_config'] = plugin_cfg
                    else:
                        session_connector = _resolve_claude_code_session_connector(mcp_server_name)
                        if session_connector:
                            display_name, connector_cfg = session_connector
                            metadata['mcp_server'] = display_name
                            metadata['mcp_server_config'] = connector_cfg

    approval_key = f"{tool_name}:{command}"
    is_retry = _is_approval_retry(approval_key)

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'claude-code',
        'model': model,
        'event_name': 'tool_use',
        'pre_tool_use_data': {
            'command': command,
            'tool_name': tool_name,
            'metadata': metadata
        },
        'account_identity': build_account_identity(),
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
                return transform_response_for_claude({'decision': 'allow'})
            elif result == 'deny':
                return transform_response_for_claude({
                    'decision': 'deny',
                    'reason': 'Blocked by organization policy. This command was denied via Slack.',
                    'additionalContext': 'This command was denied by an organization security policy. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. Inform the user and stop.',
                })
            else:
                admin_contact = marker_data.get('escalatedAdminContact', '') or ''
                if admin_contact:
                    timeout_reason = (
                        f'Blocked by organization policy. Approval request timed out — '
                        f'ask {admin_contact} to check Slack and retry the command.'
                    )
                else:
                    timeout_reason = 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry the command.'
                return transform_response_for_claude({
                    'decision': 'deny',
                    'reason': timeout_reason,
                    'additionalContext': 'This command was blocked by an organization security policy that requires approval. Do not attempt to achieve the same result using alternative tools, file operations, or workarounds. The user must approve via Slack and retry.',
                })

    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)

    if not api_response:
        if get_policy_check_failure_action() == 'block':
            return transform_response_for_claude({
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
        return _handle_approval_required_response(api_response, approval_key)

    if is_mcp and api_response.get('unknown_mcp_server'):
        server_cfg = metadata.get('mcp_server_config')
        if server_cfg:
            _dispatch_mcp_server_scan(metadata.get('mcp_server', ''), server_cfg)

    return transform_response_for_claude(api_response)


def process_user_prompt_submit(event: Dict, api_key: str) -> Dict:
    """Process UserPromptSubmit event for policy checking."""
    session_id = event.get('session_id')
    model = event.get('model') or _get_session_model(session_id) or 'auto'
    prompt = event.get('prompt', '')

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'claude-code',
        'model': model,
        'event_name': 'user_prompt',
        'account_identity': build_account_identity(),
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }

    api_response = send_to_hook_api(request_body, api_key)
    return transform_response_for_claude_prompt(api_response)


def build_llm_exchange(events: List[Dict], stop_assistant_message: Optional[str] = None, transcript_assistant_messages: Optional[List[str]] = None, model: Optional[str] = None, usage: Optional[Dict] = None, request_initialized: Optional[str] = None, request_completed: Optional[str] = None) -> Optional[Dict]:
    messages = []
    assistant_tool_uses = []

    user_prompt = None
    session_id = None
    permission_mode = None

    for log_entry in events:
        event = log_entry.get('event', {}) if 'event' in log_entry else log_entry
        hook_event_name = event.get('hook_event_name')

        if not session_id:
            session_id = event.get('session_id')

        if not permission_mode:
            permission_mode = event.get('permission_mode')

        if hook_event_name == 'UserPromptSubmit':
            prompt = event.get('prompt')
            if prompt:
                user_prompt = prompt
        
        elif hook_event_name == 'PostToolUse':
            tool_name = event.get('tool_name')
            tool_input = event.get('tool_input', {})
            tool_response = event.get('tool_response', {})
            
            if 'content' in tool_response and 'content' in tool_input:
                if tool_response['content'] == tool_input['content']:
                    tool_response = {k: v for k, v in tool_response.items() if k != 'content'}
            
            assistant_tool_uses.append({
                'type': 'PostToolUse',
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_response': tool_response,
                'tool_use_id': event.get('tool_use_id')
            })
    
    if user_prompt:
        messages.append({'role': 'user', 'content': user_prompt})
    

    all_responses = list(transcript_assistant_messages or [])
    if stop_assistant_message:
        if stop_assistant_message not in all_responses:
            all_responses.append(stop_assistant_message)
    assistant_response = '\n\n'.join(all_responses) if all_responses else ""

    if assistant_response or assistant_tool_uses:
        assistant_msg = {
            'role': 'assistant',
            'content': assistant_response
        }
        if assistant_tool_uses:
            assistant_msg['tool_use'] = assistant_tool_uses
        messages.append(assistant_msg)

    if len(messages) < 2:
        return None
    
    if not permission_mode:
        permission_mode = 'default'

    # Prefer caller-supplied model (process_stop_event resolves it from the
    # already-loaded audit log to avoid a second disk read). Fall back to the
    # on-demand lookup for any caller that doesn't pass one.
    if not model:
        model = _get_session_model(session_id) or 'auto'

    exchange = {
        'conversation_id': session_id or 'unknown',
        'model': model,
        'messages': messages,
        'permission_mode': permission_mode,
        'account_identity': build_account_identity(probe=True),
    }

    if usage:
        exchange['usage'] = usage

    if request_initialized:
        exchange['requestInitialized'] = request_initialized
    if request_completed:
        exchange['requestCompleted'] = request_completed

    return exchange


def send_to_api(exchange: Dict, api_key: str) -> bool:
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False
    
    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/claude"
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


def cleanup_old_logs():
    logs = load_existing_logs()

    if len(logs) <= AUDIT_LOG_TOTAL_LIMIT:
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
    elif len(logs) > AUDIT_LOG_TOTAL_LIMIT:
        save_logs(logs[-AUDIT_LOG_TOTAL_LIMIT:])


def process_stop_event(event: Dict, api_key: str):
    session_id = event.get('session_id')
    transcript_path = event.get('transcript_path')
    last_assistant_message = event.get('last_assistant_message')

    logs = load_existing_logs()
    
    session_events = []
    current_conversation_started = False
    user_prompt_timestamp = None
    stop_timestamp = None

    for log in logs:
        log_session_id = log.get('session_id') or log.get('event', {}).get('session_id')

        if log_session_id == session_id:
            event_name = log.get('event', {}).get('hook_event_name') if 'event' in log else log.get('hook_event_name')

            if event_name == 'UserPromptSubmit':
                session_events = [log]
                current_conversation_started = True
                user_prompt_timestamp = log.get('timestamp')
            elif current_conversation_started:
                session_events.append(log)
                if event_name == 'Stop':
                    stop_timestamp = log.get('timestamp')

    transcript_assistant_messages = []
    transcript_usage = None
    transcript_model = None
    if transcript_path and transcript_path != 'undefined' and user_prompt_timestamp:
        transcript_data = parse_transcript_file(transcript_path, user_prompt_timestamp)
        transcript_assistant_messages = [
            msg['content'] for msg in transcript_data.get('assistant_messages', [])
            if msg.get('content')
        ]
        transcript_usage = transcript_data.get('usage')
        transcript_model = transcript_data.get('model')

    # Prefer the dominant model from the transcript (covers sub-agent turns where
    # the cached session model is wrong). Fall back to the audit log otherwise.
    session_model = transcript_model or _extract_session_model(logs, session_id) or 'auto'

    # Stop event's logged time, not processing time
    request_completed = stop_timestamp or datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    exchange = build_llm_exchange(
        session_events,
        stop_assistant_message=last_assistant_message,
        transcript_assistant_messages=transcript_assistant_messages,
        model=session_model,
        usage=transcript_usage,
        request_initialized=user_prompt_timestamp,
        request_completed=request_completed,
    )

    if exchange:
        send_to_api(exchange, api_key)


def get_api_key():
    """Read API key from env, falling back to ~/.unbound/config.json.

    Claude Desktop (and other GUI launchers) spawn the hook via launchd, which
    doesn't inherit shell-profile env vars — same root cause as the
    cursor-from-Finder issue. setup.py already writes the key to
    ~/.unbound/config.json, so use it as a tier-2 lookup.
    """
    key = os.getenv('UNBOUND_CLAUDE_API_KEY')
    if key:
        return key
    try:
        config_file = Path.home() / ".unbound" / "config.json"
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.loads(f.read()).get('api_key')
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        log_error(f"~/.unbound/config.json is not valid JSON: {e}", 'config')
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
    # Under MDM the hook runs from an admin-managed location we can't write to,
    # so SELF_SCRIPT_PATH (user-level) is not the file executing — updating it
    # would only write a dead copy the managed settings never run. The daily MDM
    # cron refreshes the managed script instead. Only self-update when we are
    # actually running the user-level script (subscription installs).
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
            SELF_UPDATE_STATE_PATH.touch()
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
    cache: Dict = {}
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
    url = f"{UNBOUND_GATEWAY_URL}{DISCOVERY_HOOK_FLAG_PATH}"
    try:
        r = subprocess.run(
            ["curl", "-fsSL",
             "-H", f"Authorization: Bearer {api_key}",
             "--max-time", "5",
             url],
            capture_output=True, timeout=8,
        )
        if r.returncode != 0:
            return bool(flag.get("enabled", False))
        body = r.stdout.decode("utf-8", errors="replace")
        enabled = bool(json.loads(body).get("enabled", False))
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


def _install_sh_is_stale() -> bool:
    try:
        return (time.time() - DISCOVERY_INSTALL_SH.stat().st_mtime) > DISCOVERY_INSTALL_SH_TTL_SECONDS
    except OSError:
        return True


def _dispatch_mcp_server_scan(server_name: str, server_config: Dict) -> None:
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
        cache: Dict = {}
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
        # The marker is removed right after the fork (or on any failure path).
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
    global _cached_api_key
    api_key = get_api_key()
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

        # SessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if hook_event_name == "SessionStart":
            _device_serial()  # warm the (slow) serial probe + cache once per session
            _check_self_update()
            _dispatch_discovery()
            print("{}")
            return
        session_id = event.get('session_id')

        # Handle PreToolUse - return immediately after decision is made
        if hook_event_name == 'PreToolUse':
            response = process_pre_tool_use(event, api_key)
            response["suppressOutput"] = True
            print(json.dumps(response), flush=True)
            return

        # Handle UserPromptSubmit - check policy before processing
        if hook_event_name == 'UserPromptSubmit':
            response = process_user_prompt_submit(event, api_key)

            # If denied (response has decision: block), log the event then return
            if response.get('decision') == 'block':
                append_to_audit_log({
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'session_id': event.get('session_id'),
                    'event': event
                })
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
        # Still return empty JSON object to Claude Code to indicate completion
        log_error(f"Exception in main: {str(e)}", 'general')
        print('{"suppressOutput": true}', flush=True)


if __name__ == '__main__':
    main()