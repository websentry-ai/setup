#!/usr/bin/env python3

import sys
import json
import os
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import time
import hashlib
import re
import tempfile
import base64
from urllib.parse import urlparse


UNBOUND_GATEWAY_URL = os.environ.get(
    "UNBOUND_GATEWAY_URL", "https://api.getunbound.ai"
).rstrip("/")
CODEX_AUTH_PATH = Path.home() / ".codex" / "auth.json"
CODEX_CONFIG_PATH = Path.home() / ".codex" / "config.toml"
AUDIT_LOG = Path.home() / ".codex" / "hooks" / "agent-audit.log"
ERROR_LOG = Path.home() / ".codex" / "hooks" / "error.log"
LAST_REPORT_FILE = Path.home() / ".codex" / "hooks" / ".last_error_report"
ALLOWED_NON_MCP_HOOK_NAMES = ['Bash', 'apply_patch']  # MCP tools (mcp__*) are always checked separately
NATIVE_FILE_TOOLS = {'apply_patch'}
MCP_TOOL_PREFIX = 'mcp__'
# INVARIANT: every skill entry below carries a tool_use_id - the native one
# when the tool reports it, otherwise a deterministic synthetic one. The backend
# relies on this: two id-less invocations of one skill with the same arguments
# are byte-identical, so nothing can tell a replay from a genuine repeat.
SKILL_TOOL_NAME = 'Skill'
SKILL_SEARCH_DIRS = (('.agents', 'skills'), ('.codex', 'skills'))
SKILL_INVOKE_RE = re.compile(r'(?:^|\s)\$([A-Za-z0-9][A-Za-z0-9._:-]*)')
POLICY_CACHE_FILE = Path.home() / ".codex" / "hooks" / ".policy_cache.json"
CACHE_TTL_SECONDS = 300
# Repo-scope gate. Straying outside the allowed org is blocked on the first
# write, and the gate keeps no state on disk at all.
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'
PRETOOL_USER_MESSAGES_LIMIT = 5
AUDIT_LOG_TOTAL_LIMIT = 100

APPROVAL_TIMEOUT = 4 * 60 * 60

DISCOVERY_DEBOUNCE_SECONDS = 24 * 3600
DISCOVERY_STALE_LOCK_SECONDS = 15 * 60
DISCOVERY_CACHE_PATH = Path.home() / ".unbound" / "discovery-cache.json"
DISCOVERY_LOCK_PATH = Path.home() / ".unbound" / "discovery.lock"
DISCOVERY_DISPATCH_PATH = Path.home() / ".unbound" / "discovery.dispatch.lock"
DISCOVERY_DISPATCH_TTL_SECONDS = 10
DISCOVERY_INSTALL_DIR = Path.home() / ".local" / "share" / "unbound"
DISCOVERY_INSTALL_SH = DISCOVERY_INSTALL_DIR / "install.sh"
DISCOVERY_INSTALL_PS1 = DISCOVERY_INSTALL_DIR / "install.ps1"
DISCOVERY_INSTALL_URL = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main/install.sh"
DISCOVERY_INSTALL_PS1_URL = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main/install.ps1"

DISCOVERY_INSTALL_SH_TTL_SECONDS = 24 * 3600
UNBOUND_CONFIG_PATH = Path.home() / ".unbound" / "config.json"

SELF_UPDATE_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/codex/hooks/unbound.py"
SELF_UPDATE_INTERVAL_SECONDS = 2 * 3600
SELF_UPDATE_LOCK_TTL_SECONDS = 30
SELF_UPDATE_CURL_TIMEOUT = 8
SELF_SCRIPT_PATH = Path.home() / ".codex" / "hooks" / "unbound.py"
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
            'hook_source': 'codex',
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


def get_repo_policies() -> List[Dict]:
    """Repo-scope policies from cache, [] if absent; a stale cache still applies."""
    cache = _read_policy_cache_raw()
    if cache is None:
        return []
    policies = cache.get('repo_policies')
    return policies if isinstance(policies, list) else []


def save_policy_cache(tools_to_check: Optional[List[str]] = None, policy_check_failure_action: Optional[str] = None, repo_policies: Optional[List[Dict]] = None):
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
        if isinstance(repo_policies, list):
            cache['repo_policies'] = repo_policies
        with open(POLICY_CACHE_FILE, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cache))
    except (OSError, TypeError):
        pass


def _cache_policies_from_response(api_response: Optional[Dict]):
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


def _handle_approval_required_codex_response(api_response: Dict, approval_key: str) -> Dict:
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
    else:
        reason = 'An approval request has been sent to your Slack DMs. Please approve it there.'

    _set_approval_marker(
        approval_key,
        policy_ids,
        application_id,
        request_id=request_id,
        escalated_admin_contact=admin_contact,
    )
    return transform_response_for_codex({
        'decision': 'deny',
        'reason': reason,
        'additionalContext': (
            'Temporary hold pending Slack approval. Retry the exact same command once — '
            'the second attempt will wait for the approval and complete automatically. '
            'Workarounds will be blocked too.'
        ),
    })


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


def _typed_user_text(entry: Dict) -> str:
    """The typed text of a transcript entry, forwarded verbatim so DLP scans what
    the user wrote. Only text blocks are prompt text: tool results, meta entries
    and images are not, and yield '' so the caller skips the entry."""
    if 'toolUseResult' in entry or entry.get('isMeta'):
        return ''
    message = entry.get('message') or {}
    if message.get('role') != 'user':
        return ''
    content = message.get('content')
    if isinstance(content, str):
        return content if content.strip() else ''
    if isinstance(content, list):
        texts = [
            block.get('text') for block in content
            if isinstance(block, dict) and block.get('type') == 'text'
        ]
        joined = '\n'.join(t for t in texts if isinstance(t, str))
        return joined if joined.strip() else ''
    return ''


def _ts_key(value) -> Optional[str]:
    """Comparable form of a transcript timestamp. Numeric timestamps are epoch seconds or
    milliseconds and normalize to the same ISO form the string ones already use."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000.0 if value > 10_000_000_000 else float(value)
        try:
            return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace('+00:00', 'Z')
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _ts_lt(earlier, later) -> bool:
    """Ordering that never raises on an unexpected timestamp type. Callers decide what an
    unorderable value means; this only reports a proven ordering."""
    a, b = _ts_key(earlier), _ts_key(later)
    return a is not None and b is not None and a < b


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
                        typed = _typed_user_text(entry)
                        if typed:
                            conversation_data['user_messages'].append({
                                'content': typed,
                                'timestamp': entry_timestamp
                            })

                    elif entry_type == 'assistant':
                        if user_prompt_timestamp and not _ts_lt(user_prompt_timestamp, entry_timestamp):
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
        # Delegated subagent prompts arrive under the parent's session id; they are not
        # things the user typed, so they do not belong in the user's recent history.
        if event.get('agent_id'):
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
    # apply_patch: the patch/diff content, so each patch gets a distinct synthetic
    # id instead of every apply_patch in a turn collapsing to the tool name.
    if tool_name == 'apply_patch' and tool_input:
        return tool_input.get('input') or tool_input.get('patch') or tool_input.get('diff') or json.dumps(tool_input, sort_keys=True)
    # Default: tool name
    return tool_name


def _synthetic_tool_use_id(session_id, turn_id, tool_name, command) -> str:
    """Deterministic fallback id for tools with no native id (byte-identical pre vs
    completion). MCP input is canonicalized (sort_keys) so key-order variance between
    the pre event and the transcript-decoded completion can't diverge the id."""
    try:
        command = json.dumps(json.loads(command), sort_keys=True)
    except (ValueError, TypeError):
        pass
    key = '\x1f'.join((str(session_id or ''), str(turn_id or ''),
                       str(tool_name or ''), str(command or '')))
    return 'unb-' + hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:24]


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
    if decision == 'allow':
        return {}

    reason = api_response.get('reason', '') or 'Blocked by organization policy.'
    additional_context = api_response.get('additionalContext', '')

    hook_output = {
        'hookEventName': 'PreToolUse',
        'permissionDecision': 'deny',
        'permissionDecisionReason': reason,
    }
    if additional_context:
        hook_output['additionalContext'] = additional_context

    return {'hookSpecificOutput': hook_output}


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

    # Allowed with injected context (e.g. the spend-limit alert-threshold
    # warning "you've used $X of your $Y limit"): Codex hooks are
    # Claude-parity — additionalContext feeds the model, systemMessage shows
    # the same text to the user.
    additional_context = api_response.get('additionalContext', '')
    if additional_context:
        return {
            'hookSpecificOutput': {
                'hookEventName': 'UserPromptSubmit',
                'additionalContext': additional_context,
            },
            'systemMessage': additional_context,
        }

    return {}


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
        if '${' in path:
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


# KEEP IN SYNC: coding-discovery-tool mcp_tools_cache.py + all 5 hook copies — byte-identical, do not diverge.
# Fingerprints key the local tool-hash cache; Redis tool scores are separately
# keyed by tool content hash. Keep fingerprint output aligned with data/gateway.

_MCP_TOOLS_CACHE_FILENAME = 'mcp-tools-cache.json'
_MCP_TOOLS_CACHE_MAX_BYTES = 2 * 1024 * 1024
_MCP_CACHE_CODING_TOOL_NAMES = frozenset({'codex'})
_MCP_CACHE_CODING_TOOL_PREFIXES = ()
_UNBOUND_CODING_TOOL = 'Codex'


# Canonical MCP fingerprint port. Keep output aligned with the data, gateway,
# and discovery implementations.
CLAUDE_BUILTIN_PREFIX = 'claude-builtin:'

CLAUDE_CONNECTOR_SCOPE = 'claude-connector'

# Claude Code sanitizes display names into runtime names (non-alphanumerics -> '_'), so one
# server arrives under several spellings. chrome/browser/preview stay separate: different tools.
_CLAUDE_BUILTIN_NAMES = {
    'computer-use': 'computer-use',
    'claude-in-chrome': 'claude-in-chrome',
    'claude-for-chrome': 'claude-in-chrome',
    'claude-browser': 'claude-browser',
    'claude-preview': 'claude-preview',
    'claude-design': 'claude-design',
    'ccd-session': 'ccd-session',
    'ccd-session-mgmt': 'ccd-session-mgmt',
    'ide': 'ide',
}

_BUILTIN_NAME_SEPARATOR_RE = re.compile(r'[\s_]+')


def claude_builtin_identity(name):
    """Canonical built-in identity for a bare server name, or None."""
    key = _BUILTIN_NAME_SEPARATOR_RE.sub('-', (name or '').strip().lower())
    return _CLAUDE_BUILTIN_NAMES.get(key)

CLAUDEAI_NAME_PREFIX = 'claude.ai '
CLAUDEAI_ALLOWED_ADDITIONAL_DATA = ({}, {'scope': 'claudeai'})

# npm-package runners: the first positional arg is the package to run.
NPM_RUNNERS = frozenset({'npx', 'npm', 'bunx'})
# Sub-runners under npx/bunx that are not the package themselves (the real
# target -- usually a local script -- follows).
NPX_LOCAL_RUNNERS = frozenset({'tsx', 'ts-node'})
# npm/bunx subcommands that precede the actual package name.
NPM_SUBCOMMANDS = frozenset({'exec', 'run', 'run-script', 'x', 'create', 'init', 'install', 'i'})
# Python-package runners and the sub-commands that precede the package.
PYPI_RUNNERS = frozenset({'uvx', 'uv', 'pipx'})
PYPI_SUBCOMMANDS = frozenset({'run', 'tool', 'tool-run'})

# Prompt Security's MCP proxy wraps the real server command after this token.
PROMPT_SECURITY_BASENAME = 'prompt_security_mcp'
PROMPT_SECURITY_ARGS_SENTINEL = '__args__'

# Language runtimes that execute a local script given as an arg. They never
# produce a `bin:` identity -- their script identity is the content hash.
# Keep in sync with _HOOK_SCRIPT_RUNTIMES in the hook files (setup/*/hooks/unbound.py).
RUNTIMES = frozenset({
    'node', 'nodejs', 'bun', 'deno', 'python', 'python2', 'python3', 'py',
    'ruby', 'dart', 'php', 'perl', 'rscript',
})

# Commands that have their own rule (or are runtimes) -- excluded from the
# catch-all `bin:` tier so they don't double-resolve.
BIN_SKIP_COMMANDS = (
    RUNTIMES | NPM_RUNNERS | PYPI_RUNNERS
    | frozenset({'docker', 'builtin', PROMPT_SECURITY_BASENAME})
)

# Basenames too generic to identify a product -- `bin:` skips these (they
# collide across unrelated servers).
GENERIC_BIN_NAMES = frozenset({
    'mcp-server', 'mcpserver', 'mcp', 'server', 'main', 'index', 'start', 'app',
    'run', 'cli', 'bin', 'tool', 'agent', 'my-command', 'my-mcp-server', 'node-repl',
})

# Shells / build orchestrators / generic launchers. Their basename is not a
# product identity -- the real server lives in the args (which `bin:` drops) or
# in a file they exec. They never produce a `bin:` fingerprint.
LAUNCHER_COMMANDS = frozenset({
    'sh', 'bash', 'zsh', 'fish', 'dash', 'ksh', 'cmd', 'powershell', 'pwsh',
    'env', 'cscript', 'wscript', 'make', 'mach', 'task', 'just',
})

# A command that is itself a local script file (run directly, not via a
# runtime). Its identity is the file contents, so it routes to the `script:`
# tier -- never `bin:`.
_SCRIPT_COMMAND_RE = re.compile(r'\.(sh|py|js|cjs|mjs|ts|tsx|rb|php|dart)$', re.IGNORECASE)


_LOCAL_PATH_EXT_RE = re.compile(r'\.(js|cjs|mjs|ts|tsx|py|rb|php|dart|sh|rs|go|jar)$', re.IGNORECASE)
_EXE_SUFFIX_RE = re.compile(r'\.(exe|cmd|bat|com)$')
_PLATFORM_SUFFIX_RE = re.compile(
    r'-(darwin|linux|windows|macos|win32|win)(-(arm64|x64|x86|amd64|aarch64))?$'
)


# Scheme default ports, dropped from the identity (mirrors JS URL semantics).
_DEFAULT_PORTS = {'http': 80, 'https': 443, 'ws': 80, 'wss': 443}


def _extract_url_identity(url_value: str) -> Optional[str]:
    """
    Normalize a URL into a stable identity string: `host[:port]/path`.

    The path is kept (not stripped) so multi-tenant proxy services like
    mintmcp.com / composio don't collapse into a single fingerprint when they
    actually serve different underlying services at different paths. Query and
    fragment are dropped (those typically carry session/auth params that vary
    per install).

    Host is lowercased, trailing slashes on path are stripped, empty paths
    normalize to an absent segment.
    """
    if not url_value or not isinstance(url_value, str):
        return None
    try:
        parsed = urlparse(url_value.strip())
    except ValueError:
        return None

    host = (parsed.hostname or '').lower()
    if not host:
        return None

    # Drop the scheme's default port so `https://h:443/x` and `https://h/x`
    # share one identity (matches JS `new URL().port`, which omits defaults).
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None and _DEFAULT_PORTS.get((parsed.scheme or '').lower()) == port:
        port = None
    host_port = f'{host}:{port}' if port else host

    # Normalize path: drop trailing slashes, drop if empty or just "/"
    path = (parsed.path or '').rstrip('/')
    identity = f'{host_port}{path}' if path else host_port
    return identity


def _urls_in_args(args: List[str]) -> List[str]:
    return [
        a for a in args
        if isinstance(a, str) and (a.startswith('http://') or a.startswith('https://'))
    ]


def _command_base(command: Optional[str]) -> str:
    """Basename of a command, lowercased, with a Windows executable suffix dropped."""
    if not command:
        return ''
    base = re.split(r'[\\/]', command.strip())[-1]
    return _EXE_SUFFIX_RE.sub('', base.lower())


def _unquote(value: str) -> str:
    """Strip surrounding quotes some clients leave in arg values."""
    return value.strip('"\'')


def _looks_like_local_path(value: str) -> bool:
    """A path to a local file/script (not a package/identity)."""
    v = _unquote(value)
    if v.startswith('http://') or v.startswith('https://'):
        return False
    if v.startswith('@'):  # npm scope, not a path
        return False
    if v.startswith('git+'):
        return False
    if '${' in v:  # env-var path template
        return True
    if '/' in v or '\\' in v:
        return True
    return bool(_LOCAL_PATH_EXT_RE.search(v))


def _npm_package_from_args(args: List[str]) -> Optional[str]:
    """Find the first @scoped npm package in args, stripped of any @version suffix."""
    for arg in args:
        if not isinstance(arg, str) or not arg.startswith('@'):
            continue
        second_at = arg.find('@', 1)
        return arg[:second_at] if second_at != -1 else arg
    return None


def _normalize_npm(pkg: str) -> str:
    """@scope/name@ver -> @scope/name ; name@ver -> name"""
    p = _unquote(pkg)
    if p.startswith('@'):
        i = p.find('@', 1)
        return p[:i] if i != -1 else p
    return p.split('@')[0]


def _normalize_pypi(pkg: str) -> str:
    """Strip a version spec from a Python requirement: name==1, name>=1, name@1."""
    return re.split(r'[=<>@~!]', _unquote(pkg))[0]


def _git_identity(spec: str) -> Optional[str]:
    """git+https://github.com/owner/repo(.git)(@ref) -> github.com/owner/repo"""
    s = _unquote(spec)
    if s.startswith('git+'):
        s = s[4:]
    s = re.sub(r'^(https?|ssh|git)://', '', s)
    s = re.sub(r'^[^/]*@', '', s).replace(':', '/', 1)
    s = re.sub(r'\.git(@.*)?$', '', s)
    s = re.sub(r'@[^/]*$', '', s)
    parts = [p for p in s.split('/') if p]
    if len(parts) < 3:
        return None
    return '/'.join(parts[:3]).lower()


def _git_from_args(args: List[str]) -> Optional[str]:
    for arg in args:
        if not isinstance(arg, str):
            continue
        t = _unquote(arg)
        is_git = (
            t.startswith('git+')
            or t.startswith('git@')
            or (re.match(r'^(https?|ssh)://', t) is not None
                and re.search(r'(github\.com|gitlab\.com|bitbucket\.org)', t) is not None)
        )
        if not is_git:
            continue
        identity = _git_identity(t)
        if identity:
            return identity
    return None


def _package_from_runner_args(args: List[str], skip: frozenset) -> Optional[str]:
    """First package-looking arg under a runner, skipping flags, the runner's own
    sub-tokens, and bailing on a local-path arg (that's a script, not a package)."""
    for arg in args:
        if not isinstance(arg, str) or arg.startswith('-'):
            continue
        t = _unquote(arg)
        if t in skip:
            continue
        if _looks_like_local_path(t):
            return None
        return t
    return None


# `docker run` BOOLEAN flags — the closed, stable set that consumes NO value.
# Everything else that looks like a flag is treated as value-taking, so an
# unknown or newly-added value flag can never leak its value as the image: it
# fails toward no fingerprint rather than a wrong one. This is the reliable axis
# (the value-flag set is open-ended and grows with docker; the boolean set does
# not). `--flag=value` and attached short values (`-eKEY`) are self-contained.
DOCKER_BOOLEAN_FLAGS = frozenset({
    '-i', '--interactive', '-t', '--tty', '-d', '--detach', '-P', '--publish-all',
    '--rm', '--init', '--privileged', '--read-only', '--no-healthcheck',
    '--oom-kill-disable', '--disable-content-trust', '--sig-proxy', '-q', '--quiet',
})
_DOCKER_SHORT_BOOLEANS = set('itdPq')       # for combined forms: -it, -itd
_DOCKER_SHORT_VALUES = set('evpwulmhca')    # for attached forms: -eKEY, -p8080

# A docker image candidate, tag and digest already stripped. Repository names are
# lowercase (docker rejects `docker run FOO`), so this rejects any leaked
# uppercase value as a final backstop.
_DOCKER_IMAGE_REF_RE = re.compile(r'[a-z0-9][a-z0-9._:/-]*')
_DOCKER_DIGEST_RE = re.compile(r'@[A-Za-z0-9]+:[A-Fa-f0-9]+$')  # @sha256:<hex>


def _is_docker_image_ref(candidate: str) -> bool:
    return bool(_DOCKER_IMAGE_REF_RE.fullmatch(candidate))


def _docker_flag_consumes_value(arg: str) -> bool:
    """True when this flag takes the FOLLOWING token as its value (so that token
    is not the image). Boolean flags and self-contained forms return False;
    anything unrecognized is assumed value-taking (fail toward null)."""
    if '=' in arg:
        return False                        # --flag=value / -e=value (attached)
    if arg in DOCKER_BOOLEAN_FLAGS:
        return False
    if arg.startswith('--'):
        return True                         # any other long flag: value-taking
    letters = arg[1:]                        # short flag(s): -x or bundle -xyz
    if letters and all(c in _DOCKER_SHORT_BOOLEANS for c in letters):
        return False                        # combined booleans, e.g. -it, -itd
    if len(letters) > 1 and letters[0] in _DOCKER_SHORT_VALUES:
        return False                        # attached value, e.g. -eKEY, -p8080
    return True                             # -e / -p (separate value) or unknown


def _normalize_docker_image(arg: str) -> str:
    image = _unquote(arg)
    image = _DOCKER_DIGEST_RE.sub('', image)     # drop @sha256:<digest>
    return re.sub(r':[^/]+$', '', image)         # drop :tag, keep registry/repo


def _docker_image_from_args(args: List[str]) -> Optional[str]:
    # Skip each value flag's next token; the first bare, lowercase image-ref-shaped
    # token is the image. Unknown flags are assumed value-taking, so a leaked value
    # never becomes the fingerprint.
    if 'run' not in args:
        return None
    run_idx = args.index('run')
    skip_next = False
    for arg in args[run_idx + 1:]:
        if not isinstance(arg, str):
            continue
        if skip_next:
            skip_next = False
            continue
        if arg.startswith('-'):
            if _docker_flag_consumes_value(arg):
                skip_next = True
            continue
        image = _normalize_docker_image(arg)
        if _is_docker_image_ref(image):
            return image
    return None


def _command_is_script_file(command: str) -> bool:
    """True when the command is itself a local script file (e.g. `.../bin.sh`)."""
    base = re.split(r'[\\/]', command.strip())[-1]
    return bool(_SCRIPT_COMMAND_RE.search(base))


def _normalize_bin(command: str) -> Optional[str]:
    """Basename of a bespoke binary, normalized for cross-platform collapse. Drops
    the path, executable suffix, and platform/arch suffix; None when generic."""
    b = re.split(r'[\\/]', command.strip())[-1].lower()
    b = _EXE_SUFFIX_RE.sub('', b)
    b = _PLATFORM_SUFFIX_RE.sub('', b)
    b = b.strip(' -_')
    if not b or b in GENERIC_BIN_NAMES:
        return None
    return b


def compute_fingerprint(
    name: Optional[str],
    command: Optional[str],
    url: Optional[str],
    args: Optional[List[str]],
    additional_data: Optional[Dict[str, Any]],
    script_hash: Optional[str] = None,
) -> Optional[str]:
    """
    Derive a stable fingerprint for an MCP server.

    The function is a priority chain: the first signal that yields a result wins.
    `script_hash`, when provided, is the client-computed content hash of a local
    script (the gateway/control plane cannot read the file itself).
    Returns None when no signal is extractable.
    """
    safe_name = name or ''
    safe_args = args or []
    safe_additional_data = additional_data or {}
    base = _command_base(command)

    # 0. Prompt Security proxy: the real server command follows `__args__`.
    #    Unwrap and fingerprint the inner command instead of the wrapper.
    if base == PROMPT_SECURITY_BASENAME and PROMPT_SECURITY_ARGS_SENTINEL in safe_args:
        idx = safe_args.index(PROMPT_SECURITY_ARGS_SENTINEL)
        if idx + 1 < len(safe_args):
            inner = safe_args[idx + 1:]
            inner_cmd = inner[0] if inner else None
            inner_url = inner_cmd if inner_cmd and inner_cmd.startswith(('http://', 'https://')) else None
            return compute_fingerprint(
                name=safe_name,
                command=None if inner_url else inner_cmd,
                url=inner_url,
                args=inner[1:],
                additional_data=safe_additional_data,
                script_hash=script_hash,
            )

    # Claude desktop OAuth remote connector. Named by a per-registration UUID at
    # runtime; the client hook resolves the display name and tags the config
    # scope="claude-connector" so every instance of e.g. "Gmail" groups by name.
    # This wins over the url branch below: the connector carries a per-registration
    # url, but the device sweep that seeds the keeper omits it, so fingerprinting
    # by url here would never match claude-connector:<name>.
    if safe_additional_data.get('scope') == CLAUDE_CONNECTOR_SCOPE and safe_name:
        return f'claude-connector:{safe_name.lower()}'

    # First-party built-ins arrive as a bare name (no command/url/args); collapse
    # separator variants to one identity so aliases share a fingerprint.
    if not command and not url and not safe_args:
        builtin = claude_builtin_identity(safe_name)
        if builtin:
            return f'{CLAUDE_BUILTIN_PREFIX}{builtin}'

    # 1. url field -> url:<host[:port]/path>
    if url:
        identity = _extract_url_identity(url)
        if identity:
            return f'url:{identity}'

    # 2. URLs inside args -> url-arg:<identity> (only if all URLs resolve to a single identity)
    url_args = _urls_in_args(safe_args)
    if url_args:
        identities = {_extract_url_identity(u) for u in url_args}
        identities.discard(None)
        if len(identities) == 1:
            return f'url-arg:{next(iter(identities))}'
        if len(identities) > 1:
            return None

    # 3. git+ install spec in args (npx/uvx git installs)
    git = _git_from_args(safe_args)
    if git:
        return f'git:{git}'

    # 4. @scoped npm package anywhere in args (command-agnostic, original rule)
    scoped_npm = _npm_package_from_args(safe_args)
    if scoped_npm:
        return f'npm:{scoped_npm}'

    # 5. npm package run via npx / npm / bunx (bare or quoted-scoped)
    if base in NPM_RUNNERS:
        pkg = _package_from_runner_args(safe_args, NPX_LOCAL_RUNNERS | NPM_SUBCOMMANDS | RUNTIMES)
        if pkg:
            return f'npm:{_normalize_npm(pkg)}'

    # 6. Python package run via uvx / uv / pipx
    if base in PYPI_RUNNERS:
        pkg = _package_from_runner_args(safe_args, PYPI_SUBCOMMANDS)
        if pkg:
            return f'pypi:{_normalize_pypi(pkg)}'

    # 7. docker run <image> (skip `docker mcp ...`, the Docker MCP gateway CLI)
    if base == 'docker' and (not safe_args or safe_args[0] != 'mcp'):
        image = _docker_image_from_args(safe_args)
        if image:
            return f'docker:{image}'

    # 8. IntelliJ plugin-managed server. Parser still checks literal "builtin"
    # (that's what coding-discovery-tool/.../jetbrains/mcp_config_extractor.py writes);
    # the prefix is intellij: for accurate semantic labeling.
    if command == 'builtin' and safe_name:
        return f'intellij:{safe_name.lower()}'

    # 9. Claude.ai native integration. Two name forms arrive: the hook-resolved
    # display ("claude.ai Atlassian") and the raw runtime key
    # ("claude_ai_Atlassian") when hook resolution missed — e.g. the first-time
    # `authenticate` call, before the connector is in claudeAiMcpEverConnected.
    # Reconstruct the display form from the raw key so both fingerprint the same.
    if (
        not command
        and not safe_args
        and safe_additional_data in CLAUDEAI_ALLOWED_ADDITIONAL_DATA
    ):
        if safe_name.startswith(CLAUDEAI_NAME_PREFIX):
            return f'claudeai:{safe_name.lower()}'
        raw_key = re.fullmatch(r'claude_ai_(.+)', safe_name)
        if raw_key:
            rest = re.sub(r'_+', ' ', raw_key.group(1)).strip().lower()
            if rest:
                return f'claudeai:{CLAUDEAI_NAME_PREFIX}{rest}'

    # (Claude desktop OAuth remote connector is handled above the url branch —
    # scope="claude-connector" groups by name regardless of the per-registration url.)

    # 11. Local script identified by client-supplied content hash. Covers both
    #     runtime+file (`node x.js`) and a script run directly (`.../bin.sh`).
    #     Ignore empty / punctuation-only values (e.g. "", "/", "///") -> None.
    clean_hash = (script_hash or '').strip()
    if re.fullmatch(r'[a-f0-9]{64}', clean_hash, re.IGNORECASE):
        return f'script:{clean_hash.lower()}'

    # 12. Bespoke local binary -- basename only, args dropped (they carry
    #     per-user paths/ids that would explode cardinality). Skips runtimes,
    #     launchers/shells, and script files (those are script-tier identities).
    if (
        command
        and base not in BIN_SKIP_COMMANDS
        and base not in LAUNCHER_COMMANDS
        and not _command_is_script_file(command)
    ):
        bin_name = _normalize_bin(command)
        if bin_name:
            return f'bin:{bin_name}'

    return None

def compute_mcp_cache_key(name, command, url, args, additional_data=None, script_hash=None):
    if name is not None and not isinstance(name, str):
        return None
    if url is not None and not isinstance(url, str):
        return None
    if command is not None and not isinstance(command, str):
        return None
    if args is not None and (
        not isinstance(args, list)
        or any(not isinstance(arg, str) for arg in args)
    ):
        return None
    if additional_data is not None and not isinstance(additional_data, dict):
        return None
    return compute_fingerprint(
        name=name, command=command, url=url, args=args,
        additional_data=additional_data, script_hash=script_hash,
    )


def _unbound_state_dir_candidates():
    candidates = [Path.home() / '.unbound']
    if hasattr(os, 'getuid'):
        candidates.append(Path(f'/var/tmp/unbound-{os.getuid()}'))
    else:
        candidates.append(Path(tempfile.gettempdir()) / 'unbound')
    return candidates


def _read_mcp_tools_cache():
    home_state_dir = Path.home() / '.unbound'
    newest_cache = {}
    newest_mtime = -1.0
    for state_dir in _unbound_state_dir_candidates():
        try:
            if state_dir != home_state_dir:
                if state_dir.is_symlink() or not state_dir.is_dir():
                    continue
                if hasattr(os, 'getuid'):
                    state_dir_stat = state_dir.stat()
                    if state_dir_stat.st_uid != os.getuid() or state_dir_stat.st_mode & 0o077:
                        continue
            path = state_dir / _MCP_TOOLS_CACHE_FILENAME
            if not path.is_file():
                continue
            with open(path, 'rb') as f:
                data = f.read(_MCP_TOOLS_CACHE_MAX_BYTES + 1)
            if len(data) > _MCP_TOOLS_CACHE_MAX_BYTES:
                continue
            parsed = json.loads(data.decode('utf-8'))
            if isinstance(parsed, dict):
                mtime = path.stat().st_mtime
                if mtime > newest_mtime:
                    newest_cache = parsed
                    newest_mtime = mtime
        except Exception:
            continue
    return newest_cache


def _mcp_cache_entries_for_user(tools):
    username = Path.home().name
    entries = []
    for key, by_user in tools.items():
        if not isinstance(key, str) or not isinstance(by_user, dict):
            continue
        k = key.strip().lower()
        if k in _MCP_CACHE_CODING_TOOL_NAMES or k.startswith(_MCP_CACHE_CODING_TOOL_PREFIXES):
            entry = by_user.get(username)
            if isinstance(entry, dict):
                entries.append(entry)
    return entries


_CONTENT_HASH_RE = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)


def _lookup_tool_content_hash(server_name, mcp_tool, server_cfg):
    try:
        if not server_name or not mcp_tool or not isinstance(server_cfg, dict):
            return None
        cache_key = server_cfg.get('_unbound_fingerprint')
        if not isinstance(cache_key, str) or not cache_key:
            cache_key = compute_mcp_cache_key(
                name=server_name,
                command=server_cfg.get('command'),
                url=server_cfg.get('url'),
                args=server_cfg.get('args'),
                additional_data=server_cfg.get('additional_data'),
                script_hash=server_cfg.get('scriptHash'),
            )
        if not cache_key:
            return None
        tools = _read_mcp_tools_cache().get('tools')
        if not isinstance(tools, dict):
            return None
        for entry in _mcp_cache_entries_for_user(tools):
            by_tool = entry.get(cache_key)
            if not isinstance(by_tool, dict):
                continue
            content_hash = by_tool.get(mcp_tool)
            if isinstance(content_hash, str) and _CONTENT_HASH_RE.match(content_hash):
                return content_hash
        return None
    except Exception:
        return None


def _attach_tool_content_hash(metadata):
    try:
        original_cfg = metadata.get('mcp_server_config')
        server_cfg = dict(original_cfg) if isinstance(original_cfg, dict) else {}
        content_hash = _lookup_tool_content_hash(
            metadata.get('mcp_server'), metadata.get('mcp_tool'), server_cfg
        )
        server_cfg.pop('_unbound_fingerprint', None)
        if content_hash:
            server_cfg['tool_content_hash'] = content_hash
        if isinstance(original_cfg, dict) or content_hash:
            metadata['mcp_server_config'] = server_cfg
    except Exception:
        pass


# ───────────────────────── end MCP tool risk-scoring section ─────────────────


def _read_mcp_server_config(server_name, config_path):
    """
    Read an MCP server's config (url, command, args, type) from the codex
    config.toml file. Returns a dict with only the fields needed for
    fingerprinting, or None. Never includes env or headers (secrets).

    Codex uses TOML with sections like [mcp_servers.<name>] or [mcpServers.<name>].
    """
    try:
        if not config_path.exists():
            return None
        try:
            import tomllib  # Python 3.11+
            with open(config_path, 'rb') as f:
                data = tomllib.load(f)
        except ImportError:
            return _read_mcp_server_config_regex(server_name, config_path)

        servers = data.get('mcp_servers') or data.get('mcpServers')
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


def _read_mcp_server_config_regex(server_name, config_path):
    """Fallback TOML parser for Python <3.11. Handles only the keys we need."""
    import re
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        section_re = re.compile(
            r'\[mcp_?[Ss]ervers\.(?:"([^"]+)"|\'([^\']+)\'|([^\]\s]+))\][^\n]*\n(.*?)(?=\n\s*\[|\Z)',
            re.MULTILINE | re.DOTALL,
        )
        for m in section_re.finditer(content):
            name = m.group(1) or m.group(2) or m.group(3)
            if name != server_name:
                continue
            body = m.group(4)
            result = {}
            for key in ('url', 'command', 'type'):
                km = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', body, re.MULTILINE)
                if not km:
                    km = re.search(rf"^\s*{key}\s*=\s*'([^']*)'", body, re.MULTILINE)
                if km:
                    result[key] = km.group(1)
            args_match = re.search(r'^\s*args\s*=\s*\[([^\]]*)\]', body, re.MULTILINE | re.DOTALL)
            if args_match:
                items = re.findall(r'"([^"]*)"|\'([^\']*)\'', args_match.group(1))
                args = [a or b for a, b in items]
                if args:
                    result['args'] = args
            return result if result else None
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


def _decode_jwt_claims(id_token: str) -> Dict:
    try:
        segment = id_token.split('.')[1]
        padding = '=' * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(segment + padding)
        claims = json.loads(decoded.decode('utf-8'))
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def _codex_org_id(auth_claim: Dict) -> Optional[str]:
    orgs = auth_claim.get('organizations')
    if not isinstance(orgs, list) or not orgs:
        return None
    for org in orgs:
        if isinstance(org, dict) and org.get('is_default'):
            return org.get('id') or None
    first = orgs[0]
    return first.get('id') if isinstance(first, dict) else None


def read_account_identity() -> Dict:
    org_id = None
    plan = None
    auth_mode = None
    email_domain = None
    try:
        auth = json.loads(CODEX_AUTH_PATH.read_text(encoding='utf-8'))
        raw_mode = auth.get('auth_mode')
        if raw_mode == 'chatgpt':
            auth_mode = 'subscription'
        elif raw_mode == 'apikey':
            auth_mode = 'api_key'
        elif not raw_mode and auth.get('OPENAI_API_KEY'):
            auth_mode = 'api_key'

        id_token = (auth.get('tokens') or {}).get('id_token')
        if id_token:
            claims = _decode_jwt_claims(id_token)
            auth_claim = claims.get('https://api.openai.com/auth') or {}
            if isinstance(auth_claim, dict):
                org_id = _codex_org_id(auth_claim)
                plan = auth_claim.get('chatgpt_plan_type') or None
            email_domain = _email_domain(claims.get('email'))
    except Exception:
        pass
    return {
        'org_id': org_id,
        'plan': plan,
        'auth_mode': auth_mode,
        'email_domain': email_domain,
    }


def build_account_identity() -> Dict:
    return read_account_identity()


def process_pre_tool_use(event: Dict, api_key: str) -> Dict:
    """PreToolUse entry point - DO NOT LOG. The repo gate runs FIRST because _evaluate_pre_tool_use_policies short-circuits for apply_patch when no policy covers it."""
    gate = _repo_gate_evaluate(event)
    if gate:
        return transform_response_for_codex({
            'decision': 'deny',
            'reason': _repo_gate_block_reason(gate['repo']),
            'additionalContext': REPO_GATE_BLOCK_CONTEXT,
        })
    return _evaluate_pre_tool_use_policies(event, api_key)


def _evaluate_pre_tool_use_policies(event: Dict, api_key: str) -> Dict:
    """Run the gateway policy check for a PreToolUse event - DO NOT LOG."""
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

    recent_user_prompts = get_recent_user_prompts_for_session(
        session_id, PRETOOL_USER_MESSAGES_LIMIT, transcript_path
    )
    command = extract_command_for_pretool(event)

    # Build metadata with the raw event
    metadata = dict(event)

    if is_mcp:
        # Parse mcp__<server>__<tool> to extract server and tool for gateway matching
        parts = tool_name[len(MCP_TOOL_PREFIX):].split('__', 1)
        mcp_server = parts[0] if len(parts) >= 1 else ''
        metadata['mcp_server'] = mcp_server
        metadata['mcp_tool'] = parts[1] if len(parts) >= 2 else ''

        if mcp_server:
            server_cfg = _read_mcp_server_config(mcp_server, CODEX_CONFIG_PATH)
            if server_cfg:
                metadata['mcp_server_config'] = _augment_script_hash(server_cfg, metadata.get('cwd'))
            _attach_tool_content_hash(metadata)

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
        'account_identity': build_account_identity(),
        **_build_user_prompt_payload(recent_user_prompts),
    }

    request_body['pre_tool_use_data']['tool_use_id'] = (
        event.get('tool_use_id')
        or _synthetic_tool_use_id(session_id, event.get('turn_id'), tool_name, command)
    )

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
                admin_contact = marker_data.get('escalatedAdminContact', '') or ''
                if admin_contact:
                    timeout_reason = (
                        f'Blocked by organization policy. Approval request timed out — '
                        f'ask {admin_contact} to check Slack and retry the command.'
                    )
                else:
                    timeout_reason = 'Blocked by organization policy. Approval request timed out — check your Slack DMs and retry the command.'
                return transform_response_for_codex({
                    'decision': 'deny',
                    'reason': timeout_reason,
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

    _cache_policies_from_response(api_response)

    if api_response.get('decision') == 'approval_required':
        return _handle_approval_required_codex_response(api_response, approval_key)

    
    if is_mcp and api_response.get('unknown_mcp_server'):
        server_cfg = metadata.get('mcp_server_config')
        if server_cfg:
            _dispatch_mcp_server_scan(metadata.get('mcp_server', ''), server_cfg)

    return transform_response_for_codex(api_response)


def process_user_prompt_submit(event: Dict, api_key: str) -> Dict:
    """Process UserPromptSubmit event for policy checking. Also refreshes the policy cache, which is what makes the session's FIRST gated tool call enforceable: the gate never calls the network."""
    session_id = event.get('session_id')
    model = event.get('model') or 'auto'
    prompt = event.get('prompt', '')

    cache = load_policy_cache()
    need_pull_policies = cache is None or is_cache_stale(cache)

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'codex',
        'model': model,
        'event_name': 'user_prompt',
        'account_identity': build_account_identity(),
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }
    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)
    _cache_policies_from_response(api_response)
    return transform_response_for_codex_prompt(api_response)





def send_to_api(exchange: Dict, api_key: str) -> bool:
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False

    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/codex"
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


def _strip_git_suffix(segment: str) -> str:
    return segment[:-4] if segment.endswith('.git') else segment


def _github_remote_path(remote_url: str) -> Optional[str]:
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


def _git_origin_url(cwd: str) -> Optional[str]:
    """Origin's URL, else None; raises only if git cannot run, so callers fail open."""
    result = subprocess.run(
        ['git', '-C', cwd, 'remote', 'get-url', 'origin'],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _remote_host(remote_url: Optional[str]) -> Optional[str]:
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


def _get_git_origin_org_repo(cwd: str) -> tuple:
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


def _get_project(cwd: Optional[str]) -> Optional[str]:
    """Lowercased "<org>/<repo>" for `cwd`'s origin, for analytics; never raises."""
    try:
        if not cwd:
            return None
        org, repo = _get_git_origin_org_repo(cwd)
        return f"{org}/{repo}" if org and repo else None
    except Exception:
        return None


def _find_git_root(path: str) -> Optional[str]:
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


def _is_system_checkout_path(path: str) -> bool:
    try:
        normalized = os.path.normpath(path)
        return any(
            normalized == root or normalized.startswith(root + '/')
            for root in _SYSTEM_CHECKOUT_ROOTS
        )
    except Exception:
        return False
# `cd <target>` occurrences — absolute, ~-rooted, or relative — used to track
# the shell's working directory across the turn's exec_command calls.
_CD_TARGET_RE = re.compile(r'(?:^|[;&|\n]\s*|\bthen\s+|\bdo\s+)cd\s+(["\']?)([^\s"\';|&]+)\1')


# `git -C <dir>`, `--git-dir=<dir>`, `--work-tree=<dir>` retarget git at another checkout; a relative target is invisible to _ABS_PATH_RE.
_GIT_PATH_OPT_RE = re.compile(
    r'(?:^|\s)(?:-C\s*|--git-dir[=\s]|--work-tree[=\s])\s*'
    r'(?:"([^"]+)"|\'([^\']+)\'|([^\s"\';|&<>()]+))'
)


def _shell_segments(command):
    """(segment, following-separator) pairs, sliced from the original so quoted paths survive."""
    masked = _mask_quoted_runs(command)
    out, last = [], 0
    for m in _SHELL_SEGMENT_SEP_RE.finditer(masked):
        out.append((command[last:m.start()].strip(), m.group(0).strip()))
        last = m.end()
    out.append((command[last:].strip(), ''))
    # Stripped: _CD_TARGET_RE anchors on ^ or a separator, so a leading space hides the cd.
    return out


def _merge_cwds(first, second):
    """Ordered union, dropping duplicates and bounding the fan-out."""
    out = list(first)
    for c in second:
        if c not in out:
            out.append(c)
    return out[:8]


def _git_path_opt_targets(command, shell_dir):
    """Directories a git invocation redirects itself at, resolved against every cwd the shell could be in there."""
    targets = []
    try:
        cwds = [shell_dir]
        # Where control lands if the current && chain short-circuits: `a && b || c`
        # runs c when a failed (original cwd) or when b failed (a's cwd).
        fallback = [shell_dir]
        for segment, separator in _shell_segments(command):
            words = _segment_words(segment)
            # git only: `grep -C 3` is context lines, not a directory.
            if words and os.path.basename(words[0]) == 'git':
                for match in _GIT_PATH_OPT_RE.finditer(segment):
                    raw = match.group(1) or match.group(2) or match.group(3)
                    if not raw:
                        continue
                    for cwd in cwds:
                        target = os.path.expanduser(raw) if raw.startswith('~') else raw
                        if not target.startswith('/'):
                            if not cwd:
                                continue
                            target = os.path.join(cwd, target)
                        target = os.path.normpath(target)
                        if _is_system_checkout_path(target) or target in targets:
                            continue
                        targets.append(target)
            moved = [_next_shell_dir(segment, c) for c in cwds]
            if separator == '&&':
                # Next runs only if this one succeeded, so its cd took effect —
                # but this segment may instead have failed, which a later || reaches.
                fallback = _merge_cwds(fallback, cwds)
                cwds = moved
            elif separator == '||':
                # Reached because something failed, so that cd did not apply.
                cwds = _merge_cwds(cwds, fallback)
                fallback = list(cwds)
            elif separator in ('|', '&'):
                # Subshell: a cd on the left never reaches the right-hand command.
                pass
            else:
                # `;` or a newline: sequential, so the cd may or may not have taken.
                cwds = _merge_cwds(moved, cwds)
                fallback = list(cwds)
            cwds = cwds[:8]
    except Exception:
        return targets
    return targets


def _next_shell_dir(command: str, shell_dir: Optional[str]) -> Optional[str]:
    """Follow the last `cd` in `command`; unchanged on no cd or any error."""
    try:
        target = None
        for m in _CD_TARGET_RE.finditer(command):
            target = m.group(2)
        if not target:
            return shell_dir
        if target.startswith('~'):
            target = os.path.expanduser(target)
        if target.startswith('/'):
            return os.path.normpath(target)
        if target == '-':
            return shell_dir
        if shell_dir:
            return os.path.normpath(os.path.join(shell_dir, target))
        return shell_dir
    except Exception:
        return shell_dir


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


def _project_for_paths(candidates: List[Optional[str]], root_projects: Dict[str, Optional[str]]) -> Optional[str]:
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


# --- Repository-scope gate: blocks writes, git commands and shell writes in repos outside the org's allowed scope, decided on-device and fail-open ---

# Write tools, git commands and shell writes only; apply_patch is Codex's only write tool, and conversation and every other shell command (ls, cat, npm test) are ungated.
_REPO_GATE_WRITE_TOOLS = frozenset({'apply_patch'})
_REPO_GATE_SHELL_TOOLS = frozenset({'Bash'})
_REPO_GATE_TOOLS = _REPO_GATE_WRITE_TOOLS | _REPO_GATE_SHELL_TOOLS
REPO_GATE_BLOCK_CONTEXT = (
    'This action was blocked by an organization repository-scope policy. Do not '
    'attempt to achieve the same result using alternative tools, file operations, '
    'or workarounds. Inform the user and stop.'
)


def _repo_gate_command(tool_input: Optional[Dict]) -> Optional[str]:
    """The shell command a Bash call carries, in this hook's payload shape."""
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get('command')
    return command if isinstance(command, str) else None


def _repo_gate_applies(tool_name, command):
    """Whether this call is in the gate's scope: a write tool always, a shell call only when it invokes git or writes."""
    if tool_name in _REPO_GATE_SHELL_TOOLS:
        return _is_git_command(command) or _is_shell_write_command(command)
    return tool_name in _REPO_GATE_WRITE_TOOLS


def _repo_gate_block_policies(policies: Optional[List[Dict]]) -> List[Dict]:
    """Enforceable subset; a policy this hook cannot read is dropped, not guessed."""
    enforceable = []
    for policy in policies or []:
        if not isinstance(policy, dict):
            continue
        org = policy.get('github_org')
        if not isinstance(org, str) or not org.strip():
            continue
        enforceable.append(policy)
    return enforceable


def _repo_gate_scope_allows(policy: Dict, org: str, repo: str) -> bool:
    """Whether `org` matches this policy's allowed organization; both lowercased."""
    return org == policy['github_org'].strip().lower()


def _repo_gate_violating_repo(candidates: List[str], block_policies: List[Dict], root_projects: Dict[str, tuple]) -> Optional[str]:
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


def _repo_gate_candidates(tool_name: Optional[str], tool_input: Optional[Dict], cwd: Optional[str]) -> List[str]:
    """Paths a Codex call works in; apply_patch hides them in the patch body."""
    tool_input = tool_input or {}
    candidates = []
    if tool_name == 'Bash':
        command = tool_input.get('command')
        if isinstance(command, str):
            candidates.extend(
                p for p in _ABS_PATH_RE.findall(command)
                if not _is_system_checkout_path(p)
            )
            candidates.extend(_git_path_opt_targets(command, cwd))
            cwd = _next_shell_dir(command, cwd)
    else:
        try:
            blob = json.dumps(tool_input)
        except (TypeError, ValueError):
            blob = ''
        candidates.extend(
            p for p in _ABS_PATH_RE.findall(blob)
            if not _is_system_checkout_path(p)
        )
    if not candidates and cwd:
        candidates.append(cwd)
    return candidates


def _repo_gate_block_reason(repo: str) -> str:
    return (
        'Blocked by organization policy. "%s" is outside your organization\'s '
        'allowed repository scope.' % repo
    )


# --- incident reporting: telemetry only, dispatched after the verdict and never waited on ---

REPO_GATE_REPORT_MAX_CHARS = 2000
_REPO_GATE_INPUT_KEYS = ('command', 'commandLine', 'file_path', 'filePath',
                         'path', 'notebook_path')


def _repo_gate_clip(text: Optional[str]) -> Optional[str]:
    """Cap one reported string, keeping the body inside curl's pipe buffer."""
    if not isinstance(text, str) or not text:
        return None
    return text[:REPO_GATE_REPORT_MAX_CHARS]


def _repo_gate_binding_policy(block_policies: List[Dict]) -> Dict:
    """The policy the incident is filed against; every match denies alike."""
    return block_policies[0]


# Last ordinal this process handed out; the clock alone repeats under a burst.
_REPO_GATE_LAST_ORDINAL = [0]


def _repo_gate_incident_ordinal():
    """A value unique to this incident; the backend hashes it into the record's
    identity, so a repeat is read as a redelivery and dropped. The step past the
    last value is what guarantees that: the clock resolves to about a
    microsecond, which two reports of one process can share."""
    try:
        value = time.time_ns() // 1000
        if value <= _REPO_GATE_LAST_ORDINAL[0]:
            value = _REPO_GATE_LAST_ORDINAL[0] + 1
        _REPO_GATE_LAST_ORDINAL[0] = value
        return value
    except Exception:
        return None


def _repo_gate_post(body: str, api_key: str):
    """Never waited on, so the blocking path stays free of synchronous work."""
    proc = subprocess.Popen(
        ['curl', '-fsSL', '--max-time', '10', '-X', 'POST',
         '-H', 'Authorization: Bearer %s' % api_key,
         '-H', 'Content-Type: application/json',
         '--data-binary', '@-',
         '%s/v1/hooks/pretool' % UNBOUND_GATEWAY_URL],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.stdin.write(body.encode())
    proc.stdin.close()


def _repo_gate_report(gate: Optional[Dict], block_policies: List[Dict], context: Dict):
    """Report one WARN or BLOCK, fire and forget; never raises, never blocks."""
    try:
        if (gate or {}).get('decision') != 'deny':
            return
        # main() already resolved the key; the fallback covers entry points that skip it.
        api_key = _cached_api_key or os.getenv('UNBOUND_CODEX_API_KEY')
        if not api_key:
            return
        policy = _repo_gate_binding_policy(block_policies)
        # Numbers this incident within the session. It is the only field that
        # tells two incidents apart downstream, so it must advance per report.
        turn = _repo_gate_incident_ordinal()
        # What the call was about: its shell command, or the path it names.
        tool_input = context.get('tool_input')
        if isinstance(tool_input, dict):
            named = [tool_input.get(k) for k in _REPO_GATE_INPUT_KEYS]
            tool_input = next((v for v in named if isinstance(v, str) and v), None)
        # The pretool envelope every other post uses; the verdict rides under repo_gate.
        app_label = context.get('app_label')
        _repo_gate_post(json.dumps({
            'conversation_id': context.get('session_id'),
            'event_name': 'RepoGate',
            'unbound_app_label': app_label,
            'repo_gate': {
                'policy_id': policy.get('id'),
                'repository': gate.get('repo'),
                'decision': 'BLOCK',
                # Same value as the label above: the incidents page reads this one.
                'agent': app_label,
                'tool_name': context.get('tool_name'),
                # Repeats conversation_id above: the analytics row digests this one.
                'session_id': context.get('session_id'),
                'turn': turn,
                'prompt_text': _repo_gate_clip(context.get('prompt_text')),
                'tool_input': _repo_gate_clip(tool_input),
            },
        }), api_key)
    except Exception:
        pass


def _repo_gate_evaluate(event: Dict) -> Optional[Dict]:
    """Verdict for one tool call: None allows, else deny. Never raises."""
    try:
        tool_name = event.get('tool_name') or ''
        tool_input = event.get('tool_input')
        if not _repo_gate_applies(tool_name, _repo_gate_command(tool_input)):
            return None
        block_policies = _repo_gate_block_policies(get_repo_policies())
        if not block_policies:
            return None

        candidates = _repo_gate_candidates(
            tool_name, tool_input, event.get('cwd')
        )
        repo = _repo_gate_violating_repo(candidates, block_policies, {})
        gate = {'decision': 'deny', 'repo': repo} if repo else None
        _repo_gate_report(gate, block_policies, {
            'app_label': 'codex',
            'session_id': event.get('session_id'),
            'tool_name': tool_name,
            'tool_input': event.get('tool_input'),
        })
        return gate
    except Exception:
        return None


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


def _safe_skill_segment(value):
    """A path segment safe to join or glob: no traversal, no separators, no
    glob metacharacters, and nothing Windows reads as a drive or UNC root,
    which joinpath would treat as absolute and use to escape containment."""
    return bool(value) and '/' not in value and '\\' not in value \
        and '..' not in value and ':' not in value \
        and not any(ch in value for ch in '*?[')


def _resolve_skill_path(skill, cwd):
    """Absolute path of an invoked skill's SKILL.md, or None when it does not
    resolve. Requiring a real file on disk is what keeps non-skill tokens out."""
    try:
        prefix, _, name = (skill or '').rpartition(':')
        segments = prefix.split('/') if prefix else []
        if not _safe_skill_segment(name):
            return None
        if not all(_safe_skill_segment(segment) for segment in segments):
            return None
        nested = segments
        roots = []
        if cwd:
            roots = _trusted_ancestors(Path(cwd))
        roots.append(Path.home())
        for root in roots:
            for skill_dir in SKILL_SEARCH_DIRS:
                base = root.joinpath(*nested, *skill_dir)
                candidate = base / name / 'SKILL.md'
                if candidate.is_file():
                    return str(candidate)
                # Bundled skills sit one level deeper (skills/<bundle>/<name>).
                # Several bundles sharing a name is ambiguous, so resolve
                # nothing rather than attach the wrong path to a join key.
                matches = sorted(base.glob('*/%s/SKILL.md' % name))
                if len(matches) > 1:
                    return None
                if matches:
                    return str(matches[0])
        return None
    except Exception:
        return None


def _skill_tool_uses_from_prompt(prompt, cwd, session_id, stamp):
    """Skill invocations named in a prompt, as tool_use entries. This tool loads
    a skill by injecting SKILL.md into context rather than calling a tool, so
    the token in the prompt is the only signal the hook can see."""
    entries = []
    try:
        seen = set()
        for match in SKILL_INVOKE_RE.finditer(prompt or ''):
            name = match.group(1)
            if name in seen:
                continue
            seen.add(name)
            path = _resolve_skill_path(name, cwd)
            if not path:
                continue
            key = '\x1f'.join((str(session_id or ''), name, str(stamp or '')))
            entries.append({
                'type': 'PostToolUse',
                'tool_name': SKILL_TOOL_NAME,
                'tool_input': {'skill': name, 'args': ''},
                'tool_response': {},
                'tool_use_id': 'unb-' + hashlib.sha256(
                    key.encode('utf-8', 'replace')).hexdigest()[:24],
                'skill_name': name,
                'skill_path': path,
            })
    except Exception:
        return []
    return entries


def parse_codex_transcript_for_tools(transcript_path: str, user_prompt_timestamp: Optional[str] = None, session_cwd: Optional[str] = None) -> List[Dict]:
    """Parse Codex transcript for function_call/function_call_output pairs.

    Codex transcripts use response_item entries with:
    - type: 'function_call' (contains name, arguments with cmd)
    - type: 'function_call_output' (contains output)

    Converts to PostToolUse format matching Claude Code hooks for backend
    compatibility. Each entry gets a per-call `project` ("<org>/<repo>")
    resolved from the command's workdir / absolute paths / the shell dir
    tracked across the turn's `cd`s (seeded with `session_cwd`).
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
                    if user_prompt_timestamp and not _ts_lt(user_prompt_timestamp, entry_timestamp):
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

        # Match calls with outputs and convert to PostToolUse format.
        # shell_dir mirrors the persistent shell across the turn's commands
        # (seeded with the session cwd); root_projects caches origin lookups.
        shell_dir = session_cwd
        root_projects: Dict[str, Optional[str]] = {}
        for call_id, call_data in function_calls.items():
            name = call_data.get('name', '')
            args = call_data.get('arguments', {})
            output = function_outputs.get(call_id, '')

            # Map Codex function names to tool names
            # Codex currently only has exec_command (Bash). Other function names
            # are handled generically as fallback for future Codex tool support.
            if name == 'exec_command':
                tool_name = 'Bash'
                command = args.get('cmd', '')
                if isinstance(command, list):
                    command = ' '.join(str(c) for c in command)
                tool_input = {'command': command}
                # Attribute the call to the repo it ran in: explicit workdir
                # first, then absolute paths in the command, then the tracked
                # shell dir.
                candidates = []
                workdir = args.get('workdir')
                if isinstance(workdir, str) and workdir:
                    candidates.append(workdir)
                if isinstance(command, str):
                    candidates.extend(
                        p for p in _ABS_PATH_RE.findall(command) if not _is_system_checkout_path(p)
                    )
                    candidates.extend(_git_path_opt_targets(command, shell_dir))
                    shell_dir = _next_shell_dir(command, shell_dir)
                if not candidates and shell_dir:
                    candidates.append(shell_dir)
                project = _project_for_paths(candidates, root_projects)
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
                # Resolve from any absolute paths in the arguments (e.g.
                # apply_patch file paths), falling back to the shell dir.
                candidates = [
                    p for p in _ABS_PATH_RE.findall(json.dumps(tool_input)) if not _is_system_checkout_path(p)
                ]
                if not candidates and shell_dir:
                    candidates = [shell_dir]
                project = _project_for_paths(candidates, root_projects)

            tool_uses.append({
                'type': 'PostToolUse',
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_response': tool_response,
                'tool_use_id': call_id,
                'project': project
            })

    except Exception:
        pass

    return tool_uses


_CODEX_TOKEN_ALIASES = {
    'input_tokens': ('input_tokens', 'prompt_tokens', 'input'),
    'cached_input_tokens': ('cached_input_tokens', 'cache_read_input_tokens', 'cached_tokens'),
    'output_tokens': ('output_tokens', 'completion_tokens', 'output'),
}


def _codex_token(usage: Dict, field: str) -> int:
    for name in _CODEX_TOKEN_ALIASES[field]:
        value = usage.get(name)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
    return 0


_SUBAGENT_SCAN_WINDOW_SECONDS = 24 * 3600


def _codex_session_meta(transcript_path: str) -> Dict:
    """A rollout opens with a session_meta line carrying its id, the thread it was spawned
    from, and the fork time."""
    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            entry = json.loads(f.readline() or '{}')
    except (OSError, ValueError):
        return {}
    if entry.get('type') != 'session_meta':
        return {}
    payload = entry.get('payload')
    if not isinstance(payload, dict):
        return {}

    def nested(value, *keys):
        for key in keys:
            if not isinstance(value, dict):
                return {}
            value = value.get(key)
        return value if isinstance(value, dict) else {}

    # source is a plain string ("cli") on ordinary rollouts and a mapping on spawned ones,
    # where subagent is itself either a bare label ({"subagent": "review"}, carrying no
    # lineage at all) or a mapping naming the thread that spawned it.
    source = payload.get('source')
    spawn = nested(payload, 'source', 'subagent', 'thread_spawn')
    parent_id = (payload.get('forked_from_id')
                 or payload.get('parent_thread_id')
                 or spawn.get('parent_thread_id'))
    # forked_from_id is also how an ordinary `codex fork` or resume records its origin, and
    # such a session reports its own usage on its own Stop. Folding one into the parent would
    # bill it twice, so lineage counts only when the rollout also declares itself a subagent.
    is_subagent = isinstance(source, dict) and 'subagent' in source
    return {
        'id': payload.get('id'),
        'parent_id': parent_id if is_subagent and isinstance(parent_id, str) and parent_id else None,
        'forked_at': entry.get('timestamp'),
    }


def _codex_sessions_root(transcript_path: str) -> Optional[str]:
    path = os.path.abspath(transcript_path)
    while True:
        parent = os.path.dirname(path)
        if parent == path:
            break
        if os.path.basename(parent) == 'sessions':
            return parent
        path = parent
    default = Path.home() / '.codex' / 'sessions'
    return str(default) if default.is_dir() else None


def _codex_subagent_rollouts(transcript_path: str, user_prompt_timestamp: str) -> List[tuple]:
    """Rollouts this session spawned. Codex writes every subagent to its own file, so the
    parent transcript carries none of their usage."""
    session_id = _codex_session_meta(transcript_path).get('id')
    root = _codex_sessions_root(transcript_path)
    if not session_id or not root:
        return []
    parent_real = os.path.realpath(transcript_path)
    cutoff = time.time() - _SUBAGENT_SCAN_WINDOW_SECONDS
    found = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith('.jsonl'):
                continue
            path = os.path.join(dirpath, name)
            try:
                # Recency keeps the scan off historical rollouts. mtime is compared against
                # the same clock, never against a transcript timestamp, so skew cannot drop
                # a live child; the window is wide enough that only stale files are pruned.
                if os.path.realpath(path) == parent_real or os.path.getmtime(path) < cutoff:
                    continue
            except OSError:
                continue
            meta = _codex_session_meta(path)
            # A rollout that declares itself a subagent but records no lineage cannot be tied
            # to a parent by id at all. Matching it on cwd and timing instead would bill another
            # session's spend against this turn, so it is left out rather than guessed at.
            if meta.get('parent_id') != session_id:
                continue
            # Fork time does not include or exclude a child: a subagent can outlive the turn
            # that spawned it, so what matters is the spend inside this turn. It is carried
            # anyway, to bound which parent snapshots a replay may match.
            found.append((path, meta.get('forked_at')))
    return found


def _codex_snapshot_total(snapshot: Dict) -> int:
    """How far a cumulative snapshot has advanced, across every field we count."""
    return sum(_codex_token(snapshot, field) for field in _CODEX_TOKEN_ALIASES)


def _codex_same_totals(left: Dict, right: Dict) -> bool:
    """Two cumulative snapshots describing the same point in a session."""
    if not left or not right:
        return False
    return all(_codex_token(left, f) == _codex_token(right, f) for f in _CODEX_TOKEN_ALIASES)


def _codex_all_totals(transcript_path: str, until: Optional[str] = None) -> List[Dict]:
    """Every cumulative snapshot in a rollout, in file order, optionally only those at or
    before a given instant."""
    totals = []
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
            if total and not (until and _ts_lt(until, entry.get('timestamp'))):
                totals.append(total)
    return totals


def _codex_totals_around(transcript_path: str, anchor: Optional[str]) -> tuple:
    """Last cumulative snapshot at or before the anchor, and the last one after it."""
    before, after = {}, {}
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
            # Cumulative totals only: last_token_usage is a sticky snapshot re-emitted on
            # later events, so summing double-bills; estimating a turn beats over-billing it.
            total = (payload.get('info') or {}).get('total_token_usage')
            if not total:
                continue
            # An unorderable timestamp is treated as the pre-anchor baseline: a cumulative
            # snapshot we cannot place is far likelier to predate the anchor than to follow it,
            # and guessing the other way bills earlier spend against this turn.
            stamp = entry.get('timestamp')
            if _ts_key(stamp) is None or _ts_lt(stamp, anchor):
                before = total
            else:
                after = total
    return before, after


def _codex_usage_delta(before: Dict, after: Dict) -> tuple:
    def field(name):
        return max(_codex_token(after, name) - _codex_token(before, name), 0)

    input_tokens = field('input_tokens')
    # Codex input_tokens includes cached_input_tokens; clamp before subtracting so cache
    # isn't billed at the base rate and can never exceed the input it came from.
    cache_read = min(field('cached_input_tokens'), input_tokens)
    # reasoning_output_tokens is a subset of output_tokens, not an addition to it.
    return input_tokens - cache_read, field('output_tokens'), cache_read


def parse_codex_transcript_for_usage(transcript_path: str, user_prompt_timestamp: Optional[str] = None,
                                     subagent_floor: Optional[str] = None) -> Optional[Dict]:
    """Per-turn token usage via total_token_usage deltas (last_token_usage re-emits across turns; openai/codex#14489),
    plus the same delta over any subagent rollout this turn spawned."""
    if not transcript_path or not os.path.exists(transcript_path) or not user_prompt_timestamp:
        return None

    try:
        before, after = _codex_totals_around(transcript_path, user_prompt_timestamp)
        prompt, completion, cache_read = _codex_usage_delta(before, after) if after else (0, 0, 0)

        try:
            children = _codex_subagent_rollouts(transcript_path, user_prompt_timestamp)
            parent_totals = _codex_all_totals(transcript_path) if children else []
        except Exception as e:
            # The parent's own usage is already computed; never trade it for the children.
            log_error(f"subagent usage: cannot enumerate for {transcript_path}: {e}", 'usage')
            children = []
            parent_totals = []

        for child_path, forked_at in children:
            try:
                # A child opens with the parent's history replayed under the spawn instant, so
                # its own timestamps cannot separate inherited totals from new spend. The
                # baseline is taken from the parent at the fork instead, where the timestamps
                # are the parent's own and were never rewritten.
                child_totals = _codex_all_totals(child_path)
                if not child_totals:
                    continue
                # A replay is a prefix of the parent's own stream, so the inherited snapshot is
                # the last leading entry the parent also recorded. Magnitude cannot decide this:
                # a subagent that starts clean can still outspend the parent, and subtracting
                # from that one erases its work instead of isolating it.
                # parent_totals is the parent's whole stream as of this Stop and snapshots are
                # only ever appended, so it is a superset of anything the child could have
                # replayed: a leading entry matching nothing was never replayed.
                # Only snapshots the parent had reached by the fork can have been replayed.
                # Matching against later ones lets a child's own total coincide with a parent
                # total it never inherited, which would subtract spend the child really made.
                replayable = _codex_all_totals(transcript_path, until=forked_at) if forked_at else parent_totals
                inherited = {}
                for total in child_totals:
                    if not any(_codex_same_totals(total, seen) for seen in replayable):
                        break
                    inherited = total
                # Spend already uploaded is excluded by the child's own snapshot at the floor,
                # which is the previous Stop rather than this turn's prompt so that work
                # finishing between the two is still counted once. Cumulative totals only
                # climb, so the larger of the two lower bounds is the tighter one, and a child
                # that finished before the floor lands on its final total and adds nothing.
                at_anchor, _ = _codex_totals_around(child_path, subagent_floor or user_prompt_timestamp)
                # Compared across every counted field, not input alone: a snapshot can advance
                # on output or cache with input unchanged, and picking the looser bound then
                # re-adds spend the previous Stop already uploaded.
                if _codex_snapshot_total(at_anchor) > _codex_snapshot_total(inherited):
                    inherited = at_anchor
                child = _codex_usage_delta(inherited, child_totals[-1])
            except Exception as e:
                log_error(f"subagent usage: failed reading {child_path}: {e}", 'usage')
                continue
            prompt += child[0]
            completion += child[1]
            cache_read += child[2]
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
    submitted_prompts = []
    stop_timestamp = None
    previous_stop = None

    for log in logs:
        log_session_id = log.get('session_id') or log.get('event', {}).get('session_id')

        if log_session_id == session_id:
            log_event = log.get('event', {}) if 'event' in log else log
            event_name = log_event.get('hook_event_name')

            if event_name == 'UserPromptSubmit':
                # A spawned subagent's delegated prompt is reported under the parent's session
                # id and would otherwise be taken for the user's, pairing the child's
                # instructions with the parent's reply and anchoring the turn at the spawn.
                if log_event.get('agent_id'):
                    continue
                prompt_text = log_event.get('prompt')
                if prompt_text:
                    submitted_prompts.append((log.get('timestamp'), prompt_text))
                permission_mode = log_event.get('permission_mode', 'default')
            elif event_name == 'Stop':
                # This Stop is already logged, so the one before it marks how far the last
                # upload reported. Subagent work landing between the two belongs to nobody
                # otherwise, and a subagent routinely outlives the turn that spawned it.
                previous_stop = stop_timestamp
                stop_timestamp = log.get('timestamp')

    # Codex closes one turn for every prompt typed while it was still working, so a turn can
    # carry more than one. Keeping only the last drops what the user actually asked first, and
    # anchoring on it would start the token window after work already done.
    turn_prompts = [(ts, text) for ts, text in submitted_prompts
                    if not previous_stop or not _ts_lt(ts, previous_stop)]
    if not turn_prompts:
        turn_prompts = submitted_prompts[-1:]
    if turn_prompts:
        user_prompt_timestamp = turn_prompts[0][0]
        user_prompt = '\n\n'.join(text for _, text in turn_prompts)

    if not user_prompt:
        return

    # One message, not one per prompt: the backend keeps the last user message, so several
    # would silently discard everything the user typed before the final one.
    messages = [{'role': 'user', 'content': user_prompt}]

    # Parse tool uses from Codex transcript (function_call/function_call_output
    # pairs); the session cwd seeds shell-dir tracking for per-call project
    # attribution.
    cwd = event.get('cwd')
    assistant_tool_uses = parse_codex_transcript_for_tools(transcript_path, user_prompt_timestamp, session_cwd=cwd)

    assistant_tool_uses.extend(
        _skill_tool_uses_from_prompt(user_prompt, cwd, session_id, user_prompt_timestamp))

    for item in assistant_tool_uses:
        if not item.get('tool_use_id'):
            item['tool_use_id'] = _synthetic_tool_use_id(
                session_id, event.get('turn_id'), item.get('tool_name'),
                extract_command_for_pretool({'tool_name': item.get('tool_name'),
                                             'tool_input': item.get('tool_input') or {}}))

    assistant_msg = {
        'role': 'assistant',
        'content': last_assistant_message or ''
    }
    if assistant_tool_uses:
        assistant_msg['tool_use'] = assistant_tool_uses
    messages.append(assistant_msg)

    # Stop event's logged time, not processing time
    request_completed = stop_timestamp or datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    exchange = {
        'conversation_id': session_id or 'unknown',
        'model': event.get('model', 'auto'),
        'messages': messages,
        'permission_mode': permission_mode or 'default',
        'cwd': cwd,
        # Turn-level fallback: rows without a per-call project (the user
        # prompt row, or tool-less turns) inherit the session cwd's repo.
        'project': _get_project(cwd)
    }

    usage = parse_codex_transcript_for_usage(transcript_path, user_prompt_timestamp,
                                             subagent_floor=previous_stop)
    if usage:
        exchange['usage'] = usage

    if user_prompt_timestamp:
        exchange['requestInitialized'] = user_prompt_timestamp
    # always set (stop_timestamp or now-fallback)
    exchange['requestCompleted'] = request_completed

    # Exact per-turn id for deterministic idempotency (vs a content hash).
    turn_id = event.get('turn_id')
    if turn_id:
        exchange['turn_request_id'] = turn_id

    send_to_api(exchange, api_key)


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


def _is_windows() -> bool:
    return os.name == "nt"


def _discovery_installer():
    if _is_windows():
        return DISCOVERY_INSTALL_PS1, DISCOVERY_INSTALL_PS1_URL
    return DISCOVERY_INSTALL_SH, DISCOVERY_INSTALL_URL


def _discovery_command(installer_path: Path, backend_url: str):
    if _is_windows():
        return [
            "powershell", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(installer_path),
        ]
    return ["bash", str(installer_path), "--domain", backend_url]


def _discovery_installer_is_stale(installer_path: Path) -> bool:
    try:
        return (time.time() - installer_path.stat().st_mtime) > DISCOVERY_INSTALL_SH_TTL_SECONDS
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
                    "UNBOUND_CODING_TOOL": _UNBOUND_CODING_TOOL,
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
                installer_path, installer_url = _discovery_installer()
                DISCOVERY_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
                if _discovery_installer_is_stale(installer_path):
                    fd, _tmp = tempfile.mkstemp(dir=DISCOVERY_INSTALL_DIR, prefix="install.", suffix=".tmp")
                    os.close(fd)
                    tmp = Path(_tmp)
                    r = subprocess.run(
                        ["curl", "-fsSL", "-o", str(tmp), installer_url],
                        capture_output=True, timeout=30,
                    )
                    if r.returncode == 0:
                        if not _is_windows():
                            os.chmod(tmp, 0o755)
                        os.replace(tmp, installer_path)
                    else:
                        tmp.unlink(missing_ok=True)
                        if not installer_path.exists():
                            log_error(f"discovery {installer_path.name} download failed: {r.stderr.decode(errors='replace')[:200]}", 'discovery_gate')
                            return
                        log_error(f"discovery {installer_path.name} refresh failed; using cached copy: {r.stderr.decode(errors='replace')[:200]}", 'discovery_gate')
                discovery_cmd = _discovery_command(installer_path, backend_url)

            # api_key goes via env so it never appears in argv / /proc/<pid>/cmdline.
            popen_kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                            "stdin": subprocess.DEVNULL, "close_fds": True,
                            "env": {**os.environ, "UNBOUND_API_KEY": api_key,
                                    "UNBOUND_DOMAIN": backend_url}}
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
    api_key = os.getenv('UNBOUND_CODEX_API_KEY')
    _cached_api_key = api_key

    try:
        input_data = sys.stdin.read().strip()

        if not input_data:
            print('{}', flush=True)
            return

        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            print('{}', flush=True)
            return

        hook_event_name = event.get('hook_event_name')

        # SessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if hook_event_name == "SessionStart":
            _check_self_update()
            _dispatch_discovery()
            print("{}")
            return
        session_id = event.get('session_id')

        # Handle PreToolUse - return immediately after decision is made
        if hook_event_name == 'PreToolUse':
            response = process_pre_tool_use(event, api_key)
            print(json.dumps(response), flush=True)
            return

        # Handle UserPromptSubmit - check policy before processing
        if hook_event_name == 'UserPromptSubmit':
            # No repo gate here: conversation is never gated, but this call refreshes the policy cache so the session's first gated TOOL call is enforceable.
            response = process_user_prompt_submit(event, api_key)

            # If denied (response has decision: block), log the event then return
            if response.get('decision') == 'block':
                append_to_audit_log({
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'session_id': event.get('session_id'),
                    'event': event
                })
                print(json.dumps(response), flush=True)
                return

            # Allowed but with hook output to emit (e.g. the spend-limit
            # alert-threshold warning riding additionalContext/systemMessage):
            # log the event, then print the response so Codex surfaces the warning.
            if response:
                append_to_audit_log({
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'session_id': event.get('session_id'),
                    'event': event
                })
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

        # Codex parses suppressOutput but does not implement it, and PostToolUse reports it as
        # unsupported and marks the hook failed. An empty object is accepted on every event.
        print('{}', flush=True)

    except Exception as e:
        # Still acknowledge so Codex sees the hook complete.
        log_error(f"Exception in main: {str(e)}", 'general')
        print('{}', flush=True)


if __name__ == '__main__':
    main()
