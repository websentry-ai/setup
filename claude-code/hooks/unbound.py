#!/usr/bin/env python3

import sys
import base64
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
from urllib.parse import urlparse


UNBOUND_GATEWAY_URL = os.environ.get(
    "UNBOUND_GATEWAY_URL", "https://api.getunbound.ai"
).rstrip("/")
AUDIT_LOG = Path.home() / ".claude" / "hooks" / "agent-audit.log"
ERROR_LOG = Path.home() / ".claude" / "hooks" / "error.log"
LAST_REPORT_FILE = Path.home() / ".claude" / "hooks" / ".last_error_report"
ALLOWED_NON_MCP_HOOK_NAMES = ['Bash', 'Read', 'Write', 'Edit']  # MCP tools (mcp__*) are always checked separately
NATIVE_FILE_TOOLS = {'Read', 'Write', 'Edit'}
MCP_TOOL_PREFIX = 'mcp__'
# INVARIANT: every skill entry below carries a tool_use_id - the native one
# when the tool reports it, otherwise a deterministic synthetic one. The backend
# relies on this: two id-less invocations of one skill with the same arguments
# are byte-identical, so nothing can tell a replay from a genuine repeat.
SKILL_TOOL_NAME = 'Skill'
SKILL_SEARCH_DIRS = (('.claude', 'skills'),)

# CoWork built-in tools that are exposed under mcp__
COWORK_BUILTIN_MCP_SERVERS = frozenset({
    'workspace', 'cowork', 'cowork-onboarding', 'visualize',
    'scheduled-tasks', 'plugins', 'mcp-registry', 'session_info', 'skills',
})

# CLAUDE_CONFIG_DIR relocates .claude.json entirely; read the file Claude uses.
CLAUDE_MCP_CONFIG_PATH = (
    Path(os.environ['CLAUDE_CONFIG_DIR']) / '.claude.json'
    if os.environ.get('CLAUDE_CONFIG_DIR')
    else Path.home() / '.claude.json'
)
CLAUDE_PLUGIN_CACHE_DIR = Path.home() / ".claude" / "plugins" / "cache"
POLICY_CACHE_FILE = Path.home() / ".claude" / "hooks" / ".policy_cache.json"
CACHE_TTL_SECONDS = 300
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

MCP_DIAG_STAMP_DIR = Path.home() / ".unbound" / "mcp-diag"
MCP_DIAG_COOLDOWN_SECONDS = 6 * 3600
MCP_DIAG_VERSION = "v3"
MCP_DIAG_MAX_REPORT_CHARS = 200 * 1024  # stay well under the gateway's 256KB cap
_DIAG_CLAUDE_DIR = Path(os.environ.get('CLAUDE_CONFIG_DIR') or (Path.home() / '.claude'))

_cached_api_key = None
_reporting_error = False
_suppress_error_logging = False


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
    if _suppress_error_logging:
        return
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


_USAGE_FIELDS = ('input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens')


def _ts_lt(earlier, later) -> bool:
    """Timestamp ordering that tolerates a non-string timestamp. Only strings are ordered, so
    a format change can never raise here and discard a turn; an unorderable entry is excluded
    by every caller rather than re-folded on each later Stop."""
    return isinstance(earlier, str) and isinstance(later, str) and earlier < later


def _cache_creation_tokens(usage: Dict) -> int:
    """Cache-creation is reported either as a flat count or split across ephemeral TTLs."""
    block = usage.get('cache_creation')
    if isinstance(block, dict):
        total = 0
        for k in ('ephemeral_5m_input_tokens', 'ephemeral_1h_input_tokens'):
            try:
                total += int(block.get(k) or 0)
            except (TypeError, ValueError):
                pass
        return total
    try:
        return int(usage.get('cache_creation_input_tokens') or 0)
    except (TypeError, ValueError):
        return 0


def _usage_value(usage: Dict, field: str) -> int:
    if field == 'cache_creation_input_tokens':
        return _cache_creation_tokens(usage)
    try:
        return int(usage.get(field) or 0)
    except (TypeError, ValueError):
        return 0


def _usage_total(usage: Dict) -> int:
    return sum(_usage_value(usage, k) for k in _USAGE_FIELDS)


def _advisor_usages(message: Dict) -> List[Dict]:
    """Advisor turns ride inside usage.iterations as flattened token blocks under their own
    model. Iterations of type 'message' are already inside the top-level usage."""
    usage = message.get('usage')
    if not isinstance(usage, dict):
        return []
    iterations = usage.get('iterations')
    if not isinstance(iterations, list):
        return []
    return [
        it for it in iterations
        if isinstance(it, dict) and it.get('type') == 'advisor_message' and it.get('model')
    ]


def _agent_progress_entry(entry: Dict) -> Optional[Dict]:
    """Agent-progress lines wrap the assistant record one level deeper, so the outer type is
    not 'assistant'. The wrapper also carries user and tool-result records, which have no
    role either, so the inner usage block is what identifies a model response."""
    data = entry.get('data')
    inner = data.get('message') if isinstance(data, dict) else None
    if not isinstance(inner, dict):
        return None
    message = inner.get('message')
    if isinstance(message, dict) and isinstance(message.get('usage'), dict):
        return inner
    return None


def _record_usage(entry: Dict, message: Dict, usage_by_key: Dict) -> None:
    """Store a message's usage keyed by message.id. Claude Code writes the same assistant
    message as several streamed lines, and a replay can carry a new requestId, so the id
    alone is the identity. Prefer the non-sidechain line, then the highest total (the
    completed message, whose output has finished growing). Mirrors ccusage's dedup.
    Entries without an id are kept individually."""
    msg_usage = message.get('usage')
    sidechain = entry.get('isSidechain') is True
    mid = message.get('id')

    if isinstance(msg_usage, dict) and msg_usage:
        _keep_usage(usage_by_key, mid or ('', len(usage_by_key)), msg_usage, sidechain)

    for index, advisor in enumerate(_advisor_usages(message)):
        key = (mid, 'advisor', index) if mid else ('', len(usage_by_key))
        _keep_usage(usage_by_key, key, advisor, sidechain)


def _keep_usage(usage_by_key: Dict, key, msg_usage: Dict, sidechain: bool) -> None:
    prev = usage_by_key.get(key)
    if prev is None:
        usage_by_key[key] = (msg_usage, sidechain)
        return
    prev_usage, prev_sidechain = prev
    if sidechain != prev_sidechain:
        if prev_sidechain:
            usage_by_key[key] = (msg_usage, sidechain)
        return
    if _usage_total(msg_usage) > _usage_total(prev_usage):
        usage_by_key[key] = (msg_usage, sidechain)


def _subagent_dir(transcript_path: str) -> Optional[str]:
    """subagents/ sits beside the session's JSONL: under {session}/ in the flat layout,
    alongside the transcript in the nested one."""
    for candidate in (os.path.join(os.path.splitext(transcript_path)[0], 'subagents'),
                      os.path.join(os.path.dirname(transcript_path), 'subagents')):
        if os.path.isdir(candidate):
            return candidate
    return None


def _fold_subagent_usage(transcript_path: str, user_prompt_timestamp: Optional[str], usage_by_key: Dict) -> None:
    """Fold subagent (Task) usage into usage_by_key. Subagent turns are written to a
    subagents/ dir, never the main transcript the Stop event points at, so their tokens
    would otherwise be dropped. Same per-turn scope + dedup."""
    try:
        subdir = _subagent_dir(transcript_path)
        names = []
        if subdir:
            for root, _dirs, files in os.walk(subdir):
                names.extend(os.path.join(root, n) for n in files if n.endswith('.jsonl'))
    except Exception as e:
        log_error(f"subagent usage: cannot list dir for {transcript_path}: {e}", 'usage')
        return
    for name in names:
        try:
            with open(name, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    progress = _agent_progress_entry(entry)
                    entry = progress or entry
                    if progress is None and entry.get('type') != 'assistant':
                        continue
                    ts = entry.get('timestamp')
                    # exclude a timestamp-less entry when scoping, else it re-folds every later Stop
                    if user_prompt_timestamp and not _ts_lt(user_prompt_timestamp, ts):
                        continue
                    _record_usage(entry, entry.get('message') or {}, usage_by_key)
        except Exception as e:
            log_error(f"subagent usage: failed reading {name}: {e}", 'usage')
            continue


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


def parse_transcript_file(transcript_path: str, user_prompt_timestamp: Optional[str] = None, include_usage: bool = True) -> Dict:
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
    usage_by_key: Dict = {}
    turn_model = None  # model that handled this turn; user_prompt_timestamp filter guarantees only this turn's lines are scanned

    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)
                    progress = _agent_progress_entry(entry)
                    if progress is not None:
                        entry = progress
                    entry_type = 'assistant' if progress is not None else entry.get('type', '')
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
                        # Agent-progress records carry usage without a role field.
                        if message.get('role') == 'assistant' or progress is not None:
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

                            if include_usage:
                                _record_usage(entry, message, usage_by_key)

                except json.JSONDecodeError:
                    continue

    except Exception:
        pass

    if include_usage:
        try:
            _fold_subagent_usage(transcript_path, user_prompt_timestamp, usage_by_key)
            for msg_usage, _ in usage_by_key.values():
                for k in usage:
                    usage[k] += _usage_value(msg_usage, k)
        except Exception as e:
            log_error(f"usage aggregation failed for {transcript_path}: {e}", 'usage')

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
        data = parse_transcript_file(transcript_path, include_usage=False)
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


def _synthetic_tool_use_id(event: Dict) -> str:
    """Deterministic per-call id from replay-stable fields, so the SAME tool call
    yields the SAME id in the PreToolUse and PostToolUse emits with no shared state.
    Prefixed 'unb-' so it can never collide with a native tool_use_id. Keyed only on
    fields guaranteed on BOTH events (session + tool + command); prompt_id is omitted
    because it is not guaranteed on PostToolUse and would fork the id. MCP input is
    canonicalized (sort_keys) so key-order variance can't diverge pre from post."""
    content = extract_command_for_pretool(event)
    try:
        content = json.dumps(json.loads(content), sort_keys=True)
    except (ValueError, TypeError):
        pass
    key = '\x1f'.join((
        str(event.get('session_id') or ''),
        str(event.get('tool_name') or ''),
        str(content),
    ))
    return 'unb-' + hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:24]


def resolve_tool_use_id(event: Dict) -> str:
    """Native tool_use_id when the tool provides one, else a deterministic synthetic
    id. Every tool call gets a stable id so the backend dedups by id; the synthetic
    path is content-derived, so a pre command re-appearing in post gets the SAME id."""
    return event.get('tool_use_id') or _synthetic_tool_use_id(event)


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
            'hookSpecificOutput': {
                'hookEventName': 'UserPromptSubmit',
                'suppressOriginalPrompt': True,
            },
        }

    # Allowed with injected context (e.g. the spend-limit alert-threshold
    # warning "you've used $X of your $Y limit"): additionalContext feeds it
    # to the model, systemMessage shows the same text to the user.
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


def _norm_mcp_token(s: Optional[str]) -> str:
    return re.sub(r'_+', '_', s or '').strip('_')


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
        # Some plugins ship an unwrapped .mcp.json (server map at the root, no
        # "mcpServers" wrapper); accept it, trusting only real server entries.
        if mcp_servers is None and source.name == '.mcp.json':
            root_map = {
                key: entry
                for key, entry in data.items()
                if isinstance(entry, dict)
                and (isinstance(entry.get('command'), str) or isinstance(entry.get('url'), str))
            }
            if root_map:
                mcp_servers = root_map
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


def _read_json_file(path: Path):
    try:
        if path.is_file():
            with open(path, 'r', encoding='utf-8') as f:
                return json.loads(f.read())
    except Exception as exc:
        log_error(f"mcp plugin registry unreadable: {path}: {exc}", 'mcp_plugin')
    return None


def _installed_plugins_registry(plugins_root: Path) -> Dict:
    data = _read_json_file(plugins_root / "installed_plugins.json")
    plugins = data.get("plugins") if isinstance(data, dict) else None
    return plugins if isinstance(plugins, dict) else {}


def _marketplace_registry(plugins_root: Path) -> Dict:
    data = _read_json_file(plugins_root / "known_marketplaces.json")
    return data if isinstance(data, dict) else {}


def _directory_marketplace_plugin_dir(location: Path, plugin: str) -> Optional[Path]:
    manifest = _read_json_file(location / ".claude-plugin" / "marketplace.json")
    if not isinstance(manifest, dict):
        return None
    for entry in (manifest.get("plugins") or []):
        if not isinstance(entry, dict) or entry.get("name") != plugin:
            continue
        src = entry.get("source")
        rel = src if isinstance(src, str) else (src.get("path") if isinstance(src, dict) else None)
        if not isinstance(rel, str) or not rel:
            return None
        cand = (location / rel).resolve()
        try:
            cand.relative_to(location.resolve())
        except ValueError:
            return None
        return cand
    return None


def _authoritative_plugin_dirs(plugin: str, mk_info: Dict, installed_entries: list) -> list:
    dirs = []
    source = mk_info.get("source") if isinstance(mk_info, dict) else None
    src_type = source.get("source") if isinstance(source, dict) else None
    install_location = mk_info.get("installLocation") if isinstance(mk_info, dict) else None

    if src_type == "directory" and install_location:
        loc = Path(install_location)
        for d in (loc / "plugins" / plugin, loc / plugin, _directory_marketplace_plugin_dir(loc, plugin)):
            if d is not None and d not in dirs:
                dirs.append(d)

    for e in (installed_entries or []):
        ip = e.get("installPath") if isinstance(e, dict) else None
        if ip:
            p = Path(ip)
            if p not in dirs:
                dirs.append(p)
    return dirs


def _resolve_plugin_mcp_config(server_name: str, cache_dir: Path = CLAUDE_PLUGIN_CACHE_DIR) -> Optional[Dict]:
    if not server_name.startswith('plugin_'):
        return None
    try:
        plugins_root = cache_dir.parent
        installed = _installed_plugins_registry(plugins_root)
        if not installed:
            return _resolve_plugin_mcp_config_from_cache(server_name, cache_dir)
        marketplaces = _marketplace_registry(plugins_root)

        matches = []
        for full_name, entries in installed.items():
            plugin, _, marketplace = full_name.partition('@')
            if not server_name.startswith("plugin_%s_" % _mangle_mcp_token(plugin)):
                continue
            mk_info = marketplaces.get(marketplace) or {}
            for plugin_dir in _authoritative_plugin_dirs(plugin, mk_info, entries):
                try:
                    server_map = _plugin_mcp_server_map(plugin_dir)
                except Exception as exc:
                    log_error(f"mcp plugin dir error: {plugin_dir}: {exc}", 'mcp_plugin')
                    continue
                dir_matches = []
                for server_key, entry in server_map.items():
                    if "plugin_%s_%s" % (_mangle_mcp_token(plugin), _mangle_mcp_token(server_key)) != server_name:
                        continue
                    fields = _extract_mcp_server_fields(entry)
                    if fields is not None:
                        dir_matches.append(fields)
                if not dir_matches:
                    # Server not defined here -> try the next candidate dir.
                    continue
                matches.extend(dir_matches)
                # First candidate dir that defines the server is authoritative.
                break

        distinct = []
        for cfg in matches:
            if cfg not in distinct:
                distinct.append(cfg)
        if len(distinct) == 1:
            return distinct[0]
        if len(distinct) > 1:
            log_error(f"mcp plugin resolve ambiguous: {server_name}", 'mcp_plugin')
            return None
        return _resolve_plugin_mcp_config_from_cache(server_name, cache_dir)
    except Exception as exc:
        log_error(f"mcp plugin resolve error: {server_name}: {exc}", 'mcp_plugin')
        return None


def _resolve_plugin_mcp_config_from_cache(server_name: str, cache_dir: Path = CLAUDE_PLUGIN_CACHE_DIR) -> Optional[Dict]:
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


def _plugin_dir_roots(path: Path) -> list:
    # A --plugin-dir is either a plugin root itself or a directory of plugin roots.
    try:
        if not path.is_dir():
            return []
        if (path / ".claude-plugin" / "plugin.json").is_file() or (path / ".mcp.json").is_file():
            return [path]
        return [d for d in path.iterdir() if d.is_dir()]
    except Exception:
        return []


def _redact_url(url: str) -> str:
    """Scheme + host[:port] + path only: strips userinfo, query, and fragment.
    Anything that doesn't parse as scheme://host (e.g. 'user:pass@host', where
    urlparse mistakes 'user' for the scheme) redacts to a placeholder instead."""
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return '<unparseable-url>'
        host = p.hostname or ''
        if p.port:
            host = '%s:%d' % (host, p.port)
        return '%s://%s%s' % (p.scheme, host, p.path)
    except Exception:
        return '<unparseable-url>'


def _match_server_key_suffix(plugin_dir: Path, unprefixed_name: str) -> list:
    """Configs in plugin_dir whose mangled server key is unprefixed_name's suffix; [] on error."""
    try:
        server_map = _plugin_mcp_server_map(plugin_dir)
    except Exception as exc:
        log_error(f"mcp plugin dir error: {plugin_dir}: {exc}", 'mcp_plugin')
        return []
    matches = []
    for server_key, entry in server_map.items():
        suffix = '_' + _mangle_mcp_token(server_key)
        if len(suffix) < 2 or not unprefixed_name.endswith(suffix):
            continue
        # All-digit plugin half only (the rename pattern); blocks partial-segment binds.
        if not unprefixed_name[:-len(suffix)].isdigit():
            continue
        fields = _extract_mcp_server_fields(entry)
        if fields is not None:
            matches.append(fields)
    return matches


def _match_exact_identity(plugin_dir: Path, server_name: str) -> list:
    """Configs where dir basename + server key reconstruct server_name exactly.
    This is Claude Code's own manifest-less naming (name = basename(dir)), so a
    hit is verified identity, not a guess; [] on error or no reconstruction."""
    prefix = 'plugin_%s_' % _mangle_mcp_token(plugin_dir.name)
    if not server_name.startswith(prefix):
        return []
    try:
        server_map = _plugin_mcp_server_map(plugin_dir)
    except Exception as exc:
        log_error(f"mcp plugin dir error: {plugin_dir}: {exc}", 'mcp_plugin')
        return []
    matches = []
    for server_key, entry in server_map.items():
        if server_name == prefix + _mangle_mcp_token(server_key):
            fields = _extract_mcp_server_fields(entry)
            if fields is not None:
                matches.append(fields)
    return matches


def _resolve_plugin_mcp_config_by_server_key(server_name: str, cache_dir: Path = CLAUDE_PLUGIN_CACHE_DIR,
                                             extra_dirs: Optional[list] = None,
                                             allow_suffix_guess: bool = True) -> Optional[Dict]:
    """Last resort for opaque plugin IDs (e.g. plugin_1693077056_toolchain).
    Stage 1 (always): exact identity -- a dir whose basename + server key
    reconstruct the full name; verified, so safe alongside --plugin-url.
    Stage 2 (allow_suffix_guess only): match the mangled server-key SUFFIX with
    an all-digit plugin half, in authority tiers mirroring the prefix resolver
    (registry dirs incl. live marketplace paths, then cache tree, then
    --plugin-dir roots); first tier with a match decides, first dir defining
    the key wins within a plugin. Ambiguity (distinct configs) -> None."""
    if not server_name.startswith('plugin_'):
        return None
    try:
        unprefixed_name = server_name[len('plugin_'):]
        plugins_root = cache_dir.parent
        seen_dirs = set()

        registry_dir_groups = []
        marketplaces = _marketplace_registry(plugins_root)
        for full_name, entries in _installed_plugins_registry(plugins_root).items():
            plugin, _, marketplace = full_name.partition('@')
            dirs = []
            for d in _authoritative_plugin_dirs(plugin, marketplaces.get(marketplace) or {}, entries):
                if d not in seen_dirs:
                    seen_dirs.add(d)
                    dirs.append(d)
            if dirs:
                registry_dir_groups.append(dirs)

        extra_roots = []
        for extra in (extra_dirs or []):
            for root in _plugin_dir_roots(Path(extra)):
                if root not in seen_dirs:
                    seen_dirs.add(root)
                    extra_roots.append(root)

        # Cache tree excluded: its dirs are version-named, so exact reconstruction can't match there.
        exact = []
        for d in [d for dirs in registry_dir_groups for d in dirs] + extra_roots:
            exact.extend(_match_exact_identity(d, server_name))
        distinct = []
        for cfg in exact:
            if cfg not in distinct:
                distinct.append(cfg)
        if len(distinct) == 1:
            return distinct[0]
        if len(distinct) > 1:
            log_error(f"mcp plugin exact resolve ambiguous: {server_name}", 'mcp_plugin')
            return None

        if not allow_suffix_guess:
            # --plugin-url plugins have no verifiable local files: never guess for them.
            log_error(f"mcp plugin suffix guess disabled (--plugin-url present): {server_name}", 'mcp_plugin')
            return None

        registry_matches = []
        for dirs in registry_dir_groups:
            for d in dirs:
                found = _match_server_key_suffix(d, unprefixed_name)
                if found:
                    registry_matches.extend(found)
                    break  # first dir defining the key is authoritative for this plugin

        cache_matches = []
        if cache_dir.is_dir():
            for marketplace_dir in cache_dir.iterdir():
                if not marketplace_dir.is_dir():
                    continue
                for plugin_dir in marketplace_dir.iterdir():
                    if not plugin_dir.is_dir():
                        continue
                    try:
                        version_dir = _select_plugin_version_dir(plugin_dir)
                    except Exception:
                        continue
                    if version_dir is None or version_dir in seen_dirs:
                        continue
                    seen_dirs.add(version_dir)
                    cache_matches.extend(_match_server_key_suffix(version_dir, unprefixed_name))

        extra_matches = []
        for root in extra_roots:
            extra_matches.extend(_match_server_key_suffix(root, unprefixed_name))

        for matches in (registry_matches, cache_matches, extra_matches):
            if not matches:
                continue
            distinct = []
            for cfg in matches:
                if cfg not in distinct:
                    distinct.append(cfg)
            if len(distinct) == 1:
                return distinct[0]
            log_error(f"mcp plugin suffix resolve ambiguous: {server_name}", 'mcp_plugin')
            return None
        log_error(f"mcp plugin suffix resolve miss: {server_name}", 'mcp_plugin')
        return None
    except Exception as exc:
        log_error(f"mcp plugin suffix resolve error: {server_name}: {exc}", 'mcp_plugin')
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
                if isinstance(display, str) and _norm_mcp_token(_mangle_mcp_token(display)) == _norm_mcp_token(server_name):
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


_CLAUDE_SESSION_SUBDIRS = ('claude-code-sessions', 'local-agent-mode-sessions')


def _claude_session_dirs() -> list:
    try:
        home = Path.home()
        if sys.platform == 'darwin':
            base = home / 'Library' / 'Application Support' / 'Claude'
        elif sys.platform.startswith('win'):
            appdata = os.environ.get('APPDATA')
            if not appdata:
                return []
            base = Path(appdata) / 'Claude'
        else:
            base = home / '.config' / 'Claude'
        return [base / sub for sub in _CLAUDE_SESSION_SUBDIRS]
    except Exception:
        return []


_HOOK_SCRIPT_RUNTIMES = {
    'node', 'nodejs', 'bun', 'deno', 'python', 'python2', 'python3', 'py',
    'ruby', 'dart', 'php', 'perl', 'rscript',
}
_HOOK_SCRIPT_EXT_RE = re.compile(r'\.(sh|py|js|cjs|mjs|ts|tsx|rb|php|dart)$', re.IGNORECASE)
_HOOK_RUNNER_SUBTOKENS = {'run', 'tsx', 'ts-node'}


def _hook_command_basename(command: str) -> str:
    base = re.split(r'[\\/]', (command or '').strip())[-1]
    return re.sub(r'\.(exe|cmd|bat|com)$', '', base.lower())


def _hook_looks_like_path(value: str) -> bool:
    v = (value or '').strip().strip('"\'')
    if v.startswith(('http://', 'https://', '@', 'git+')):
        return False
    # Only treat an arg as a local script if it has a recognised script
    # extension. Previously any '/'-containing arg matched, which let a crafted
    # runtime config (e.g. `python3 /etc/passwd`) read arbitrary non-script files.
    return bool(_HOOK_SCRIPT_EXT_RE.search(v))


def _hook_candidate_script(command: Optional[str], args: Optional[List]) -> Optional[str]:
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


def _compute_script_hash(command: Optional[str], args: Optional[List], cwd: Optional[str]) -> Optional[str]:
    """sha256 of the local script's contents, or None when it isn't a resolvable
    local script. Matches what the backend recomputes from the uploaded body, so
    the gateway's `script:<hash>` lookup lines up with the stored fingerprint."""
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
        # Hash at most _HOOK_MAX_SCRIPT_BYTES so the gateway's scriptHash matches
        # the bytes the backend re-hashes from the (same-capped) uploaded body.
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


def _session_file_created_at(path) -> float:
    try:
        st = path.stat()
        return getattr(st, 'st_birthtime', None) or st.st_mtime
    except Exception:
        return 0.0


def _resolve_claude_code_session_connector(server_uuid: str) -> Optional[tuple]:
    if not _is_uuid(server_uuid):
        return None
    try:
        latest = None
        latest_ts = -1.0
        for base in _claude_session_dirs():
            if not base or not base.exists():
                continue
            try:
                candidates = base.glob('*/*/local_*.json')
            except Exception:
                continue
            for f in candidates:
                ts = _session_file_created_at(f)
                if ts > latest_ts:
                    latest_ts, latest = ts, f
        if latest is None:
            return None
        try:
            data = json.loads(latest.read_text(encoding='utf-8'))
        except Exception:
            return None
        for entry in (data.get('remoteMcpServersConfig') or []):
            if isinstance(entry, dict) and (entry.get('uuid') or '').lower() == server_uuid.lower():
                name = entry.get('name')
                if not name:
                    continue
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


def _augment_script_hash(result: Optional[Dict], cwd: Optional[str]) -> Optional[Dict]:
    """Add scriptHash to an MCP server config when it runs a local script, so the
    gateway can fingerprint it as `script:<hash>`."""
    if result and result.get('command'):
        script_hash = _compute_script_hash(result.get('command'), result.get('args'), cwd)
        if script_hash:
            result['scriptHash'] = script_hash
    return result


_HOOK_MAX_SCRIPT_BYTES = 256 * 1024


def _read_script_body_b64(command, args, cwd):
    """base64 of the local script's first _HOOK_MAX_SCRIPT_BYTES bytes (the scan
    body), or None. The backend re-hashes these exact bytes, so this must read the
    same prefix _compute_script_hash hashed. Capped (and truncated, not skipped)
    so the body stays consistent with the hash and the payload stays small."""
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
        with open(path, 'rb') as f:
            data = f.read(_HOOK_MAX_SCRIPT_BYTES)
        return base64.b64encode(data).decode('ascii')
    except Exception:
        return None


def _macos_proc_argv(pid: int) -> Optional[List[str]]:
    import ctypes
    import struct

    CTL_KERN = 1
    KERN_ARGMAX = 8
    KERN_PROCARGS2 = 49

    libc = ctypes.CDLL(None, use_errno=True)

    argmax = ctypes.c_int(0)
    size = ctypes.c_size_t(ctypes.sizeof(argmax))
    mib2 = (ctypes.c_int * 2)(CTL_KERN, KERN_ARGMAX)
    if libc.sysctl(mib2, 2, ctypes.byref(argmax), ctypes.byref(size), None, 0) != 0:
        return None

    buf = ctypes.create_string_buffer(argmax.value)
    size = ctypes.c_size_t(argmax.value)
    mib3 = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, int(pid))
    if libc.sysctl(mib3, 3, buf, ctypes.byref(size), None, 0) != 0:
        return None

    # KERN_PROCARGS2 layout: int argc, exec_path\0, padding\0*, then argc null-terminated args.
    data = buf.raw[:size.value]
    if len(data) < 4:
        return None
    argc = struct.unpack('i', data[:4])[0]
    end = data.find(b'\x00', 4)
    if end == -1:
        return None
    pos = end
    while pos < len(data) and data[pos] == 0:
        pos += 1
    argv = []
    for _ in range(argc):
        end = data.find(b'\x00', pos)
        if end == -1:
            break
        argv.append(data[pos:end].decode('utf-8', 'replace'))
        pos = end + 1
    return argv


def _process_argv(pid: int) -> List[str]:
    try:
        cmdline = Path(f"/proc/{pid}/cmdline")
        if cmdline.exists():
            raw = cmdline.read_bytes()
            return [a.decode('utf-8', 'replace') for a in raw.split(b'\x00') if a]
    except Exception:
        pass
    if platform.system() == 'Darwin':
        try:
            argv = _macos_proc_argv(pid)
            if argv:
                return argv
        except Exception:
            pass
    return []


def _parent_pid(pid: int) -> Optional[int]:
    try:
        stat = Path(f"/proc/{pid}/stat")
        if stat.exists():
            # comm (field 2) may hold spaces/parens; ppid is the 2nd field after the last ')'.
            data = stat.read_text()
            return int(data[data.rfind(')') + 1:].split()[1])
    except Exception:
        pass
    try:
        out = subprocess.run(['ps', '-o', 'ppid=', '-p', str(pid)],
                             capture_output=True, text=True, timeout=2)
        s = out.stdout.strip()
        return int(s) if s else None
    except Exception:
        return None


def _is_claude_cli(argv: List[str]) -> bool:
    return bool(argv) and _hook_command_basename(argv[0]) == 'claude'


def _claude_launch_argv() -> Optional[tuple]:
    # The detached --mcp-diagnostic child is reparented, so it can't walk up to
    # Claude. The parent forwards Claude's pid+argv via env; honor that here so
    # launch_config / plugin_by_key replay against the real launch context.
    fwd = os.environ.get('UNBOUND_DIAG_LAUNCH_ARGV')
    if fwd:
        try:
            return int(os.environ.get('UNBOUND_DIAG_LAUNCH_PID') or os.getpid()), json.loads(fwd)
        except Exception:
            pass
    # Prefer the Claude CLI ancestor as the --mcp-config source. argv[0] is
    # best-effort provenance (spoofable via exec -a), but the launcher already
    # controls its own config, so this mainly avoids reading an unrelated
    # wrapper's argv rather than being a hard integrity guarantee.
    pid = os.getpid()
    for _ in range(12):
        argv = _process_argv(pid)
        if _is_claude_cli(argv):
            return pid, argv
        ppid = _parent_pid(pid)
        if not ppid or ppid == pid or ppid <= 1:
            break
        pid = ppid
    return None


def _argv_flag_values(argv: List[str], flag: str) -> List[str]:
    # Variadic flag: it consumes every following token until the next flag.
    values = []
    i = 0
    n = len(argv)
    prefix = flag + '='
    while i < n:
        a = argv[i]
        if a == flag:
            i += 1
            while i < n and not argv[i].startswith('-'):
                values.append(argv[i])
                i += 1
            continue
        if a.startswith(prefix):
            values.append(a[len(prefix):])
        i += 1
    return values


def _mcp_config_values_from_argv(argv: List[str]) -> List[str]:
    return _argv_flag_values(argv, '--mcp-config')


def _proc_cwd(pid: int) -> Optional[str]:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except Exception:
        pass
    if platform.system() == 'Darwin':
        try:
            out = subprocess.run(['lsof', '-a', '-p', str(pid), '-d', 'cwd', '-Fn'],
                                 capture_output=True, text=True, timeout=2)
            for line in out.stdout.splitlines():
                if line.startswith('n'):
                    return line[1:]
        except Exception:
            pass
    return None


def _load_mcp_config_blob(raw: str, cwd: Optional[str] = None) -> Optional[Dict]:
    raw = (raw or '').strip()
    if not raw:
        return None
    if raw[0] in '{[':
        try:
            return json.loads(raw)
        except Exception:
            return None
    try:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            if not cwd:
                return None
            path = Path(cwd) / path
        if path.is_file() and path.stat().st_size <= 1_000_000:
            return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None
    return None


def _resolve_launch_mcp_config(server_name: str) -> Optional[Dict]:
    try:
        found = _claude_launch_argv()
        if not found:
            return None
        pid, argv = found
        cwd = _proc_cwd(pid)
        match = None
        for raw in _mcp_config_values_from_argv(argv):
            data = _load_mcp_config_blob(raw, cwd)
            servers = data.get('mcpServers') if isinstance(data, dict) else None
            if isinstance(servers, dict) and server_name in servers:
                result = _extract_mcp_server_fields(servers[server_name])
                if result:
                    match = result  # Claude merges --mcp-config values last-wins per server.
        return _augment_script_hash(match, cwd) if match else None
    except Exception:
        return None


def _claude_plugin_launch_values() -> tuple:
    """(--plugin-dir paths, --plugin-url values) from the Claude CLI ancestor argv."""
    try:
        found = _claude_launch_argv()
        if not found:
            return [], []
        pid, argv = found
        urls = _argv_flag_values(argv, '--plugin-url')
        dirs = []
        cwd = None
        for raw in _argv_flag_values(argv, '--plugin-dir'):
            path = Path(raw).expanduser()
            if not path.is_absolute():
                if cwd is None:
                    cwd = _proc_cwd(pid) or ''
                if not cwd:
                    continue
                path = Path(cwd) / path
            if path not in dirs:
                dirs.append(path)
        return dirs, urls
    except Exception:
        return [], []


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
                                return _augment_script_hash(result, cwd)
                    parent = os.path.dirname(cwd_path)
                    if parent == cwd_path:
                        break
                    cwd_path = parent

        top_servers = config.get('mcpServers', {})
        if isinstance(top_servers, dict) and server_name in top_servers:
            result = _extract_mcp_server_fields(top_servers[server_name])
            if result:
                return _augment_script_hash(result, cwd)

        return None
    except Exception:
        return None


def _read_mcp_server_config_worktree_union(server_name: str, config_path: Path,
                                           cwd: Optional[str] = None) -> Optional[Dict]:
    """Claude unions local-scope servers across all linked worktrees of cwd's
    repo, so a sibling checkout's project entry can be live here too."""
    try:
        if not cwd or not config_path.exists():
            return None
        roots = _git_worktree_roots(cwd)
        if not roots:
            return None
        with open(config_path, 'r', encoding='utf-8') as f:
            projects = (json.loads(f.read()) or {}).get('projects')
        if not isinstance(projects, dict):
            return None
        for root in roots:
            proj_data = projects.get(root.replace('\\', '/').rstrip('/'))
            if not isinstance(proj_data, dict):
                continue
            proj_servers = proj_data.get('mcpServers', {})
            if isinstance(proj_servers, dict) and server_name in proj_servers:
                result = _extract_mcp_server_fields(proj_servers[server_name])
                if result:
                    return _augment_script_hash(result, cwd)
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


def _claude_desktop_support_dirs() -> List[Path]:
    """Claude Desktop app support dir(s) per OS. Team/SSO desktop sessions cache
    the active account's oauthAccount under local-agent-mode-sessions/ here."""
    system = platform.system().lower()
    if system == 'darwin':
        return [Path.home() / 'Library' / 'Application Support' / 'Claude']
    if system == 'windows':
        appdata = os.getenv('APPDATA')
        return [Path(appdata) / 'Claude'] if appdata else []
    return [Path.home() / '.config' / 'Claude']


_DESKTOP_SESSION_MAX_BYTES = 512 * 1024


def _desktop_session_email() -> Optional[str]:
    """Fallback for Team/SSO Claude Desktop, where the desktop app doesn't hydrate
    oauthAccount into ~/.claude.json (anthropics/claude-code#57026) but does write
    the active account's oauthAccount (with emailAddress) into each per-session
    sandbox config. These configs are sandbox-writable and thus untrusted, so the
    email is returned only when every session that carries one agrees on a single
    address; any disagreement (multiple accounts, or a forged/injected config) or
    failure yields None, so the hook emits a blank email rather than a wrong one.
    Best effort — never raises."""
    timed = []
    try:
        bases = _claude_desktop_support_dirs()
    except Exception:
        return None
    for base in bases:
        try:
            # list() forces the lazy glob traversal to happen inside this guard —
            # a mid-iteration traversal error (e.g. an unreadable subdir) then only
            # skips this base instead of aborting the whole scan.
            candidates = list((base / 'local-agent-mode-sessions').glob('*/*/local_*/.claude/.claude.json'))
        except Exception:
            continue
        for path in candidates:
            # stat per file so one unreadable/vanished entry can't poison the sort.
            try:
                timed.append((path.stat().st_mtime, path))
            except Exception:
                continue
    timed.sort(key=lambda t: t[0], reverse=True)
    found = None
    found_key = None
    for _, path in timed:
        # A session that exists but can't be read (oversized, IO/parse error) is a
        # blind spot — it could belong to a different account, so we can't verify
        # agreement. Return blank rather than fall through to a possibly-stale email.
        # Bound the read itself (read MAX+1 bytes) rather than trusting a separate
        # stat(): a rewrite-after-stat race can't feed an unbounded file into read.
        try:
            with open(path, 'rb') as f:
                data = f.read(_DESKTOP_SESSION_MAX_BYTES + 1)
            if len(data) > _DESKTOP_SESSION_MAX_BYTES:
                return None
            oauth = json.loads(data.decode('utf-8')).get('oauthAccount')
        except Exception:
            return None
        if not isinstance(oauth, dict):
            continue
        raw = oauth.get('emailAddress')
        email = raw.strip() if isinstance(raw, str) else ''
        if not email:
            continue
        key = email.lower()
        if found_key is None:
            found, found_key = email, key
        elif key != found_key:
            return None  # accounts disagree — blank over wrong
    return found


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
            _raw_email = oauth.get('emailAddress')
            if isinstance(_raw_email, str):
                email = _raw_email.strip() or None
            else:
                email = None
            auth_mode = 'subscription'
        elif os.getenv('ANTHROPIC_API_KEY') or (config.get('customApiKeyResponses') or {}).get('approved'):
            auth_mode = 'api_key'
    except Exception:
        pass
    if not email:
        try:
            email = _desktop_session_email()
        except Exception:
            email = None
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


def _unbound_app_label(event: Dict) -> str:
    """This one hook script serves both Claude Code and Cowork. Report Cowork
    under its own label so the gateway can scope policies/analytics per surface.
    The Claude Desktop app marks Cowork in the hook environment; builds that
    predate those env vars still get caught by the sandbox path marker
    (cwd/transcript_path under local-agent-mode-sessions). Requires gateway
    support for 'cowork' — old gateways drop the label from their label-keyed
    maps."""
    try:
        if os.environ.get('CLAUDE_CODE_IS_COWORK') == '1':
            return 'cowork'
        if os.environ.get('CLAUDE_CODE_ENTRYPOINT') in (
            'local-agent', 'local_agent', 'remote_cowork'
        ):
            return 'cowork'
    except Exception:
        pass
    for field in ('cwd', 'transcript_path'):
        if 'local-agent-mode-sessions' in (event.get(field) or ''):
            return 'cowork'
    return 'claude-code'


def process_pre_tool_use(event: Dict, api_key: str) -> Dict:
    """Process PreToolUse event - DO NOT LOG."""
    session_id = event.get('session_id')
    model = event.get('model') or _get_session_model(session_id) or 'auto'
    transcript_path = event.get('transcript_path')
    tool_name = event.get('tool_name', '')

    is_mcp = tool_name.startswith(MCP_TOOL_PREFIX)
    if is_mcp:
        builtin_seg = tool_name[len(MCP_TOOL_PREFIX):].split('__', 1)[0]
        if builtin_seg in COWORK_BUILTIN_MCP_SERVERS:
            return {}
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
        plugin_dirs = plugin_urls = None  # lazy: --plugin-dir paths / --plugin-url values

        if mcp_server_name:
            cwd = event.get('cwd')
            server_cfg = _read_mcp_server_config(
                mcp_server_name, CLAUDE_MCP_CONFIG_PATH, cwd=cwd
            )
            if server_cfg:
                metadata['mcp_server_config'] = server_cfg

            if not server_cfg:
                connector = _resolve_claude_ai_connector(mcp_server_name, config_path=CLAUDE_MCP_CONFIG_PATH)
                if connector:
                    display_name, connector_cfg = connector
                    metadata['mcp_server'] = display_name
                    metadata['mcp_server_config'] = connector_cfg
                else:
                    plugin_cfg = _resolve_plugin_mcp_config(mcp_server_name, cache_dir=CLAUDE_PLUGIN_CACHE_DIR)
                    if plugin_cfg:
                        metadata['mcp_server_config'] = plugin_cfg
                    else:
                        session_connector = _resolve_claude_code_session_connector(mcp_server_name)
                        if session_connector:
                            display_name, connector_cfg = session_connector
                            metadata['mcp_server'] = display_name
                            metadata['mcp_server_config'] = connector_cfg
                            if _is_uuid(mcp_server_name):
                                metadata['mcp_server_uuid'] = mcp_server_name
                        else:
                            launch_cfg = _resolve_launch_mcp_config(mcp_server_name)
                            if launch_cfg:
                                metadata['mcp_server_config'] = launch_cfg
                            elif mcp_server_name.startswith('plugin_'):
                                # Opaque plugin ID: no prefix matched, fall back to exact/suffix matching.
                                plugin_dirs, plugin_urls = _claude_plugin_launch_values()
                                fallback_cfg = _resolve_plugin_mcp_config_by_server_key(
                                    mcp_server_name, cache_dir=CLAUDE_PLUGIN_CACHE_DIR,
                                    extra_dirs=plugin_dirs, allow_suffix_guess=not plugin_urls,
                                )
                                if fallback_cfg:
                                    metadata['mcp_server_config'] = fallback_cfg

            if not metadata.get('mcp_server_config'):
                union_cfg = _read_mcp_server_config_worktree_union(
                    mcp_server_name, CLAUDE_MCP_CONFIG_PATH, cwd=cwd
                )
                if union_cfg:
                    metadata['mcp_server_config'] = union_cfg

    approval_key = f"{tool_name}:{command}"
    is_retry = _is_approval_retry(approval_key)

    # Raw CLAUDE_CODE_ENTRYPOINT, forwarded so the gateway can tell a headless
    # session (sdk-cli/sdk-ts/sdk-py) apart from an interactive one.
    client_entrypoint = os.environ.get('CLAUDE_CODE_ENTRYPOINT', 'cli')

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': _unbound_app_label(event),
        'model': model,
        'event_name': 'tool_use',
        'pre_tool_use_data': {
            'command': command,
            'tool_name': tool_name,
            'metadata': metadata
        },
        'account_identity': build_account_identity(),
        'client_entrypoint': client_entrypoint,
        **_build_user_prompt_payload(recent_user_prompts),
    }

    request_body['pre_tool_use_data']['tool_use_id'] = resolve_tool_use_id(event)

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
            _dispatch_mcp_server_scan(metadata.get('mcp_server', ''), server_cfg, cwd=metadata.get('cwd'))

    # Null fingerprint: the hook resolved no config for a real MCP server. The
    # gateway can't flag this — a null fingerprint yields no unknown_mcp_server
    # hint — so key off our own resolution result, not the gateway response.
    if is_mcp and metadata.get('mcp_server') and not metadata.get('mcp_server_config'):
        if plugin_dirs is None:
            plugin_dirs, plugin_urls = _claude_plugin_launch_values()
        log_error(
            f"unknown mcp server with no resolvable config: {metadata.get('mcp_server', '')}"
            f" (plugin-dir={[str(p) for p in plugin_dirs]}"
            f" plugin-url={[_redact_url(u) for u in plugin_urls]})",
            'mcp_server',
        )
        _dispatch_mcp_diagnostic(metadata.get('mcp_server', ''), metadata.get('cwd'), api_key)

    return transform_response_for_claude(api_response)


def _github_remote_path(remote_url: str) -> Optional[str]:
    """The 'ORG/repo' path of a GitHub remote URL, with any trailing slash
    stripped. Handles the SSH scp form (git@github.com:ORG/repo.git) and the
    HTTPS/scheme form (https://github.com/ORG/repo.git). None if the URL is empty
    or unparseable. The per-segment '.git' strip is left to the callers."""
    if not remote_url:
        return None
    url = remote_url.strip()
    if '://' in url:
        # scheme://[user@]host/ORG/repo(.git)
        after_scheme = url.split('://', 1)[1]
        path = after_scheme.split('/', 1)[1] if '/' in after_scheme else ''
    elif ':' in url:
        # scp-like: [user@]host:ORG/repo(.git)
        path = url.split(':', 1)[1]
    else:
        return None
    path = path.strip('/')
    return path or None


def _strip_git_suffix(segment: str) -> str:
    return segment[:-4] if segment.endswith('.git') else segment


def _parse_github_org(remote_url: str) -> Optional[str]:
    """Org/owner (first path segment after the host) of a GitHub remote URL.
    Returns None if the URL is empty or unparseable."""
    path = _github_remote_path(remote_url)
    if not path:
        return None
    org = _strip_git_suffix(path.split('/', 1)[0])
    return org or None


def _parse_github_repo(remote_url: str) -> Optional[str]:
    """Repo name (second path segment) of a GitHub remote URL, with a trailing
    '.git' stripped. None if absent or unparseable."""
    path = _github_remote_path(remote_url)
    if not path:
        return None
    parts = path.split('/')
    if len(parts) < 2:
        return None
    repo = _strip_git_suffix(parts[1])
    return repo or None


def _get_git_origin_org_repo(cwd: str) -> tuple:
    """Lowercased (org, repo) of `cwd`'s `origin` remote, or (None, None) when
    `cwd` is not a git repo or has no `origin` (a clean non-zero git exit). Raises
    only when git cannot be executed at all (missing binary / timeout) so the
    caller can tell an honest 'non-compliant' apart from an internal failure and
    fail-open."""
    result = subprocess.run(
        ['git', '-C', cwd, 'remote', 'get-url', 'origin'],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return (None, None)
    url = result.stdout.strip()
    org = _parse_github_org(url)
    repo = _parse_github_repo(url)
    return (org.lower() if org else None, repo.lower() if repo else None)


def _get_project(cwd: Optional[str]) -> Optional[str]:
    """Lowercased "<org>/<repo>" for `cwd`'s git origin, attached to hook
    requests for analytics. None when cwd is missing, not a git repo, has no
    origin, or anything fails — fully fail-open (never raises)."""
    try:
        if not cwd:
            return None
        org, repo = _get_git_origin_org_repo(cwd)
        return f"{org}/{repo}" if org and repo else None
    except Exception:
        return None


# Per-repo observation tiers for the end-of-turn exchange. The hook reports
# raw facts (which repos the turn touched, and how); the attribution policy
# lives server-side where it can be tuned without redeploying hooks.
_WRITE_TOOLS = {'Edit', 'Write', 'NotebookEdit'}
_READ_TOOLS = {'Read', 'Grep', 'Glob'}

# Any absolute path inside a Bash command (cd targets, git -C, pytest /x/…).
# Left boundary required so the slash inside a relative token (tests/webapp/)
# doesn't read as an absolute path.
_ABS_PATH_RE = re.compile(r'(?:^|[\s"\'=(])(/[^\s"\';|&<>()]+)')
# Package-manager / OS checkouts that are real git clones but never the
# engineer's project — Homebrew installs itself as a clone of Homebrew/brew,
# so a command merely referencing /opt/homebrew/bin/… would otherwise
# attribute the call to "homebrew/brew". Candidates under these roots are
# skipped so resolution falls through to the shell's working directory.
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
# the persistent shell's working directory across the turn's Bash calls.
_CD_TARGET_RE = re.compile(r'(?:^|[;&|\n]\s*|\bthen\s+|\bdo\s+)cd\s+(["\']?)([^\s"\';|&]+)\1')


def _find_git_root(path: str) -> Optional[str]:
    """Nearest ancestor of `path` (inclusive) containing a `.git` entry
    (directory, or file for linked worktrees). Pure filesystem stats — no
    subprocess. None when outside any repo or on any error (fail-open)."""
    try:
        p = Path(path)
        for parent in [p] + list(p.parents):
            if (parent / '.git').exists():
                return str(parent)
    except Exception:
        pass
    return None


def _git_worktree_roots(path: str) -> List[str]:
    """Worktree roots of the repo containing `path`, main checkout first.
    Pure file reads, no git subprocess; [] outside a repo or on any error."""
    try:
        root = _find_git_root(path)
        if not root:
            return []
        dot_git = Path(root) / '.git'
        if dot_git.is_dir():
            common = dot_git
            main_root = root
        else:
            target = dot_git.read_text(encoding='utf-8').strip()
            if not target.startswith('gitdir:'):
                return []
            # gitdir pointers may be relative; git resolves them against the
            # directory holding them, so mirror that.
            gitdir = Path(os.path.normpath(
                os.path.join(root, target[len('gitdir:'):].strip())))
            if gitdir.parent.name != 'worktrees' or gitdir.parent.parent.name != '.git':
                return []
            common = gitdir.parent.parent
            main_root = str(common.parent)
        roots = [main_root]
        wt_dir = common / 'worktrees'
        if wt_dir.is_dir():
            for entry in sorted(wt_dir.iterdir()):
                try:
                    linked = (entry / 'gitdir').read_text(encoding='utf-8').strip()
                except OSError:
                    continue
                wt_root = str(Path(os.path.normpath(
                    os.path.join(str(entry), linked))).parent)
                if wt_root not in roots:
                    roots.append(wt_root)
        return roots
    except Exception:
        return []


def _next_shell_dir(command: str, shell_dir: Optional[str]) -> Optional[str]:
    """Follow the last `cd` in `command` from `shell_dir`, mirroring the
    persistent shell's directory between Bash calls. Absolute and ~-rooted
    targets replace the dir; relative ones join onto it. Unchanged when the
    command has no cd or on any error."""
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
        if target == '-':  # `cd -` — previous dir isn't tracked; keep as-is
            return shell_dir
        if shell_dir:
            return os.path.normpath(os.path.join(shell_dir, target))
        return shell_dir
    except Exception:
        return shell_dir


def _project_for_tool_use(tool_name: Optional[str], tool_input: Optional[Dict], shell_dir: Optional[str], root_projects: Dict[str, Optional[str]]) -> tuple:
    """Resolve the git project ("<org>/<repo>") a single tool call worked in.
    Writes/reads resolve from the tool's file path; Bash resolves from the
    first absolute path in the command, else the shell's working directory
    tracked across the turn's `cd`s. Returns (project, shell_dir) — shell_dir
    updated when the command changed directory. `root_projects` caches the
    origin lookup so `git remote get-url` runs at most once per distinct repo.
    (None, shell_dir) when nothing resolves (fail-open)."""
    try:
        tool_input = tool_input or {}
        candidates = []
        if tool_name in _WRITE_TOOLS:
            path = tool_input.get('file_path') or tool_input.get('notebook_path')
            if isinstance(path, str) and path.startswith('/') and not _is_system_checkout_path(path):
                candidates.append(os.path.dirname(path))
        elif tool_name in _READ_TOOLS:
            path = tool_input.get('file_path') or tool_input.get('path')
            if isinstance(path, str) and path.startswith('/') and not _is_system_checkout_path(path):
                candidates.append(os.path.dirname(path) if tool_name == 'Read' else path)
        elif tool_name == 'Bash':
            command = tool_input.get('command')
            if isinstance(command, str):
                candidates.extend(
                    p for p in _ABS_PATH_RE.findall(command) if not _is_system_checkout_path(p)
                )
                shell_dir = _next_shell_dir(command, shell_dir)
                if not candidates and shell_dir:
                    candidates.append(shell_dir)
        for candidate in candidates:
            root = _find_git_root(candidate)
            if not root:
                continue
            if root not in root_projects:
                root_projects[root] = _get_project(root)
            if root_projects[root]:
                return root_projects[root], shell_dir
        return None, shell_dir
    except Exception:
        return None, shell_dir


def process_user_prompt_submit(event: Dict, api_key: str) -> Dict:
    """Process UserPromptSubmit event for policy checking."""
    session_id = event.get('session_id')
    model = event.get('model') or _get_session_model(session_id) or 'auto'
    prompt = event.get('prompt', '')

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': _unbound_app_label(event),
        'model': model,
        'event_name': 'user_prompt',
        'account_identity': build_account_identity(),
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }

    api_response = send_to_hook_api(request_body, api_key)
    response = transform_response_for_claude_prompt(api_response)
    return response


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


def _resolve_skill_path(skill: Optional[str], cwd: Optional[str]) -> Optional[str]:
    """Absolute path of the invoked skill's SKILL.md. The tool call carries only
    the skill name, so map it back on device — the backend joins this against
    the skills discovery already reported. None when it can't be resolved."""
    try:
        prefix, _, name = (skill or '').rpartition(':')
        segments = prefix.split('/') if prefix else []
        if not _safe_skill_segment(name):
            return None
        if not all(_safe_skill_segment(segment) for segment in segments):
            return None

        # Plugin skills ("<plugin>:<name>") live outside the project tree.
        if prefix and '/' not in prefix:
            plugins_dir = CLAUDE_PLUGIN_CACHE_DIR.parent
            for pattern in ('cache/*/%s/*/skills/%s/SKILL.md',
                            'marketplaces/*/plugins/%s/skills/%s/SKILL.md'):
                matches = sorted(plugins_dir.glob(pattern % (prefix, name)))
                # Several copies of one plugin skill is ambiguous, so resolve
                # nothing rather than guess, as the bundled path already does.
                if len(matches) > 1:
                    return None
                if matches:
                    return str(matches[0])

        # Directory-scoped skills ("apps/web:deploy") hang off an ancestor dir.
        # A prefixed skill never falls back to the bare name — "slack:standup"
        # and a personal "standup" are different skills.
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


def build_llm_exchange(events: List[Dict], stop_assistant_message: Optional[str] = None, transcript_assistant_messages: Optional[List[str]] = None, model: Optional[str] = None, usage: Optional[Dict] = None, request_initialized: Optional[str] = None, request_completed: Optional[str] = None, cwd: Optional[str] = None) -> Optional[Dict]:
    messages = []
    assistant_tool_uses = []

    user_prompt = None
    prompt_cwd = None
    session_id = None
    permission_mode = None
    # Per-tool-use project resolution state: the persistent shell starts at
    # the session cwd; origin lookups are cached per repo root.
    shell_dir = cwd
    root_projects = {}

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
                # The prompt's own cwd beats the session cwd for resolving a
                # repo-level skill when the agent was opened at a parent dir.
                prompt_cwd = event.get('cwd') or prompt_cwd

        elif hook_event_name == 'PostToolUse':
            tool_name = event.get('tool_name')
            tool_input = event.get('tool_input', {})
            tool_response = event.get('tool_response', {})

            if 'content' in tool_response and 'content' in tool_input:
                if tool_response['content'] == tool_input['content']:
                    tool_response = {k: v for k, v in tool_response.items() if k != 'content'}

            # Attribute this tool call to the repo it worked in (file path /
            # Bash cwd tracking); rides on the tool_use entry so the backend
            # can store per-call project on each analytics row.
            tool_project, shell_dir = _project_for_tool_use(tool_name, tool_input, shell_dir, root_projects)

            tool_use_entry = {
                'type': 'PostToolUse',
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_response': tool_response,
                'tool_use_id': resolve_tool_use_id(event),
                'project': tool_project
            }
            # Lift the invoked skill to stable keys so the backend reads one
            # field regardless of how a tool spells its skill input.
            if tool_name == SKILL_TOOL_NAME and isinstance(tool_input, dict):
                skill = tool_input.get('skill')
                tool_use_entry['skill_name'] = skill
                skill_path = _resolve_skill_path(
                    skill, event.get('cwd') or prompt_cwd or cwd)
                if skill_path:
                    tool_use_entry['skill_path'] = skill_path
            assistant_tool_uses.append(tool_use_entry)
    
    # A typed `/name` is expanded by Claude Code itself and never reaches the
    # Skill tool, so recover it from the prompt. Resolving on disk is what
    # keeps built-ins like /clear and /help out.
    if user_prompt and user_prompt.startswith('/'):
        typed = user_prompt[1:].split(None, 1)
        typed_skill = typed[0] if typed else ''
        typed_args = typed[1] if len(typed) > 1 else ''
        typed_path = _resolve_skill_path(typed_skill, prompt_cwd or cwd)
        if typed_path:
            typed_key = '\x1f'.join((
                str(session_id or ''), typed_skill, typed_args,
                str(request_initialized or ''),
            ))
            assistant_tool_uses.append({
                'type': 'PostToolUse',
                'tool_name': SKILL_TOOL_NAME,
                'tool_input': {'skill': typed_skill, 'args': typed_args},
                'tool_response': {},
                'tool_use_id': 'unb-' + hashlib.sha256(
                    typed_key.encode('utf-8', 'replace')).hexdigest()[:24],
                'skill_name': typed_skill,
                'skill_path': typed_path,
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
        'cwd': cwd,
        # Turn-level fallback: rows without a per-call project (the user
        # prompt row, or tool-less turns) inherit the session cwd's repo.
        'project': _get_project(cwd),
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
        cwd=event.get('cwd'),
    )

    if exchange:
        exchange['unbound_app_label'] = _unbound_app_label(event)
        # prompt_id == Cowork's OTEL prompt.id; lets the backend de-dup a turn
        # logged on both hooks and OTEL. Absent on Claude Code < v2.1.196.
        prompt_id = event.get('prompt_id')
        if prompt_id:
            exchange['turn_request_id'] = prompt_id
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


def _install_sh_is_stale() -> bool:
    try:
        return (time.time() - DISCOVERY_INSTALL_SH.stat().st_mtime) > DISCOVERY_INSTALL_SH_TTL_SECONDS
    except OSError:
        return True


def _dispatch_mcp_server_scan(server_name: str, server_config: Dict, cwd: Optional[str] = None) -> None:
    """Report ONE unknown MCP server out-of-band.

    Detached so the blocking PreToolUse hook returns immediately. Secrets
    (server_config args, api key) go via env, never argv or the shell string.
    """
    if not server_name:
        log_error("mcp scan dispatch: empty server name, skipping", 'mcp_server')
        return
    try:
        if (isinstance(server_config, dict) and server_config.get('command')
                and not server_config.get('script_content')):
            body = _read_script_body_b64(server_config.get('command'), server_config.get('args'), cwd)
            if body:
                server_config = {**server_config, 'script_content': body}
    except Exception:
        pass
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


_MCP_DIAG_SECRETISH = re.compile(
    r'(?i)(authorization|bearer|api[_-]?key|apikey|token|secret|password|passwd|credential)')


def _mcp_diag_host_of(url):
    # hostname[:port] only — urlparse drops any user:pass@ userinfo (a credential).
    try:
        p = urlparse(str(url))
        if p.scheme and p.hostname:
            return '%s://%s%s' % (p.scheme, p.hostname, ':%d' % p.port if p.port else '')
    except Exception:
        pass
    return '<unparseable-url>'


def _mcp_diag_redact_cfg(cfg):
    if not isinstance(cfg, dict):
        return None
    out = {}
    if cfg.get('url'):
        out['url_host'] = _mcp_diag_host_of(cfg['url'])
        out['url_has_query'] = '?' in str(cfg['url'])
    if cfg.get('command'):
        out['command'] = os.path.basename(str(cfg['command']))
    if isinstance(cfg.get('args'), list):
        out['args_count'] = len(cfg['args'])
    if cfg.get('type'):
        out['type'] = cfg['type']
    if cfg.get('scriptHash'):
        out['scriptHash'] = str(cfg['scriptHash'])[:16]
    if isinstance(cfg.get('env'), dict):
        out['env_keys'] = len(cfg['env'])
    if isinstance(cfg.get('headers'), dict):
        out['header_keys'] = len(cfg['headers'])
    return out


def _diag_settings_files(cwd):
    proj = Path(cwd) if cwd else Path.cwd()
    return [
        _DIAG_CLAUDE_DIR / 'settings.json',
        _DIAG_CLAUDE_DIR / 'settings.local.json',
        proj / '.claude' / 'settings.json',
        proj / '.claude' / 'settings.local.json',
        Path('/Library/Application Support/ClaudeCode/managed-settings.json'),
        Path('/etc/claude-code/managed-settings.json'),
        Path('C:/ProgramData/ClaudeCode/managed-settings.json'),
    ]


def _diag_hash_file(path):
    try:
        st = os.stat(path)
        h = hashlib.sha256()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        return {
            'path': str(path),
            'size': st.st_size,
            'mtime': datetime.utcfromtimestamp(st.st_mtime).isoformat() + 'Z',
            'sha256': h.hexdigest(),
        }
    except Exception:
        return None


def _diag_installed_hooks(cwd):
    """Locate the hook Claude Code actually runs (not this file when run from a
    repo checkout): the standard install path plus any .py named by a hook
    command in settings. Each with its own sha256 so versions are comparable."""
    cands = [
        SELF_SCRIPT_PATH,
        _DIAG_CLAUDE_DIR / 'hooks' / 'unbound.py',
        Path('/Library/Application Support/ClaudeCode/hooks/unbound.py'),
        Path('C:/ProgramData/ClaudeCode/hooks/unbound.py'),
    ]
    for s in _diag_settings_files(cwd):
        try:
            data = json.loads(s.read_text(encoding='utf-8'))
        except Exception:
            continue
        for entries in (data.get('hooks') or {}).values():
            for entry in (entries if isinstance(entries, list) else []):
                for hk in ((entry or {}).get('hooks') or []):
                    cmd = (hk or {}).get('command')
                    if isinstance(cmd, str):
                        for m in re.finditer(r'([^\s"\']+\.py)', cmd):
                            cands.append(Path(os.path.expanduser(m.group(1))))
    out, seen = [], set()
    for c in cands:
        try:
            rp = os.path.realpath(c)
            if rp in seen or not os.path.isfile(rp):
                continue
            seen.add(rp)
            info = _diag_hash_file(rp)
            if info:
                out.append(info)
        except Exception:
            continue
    return out


def _mcp_diag_hook_info(cwd):
    """sha256 of the running file + the installed hook(s) Claude runs, plus
    whether settings still reference the hook (persisted vs tampered)."""
    info = {'running': _diag_hash_file(os.path.abspath(__file__)),
            'installed': _diag_installed_hooks(cwd),
            'registration': 'unknown'}
    try:
        referenced = False
        for s in _diag_settings_files(cwd):
            try:
                blob = json.dumps(json.loads(s.read_text(encoding='utf-8')).get('hooks') or {})
            except Exception:
                continue
            if 'unbound' in blob:
                referenced = True
                break
        info['registration'] = 'persisted' if referenced else 'tampered'
    except Exception:
        pass
    return info


def _mcp_diag_resolution(server, cwd):
    # Suppress the resolvers' own log_error/report_error_to_gateway calls: this is
    # a passive replay, so it must not pollute the shared error.log or its own tail.
    global _suppress_error_logging
    sources = {}
    resolved, via, cfg = None, None, None

    def _plugin_by_key():
        # Match the live ladder exactly (only for plugin_ ids, with launch values),
        # else the replay can claim a hit the hook would refuse.
        if not str(server).startswith('plugin_'):
            return None
        dirs, urls = _claude_plugin_launch_values()
        return _resolve_plugin_mcp_config_by_server_key(
            server, cache_dir=CLAUDE_PLUGIN_CACHE_DIR,
            extra_dirs=dirs, allow_suffix_guess=not urls,
        )

    attempts = (
        ('claude_json', lambda: _read_mcp_server_config(server, CLAUDE_MCP_CONFIG_PATH, cwd=cwd)),
        ('claude_ai_connector',
         lambda: (_resolve_claude_ai_connector(server, config_path=CLAUDE_MCP_CONFIG_PATH) or (None, None))[1]),
        ('plugin_cache', lambda: _resolve_plugin_mcp_config(server, cache_dir=CLAUDE_PLUGIN_CACHE_DIR)),
        ('session_connector',
         lambda: (_resolve_claude_code_session_connector(server) or (None, None))[1]),
        ('launch_config', lambda: _resolve_launch_mcp_config(server)),
        ('plugin_by_key', _plugin_by_key),
        ('worktree_union',
         lambda: _read_mcp_server_config_worktree_union(server, CLAUDE_MCP_CONFIG_PATH, cwd=cwd)),
    )
    _suppress_error_logging = True
    try:
        for label, fn in attempts:
            try:
                got = fn()
            except Exception:
                sources[label] = 'error'
                continue
            sources[label] = 'hit' if got else 'miss'
            if got and resolved is None:
                resolved, via, cfg = True, label, got
    finally:
        _suppress_error_logging = False
    return {
        'sources': sources,
        'resolved': bool(resolved),
        'via': via,
        'config': _mcp_diag_redact_cfg(cfg) if resolved else None,
    }


def _mcp_diag_claude_json(server, cwd):
    out = {'present': CLAUDE_MCP_CONFIG_PATH.exists(), 'size': None, 'mtime': None,
           'parse_ok': None, 'top_level': None, 'top_level_servers': [],
           'project_count': None, 'project_entry': None, 'scoped_under': []}
    if not out['present']:
        return out
    try:
        st = CLAUDE_MCP_CONFIG_PATH.stat()
        out['size'] = st.st_size
        out['mtime'] = datetime.utcfromtimestamp(st.st_mtime).isoformat() + 'Z'
    except Exception:
        pass
    try:
        cfg = json.loads(CLAUDE_MCP_CONFIG_PATH.read_text(encoding='utf-8'))
        out['parse_ok'] = True
    except Exception:
        out['parse_ok'] = False
        return out
    if not isinstance(cfg, dict):
        return out
    top = cfg.get('mcpServers') or {}
    projects = cfg.get('projects') or {}
    out['top_level'] = server in top
    out['top_level_servers'] = sorted(top.keys())
    out['project_count'] = len(projects)

    real = os.path.realpath(cwd) if cwd else os.path.realpath(os.getcwd())
    entry = projects.get(cwd) if cwd else None
    entry = entry or projects.get(real)
    if isinstance(entry, dict):
        pe = {}
        for k in ('enableAllProjectMcpServers', 'hasTrustDialogAccepted'):
            if k in entry:
                pe[k] = entry[k]
        for k in ('enabledMcpjsonServers', 'disabledMcpjsonServers'):
            if entry.get(k):
                pe[k] = entry[k]
        pe['mcpServers'] = sorted((entry.get('mcpServers') or {}).keys())
        out['project_entry'] = pe

    for proj, v in projects.items():
        if isinstance(v, dict) and server in (v.get('mcpServers') or {}):
            # The hook matches project keys literally against the raw cwd (not
            # realpath), so judge the marker the same way to avoid a false 'hit'.
            marker = ''
            if cwd and proj == cwd:
                marker = 'matches-cwd'
            elif cwd and cwd.startswith(proj.rstrip('/') + '/'):
                marker = 'ancestor-of-cwd (hook walks up literally)'
            out['scoped_under'].append({'dir': proj, 'marker': marker})
    return out


def _mcp_diag_project_mcp_json(cwd):
    """Project .mcp.json up the cwd chain — the hook does NOT read these."""
    found = []
    try:
        start = Path(cwd or os.getcwd()).resolve()
    except Exception:
        return found
    seen = set()
    for d in [start] + list(start.parents):
        f = d / '.mcp.json'
        if f in seen or not f.is_file():
            continue
        seen.add(f)
        try:
            data = json.loads(f.read_text(encoding='utf-8'))
            m = data.get('mcpServers')
            if not isinstance(m, dict):
                m = data if isinstance(data, dict) else {}
            names = sorted(m.keys())
        except Exception:
            names = []
        found.append({'file': str(f), 'servers': names[:40]})
    return found


def _mcp_diag_scrub(text):
    def _strip(m):
        return re.sub(r'://[^/@\s]*@', '://', m.group(1)) + '…'
    lines, dropped = [], 0
    for line in str(text).splitlines():
        if _MCP_DIAG_SECRETISH.search(line):
            dropped += 1
            continue
        line = re.sub(r'([a-zA-Z][a-zA-Z0-9+.-]*://[^/?#\s]+)[^\s]*', _strip, line)
        lines.append(line[:220])
    if dropped:
        lines.append('[%d credential-bearing line(s) suppressed]' % dropped)
    return '\n'.join(lines[:60])


def _mcp_diag_claude_mcp_get(server):
    try:
        p = subprocess.run(['claude', 'mcp', 'get', server],
                           capture_output=True, text=True, timeout=45)
        return _mcp_diag_scrub((p.stdout or '') + (p.stderr or ''))
    except Exception as exc:
        return '<claude mcp get failed: %s>' % type(exc).__name__


def _mcp_diag_error_log_tail():
    if not ERROR_LOG.exists():
        return []
    try:
        lines = ERROR_LOG.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception:
        return []
    sig = re.compile(r'(?i)mcp|fingerprint|resolve|connector|plugin')
    tail = [l[:300] for l in lines if sig.search(l)][-15:]
    return _mcp_diag_scrub('\n'.join(tail)).splitlines()


def _diag_scrub_value(v):
    """Strip URL userinfo (proxy creds) and drop a whole credential-bearing token
    before a raw value (env var, ps flag) goes into the report."""
    s = str(v)
    if _MCP_DIAG_SECRETISH.search(s):
        return '<redacted>'
    s = re.sub(r'(://)[^/@\s]*@', r'\1', s)
    return s[:200]


def _diag_summarize_entry(entry):
    """Compact, secret-free summary of one MCP server config entry."""
    if not isinstance(entry, dict):
        return str(entry)[:80]
    bits = []
    if entry.get('type'):
        bits.append(str(entry['type']))
    if entry.get('url'):
        bits.append(_mcp_diag_host_of(entry['url']) + ('…' if '?' in str(entry['url']) else ''))
    if entry.get('command'):
        cmd = str(entry['command'])
        bits.append('cmd=%s' % os.path.basename(cmd))
        if os.path.isabs(cmd):
            bits.append('exists' if os.path.exists(cmd) else 'MISSING-ON-DISK')
    if isinstance(entry.get('args'), list) and entry['args']:
        bits.append('args=%d' % len(entry['args']))
    if isinstance(entry.get('env'), dict):
        bits.append('env=%d keys' % len(entry['env']))
    if isinstance(entry.get('headers'), dict):
        bits.append('headers=%d keys' % len(entry['headers']))
    return ', '.join(bits) or '<empty>'


def _diag_servers_from_json(path):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    m = data.get('mcpServers')
    if isinstance(m, dict):
        return m
    # some plugins ship an unwrapped {name: entry} map at the root
    if data and all(isinstance(v, dict) and ('command' in v or 'url' in v) for v in data.values()):
        return data
    return None


def _diag_plugin_dirs():
    dirs = []
    root = _DIAG_CLAUDE_DIR / 'plugins'
    try:
        data = json.loads((root / 'installed_plugins.json').read_text(encoding='utf-8'))
        for full_name, entries in (data.get('plugins') or {}).items():
            for e in (entries or []):
                ip = e.get('installPath') if isinstance(e, dict) else None
                if ip:
                    dirs.append(('installed:%s' % full_name, Path(ip)))
    except Exception:
        pass
    try:
        for marketplace in (root / 'cache').iterdir():
            if not marketplace.is_dir():
                continue
            for plugin in marketplace.iterdir():
                if not plugin.is_dir():
                    continue
                for version in plugin.iterdir():
                    if version.is_dir():
                        dirs.append(('cache:%s/%s/%s' % (marketplace.name, plugin.name, version.name), version))
    except Exception:
        pass
    return dirs


def _diag_mcp_config_paths_from_ps(ps_out):
    paths = []
    for line in ps_out.splitlines():
        if 'claude' not in line or 'mcp-diagnostic' in line:
            continue
        for m in re.finditer(r'--mcp-config[= ]+("[^"]+"|\'[^\']+\'|\S+)', line):
            paths.append(m.group(1).strip('"\''))
    return list(dict.fromkeys(paths))


def _diag_inventory(cwd, ps_out):
    """Every MCP server source on disk — the ones the hook reads AND the ones it
    does NOT (project .mcp.json, plugin dirs, --mcp-config) — each summarized."""
    def _summ(m):
        return {k: _diag_summarize_entry(v) for k, v in (m or {}).items()}

    inv = []
    try:
        cfg = json.loads(CLAUDE_MCP_CONFIG_PATH.read_text(encoding='utf-8'))
    except Exception:
        cfg = None
    if isinstance(cfg, dict):
        if isinstance(cfg.get('mcpServers'), dict) and cfg['mcpServers']:
            inv.append({'source': '~/.claude.json (user)', 'file': str(CLAUDE_MCP_CONFIG_PATH),
                        'servers': _summ(cfg['mcpServers'])})
        for proj, v in (cfg.get('projects') or {}).items():
            m = v.get('mcpServers') if isinstance(v, dict) else None
            if isinstance(m, dict) and m:
                inv.append({'source': '~/.claude.json project[%s]' % proj,
                            'file': str(CLAUDE_MCP_CONFIG_PATH), 'servers': _summ(m)})
    seen = set()
    try:
        start = Path(cwd or os.getcwd()).resolve()
        for d in [start] + list(start.parents):
            f = d / '.mcp.json'
            if f in seen or not f.is_file():
                continue
            seen.add(f)
            m = _diag_servers_from_json(f)
            if m:
                inv.append({'source': 'project .mcp.json (hook does NOT read)',
                            'file': str(f), 'servers': _summ(m)})
    except Exception:
        pass
    for label, d in _diag_plugin_dirs():
        for cand in (d / '.mcp.json', d / '.claude-plugin' / 'plugin.json'):
            if not cand.is_file():
                continue
            m = _diag_servers_from_json(cand)
            if m:
                inv.append({'source': 'plugin %s' % label, 'file': str(cand), 'servers': _summ(m)})
    for p in _diag_mcp_config_paths_from_ps(ps_out):
        path = Path(os.path.expanduser(p))
        is_file = path.is_file()
        m = _diag_servers_from_json(path) if is_file else None
        # --mcp-config can be inline JSON (secret-bearing), not a path — don't echo it.
        shown = str(path) if is_file else '<inline or non-file --mcp-config>'
        inv.append({'source': '--mcp-config (hook reads via launch_config)', 'file': shown, 'servers': _summ(m)})
    return inv


def _diag_norm(s):
    return re.sub(r'[^a-z0-9]', '', str(s).lower())


def _diag_target_appears(server, inventory):
    exact, near = [], []
    ns = _diag_norm(server)
    for item in inventory:
        for k, summ in (item.get('servers') or {}).items():
            row = {'source': item['source'], 'file': item['file'], 'name': k, 'cfg': summ}
            if k == server:
                exact.append(row)
            elif ns and (ns in _diag_norm(k) or _diag_norm(k) in ns):
                near.append(row)
    return {'exact': exact, 'near': near}


def _diag_unbound_client():
    out = {}
    base = Path.home() / '.unbound'
    try:
        c = json.loads((base / 'config.json').read_text(encoding='utf-8'))
        for k in ('email', 'org_name', 'gateway_url', 'base_url', 'frontend_url', 'discovery_local_dir'):
            if c.get(k):
                out[k] = c[k]
        out['api_key'] = 'present' if c.get('api_key') else 'absent'
    except Exception:
        out['config'] = 'missing-or-unreadable'
    for fname in ('identity.json', 'discovery-cache.json'):
        p = base / fname
        try:
            out[fname] = p.stat().st_size if p.is_file() else 'missing'
        except Exception:
            out[fname] = 'unreadable'
    return out


def _diag_claude_mcp_list():
    try:
        p = subprocess.run(['claude', 'mcp', 'list'], capture_output=True, text=True, timeout=45)
        return _mcp_diag_scrub((p.stdout or '') + (p.stderr or ''))
    except Exception as exc:
        return '<claude mcp list failed: %s>' % type(exc).__name__


def _diag_plugin_registries():
    out = {}
    root = _DIAG_CLAUDE_DIR / 'plugins'
    for f in ('installed_plugins.json', 'known_marketplaces.json'):
        try:
            data = json.loads((root / f).read_text(encoding='utf-8'))
            keys = data.get('plugins') if f.startswith('installed') else data
            out[f] = sorted((keys or {}).keys())
        except Exception:
            out[f] = 'missing-or-unreadable'
    out['cache_dir'] = str(root / 'cache') if (root / 'cache').is_dir() else 'missing'
    return out


_DIAG_SECRET_VALUE = re.compile(
    r'^(sk-|sk_live_|sk_test_|ghp_|gho_|ghu_|ghs_|github_pat_|xox[baprs]-'
    r'|glpat-|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,})'
    r'|^[A-Za-z0-9+_=-]{32,}$'
)


def _diag_scrub_cmdline(tokens, cap=1500):
    """Scrub a command line token-by-token so one secret redacts alone."""
    try:
        out = []
        redact_next = False
        for t in tokens:
            s = str(t)
            if redact_next and not s.startswith('-'):
                out.append('<redacted>')
                redact_next = False
                continue
            redact_next = False
            candidates = [s.strip('\'"')]
            if '=' in s:
                candidates.append(s.split('=', 1)[1].strip('\'"'))
            keyword_hit = _MCP_DIAG_SECRETISH.search(s)
            if keyword_hit or any(_DIAG_SECRET_VALUE.match(c) for c in candidates):
                out.append('<redacted>')
                redact_next = bool(keyword_hit) and s.startswith('-') and '=' not in s
                continue
            out.append(re.sub(r'(://)[^/@\s]*@', r'\1', s)[:600])
        return ' '.join(out)[:cap]
    except Exception:
        return None


def _diag_launch_flags(ps_out):
    """Full scrubbed command line of every running claude process."""
    rows = []
    for l in ps_out.splitlines():
        if 'claude' not in l or 'mcp-diagnostic' in l or ' grep ' in l:
            continue
        parts = l.split(None, 2)
        args = parts[2] if len(parts) == 3 else l
        if 'claude' not in args:
            continue
        row = _diag_scrub_cmdline(args.split())
        if row:
            rows.append(row)
    return rows[:10]


def _diag_launch_argv():
    """The session's own Claude ancestor argv, scrubbed."""
    try:
        found = _claude_launch_argv()
        if not found:
            return None
        return _diag_scrub_cmdline(found[1], cap=6000)
    except Exception:
        return None


def _mcp_diag_worktrees(server, cwd):
    """The .git pointer for cwd and each worktree root's project-entry servers."""
    out = {'git_root': None, 'dot_git': None, 'roots': []}
    try:
        start = os.path.abspath(cwd) if cwd else os.getcwd()
        root = _find_git_root(start)
        out['git_root'] = root
        if not root:
            return out
        dot_git = Path(root) / '.git'
        out['dot_git'] = (dot_git.read_text(encoding='utf-8').strip()[:300]
                          if dot_git.is_file() else '<directory>')
        try:
            projects = json.loads(
                CLAUDE_MCP_CONFIG_PATH.read_text(encoding='utf-8')).get('projects') or {}
        except Exception:
            projects = {}
        for r in _git_worktree_roots(start):
            entry = projects.get(r.replace('\\', '/').rstrip('/'))
            servers = entry.get('mcpServers') if isinstance(entry, dict) else None
            names = sorted(servers.keys()) if isinstance(servers, dict) else []
            out['roots'].append(
                {'root': r, 'servers': names[:20], 'has_target': server in names})
    except Exception:
        pass
    return out


def _diag_settings_registration(cwd):
    out = []
    for s in _diag_settings_files(cwd):
        try:
            if not s.is_file():
                continue
            data = json.loads(s.read_text(encoding='utf-8'))
        except Exception:
            continue
        hooks = data.get('hooks') or {}
        if not hooks:
            continue
        events, cmds = [], []
        for event, entries in hooks.items():
            events.append('%s%s' % (event, ' [unbound]' if 'unbound' in json.dumps(entries) else ''))
            for entry in (entries if isinstance(entries, list) else []):
                for hk in ((entry or {}).get('hooks') or []):
                    cmd = (hk or {}).get('command')
                    if isinstance(cmd, str):
                        cmds.append(_diag_scrub_value(cmd))
        out.append({'file': str(s), 'events': events, 'commands': sorted(set(cmds))})
    return out


def _diag_run1(cmd, timeout=15):
    try:
        return (subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout or '').strip()
    except Exception:
        return ''


def _build_mcp_diagnostic(server, cwd):
    out = _diag_run1(['claude', '--version'], 20)
    claude_version = out.splitlines()[0] if out else '<not on PATH>'
    abs_cwd = os.path.abspath(cwd) if cwd else os.path.abspath(os.getcwd())
    try:
        real_cwd = os.path.realpath(abs_cwd)
    except Exception:
        real_cwd = None
    try:
        ps_out = subprocess.run(['ps', '-eo', 'pid,ppid,args'],
                                capture_output=True, text=True, timeout=20).stdout or ''
    except Exception:
        ps_out = ''
    env_vars = {v: _diag_scrub_value(os.environ[v]) for v in (
        'CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_ENTRYPOINT', 'ANTHROPIC_BASE_URL',
        'ANTHROPIC_API_URL', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY') if os.environ.get(v)}
    inventory = _diag_inventory(cwd, ps_out)
    return {
        'version': MCP_DIAG_VERSION,
        'server': server,
        'cwd': cwd,
        'cwd_resolved': real_cwd,
        'cwd_is_symlink': bool(real_cwd and real_cwd != abs_cwd),
        'home': str(Path.home()),
        'user': os.environ.get('USER') or os.environ.get('LOGNAME') or '?',
        'hostname': _diag_run1(['hostname'])[:80],
        'platform': sys.platform,
        'python': sys.version.split()[0],
        'claude_version': claude_version,
        'claude_path': _diag_run1(['bash', '-lc', 'command -v claude'], 20),
        'env_vars': env_vars,
        'hook': _mcp_diag_hook_info(cwd),
        'hook_registration': _diag_settings_registration(cwd),
        'resolution': _mcp_diag_resolution(server, cwd),
        'worktrees': _mcp_diag_worktrees(server, cwd),
        'launch_argv': _diag_launch_argv(),
        'claude_json': _mcp_diag_claude_json(server, cwd),
        'project_mcp_json': _mcp_diag_project_mcp_json(cwd),
        'mcp_inventory': inventory,
        'target_appears': _diag_target_appears(server, inventory),
        'unbound_client': _diag_unbound_client(),
        'plugin_registries': _diag_plugin_registries(),
        'launch_flags': _diag_launch_flags(ps_out),
        'claude_mcp_list': _diag_claude_mcp_list(),
        'claude_mcp_get': _mcp_diag_claude_mcp_get(server),
        'error_log_tail': _mcp_diag_error_log_tail(),
    }


def _upload_mcp_diagnostic(payload, api_key):
    try:
        body = json.dumps({'diagnostic': payload, 'hook_source': 'claude-code'})
    except Exception as exc:
        log_error('mcp diagnostic serialize failed: %s' % exc, 'mcp_server')
        return
    proc = None
    try:
        proc = subprocess.Popen(
            ['curl', '-fsSL', '--max-time', '30', '-X', 'POST',
             '-H', 'Authorization: Bearer %s' % api_key,
             '-H', 'Content-Type: application/json',
             '--data-binary', '@-',
             '%s/v1/hooks/mcp-diagnostics' % UNBOUND_GATEWAY_URL],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.communicate(body.encode(), timeout=35)
        # curl -f exits non-zero on HTTP/transfer errors without raising.
        if proc.returncode:
            log_error('mcp diagnostic upload: curl exit %s' % proc.returncode, 'mcp_server')
    except Exception as exc:
        # Don't leave an orphaned curl on timeout — kill and reap it.
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
                proc.communicate()
            except Exception:
                pass
        log_error('mcp diagnostic upload failed: %s' % exc, 'mcp_server')


def _render_mcp_diagnostic(d):
    """Flatten the diagnostic dict into a plain-text report (consumed by an agent,
    so structure isn't needed). Kept simple so new sections are one append away."""
    L = []

    def head(t):
        L.append('\n=== %s ===' % t)

    def kv(k, v):
        L.append('%-18s: %s' % (k, v))

    L.append('unbound-mcp-diag %s   server=%s' % (d.get('version'), d.get('server')))
    head('environment')
    for k in ('cwd', 'cwd_resolved', 'cwd_is_symlink', 'home', 'user', 'hostname',
              'platform', 'python', 'claude_version', 'claude_path'):
        kv(k, d.get(k))
    for k, v in (d.get('env_vars') or {}).items():
        kv(k, v)

    head('unbound hook')
    hk = d.get('hook') or {}
    run = hk.get('running') or {}
    kv('running', '%s  (sha256 %s)' % (run.get('path'), (run.get('sha256') or '')[:16]))
    for ih in (hk.get('installed') or []):
        kv('installed', '%s  (sha256 %s)' % (ih.get('path'), (ih.get('sha256') or '')[:16]))
    kv('registration', hk.get('registration'))

    head('hook registration in settings')
    for row in (d.get('hook_registration') or []):
        L.append('  %s -> %s' % (row.get('file'), ', '.join(row.get('events') or [])))
        for c in (row.get('commands') or []):
            L.append('      cmd: %s' % c)

    head('~/.claude.json')
    cj = d.get('claude_json') or {}
    for k in ('present', 'size', 'mtime', 'parse_ok', 'project_count'):
        kv(k, cj.get(k))
    kv('top-level servers', ', '.join(cj.get('top_level_servers') or []) or '<none>')
    if cj.get('project_entry'):
        kv('project entry', json.dumps(cj['project_entry']))
    for su in (cj.get('scoped_under') or []):
        L.append('  scoped under %s   %s' % (su.get('dir'), su.get('marker') or ''))

    head('resolution replay (authoritative)')
    res = d.get('resolution') or {}
    for k, v in (res.get('sources') or {}).items():
        kv('  ' + k, v)
    kv('resolved', res.get('resolved'))
    kv('via', res.get('via'))
    if res.get('config'):
        kv('config', json.dumps(res['config']))

    head('git worktree chain (claude unions local scope across these roots)')
    wt = d.get('worktrees') or {}
    kv('git_root', wt.get('git_root'))
    kv('.git', wt.get('dot_git'))
    for r in (wt.get('roots') or []):
        mark = '   <-- has target' if r.get('has_target') else ''
        L.append('  %s   servers=[%s]%s' % (
            r.get('root'), ', '.join(r.get('servers') or []), mark))

    head('MCP server inventory (every source on disk)')
    for it in (d.get('mcp_inventory') or []):
        L.append('  %s   (%s)' % (it.get('source'), it.get('file')))
        for name, summ in (it.get('servers') or {}).items():
            L.append('      %-42s %s' % (name, summ))

    head('where does the target appear')
    ta = d.get('target_appears') or {}
    for kind in ('exact', 'near'):
        for e in (ta.get(kind) or []):
            L.append('  %-5s %s   in %s   [%s]' % (kind, e.get('name'), e.get('source'), e.get('cfg')))

    head('unbound client state (~/.unbound)')
    for k, v in (d.get('unbound_client') or {}).items():
        kv('  ' + k, v)

    head('plugin registries')
    for k, v in (d.get('plugin_registries') or {}).items():
        kv('  ' + k, v if isinstance(v, str) else ', '.join(v))

    head('claude launch command (session ancestor)')
    L.append(d.get('launch_argv') or '<not found>')

    head('claude processes (full scrubbed command lines)')
    for f in (d.get('launch_flags') or []):
        L.append('  %s' % f)

    head('project .mcp.json files (hook does NOT read)')
    for pj in (d.get('project_mcp_json') or []):
        L.append('  %s -> %s' % (pj.get('file'), ', '.join(pj.get('servers') or [])))

    head('claude mcp list')
    L.append(d.get('claude_mcp_list') or '<none>')
    head('claude mcp get %s' % d.get('server'))
    L.append(d.get('claude_mcp_get') or '<none>')

    head('hook error.log (mcp-related)')
    for ln in (d.get('error_log_tail') or []):
        L.append('  %s' % ln)

    return '\n'.join(str(x) for x in L)


def _run_mcp_diagnostic_cli():
    server = os.environ.get('UNBOUND_DIAG_SERVER') or ''
    cwd = os.environ.get('UNBOUND_DIAG_CWD') or None
    api_key = os.environ.get('UNBOUND_DIAG_API_KEY') or get_api_key()
    if not server or not api_key:
        return
    try:
        report = _render_mcp_diagnostic(_build_mcp_diagnostic(server, cwd))
    except Exception as exc:
        log_error('mcp diagnostic build failed: %s' % exc, 'mcp_server')
        return
    if len(report) > MCP_DIAG_MAX_REPORT_CHARS:
        report = report[:MCP_DIAG_MAX_REPORT_CHARS] + '\n… [report truncated]'
    _upload_mcp_diagnostic({'report': report, 'server': server, 'cwd': cwd or ''}, api_key)


def _mcp_diag_stamp_path(server, cwd):
    key = hashlib.sha256(('%s\x00%s' % (server, cwd or '')).encode('utf-8', 'replace')).hexdigest()[:16]
    return MCP_DIAG_STAMP_DIR / key


def _mcp_diag_on_cooldown(server, cwd):
    try:
        stamp = _mcp_diag_stamp_path(server, cwd)
        return stamp.exists() and (time.time() - stamp.stat().st_mtime) < MCP_DIAG_COOLDOWN_SECONDS
    except Exception:
        return False


def _mcp_diag_mark_dispatched(server, cwd):
    try:
        MCP_DIAG_STAMP_DIR.mkdir(parents=True, exist_ok=True)
        _mcp_diag_stamp_path(server, cwd).write_text(str(int(time.time())), encoding='utf-8')
    except Exception:
        pass


def _dispatch_mcp_diagnostic(server_name, cwd, api_key):
    """Re-invoke the diagnostic detached so the slow `claude mcp` CLI stays off
    the blocking PreToolUse path. Frozen builds drive the binary's
    `mcp-diagnostic` subcommand; the .py hook re-invokes itself."""
    if not server_name or not api_key:
        return
    if RUNNING_FROZEN:
        # sys.executable is the frozen unbound-hook binary itself.
        cmd = [sys.executable, 'mcp-diagnostic', os.environ.get('UNBOUND_HOOK_TOOL') or 'claude-code']
    else:
        try:
            script = os.path.abspath(__file__)
        except Exception:
            return
        if not os.path.isfile(script):
            return
        cmd = [sys.executable, script, '--mcp-diagnostic']
    if _mcp_diag_on_cooldown(server_name, cwd):
        return
    # Capture Claude's launch context HERE (in-process, before the child detaches
    # and loses it) and forward it so the replay sees the real --plugin-*/--mcp-config.
    child_env = {'UNBOUND_DIAG_SERVER': server_name,
                 'UNBOUND_DIAG_CWD': cwd or '',
                 'UNBOUND_DIAG_API_KEY': api_key}
    try:
        found = _claude_launch_argv()
        if found:
            pid, argv = found
            child_env['UNBOUND_DIAG_LAUNCH_PID'] = str(pid)
            child_env['UNBOUND_DIAG_LAUNCH_ARGV'] = json.dumps(argv)
    except Exception:
        pass
    try:
        popen_kwargs = {
            'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL,
            'stdin': subprocess.DEVNULL, 'close_fds': True,
            'env': {**os.environ, **child_env},
        }
        if os.name == 'nt':
            popen_kwargs['creationflags'] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs['start_new_session'] = True
        subprocess.Popen(cmd, **popen_kwargs)
        # Stamp only after a successful spawn, so a failed dispatch doesn't mute 6h.
        _mcp_diag_mark_dispatched(server_name, cwd)
    except Exception as exc:
        log_error('mcp diagnostic dispatch failed for %s: %s' % (server_name, exc), 'mcp_server')


def _dispatch_discovery() -> None:
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

    if len(sys.argv) > 1 and sys.argv[1] == '--mcp-diagnostic':
        _run_mcp_diagnostic_cli()
        return

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

        # SessionStart fires once per session — TTL gate for discovery and housekeeping
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

            # Allowed but with hook output to emit (e.g. the spend-limit
            # alert-threshold warning riding additionalContext/systemMessage):
            # log the event, then print the response instead of the default
            # suppressOutput so Claude Code surfaces the warning.
            if response:
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