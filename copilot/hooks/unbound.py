#!/usr/bin/env python3
"""
Real-time GitHub Copilot hook event processor.
Reads JSON events from stdin, appends to agent-audit.log, and processes them on stop events.
"""

import sys
import json
import os
import platform
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import tempfile
import time
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

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

# Frozen-binary mode (the PyInstaller-packaged `unbound-hook` CLI). The frozen
# binary must make ZERO network calls other than the backend/gateway APIs:
# self-update is owned by the MDM package (never in-place), and discovery runs
# from the locally installed binary instead of a GitHub-fetched install.sh.
# UNBOUND_HOOK_FROZEN=1 lets tests exercise these gates without freezing.
RUNNING_FROZEN = bool(getattr(sys, "frozen", False)) or os.environ.get("UNBOUND_HOOK_FROZEN") == "1"
FROZEN_DISCOVERY_BIN = "/opt/unbound/current/unbound-discovery/unbound-discovery"

# Copilot tool names (VS Code agent mode + CLI) translated to the canonical
# gateway vocabulary. Covers both surfaces: VS Code's model-facing tool names
# and the CLI's shell/glob/grep/view/write tools. Anything not listed here and
# not an MCP tool falls through map_copilot_tool's afterMCPExecution branch and
# is scored by the action-based rubric (reads/benign stay low).
SHELL_TOOLS = {'bash', 'shell', 'run_in_terminal', 'runInTerminal', 'terminal', 'send_to_terminal'}
READ_TOOLS = {
    'read_file', 'readFile', 'view', 'cat', 'list_dir', 'listDirectory',
    'read_project_structure', 'read_notebook_cell_output',
    'get_notebook_summary', 'copilot_getNotebookSummary', 'view_image',
}
WRITE_TOOLS = {
    'create_file', 'create', 'createFile', 'write', 'write_file', 'new_file',
    'create_directory',
}
EDIT_TOOLS = {
    'str_replace', 'edit', 'edit_file', 'editFile', 'edit_files', 'apply_patch',
    'insert_edit', 'insert_edit_into_file', 'replace_string_in_file',
    'multi_replace_string_in_file', 'edit_notebook_file',
}

# Copilot terminal/search tools mapped to a synthetic shell command for analytics.
# `x or ''` (not `.get(k, '')`) so a present-but-None value coerces to ''.
TERMINAL_LIKE_TOOLS = {
    'get_terminal_output':   lambda a: 'true',
    'kill_terminal':         lambda a: 'true',
    'terminal_last_command': lambda a: 'true',
    'terminal_selection':    lambda a: 'true',
    'get_task_output':       lambda a: 'true',
    'get_changed_files':     lambda a: 'git status',
    'grep_search':           lambda a: f"grep {a.get('query') or ''} {a.get('includePattern') or ''}".strip(),
    'grep':                  lambda a: f"grep {a.get('pattern') or a.get('query') or ''}".strip(),
    'file_search':           lambda a: f"find {a.get('query') or ''}".strip(),
    'glob':                  lambda a: f"find {a.get('pattern') or a.get('query') or ''}".strip(),
}

# Copilot orchestration / planning / UI / memory tools — no security-relevant
# action of their own; dropped (not emitted as analytics), the same way Claude
# Code's Task/Agent tools are not scored. A subagent's real actions are reported
# and scored as their own tool calls, so scoring the wrapper double-counts.
INTERNAL_TOOLS = {
    # subagents / agent control
    'execution_subagent', 'explore_subagent', 'search_subagent', 'runSubagent',
    'run_task', 'switch_agent',
    # planning / intent / memory / tool discovery
    'manage_todo_list', 'report_intent', 'memory', 'resolve_memory_file_uri',
    'tool_search',
    # VS Code editor meta / UI confirmations
    'run_vscode_command', 'get_vscode_api', 'get_project_setup_info',
    'vscode_askQuestions', 'vscode_get_confirmation',
    'vscode_get_confirmation_with_options', 'vscode_get_terminal_confirmation',
}
ALLOWED_NON_MCP_HOOK_NAMES = {'Bash', 'Read', 'Write', 'Edit'}  # MCP tools (mcp*) are always checked separately
NATIVE_FILE_TOOLS = {'Read', 'Write', 'Edit'}
POLICY_CACHE_FILE = LOG_DIR / ".policy_cache.json"
CACHE_TTL_SECONDS = 300
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'
PRETOOL_USER_MESSAGES_LIMIT = 5
AUDIT_LOG_TOTAL_LIMIT = 100
# Sentinel hook_event_name for the agent-audit.log rows that record which toolCallIds
# were already forwarded, so a later Stop sends only new tool calls. Not a real Copilot
# event: every existing reader filters by its own event name and skips it, and
# cleanup_old_logs prunes it per-session like any other row (no new file, no new state).
FORWARDED_TOOLS_EVENT = '_unbound_forwarded'

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
    """Manage log file size by keeping only the most recent session's entries once the
    audit log exceeds AUDIT_LOG_TOTAL_LIMIT. The _unbound_forwarded watermark markers are
    handled separately: excluded from session grouping (their key is transcript-derived,
    not the payload session_id, so they must not be mistaken for a distinct session) and
    always retained (last few sessions' consolidated markers), so a long session's dedup
    state is never evicted."""
    logs = load_existing_logs()

    if len(logs) <= AUDIT_LOG_TOTAL_LIMIT:
        return

    def _is_marker(log):
        return log.get('event', {}).get('hook_event_name') == FORWARDED_TOOLS_EVENT

    markers = [log for log in logs if _is_marker(log)]
    entries = [log for log in logs if not _is_marker(log)]

    session_order = []
    seen_sessions = set()
    for log in entries:
        session_id = log.get('event', {}).get('session_id')
        if session_id and session_id not in seen_sessions:
            session_order.append(session_id)
            seen_sessions.add(session_id)

    if len(session_order) > 1:
        most_recent_session = session_order[-1]
        kept = [log for log in entries
                if log.get('event', {}).get('session_id') == most_recent_session]
    elif len(entries) > AUDIT_LOG_TOTAL_LIMIT:
        kept = entries[-AUDIT_LOG_TOTAL_LIMIT:]
    else:
        kept = entries
    # Always keep the watermark markers (one small consolidated row per session; the
    # active session's is always the newest), bounded to the most recent sessions.
    save_logs(kept + markers[-20:])


def stop_session_key(event):
    """Stable per-session key for the forwarded-tool watermark. Derived from the transcript
    path FIRST -- it is constant for a session and present on every Stop that builds an
    exchange -- so the key never flips between Stops that do and don't carry session_id
    (which would split the watermark and resend the whole history). Falls back to
    session_id only when there is no transcript path."""
    tp = event.get('transcript_path')
    if tp:
        p = Path(tp)
        return p.parent.name if p.stem == 'events' else p.stem
    return event.get('session_id') or event.get('sessionId')


def get_forwarded_state(session_id):
    """(forwarded toolCallIds, last-sent text signature) for this session, from the
    consolidated audit-log marker. Lets each Stop send only new tool calls, and skip a
    Stop whose text+tools are both unchanged from the last send.

    This is a best-effort PAYLOAD OPTIMIZATION, not a security control: the audit log is
    user-writable, so a local process could forge `_unbound_forwarded` rows to omit tools
    from the exchange. That's not a new exposure -- the hook already runs as the user and
    the whole endpoint is untrusted; the gateway/proxy plane and its server-side dedup are
    the integrity backstop. Keyed on bare ids only for that reason (never trusted for
    enforcement)."""
    sent, last_sig = set(), None
    if not session_id:
        return sent, last_sig
    for log in load_existing_logs():
        event = log.get('event', {})
        if event.get('hook_event_name') != FORWARDED_TOOLS_EVENT:
            continue
        if event.get('session_id') != session_id:
            continue
        ids = event.get('forwarded_tool_ids')
        if isinstance(ids, list):
            sent.update(ids)
        sig = event.get('text_sig')
        if sig:
            last_sig = sig
    return sent, last_sig


def record_forwarded_tool_ids(session_id, tool_ids, text_sig=None):
    """Persist the forwarded toolCallIds + the last-sent text signature for this session as
    a SINGLE consolidated marker, rewritten (re-appended last) on each Stop. Keeping one
    cumulative marker -- rather than one append per Stop -- means it survives
    cleanup_old_logs' last-N trim in a long session, so old ids aren't forgotten and their
    tool calls resent. Called after a successful send; a failed send simply resends next
    Stop (the backend dedups)."""
    if not session_id:
        return
    merged = set(tool_ids or ())
    kept = []
    for log in load_existing_logs():
        ev = log.get('event', {})
        if (ev.get('hook_event_name') == FORWARDED_TOOLS_EVENT
                and ev.get('session_id') == session_id):
            ids = ev.get('forwarded_tool_ids')
            if isinstance(ids, list):
                merged.update(ids)
            if text_sig is None:
                text_sig = ev.get('text_sig')  # carry forward the last known text sig
            continue  # drop the old marker; a fresh consolidated one is appended below
        kept.append(log)
    kept.append({
        'timestamp': datetime.now().astimezone().isoformat().replace('+00:00', 'Z'),
        'event': {
            'hook_event_name': FORWARDED_TOOLS_EVENT,
            'session_id': session_id,
            'forwarded_tool_ids': sorted(merged),
            'text_sig': text_sig,
        },
    })
    save_logs(kept)


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


def get_last_user_prompt_timestamp_for_session(session_id):
    """Latest UserPromptSubmit audit-log timestamp; turn start."""
    if not session_id:
        return None
    found = None
    for log in load_existing_logs():
        event = log.get('event', {})
        if event.get('hook_event_name') != 'UserPromptSubmit':
            continue
        if event.get('session_id') != session_id:
            continue
        ts = log.get('timestamp')
        if ts:
            found = ts
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
    # The Copilot CLI emits Claude-style canonical names directly (Read / Write
    # / Edit / Bash); only the VS Code agent uses the lowercase vocabulary in
    # the sets below. Pass canonical names through, otherwise every CLI
    # native-file tool call resolves to '' and is silently skipped — which
    # disabled all native-file (read/write/edit) policy enforcement for the CLI.
    if raw in ALLOWED_NON_MCP_HOOK_NAMES:
        return raw
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


# VS Code stable + Insiders "Code/User" dirs for the current OS. Uses
# platform.system() rather than sys.platform/os.name so static checkers do not
# narrow it to one OS and flag the other branches as unreachable.
def _vscode_user_dirs():
    system = platform.system()
    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            return []
        base = Path(appdata)
    elif system == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path.home() / ".config"
    return [base / "Code" / "User", base / "Code - Insiders" / "User"]


# Plugin-bundle `.mcp.json` paths: VS Code agentPlugins + Copilot CLI installed-plugins.
# Bundles ship MCP servers here and never merge them into mcp.json, so scan them or the
# server resolves to null. Not capped — dropping a config would leave its server
# unresolved and silently skip the fingerprint sanction check (fail-open).
def _plugin_mcp_config_paths(home):
    paths = []
    for user_dir in _vscode_user_dirs():
        try:
            paths.extend(sorted((user_dir.parent / "agentPlugins").glob("*/*/*/.mcp.json")))
        except OSError:
            pass
    try:
        paths.extend(sorted((home / ".copilot" / "installed-plugins").glob("*/.mcp.json")))
    except OSError:
        pass
    return paths


# All Copilot MCP config locations, ordered for the last-wins merge in
# read_copilot_mcp_servers: workspace (untrusted) < plugins < trusted (user/global/CLI).
def _copilot_mcp_config_paths(cwd=None):
    home = Path.home()

    workspace = []
    if cwd:
        workspace.append(Path(cwd) / ".vscode" / "mcp.json")
        workspace.append(Path(cwd) / ".mcp.json")

    trusted = []
    for user_dir in _vscode_user_dirs():
        trusted.append(user_dir / "mcp.json")
        trusted.append(user_dir / "settings.json")
        profiles = user_dir / "profiles"
        try:
            if profiles.is_dir():
                for profile in sorted(profiles.iterdir()):
                    trusted.append(profile / "mcp.json")
        except OSError:
            pass
    trusted.append(home / ".config" / "github-copilot" / "intellij" / "mcp.json")
    trusted.append(home / ".copilot" / "mcp-config.json")

    return workspace + _plugin_mcp_config_paths(home) + trusted

_JSONC_COMMENT_RE = re.compile(
    r'"(?:\\.|[^"\\])*"'   # string literal (preserved)
    r'|//[^\n\r]*'         # line comment (dropped)
    r'|/\*.*?\*/',         # block comment (dropped)
    re.DOTALL,
)
_JSONC_TRAILING_COMMA_RE = re.compile(
    r'"(?:\\.|[^"\\])*"'   # string literal (preserved)
    r'|,(?=\s*[}\]])',     # trailing comma (dropped; brace left via lookahead)
    re.DOTALL,
)


def _strip_jsonc(text):
    # Two string-aware passes: both match string literals first so commas/comment
    # markers inside a quoted value are preserved verbatim. Pass 1 drops comments;
    # pass 2 drops trailing commas (now that any comment between a comma and its
    # brace is gone) via a lookahead that leaves the brace in place.
    def keep_strings(match):
        token = match.group(0)
        return token if token.startswith('"') else ''
    no_comments = _JSONC_COMMENT_RE.sub(keep_strings, text)
    return _JSONC_TRAILING_COMMA_RE.sub(keep_strings, no_comments)

def _parse_jsonc(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_strip_jsonc(text))
    except (json.JSONDecodeError, TypeError):
        return None


_TOKEN_RE = re.compile(
    r'sk-[A-Za-z0-9_\-]{6,}'
    r'|gh[opsur]_[A-Za-z0-9]{20,}'
    r'|github_pat_[A-Za-z0-9_]{20,}'
    r'|xox[baprs]-[A-Za-z0-9-]{10,}'
    r'|AKIA[0-9A-Z]{16}'
    r'|AIza[0-9A-Za-z_\-]{20,}'
)
_REDACTED = '***'


# Reduce any url to scheme://host[:port]/path — the only part the gateway
# fingerprints. Userinfo and query/fragment (which carry credentials, any
# scheme) are dropped; known token shapes in the path are masked.
def _redact_url(url):
    if not isinstance(url, str):
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return _REDACTED
    host = parts.hostname
    if not parts.scheme or not host:
        return _REDACTED
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urlunsplit((parts.scheme, netloc, _TOKEN_RE.sub(_REDACTED, parts.path), '', ''))


# Allowlist: forward only fingerprint-relevant args (urls, @npm packages); drop
# everything else so no secret can ride along. Urls are credential-stripped.
def _redact_args(args):
    if not isinstance(args, list):
        return args
    kept = []
    for arg in args:
        if not isinstance(arg, str):
            continue
        if '://' in arg:
            kept.append(_redact_url(arg))
        elif arg.startswith('@'):
            kept.append(arg)
    return kept


def _sanitize_mcp_server_fields(server, cwd=None):
    if not isinstance(server, dict):
        return None
    result = {}
    if server.get('url'):
        result['url'] = _redact_url(server['url'])
    if server.get('command'):
        result['command'] = server['command']
    if server.get('args'):
        result['args'] = _redact_args(server['args'])
    if server.get('type'):
        result['type'] = server['type']
    if not result:
        return None
    
    script_hash = _compute_script_hash(server.get('command'), server.get('args'), cwd)
    if script_hash:
        result['scriptHash'] = script_hash
    return result


_MCP_CONFIG_MAX_BYTES = 1_000_000


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


def read_copilot_mcp_servers(cwd=None):
    servers = {}
    plugin_names = set()
    # Exact set of plugin-bundle paths (not a path-substring guess, which could
    # misclassify a workspace file living under an agentPlugins-named dir).
    plugin_paths = set(_plugin_mcp_config_paths(Path.home()))
    for config_path in _copilot_mcp_config_paths(cwd):
        try:
            if not config_path.exists():
                continue
            if config_path.stat().st_size > _MCP_CONFIG_MAX_BYTES:
                continue
            with open(config_path, 'r', encoding='utf-8') as f:
                config = _parse_jsonc(f.read())
            if not isinstance(config, dict):
                continue
            raw = config.get('servers')
            if not isinstance(raw, dict):
                raw = config.get('mcpServers')
            if not isinstance(raw, dict):
                nested = config.get('mcp')
                raw = nested.get('servers') if isinstance(nested, dict) else None
            if not isinstance(raw, dict):
                continue
            is_plugin = config_path in plugin_paths
            # A plugin's relative command/script is relative to its own bundle,
            # not the workspace cwd — resolve script hashes against the bundle dir
            # so the fingerprint is correct (and not workspace-spoofable).
            base = config_path.parent if is_plugin else cwd
            for name, server in raw.items():
                fields = _sanitize_mcp_server_fields(server, base) or {}
                # Only two different plugin bundles claiming one name is ambiguous
                # (arbitrary winner); a user config overriding a plugin is expected.
                if is_plugin:
                    if name in plugin_names and servers.get(name) != fields:
                        log_error(
                            f"copilot mcp plugin name collision: {name}", 'mcp_plugin'
                        )
                    plugin_names.add(name)
                servers[name] = fields
        except Exception as e:
            # Missing files are skipped above without raising; this only fires on
            # a genuine read failure, so it's worth surfacing for diagnosis.
            log_error(f"copilot mcp config read failed path={config_path} err={e}", 'mcp_config')
            continue
    return servers


# Mirror Copilot's server-name sanitization for tool-name prefixes.
def _sanitize_copilot_server_name(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '-', name.replace('@', '-'))


# Only the delimiters Copilot actually emits: '-' (sanitized serverName-toolName)
# and '__' (Claude-style). The loose set previously here ('_', '/', '.') caused
# false-positive relabels of unrelated tools sharing a server's prefix.
_MCP_NAME_SEPARATORS = ('__', '-')
# A server name must be at least this long to anchor a bare-name match, so a
# one-char config entry can't swallow arbitrary tool names.
_MIN_MCP_SERVER_NAME = 2


# Resolve (server, tool, config) from a Copilot tool name. The mcp__ form is
# self-delimiting; the bare form is matched against configured server names.
# Matching is case-insensitive (Copilot lowercases nothing, configs vary case)
# and the longest server match wins; ties resolve to config/iteration order.
def detect_mcp_call(raw_tool, mcp_servers):
    if not raw_tool:
        return (None, None, None)

    if raw_tool.startswith('mcp__'):
        parts = raw_tool[len('mcp__'):].split('__', 1)
        server = parts[0]
        mcp_tool = parts[1] if len(parts) >= 2 else ''
        return (server, mcp_tool, mcp_servers.get(server))

    raw_lower = raw_tool.lower()
    best = None  # (matched_len, server_name, mcp_tool)
    for server_name in mcp_servers:
        for candidate in {server_name, _sanitize_copilot_server_name(server_name)}:
            if len(candidate) < _MIN_MCP_SERVER_NAME:
                continue
            cand_lower = candidate.lower()
            if raw_lower == cand_lower:
                mcp_tool = ''
            elif raw_lower.startswith(cand_lower):
                remainder = raw_tool[len(candidate):]
                sep = next((s for s in _MCP_NAME_SEPARATORS if remainder.startswith(s)), None)
                if sep is None:
                    continue
                mcp_tool = remainder[len(sep):]
            else:
                continue
            if best is None or len(candidate) > best[0]:
                best = (len(candidate), server_name, mcp_tool)

    if best is None:
        return (None, None, None)
    return (best[1], best[2], mcp_servers.get(best[1]))


# VS Code Copilot names MCP tools `mcp_<server>_<tool>` (single underscore,
# sanitized + truncated server) — unlike the Claude-style `mcp__server__tool` the
# gateway parses. Reverse-map the token to a configured server to forward its config.
def _vscode_sanitize(name):
    return re.sub(r'[^a-z0-9]', '_', name.lower())


def _vscode_server_aliases(server_name):
    """Sanitized full key + last path segment (e.g. 'io.github.github/github-mcp-server' -> 'github-mcp-server')."""
    aliases = {_vscode_sanitize(server_name), _vscode_sanitize(server_name.rsplit('/', 1)[-1])}
    return {a for a in aliases if len(a) >= _MIN_MCP_SERVER_NAME}


def _vscode_fingerprint_key(config):
    """Coarse identity used to decide if two configured servers are really the same
    one (mirrors the gateway's url-first / command+args fingerprint priority).
    Returns None when identity can't be established."""
    if not config:
        return None
    if config.get('url'):
        return ('url', config['url'])
    if config.get('command'):
        return ('cmd', config['command'], tuple(config.get('args') or []))
    return None


def _resolve_vscode_mcp(raw_tool, mcp_servers):
    """Resolve (server, tool, config) from a VS Code `mcp_<server>_<tool>` name,
    tolerating truncation; longest server-prefix wins, exact beats truncated on ties.
    If a *different* server also matches and can't be proven to be the same server
    (identical fingerprint config), the token is ambiguous -> unresolved (don't
    guess); same-config duplicates (e.g. two keys for one server) still resolve."""
    if not raw_tool.startswith('mcp_') or raw_tool.startswith('mcp__'):
        return (None, None, None)
    body = raw_tool[len('mcp_'):]
    body_lower = body.lower()
    segments = body.split('_')
    candidates = []  # (server_portion_len, exact_flag, server_name, tool)
    for server_name in mcp_servers:
        for alias in _vscode_server_aliases(server_name):
            if body_lower.startswith(alias + '_'):
                cand = (len(alias), 1, server_name, body[len(alias) + 1:])
            else:
                cand = None
                for k in range(len(segments) - 1, 0, -1):
                    left = '_'.join(segments[:k])
                    if len(left) >= _MIN_MCP_SERVER_NAME and alias.startswith(left.lower()):
                        cand = (len(left), 0, server_name, '_'.join(segments[k:]))
                        break
            if cand is not None and cand[3]:
                candidates.append(cand)
    if not candidates:
        return (None, None, None)
    best = max(candidates, key=lambda c: c[:2])
    best_key = _vscode_fingerprint_key(mcp_servers.get(best[2]))
    for cand in candidates:
        if cand[2] == best[2]:
            continue
        other_key = _vscode_fingerprint_key(mcp_servers.get(cand[2]))
        if best_key is None or other_key is None or other_key != best_key:
            return (None, None, None)
    return (best[2], best[3], mcp_servers.get(best[2]))


def extract_command_for_pretool(canonical, tool_input):
    """Extract the policy-check command from tool_input keyed by canonical tool type."""
    if canonical == 'Bash':
        # Shell tools key the payload differently: run_in_terminal/bash use
        # `command`; send_to_terminal and some variants use `input`/`text`.
        # `value` holds an unparseable raw payload preserved by _normalize_arguments.
        # Try all so the policy check never sees an empty command for a real
        # shell execution.
        return (tool_input.get('command') or tool_input.get('input')
                or tool_input.get('text') or tool_input.get('value') or '')
    if canonical in ('Read', 'Write', 'Edit'):
        return tool_input.get('filePath') or tool_input.get('path') or tool_input.get('file_path') or ''
    if canonical.startswith('mcp'):
        return json.dumps(tool_input)
    return ''


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


def transform_response_for_copilot(api_response):
    """Transform a gateway response to Copilot PreToolUse output format."""
    if not api_response:
        return {}

    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')
    additional_context = api_response.get('additionalContext', '')

    # On 'allow', emit no decision ({}) so Copilot falls through to the user's
    # local config/rules instead of force-allowing over them. Copilot preToolUse
    # precedence: an explicit 'allow' overrides a local deny; '{}' defers to it.
    # We only force an explicit decision to deny/ask.
    if decision == 'allow':
        return {}

    # Emit BOTH shapes so the decision is honored regardless of which the
    # running Copilot surface reads: the top-level form documented in the
    # Copilot CLI hooks reference, AND the nested hookSpecificOutput form
    # (Claude-compatible, used by the VS Code agent). Same values, no conflict.
    return {
        'permissionDecision': decision,
        'permissionDecisionReason': reason,
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
    raw_tool = event.get('tool_name') or event.get('toolName') or ''
    # VS Code can hand toolArgs over as a JSON string. Every reader below calls
    # tool_input.get(), so normalize once here — a raw str raised out of the hook, and a
    # hook that raises fails open, so the tool ran with no policy check at all.
    tool_input = _normalize_arguments(event.get('tool_input') or event.get('toolArgs') or {})
    session_id = event.get('session_id') or event.get('sessionId')

    # Translate the Copilot tool name to the canonical gateway vocabulary.
    canonical = canonical_tool_name(raw_tool)
    is_mcp = canonical.startswith('mcp')
    mcp_server = mcp_tool = mcp_server_config = None

    # VS Code's `mcp_<server>_<tool>` form: canonical_tool_name() leaves the `mcp`
    # prefix as-is so the bare-tool detection below is skipped; resolve the server
    # here and forward its config so the gateway can fingerprint it.
    if is_mcp and raw_tool.startswith('mcp_') and not raw_tool.startswith('mcp__'):
        mcp_servers = read_copilot_mcp_servers(event.get('cwd'))
        mcp_server, mcp_tool, mcp_server_config = _resolve_vscode_mcp(raw_tool, mcp_servers)
        if mcp_server is not None:
            canonical = f"mcp__{mcp_server}__{mcp_tool}"
            log_error(
                f"copilot vscode mcp detected session={session_id} tool={raw_tool} "
                f"server={mcp_server} mcp_tool={mcp_tool} "
                f"config={'yes' if mcp_server_config else 'no'}",
                'mcp_match',
            )
        else:
            # Unmappable server: fall through to the gateway with mcp_server unset
            # (not a short-circuit) so its other policies/logging/metering still run;
            # the allow-list isn't evaluated without a resolved server (fail-open).
            log_error(f"copilot vscode mcp UNRESOLVED session={session_id} tool={raw_tool}", 'mcp_match')

    if not is_mcp and canonical not in ALLOWED_NON_MCP_HOOK_NAMES:
        cwd = event.get('cwd')
        mcp_servers = read_copilot_mcp_servers(cwd)
        mcp_server, mcp_tool, mcp_server_config = detect_mcp_call(raw_tool, mcp_servers)
        if mcp_server is None:
            # A bare (non-mcp__) tool can only be resolved against the MCP config.
            # If no config was readable, a genuine MCP call can't be identified
            # and would slip the allow-list — surface that distinctly so the
            # potential bypass is observable rather than silent. Skip known-benign
            # native tools so the log isn't noisy.
            if raw_tool and raw_tool not in INTERNAL_TOOLS and raw_tool not in TERMINAL_LIKE_TOOLS:
                if not mcp_servers and not raw_tool.startswith('mcp__'):
                    log_error(
                        f"copilot mcp UNRESOLVED (no readable MCP config) tool={raw_tool}",
                        'mcp_config',
                    )
                else:
                    log_error(f"copilot pre_tool_use unmatched tool={raw_tool}", 'mcp_match')
            return {}
        is_mcp = True
        canonical = f"mcp__{mcp_server}__{mcp_tool}"
        # Names only — never args/config (those can carry secrets).
        log_error(
            f"copilot mcp detected session={session_id} tool={raw_tool} "
            f"server={mcp_server} mcp_tool={mcp_tool} "
            f"config={'yes' if mcp_server_config else 'no'}",
            'mcp_match',
        )

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

    if mcp_server is not None:
        metadata['mcp_server'] = mcp_server
        metadata['mcp_tool'] = mcp_tool
        if mcp_server_config:
            metadata['mcp_server_config'] = mcp_server_config

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
        except (ValueError, RecursionError):
            # RecursionError (deeply nested args) is not a ValueError, and an uncaught one
            # here fails the hook open — keep the raw payload so the policy check still sees it.
            return {'value': arguments}
    return {}


def _extract_patch_target_path(args):
    """`apply_patch` carries the target file inside its patch `input` text rather
    than a filePath/path arg. Pull the first `*** {Add|Update|Delete} File: <path>`
    so the edit is scored like insert_edit_into_file / create_file instead of being
    dropped for want of a path. Returns '' when no path line is present."""
    text = args.get('input') or args.get('patch') or args.get('diff') or ''
    if not isinstance(text, str):
        return ''
    m = re.search(r'^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+)$', text, re.MULTILINE)
    return m.group(1).strip() if m else ''


def map_copilot_tool(name, args, result_content):
    """Map a Copilot tool call to a cursor-style tool_use entry.

    Returns None for internal orchestration tools (intentionally not emitted).
    """
    if name in INTERNAL_TOOLS:
        return None
    if name in SHELL_TOOLS:
        entry = {
            'type': 'afterShellExecution',
            'command': args.get('command') or args.get('input') or args.get('text') or '',
            'output': result_content or '',
        }
    elif name in TERMINAL_LIKE_TOOLS:
        entry = {
            'type': 'afterShellExecution',
            'command': TERMINAL_LIKE_TOOLS[name](args),
            'output': result_content or '',
        }
    elif name in READ_TOOLS:
        entry = {
            'type': 'beforeReadFile',
            'file_path': args.get('filePath') or args.get('path') or args.get('file_path') or '',
            'content': result_content or '',
        }
    elif name in WRITE_TOOLS or name in EDIT_TOOLS:
        entry = {
            'type': 'afterFileEdit',
            'file_path': (args.get('filePath') or args.get('path') or args.get('file_path')
                          or _extract_patch_target_path(args) or ''),
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


def build_exchange_from_transcript(transcript_path, fallback_session_id, session_start_model=None,
                                   already_forwarded=None):
    """Parse a Copilot JSONL transcript into a cursor-style LLM exchange.

    Reads defensively — blank or unparseable lines are skipped, never raised.

    Copilot fires a Stop per agent turn but the transcript slice below spans every
    turn since the last user message, so without a guard each Stop re-sends the whole
    accumulated tool history. `already_forwarded` is the set of toolCallIds sent on
    earlier Stops of this session (from the audit-log markers); tool calls in it are
    skipped so only NEW ones ride each request. Returns (exchange, forwarded_now, text_sig) where forwarded_now is the set of
    toolCallIds included this time and text_sig fingerprints the turn's text — the caller
    records them only after a successful send, so a failed send simply retries."""
    already_forwarded = already_forwarded or set()
    if not transcript_path or not os.path.exists(transcript_path):
        return None, set(), None

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
        return None, set(), None

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
        return None, set(), None

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
    forwarded_now = set()
    for call_id in tool_calls:
        if call_id in already_forwarded:
            continue  # sent on an earlier Stop of this session — don't resend
        call = tool_data[call_id]
        mapped = map_copilot_tool(call['name'], call['arguments'], call['result'])
        # Advance the watermark for EVERY handled call, mapped or not: an internal tool
        # maps to None (nothing to send) but must still be recorded, else a turn of only
        # internal tools is reparsed on every later Stop and never records progress.
        forwarded_now.add(call_id)
        # `is not None` (not truthiness): None means a consciously-dropped internal
        # tool; an empty-but-valid dict should still be appended.
        if mapped is not None:
            tool_use.append(mapped)

    # Signature of the turn's user+assistant TEXT (independent of tool_use). The caller
    # sends when there are new tools OR new text, and no-ops only when BOTH are unchanged
    # from the last successful send. So a pure tool-replay doesn't re-post, but a Stop
    # that appended new assistant text still sends (and is logged) even with no new tools.
    text_sig = hashlib.sha256(
        '\x1f'.join([user_prompt or ''] + text_parts).encode('utf-8', 'replace')
    ).hexdigest()

    messages = []
    if user_prompt:
        messages.append({'role': 'user', 'content': user_prompt})

    assistant_msg = {'role': 'assistant', 'content': '\n\n'.join(text_parts)}
    if tool_use:
        assistant_msg['tool_use'] = tool_use
    messages.append(assistant_msg)

    if not messages:
        return None, set(), None

    return {
        'conversation_id': conversation_id,
        'model': model or session_start_model or 'auto',
        'messages': messages,
    }, forwarded_now, text_sig


def send_to_api(exchange, api_key):
    """Send exchange data to Unbound API."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False

    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/copilot"
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
    if RUNNING_FROZEN:
        # Binary deployments are updated by the MDM package, never in place.
        return
    # Only self-update when we are actually running the user-level script we
    # would overwrite. If the hook is ever invoked from a managed/alternate path
    # (MDM-managed location, symlink), SELF_SCRIPT_PATH is not the executing file
    # and updating it would only write a dead copy. Matches the guard the other
    # tools' hooks use.
    try:
        running = os.path.normcase(str(Path(__file__).resolve()))
        target = os.path.normcase(str(SELF_SCRIPT_PATH.resolve()))
    except Exception as e:
        log_error(f"self_update skipped: could not resolve script path: {e}", 'self_update')
        return
    if running != target:
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
                if not DISCOVERY_INSTALL_SH.exists():
                    r = subprocess.run(
                        ["curl", "-fsSL", "-o", str(DISCOVERY_INSTALL_SH), DISCOVERY_INSTALL_URL],
                        capture_output=True, timeout=30,
                    )
                    if r.returncode != 0:
                        log_error(f"discovery install.sh download failed: {r.stderr.decode(errors='replace')[:200]}", 'discovery_gate')
                        return
                    os.chmod(DISCOVERY_INSTALL_SH, 0o755)
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

        event_name = event.get('hook_event_name') or event.get('hookEventName')

        # SessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if event_name == 'SessionStart':
            _check_self_update()
            _dispatch_discovery()
            print("{}")
            return

        if event_name in ('PreToolUse', 'preToolUse'):
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
            # Watermark key mirrors the exchange's session fallback, so get/record stay
            # consistent even when the Stop payload omits session_id.
            wm_key = stop_session_key(event)
            already_forwarded, last_text_sig = get_forwarded_state(wm_key)
            exchange, forwarded_now, text_sig = build_exchange_from_transcript(
                event.get('transcript_path'), session_id,
                session_start_model=get_session_start_model(session_id),
                already_forwarded=already_forwarded,
            )
            # Send only when there is something new -- new tool calls OR new assistant
            # text -- so a pure replay Stop is a no-op, but a Stop that appended new text
            # (even with no new tools) is still sent and logged.
            if exchange and (forwarded_now or text_sig != last_text_sig):
                # Turn boundaries from event-fire times
                request_initialized = get_last_user_prompt_timestamp_for_session(session_id)
                if request_initialized:
                    exchange['requestInitialized'] = request_initialized
                exchange['requestCompleted'] = timestamp
                # Record only after the send succeeds, so a failed send retries next Stop
                # (the backend dedups). Updates the text signature too, even with no new
                # tools, so an unchanged later Stop becomes a no-op.
                if send_to_api(exchange, api_key):
                    record_forwarded_tool_ids(wm_key, forwarded_now, text_sig)
            cleanup_old_logs()

        # Output required by Copilot hooks
        print("{}")

    except Exception as e:
        # Log errors but still output {} to not break Copilot
        log_error(f"Exception in main: {str(e)}", 'general')
        print("{}")


if __name__ == '__main__':
    main()
