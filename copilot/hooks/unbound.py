#!/usr/bin/env python3
"""
Real-time GitHub Copilot hook event processor.
Reads JSON events from stdin, appends to agent-audit.log, and processes them on stop events.
"""

import sys
import json
import os
import platform
import stat
import subprocess
from pathlib import Path, PureWindowsPath
from datetime import datetime, timezone
import tempfile
import time
import hashlib
import re
import sqlite3
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def _copilot_home():
    return Path(os.environ.get('COPILOT_HOME') or Path.home() / '.copilot').expanduser()


UNBOUND_GATEWAY_URL = os.environ.get(
    "UNBOUND_GATEWAY_URL", "https://api.getunbound.ai"
).rstrip("/")

APPROVAL_TIMEOUT = 4 * 60 * 60

DISCOVERY_DEBOUNCE_SECONDS = 24 * 3600
DISCOVERY_STALE_LOCK_SECONDS = 15 * 60
DISCOVERY_CACHE_PATH = Path.home() / ".unbound" / "discovery-cache.json"
DISCOVERY_LOCK_PATH = Path.home() / ".unbound" / "discovery.lock"
DISCOVERY_DISPATCH_PATH = Path.home() / ".unbound" / "discovery.dispatch.lock"
DISCOVERY_DISPATCH_TTL_SECONDS = 60
DISCOVERY_INSTALL_DIR = Path.home() / ".local" / "share" / "unbound"
DISCOVERY_INSTALL_SH = DISCOVERY_INSTALL_DIR / "install.sh"
DISCOVERY_INSTALL_PS1 = DISCOVERY_INSTALL_DIR / "install.ps1"
DISCOVERY_INSTALL_URL = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main/install.sh"
DISCOVERY_INSTALL_PS1_URL = "https://raw.githubusercontent.com/websentry-ai/coding-discovery-tool/main/install.ps1"
UNBOUND_CONFIG_PATH = Path.home() / ".unbound" / "config.json"

APPROVAL_POLL_PHASES = (
    (5 * 60,        3),    # 0-5 min: 3s
    (30 * 60,       15),   # 5-30 min: 15s
    (2 * 60 * 60,   60),   # 30 min - 2h: 1min
    (4 * 60 * 60,   120),  # 2h - 4h: 2min
)

# Use user's home directory for logs
LOG_DIR = _copilot_home() / "hooks"
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

SHELL_TOOLS = {'bash', 'shell', 'powershell', 'run_in_terminal', 'runInTerminal', 'terminal'}
READ_TOOLS = {'read_file', 'readFile', 'view', 'cat'}
WRITE_TOOLS = {'create_file', 'create', 'createFile', 'write', 'write_file', 'new_file'}
EDIT_TOOLS = {
    'str_replace', 'edit_file', 'editFile', 'apply_patch', 'insert_edit',
    'replace_string_in_file',
}

ALLOWED_NON_MCP_HOOK_NAMES = {'Bash', 'Read', 'Write', 'Edit'}
NATIVE_FILE_TOOLS = {'Read', 'Write', 'Edit'}
# INVARIANT: every skill entry below carries a tool_use_id - the native one
# when the tool reports it, otherwise a deterministic synthetic one. The backend
# relies on this: two id-less invocations of one skill with the same arguments
# are byte-identical, so nothing can tell a replay from a genuine repeat.
SKILL_TOOL_NAME = 'Skill'
SKILL_SEARCH_DIRS = (('.copilot', 'skills'), ('.github', 'skills'),
                     ('.agents', 'skills'), ('.claude', 'skills'))
SKILL_INVOKE_RE = re.compile(r'(?:^|\s)/([A-Za-z0-9][A-Za-z0-9._:-]*)')
POLICY_CACHE_FILE = LOG_DIR / ".policy_cache.json"
CACHE_TTL_SECONDS = 300
# Repo-scope gate. Straying outside the allowed org is blocked on the first
# write, and the gate keeps no state on disk at all.
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'
PRETOOL_USER_MESSAGES_LIMIT = 5
AUDIT_LOG_TOTAL_LIMIT = 100
# Sentinel hook_event_name for the agent-audit.log rows that record which toolCallIds
# were already forwarded, so a later Stop sends only new tool calls. Not a real Copilot
# event: every existing reader filters by its own event name and skips it, and
# cleanup_old_logs prunes it per-session like any other row (no new file, no new state).
FORWARDED_TOOLS_EVENT = '_unbound_forwarded'
# Distinguishes 'carry the old value forward' from 'clear it'.
_UNSET = object()
# Safety net, not the working bound. Entries drop themselves as soon as their tokens
# land or their turn leaves the transcript, so the list tracks a session's unsettled
# turns and can never exceed its length. This only exists so a pathological session
# cannot grow the marker without limit. Sized against real sessions rather than a guess:
# 57 turns at p95 and 301 at the observed maximum, and VS Code sometimes writes the whole
# journal only as the session closes, which leaves every turn of a long session pending
# until SessionEnd. Each entry is a handful of short strings, so 500 is well under a
# hundred kilobytes.
MAX_PENDING_TURNS = 500

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


def _skill_tool_uses_from_events(skill_events, cwd, turn_key=None):
    """Skill invocations from Copilot's session event stream, keyed to the turn
    so a later turn's use of the same skill is a distinct row. `skill.invoked` is
    undocumented and unversioned, so each field is probed across plausible names
    and a missing path falls back to resolving the name on disk."""
    entries = []
    try:
        for event in skill_events or []:
            if not isinstance(event, dict):
                continue
            data = event.get('data')
            if not isinstance(data, dict):
                continue
            name = ''
            for key in ('name', 'skillName', 'skill_name', 'skill'):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    name = value.strip()
                    break
            path = ''
            for key in ('path', 'skillPath', 'skill_path', 'filePath', 'file_path'):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    path = value.strip()
                    break
            # The name field may itself be a path; derive the skill from it.
            if name and ('/' in name or os.sep in name):
                parts = [seg for seg in name.replace(os.sep, '/').split('/') if seg]
                if parts and parts[-1] == 'SKILL.md':
                    path = path or name
                    parts = parts[:-1]
                name = parts[-1] if parts else ''
            if not name:
                continue
            # The event payload is undocumented, so only trust a path that is
            # really a skill file on disk AND names the same skill; otherwise a
            # valid path for a different skill would misattribute the row.
            path_name = _skill_name_from_path(path, cwd) if path else None
            if not (path_name == name and os.path.isfile(path)):
                path = _resolve_skill_path(name, cwd) or ''
                # No path means no evidence this name is a real skill. Every
                # other detector requires that, and an unjoinable row is worse
                # than none, so drop it rather than watermark it as sent.
                if not path:
                    continue
            # The envelope id is unique per event, so it keeps repeat invocations
            # distinct without depending on turn text, which repeats verbatim
            # across identical turns. Index only backs it up if an id is absent.
            key = 'skill\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s' % (
                event.get('id') or '', turn_key or '', name, path, len(entries))
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
            key = '\x1f'.join((str(session_id or ''), name, str(stamp or ''), str(len(entries))))
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


def stop_session_key(event):
    """Stable per-session key for the forwarded-tool watermark. Derived from the transcript
    path FIRST -- it is constant for a session and present on every Stop that builds an
    exchange -- so the key never flips between Stops that do and don't carry session_id
    (which would split the watermark and resend the whole history). Falls back to
    session_id only when there is no transcript path."""
    # Type-checked because the floor lookup runs this over historical audit-log rows, and
    # a non-string path there would raise out of the Stop handler and drop the exchange.
    tp = event.get('transcript_path')
    if isinstance(tp, str) and tp:
        p = Path(tp)
        return p.parent.name if p.stem == 'events' else p.stem
    return event.get('session_id') or event.get('sessionId')


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

    # Grouped by stop_session_key, the same identity the usage-window floor looks Stops up
    # by. Grouping on the payload session_id instead would drop a Stop that omits it, and
    # the next window would lose its lower bound and recount the session from the start.
    # The two agree whenever session_id is present: for both surfaces the transcript path
    # ends in the session id.
    session_order = []
    seen_sessions = set()
    for log in entries:
        session_id = stop_session_key(log.get('event', {}))
        if session_id and session_id not in seen_sessions:
            session_order.append(session_id)
            seen_sessions.add(session_id)

    if len(session_order) > 1:
        most_recent_session = session_order[-1]
        kept = [log for log in entries
                if stop_session_key(log.get('event', {})) == most_recent_session]
    elif len(entries) > AUDIT_LOG_TOTAL_LIMIT:
        kept = entries[-AUDIT_LOG_TOTAL_LIMIT:]
    else:
        kept = entries
    # Always keep the watermark markers (one small consolidated row per session; the
    # active session's is always the newest), bounded to the most recent sessions.
    save_logs(kept + markers[-20:])


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
    sent, last_sig, prompted, usage_index = set(), None, set(), 0
    if not session_id:
        return sent, last_sig, prompted, usage_index
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
        # Advisory like the tool ids above, and with the same caveat: a local writer could
        # seed these to keep prompt text out of an exchange. The hook already runs as the
        # user, who can equally edit the transcript it reads, so this adds no exposure --
        # the gateway's server-side record is the integrity backstop.
        prompt_ids = event.get('forwarded_prompt_ids')
        if isinstance(prompt_ids, list):
            prompted.update(prompt_ids)
        reported = event.get('usage_request_index')
        if isinstance(reported, int) and reported > usage_index:
            usage_index = reported
    return sent, last_sig, prompted, usage_index


def record_forwarded_tool_ids(session_id, tool_ids, text_sig=None, prompt_ids=None, usage_index=None,
                             turn_digests=None, pending_turns=_UNSET):
    """Persist the forwarded toolCallIds + the last-sent text signature for this session as
    a SINGLE consolidated marker, rewritten (re-appended last) on each Stop. Keeping one
    cumulative marker -- rather than one append per Stop -- means it survives
    cleanup_old_logs' last-N trim in a long session, so old ids aren't forgotten and their
    tool calls resent. Called after a successful send; a failed send simply resends next
    Stop (the backend dedups)."""
    if not session_id:
        return
    merged = set(tool_ids or ())
    merged_prompts = set(prompt_ids or ())
    kept = []
    for log in load_existing_logs():
        ev = log.get('event', {})
        if (ev.get('hook_event_name') == FORWARDED_TOOLS_EVENT
                and ev.get('session_id') == session_id):
            ids = ev.get('forwarded_tool_ids')
            if isinstance(ids, list):
                merged.update(ids)
            old_prompts = ev.get('forwarded_prompt_ids')
            if isinstance(old_prompts, list):
                merged_prompts.update(old_prompts)
            if text_sig is None:
                text_sig = ev.get('text_sig')  # carry forward the last known text sig
            if usage_index is None:
                usage_index = ev.get('usage_request_index')
            if turn_digests is None:
                turn_digests = ev.get('turn_digests')
            if pending_turns is _UNSET:
                pending_turns = ev.get('pending_turns')
            continue  # drop the old marker; a fresh consolidated one is appended below
        kept.append(log)
    kept.append({
        'timestamp': datetime.now().astimezone().isoformat().replace('+00:00', 'Z'),
        'event': {
            'hook_event_name': FORWARDED_TOOLS_EVENT,
            'session_id': session_id,
            'forwarded_tool_ids': sorted(merged),
            'forwarded_prompt_ids': sorted(merged_prompts),
            'text_sig': text_sig,
            'usage_request_index': usage_index if isinstance(usage_index, int) else 0,
            # Digests of turns already sent, so a repeated prompt-and-reply gets its own
            # occurrence rather than colliding with the earlier one.
            'turn_digests': turn_digests if isinstance(turn_digests, list) else [],
            # Turns sent whose tokens or model had not landed yet. Each holds an id and
            # a window, never prompt text: the turn is rebuilt from the transcript.
            'pending_turns': (pending_turns if pending_turns is not _UNSET else []) or [],
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


def get_turn_start_timestamp_for_session(session_id):
    """First UserPromptSubmit of the turn; turn start. Typing while Copilot is still
    working adds prompts to the running turn, and anchoring on the last would start the
    turn after work the earlier prompt had already caused. The Stop being handled is
    already logged, so the turn it closed is reported through completed_start."""
    if not session_id:
        return None
    turn_start = None
    completed_start = None
    for log in load_existing_logs():
        event = log.get('event', {})
        if event.get('session_id') != session_id:
            continue
        name = event.get('hook_event_name')
        if name == 'UserPromptSubmit':
            if turn_start is None:
                turn_start = log.get('timestamp')
        elif name == 'Stop':
            if turn_start is not None:
                completed_start = turn_start
            turn_start = None
    return turn_start or completed_start


def _transcript_path_for_session(event):
    """SessionEnd carries sessionId, timestamp, cwd and reason but no transcript path, so
    recover it from the newest event of this session that had one. Matched by
    stop_session_key, the identity the window floor and log cleanup also use, so a row that
    omits session_id is not passed over."""
    key = stop_session_key(event)
    if not key:
        return None
    for log in reversed(load_existing_logs()):
        logged = log.get('event', {})
        if stop_session_key(logged) != key:
            continue
        path = logged.get('transcript_path')
        if isinstance(path, str) and path:
            return path
    return None


def turn_content_digest(user_prompt, assistant_prompt):
    """Digest of what both this hook and the server-side transcript parser can see of one
    turn. NUL-joined so a prompt ending where the reply begins cannot forge another
    turn's digest. KEEP IN SYNC: ai-gateway-data coding_tools_backfill_service."""
    return hashlib.sha256(
        (user_prompt or '').encode('utf-8') + b'\x00' + (assistant_prompt or '').encode('utf-8')
    ).hexdigest()


def build_turn_request_id(session_id, digest, occurrence):
    """Stable id for one turn, keyed on content rather than position.

    Position is not usable: a turn that never reached the gateway is in the transcript
    and not in our history, so counting turns would map one turn's tokens onto its
    neighbour. Content is the same on both sides by construction. `occurrence` separates
    turns whose prompt AND reply are byte-identical inside one session."""
    return str(uuid.uuid5(
        uuid.NAMESPACE_OID,
        'turn:copilot:%s:%s:%d' % (session_id, digest, occurrence),
    ))


def exchange_turn_content(exchange):
    """(user prompt, assistant text) of an exchange, in the shape the digest is taken over."""
    user_prompt = ''
    assistant_prompt = ''
    for message in (exchange or {}).get('messages') or []:
        if not isinstance(message, dict):
            continue
        if message.get('role') == 'user':
            user_prompt = message.get('content') or ''
        elif message.get('role') == 'assistant':
            assistant_prompt = message.get('content') or ''
    return user_prompt, assistant_prompt


def get_session_marker(session_key):
    """The consolidated per-session marker, or an empty dict."""
    if not session_key:
        return {}
    for log in reversed(load_existing_logs()):
        event = log.get('event', {})
        if (event.get('hook_event_name') == FORWARDED_TOOLS_EVENT
                and event.get('session_id') == session_key):
            return event
    return {}


def turn_prompt_id(entry, conversation_id, index, content):
    """Stable id for a user prompt entry. An entry without an envelope id still has to be
    watermarked, or every later Stop re-selects it and re-uploads its text with the
    current turn."""
    return entry.get('id') or 'unb-' + hashlib.sha256(
        ('%s\x1f%d\x1f%s' % (conversation_id or '', index, content or ''))
        .encode('utf-8', 'replace')).hexdigest()[:24]


def complete_pending_turns(event, wm_key, api_key, final=False):
    """Complete every turn still waiting on its numbers; return those still waiting.

    A list rather than one slot: a turn whose tokens have not landed by the next Stop
    would otherwise be displaced by that Stop's own pending turn, and its tokens lost."""
    pending_turns = get_session_marker(wm_key).get('pending_turns') or []
    return [p for p in pending_turns
            if not complete_pending_turn(event, p, api_key, final)]


def complete_pending_turn(event, pending, api_key, final=False):
    """Re-send an earlier turn once its tokens or model have landed.

    Copilot writes both after the turn has already been reported, so its own Stop had
    nothing to send. The re-send carries the id the turn was sent with, so the control
    plane fills that row rather than adding a second one. Returns True when the turn is
    settled and can be dropped."""
    if not isinstance(pending, dict) or not pending.get('turn_request_id'):
        return True

    transcript_path = event.get('transcript_path')
    conversation_id = pending.get('conversation_id')
    # By the turn's own window, never by the live path's watermark: every turn after this
    # one has settled by now, and a watermark read would hand this turn all of them.
    usage = pending_turn_usage(transcript_path, conversation_id,
                               pending.get('since'), pending.get('until'))
    model = _vscode_turn_model(transcript_path, conversation_id,
                               pending.get('since'), pending.get('until'))
    # Tokens are the point, and VS Code can expose a model before it has finished
    # accounting. Sending on the model alone and clearing the slot would lose those
    # tokens permanently, so a model-only result waits -- except at SessionEnd, which is
    # the last chance this session gets.
    if not usage and not (final and model):
        return False

    content = rebuild_turn_content(transcript_path, conversation_id, pending.get('prompt_id'))
    if content is None:
        # The turn is no longer in the transcript, so nothing can be rebuilt for it.
        return True
    user_prompt, assistant_prompt = content

    exchange = {
        'conversation_id': conversation_id,
        'model': model or 'auto',
        'messages': [{'role': 'user', 'content': user_prompt},
                     {'role': 'assistant', 'content': assistant_prompt}],
        'turn_request_id': pending['turn_request_id'],
        'requestInitialized': pending.get('since') or pending.get('until'),
        'requestCompleted': pending.get('until'),
    }
    if usage:
        exchange['usage'] = usage
    if not send_to_api(exchange, api_key):
        return False
    # Settled means the tokens are in, not merely that something was sent. A model-only
    # send is progress, so the slot stays and any later event for this session can still
    # attach them; re-sending fills the same row and changes nothing.
    return bool(usage)


def rebuild_turn_content(transcript_path, conversation_id, prompt_id):
    """(user prompt, assistant text) for one earlier turn, or None.

    Anchored on the turn's own prompt entry rather than a time window: transcript entries
    carry no timestamp, and the turn ends where the next user prompt begins. Reads the
    transcript again rather than keeping the text on disk, so no prompt text is persisted."""
    if not transcript_path or not prompt_id:
        return None
    try:
        entries = []
        with open(transcript_path, 'r', encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        log_error('turn rebuild read failed: %s' % e, 'usage')
        return None

    user_prompt = None
    assistant_parts = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get('type')
        data = entry.get('data') or {}
        if entry_type == 'user.message':
            if user_prompt is not None:
                break  # the next prompt closes the turn
            content = data.get('content')
            if turn_prompt_id(entry, conversation_id, index, content) == prompt_id:
                user_prompt = content or ''
        elif entry_type == 'assistant.message' and user_prompt is not None:
            content = data.get('content')
            if isinstance(content, str) and content:
                assistant_parts.append(content)
    if user_prompt is None:
        return None
    return user_prompt, '\n\n'.join(assistant_parts)


def get_previous_stop_timestamp_for_session(event):
    """Close of the previous turn, which is the floor of this turn's usage window. The Stop
    being handled is already logged, so the one before it is that floor. Keyed by
    stop_session_key rather than the payload's session_id: a Stop that omits session_id
    would match no earlier Stop, lose its floor, and recount every earlier request in the
    session."""
    key = stop_session_key(event)
    if not key:
        return None
    stops = [log.get('timestamp') for log in load_existing_logs()
             if log.get('event', {}).get('hook_event_name') == 'Stop'
             and stop_session_key(log.get('event', {})) == key]
    # A Stop is already logged by the time it is handled, so its own row is the last one.
    # SessionEnd is a different event, so every Stop in the log precedes it.
    if event.get('hook_event_name') == 'Stop':
        return stops[-2] if len(stops) > 1 else None
    return stops[-1] if stops else None


def _build_user_prompt_payload(recent_user_prompts):
    last = recent_user_prompts[-1] if recent_user_prompts else None
    return {
        'messages': [{'role': 'user', 'content': last}] if last else [],
        'user_prompts': recent_user_prompts,
    }


def canonical_tool_name(raw):
    """Translate a Copilot tool name to the canonical gateway vocabulary.
    Returns '' when the tool is not security-relevant."""
    if not isinstance(raw, str):
        return ''
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
    if raw.lower().startswith('mcp_'):
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


# Plugin-bundle `.mcp.json` paths (VS Code agentPlugins + Copilot CLI); never merged
# into mcp.json, so scan them. Not capped — a dropped config would fail open.
def _plugin_mcp_config_paths(home=None):
    paths = []
    for user_dir in _vscode_user_dirs():
        try:
            paths.extend(sorted((user_dir.parent / "agentPlugins").glob("*/*/*/.mcp.json")))
        except OSError:
            pass
    try:
        plugin_root = home / ".copilot" if home is not None else _copilot_home()
        paths.extend(sorted((plugin_root / "installed-plugins").glob("*/.mcp.json")))
    except OSError:
        pass
    return paths


def _workspace_mcp_config_paths(cwd):
    if not cwd:
        return []
    try:
        current = Path(cwd).resolve()
    except OSError:
        current = Path(cwd)
    directories = []
    found_git_root = False
    while True:
        directories.append(current)
        try:
            if (current / ".git").exists():
                found_git_root = True
                break
        except OSError:
            break
        if current.parent == current:
            break
        current = current.parent
    if not found_git_root:
        directories = directories[:1]
    paths = [directories[0] / ".vscode" / "mcp.json"]
    for directory in reversed(directories):
        paths.append(directory / ".github" / "mcp.json")
        paths.append(directory / ".mcp.json")
    return paths


def _copilot_mcp_config_paths(cwd=None, plugins=None):
    home = Path.home()
    user = []
    for user_dir in _vscode_user_dirs():
        user.append(user_dir / "mcp.json")
        user.append(user_dir / "settings.json")
        profiles = user_dir / "profiles"
        try:
            if profiles.is_dir():
                for profile in sorted(profiles.iterdir()):
                    user.append(profile / "mcp.json")
        except OSError:
            pass
    user.append(home / ".config" / "github-copilot" / "intellij" / "mcp.json")
    user.append(_copilot_home() / "mcp-config.json")

    if plugins is None:
        plugins = _plugin_mcp_config_paths()
    return user + _workspace_mcp_config_paths(cwd) + plugins

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


def _extract_mcp_server_fields(server):
    if not isinstance(server, dict):
        return None
    result = {
        key: server[key]
        for key in ('url', 'command', 'args', 'type')
        if server.get(key)
    }
    return result or None


_MCP_CONFIG_MAX_BYTES = 1_000_000

# KEEP IN SYNC: coding-discovery-tool mcp_tools_cache.py + all 5 hook copies — byte-identical, do not diverge.
# Fingerprints key the local tool-hash cache; Redis tool scores are separately
# keyed by tool content hash. Keep fingerprint output aligned with data/gateway.

_MCP_TOOLS_CACHE_FILENAME = 'mcp-tools-cache.json'
_MCP_TOOLS_CACHE_MAX_BYTES = 2 * 1024 * 1024
_MCP_CACHE_CODING_TOOL_NAMES = frozenset({'github copilot cli'})
_MCP_CACHE_CODING_TOOL_PREFIXES = ('github copilot',)
_UNBOUND_CODING_TOOL = 'GitHub Copilot CLI'


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

    if (safe_additional_data.get('scope') == 'copilot-builtin' and safe_name
            and not command and not url and not safe_args):
        return f'copilot-builtin:{safe_name.lower()}'

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
        if content_hash:
            server_cfg['tool_content_hash'] = content_hash
        if isinstance(original_cfg, dict) or content_hash:
            metadata['mcp_server_config'] = server_cfg
    except Exception:
        pass


# ───────────────────────── end MCP tool risk-scoring section ─────────────────


def _mcp_servers_from_config(config, allow_bare=False):
    raw = config.get('servers')
    if not isinstance(raw, dict):
        raw = config.get('mcpServers')
    if not isinstance(raw, dict):
        nested = config.get('mcp')
        raw = nested.get('servers') if isinstance(nested, dict) else None
    if not isinstance(raw, dict) and allow_bare:
        raw = {
            name: value for name, value in config.items()
            if isinstance(value, dict)
            and any(key in value for key in ('command', 'url', 'type', 'args'))
        }
    return raw if isinstance(raw, dict) else None


def read_copilot_mcp_servers(cwd=None):
    servers = {}
    server_sources = {}
    ambiguous_names = set()
    plugin_names = set()
    # Match plugin bundles by exact path (a substring check could misclassify).
    plugin_list = _plugin_mcp_config_paths()
    plugin_paths = set(plugin_list)
    workspace_paths = set(_workspace_mcp_config_paths(cwd))
    for config_path in _copilot_mcp_config_paths(cwd, plugin_list):
        try:
            if not config_path.exists():
                continue
            if config_path.stat().st_size > _MCP_CONFIG_MAX_BYTES:
                continue
            with open(config_path, 'r', encoding='utf-8') as f:
                config = _parse_jsonc(f.read())
            if not isinstance(config, dict):
                continue
            allow_bare = config_path.name == '.mcp.json' or (
                config_path.name == 'mcp.json' and config_path.parent.name == '.github'
            )
            raw = _mcp_servers_from_config(config, allow_bare=allow_bare)
            if not isinstance(raw, dict):
                continue
            is_plugin = config_path in plugin_paths
            source = 'plugin' if is_plugin else (
                'workspace' if config_path in workspace_paths else 'user'
            )
            for name, server in raw.items():
                fields = _extract_mcp_server_fields(server) or {}
                # Surface only genuine plugin-vs-plugin name clashes (name only).
                if is_plugin:
                    if name in plugin_names and servers.get(name) != fields:
                        log_error(
                            f"copilot mcp plugin name collision: {name}", 'mcp_plugin'
                        )
                    plugin_names.add(name)
                previous_source = server_sources.get(name)
                if name in ambiguous_names:
                    continue
                if (
                    previous_source is not None
                    and previous_source != source
                    and servers.get(name) != fields
                ):
                    servers[name] = None
                    ambiguous_names.add(name)
                elif previous_source is None or previous_source == source:
                    servers[name] = fields
                server_sources[name] = source
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
# Only builtins with a seeded canonical-group link belong here: an unseeded
# copilot-builtin fingerprint has no metadata row, so the gateway retry-loops forever.
_BUILTIN_MCP_SERVERS = ('github-mcp-server', 'playwright')
# A server name must be at least this long to anchor a bare-name match, so a
# one-char config entry can't swallow arbitrary tool names.
_MIN_MCP_SERVER_NAME = 2
_VSCODE_TRUNCATED_SERVER_LENGTH = 13


def detect_mcp_call(raw_tool, mcp_servers):
    if not raw_tool:
        return (None, None, None)

    if raw_tool.lower().startswith('mcp__'):
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
            if not raw_lower.startswith(cand_lower):
                continue
            remainder = raw_tool[len(candidate):]
            sep = next((s for s in _MCP_NAME_SEPARATORS if remainder.startswith(s)), None)
            if sep is None:
                continue
            mcp_tool = remainder[len(sep):]
            if not mcp_tool:
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


def _resolve_vscode_mcp(raw_tool, mcp_servers):
    """Resolve (server, tool, config) from a VS Code `mcp_<server>_<tool>` name,
    tolerating truncation; longest server-prefix wins, exact beats truncated on ties.
    If a different server also matches and has a different resolved config, the
    token is ambiguous and remains unresolved. Duplicate keys with the same config
    still resolve."""
    raw_lower = raw_tool.lower()
    if not raw_lower.startswith('mcp_') or raw_lower.startswith('mcp__'):
        return (None, None, None)
    body = raw_tool[len('mcp_'):]
    body_lower = body.lower()
    candidates = []  # (server_portion_len, exact_flag, server_name, tool)
    for server_name in mcp_servers:
        for alias in _vscode_server_aliases(server_name):
            if body_lower.startswith(alias + '_'):
                remainder = body[len(alias):]
                separator_length = 2 if remainder.startswith('__') else 1
                cand = (len(alias), 1, server_name, remainder[separator_length:])
            else:
                cand = None
                truncated = alias[:_VSCODE_TRUNCATED_SERVER_LENGTH]
                if (
                    len(alias) > _VSCODE_TRUNCATED_SERVER_LENGTH
                    and body_lower.startswith(truncated + '_')
                ):
                    cand = (
                        len(truncated), 0, server_name,
                        body[len(truncated) + 1:],
                    )
            if cand is not None and cand[3]:
                candidates.append(cand)
    if not candidates:
        return (None, None, None)
    best = max(candidates, key=lambda c: c[:2])
    best_config = mcp_servers.get(best[2])
    for cand in candidates:
        if cand[2] == best[2]:
            continue
        if best_config is None or mcp_servers.get(cand[2]) != best_config:
            return (None, None, None)
    return (best[2], best[3], mcp_servers.get(best[2]))


def _explicit_mcp_identity_matches(raw_tool, server_name, tool_name):
    if not all(isinstance(value, str) and 0 < len(value) <= 512
               for value in (raw_tool, server_name, tool_name)):
        return False
    raw_lower = raw_tool.lower()
    cli_name = (
        f'{_sanitize_copilot_server_name(server_name)}-'
        f'{_sanitize_copilot_server_name(tool_name)}'
    ).lower()
    if raw_lower == cli_name:
        return True
    if raw_lower == f'mcp__{server_name}__{tool_name}'.lower():
        return True
    if not raw_lower.startswith('mcp_') or raw_lower.startswith('mcp__'):
        return False
    body = _vscode_sanitize(raw_tool[4:])
    tool_token = _vscode_sanitize(tool_name)
    for separator in ('__', '_'):
        suffix = separator + tool_token
        if not tool_token or not body.endswith(suffix):
            continue
        server_token = body[:-len(suffix)]
        if len(server_token) < _MIN_MCP_SERVER_NAME:
            continue
        if any(
            alias == server_token
            or (
                len(alias) > _VSCODE_TRUNCATED_SERVER_LENGTH
                and server_token == alias[:_VSCODE_TRUNCATED_SERVER_LENGTH]
            )
            for alias in _vscode_server_aliases(server_name)
        ):
            return True
    return False


def resolve_copilot_mcp(raw_tool, mcp_servers, server_name=None, tool_name=None):
    lowered = (raw_tool or '').lower()
    builtin = (None, None, None)
    for server in _BUILTIN_MCP_SERVERS:
        prefix = server + '-'
        if lowered.startswith(prefix):
            tool = raw_tool[len(prefix):]
            if tool:
                builtin = (server, tool, mcp_servers.get(server))
                break
    resolved = None
    if _explicit_mcp_identity_matches(raw_tool, server_name, tool_name) and (
        builtin[0] is None
        or len(_sanitize_copilot_server_name(server_name)) >= len(builtin[0])
    ):
        resolved = (server_name, tool_name, mcp_servers.get(server_name))
    if resolved is None:
        if lowered.startswith('mcp_') and not lowered.startswith('mcp__'):
            configured = _resolve_vscode_mcp(raw_tool, mcp_servers)
        else:
            configured = detect_mcp_call(raw_tool, mcp_servers)
        resolved = configured
        if builtin[0] is not None and (
            configured[0] is None
            or len(_sanitize_copilot_server_name(configured[0])) < len(builtin[0])
        ):
            resolved = builtin
    server, tool, config = resolved
    if server in _BUILTIN_MCP_SERVERS and not config and server not in mcp_servers:
        config = {'additional_data': {'scope': 'copilot-builtin'}}
    return (server, tool, config)


def extract_command_for_pretool(canonical, tool_input):
    """Extract the policy-check command from tool_input keyed by canonical tool type."""
    if canonical == 'Bash':
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
    """PreToolUse entry point. The repo gate runs FIRST because _evaluate_pre_tool_use_policies short-circuits for Read/Write/Edit when no policy covers them."""
    gate = _repo_gate_evaluate(event)
    if gate:
        return transform_response_for_copilot({
            'decision': 'deny',
            'reason': _repo_gate_block_reason(gate['repo']),
            'additionalContext': REPO_GATE_BLOCK_CONTEXT,
        })
    return _evaluate_pre_tool_use_policies(event, api_key)


def _evaluate_pre_tool_use_policies(event, api_key):
    """Run the gateway policy check for a PreToolUse event."""
    raw_tool = event.get('tool_name') or event.get('toolName') or ''
    if not isinstance(raw_tool, str):
        return {}
    # VS Code can hand toolArgs over as a JSON string. Every reader below calls
    # tool_input.get(), so normalize once here — a raw str raised out of the hook, and a
    # hook that raises fails open, so the tool ran with no policy check at all.
    tool_input = _normalize_arguments(event.get('tool_input') or event.get('toolArgs') or {})
    session_id = event.get('session_id') or event.get('sessionId')

    explicit_server = event.get('mcp_server_name') or event.get('mcpServerName')
    explicit_tool = event.get('mcp_tool_name') or event.get('mcpToolName')
    explicit_mcp = (
        isinstance(explicit_server, str) and bool(explicit_server)
        and isinstance(explicit_tool, str) and bool(explicit_tool)
    )
    canonical = canonical_tool_name(raw_tool)
    is_mcp = canonical.lower().startswith('mcp_')
    mcp_server = mcp_tool = mcp_server_config = None
    scan_config = None

    if explicit_mcp or is_mcp or canonical not in ALLOWED_NON_MCP_HOOK_NAMES:
        mcp_servers = read_copilot_mcp_servers(event.get('cwd'))
        mcp_server, mcp_tool, mcp_server_config = resolve_copilot_mcp(
            raw_tool,
            mcp_servers,
            explicit_server,
            explicit_tool,
        )
        if mcp_server is None:
            if canonical not in ALLOWED_NON_MCP_HOOK_NAMES and not is_mcp:
                return {}
            if is_mcp:
                log_error(
                    f"copilot mcp unresolved session={session_id} tool={raw_tool}",
                    'mcp_match',
                )
        else:
            is_mcp = True
            canonical = f"mcp__{mcp_server}__{mcp_tool}"
            if isinstance(mcp_server_config, dict) and (
                (mcp_server_config.get('additional_data') or {}).get('scope')
                != 'copilot-builtin'
            ):
                # A builtin has nothing on disk; its targeted scan can only
                # ever report unknown_config_shape.
                scan_config = mcp_server_config
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
        _attach_tool_content_hash(metadata)

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

    _cache_policies_from_response(api_response)

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

    if (
        is_mcp
        and api_response.get('decision') != 'deny'
        and api_response.get('unknown_mcp_server')
        and scan_config
    ):
        _dispatch_mcp_server_scan(mcp_server, scan_config)

    return transform_response_for_copilot(api_response)


def process_user_prompt_submit(event, api_key):
    """Process UserPromptSubmit event for policy checking. Also refreshes the policy cache, which is what makes the session's FIRST gated tool call enforceable: the gate never calls the network."""
    session_id = event.get('session_id')
    model = get_session_start_model(session_id) or 'auto'
    prompt = event.get('prompt', '')

    cache = load_policy_cache()
    need_pull_policies = cache is None or is_cache_stale(cache)

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'copilot',
        'model': model,
        'event_name': 'user_prompt',
        'messages': [{'role': 'user', 'content': prompt}] if prompt else []
    }
    if need_pull_policies:
        request_body['pull_policies'] = True

    api_response = send_to_hook_api(request_body, api_key)
    _cache_policies_from_response(api_response)
    return transform_response_for_copilot_prompt(api_response)


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
# `cd <target>` occurrences — absolute, ~-rooted, or relative — used to track
# the shell's working directory across the turn's shell commands.
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



def _next_shell_dir(command, shell_dir):
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


# --- Repository-scope gate: blocks writes, git commands and shell writes in repos outside the org's allowed scope, decided on-device and fail-open ---

# Write tools, git commands and shell writes only; reads, conversation and every other shell command (ls, cat, npm test) are ungated. Names are canonical_tool_name output.
_REPO_GATE_WRITE_TOOLS = frozenset({'Write', 'Edit'})
_REPO_GATE_SHELL_TOOLS = frozenset({'Bash'})
_REPO_GATE_TOOLS = _REPO_GATE_WRITE_TOOLS | _REPO_GATE_SHELL_TOOLS
REPO_GATE_BLOCK_CONTEXT = (
    'This action was blocked by an organization repository-scope policy. Do not '
    'attempt to achieve the same result using alternative tools, file operations, '
    'or workarounds. Inform the user and stop.'
)






def _repo_gate_command(tool_input):
    """The shell command a Bash call carries; Copilot spells the key four ways."""
    if not isinstance(tool_input, dict):
        return None
    command = (tool_input.get('command') or tool_input.get('input')
               or tool_input.get('text') or tool_input.get('value'))
    return command if isinstance(command, str) else None


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


def _repo_gate_candidates(canonical, tool_input, cwd):
    """Paths a Copilot call works in; pathless file tools scan serialized input."""
    tool_input = tool_input or {}
    candidates = []
    if canonical == 'Bash':
        command = (tool_input.get('command') or tool_input.get('input')
                   or tool_input.get('text') or tool_input.get('value') or '')
        if isinstance(command, str) and command:
            candidates.extend(
                p for p in _ABS_PATH_RE.findall(command)
                if not _is_system_checkout_path(p)
            )
            candidates.extend(_git_path_opt_targets(command, cwd))
            cwd = _next_shell_dir(command, cwd)
        if not candidates and cwd:
            candidates.append(cwd)
        return candidates
    path = (tool_input.get('filePath') or tool_input.get('path')
            or tool_input.get('file_path'))
    # A relative path resolves against the cwd; unresolvable falls to the blob scan.
    if isinstance(path, str) and path and not path.startswith('/') and cwd:
        path = os.path.normpath(os.path.join(cwd, path))
    if isinstance(path, str) and path.startswith('/'):
        if not _is_system_checkout_path(path):
            candidates.append(os.path.dirname(path))
        return candidates
    try:
        blob = json.dumps(tool_input)
    except (TypeError, ValueError):
        blob = ''
    candidates.extend(
        p for p in _ABS_PATH_RE.findall(blob) if not _is_system_checkout_path(p)
    )
    return candidates


def _repo_gate_session_id(event):
    """Copilot sends the conversation id under either spelling."""
    return event.get('session_id') or event.get('sessionId')


def _repo_gate_block_reason(repo):
    return (
        'Blocked by organization policy. "%s" is outside your organization\'s '
        'allowed repository scope.' % repo
    )


# --- incident reporting: telemetry only, dispatched after the verdict and never waited on ---

REPO_GATE_REPORT_MAX_CHARS = 2000
_REPO_GATE_INPUT_KEYS = ('command', 'commandLine', 'file_path', 'filePath',
                         'path', 'notebook_path')


def _repo_gate_clip(text):
    """Cap one reported string, keeping the body inside curl's pipe buffer."""
    if not isinstance(text, str) or not text:
        return None
    return text[:REPO_GATE_REPORT_MAX_CHARS]


def _repo_gate_binding_policy(block_policies):
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


def _repo_gate_post(body, api_key):
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


def _repo_gate_report(gate, block_policies, context):
    """Report one WARN or BLOCK, fire and forget; never raises, never blocks."""
    try:
        if (gate or {}).get('decision') != 'deny':
            return
        # main() already resolved the key; the fallback covers entry points that skip it.
        api_key = _cached_api_key or get_api_key()
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


def _repo_gate_evaluate(event):
    """Verdict for one tool call: None allows, else deny. Never raises."""
    try:
        canonical = canonical_tool_name(
            event.get('tool_name') or event.get('toolName') or '')
        tool_input = _normalize_arguments(
            event.get('tool_input') or event.get('toolArgs') or {})
        if not _repo_gate_applies(canonical, _repo_gate_command(tool_input)):
            return None
        block_policies = _repo_gate_block_policies(get_repo_policies())
        if not block_policies:
            return None

        candidates = _repo_gate_candidates(
            canonical, tool_input, event.get('cwd'))
        repo = _repo_gate_violating_repo(candidates, block_policies, {})
        gate = {'decision': 'deny', 'repo': repo} if repo else None
        _repo_gate_report(gate, block_policies, {
            'app_label': 'copilot',
            'session_id': event.get('session_id'),
            'tool_name': canonical,
            'tool_input': tool_input,
        })
        return gate
    except Exception:
        return None


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
    so the edit is scored like other file edits instead of being
    dropped for want of a path. Returns '' when no path line is present."""
    text = args.get('input') or args.get('patch') or args.get('diff') or ''
    if not isinstance(text, str):
        return ''
    m = re.search(r'^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+)$', text, re.MULTILINE)
    return m.group(1).strip() if m else ''


def map_copilot_tool(name, args, result_content, shell_state=None, root_projects=None,
                     mcp_servers=None, mcp_server_name=None, mcp_tool_name=None):
    """Map a Copilot tool call to a cursor-style tool_use entry.

    Returns None for internal and unsupported native tools.

    When `shell_state` ({'dir': <path>} tracked across the turn) and
    `root_projects` (per-repo origin cache) are provided, each entry gets a
    per-call `project` ("<org>/<repo>") — file entries resolve from their
    file path (relative paths joined onto the shell dir), shell entries from
    absolute paths in the command or the tracked shell dir.
    """
    if not isinstance(name, str) or not name:
        return None
    shell_state = shell_state if shell_state is not None else {}
    root_projects = root_projects if root_projects is not None else {}

    def _abs(path):
        if not isinstance(path, str) or not path:
            return None
        if path.startswith('/'):
            return path
        base = shell_state.get('dir')
        return os.path.normpath(os.path.join(base, path)) if base else None

    project = None
    if name in SHELL_TOOLS:
        command = args.get('command') or args.get('input') or args.get('text') or ''
        entry = {
            'type': 'afterShellExecution',
            'command': command,
            'output': result_content or '',
        }
        candidates = []
        if isinstance(command, str):
            candidates.extend(p for p in _ABS_PATH_RE.findall(command) if not _is_system_checkout_path(p))
            candidates.extend(_git_path_opt_targets(command, shell_state.get('dir')))
            shell_state['dir'] = _next_shell_dir(command, shell_state.get('dir'))
        if not candidates and shell_state.get('dir'):
            candidates.append(shell_state['dir'])
        project = _project_for_paths(candidates, root_projects)
    elif name in READ_TOOLS:
        file_path = args.get('filePath') or args.get('path') or args.get('file_path') or ''
        entry = {
            'type': 'beforeReadFile',
            'file_path': file_path,
            'content': result_content or '',
        }
        abs_path = _abs(file_path)
        if abs_path and _is_system_checkout_path(abs_path):
            abs_path = None
        project = _project_for_paths([os.path.dirname(abs_path)] if abs_path else [], root_projects)
    elif name in WRITE_TOOLS or name in EDIT_TOOLS:
        file_path = (args.get('filePath') or args.get('path') or args.get('file_path')
                     or _extract_patch_target_path(args) or '')
        entry = {
            'type': 'afterFileEdit',
            'file_path': file_path,
            'content': args.get('content') or args.get('file_text') or result_content or '',
        }
        abs_path = _abs(file_path)
        if abs_path and _is_system_checkout_path(abs_path):
            abs_path = None
        project = _project_for_paths([os.path.dirname(abs_path)] if abs_path else [], root_projects)
    else:
        mcp_servers = mcp_servers or {}
        lowered_name = name.lower()
        mcp_server, mcp_tool, mcp_server_config = resolve_copilot_mcp(
            name, mcp_servers, mcp_server_name, mcp_tool_name
        )
        if mcp_server is None and not lowered_name.startswith('mcp_'):
            return None
        entry = {
            'type': 'afterMCPExecution',
            'tool_name': name,
            'tool_input': args,
            'result_json': result_content or '',
        }
        if mcp_server is not None:
            entry['server_name'] = mcp_server
            entry['mcp_tool_name'] = mcp_tool
            metadata = {
                'mcp_server': mcp_server,
                'mcp_tool': mcp_tool,
                'mcp_server_config': mcp_server_config,
            }
            _attach_tool_content_hash(metadata)
            if metadata.get('mcp_server_config'):
                entry['mcp_server_config'] = metadata['mcp_server_config']
        try:
            candidates = [p for p in _ABS_PATH_RE.findall(json.dumps(args)) if not _is_system_checkout_path(p)]
        except Exception:
            candidates = []
        project = _project_for_paths(candidates, root_projects)

    # Drop empty-string values.
    mapped = {k: v for k, v in entry.items() if v != ''}
    if project:
        mapped['project'] = project
    return mapped


_USAGE_FIELDS = ('input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens')
# COPILOT_HOME replaces the whole ~/.copilot path (GitHub Copilot CLI config-dir reference).
_COPILOT_STORE = _copilot_home() / 'session-store.db'
# Stop fires before VS Code finishes a response; the counts are written during the stream
# and finalised after it, with elapsedMs written last. Observed lead from Stop to a finished
# response: 1.1s to 9.8s. Exceeding this bound is not data loss -- the watermark holds and a
# later Stop reports the turn. The Stop hook's budget is 60s.
_VSCODE_SETTLE_SECONDS = 10.0
_VSCODE_POLL_SECONDS = 0.25
_VSCODE_MAX_LINES = 50000
_VSCODE_MAX_LINE_CHARS = 1 << 20
# No separator, drive letter or dot-only name can appear, so an id can only ever name a
# file directly inside chatSessions/ and cannot escape it by construction.
_SAFE_ID_CHARS = frozenset('abcdefghijklmnopqrstuvwxyz'
                           'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')
# On Windows these resolve to devices wherever they appear, so opening one would attach to
# the device and hang the hook rather than miss a file.
_RESERVED_DEVICE_NAMES = frozenset(['con', 'prn', 'aux', 'nul']
                                   + ['com%d' % n for n in range(1, 10)]
                                   + ['lpt%d' % n for n in range(1, 10)])


def _is_regular_file(path):
    """A FIFO or device node here would block the hook for its whole budget, so opening is
    gated on a real file rather than on mere existence. Symlinks are followed: anything able
    to plant one inside the user's own home could edit this script instead."""
    try:
        return path.is_file()
    except OSError:
        return False


def _safe_path_component(value):
    return (isinstance(value, str) and 1 <= len(value) <= 128
            and not set(value) - _SAFE_ID_CHARS and value not in ('.', '..')
            and value.split('.')[0].lower() not in _RESERVED_DEVICE_NAMES)


def _capped_lines(handle, max_lines, max_chars):
    """Lines from an untrusted journal, bounded in count and in length. A count cap alone
    does not bound memory: one oversized line is still read whole before the count is seen.
    In text mode the readline hint counts characters, so utf-8 bounds the bytes at 4x that.
    Draining an oversize line is charged against the same budget, so the whole read costs at
    most max_lines readline calls however the file is shaped."""
    count = 0
    while count < max_lines:
        line = handle.readline(max_chars)
        if not line:
            return
        count += 1
        if len(line) >= max_chars and not line.endswith('\n'):
            while count < max_lines:  # drop the rest of an oversize line rather than buffer it
                rest = handle.readline(max_chars)
                count += 1
                if not rest or rest.endswith('\n'):
                    break
            continue
        yield line


def _epoch(value):
    """Audit-log stamps carry a local offset; Copilot's stores use Z or epoch millis."""
    if value is None or value == '' or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value / 1000.0 if value > 10_000_000_000 else float(value)
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return None


def _in_window(created, since, until):
    """Half-open (previous Stop, this Stop], so consecutive Stops partition the session
    instead of re-counting the same requests."""
    return created is not None and created <= until and (since is None or created > since)


def _cli_turn_usage(conversation_id, since, until):
    """Per-request tokens the CLI writes to its own store within seconds of each call.
    Its input_tokens counts both cache tiers, so they come back out to leave fresh input."""
    if not conversation_id or not _is_regular_file(_COPILOT_STORE):
        return None
    conn = None
    try:
        conn = sqlite3.connect(str(_COPILOT_STORE), timeout=1.0)
        conn.execute('PRAGMA query_only = 1')
        # Copilot builds older than this table are silent, not an error worth logging each Stop.
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table'"
                            " AND name = 'assistant_usage_events'").fetchone():
            return None
        rows = conn.execute(
            'SELECT input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, created_at'
            ' FROM assistant_usage_events WHERE session_id = ?', (conversation_id,)).fetchall()
        # Totals stay inside the guard: a non-numeric column would otherwise raise past the
        # Stop handler and drop the whole exchange, not just its usage.
        totals = dict((field, 0) for field in _USAGE_FIELDS)
        for row_input, row_output, cache_read, cache_write, created_at in rows:
            created = _epoch(created_at)
            if not _in_window(created, since, until):
                continue
            cache_read = max(int(cache_read or 0), 0)
            cache_write = max(int(cache_write or 0), 0)
            totals['input_tokens'] += max(int(row_input or 0) - cache_read - cache_write, 0)
            totals['output_tokens'] += max(int(row_output or 0), 0)
            totals['cache_read_input_tokens'] += cache_read
            totals['cache_creation_input_tokens'] += cache_write
    except Exception as e:
        log_error('cli usage read failed: %s' % e, 'usage')
        return None
    finally:
        if conn is not None:
            conn.close()
    return totals


def _vscode_store_path(transcript_path, conversation_id):
    """VS Code keeps per-request tokens in its own chat store, beside the copilot-chat
    transcript directory the hook reads. The transcripts themselves carry no tokens."""
    if not transcript_path or not _safe_path_component(conversation_id):
        return None
    parent = Path(transcript_path).parent
    if parent.name != 'transcripts':
        return None
    path = parent.parent.parent / 'chatSessions' / (conversation_id + '.jsonl')
    return path if _is_regular_file(path) else None


def _merge_vscode_request(requests, index, obj):
    if not isinstance(obj, dict):
        return
    entry = requests.setdefault(index, {})
    for field in ('promptTokens', 'completionTokens', 'timestamp', 'elapsedMs', 'modelId'):
        if obj.get(field) is not None:
            entry[field] = obj[field]
    # The model that actually served the request. Written with the response, so it lands
    # later than modelId, which is set when the request is created.
    result = obj.get('result')
    if isinstance(result, dict):
        for round_ in (result.get('metadata') or {}).get('toolCallRounds') or []:
            if isinstance(round_, dict) and round_.get('modelId'):
                entry['servedBy'] = round_['modelId']


def _vscode_requests(path):
    """Final state of the chat journal: a base snapshot, then whole requests appended and
    later patched field by field, so the last write for each field wins."""
    requests = {}
    next_index = 0
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            for line in _capped_lines(handle, _VSCODE_MAX_LINES, _VSCODE_MAX_LINE_CHARS):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = entry.get('k')
                value = entry.get('v')
                if key is None:
                    for obj in (value or {}).get('requests') or []:
                        _merge_vscode_request(requests, next_index, obj)
                        next_index += 1
                    continue
                keypath = [str(part) for part in key] if isinstance(key, list) else [str(key)]
                if keypath == ['requests'] and isinstance(value, list):
                    for obj in value:
                        _merge_vscode_request(requests, next_index, obj)
                        next_index += 1
                elif len(keypath) == 3 and keypath[0] == 'requests':
                    try:
                        index = int(keypath[1])
                    except ValueError:
                        continue
                    _merge_vscode_request(requests, index, {keypath[2]: value})
    except Exception as e:
        log_error('vscode usage read failed: %s' % e, 'usage')
        return None
    return requests


def _vscode_turn_model(transcript_path, conversation_id, previous_stop, turn_end):
    """Model for the turn this Stop is reporting. VS Code records it per request, so a
    mid-session switch is picked up; the transcript the exchange is built from carries no
    model at all, which is why every row otherwise reads 'auto'.

    Windowed to this turn, the same way usage is: from the previous Stop to this one. The
    journal is written lazily, so at this Stop the turn's own request may not be there yet.
    Without the lower bound the newest request would then be the PREVIOUS turn's, and its
    model would be reported here as though it were this one's -- a confidently wrong answer
    where saying nothing is correct. Reporting nothing leaves the row at 'auto'.

    Prefer the model that served the request, which names the real model behind an 'auto'
    pick but only lands once the response completes. The selection is there from the moment
    the prompt is sent, so an explicitly chosen model is reported even without it."""
    path = _vscode_store_path(transcript_path, conversation_id)
    if not path:
        return None
    requests = _vscode_requests(path)
    if not requests:
        return None
    since, until = _epoch(previous_stop), _epoch(turn_end)
    if until is None:
        return None
    windowed = [i for i in requests
                if _in_window(_epoch(requests[i].get('timestamp')), since, until)]
    if not windowed:
        return None
    entry = requests[max(windowed)]
    served = entry.get('servedBy')
    if isinstance(served, str) and served:
        return served
    selected = entry.get('modelId')
    if isinstance(selected, str) and selected:
        # Selections are namespaced (copilot/claude-haiku-4.5); the catalog is not.
        return selected.split('/', 1)[-1] or None
    return None


def _vscode_turn_usage(transcript_path, conversation_id, start_index, since=None, until=None):
    """Usage for requests from start_index on, stopping at the first whose tokens are not
    written yet. VS Code fills them in after Stop fires, and the lead grows with turn
    length, so an unfinished request is left for a later Stop rather than skipped. Returns
    (usage, next index to report, whether a request is still being written at that index).
    No cache split is reported.

    Position alone does not say which turn a request belongs to: one that settles after its
    own turn's Stop is still unread at the next one, so `since`/`until` decide what this
    turn may count."""
    path = _vscode_store_path(transcript_path, conversation_id)
    if not path:
        return None, start_index, False
    requests = _vscode_requests(path)
    if requests is None:
        return None, start_index, False
    totals = dict((field, 0) for field in _USAGE_FIELDS)
    index = max(int(start_index or 0), 0)
    lo, hi = _epoch(since), _epoch(until)
    # Guarded: a non-numeric count in the journal would otherwise raise past the Stop
    # handler and drop the whole exchange, not just its usage.
    try:
        while index in requests:
            entry = requests[index]
            prompt, completion = entry.get('promptTokens'), entry.get('completionTokens')
            # elapsedMs is written after the final counts, so it is the only reliable signal
            # that they have stopped climbing; the counts themselves appear mid-stream.
            if prompt is None or completion is None or entry.get('elapsedMs') is None:
                break
            created = _epoch(entry.get('timestamp'))
            # Past this turn's close the requests belong to turns not yet reported, so the
            # watermark stops here. Nothing is pending: what remains is a later turn's work,
            # not this one's, and waiting on it would stall the hook for the settle window.
            if hi is not None and created is not None and created > hi:
                return totals, index, False
            # An earlier turn's late request is read here but not counted here; it is left
            # to that turn's own windowed completion. The index still advances past it.
            if hi is None or _in_window(created, lo, hi):
                totals['input_tokens'] += max(int(prompt), 0)
                totals['output_tokens'] += max(int(completion), 0)
            index += 1
    except (TypeError, ValueError) as e:
        log_error('vscode usage totals failed: %s' % e, 'usage')
        return None, start_index, False
    return totals, index, index in requests


def _await_vscode_journal(transcript_path, conversation_id):
    """Wait out the settle window for a journal that has not finished being written.

    Only worth doing at session end. Mid-session an unwritten journal means a later Stop
    reports the turn, but at session end there is no later Stop, and VS Code sometimes
    writes the whole journal only as the session closes."""
    path = _vscode_store_path(transcript_path, conversation_id)
    if not path:
        return
    stamp = _vscode_store_stamp(path)
    deadline = time.monotonic() + _VSCODE_SETTLE_SECONDS
    written = False
    while time.monotonic() < deadline:
        time.sleep(_VSCODE_POLL_SECONDS)
        current = _vscode_store_stamp(path)
        if current is not None and current != stamp:
            # Still being written. Keep waiting for it to go quiet rather than reading a
            # half-written turn.
            stamp = current
            written = True
            continue
        if written:
            return  # it grew and has now settled
        # Unchanged so far means the write has not started, which is the case worth
        # waiting out here: returning now would give up on a journal VS Code writes a
        # few seconds into the close.


def _vscode_windowed_usage(transcript_path, conversation_id, since, until):
    """Usage for the requests belonging to one past turn, chosen by the window it ran in.

    A deferred turn cannot use the index the live path uses. That reader takes every
    settled request from a point onward, which is right for a Stop reporting the turn that
    just ended and wrong for a turn completed later, when the requests of every turn after
    it have settled too and the first read would swallow them all."""
    path = _vscode_store_path(transcript_path, conversation_id)
    if not path:
        return None
    requests = _vscode_requests(path)
    if not requests:
        return None
    lo, hi = _epoch(since), _epoch(until)
    if hi is None:
        return None
    totals = dict((field, 0) for field in _USAGE_FIELDS)
    found = False
    # Guarded for the same reason the index reader is: a non-numeric count in the journal
    # must not raise past the hook.
    try:
        for index in sorted(requests):
            entry = requests[index]
            if not _in_window(_epoch(entry.get('timestamp')), lo, hi):
                continue
            prompt, completion = entry.get('promptTokens'), entry.get('completionTokens')
            # elapsedMs is written after the final counts, so a request without it is
            # still climbing and is left out rather than counted low.
            if prompt is None or completion is None or entry.get('elapsedMs') is None:
                continue
            totals['input_tokens'] += max(int(prompt), 0)
            totals['output_tokens'] += max(int(completion), 0)
            found = True
    except (TypeError, ValueError) as e:
        log_error('vscode windowed usage failed: %s' % e, 'usage')
        return None
    if not found:
        return None
    totals['total_tokens'] = sum(totals[field] for field in _USAGE_FIELDS)
    return totals


def pending_turn_usage(transcript_path, conversation_id, since, until):
    """Usage for one turn being completed after the fact, by its own window on either
    surface. Both stores stamp every request, so neither needs the live path's watermark."""
    if transcript_path and Path(transcript_path).stem == 'events':
        usage = _cli_turn_usage(conversation_id, _epoch(since), _epoch(until))
        if usage and any(usage.values()):
            usage['total_tokens'] = sum(usage[field] for field in _USAGE_FIELDS)
            return usage
        return None
    return _vscode_windowed_usage(transcript_path, conversation_id, since, until)


def _vscode_store_stamp(path):
    """(mtime, size) of the chat journal, or None when it cannot be stat'd."""
    if not path:
        return None
    try:
        st = path.stat()
        return (st.st_mtime, st.st_size)
    except OSError:
        return None


def _vscode_settled_usage(transcript_path, conversation_id, start_index, since=None, until=None):
    """Wait for this turn to finish being written. Stop fires before the response ends, so
    a first read usually has nothing to report. Giving up is safe: the watermark does not
    advance, so a later Stop reports the turn instead.

    A turn being completed after the fact does not come through here at all; it reads by
    its own window, because by then every later turn has settled too."""
    usage, next_index, pending = _vscode_turn_usage(transcript_path, conversation_id,
                                                    start_index, since, until)
    # Wait only while a request is mid-write. With nothing pending there is nothing to wait
    # for, and blocking every quiet Stop for the full window would be pure cost.
    if usage is None or next_index > start_index or not pending:
        return usage, next_index
    path = _vscode_store_path(transcript_path, conversation_id)
    stamp = _vscode_store_stamp(path)
    deadline = time.monotonic() + _VSCODE_SETTLE_SECONDS
    while time.monotonic() < deadline:
        time.sleep(_VSCODE_POLL_SECONDS)
        # Re-parse only when the journal actually grew; polling alone would otherwise
        # re-read the whole file once per interval for the length of the wait.
        current = _vscode_store_stamp(path)
        if current is not None and current == stamp:
            continue
        stamp = current
        usage, next_index, _pending = _vscode_turn_usage(transcript_path, conversation_id,
                                                         start_index, since, until)
        if usage is None or next_index > start_index:
            break
    return usage, next_index


def get_turn_usage(transcript_path, conversation_id, previous_stop, turn_end, usage_index=0):
    """Exact usage for the turn, read from the local store behind whichever surface wrote
    the transcript -- Copilot forwards none, so without this the backend estimates from
    visible text and misses cache reads, tool definitions and system instructions.
    Windowed from the previous Stop rather than from this turn's prompt: Copilot fires a
    Stop per agent turn, so an open-ended window re-counts requests on every Stop, and a
    prompt-floored one drops the requests that land in the gap before the next prompt is
    logged. Consecutive Stops therefore partition the session exactly."""
    if transcript_path and Path(transcript_path).stem == 'events':
        since, until = _epoch(previous_stop), _epoch(turn_end)
        usage = None if until is None else _cli_turn_usage(conversation_id, since, until)
        next_index = usage_index
    else:
        usage, next_index = _vscode_settled_usage(transcript_path, conversation_id,
                                                  usage_index, previous_stop, turn_end)
    if not usage or not any(usage.values()):
        return None, next_index
    usage['total_tokens'] = sum(usage[field] for field in _USAGE_FIELDS)
    return usage, next_index


def build_exchange_from_transcript(transcript_path, fallback_session_id, session_start_model=None,
                                   cwd=None, already_forwarded=None, already_prompted=None):
    """Parse a Copilot JSONL transcript into a cursor-style LLM exchange.

    `cwd` (the hook event's working directory) seeds shell-dir tracking for
    per-call project attribution and rides on the exchange.

    Reads defensively — blank or unparseable lines are skipped, never raised.

    Copilot fires a Stop per agent turn but the transcript slice below spans every
    turn since the last user message, so without a guard each Stop re-sends the whole
    accumulated tool history. `already_forwarded` is the set of toolCallIds sent on
    earlier Stops of this session (from the audit-log markers); tool calls in it are
    skipped so only NEW ones ride each request. Returns (exchange, forwarded_now, text_sig) where forwarded_now is the set of
    toolCallIds included this time and text_sig fingerprints the turn's text — the caller
    records them only after a successful send, so a failed send simply retries."""
    already_forwarded = already_forwarded or set()
    already_prompted = already_prompted or set()
    if not transcript_path or not os.path.exists(transcript_path):
        return None, set(), None, set()

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
        return None, set(), None, set()

    # CLI stores transcripts at ~/.copilot/session-state/<conversation_id>/events.jsonl;
    # VS Code at .../transcripts/<sessionId>.jsonl. Recover the id from the path
    # when the payload carries none.
    conversation_id = fallback_session_id
    if not conversation_id:
        p = Path(transcript_path)
        conversation_id = p.parent.name if p.stem == 'events' else p.stem
    model = None
    turn_start_index = -1
    turn_prompts = []
    turn_prompt_ids = set()
    # The turn is every prompt not yet reported. Position in the transcript cannot decide
    # this: a prompt typed mid-turn lands inside the open agent turn in the CLI and outside
    # it in VS Code, and Copilot narrates progress as assistant text, so neither the agent
    # turn nor the assistant messages mark a boundary.

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
            content = data.get('content')
            # An entry without an envelope id still has to be watermarked, or every later
            # Stop re-selects it and re-uploads its text with the current turn. Keyed the
            # same way turn_id is when its id is missing.
            message_id = turn_prompt_id(entry, conversation_id, i, content)
            if message_id in already_prompted:
                continue
            if turn_start_index < 0:
                turn_start_index = i
            if content:
                turn_prompts.append(content)
            turn_prompt_ids.add(message_id)

    if turn_start_index < 0:
        return None, set(), None, set()

    # One message, not one per prompt: the backend keeps only the last user message.
    user_prompt = '\n\n'.join(turn_prompts) or None
    # Envelope id of this turn's user message: unique even when two turns
    # carry identical text, unlike a hash of that text.
    turn_id = entries[turn_start_index].get('id') or ''
    if not turn_id:
        # text_sig grows as assistant text accumulates, so it changes between
        # Stops of one turn and would defeat the watermark. The user prompt does
        # not change mid-turn, so hash that instead.
        # turn_start_index is the turn's position in the session: fixed while a
        # turn's assistant text grows, and different for a later turn even when
        # its prompt is identical.
        turn_id = hashlib.sha256(
            ('%s\x1f%s\x1f%s' % (conversation_id or '', turn_start_index, user_prompt or '')
             ).encode('utf-8', 'replace')).hexdigest()[:24]

    text_parts = []
    tool_calls = []          # ordered list of call ids
    tool_data = {}           # call_id -> {name, arguments, result, success}
    skill_events = []        # raw `skill.invoked` payloads seen this turn

    def _register(call_id):
        if call_id not in tool_data:
            tool_data[call_id] = {
                'name': '',
                'arguments': {},
                'result': None,
                'success': None,
                'mcp_server_name': None,
                'mcp_tool_name': None,
            }
            tool_calls.append(call_id)
        return tool_data[call_id]

    for entry in entries[turn_start_index + 1:]:
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
                if req.get('mcpServerName'):
                    call['mcp_server_name'] = req['mcpServerName']
                if req.get('mcpToolName'):
                    call['mcp_tool_name'] = req['mcpToolName']
                call['arguments'] = _normalize_arguments(req.get('arguments'))

        elif entry_type == 'skill.invoked':
            skill_events.append(entry)

        elif entry_type == 'tool.execution_start':
            call_id = data.get('toolCallId')
            if not call_id:
                continue
            call = _register(call_id)
            if data.get('toolName'):
                call['name'] = data['toolName']
            if data.get('mcpServerName'):
                call['mcp_server_name'] = data['mcpServerName']
            if data.get('mcpToolName'):
                call['mcp_tool_name'] = data['mcpToolName']
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
    # Per-call project attribution state: the shell starts at the session
    # cwd; origin lookups are cached once per repo across the turn.
    shell_state = {'dir': cwd}
    root_projects = {}
    mcp_servers = read_copilot_mcp_servers(cwd)
    forwarded_now = set()
    for call_id in tool_calls:
        call = tool_data[call_id]
        if call_id in already_forwarded:
            # Sent on an earlier Stop of this session — don't resend, but still
            # follow any `cd` so later calls' project attribution keeps tracking
            # the shell's working directory across the whole slice.
            if call['name'] in SHELL_TOOLS and isinstance(call.get('arguments'), dict):
                command = (call['arguments'].get('command') or call['arguments'].get('input')
                           or call['arguments'].get('text') or '')
                if isinstance(command, str):
                    shell_state['dir'] = _next_shell_dir(command, shell_state.get('dir'))
            continue
        mapped = map_copilot_tool(call['name'], call['arguments'], call['result'],
                                  shell_state=shell_state, root_projects=root_projects,
                                  mcp_servers=mcp_servers,
                                  mcp_server_name=call['mcp_server_name'],
                                  mcp_tool_name=call['mcp_tool_name'])
        # Advance the watermark for EVERY handled call, mapped or not: an internal tool
        # maps to None (nothing to send) but must still be recorded, else a turn of only
        # internal tools is reparsed on every later Stop and never records progress.
        forwarded_now.add(call_id)
        # `is not None` (not truthiness): None means a consciously-dropped internal
        # tool; an empty-but-valid dict should still be appended.
        if mapped is not None:
            if call_id:
                mapped['tool_use_id'] = call_id  # native transcript toolCallId — no synthetic id
            tool_use.append(mapped)

    # Signature of the turn's user+assistant TEXT (independent of tool_use). The caller
    # sends when there are new tools OR new text, and no-ops only when BOTH are unchanged
    # from the last successful send. So a pure tool-replay doesn't re-post, but a Stop
    # that appended new assistant text still sends (and is logged) even with no new tools.
    text_sig = hashlib.sha256(
        '\x1f'.join([user_prompt or ''] + text_parts).encode('utf-8', 'replace')
    ).hexdigest()

    # Copilot injects SKILL.md rather than calling a tool, but its session event
    # stream records the load; fall back to the prompt token when it doesn't.
    skill_uses = _skill_tool_uses_from_events(
        skill_events, cwd, turn_key=turn_id)
    seen_skills = {e.get('skill_name') for e in skill_uses}
    skill_uses += [e for e in _skill_tool_uses_from_prompt(
        user_prompt, cwd, conversation_id, turn_id)
        if e.get('skill_name') not in seen_skills]
    # Skills ride the same watermark as tool calls; without this a later Stop in
    # the same turn re-sends them and inflates counts.
    for entry in skill_uses:
        entry_id = entry.get('tool_use_id')
        if entry_id in already_forwarded:
            continue
        if entry_id:
            forwarded_now.add(entry_id)
        tool_use.append(entry)

    messages = []
    if user_prompt:
        messages.append({'role': 'user', 'content': user_prompt})

    assistant_msg = {'role': 'assistant', 'content': '\n\n'.join(text_parts)}
    if tool_use:
        assistant_msg['tool_use'] = tool_use
    messages.append(assistant_msg)

    if not messages:
        return None, set(), None, set()

    return {
        'conversation_id': conversation_id,
        'model': model or session_start_model or 'auto',
        'messages': messages,
        'cwd': cwd,
        # Turn-level fallback: rows without a per-call project (the user
        # prompt row, or tool-less turns) inherit the session cwd's repo.
        'project': _get_project(cwd),
    }, forwarded_now, text_sig, turn_prompt_ids


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


def _is_windows() -> bool:
    return os.name == "nt"


def _discovery_installer():
    if _is_windows():
        return DISCOVERY_INSTALL_PS1, DISCOVERY_INSTALL_PS1_URL
    return DISCOVERY_INSTALL_SH, DISCOVERY_INSTALL_URL


def _windows_system32_path(*parts: str) -> str:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise OSError("SystemRoot is not set")
    root = PureWindowsPath(system_root)
    if not root.is_absolute():
        raise OSError("SystemRoot is not absolute")
    return str(root.joinpath("System32", *parts))


def _discovery_command(installer_path: Path, backend_url: str):
    if _is_windows():
        return [
            _windows_system32_path("WindowsPowerShell", "v1.0", "powershell.exe"),
            "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(installer_path),
        ]
    return ["bash", str(installer_path), "--domain", backend_url]


def _ensure_discovery_installer(
    installer_path=None,
    installer_url=None,
):
    installer_path = installer_path or DISCOVERY_INSTALL_SH
    installer_url = installer_url or DISCOVERY_INSTALL_URL
    if installer_path.exists():
        return True
    DISCOVERY_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    fd, temporary_path = tempfile.mkstemp(dir=str(DISCOVERY_INSTALL_DIR), suffix='.tmp')
    os.close(fd)
    try:
        curl = _windows_system32_path("curl.exe") if _is_windows() else "curl"
        result = subprocess.run(
            [curl, "-fsSL", "-o", temporary_path, installer_url],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            log_error(
                f"discovery {installer_path.name} download failed: "
                + result.stderr.decode(errors='replace')[:200],
                'discovery_gate',
            )
            return False
        if installer_path == DISCOVERY_INSTALL_SH:
            os.chmod(temporary_path, 0o755)
        os.replace(temporary_path, installer_path)
        return True
    finally:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass


def _state_dir_reject_reason(path: Path, private: bool = False) -> Optional[str]:
    """None if the dir can hold discovery state, else why not. Clears a stale marker."""
    try:
        posix = hasattr(os, "getuid")
        if private:
            # Windows st_mode is synthetic (0o777, never sticky), so the POSIX
            # world-writable check there would reject every candidate.
            if posix:
                try:
                    pst = os.lstat(str(path.parent))
                    if (pst.st_mode & 0o002) and not (pst.st_mode & 0o1000):
                        return "fallback parent world-writable and not sticky"
                except OSError:
                    pass
            try:
                st = os.lstat(str(path))
                if path.is_symlink() or not stat.S_ISDIR(st.st_mode):
                    return "fallback dir is a symlink or not a dir"
                if posix and st.st_uid != os.getuid():
                    return "fallback dir foreign-owned"
            except FileNotFoundError:
                pass
        if private and posix:
            # Create with the mode so a symlink planted after the lstat cannot be
            # chmod-ed through; a pre-existing dir was validated above.
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                os.mkdir(str(path), 0o700)
            except FileExistsError:
                pass
            if os.lstat(str(path)).st_mode & 0o077:
                return "fallback dir not private"
        else:
            path.mkdir(parents=True, exist_ok=True)
        if not os.access(str(path), os.W_OK | os.X_OK):
            return "dir not writable"
        # os.access cannot see a Windows ACL denial; an actual write can.
        fd, probe = tempfile.mkstemp(prefix=".probe.", dir=str(path))
        os.close(fd)
        os.unlink(probe)
        cache_file = path / DISCOVERY_CACHE_PATH.name
        if cache_file.exists() and not os.access(str(cache_file), os.R_OK):
            return "cache file unreadable"
        # Non-destructive: a poisoned marker denies the open, a live peer's does not.
        marker = path / DISCOVERY_DISPATCH_PATH.name
        if marker.exists():
            os.close(os.open(str(marker), os.O_WRONLY))
        return None
    except OSError as e:
        return "%s errno=%s" % (type(e).__name__, e.errno)


def _relocate_state_dir(reason: str) -> bool:
    """Repoint cache/lock/marker at the temp fallback. True if it moved."""
    global DISCOVERY_CACHE_PATH, DISCOVERY_LOCK_PATH, DISCOVERY_DISPATCH_PATH
    current = DISCOVERY_DISPATCH_PATH.parent
    if _is_windows():
        fallback = Path(tempfile.gettempdir()) / "unbound"
    else:
        fallback = Path("/var/tmp/unbound-%d" % os.getuid())
    fallback_reason = ("same as current" if fallback == current
                       else _state_dir_reject_reason(fallback, private=True))
    # Paths carry the OS username; log the candidate, not the path (see #281).
    if fallback_reason is not None:
        log_error("discovery gate: no usable state dir (home: %s / fallback: %s)"
                  % (reason, fallback_reason), 'discovery_gate')
        return False
    log_error("discovery gate: home state dir unusable (%s); using fallback" % reason,
              'discovery_gate')
    DISCOVERY_CACHE_PATH = fallback / DISCOVERY_CACHE_PATH.name
    DISCOVERY_LOCK_PATH = fallback / DISCOVERY_LOCK_PATH.name
    DISCOVERY_DISPATCH_PATH = fallback / DISCOVERY_DISPATCH_PATH.name
    return True


def _resolve_state_dir() -> None:
    """Relocate before dispatching if the current state dir is unusable."""
    reason = _state_dir_reject_reason(DISCOVERY_DISPATCH_PATH.parent)
    if reason is not None:
        _relocate_state_dir(reason)


def _dispatch_discovery() -> None:
    try:
        _resolve_state_dir()
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
        except OSError:
            try:
                age = time.time() - DISCOVERY_DISPATCH_PATH.stat().st_mtime
            except OSError:
                age = DISCOVERY_DISPATCH_TTL_SECONDS + 1
            if age < DISCOVERY_DISPATCH_TTL_SECONDS:
                return
            try:
                DISCOVERY_DISPATCH_PATH.unlink(missing_ok=True)
                _dispatch_fd = os.open(str(DISCOVERY_DISPATCH_PATH),
                                       os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(_dispatch_fd)
            except OSError as e:
                log_error(f"discovery gate: dispatch claim failed: {type(e).__name__} errno={e.errno}", 'discovery_gate')
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
                if not _ensure_discovery_installer(installer_path, installer_url):
                    return
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
            DISCOVERY_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".discovery-cache.", suffix=".tmp",
                                       dir=str(DISCOVERY_CACHE_PATH.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(cache, f, indent=2, sort_keys=True)
                os.replace(tmp, DISCOVERY_CACHE_PATH)
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        finally:
            try:
                DISCOVERY_DISPATCH_PATH.unlink(missing_ok=True)
            except OSError:
                pass
    except Exception as e:
        log_error(f"discovery gate failed: {e}", 'discovery_gate')


def _dispatch_mcp_server_scan(server_name, server_config):
    if not server_name or not isinstance(server_config, dict):
        return
    try:
        with UNBOUND_CONFIG_PATH.open("r", encoding="utf-8") as f:
            unbound_config = json.load(f)
        api_key = unbound_config.get("api_key")
        backend_url = unbound_config.get("base_url")
        if not api_key or not backend_url:
            return

        if RUNNING_FROZEN:
            if not os.path.isfile(FROZEN_DISCOVERY_BIN):
                return
            scan_cmd = [FROZEN_DISCOVERY_BIN, "mcp-scan", "--name", server_name,
                        "--domain", backend_url]
        else:
            if not _ensure_discovery_installer():
                return
            scan_cmd = [
                "bash", str(DISCOVERY_INSTALL_SH), "mcp-scan", "--name", server_name,
                "--domain", backend_url,
            ]

        popen_kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "stdin": subprocess.DEVNULL,
            "close_fds": True,
            "env": {
                **os.environ,
                "UNBOUND_API_KEY": api_key,
                "UNBOUND_MCP_SERVER_JSON": json.dumps(server_config),
                "UNBOUND_CODING_TOOL": _UNBOUND_CODING_TOOL,
            },
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = (
                subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:
            popen_kwargs["start_new_session"] = True
        subprocess.Popen(scan_cmd, **popen_kwargs)
    except Exception as exc:
        log_error(f"mcp scan dispatch failed for {server_name}: {exc}", 'mcp_server')


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
            append_to_audit_log({
                'timestamp': datetime.now().astimezone().isoformat().replace('+00:00', 'Z'),
                'event': event,
            })
            # No repo gate here: conversation is never gated, but this call refreshes the policy cache so the session's first gated TOOL call is enforceable.
            response = process_user_prompt_submit(event, api_key)
            print(json.dumps(response) if response else "{}", flush=True)
            return

        # Create log entry with timestamp; the event already carries hook_event_name
        timestamp = datetime.now().astimezone().isoformat().replace('+00:00', 'Z')
        log_entry = {
            'timestamp': timestamp,
            'event': event,
        }
        append_to_audit_log(log_entry)

        if event_name in ('Stop', 'SessionEnd'):
            # Copilot sends the conversation id under either spelling and SessionEnd uses
            # the camelCase one. The turn-start and session-model lookups key on it, so
            # reading only the snake_case name would cost the exchange its start time and
            # its model attribution.
            session_id = event.get('session_id') or event.get('sessionId')
            if event_name == 'SessionEnd' and not event.get('transcript_path'):
                recovered = _transcript_path_for_session(event)
                if recovered:
                    event = dict(event, transcript_path=recovered)
            # Watermark key mirrors the exchange's session fallback, so get/record stay
            # consistent even when the Stop payload omits session_id.
            wm_key = stop_session_key(event)
            already_forwarded, last_text_sig, already_prompted, usage_index = get_forwarded_state(wm_key)
            exchange, forwarded_now, text_sig, prompts_now = build_exchange_from_transcript(
                event.get('transcript_path'), session_id,
                session_start_model=get_session_start_model(session_id),
                cwd=event.get('cwd'),
                already_forwarded=already_forwarded,
                already_prompted=already_prompted,
            )
            # Resolved before the send gate so a turn whose tokens landed too late for its
            # own Stop can ride this one. A Stop with nothing new builds no exchange at all,
            # so there is never anything to attach deferred usage to on a pure replay: it
            # waits for the next real turn, and a session that ends first loses it.
            if event_name == 'SessionEnd':
                # Before anything reads, because this is the last chance for every turn in
                # the session including the one ending it. Waiting after the read would
                # leave that turn a pending entry no later event will ever process.
                _await_vscode_journal(event.get('transcript_path'),
                                      (exchange or {}).get('conversation_id') or session_id)

            usage = None
            if exchange:
                previous_stop = get_previous_stop_timestamp_for_session(event)
                usage, usage_index = get_turn_usage(
                    event.get('transcript_path'), exchange.get('conversation_id'),
                    previous_stop, timestamp, usage_index)
                # After the usage settle, not before: that wait is for this same journal
                # being written, so resolving the model here sees anything it waited for.
                turn_model = _vscode_turn_model(event.get('transcript_path'),
                                                exchange.get('conversation_id'),
                                                previous_stop, timestamp)
                if turn_model:
                    exchange['model'] = turn_model
            # Send only when there is something new -- new tool calls, new assistant text,
            # or usage carried over from an earlier turn -- so a pure replay Stop is a
            # no-op, but a Stop that appended new text (even with no new tools) is sent.
            # The same gate makes SessionEnd a no-op unless the session ended with a turn
            # that no Stop ever reported; a turn already sent is left alone, because usage
            # is part of the backend's request id and re-sending would add a row, not
            # complete the existing one.
            # Earlier turns whose numbers arrived after their own Stop are completed here,
            # before this turn is handled, so each turn carries its own tokens.
            was_pending = get_session_marker(wm_key).get('pending_turns') or []
            still_pending = complete_pending_turns(
                event, wm_key, api_key, final=(event_name == 'SessionEnd'))

            if exchange and (forwarded_now or text_sig != last_text_sig or usage):
                # Turn boundaries from event-fire times
                request_initialized = get_turn_start_timestamp_for_session(session_id)
                if request_initialized:
                    exchange['requestInitialized'] = request_initialized
                exchange['requestCompleted'] = timestamp
                if usage:
                    exchange['usage'] = usage

                # Content, not position: the id has to survive being sent again once the
                # tokens land, and a turn that never reached the gateway would shift every
                # position after it.
                marker = get_session_marker(wm_key)
                digests = marker.get('turn_digests') or []
                user_prompt, assistant_prompt = exchange_turn_content(exchange)
                digest = turn_content_digest(user_prompt, assistant_prompt)
                turn_request_id = build_turn_request_id(session_id, digest, digests.count(digest))
                exchange['turn_request_id'] = turn_request_id

                # Record only after the send succeeds, so a failed send retries next Stop
                # (the backend dedups). Updates the text signature too, even with no new
                # tools, so an unchanged later Stop becomes a no-op.
                if send_to_api(exchange, api_key):
                    # One slot, holding an id and a window, never prompt text. Kept only
                    # while something is still missing, so a complete turn leaves nothing
                    # behind for the next Stop to re-send.
                    # Only one prompt can anchor a rebuild: the rebuild reads from that
                    # prompt to the next one, so a turn opened by several prompts would be
                    # cut short. Those turns simply go uncompleted.
                    anchor = next(iter(prompts_now)) if len(prompts_now) == 1 else None
                    # 'auto' is the unresolved model, not a missing one: a CLI turn takes
                    # its model from the transcript and is already settled.
                    incomplete = not usage or exchange.get('model') in (None, '', 'auto')
                    pending_turns = list(still_pending)
                    if incomplete and anchor:
                        pending_turns.append({
                            'turn_request_id': turn_request_id,
                            'conversation_id': exchange.get('conversation_id'),
                            'prompt_id': anchor,
                            'since': previous_stop,
                            'until': timestamp,
                        })
                    record_forwarded_tool_ids(wm_key, forwarded_now, text_sig, prompts_now,
                                              usage_index, digests + [digest],
                                              pending_turns[-MAX_PENDING_TURNS:])
            elif still_pending != was_pending:
                # Nothing new this Stop, but some turns settled; drop just those.
                record_forwarded_tool_ids(wm_key, set(), None, None, None, None,
                                          still_pending)
            cleanup_old_logs()

        # Output required by Copilot hooks
        print("{}")

    except Exception as e:
        # Log errors but still output {} to not break Copilot
        log_error(f"Exception in main: {str(e)}", 'general')
        print("{}")


if __name__ == '__main__':
    main()
