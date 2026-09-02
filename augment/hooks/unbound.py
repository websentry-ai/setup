#!/usr/bin/env python3

import sys
import json
import os
import subprocess
from pathlib import Path, PureWindowsPath
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import time
import hashlib
import re
import tempfile
import platform
from urllib.parse import urlparse, urlsplit, urlunsplit


UNBOUND_GATEWAY_URL = os.environ.get(
    "UNBOUND_GATEWAY_URL", "https://api.getunbound.ai"
).rstrip("/")
AUDIT_LOG = Path.home() / ".augment" / "hooks" / "agent-audit.log"
ERROR_LOG = Path.home() / ".augment" / "hooks" / "error.log"
LAST_REPORT_FILE = Path.home() / ".augment" / "hooks" / ".last_error_report"

# Augment tool vocabulary -> Unbound tool family. Augment forwards its own raw
# tool_name (launch-process, str-replace-editor, save-file, view/read-file,
# remove-files, ...); we map the well-known ones onto the families the gateway
# already understands but keep forwarding the raw name generically so a new /
# unmapped Augment tool still reaches policy evaluation.
AUGMENT_TOOL_FAMILY = {
    'launch-process': 'Bash',
    'str-replace-editor': 'Edit',
    'save-file': 'Write',
    'view': 'Read',
    'read-file': 'Read',
    'remove-files': 'Delete',
}
# Native (non-MCP) Augment tools whose family is a file operation — used to gate
# the policy-cache "tools_to_check" fast path, mirroring claude-code's
# NATIVE_FILE_TOOLS. Expressed in Augment vocab. remove-files is deliberately
# EXCLUDED: it is a destructive delete that must always reach the gateway, so it
# lives only in ALLOWED_NON_MCP_HOOK_NAMES (never eligible for the fast path).
NATIVE_FILE_TOOLS = {'str-replace-editor', 'save-file', 'view', 'read-file'}
# INVARIANT: every skill entry below carries a tool_use_id - the native one
# when the tool reports it, otherwise a deterministic synthetic one. The backend
# relies on this: two id-less invocations of one skill with the same arguments
# are byte-identical, so nothing can tell a replay from a genuine repeat.
SKILL_TOOL_NAME = 'Skill'
SKILL_SEARCH_DIRS = (('.augment', 'skills'), ('.claude', 'skills'),
                     ('.agents', 'skills'))
_SKILL_BODY_SCAN_LIMIT = 400
_SKILL_BODY_MATCH_CHARS = 400
# Non-MCP Augment tools we always evaluate (the rest fall through to the cache
# fast path). MCP tools are detected via the is_mcp_tool flag, not a name prefix.
ALLOWED_NON_MCP_HOOK_NAMES = ['launch-process', 'str-replace-editor', 'save-file', 'view', 'read-file', 'remove-files']
CLAUDE_PLUGIN_CACHE_DIR = Path.home() / ".claude" / "plugins" / "cache"
POLICY_CACHE_FILE = Path.home() / ".augment" / "hooks" / ".policy_cache.json"
CACHE_TTL_SECONDS = 300
# Repo-scope gate. Straying outside the allowed org is blocked on the first
# write, and the gate keeps no state on disk at all.
POLICY_CHECK_FAILURE_DEFAULT = 'allow'
POLICY_CHECK_FAILURE_BLOCK_REASON = 'policy engine unavailable — please retry'
AUDIT_LOG_TOTAL_LIMIT = 100

APPROVAL_TIMEOUT = 4 * 60 * 60

# Curl timeout (seconds) for the PreToolUse policy-check path (send_to_hook_api).
# Augment hard-caps the PreToolUse hook at 15s and (unlike Claude Code) does NOT
# fail open when it kills it, so this path must return gracefully within 15s. One
# 12s attempt covers the gateway classifier (~8s + RTT) with margin to fail open;
# the old 3x4s gave each attempt less time than the gateway needs, so the
# classifier path always timed out.
PRETOOL_CURL_TIMEOUT = 12

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

DISCOVERY_INSTALL_SH_TTL_SECONDS = 24 * 3600
UNBOUND_CONFIG_PATH = Path.home() / ".unbound" / "config.json"
IDENTITY_CACHE_PATH = Path.home() / ".unbound" / "identity.json"

SELF_UPDATE_URL = "https://raw.githubusercontent.com/websentry-ai/setup/refs/heads/main/augment/hooks/unbound.py"
SELF_UPDATE_INTERVAL_SECONDS = 2 * 3600
SELF_UPDATE_LOCK_TTL_SECONDS = 30
SELF_UPDATE_CURL_TIMEOUT = 10
SELF_SCRIPT_PATH = Path.home() / ".augment" / "hooks" / "unbound.py"
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


def _skill_dirs(cwd):
    """Every directory a skill could live in for this invocation, bounded by
    the same trust boundary the other skill helpers use. Accepts one path or
    several, since Augment can report more than one workspace root."""
    starts = [cwd] if isinstance(cwd, str) else list(cwd or [])
    roots = []
    for start in starts:
        if start:
            roots += _trusted_ancestors(Path(start))
    roots.append(Path.home())
    # Workspace roots repeat across events and their ancestor chains overlap;
    # without this the same tree is rescanned and the scan cap trips early.
    dirs, seen = [], set()
    for root in roots:
        for skill_dir in SKILL_SEARCH_DIRS:
            candidate = root.joinpath(*skill_dir)
            if str(candidate) not in seen:
                seen.add(str(candidate))
                dirs.append(candidate)
    return dirs


SKILL_READ_TOOLS = frozenset({'view', 'read-file', 'read'})


def _skill_absolute_read_path(read_path, roots):
    """Absolute form of a read path. Augment can report workspace-relative
    paths, which no absolute skill root would ever match."""
    try:
        if not read_path or os.path.isabs(read_path):
            return read_path
        for root in roots or []:
            candidate = os.path.join(root, read_path)
            if os.path.isfile(candidate):
                return candidate
        return read_path
    except Exception:
        return read_path


def _skill_read_path(event):
    """Path a read tool opened, across the field names Augment uses."""
    try:
        if (event.get('tool_name') or '') not in SKILL_READ_TOOLS:
            return None
        tool_input = event.get('tool_input') or {}
        for key in ('path', 'file_path', 'filePath'):
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                return value
        for change in (event.get('file_changes') or []):
            if isinstance(change, dict):
                value = change.get('path') or change.get('file_path')
                if isinstance(value, str) and value:
                    return value
        return None
    except Exception:
        return None


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


def _skill_path_key(path):
    """Separator-normalised path, so a read (which keeps the payload's '/')
    and a body match (which uses str(Path), '\\' on Windows) compare equal."""
    return path.replace('\\', '/') if isinstance(path, str) else path


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

def _skill_body(path):
    """SKILL.md contents with any YAML frontmatter stripped."""
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return ''
    if text.startswith('---'):
        end = text.find('\n---', 3)
        if end != -1:
            text = text[text.find('\n', end + 1) + 1:]
    return text.strip()


def _skill_from_prompt_body(prompt, cwd):
    """(name, path) when a prompt IS a skill's body. Auggie submits a skill's
    instructions as the request instead of the slash token, so matching the
    body on disk is the only way to identify a typed invocation."""
    try:
        text = (prompt or '').strip()
        if not text or '\n' not in text:
            return None
        head = text.splitlines()[0].strip()
        if not head:
            return None
        normalized = ' '.join(text.split())
        best = None
        scanned = 0
        for base in _skill_dirs(cwd):
            candidates = sorted(base.glob('*/SKILL.md')) + sorted(base.glob('*/*/SKILL.md'))
            for path in candidates:
                scanned += 1
                if scanned > _SKILL_BODY_SCAN_LIMIT:
                    return (best[1], best[2]) if best else None
                body = _skill_body(path)
                if not body or body.splitlines()[0].strip() != head:
                    continue
                flat = ' '.join(body.split())
                if normalized.startswith(flat[:_SKILL_BODY_MATCH_CHARS]):
                    # A short skill can be a prefix of a longer one, so keep the
                    # most specific match rather than the first.
                    if best is None or len(flat) > best[0]:
                        best = (len(flat), path.parent.name, str(path))
        return (best[1], best[2]) if best else None
    except Exception:
        return None


def _skill_entry(name, path, session_id, stamp, seq=0):
    """A skill invocation shaped like the tool_use entries the backend reads."""
    key = '\x1f'.join((str(session_id or ''), str(name), str(stamp or ''), str(seq)))
    return {
        'type': 'PostToolUse',
        'tool_name': SKILL_TOOL_NAME,
        'tool_input': {'skill': name, 'args': ''},
        'tool_response': {},
        'tool_use_id': 'unb-' + hashlib.sha256(
            key.encode('utf-8', 'replace')).hexdigest()[:24],
        'skill_name': name,
        'skill_path': path,
    }


def _utc_now_z() -> str:
    """UTC timestamp as an ISO-8601 string with a single 'Z' designator.

    datetime.now(timezone.utc).isoformat() emits a '+00:00' offset; appending a
    literal 'Z' to that produced a malformed double designator ('...+00:00Z',
    e.g. '2026-06-24T23:22:10.527627+00:00Z'). Replacing the offset with 'Z'
    yields a clean '...Z' (e.g. '2026-06-24T23:22:10.527627Z'). is_cache_stale
    parses this (and the legacy malformed/naive forms) via rstrip('Z')."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


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


def curl_with_auth(auth_headers: List[str], curl_args: List[str], *,
                   input: Optional[bytes] = None, timeout: int = 20):
    """Run curl with secret auth header(s) kept OFF the argv.

    On a shared / multi-user / MDM host the curl argv is world-readable via
    /proc/<pid>/cmdline and `ps`, so an `Authorization: Bearer <key>` or
    `X-API-KEY: <key>` passed as `-H "<header>"` would leak the secret. Instead
    write the auth header line(s) to a 0600 temp file and pass `-H @<tmpfile>`
    (curl reads headers from the file); the request body stays off-argv too via
    the caller's `--data-binary @-` on stdin. The temp file is deleted in a
    finally. `curl_args` is everything except the auth header (flags + the URL).

    Returns the subprocess.CompletedProcess, or None if the header file could
    not be written (caller treats that like a failed request → fail-open)."""
    fd, tmp_path = tempfile.mkstemp(prefix=".curlhdr.", suffix=".txt")
    try:
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                # One header per line; curl strips the trailing newline.
                f.write("\n".join(auth_headers) + "\n")
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return None
        cmd = ["curl", *curl_args, "-H", f"@{tmp_path}"]
        return subprocess.run(cmd, input=input, capture_output=True, timeout=timeout)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def report_error_to_gateway(message, category='general', api_key=None):
    """Fire-and-forget error report to gateway. Never blocks, never raises."""
    global _reporting_error
    if _reporting_error or not api_key or not _should_report():
        return
    _reporting_error = True
    message = redact_secrets(message, api_key)
    try:
        payload = json.dumps({
            'errors': [{'message': message, 'timestamp': _utc_now_z(), 'category': category}],
            'hook_source': 'augment_code',
        })
        # Auth header off-argv via the 0600 temp file; body off-argv via stdin.
        # Rate-limited (1/60s) + reentrancy-guarded, so a short blocking curl
        # here is acceptable and keeps the Bearer key out of /proc/<pid>/cmdline.
        curl_with_auth(
            [f"Authorization: Bearer {api_key}"],
            ["-fsSL", "-X", "POST",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-",
             f"{UNBOUND_GATEWAY_URL}/v1/hooks/errors"],
            input=payload.encode(),
            timeout=10,
        )
    except Exception:
        pass
    finally:
        _reporting_error = False


def log_error(message: str, category: str = 'general', report_to_gateway: bool = True):
    """Log error with timestamp to error.log, keeping only last 25 errors.
    report_to_gateway=False skips the gateway report (a rate-limited but blocking
    curl) for latency-sensitive paths that can't afford a second network wait."""
    message = redact_secrets(message, _cached_api_key)
    timestamp = _utc_now_z()
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

    if report_to_gateway:
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
    """Read failure-action from cache, defaulting to 'allow'. Ignores TTL.

    DEFER (known limitation): a stale cached failure-action of 'block' is
    intentionally honored offline with no TTL — fail-closed is the safe default
    when the gateway is unreachable. If reverting block->allow on an offline
    fleet ever becomes a problem, revisit adding a TTL here.
    """
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
            'last_synced': _utc_now_z(),
            'tools_to_check': tools_to_check,
            'policy_check_failure_action': policy_check_failure_action,
            'repo_policies': repo_policies,
        }
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
    """Check if cached data is older than CACHE_TTL_SECONDS.

    Compares aware-with-aware: parse last_synced and, if it came back naive
    (legacy on-disk values written before the tz-aware change), pin it to UTC
    so the subtraction against datetime.now(timezone.utc) never mixes
    aware/naive (which would raise TypeError and wrongly report 'stale')."""
    try:
        synced = datetime.fromisoformat(cache['last_synced'].rstrip('Z'))
        if synced.tzinfo is None:
            synced = synced.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - synced).total_seconds()
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


_APPROVAL_MARKER_FILE = Path.home() / ".augment" / "hooks" / ".approval_pending"


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
    # WARN/approval-required is delegated to the native toolPermissions ask-user
    # layer; the approval poll flow still surfaces a deny so the agent retries.
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
    memory (the PreToolUse handler). Loads the audit log and delegates to
    `_extract_session_model`."""
    if not session_id:
        return None
    try:
        return _extract_session_model(load_existing_logs(), session_id)
    except Exception:
        return None


def extract_command_for_pretool(event: Dict) -> str:
    """Extract a representative command/target string from Augment's tool_input.

    Augment's tool_input is an object whose shape varies per tool, so read
    defensively across the keys each Augment tool family uses, falling back to a
    JSON dump so the gateway always receives *something* matchable. MCP tools
    carry an opaque argument object — stringify the whole thing."""
    tool_input = event.get('tool_input')
    if not isinstance(tool_input, dict):
        tool_input = {}
    tool_name = event.get('tool_name', '')

    # MCP tools: stringify the input (server/tool live in mcp_metadata).
    if event.get('is_mcp_tool'):
        return json.dumps(tool_input)

    family = AUGMENT_TOOL_FAMILY.get(tool_name)

    # Shell/terminal family (launch-process): the command line. Use
    # `value is not None` (not truthiness) so an explicit empty-string command is
    # forwarded as-is rather than dumping the whole tool_input — an empty command
    # is a meaningful, policy-evaluable input.
    if family == 'Bash' or tool_name == 'launch-process':
        # DEFER (schema TBC): the 'commandLine' fallback key is unverified against
        # a live Augment instance — confirm before relying on it. Gateway deny
        # remains authoritative regardless of which key is read.
        for key in ('command', 'commandLine'):
            value = tool_input.get(key)
            if value is not None:
                return value if isinstance(value, str) else json.dumps(value)
        return json.dumps(tool_input)

    # File families (edit/write/read/delete): the path. Post-tool events may carry the
    # path only in file_changes[0] (not tool_input), so fall back to it -- matching how
    # _augment_posttooluse_to_exchange resolves the path -- so a pre event (tool_input
    # path) and its completion (file_changes path) hash to the same id.
    if family in ('Edit', 'Write', 'Read', 'Delete') or tool_name in NATIVE_FILE_TOOLS:
        for key in ('path', 'file_path', 'filePath'):
            value = tool_input.get(key)
            if value:
                return value if isinstance(value, str) else json.dumps(value)
        file_changes = event.get('file_changes')
        if isinstance(file_changes, list) and file_changes and isinstance(file_changes[0], dict):
            path = file_changes[0].get('path')
            if path:
                return path if isinstance(path, str) else json.dumps(path)
        return json.dumps(tool_input)

    # Unknown tool: surface whatever input it carries so policy can still match.
    if tool_input:
        return json.dumps(tool_input)
    return tool_name


def send_to_hook_api(request_body: Dict, api_key: str) -> Dict:
    """Send request to /v1/hooks/pretool endpoint."""
    if not api_key:
        return {}

    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/pretool"
    data = json.dumps(request_body)

    # Single attempt: a per-call timeout that covers the gateway's ~8s classifier
    # and retries cannot both fit under Augment's 15s hook cap, and gateway latency
    # (not transient blips) is what fails this path. On error/timeout, fall open.
    try:
        # Auth header off-argv (0600 temp file); body off-argv (stdin).
        result = curl_with_auth(
            [f"Authorization: Bearer {api_key}"],
            ["-fsSL", "-X", "POST",
             "-H", "Content-Type: application/json",
             "--data-binary", "@-", url],
            input=data.encode(),
            timeout=PRETOOL_CURL_TIMEOUT,
        )
        if result is None:
            return {}

        # rc==0 means curl got an HTTP 2xx (-f fails on 4xx/5xx). Parse the body
        # if present, otherwise return {} (an empty 2xx is a non-blocking allow).
        if result.returncode == 0 and result.stdout:
            try:
                return json.loads(result.stdout.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}
    except Exception as e:
        # Local log only: the gateway error-report is itself a (rate-limited)
        # blocking curl, so a second network wait here could push past Augment's
        # 15s PreToolUse cap and turn fail-open into a hard kill.
        log_error(f"Hook API error: {str(e)}", 'api_call', report_to_gateway=False)

    return {}


def _next_poll_interval(elapsed: float) -> int:
    """Pick the polling interval for the current elapsed time using APPROVAL_POLL_PHASES."""
    for upto, interval in APPROVAL_POLL_PHASES:
        if elapsed < upto:
            return interval
    return APPROVAL_POLL_PHASES[-1][1]

def poll_approval_status(api_key: str, policy_ids: list, application_id: str, request_id: str = '', timeout: int = APPROVAL_TIMEOUT) -> str:
    """Poll the approval-status endpoint until approved, denied, or timeout.
    Returns 'approved', 'deny', or 'timeout'.

    FLAG (Phase 2): this inline poll can run up to APPROVAL_TIMEOUT (~4h via
    APPROVAL_POLL_PHASES), which vastly exceeds Augment's 15000ms PreToolUse
    hook timeout — on Augment the hook would be killed before an approval ever
    resolves. This path is NOT exercised in Phase 1: the gateway never returns
    decision == 'approval_required' for unbound_app_label='augment_code' until
    Phase 2. When the Augment approval contract goes live, Phase 2 must make
    this poll bounded/re-entrant within the hook timeout: poll briefly per
    invocation, persist state via the existing _APPROVAL_MARKER_FILE, and return
    promptly so the next tool call resumes the wait."""

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
                # Auth header off-argv (0600 temp file); body off-argv (stdin).
                result = curl_with_auth(
                    [f"Authorization: Bearer {api_key}"],
                    ["-fsSL", "-X", "POST",
                     "-H", "Content-Type: application/json",
                     "--data-binary", "@-", url],
                    input=body.encode(),
                    timeout=10,
                )
                if result is not None and result.returncode == 0 and result.stdout:
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
    """Transform a gateway decision into an Augment PreToolUse hook output.

    Augment's hook output today only renders permissionDecision == "deny"
    (allow/ask are reserved for a future Augment release), so this maps:
      - allow                -> {} (empty; NEVER force-allow — let Augment run
                                its normal toolPermissions flow).
      - deny (BLOCK)         -> permissionDecision "deny" with the reason.
      - warn / ask /
        approval_required    -> {} (empty). WARN is delegated to the native
                                toolPermissions "ask-user" layer the installer
                                seeds; we do NOT coerce WARN -> deny.
      - any other non-allow  -> {} (empty); only a true BLOCK ever denies.
    The keyed-output JSON path is used (not exit 2) so a deny is emitted exactly
    once with no double-deny.
    """
    if not api_response:
        return {}

    decision = api_response.get('decision', 'allow')
    reason = api_response.get('reason', '')

    # Only a hard BLOCK (decision == 'deny') is rendered by Augment today.
    # Everything else (allow, warn, ask, approval_required, unexpected) returns
    # empty and is left to the native toolPermissions ask-user layer.
    if decision == 'deny':
        # Augment renders ONLY permissionDecisionReason on a PreToolUse deny, so
        # merge any additionalContext (our deny/block-failure responses put
        # agent-facing instructions there, e.g. "do not attempt workarounds")
        # into the reason or it would be dropped. Trim/skip when either side is
        # empty so we never emit a stray leading/trailing separator.
        additional_context = (api_response.get('additionalContext') or '').strip()
        reason_text = (reason or '').strip()
        if additional_context and reason_text:
            decision_reason = reason_text + '\n\n' + additional_context
        else:
            decision_reason = reason_text or additional_context
        return {
            'hookSpecificOutput': {
                'hookEventName': 'PreToolUse',
                'permissionDecision': 'deny',
                'permissionDecisionReason': decision_reason,
            }
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


# KEEP IN SYNC: coding-discovery-tool mcp_tools_cache.py + all 5 hook copies — byte-identical, do not diverge.
# Fingerprints key the local tool-hash cache; Redis tool scores are separately
# keyed by tool content hash. Keep fingerprint output aligned with data/gateway.

_MCP_TOOLS_CACHE_FILENAME = 'mcp-tools-cache.json'
_MCP_TOOLS_CACHE_MAX_BYTES = 2 * 1024 * 1024
_MCP_CACHE_CODING_TOOL_NAMES = frozenset({'auggie cli'})
_MCP_CACHE_CODING_TOOL_PREFIXES = ('augment (',)
_UNBOUND_CODING_TOOL = 'Auggie CLI'


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


# ── Cross-surface Augment MCP config resolution ──────────────────────────────
# Augment does NOT embed the server in the MCP tool_name (no `mcp__server__tool`)
# and the VS Code extension sends mcp_metadata=null, so an MCP call arrives as a
# raw tool_name of `<tool>_<userServerName>` (single underscores, user-chosen
# name) that can't be split reliably. We instead read Augment's own MCP config
# (the copilot model) across every surface — Auggie CLI, VS Code (+ forks) —
# recover the real server + its command/url by matching the raw name's server
# suffix, and forward mcp_server / mcp_tool / mcp_server_config so the gateway
# can fingerprint it -> canonical group -> policy match + analytics.
_MCP_CONFIG_MAX_BYTES = 1_000_000
_MIN_MCP_SERVER_NAME = 2


def _vscode_user_dirs() -> List[Path]:
    home = Path.home()
    if sys.platform == 'darwin':
        base = home / 'Library' / 'Application Support'
    elif os.name == 'nt':
        appdata = os.environ.get('APPDATA')
        base = Path(appdata) if appdata else home / 'AppData' / 'Roaming'
    else:
        cfg = os.environ.get('XDG_CONFIG_HOME')
        base = Path(cfg) if cfg else home / '.config'
    return [base / n / 'User' for n in ('Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf')]


def _augment_workspace_roots(event: Dict) -> List[Path]:
    roots = []
    for r in (event.get('workspace_roots') or []):
        if isinstance(r, str) and r:
            roots.append(Path(r))
    cwd = event.get('cwd')
    if isinstance(cwd, str) and cwd:
        roots.append(Path(cwd))
    return roots


def _augment_mcp_config_sources(event: Dict) -> List[tuple]:
    """(path, format) for every Augment MCP config surface; format in
    {'cli', 'vscode'}."""
    home = Path.home()
    sources = [(home / '.augment' / 'settings.json', 'cli')]
    for root in _augment_workspace_roots(event):
        sources.append((root / '.augment' / 'settings.json', 'cli'))
        sources.append((root / '.augment' / 'settings.local.json', 'cli'))
    for user_dir in _vscode_user_dirs():
        sources.append((
            user_dir / 'globalStorage' / 'augment.vscode-augment'
            / 'augment-global-state' / 'mcpServers.json', 'vscode'))
    return sources


def _split_command_string(cmd: str):
    """VS Code packs the whole command line into one string; split into
    (command, args) on whitespace."""
    if not isinstance(cmd, str) or not cmd.strip():
        return None, []
    parts = cmd.split()
    return (parts[0], parts[1:]) if parts else (None, [])


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


def _normalize_mcp_entry(entry: Dict, name: Optional[str] = None) -> Optional[Dict]:
    """Normalize a config entry from any surface to {command, args, url, type}
    (fingerprint-relevant fields only, secrets redacted). Handles VS Code's single
    command string. env/headers are intentionally never read or forwarded."""
    if not isinstance(entry, dict):
        return None
    out = {}
    if entry.get('type'):
        out['type'] = entry['type']
    if entry.get('url'):
        out['url'] = _redact_url(entry['url'])
    cmd = entry.get('command')
    args = entry.get('args')
    if isinstance(args, str):
        args = args.split()
    if isinstance(cmd, str) and ' ' in cmd.strip() and not args:
        c, a = _split_command_string(cmd)
        if c:
            args = a
            out['command'], out['args'] = c, _redact_args(a)
    elif cmd:
        out['command'] = cmd
        if isinstance(args, list):
            out['args'] = _redact_args(args)
    elif isinstance(args, list) and args:
        out['args'] = _redact_args(args)
    extra = entry.get('arguments')
    if 'args' not in out and isinstance(extra, str) and extra.strip():
        args = extra.split()
        out['args'] = _redact_args(args)
    fingerprint = compute_mcp_cache_key(
        name=name,
        command=out.get('command'),
        url=entry.get('url'),
        args=args if isinstance(args, list) else None,
        additional_data=entry.get('additional_data'),
        script_hash=out.get('scriptHash'),
    )
    if fingerprint:
        out['_unbound_fingerprint'] = fingerprint
    return out or None


def read_augment_mcp_servers(event: Dict) -> Dict:
    """Aggregate MCP servers across all Augment surfaces into {name -> config}.
    First definition of a name wins; never raises (fail-open)."""
    servers = {}
    for path, fmt in _augment_mcp_config_sources(event):
        try:
            if not path.exists() or path.stat().st_size > _MCP_CONFIG_MAX_BYTES:
                continue
            data = json.loads(path.read_text(encoding='utf-8'))
            entries = []
            if fmt == 'vscode' and isinstance(data, list):
                entries = [(e.get('name'), e) for e in data if isinstance(e, dict)]
            elif fmt == 'cli' and isinstance(data, dict) and isinstance(data.get('mcpServers'), dict):
                entries = list(data['mcpServers'].items())
            for name, entry in entries:
                if name:
                    servers.setdefault(name, _normalize_mcp_entry(entry, name=name) or {})
        except Exception as exc:
            log_error(f"augment mcp config read failed {path}: {exc}", 'mcp_config')
            continue
    return servers


def _augment_mcp_fingerprint_key(cfg: Optional[Dict]):
    if not cfg:
        return None
    if cfg.get('url'):
        return ('url', cfg['url'])
    if cfg.get('command'):
        return ('cmd', cfg['command'], tuple(cfg.get('args') or []))
    return None


def resolve_augment_mcp(raw_tool: str, mcp_servers: Dict):
    """Augment names an MCP tool `<tool>_<serverDisplayName>` (server is a SUFFIX,
    munged: non-alphanumerics -> '_'). Match the longest configured server name as
    a suffix; if a different server with a different fingerprint also matches it is
    ambiguous -> unresolved (don't guess). Returns (server, tool, config)."""
    if not raw_tool or not mcp_servers:
        return (None, None, None)
    raw_lower = raw_tool.lower()
    candidates = []  # (munged_len, server_name, tool)
    for server_name in mcp_servers:
        munged = _mangle_mcp_token(server_name)
        if len(munged) < _MIN_MCP_SERVER_NAME:
            continue
        suffix = '_' + munged.lower()
        if raw_lower.endswith(suffix) and len(raw_tool) > len(suffix):
            tool = raw_tool[:len(raw_tool) - len(suffix)]
            candidates.append((len(munged), server_name, tool))
    if not candidates:
        return (None, None, None)
    best = max(candidates, key=lambda c: c[0])
    best_key = _augment_mcp_fingerprint_key(mcp_servers.get(best[1]))
    for cand in candidates:
        if cand[1] == best[1]:
            continue
        other_key = _augment_mcp_fingerprint_key(mcp_servers.get(cand[1]))
        if best_key is None or other_key is None or other_key != best_key:
            return (None, None, None)
    return (best[1], best[2], mcp_servers.get(best[1]))


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


def _email_domain(email: Optional[str]) -> Optional[str]:
    try:
        if email and '@' in email:
            domain = email.rsplit('@', 1)[1].strip().lower()
            return domain or None
    except Exception:
        pass
    return None


def _config_email() -> Optional[str]:
    """The signed-in user's email from ~/.unbound/config.json, which the installer
    writes. Fully fail-safe: any read/parse error -> None, never raises."""
    try:
        with open(UNBOUND_CONFIG_PATH, 'r', encoding='utf-8') as f:
            cfg = json.loads(f.read())
        if isinstance(cfg, dict):
            return (cfg.get('email') or '').strip() or None
    except Exception:
        pass
    return None


def read_account_identity(event: Optional[Dict] = None) -> Dict:
    """Resolve the signed-in user's email.

    Prefer context.userEmail, which Auggie delivers because setup.py seeds the
    includeUserContext metadata flag; otherwise fall back to the `email` the
    installer writes into ~/.unbound/config.json. org/plan/auth_mode are always
    None (the gateway resolves the org from the API key). Fail-safe: any read
    error -> None, never raises."""
    email = None
    try:
        if isinstance(event, dict):
            context = event.get('context')
            if isinstance(context, dict):
                email = (context.get('userEmail') or '').strip() or None
    except Exception:
        pass
    if email is None:
        email = _config_email()
    return {
        'org_id': None,
        'plan': None,
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
    shared with the claude-code/cursor hooks, so we merge and write atomically."""
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


def build_account_identity(event: Optional[Dict] = None, probe: bool = False) -> Dict:
    """read_account_identity reads context.userEmail off the event; just add the
    device serial. probe defaults False so the latency-critical pre-tool path only
    reads the cache; the end-of-turn exchange passes probe=True. Never raises — on
    any failure the hook proceeds with whatever identity it has (possibly none)."""
    try:
        identity = read_account_identity(event)
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


def _augment_model(event: Dict, session_id: Optional[str]) -> str:
    """Model for this turn: Augment injects context.modelName when the matcher
    enables includeUserContext; fall back to the cached SessionStart model, then
    'auto'."""
    try:
        context = event.get('context')
        if isinstance(context, dict):
            name = (context.get('modelName') or '').strip()
            if name:
                return name
    except Exception:
        pass
    return event.get('model') or _get_session_model(session_id) or 'auto'


def _resolve_tool_use_id(event: Dict) -> str:
    """Native per-call id if present, else a deterministic synthetic one.

    Augment has no native tool_use_id and no turn id, so the id is derived
    purely from replay-stable content (conversation/session id + raw tool name
    + extracted command). The PreToolUse emit and the Stop-replayed PostToolUse
    emit run in different processes yet compute the byte-identical id for the
    same call — no side file, no timestamps. Native id always wins; any error
    falls back to native-or-absent (fail-open, never crashes the hook)."""
    native = event.get('tool_use_id')
    if native:
        return native
    try:
        content = extract_command_for_pretool(event)
        try:
            content = json.dumps(json.loads(content), sort_keys=True)
        except (ValueError, TypeError):
            pass
        key = '\x1f'.join((
            str(event.get('session_id') or event.get('conversation_id') or ''),
            str(event.get('tool_name') or ''),
            str(content),
        ))
        return 'unb-' + hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:24]
    except Exception:
        return native


def process_pre_tool_use(event: Dict, api_key: str) -> Dict:
    """PreToolUse entry point - DO NOT LOG. The gate runs FIRST because _evaluate_pre_tool_use_policies short-circuits for the native file tools; both Augment gates share one scope and deny from the first violating call, with no warning phase."""
    if _repo_gate_gated_call(event):
        workspace_repo = _repo_gate_session_repo(event, report=True)
        if workspace_repo:
            return transform_response_for_claude({
                'decision': 'deny',
                'reason': _repo_gate_workspace_block_reason(workspace_repo),
                'additionalContext': REPO_GATE_BLOCK_CONTEXT,
            })
    gate = _repo_gate_evaluate(event)
    if gate:
        return transform_response_for_claude({
            'decision': 'deny',
            'reason': _repo_gate_block_reason(gate['repo']),
            'additionalContext': REPO_GATE_BLOCK_CONTEXT,
        })
    return _evaluate_pre_tool_use_policies(event, api_key)


def _evaluate_pre_tool_use_policies(event: Dict, api_key: str) -> Dict:
    """Run the gateway policy check for a PreToolUse event - DO NOT LOG."""
    session_id = event.get('session_id')
    model = _augment_model(event, session_id)
    tool_name = event.get('tool_name', '')

    # Augment tells us directly whether a tool is MCP (no mcp__ name prefix).
    is_mcp = bool(event.get('is_mcp_tool'))
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

    command = extract_command_for_pretool(event)

    # Build metadata with the raw event.
    metadata = dict(event)
    tool_input = event.get('tool_input') if isinstance(event.get('tool_input'), dict) else {}
    for key in ('file_path', 'path', 'filePath'):
        if key in tool_input:
            metadata['file_path'] = tool_input[key]
            break

    if is_mcp:
        # mcp_metadata is set only when the matcher has includeMCPMetadata AND the
        # surface populates it (the VS Code extension sends null). Prefer it; else
        # recover the real server + tool by matching the raw tool_name's server
        # suffix against Augment's own MCP config across CLI/VS Code.
        servers = read_augment_mcp_servers(event)
        mcp_server_name = mcp_tool_name = ''
        mcp_cfg = None
        mcp_metadata = event.get('mcp_metadata')
        if isinstance(mcp_metadata, dict):
            mcp_server_name = (mcp_metadata.get('mcpExecutedToolServerName') or '').strip()
            mcp_tool_name = (mcp_metadata.get('mcpExecutedToolName') or '').strip()
        if mcp_server_name:
            mcp_cfg = servers.get(mcp_server_name)
        else:
            r_server, r_tool, mcp_cfg = resolve_augment_mcp(tool_name, servers)
            if r_server:
                mcp_server_name, mcp_tool_name = r_server, r_tool
        if mcp_server_name:
            metadata['mcp_server'] = mcp_server_name
            metadata['mcp_tool'] = mcp_tool_name
            if mcp_cfg:
                metadata['mcp_server_config'] = mcp_cfg
            _attach_tool_content_hash(metadata)

    approval_key = f"{tool_name}:{command}"
    is_retry = _is_approval_retry(approval_key)

    request_body = {
        'conversation_id': session_id,
        'unbound_app_label': 'augment_code',
        'model': model,
        'event_name': 'tool_use',
        'pre_tool_use_data': {
            'command': command,
            'tool_name': tool_name,
            'metadata': metadata
        },
        'account_identity': build_account_identity(event),
        # Augment has no UserPromptSubmit hook, so there is no recent-prompt
        # history to forward.
        'messages': [],
        'user_prompts': [],
    }

    _tuid = _resolve_tool_use_id(event)
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
        # Fail-open is load-bearing: a failing/unreachable check ALLOWS. The ONLY
        # non-fail-open path is an explicit cached policy_check_failure_action of
        # 'block' (defaults to 'allow').
        if get_policy_check_failure_action() == 'block':
            return transform_response_for_claude({
                'decision': 'deny',
                'reason': POLICY_CHECK_FAILURE_BLOCK_REASON,
                'additionalContext': 'The organization policy engine could not be reached. This is a transient infrastructure failure. Tell the user the policy engine is unavailable and ask them to retry.',
            })
        # Local log only (mirrors send_to_hook_api's except): the gateway report
        # is a blocking curl, so a second network wait after the ~12s pretool call
        # would blow Augment's 15s PreToolUse cap and turn fail-open into a kill.
        log_error(
            f'Hook bypassed_due_to_failure: gateway unreachable for tool={tool_name}',
            category='bypassed_due_to_failure',
            report_to_gateway=False,
        )
        return {}

    _cache_policies_from_response(api_response)

    if api_response.get('decision') == 'approval_required':
        # FLAG (Phase 2): inert in Phase 1 — the gateway never returns
        # 'approval_required' for unbound_app_label='augment_code' yet. When it does,
        # the inline poll_approval_status wait (up to ~4h) exceeds Augment's
        # 15000ms PreToolUse timeout and would be killed; see the bounded/
        # re-entrant note on poll_approval_status.
        return _handle_approval_required_response(api_response, approval_key)

    if is_mcp and api_response.get('unknown_mcp_server'):
        server_cfg = metadata.get('mcp_server_config')
        if server_cfg:
            _dispatch_mcp_server_scan(metadata.get('mcp_server', ''), server_cfg)

    return transform_response_for_claude(api_response)


def _strip_git_suffix(segment: str) -> str:
    return segment[:-4] if segment.endswith('.git') else segment


def _github_remote_path(remote_url: Optional[str]) -> Optional[str]:
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


# Canonical (post-AUGMENT_TOOL_FAMILY) tool names whose input carries a file
# path — used for per-tool-call project attribution on the Stop exchange.
_FILE_TOOLS = {'Read', 'Write', 'Edit', 'Delete'}

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
# the shell's working directory across the turn's launch-process calls.
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
        if target == '-':  # `cd -` — previous dir isn't tracked; keep as-is
            return shell_dir
        if shell_dir:
            return os.path.normpath(os.path.join(shell_dir, target))
        return shell_dir
    except Exception:
        return shell_dir


def _project_for_tool_use(tool_name: Optional[str], tool_input: Optional[Dict], shell_dir: Optional[str], root_projects: Dict[str, Optional[str]]) -> tuple:
    """Resolve the git project ("<org>/<repo>") a single tool call worked in.
    File tools resolve from the tool's file path (Augment often sends
    workspace-relative paths — those join onto the tracked shell dir); Bash
    resolves from the first absolute path in the command, else the shell's
    working directory tracked across the turn's `cd`s. Returns
    (project, shell_dir) — shell_dir updated when the command changed
    directory. `root_projects` caches the origin lookup so `git remote
    get-url` runs at most once per distinct repo. (None, shell_dir) when
    nothing resolves (fail-open)."""
    try:
        tool_input = tool_input or {}
        candidates = []
        if tool_name in _FILE_TOOLS:
            path = tool_input.get('file_path')
            if isinstance(path, str) and path:
                if not path.startswith('/') and shell_dir:
                    path = os.path.normpath(os.path.join(shell_dir, path))
                if path.startswith('/') and not _is_system_checkout_path(path):
                    candidates.append(os.path.dirname(path))
        elif tool_name == 'Bash':
            command = tool_input.get('command')
            if isinstance(command, str):
                candidates.extend(
                    p for p in _ABS_PATH_RE.findall(command) if not _is_system_checkout_path(p)
                )
                candidates.extend(_git_path_opt_targets(command, shell_dir))
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


# --- Repository-scope gate: blocks writes, git commands and shell writes outside the org's allowed scope; Augment (https://docs.augmentcode.com/cli/hooks) has no warning phase and denies from the first violating call ---

# Write tools, git commands and shell writes only; the read tools (view, read-file) are ungated, remove-files is a write, and every other shell command (ls, cat, npm test) is ungated.
_REPO_GATE_WRITE_TOOLS = frozenset({'str-replace-editor', 'save-file',
                                    'remove-files'})
_REPO_GATE_SHELL_TOOLS = frozenset({'launch-process'})
_REPO_GATE_TOOLS = _REPO_GATE_WRITE_TOOLS | _REPO_GATE_SHELL_TOOLS
REPO_GATE_BLOCK_CONTEXT = (
    'This action was blocked by an organization repository-scope policy. Do not '
    'attempt to achieve the same result using alternative tools, file operations, '
    'or workarounds. Inform the user and stop.'
)






def _repo_gate_command(tool_input):
    """The shell command a launch-process call carries, in Augment's shape."""
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get('command') or tool_input.get('commandLine')
    return command if isinstance(command, str) else None


def _repo_gate_applies(tool_name, command):
    """Whether this call is in the gate's scope: a write tool always, a shell call only when it invokes git or writes."""
    if tool_name in _REPO_GATE_SHELL_TOOLS:
        return _is_git_command(command) or _is_shell_write_command(command)
    return tool_name in _REPO_GATE_WRITE_TOOLS


def _repo_gate_gated_call(event: Dict) -> bool:
    """Whether this PreToolUse call is in the gate's scope at all; both Augment gates consult it, so reads and non-mutating shell commands pass either way."""
    try:
        if event.get('is_mcp_tool'):
            return False
        return _repo_gate_applies(
            event.get('tool_name') or '',
            _repo_gate_command(event.get('tool_input')))
    except Exception:
        return False


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
    """Paths an Augment call works in; relative paths join the working dir."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    candidates = []
    if tool_name in _REPO_GATE_SHELL_TOOLS:
        command = tool_input.get('command') or tool_input.get('commandLine')
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
    path = None
    for key in ('path', 'file_path', 'filePath'):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            path = value
            break
    if not path:
        return candidates
    if not path.startswith('/') and cwd:
        path = os.path.normpath(os.path.join(cwd, path))
    if path.startswith('/') and not _is_system_checkout_path(path):
        candidates.append(os.path.dirname(path))
    return candidates


def _repo_gate_block_reason(repo: str) -> str:
    """Augment renders only permissionDecisionReason, so this carries it all."""
    return (
        'Blocked by organization policy. This action works in the repository '
        '"%s", which is outside your organization\'s allowed repository scope. '
        'Move this work to an in-scope repository.' % repo
    )


def _repo_gate_workspace_block_reason(repo: str) -> str:
    """Augment renders only permissionDecisionReason, so this carries it all."""
    return (
        'Blocked by organization policy. This workspace is the repository "%s", '
        'which is outside your organization\'s allowed repository scope, so every '
        'tool call here is blocked. Move this work to an in-scope repository and '
        'start a new session there.' % repo
    )


def _repo_gate_session_advisory(repo: str) -> str:
    """SessionStart advisory text; SessionStart cannot block."""
    return (
        'Unbound repository policy: this workspace is the repository "%s", which '
        'is outside your organization\'s allowed repository scope. Edits, file '
        'writes and git commands in this workspace will be denied; reading is '
        'allowed. Tell the user to move this work to an in-scope repository.'
        % repo
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
    """Stable pick among denying policies; augment denies from the first call."""
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


def _repo_gate_evaluate(event: Dict) -> Optional[Dict]:
    """Per-path deny: straying outside the allowed org is blocked outright."""
    try:
        if not _repo_gate_gated_call(event):
            return None
        tool_name = event.get('tool_name') or ''
        block_policies = _repo_gate_block_policies(get_repo_policies())
        if not block_policies:
            return None

        candidates = _repo_gate_candidates(
            tool_name, event.get('tool_input'), event.get('cwd')
        )
        repo = _repo_gate_violating_repo(candidates, block_policies, {})
        if not repo:
            return None
        gate = {'decision': 'deny', 'repo': repo}
        _repo_gate_report(gate, block_policies, {
            'app_label': 'augment_code',
            'session_id': event.get('session_id'),
            'tool_name': tool_name,
            'tool_input': event.get('tool_input'),
        })
        return gate
    except Exception:
        return None


def _repo_gate_session_repo(event: Dict, report: bool = False) -> Optional[str]:
    """Out-of-scope repo at the workspace root; SessionStart advises, so no report."""
    try:
        block_policies = _repo_gate_block_policies(get_repo_policies())
        if not block_policies:
            return None
        cwd = event.get('cwd') or _resolve_cwd(event)
        if not cwd:
            return None
        repo = _repo_gate_violating_repo([cwd], block_policies, {})
        if repo and report:
            _repo_gate_report({'decision': 'deny', 'repo': repo}, block_policies, {
                'app_label': 'augment_code',
                'session_id': event.get('session_id'),
                'tool_name': event.get('tool_name'),
                'tool_input': event.get('tool_input'),
            })
        return repo
    except Exception:
        return None


def _repo_gate_session_start_output(event: Dict) -> Dict:
    """SessionStart advisory; cannot block, so it files no incident."""
    repo = _repo_gate_session_repo(event)
    if not repo:
        return {}
    return {
        'hookSpecificOutput': {
            'hookEventName': 'SessionStart',
            'additionalContext': _repo_gate_session_advisory(repo),
        }
    }


def _augment_posttooluse_to_exchange(ev: Dict, mcp_servers: Optional[Dict] = None) -> Optional[Dict]:
    """Map an Augment PostToolUse event to the Claude-Code-hooks tool_use shape the
    backend analyzer consumes (type / tool_name / tool_input / tool_response).
    Augment's raw tool names are canonicalized (launch-process -> Bash, view ->
    Read, save-file -> Write, str-replace-editor -> Edit, remove-files -> Delete)
    and MCP calls become mcp__<server>__<tool>, so the analyzer stores
    terminal_command / read_file / apply_diff / mcp_server exactly like Claude
    Code / Codex."""
    raw_name = ev.get('tool_name') or ''
    tool_input = ev.get('tool_input') if isinstance(ev.get('tool_input'), dict) else {}
    tool_output = ev.get('tool_output')
    tool_error = ev.get('tool_error')
    file_changes = ev.get('file_changes') if isinstance(ev.get('file_changes'), list) else []
    first_change = file_changes[0] if file_changes and isinstance(file_changes[0], dict) else {}

    def _io_response():
        return {k: v for k, v in (('stdout', tool_output), ('stderr', tool_error)) if v}

    if ev.get('is_mcp_tool'):
        mcp = ev.get('mcp_metadata') if isinstance(ev.get('mcp_metadata'), dict) else {}
        server = (mcp.get('mcpExecutedToolServerName') or '').strip()
        tool = (mcp.get('mcpExecutedToolName') or '').strip()
        if not server:
            # mcp_metadata is null on VS Code/Auggie; resolve the real server +
            # tool from Augment's MCP config by raw-name suffix match so analytics
            # shows the server instead of 'unknown'.
            r_server, r_tool, _ = resolve_augment_mcp(raw_name, mcp_servers or {})
            if r_server:
                server, tool = r_server, r_tool
        server = server or 'unknown'
        tool = tool or raw_name or 'unknown'
        return {
            'type': 'PostToolUse',
            'tool_name': f'mcp__{server}__{tool}',
            'tool_input': tool_input,
            'tool_response': _io_response(),
            'tool_use_id': ev.get('tool_use_id') or _resolve_tool_use_id(ev),
        }

    canonical = AUGMENT_TOOL_FAMILY.get(raw_name, raw_name)

    if canonical == 'Bash':
        canon_input = {'command': tool_input.get('command', '')}
        tool_response = _io_response()
    elif canonical in ('Read', 'Write', 'Edit', 'Delete'):
        path = (tool_input.get('file_path') or tool_input.get('path')
                or tool_input.get('filePath') or first_change.get('path') or '')
        canon_input = {'file_path': path}
        if canonical == 'Read':
            tool_response = {'content': tool_output} if tool_output else {}
        else:
            # Best-effort written text for line-count analytics: Write reads
            # tool_input.content, Edit reads new_string/old_string.
            content = first_change.get('content') or tool_input.get('content') or ''
            if canonical == 'Write':
                if content:
                    canon_input['content'] = content
            else:
                old_content = first_change.get('oldContent') or tool_input.get('old_string') or ''
                if old_content:
                    canon_input['old_string'] = old_content
                if content:
                    canon_input['new_string'] = content
            tool_response = {}
    else:
        # Unmapped Augment tool (web-fetch, codebase-retrieval, ...): forward raw.
        # The current analyzer ignores unknown tool_names; nothing is mis-stored.
        canon_input = tool_input
        tool_response = _io_response()

    return {
        'type': 'PostToolUse',
        'tool_name': canonical,
        'tool_input': canon_input,
        'tool_response': tool_response,
        'tool_use_id': ev.get('tool_use_id') or _resolve_tool_use_id(ev),
    }


def build_llm_exchange(event: Dict, post_tool_events: List[Dict], model: Optional[str] = None) -> Optional[Dict]:
    """Build the end-of-turn exchange for the audit endpoint from Augment's Stop
    event. With includeConversationData set (block-level Stop metadata), Augment
    adds a `conversation` field carrying {userPrompt, agentTextResponse}; an older
    `event._exchange.exchange.{request_message, response_text}` shape is also
    accepted. The PostToolUse tool calls are reconstructed from the audit log."""
    messages = []
    assistant_tool_uses = []

    session_id = event.get('session_id')

    exchange_wrap = event.get('_exchange') if isinstance(event.get('_exchange'), dict) else {}
    exchange = exchange_wrap.get('exchange') if isinstance(exchange_wrap.get('exchange'), dict) else {}
    # Fall back to the legacy `conversation` shape in case a future Augment uses it.
    conversation = event.get('conversation') if isinstance(event.get('conversation'), dict) else {}
    user_prompt = (exchange.get('request_message')
                   or conversation.get('userPrompt') or '').strip() or None
    assistant_response = (exchange.get('response_text')
                          or conversation.get('agentTextResponse') or '').strip()

    # Per-tool-use project resolution state: the shell starts at the session
    # cwd; origin lookups are cached per repo root across the turn.
    cwd = event.get('cwd')
    shell_dir = cwd
    root_projects = {}

    read_skills = set()
    mcp_servers = read_augment_mcp_servers(event)
    for log_entry in post_tool_events:
        ev = log_entry.get('event', {}) if 'event' in log_entry else log_entry
        if ev.get('hook_event_name') != 'PostToolUse':
            continue
        shaped = _augment_posttooluse_to_exchange(ev, mcp_servers)
        if shaped:
            # Attribute this tool call to the repo it worked in (file path /
            # shell cwd tracking); rides on the tool_use entry so the backend
            # can store per-call project on each analytics row.
            tool_project, shell_dir = _project_for_tool_use(
                shaped.get('tool_name'), shaped.get('tool_input'), shell_dir, root_projects)
            shaped['project'] = tool_project
            assistant_tool_uses.append(shaped)

            # Auggie loads an auto-triggered skill by READING its SKILL.md, so
            # that read is the invocation signal. Writes and edits to a skill
            # file are not invocations.
            # The read event carries its own workspace roots; the Stop cwd
            # alone misses reads in a subdirectory or under a relative path.
            event_roots = [str(r) for r in _augment_workspace_roots(ev)]
            if cwd:
                event_roots.append(cwd)
            read_path = _skill_absolute_read_path(_skill_read_path(ev), event_roots)
            skill_name = _skill_name_from_path(read_path, event_roots or cwd)
            # Re-reading one SKILL.md in a turn is still a single invocation.
            # Keyed by path, not name: two skills can share a name under
            # different roots and are different skills.
            if skill_name and _skill_path_key(read_path) not in read_skills:
                read_skills.add(_skill_path_key(read_path))
                assistant_tool_uses.append(
                    _skill_entry(skill_name, read_path, session_id,
                                 log_entry.get('timestamp'), len(assistant_tool_uses)))

    # A typed `/name` arrives as the skill's body, not the token, so match the
    # prompt against SKILL.md on disk before falling back to the token. Skills
    # already seen in a read are skipped individually, not wholesale.
    seen_skills = {_skill_path_key(e.get('skill_path'))
                   for e in assistant_tool_uses if e.get('skill_name')}
    # Same roots the read path uses, so a skill under another workspace folder
    # resolves from the prompt body too.
    body_roots = []
    for log_entry in post_tool_events:
        ev = log_entry.get('event', {}) if 'event' in log_entry else log_entry
        body_roots += [str(r) for r in _augment_workspace_roots(ev)]
    if cwd:
        body_roots.append(cwd)
    matched = _skill_from_prompt_body(user_prompt, body_roots or cwd)
    if matched and _skill_path_key(matched[1]) not in seen_skills:
        assistant_tool_uses.append(
            _skill_entry(matched[0], matched[1], session_id,
                         event.get('timestamp'), len(assistant_tool_uses)))

    if user_prompt:
        messages.append({'role': 'user', 'content': user_prompt})

    if assistant_response or assistant_tool_uses:
        assistant_msg = {'role': 'assistant', 'content': assistant_response}
        if assistant_tool_uses:
            assistant_msg['tool_use'] = assistant_tool_uses
        messages.append(assistant_msg)

    # Require both a user prompt and an assistant turn before emitting. A
    # tool-only exchange (PostToolUse records but no userPrompt) is dropped here;
    # process_stop_event emits a visible drop signal so such turns are never lost
    # silently.
    if len(messages) < 2:
        return None

    if not model:
        model = _augment_model(event, session_id)

    return {
        'conversation_id': session_id or 'unknown',
        'model': model,
        'messages': messages,
        'permission_mode': 'default',
        'cwd': cwd,
        # Turn-level fallback: rows without a per-call project (the user
        # prompt row, or tool-less turns) inherit the session cwd's repo.
        'project': _get_project(cwd),
        'account_identity': build_account_identity(event, probe=True),
    }


def send_to_api(exchange: Dict, api_key: str) -> bool:
    """Send the end-of-turn exchange to the Unbound audit endpoint
    (/v1/hooks/augment). Fail-open: any non-2xx (curl -f -> rc != 0 -> False) is a
    no-op — Stop never blocks."""
    if not api_key:
        log_error("No API key present in send_to_api function", 'config')
        return False

    url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/augment"
    data = json.dumps(exchange)

    for attempt in range(3):
        try:
            # Auth header off-argv (0600 temp file); body off-argv (stdin).
            result = curl_with_auth(
                [f"Authorization: Bearer {api_key}"],
                ["-fsSL", "-X", "POST",
                 "-H", "Content-Type: application/json",
                 "--data-binary", "@-", url],
                input=data.encode(),
                timeout=10,
            )
            if result is None:
                log_error("API request failed: could not write auth header file", 'api_call')
            elif result.returncode == 0:
                return True
            else:
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

    logs = load_existing_logs()

    # Accumulate this turn's PostToolUse entries — those since the most recent
    # prior boundary (SessionStart or prior Stop). main() appends the current
    # Stop to the audit log BEFORE calling us, so on each boundary we stash the
    # segment that just ended in `turn_events`; `session_events or turn_events`
    # then yields the current turn whether or not the current Stop is already
    # logged (resetting on the current Stop would otherwise drop this turn).
    turn_events = []
    session_events = []
    for log in logs:
        log_session_id = log.get('session_id') or log.get('event', {}).get('session_id')
        if log_session_id != session_id:
            continue
        ev = log.get('event', {}) if 'event' in log else log
        name = ev.get('hook_event_name')
        if name in ('SessionStart', 'Stop'):
            turn_events = session_events
            session_events = []
        elif name == 'PostToolUse':
            session_events.append(log)
    session_events = session_events or turn_events

    model = _extract_session_model(logs, session_id) or _augment_model(event, session_id)

    exchange = build_llm_exchange(event, session_events, model=model)

    if exchange:
        send_to_api(exchange, api_key)
    elif session_events:
        # The turn had PostToolUse records but build_llm_exchange returned None
        # (Stop carried no conversation.userPrompt, so messages < 2). Expected
        # when the user keeps Augment's conversation data off (privacy) or runs a
        # build that omits it — so log locally only and never report to the
        # gateway/Sentry (a per-turn report floods it). Fail-open: never blocks.
        log_error(
            f"Dropped Stop turn for session={session_id}: "
            f"{len(session_events)} PostToolUse record(s) but no usable exchange "
            f"(missing userPrompt/assistant content)",
            'dropped_turn',
            report_to_gateway=False,
        )


def get_api_key():
    """Read API key from env, falling back to ~/.unbound/config.json.

    GUI launchers spawn the hook without inheriting shell-profile env vars, so
    setup.py also writes the key to ~/.unbound/config.json as a tier-2 lookup
    (shared with unbound-cli)."""
    key = os.getenv('UNBOUND_AUGMENT_API_KEY')
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


def _state_dir_reject_reason(path: Path, private: bool = False) -> Optional[str]:
    """None if the dir can hold discovery state, else why not. Clears a stale marker."""
    try:
        if private:
            try:
                pst = os.lstat(str(path.parent))
                if (pst.st_mode & 0o002) and not (pst.st_mode & 0o1000):
                    return "fallback parent world-writable and not sticky"
            except OSError:
                pass
            if path.is_symlink():
                return "fallback dir is a symlink"
            try:
                if os.lstat(str(path)).st_uid != os.getuid():
                    return "fallback dir foreign-owned"
            except FileNotFoundError:
                pass
        path.mkdir(parents=True, exist_ok=True)
        if private:
            os.chmod(str(path), 0o700)
            if os.lstat(str(path)).st_mode & 0o077:
                return "fallback dir not private"
        if not os.access(str(path), os.W_OK | os.X_OK):
            return "dir not writable"
        # os.access cannot see a Windows ACL denial; an actual write can.
        fd, probe = tempfile.mkstemp(prefix=".probe.", dir=str(path))
        os.close(fd)
        os.unlink(probe)
        cache_file = path / DISCOVERY_CACHE_PATH.name
        if cache_file.exists() and not os.access(str(cache_file), os.R_OK):
            return "cache file unreadable"
        # A fresh marker means a peer is mid-dispatch; only a stale one must be clearable.
        marker = path / DISCOVERY_DISPATCH_PATH.name
        if marker.exists() and (time.time() - marker.stat().st_mtime) >= DISCOVERY_DISPATCH_TTL_SECONDS:
            marker.unlink()
        return None
    except OSError as e:
        return "%s errno=%s" % (type(e).__name__, e.errno)


def _resolve_state_dir() -> None:
    """Repoint cache/lock/marker at the first usable dir, mirroring the agent's fallback."""
    global DISCOVERY_CACHE_PATH, DISCOVERY_LOCK_PATH, DISCOVERY_DISPATCH_PATH
    current = DISCOVERY_DISPATCH_PATH.parent
    reason = _state_dir_reject_reason(current)
    if reason is None:
        return
    if _is_windows():
        fallback, private = Path(tempfile.gettempdir()) / "unbound", False
    else:
        fallback, private = Path("/var/tmp/unbound-%d" % os.getuid()), True
    fallback_reason = ("same as current" if fallback == current
                       else _state_dir_reject_reason(fallback, private))
    if fallback_reason is not None:
        log_error("discovery gate: no usable state dir (%s: %s / %s: %s)"
                  % (current, reason, fallback, fallback_reason), 'discovery_gate')
        return
    log_error("discovery gate: state dir %s unusable (%s); using %s" % (current, reason, fallback),
              'discovery_gate')
    DISCOVERY_CACHE_PATH = fallback / DISCOVERY_CACHE_PATH.name
    DISCOVERY_LOCK_PATH = fallback / DISCOVERY_LOCK_PATH.name
    DISCOVERY_DISPATCH_PATH = fallback / DISCOVERY_DISPATCH_PATH.name


def _dispatch_discovery() -> None:
    try:
        _resolve_state_dir()
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
                DISCOVERY_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
                if _discovery_installer_is_stale(installer_path):
                    fd, _tmp = tempfile.mkstemp(dir=DISCOVERY_INSTALL_DIR, prefix="install.", suffix=".tmp")
                    os.close(fd)
                    tmp = Path(_tmp)
                    curl = _windows_system32_path("curl.exe") if _is_windows() else "curl"
                    r = subprocess.run(
                        [curl, "-fsSL", "-o", str(tmp), installer_url],
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


def _resolve_cwd(event: Dict) -> Optional[str]:
    """Working directory for this turn: AUGMENT_PROJECT_DIR env (set by the
    Augment runtime) or the first workspace root."""
    cwd = os.environ.get("AUGMENT_PROJECT_DIR")
    if cwd:
        return cwd
    roots = event.get("workspace_roots")
    if isinstance(roots, list) and roots:
        first = roots[0]
        if isinstance(first, str) and first:
            return first
    return None


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

        # Augment identifies the conversation with conversation_id; alias it to
        # session_id once, early, so every downstream helper reads it uniformly.
        if 'session_id' not in event and event.get('conversation_id'):
            event['session_id'] = event.get('conversation_id')
        # Surface the resolved working directory for MCP/scan helpers.
        cwd = _resolve_cwd(event)
        if cwd and not event.get('cwd'):
            event['cwd'] = cwd

        hook_event_name = event.get('hook_event_name')

        # SessionStart fires once per session — natural TTL gate for the
        # debounced discovery scan dispatch.
        if hook_event_name == "SessionStart":
            _device_serial()  # warm the (slow) serial probe + cache once per session
            _check_self_update()
            _dispatch_discovery()
            print(json.dumps(_repo_gate_session_start_output(event)), flush=True)
            return
        session_id = event.get('session_id')

        # Handle PreToolUse - return immediately after decision is made
        if hook_event_name == 'PreToolUse':
            response = process_pre_tool_use(event, api_key)
            response["suppressOutput"] = True
            print(json.dumps(response), flush=True)
            return

        timestamp = _utc_now_z()
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
        # Still return empty JSON object to Augment to indicate completion
        log_error(f"Exception in main: {str(e)}", 'general')
        print('{"suppressOutput": true}', flush=True)


if __name__ == '__main__':
    main()
